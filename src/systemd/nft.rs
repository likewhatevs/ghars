//! nft rule generation for netns-mode runners.
//!
//! Splits from the (previously monolithic) `systemd.rs` module:
//! - [`NftRules`] pair shape (host + ns rule files).
//! - [`render_nft_rules`] entry point.
//! - DNS auto-allow helpers (`dns_auto_allow_destinations`,
//!   `write_dns_auto_allow_lines`).
//! - Rule-text emitters (`render_nft_host`, `render_nft_ns`,
//!   `proto_tokens`, `egress_rule_lines`).
//!
//! Rule rendering is a pure function: no D-Bus, no filesystem.

use std::fmt::Write;
use std::net::IpAddr;

use crate::config::{EffectiveNetworkBinding, PortSpec, Proto};
use crate::{GharsError, Result};

/// Pair of nft rule files for one Netns runner. Generated from the
/// resolved network binding's `allowed_egress` rules + the allocated
/// /30 subnet. `ip_allow` / `ip_deny` on the same binding are
/// emitted separately as systemd `IPAddressAllow=` / `IPAddressDeny=`
/// directives by `render_runner_unit` (cgroup-BPF layer), not by
/// this function — see the `ip_allow` doc-comment on
/// `crate::config::NetworkSpec` for the cgroup-BPF vs nft layer split.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct NftRules {
    /// Host-side rules. Loaded by `ghars-net@%i.service`'s `nft -f
    /// /etc/ghars/nft.d/%i-host.nft` `ExecStart` line. Filters traffic
    /// arriving on the runner's veth, before forwarding.
    pub host_rules: String,
    /// Inside-namespace rules. Loaded inside the runner's netns via
    /// `ghars _netns-veth %i nft -f /etc/ghars/nft.d/%i-ns.nft`.
    /// Defense in depth: drops misbehaving outbound traffic before it
    /// reaches the veth.
    pub ns_rules: String,
}

/// Render the host-side + ns-side nft rule files for one runner.
///
/// `runner_name` is the systemd instance name (e.g. `"buckos"`). The
/// table names follow the `ghars_RUNNER` (host) and `ghars_RUNNER_ns`
/// (inside) convention used by the `ghars-net@.service` `ExecStop=`.
///
/// **Caller invariant (SEC-35):** `runner_name` MUST already match
/// `crate::config::IDENTIFIER_REGEX` (`^[a-z]([a-z0-9-]*[a-z0-9])?$`,
/// ≤ 64 chars). The full `IDENTIFIER_REGEX` charset (`a-z 0-9 -`) is a
/// subset of nft's identifier alphabet for table/chain names and
/// interface-glob patterns, so a runner name that passes
/// `validators::validate_runner_name` interpolates safely into every
/// `ghars_RUNNER`, `ghars-RUNNER-h`, `ghars-RUNNER-r`, `ghars-RUNNER-*`,
/// and log-prefix string this generator emits. We re-validate at the
/// entry of this function as a defense-in-depth check; an invalid
/// runner name reaching this point is a programming error elsewhere
/// (config loader / count expander), but we'd rather refuse than emit
/// a malformed nft file that risks injecting attacker-controlled
/// nft syntax.
///
/// The generator masquerades `subnet` only — per Challenge 7
/// scoping. Comments inside `EgressRule`s must already have passed
/// `crate::validators::validate_egress_comment` (which rejects any
/// character outside `[A-Za-z0-9 _.,:/+-]`) before reaching the
/// generator; the renderer interpolates them verbatim and an
/// `assert!` (live in release) panics on programming errors that
/// bypass the validator (SEC-30).
///
/// # Errors
///
/// Returns `GharsError::Validation` if `runner_name` fails the
/// identifier regex (SEC-35 defense-in-depth gate). Other future
/// validation hooks (CIDR ranges, port-range sanity beyond the
/// config-time validator) hang off this same Result.
pub fn render_nft_rules(runner_name: &str, binding: &EffectiveNetworkBinding) -> Result<NftRules> {
    crate::validators::validate_runner_name(runner_name).map_err(|e| match e {
        GharsError::Validation(msg, _) => GharsError::Validation(
            format!("nft rule generator refused runner name: {msg}"),
            "runner names must match ^[a-z]([a-z0-9-]*[a-z0-9])?$ (SEC-35)".into(),
        ),
        other => other,
    })?;
    // Defense-in-depth: this generator emits `iifname
    // "ghars-{runner_name}-h"` and `oifname "ghars-{runner_name}-h"`
    // matchers that the kernel will refuse if the rendered interface
    // name exceeds IFNAMSIZ - 1. `cli::validate_netns_runner_name_lengths`
    // gates this at config-load, but
    // direct callers of `render_nft_rules` (snapshot tests,
    // hypothetical future code paths) bypass that gate. Re-check the
    // cap alongside the existing IDENTIFIER_REGEX gate so a programming
    // error here surfaces a structured Validation instead of leaking
    // an oversize string into the generated nft file.
    if runner_name.len() > crate::validators::NETNS_RUNNER_NAME_MAX_LEN {
        return Err(GharsError::Validation(
            format!(
                "nft rule generator refused runner name: {runner_name:?} is {got} chars; \
                 derived veth 'ghars-{runner_name}-h' would exceed kernel IFNAMSIZ ({ifn})",
                got = runner_name.len(),
                ifn = crate::validators::IFNAMSIZ,
            ),
            format!(
                "shorten the runner name to <={} chars or switch to network mode 'open'",
                crate::validators::NETNS_RUNNER_NAME_MAX_LEN,
            ),
        ));
    }
    // nft rules are Netns-mode-only — Open mode runners share the
    // host netns and have no per-runner veth or table. Delegate to
    // `EffectiveNetworkBinding::netns_subnet` for the typed
    // mode⇒subnet contract check; the helper returns a typed
    // `NetnsSubnetError` enum which we wrap into a
    // `GharsError::Validation` with a renderer-specific message
    // here. The caller in `apply::netns::provision_netns_artifacts`
    // already gates Open mode at its own entry; this defense-in-
    // depth check catches direct callers (snapshot tests, future
    // programmatic spec builders) that bypass the apply-side gate.
    let subnet = binding.netns_subnet().map_err(|e| match e {
        crate::config::NetnsSubnetError::NetnsMissingSubnet => GharsError::Validation(
            format!(
                "render_nft_rules refused netns binding for runner {runner_name:?}: \
                 subnet is None despite mode = Netns; \
                 this is a ghars bug — lower_to_effective and render_nft_rules \
                 disagree on the mode⇒subnet contract",
            ),
            "report this as a ghars issue with the failing config".into(),
        ),
        crate::config::NetnsSubnetError::OpenMode => GharsError::Validation(
            format!(
                "render_nft_rules refused Open-mode binding for runner {runner_name:?}: \
                 nft rules apply only to Netns-mode runners",
            ),
            "Open-mode bindings have no per-runner veth or netns; \
             use IPAddressAllow / IPAddressDeny / RestrictAddressFamilies \
             in the [network.NAME] block instead"
                .into(),
        ),
    })?;
    // DNS auto-allow destinations (Part 9c — Forward / Static).
    // Design: Forward mode emits implicit udp+tcp/53 to the runner's
    // host-side veth IP (systemd-resolved DNSStubListenerExtra binds
    // there). Static mode emits implicit udp+tcp/53 to each
    // operator-supplied server IP. Operators NEVER need a manual
    // `port = 53` egress rule for DNS — the renderer derives the
    // destination(s) from the resolved DnsMode + subnet.
    let dns_dests = dns_auto_allow_destinations(&binding.spec.dns, subnet)?;
    let host = render_nft_host(runner_name, binding, subnet, &dns_dests);
    let ns = render_nft_ns(runner_name, binding, &dns_dests);
    Ok(NftRules {
        host_rules: host,
        ns_rules: ns,
    })
}

/// Resolve the DNS auto-allow destinations from a `DnsMode` and
/// the netns binding's `/30` subnet. Returns the list of `IpAddr`s
/// the generator must emit udp+tcp/53 accept rules for.
///
/// - `DnsMode::Forward` → the runner's host-side veth IP (single
///   address derived from the `/30` subnet).
/// - `DnsMode::Static { servers }` → every operator-supplied server.
///   Validator (`validate_dns_mode`) gates non-empty at config-load,
///   so this path returns at least one address.
///
/// Caller (`render_nft_rules`) extracts the subnet from the binding
/// AFTER asserting `mode == Netns`, so the value passed in is
/// always the resolved /30 (the field is `Option<IpNet>` on the
/// binding to reflect that Open-mode bindings own no subnet).
///
/// Errors only when `subnet_addresses` rejects the subnet (non-`/30`
/// or non-IPv4); apply.rs's preflight + the netns subnet allocator
/// guarantee a `/30` IPv4 binding, so this is a defense-in-depth
/// gate that surfaces a structured `Validation` over an opaque nft
/// rule failure.
fn dns_auto_allow_destinations(
    dns: &crate::config::DnsMode,
    subnet: ipnet::IpNet,
) -> Result<Vec<IpAddr>> {
    match dns {
        crate::config::DnsMode::Forward => {
            let (host_ip, _runner_ip) = crate::netns::subnet_addresses(&subnet)?;
            Ok(vec![host_ip])
        }
        crate::config::DnsMode::Static { servers } => Ok(servers.clone()),
    }
}

/// Emit the udp+tcp/53 accept lines for `dests` into the
/// `output_filter` chain currently being rendered at `s` (caller is
/// responsible for indentation; we emit two complete lines per dest
/// at the chain's current cursor). nft uses `ip daddr` for IPv4 and
/// `ip6 daddr` for IPv6. udp first, then tcp — matches the design
/// example ordering ("udp+tcp/53").
fn write_dns_auto_allow_lines(s: &mut String, dests: &[IpAddr]) {
    for dest in dests {
        let proto_match = match dest {
            IpAddr::V4(_) => "ip",
            IpAddr::V6(_) => "ip6",
        };
        let _ = writeln!(
            s,
            "        {proto_match} daddr {dest} udp dport 53 accept comment \"ghars dns auto-allow\""
        );
        let _ = writeln!(
            s,
            "        {proto_match} daddr {dest} tcp dport 53 accept comment \"ghars dns auto-allow\""
        );
    }
}

fn render_nft_host(
    runner_name: &str,
    binding: &EffectiveNetworkBinding,
    subnet: ipnet::IpNet,
    dns_dests: &[IpAddr],
) -> String {
    let mut s = String::new();
    let _ = writeln!(s, "# generated by ghars apply — DO NOT EDIT");
    let _ = writeln!(
        s,
        "# runner={runner_name} netns=ghars-{runner_name} veth=ghars-{runner_name}-h"
    );
    let _ = writeln!(s, "# subnet={subnet}");
    s.push('\n');

    let _ = writeln!(s, "table inet ghars_{runner_name} {{");
    s.push_str("    chain output_filter {\n");
    s.push_str("        ct state established,related accept\n");
    // ICMP frag-needed: Part 9c Challenge 5 — never drop. PMTU
    // discovery requires this.
    s.push_str(
        "        meta l4proto icmp icmp type destination-unreachable icmp code frag-needed accept\n",
    );
    // DNS auto-allow (Part 9c — Forward / Static). Forward mode
    // targets the host-side veth IP (DNSStubListenerExtra=); Static
    // targets each operator-supplied server IP. Emitted BEFORE the
    // operator's `allowed_egress` rules so DNS sits in a fixed
    // position regardless of operator config. For Forward mode,
    // packets to host_ip hit local input on the host (not the
    // forward chain), so this host-side rule is defense-in-depth;
    // for Static mode, packets are forwarded to the LAN and this
    // rule is load-bearing for forward-chain matching via the
    // `iifname "ghars-RUNNER-h" jump output_filter` plumbing below.
    write_dns_auto_allow_lines(&mut s, dns_dests);
    for rule in &binding.spec.allowed_egress {
        for (proto_token, _) in proto_tokens(rule.proto) {
            for line in
                egress_rule_lines(&rule.addr, &rule.port, proto_token, rule.comment.as_deref())
            {
                let _ = writeln!(s, "        {line}");
            }
        }
    }
    let _ = writeln!(
        s,
        "        log prefix \"ghars-{runner_name} drop: \" level info"
    );
    s.push_str("        drop\n");
    s.push_str("    }\n");

    s.push_str("    chain forward {\n");
    s.push_str("        type filter hook forward priority filter\n");
    let _ = writeln!(
        s,
        "        iifname \"ghars-{runner_name}-h\" jump output_filter"
    );
    // MSS clamping for TCP — Part 9c Challenge 5. Both directions on
    // the veth.
    let _ = writeln!(
        s,
        "        oifname \"ghars-{runner_name}-h\" tcp flags syn / syn,rst tcp option maxseg size set rt mtu"
    );
    let _ = writeln!(
        s,
        "        iifname \"ghars-{runner_name}-h\" tcp flags syn / syn,rst tcp option maxseg size set rt mtu"
    );
    s.push_str("    }\n");

    s.push_str("    chain postroute {\n");
    s.push_str("        type nat hook postrouting priority srcnat\n");
    // Per-runner masquerade scope (SEC-07 / Challenge 7). Source is
    // THIS runner's /30 only; if the runner's table is destroyed by
    // ExecStop, the masquerade rule vanishes with it.
    let _ = writeln!(
        s,
        "        ip saddr {subnet} oifname != \"ghars-{runner_name}-*\" masquerade"
    );
    s.push_str("    }\n");
    s.push_str("}\n");
    s
}

fn render_nft_ns(
    runner_name: &str,
    binding: &EffectiveNetworkBinding,
    dns_dests: &[IpAddr],
) -> String {
    let mut s = String::new();
    let _ = writeln!(s, "# generated by ghars apply — DO NOT EDIT");
    let _ = writeln!(s, "# runner={runner_name} namespace=ghars-{runner_name}");
    s.push('\n');

    let _ = writeln!(s, "table inet ghars_{runner_name}_ns {{");
    s.push_str("    chain output_filter {\n");
    s.push_str("        ct state established,related accept\n");
    s.push_str("        oifname \"lo\" accept\n");
    s.push_str(
        "        meta l4proto icmp icmp type destination-unreachable icmp code frag-needed accept\n",
    );
    // DNS auto-allow inside the netns — see render_nft_host comment.
    // Inside-netns table is the load-bearing one for both modes:
    // every DNS query exits the netns through this chain, so it
    // MUST allow udp+tcp/53 to the resolved destination(s) or the
    // log+drop tail at the bottom of the chain swallows the query.
    write_dns_auto_allow_lines(&mut s, dns_dests);
    for rule in &binding.spec.allowed_egress {
        for (proto_token, _) in proto_tokens(rule.proto) {
            for line in
                egress_rule_lines(&rule.addr, &rule.port, proto_token, rule.comment.as_deref())
            {
                let _ = writeln!(s, "        {line}");
            }
        }
    }
    let _ = writeln!(
        s,
        "        log prefix \"ghars-{runner_name} ns-drop: \" level info"
    );
    s.push_str("        drop\n");
    s.push_str("    }\n");

    s.push_str("    chain output {\n");
    s.push_str("        type filter hook output priority filter\n");
    s.push_str("        jump output_filter\n");
    s.push_str("    }\n");

    s.push_str("    chain input {\n");
    s.push_str("        type filter hook input priority filter\n");
    s.push_str("        ct state established,related accept\n");
    s.push_str("        iifname \"lo\" accept\n");
    let _ = writeln!(s, "        iifname \"ghars-{runner_name}-r\" accept");
    let _ = writeln!(
        s,
        "        log prefix \"ghars-{runner_name} ns-in-drop: \" level info"
    );
    s.push_str("        drop\n");
    s.push_str("    }\n");
    s.push_str("}\n");
    s
}

fn proto_tokens(proto: Proto) -> Vec<(&'static str, &'static str)> {
    // Returns (nft proto token, comment-friendly label) pairs. `Both`
    // expands to two passes so the generator emits one rule per L4
    // protocol — nft has no `proto in {tcp, udp}` shorthand for dport
    // matching that mixes both cleanly.
    match proto {
        Proto::Tcp => vec![("tcp", "tcp")],
        Proto::Udp => vec![("udp", "udp")],
        Proto::Both => vec![("tcp", "tcp"), ("udp", "udp")],
    }
}

fn egress_rule_lines(
    addr: &str,
    port: &PortSpec,
    proto: &'static str,
    comment: Option<&str>,
) -> Vec<String> {
    // EgressRule.addr is parsed by the config-time validator as IpAddr
    // or IpNet; we pass it through verbatim. nft accepts both `ip
    // daddr 1.2.3.4` and `ip daddr 1.2.3.0/24`.
    //
    // SEC-30: comment is interpolated unsanitized between `"` chars.
    // The validator (validate_egress_comment) rejects any character
    // that could break the string literal at config-load time, so the
    // only path here is via inputs that already passed that gate. The
    // assert! below is a defense-in-depth gate against any future
    // call site that constructs an EgressRule programmatically and
    // skips validation: panic-on-violation is preferred over silently
    // emitting a malformed nft rule, and assert! (not debug_assert!)
    // keeps the gate live in release builds where the SEC-30 attack
    // would otherwise hit production.
    if let Some(c) = comment {
        assert!(
            c.chars().all(|ch| ch.is_ascii_alphanumeric()
                || matches!(ch, ' ' | '_' | '.' | ',' | ':' | '/' | '+' | '-')),
            "EgressRule.comment {c:?} contains chars outside [A-Za-z0-9 _.,:/+-]; \
             validate_egress_comment must run before render_nft_rules"
        );
    }
    let daddr = if addr.contains(':') {
        "ip6 daddr"
    } else {
        "ip daddr"
    };
    match port {
        PortSpec::Single(p) => {
            let mut line = format!("{daddr} {addr} {proto} dport {p} accept");
            if let Some(c) = comment {
                let _ = write!(line, " comment \"{c}\"");
            }
            vec![line]
        }
        PortSpec::Set(ports) => {
            // nft `dport { p1, p2, ... }` set syntax.
            let set = ports
                .iter()
                .map(u16::to_string)
                .collect::<Vec<_>>()
                .join(", ");
            let mut line = format!("{daddr} {addr} {proto} dport {{ {set} }} accept");
            if let Some(c) = comment {
                let _ = write!(line, " comment \"{c}\"");
            }
            vec![line]
        }
        PortSpec::Range { start, end } => {
            // nft range syntax: `dport START-END`.
            let mut line = format!("{daddr} {addr} {proto} dport {start}-{end} accept");
            if let Some(c) = comment {
                let _ = write!(line, " comment \"{c}\"");
            }
            vec![line]
        }
    }
}

// --- Test surface --------------------------------------------------------

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used)]
mod tests {
    use super::*;
    use ipnet::IpNet;

    use crate::config::{DnsMode, EgressRule, Ipv6Mode, NetworkMode, NetworkSpec};

    fn netns_binding(subnet: &str, allowed: Vec<EgressRule>) -> EffectiveNetworkBinding {
        EffectiveNetworkBinding {
            name: "buck2-isolated".into(),
            spec: NetworkSpec {
                mode: NetworkMode::Netns,
                allowed_egress: allowed,
                ip_allow: vec![],
                ip_deny: vec![],
                restrict_address_families: vec![],
                dns: DnsMode::default(),
                ipv6: Ipv6Mode::default(),
            },
            subnet: Some(subnet.parse::<IpNet>().unwrap()),
        }
    }

    #[test]
    fn render_nft_emits_per_runner_table_and_masquerade() {
        let binding = netns_binding(
            "10.200.0.0/30",
            vec![EgressRule {
                addr: "192.168.2.84".into(),
                port: PortSpec::Single(3128),
                proto: Proto::Tcp,
                comment: Some("squid proxy".into()),
            }],
        );
        let rules = render_nft_rules("buckos", &binding).unwrap();
        assert!(rules.host_rules.contains("table inet ghars_buckos"));
        assert!(
            rules
                .host_rules
                .contains("ip daddr 192.168.2.84 tcp dport 3128 accept")
        );
        assert!(rules.host_rules.contains("comment \"squid proxy\""));
        assert!(
            rules
                .host_rules
                .contains("ip saddr 10.200.0.0/30 oifname != \"ghars-buckos-*\" masquerade")
        );
        // Per-runner ns table.
        assert!(rules.ns_rules.contains("table inet ghars_buckos_ns"));
    }

    #[test]
    fn render_nft_includes_icmp_frag_needed_in_both_tables() {
        // Challenge 5: PMTU discovery requires accepting ICMP type 3
        // code 4 in BOTH the host forward path and the netns input.
        let binding = netns_binding("10.200.0.0/30", vec![]);
        let rules = render_nft_rules("buckos", &binding).unwrap();
        assert!(
            rules
                .host_rules
                .contains("icmp type destination-unreachable icmp code frag-needed accept")
        );
        assert!(
            rules
                .ns_rules
                .contains("icmp type destination-unreachable icmp code frag-needed accept")
        );
    }

    #[test]
    fn render_nft_includes_mss_clamp_on_both_directions() {
        let binding = netns_binding("10.200.0.0/30", vec![]);
        let rules = render_nft_rules("buckos", &binding).unwrap();
        assert!(rules.host_rules.contains(
            "oifname \"ghars-buckos-h\" tcp flags syn / syn,rst tcp option maxseg size set rt mtu"
        ));
        assert!(rules.host_rules.contains(
            "iifname \"ghars-buckos-h\" tcp flags syn / syn,rst tcp option maxseg size set rt mtu"
        ));
    }

    #[test]
    fn render_nft_handles_proto_both() {
        let binding = netns_binding(
            "10.200.0.0/30",
            vec![EgressRule {
                addr: "1.2.3.4".into(),
                port: PortSpec::Single(53),
                proto: Proto::Both,
                comment: None,
            }],
        );
        let rules = render_nft_rules("r", &binding).unwrap();
        // Both tcp + udp lines emitted.
        assert!(
            rules
                .host_rules
                .contains("ip daddr 1.2.3.4 tcp dport 53 accept")
        );
        assert!(
            rules
                .host_rules
                .contains("ip daddr 1.2.3.4 udp dport 53 accept")
        );
    }

    #[test]
    fn render_nft_emits_ip6_daddr_for_ipv6_egress() {
        let binding = netns_binding(
            "10.200.0.0/30",
            vec![EgressRule {
                addr: "2001:db8::1".into(),
                port: PortSpec::Single(443),
                proto: Proto::Tcp,
                comment: None,
            }],
        );
        let rules = render_nft_rules("r", &binding).unwrap();
        assert!(
            rules
                .host_rules
                .contains("ip6 daddr 2001:db8::1 tcp dport 443 accept"),
            "IPv6 egress must use `ip6 daddr`, not `ip daddr`; got:\n{}",
            rules.host_rules
        );
        assert!(
            !rules.host_rules.contains("ip daddr 2001:db8::1"),
            "IPv6 address must NOT use `ip daddr`; got:\n{}",
            rules.host_rules
        );
    }

    #[test]
    fn render_nft_emits_ip_daddr_for_ipv4_egress() {
        let binding = netns_binding(
            "10.200.0.0/30",
            vec![EgressRule {
                addr: "192.168.2.84".into(),
                port: PortSpec::Single(3128),
                proto: Proto::Tcp,
                comment: None,
            }],
        );
        let rules = render_nft_rules("r", &binding).unwrap();
        assert!(
            rules
                .host_rules
                .contains("ip daddr 192.168.2.84 tcp dport 3128 accept"),
            "IPv4 egress must use `ip daddr`; got:\n{}",
            rules.host_rules
        );
    }

    #[test]
    fn render_nft_emits_dns_auto_allow_for_forward_mode() {
        // Part 9c — Forward mode emits implicit udp+tcp/53 to the
        // runner's host-side veth IP (DNSStubListenerExtra=). For a
        // /30 of 10.200.0.0/30 the host side is 10.200.0.1.
        let binding = netns_binding("10.200.0.0/30", vec![]);
        let rules = render_nft_rules("buckos", &binding).unwrap();
        for body in [&rules.host_rules, &rules.ns_rules] {
            assert!(
                body.contains(
                    "ip daddr 10.200.0.1 udp dport 53 accept comment \"ghars dns auto-allow\""
                ),
                "Forward mode must emit udp/53 auto-allow to host_ip in both tables; got:\n{body}"
            );
            assert!(
                body.contains(
                    "ip daddr 10.200.0.1 tcp dport 53 accept comment \"ghars dns auto-allow\""
                ),
                "Forward mode must emit tcp/53 auto-allow to host_ip in both tables; got:\n{body}"
            );
        }
    }

    #[test]
    fn render_nft_emits_dns_auto_allow_for_static_mode_per_server() {
        // Part 9c — Static mode emits implicit udp+tcp/53 to EACH
        // operator-supplied server. The validator
        // (validate_dns_mode) already rejects empty servers list at
        // config-load, so the renderer can rely on at least one IP.
        let mut binding = netns_binding("10.200.0.0/30", vec![]);
        binding.spec.dns = crate::config::DnsMode::Static {
            servers: vec!["1.1.1.1".parse().unwrap(), "8.8.8.8".parse().unwrap()],
        };
        let rules = render_nft_rules("buckos", &binding).unwrap();
        for body in [&rules.host_rules, &rules.ns_rules] {
            for server in ["1.1.1.1", "8.8.8.8"] {
                assert!(
                    body.contains(&format!(
                        "ip daddr {server} udp dport 53 accept comment \"ghars dns auto-allow\""
                    )),
                    "Static mode must emit udp/53 auto-allow for {server} in both tables; got:\n{body}"
                );
                assert!(
                    body.contains(&format!(
                        "ip daddr {server} tcp dport 53 accept comment \"ghars dns auto-allow\""
                    )),
                    "Static mode must emit tcp/53 auto-allow for {server} in both tables; got:\n{body}"
                );
            }
        }
        // Forward's host_ip MUST NOT appear when Static is selected
        // — Static doesn't go through the host's resolved.
        for body in [&rules.host_rules, &rules.ns_rules] {
            assert!(
                !body.contains("ip daddr 10.200.0.1 udp dport 53 accept"),
                "Static mode must NOT emit Forward's host_ip auto-allow; got:\n{body}"
            );
        }
    }

    #[test]
    fn render_nft_dns_auto_allow_does_not_require_operator_egress_entry() {
        // Coverage for the design contract: "NO operator allowed_egress
        // entry needed for DNS — it's implicit when dns = forward".
        // Empty allowed_egress + Forward dns must still produce
        // working DNS via the auto-allow rules.
        let binding = netns_binding("10.200.0.0/30", vec![]);
        let rules = render_nft_rules("r", &binding).unwrap();
        // No operator rules → only the system-supplied lines (ct,
        // icmp, dns auto-allow) precede the log+drop tail.
        assert!(rules.ns_rules.contains("ip daddr 10.200.0.1 udp dport 53"));
        assert!(rules.ns_rules.contains("ip daddr 10.200.0.1 tcp dport 53"));
        // Drop tail must still be present (defense-in-depth: the
        // auto-allow inserts BEFORE the log+drop, never replaces it).
        assert!(rules.ns_rules.contains("ns-drop"));
        assert!(rules.ns_rules.contains("\n        drop\n"));
    }

    #[test]
    fn render_nft_dns_auto_allow_emitted_before_operator_egress() {
        // Position invariant — auto-allow rules sit AFTER the
        // ct/icmp system rules but BEFORE the operator's
        // `allowed_egress` lines, so DNS sits at a fixed location
        // regardless of operator config (debugging predictability).
        let binding = netns_binding(
            "10.200.0.0/30",
            vec![EgressRule {
                addr: "192.168.2.84".into(),
                port: PortSpec::Single(3128),
                proto: Proto::Tcp,
                comment: Some("squid proxy".into()),
            }],
        );
        let rules = render_nft_rules("r", &binding).unwrap();
        let dns_idx = rules
            .ns_rules
            .find("ip daddr 10.200.0.1 udp dport 53")
            .expect("dns auto-allow line must be present");
        let op_idx = rules
            .ns_rules
            .find("ip daddr 192.168.2.84 tcp dport 3128")
            .expect("operator egress line must be present");
        let icmp_idx = rules
            .ns_rules
            .find("icmp code frag-needed accept")
            .expect("icmp frag-needed must be present");
        assert!(
            icmp_idx < dns_idx && dns_idx < op_idx,
            "expected order: icmp frag-needed < dns auto-allow < operator egress; \
             got icmp@{icmp_idx} dns@{dns_idx} op@{op_idx}\n{}",
            rules.ns_rules
        );
    }

    #[test]
    fn render_nft_handles_port_set_and_range() {
        let binding = netns_binding(
            "10.200.0.0/30",
            vec![
                EgressRule {
                    addr: "10.0.0.1".into(),
                    port: PortSpec::Set(vec![80, 443]),
                    proto: Proto::Tcp,
                    comment: None,
                },
                EgressRule {
                    addr: "10.0.0.2".into(),
                    port: PortSpec::Range {
                        start: 1024,
                        end: 2048,
                    },
                    proto: Proto::Tcp,
                    comment: None,
                },
            ],
        );
        let rules = render_nft_rules("r", &binding).unwrap();
        assert!(rules.host_rules.contains("dport { 80, 443 }"));
        assert!(rules.host_rules.contains("dport 1024-2048"));
    }

    #[test]
    fn render_nft_passes_safe_comment_unchanged() {
        // SEC-30: validate_egress_comment is the single gate; the
        // renderer interpolates a comment that's already in the safe
        // set verbatim. No `?` substitution, no escaping. Any byte
        // that survives this assertion is a byte that was in the
        // operator's TOML.
        let binding = netns_binding(
            "10.200.0.0/30",
            vec![EgressRule {
                addr: "1.2.3.4".into(),
                port: PortSpec::Single(80),
                proto: Proto::Tcp,
                comment: Some("squid proxy 8.8.8.8/32".into()),
            }],
        );
        let rules = render_nft_rules("r", &binding).unwrap();
        assert!(
            rules
                .host_rules
                .contains("comment \"squid proxy 8.8.8.8/32\""),
            "expected comment to pass through verbatim; got: {}",
            rules.host_rules
        );
    }

    // SEC-35: instance-name escaping in nft commands and helper
    // scripts. The nft generator interpolates `runner_name` directly
    // into table/chain names, interface names, and log-prefix strings;
    // we depend on the IDENTIFIER_REGEX-validated runner name being a
    // safe subset of nft's identifier alphabet. The next four tests
    // pin both halves of that contract.

    #[test]
    fn render_nft_rejects_runner_name_with_uppercase() {
        let binding = netns_binding("10.200.0.0/30", vec![]);
        let err = render_nft_rules("Buckos", &binding).expect_err("must reject");
        assert!(format!("{err}").contains("nft rule generator refused"));
    }

    #[test]
    fn render_nft_rejects_runner_name_with_underscore() {
        // Underscore is allowed in nft identifiers but NOT in
        // IDENTIFIER_REGEX. The generator gates on the regex so an
        // underscore in the runner name is a programming error from
        // the loader (which should have rejected it already); the
        // generator's defense-in-depth check refuses anyway.
        let binding = netns_binding("10.200.0.0/30", vec![]);
        let err = render_nft_rules("buck_os", &binding).expect_err("must reject");
        assert!(format!("{err}").contains("nft rule generator refused"));
    }

    #[test]
    fn render_nft_rejects_runner_name_with_shell_metachar() {
        let binding = netns_binding("10.200.0.0/30", vec![]);
        // Backtick + `;` + space — every common shell metachar must
        // bounce off the IDENTIFIER_REGEX gate.
        for bad in [
            "bad`name",
            "bad;rm -rf /",
            "bad name",
            "bad/name",
            "bad$name",
        ] {
            let err = render_nft_rules(bad, &binding).expect_err(&format!("must reject {bad:?}"));
            assert!(format!("{err}").contains("nft rule generator refused"));
        }
    }

    #[test]
    fn render_nft_accepts_full_identifier_charset() {
        // The full IDENTIFIER_REGEX charset is `^[a-z]([a-z0-9-]*[a-z0-9])?$`.
        // Use a name that exercises all of `[a-z]` + `[0-9]` + `-`
        // while staying within `NETNS_RUNNER_NAME_MAX_LEN` (the
        // generator enforces the IFNAMSIZ-derived cap as
        // defense-in-depth, so this test feeds a name that fits the
        // tighter netns cap rather than the looser identifier-shape
        // cap). 7 chars covers `[a-z]` + `[0-9]` + `-` and exercises
        // all three character classes the regex permits. Mirrors
        // SEC-35's "verify the full regex charset produces valid nft
        // syntax".
        let name = "a1-b2-c";
        let binding = netns_binding(
            "10.200.0.0/30",
            vec![EgressRule {
                addr: "1.2.3.4".into(),
                port: PortSpec::Single(443),
                proto: Proto::Tcp,
                comment: None,
            }],
        );
        let rules = render_nft_rules(name, &binding).unwrap();

        // Table name follows ghars_RUNNER convention with underscores
        // separating ghars and the verbatim runner name. nft accepts
        // `-` and digits inside table identifiers (kernel tablename
        // grammar permits the full a-z 0-9 _ - set).
        assert!(
            rules
                .host_rules
                .contains(&format!("table inet ghars_{name}"))
        );
        assert!(
            rules
                .ns_rules
                .contains(&format!("table inet ghars_{name}_ns"))
        );

        // Interface globs `ghars-RUNNER-h`, `ghars-RUNNER-r`,
        // `ghars-RUNNER-*` are all quoted in the rule output. None of
        // them can contain unbalanced quotes — the runner name doesn't
        // include `"`.
        assert!(rules.host_rules.contains(&format!("\"ghars-{name}-h\"")));
        assert!(rules.host_rules.contains(&format!("\"ghars-{name}-*\"")));
        assert!(rules.ns_rules.contains(&format!("\"ghars-{name}-r\"")));

        // Log-prefix string literals are also balanced and contain the
        // verbatim runner name without escape sequences.
        assert!(
            rules
                .host_rules
                .contains(&format!("\"ghars-{name} drop: \""))
        );
        assert!(
            rules
                .ns_rules
                .contains(&format!("\"ghars-{name} ns-drop: \""))
        );

        // Sanity: every double-quote in the output is paired (no
        // dangling `"`s that would cause nft to swallow following
        // tokens). Counting is sufficient because every rendered
        // string literal closes with a matching `"`.
        let dq_count = rules.host_rules.chars().filter(|&c| c == '"').count();
        assert!(
            dq_count.is_multiple_of(2),
            "host rules have unbalanced quotes"
        );
        let dq_count = rules.ns_rules.chars().filter(|&c| c == '"').count();
        assert!(
            dq_count.is_multiple_of(2),
            "ns rules have unbalanced quotes"
        );
    }

    /// `render_nft_rules` MUST refuse Open-mode bindings: nft
    /// rules apply only to Netns-mode runners (per-runner veth +
    /// table). The caller in `apply::netns::provision_netns_artifacts`
    /// already gates Open-mode at its own entry, but a direct
    /// caller (snapshot tests, future programmatic spec builders)
    /// bypasses that gate. The renderer's structured Validation
    /// rejection beats the alternative (None-deref panic on
    /// `binding.subnet` later).
    #[test]
    fn render_nft_rejects_open_mode_binding() {
        let binding = EffectiveNetworkBinding {
            name: "hostnet".into(),
            spec: NetworkSpec {
                mode: NetworkMode::Open,
                allowed_egress: vec![],
                ip_allow: vec!["10.0.0.0/8".parse::<IpNet>().unwrap()],
                ip_deny: vec![],
                restrict_address_families: vec![],
                dns: DnsMode::default(),
                ipv6: Ipv6Mode::default(),
            },
            // Open mode binding carries no subnet — the lowering
            // pipeline guarantees this; the test fixture mirrors
            // production.
            subnet: None,
        };
        let err = render_nft_rules("hostnet", &binding).expect_err("must reject");
        let msg = format!("{err}");
        assert!(
            msg.contains("Open-mode binding"),
            "msg must name the offending shape: {msg}"
        );
        assert!(
            msg.contains("nft rules apply only to Netns-mode runners"),
            "msg must explain why: {msg}"
        );
        // Helper interpolates the caller label; pin that the
        // render_nft_rules path is named so the operator can locate
        // the rejecting site.
        assert!(
            msg.contains("render_nft_rules"),
            "msg must name the calling renderer: {msg}"
        );
    }

    /// Defense-in-depth gate against a code-bug shape: a Netns-mode
    /// binding reaching `render_nft_rules` with `subnet = None`
    /// would mean `lower_to_effective` and `render_nft_rules`
    /// disagree on the mode⇒subnet contract. The renderer surfaces
    /// a structured Validation error rather than panicking on the
    /// downstream subnet usage.
    #[test]
    fn render_nft_rejects_netns_binding_without_subnet() {
        let binding = EffectiveNetworkBinding {
            name: "ci-net".into(),
            spec: NetworkSpec {
                mode: NetworkMode::Netns,
                allowed_egress: vec![EgressRule {
                    addr: "10.0.0.1".into(),
                    port: PortSpec::Single(443),
                    proto: Proto::Tcp,
                    comment: None,
                }],
                ip_allow: vec![],
                ip_deny: vec![],
                restrict_address_families: vec![],
                dns: DnsMode::default(),
                ipv6: Ipv6Mode::default(),
            },
            subnet: None,
        };
        let err = render_nft_rules("ci-net", &binding).expect_err("must reject");
        let msg = format!("{err}");
        assert!(
            msg.contains("subnet is None despite mode = Netns"),
            "msg must name the contract violation: {msg}"
        );
        assert!(
            msg.contains("ghars bug"),
            "msg must flag it as a bug-shaped input: {msg}"
        );
    }
}
