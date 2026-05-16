use super::*;
use rstest::rstest;
use tempfile::TempDir;

use super::tests_a::egress;

#[test]
fn egress_comment_rejects_backslash() {
    // `\` inside an nft string literal is a quoting prefix; even
    // when balanced, it would smuggle escape sequences past the
    // operator's intent.
    let err = validate_egress_comment("escape\\here").expect_err("must reject");
    assert!(format!("{err}").contains("disallowed character"));
}

#[test]
fn egress_comment_rejects_shell_meta() {
    // nft files are loaded by `nft -f`, never by a shell — but
    // copy-pasted comments can end up in shell scripts the
    // operator wraps around ghars. Reject `$ ( ) ;` so a comment
    // that would survive the nft parser still can't smuggle a
    // command if grep'd into a shell context downstream.
    for c in ['$', '(', ')', ';', '`', '|', '&', '\n'] {
        let s = format!("hello{c}world");
        validate_egress_comment(&s)
            .err()
            .unwrap_or_else(|| panic!("must reject char {c:?}"));
    }
}

#[test]
fn egress_comment_accepts_plus_sign() {
    // `+` is in the allowlist alongside `-`; useful for human
    // comments like "8.8.8.8 + 8.8.4.4" or "primary+secondary".
    // It's harmless inside an nft string literal — the nft parser
    // treats `+` as a literal char in `comment "..."`. Pin
    // acceptance so a future tighten doesn't drop it without a
    // visible test failure.
    validate_egress_comment("a+b").unwrap();
    validate_egress_comment("primary+secondary").unwrap();
}

#[test]
fn egress_comment_rejects_non_ascii() {
    // `c.is_ascii_alphanumeric()` is the only `true` branch; any
    // non-ASCII letter (latin-1, accented, or multi-byte UTF-8)
    // is rejected. Pin one representative each: a multi-byte
    // codepoint and a 4-byte codepoint.
    validate_egress_comment("café").expect_err("multi-byte rejected");
    validate_egress_comment("🦀").expect_err("4-byte rejected");
}

#[test]
fn egress_comment_reports_first_offender() {
    // Multiple bad chars: the validator names the FIRST one and
    // its position. Don't silently coalesce — operator should fix
    // the leftmost offender first, then re-run.
    let err = validate_egress_comment("ok\"first;second").expect_err("must reject");
    let msg = format!("{err}");
    assert!(msg.contains("position 2"), "leftmost first: {msg}");
    assert!(msg.contains("'\"'"), "name `\"` not `;`: {msg}");
}

#[test]
fn egress_rule_rejects_unsafe_comment() {
    // SEC-30: validate_egress_rule plumbs the comment through
    // validate_egress_comment. End-to-end so a future refactor
    // that decouples them fails this test.
    let mut rule = egress("10.0.0.1", crate::config::PortSpec::Single(80));
    rule.comment = Some("bad\"quote".into());
    let err = validate_egress_rule(&rule).expect_err("must reject");
    assert!(format!("{err}").contains("disallowed character"));
}

#[test]
fn egress_rule_accepts_safe_comment() {
    // Positive path: a comment in the safe set passes through.
    let mut rule = egress("10.0.0.1", crate::config::PortSpec::Single(80));
    rule.comment = Some("squid proxy 8.8.8.8/32".into());
    validate_egress_rule(&rule).unwrap();
}

// ---- dns_mode -----------------------------------------------------

#[test]
fn dns_forward_accepted() {
    validate_dns_mode(&crate::config::DnsMode::Forward).unwrap();
}

#[test]
fn dns_static_accepts_one_server() {
    let dns = crate::config::DnsMode::Static {
        servers: vec!["1.1.1.1".parse().unwrap()],
    };
    validate_dns_mode(&dns).unwrap();
}

#[test]
fn dns_static_rejects_empty_servers() {
    let dns = crate::config::DnsMode::Static { servers: vec![] };
    let err = validate_dns_mode(&dns).expect_err("must reject empty");
    assert!(format!("{err}").contains("requires at least one server"));
}

// ---- network_spec -------------------------------------------------

fn netns_spec_with(
    allowed_egress: Vec<crate::config::EgressRule>,
    ip_allow: Vec<IpNet>,
) -> crate::config::NetworkSpec {
    crate::config::NetworkSpec {
        mode: crate::config::NetworkMode::Netns,
        allowed_egress,
        ip_allow,
        ip_deny: vec![],
        restrict_address_families: vec![],
        dns: crate::config::DnsMode::default(),
        ipv6: crate::config::Ipv6Mode::default(),
    }
}

#[test]
fn network_spec_netns_requires_egress_or_ip_allow() {
    let spec = netns_spec_with(vec![], vec![]);
    let err = validate_network_spec(&spec).expect_err("must reject empty");
    assert!(format!("{err}").contains("no allowed_egress and no ip_allow"));
}

#[test]
fn network_spec_netns_accepts_with_egress() {
    let spec = netns_spec_with(
        vec![egress(
            "192.168.2.84",
            crate::config::PortSpec::Single(3128),
        )],
        vec![],
    );
    validate_network_spec(&spec).unwrap();
}

#[test]
fn network_spec_netns_accepts_with_ip_allow() {
    let spec = netns_spec_with(vec![], vec!["192.168.2.84/32".parse::<IpNet>().unwrap()]);
    validate_network_spec(&spec).unwrap();
}

#[test]
fn network_spec_propagates_egress_rule_failures() {
    let spec = netns_spec_with(
        vec![egress("10.0.0.1", crate::config::PortSpec::Single(0))],
        vec![],
    );
    let err = validate_network_spec(&spec).expect_err("must reject port 0");
    assert!(format!("{err}").contains("port 0"));
}

#[test]
fn network_spec_propagates_dns_failures() {
    let mut spec = netns_spec_with(
        vec![egress("10.0.0.1", crate::config::PortSpec::Single(3128))],
        vec![],
    );
    spec.dns = crate::config::DnsMode::Static { servers: vec![] };
    let err = validate_network_spec(&spec).expect_err("must reject empty dns");
    assert!(format!("{err}").contains("requires at least one server"));
}

#[test]
fn network_spec_open_does_not_require_egress() {
    let spec = crate::config::NetworkSpec {
        mode: crate::config::NetworkMode::Open,
        allowed_egress: vec![],
        ip_allow: vec![],
        ip_deny: vec![],
        restrict_address_families: vec![],
        dns: crate::config::DnsMode::default(),
        ipv6: crate::config::Ipv6Mode::default(),
    };
    validate_network_spec(&spec).unwrap();
}

/// Open-mode `[network.NAME]` rejects `allowed_egress` because
/// nft rules are Netns-only — emitting them on Open mode would
/// silently fall through (no namespace, no nft rule emission)
/// and the operator would discover the gap by observing
/// unfiltered egress.
#[test]
fn network_spec_open_rejects_allowed_egress() {
    let spec = crate::config::NetworkSpec {
        mode: crate::config::NetworkMode::Open,
        allowed_egress: vec![egress("10.0.0.1", crate::config::PortSpec::Single(443))],
        ip_allow: vec![],
        ip_deny: vec![],
        restrict_address_families: vec![],
        dns: crate::config::DnsMode::default(),
        ipv6: crate::config::Ipv6Mode::default(),
    };
    let err = validate_network_spec(&spec).expect_err("must reject");
    let msg = format!("{err}");
    assert!(
        msg.contains("allowed_egress requires mode = netns"),
        "msg must name the rule: {msg}"
    );
}

/// Open-mode `[network.NAME]` rejects non-Forward `dns` because
/// the per-runner DNS policy applies inside the netns; Open-mode
/// runners inherit the host's `/etc/resolv.conf` and the field
/// would be silently ignored.
#[test]
fn network_spec_open_rejects_static_dns() {
    let spec = crate::config::NetworkSpec {
        mode: crate::config::NetworkMode::Open,
        allowed_egress: vec![],
        ip_allow: vec![],
        ip_deny: vec![],
        restrict_address_families: vec![],
        dns: crate::config::DnsMode::Static {
            servers: vec!["1.1.1.1".parse().unwrap()],
        },
        ipv6: crate::config::Ipv6Mode::default(),
    };
    let err = validate_network_spec(&spec).expect_err("must reject");
    let msg = format!("{err}");
    assert!(
        msg.contains("dns requires mode = netns"),
        "msg must name the rule: {msg}"
    );
}

/// Open-mode `[network.NAME]` rejects `ipv6 = Enabled` because
/// IPv6 ULA allocation is a Netns-mode artifact; Open-mode
/// runners share the host's IPv6 stack and no allocation
/// happens.
#[test]
fn network_spec_open_rejects_ipv6_enabled() {
    let spec = crate::config::NetworkSpec {
        mode: crate::config::NetworkMode::Open,
        allowed_egress: vec![],
        ip_allow: vec![],
        ip_deny: vec![],
        restrict_address_families: vec![],
        dns: crate::config::DnsMode::default(),
        ipv6: crate::config::Ipv6Mode::Enabled,
    };
    let err = validate_network_spec(&spec).expect_err("must reject");
    let msg = format!("{err}");
    assert!(
        msg.contains("ipv6 = enabled requires mode = netns"),
        "msg must name the rule: {msg}"
    );
}

/// Positive companion: Open-mode block with cgroup-BPF fields
/// (`ip_allow` / `ip_deny` / `restrict_address_families`) MUST
/// pass validation. These fields apply at the cgroup layer
/// regardless of namespace, so neither mode rejects them.
#[test]
fn network_spec_open_accepts_cgroup_bpf_fields() {
    let spec = crate::config::NetworkSpec {
        mode: crate::config::NetworkMode::Open,
        allowed_egress: vec![],
        ip_allow: vec!["10.0.0.0/8".parse::<IpNet>().unwrap()],
        ip_deny: vec!["0.0.0.0/0".parse::<IpNet>().unwrap()],
        restrict_address_families: vec!["AF_INET".into()],
        dns: crate::config::DnsMode::default(),
        ipv6: crate::config::Ipv6Mode::default(),
    };
    validate_network_spec(&spec).unwrap();
}

// ---- validate_restrict_address_families ---------------------------

/// AF_* tokens that systemd accepts must pass through. Pin
/// every common family to catch a regression that accidentally
/// rejects a legit token.
#[rstest]
#[case::unix("AF_UNIX")]
#[case::inet("AF_INET")]
#[case::inet6("AF_INET6")]
#[case::netlink("AF_NETLINK")]
#[case::packet("AF_PACKET")]
#[case::with_digit("AF_INET6")]
#[case::ieee802154("AF_IEEE802154")]
fn validate_restrict_address_families_accepts_valid(#[case] family: &str) {
    validate_restrict_address_families("network.restrict_address_families", &[family.into()])
        .expect("valid AF_* token must pass");
}

/// Tokens that don't match the AF_[A-Z0-9_]+ shape MUST reject:
/// lowercase forms (systemd is case-sensitive), missing prefix,
/// typos, stray punctuation, and `~`-prefix denylist tokens
/// (intrinsically rejected by the `^AF_` anchor — documents the
/// gap that prevents systemd's polarity-flip ambiguity for this
/// field; sister to `validate_extra_syscalls`' explicit `~`-prefix
/// check).
#[rstest]
#[case::lowercase("af_unix")]
#[case::mixed_case("Af_Unix")]
#[case::missing_prefix("INET")]
#[case::typo("AF_BOGUS TYPO")]
#[case::with_dash("AF-UNIX")]
#[case::with_dot("AF_UNIX.0")]
#[case::trailing_space("AF_UNIX ")]
#[case::leading_space(" AF_UNIX")]
#[case::tilde_prefix("~AF_UNIX")]
#[case::tilde_alone("~")]
fn validate_restrict_address_families_rejects_malformed(#[case] family: &str) {
    let err =
        validate_restrict_address_families("network.restrict_address_families", &[family.into()])
            .expect_err("malformed token must reject");
    let msg = format!("{err}");
    assert!(
        msg.contains("not a valid AF_* token"),
        "msg must name the violation: {msg}"
    );
    assert!(
        msg.contains("network.restrict_address_families"),
        "msg must name the offending field: {msg}"
    );
    // Defense-in-depth: the offending token is quoted so the
    // operator can find it in their TOML.
    assert!(
        msg.contains(&format!("{family:?}")),
        "msg must quote the offending token verbatim: {msg}"
    );
}

/// Empty entries are also rejected (a stray comma in TOML can
/// produce an empty string between commas).
#[test]
fn validate_restrict_address_families_rejects_empty_entry() {
    let err =
        validate_restrict_address_families("hardening.restrict_address_families", &[String::new()])
            .expect_err("empty entry must reject");
    let msg = format!("{err}");
    assert!(msg.contains("entry is empty"), "msg: {msg}");
    assert!(
        msg.contains("hardening.restrict_address_families"),
        "msg must name the field: {msg}"
    );
}

/// Empty list passes (Vec<String> default is empty; that's "no
/// restriction").
#[test]
fn validate_restrict_address_families_accepts_empty_list() {
    validate_restrict_address_families("hardening.restrict_address_families", &[]).unwrap();
}

/// Tokens longer than `AF_FAMILY_MAX_LEN` (32 bytes) reject,
/// even if the shape regex would otherwise accept them. Defense-
/// in-depth against operator-pasted nonsense; real AF_* tokens
/// are well under 32 bytes.
#[test]
fn validate_restrict_address_families_rejects_overlong() {
    // 33 bytes total: "AF_" + 30 'X' chars.
    let overlong = format!("AF_{}", "X".repeat(30));
    assert_eq!(overlong.len(), 33);
    let err = validate_restrict_address_families(
        "hardening.restrict_address_families",
        std::slice::from_ref(&overlong),
    )
    .expect_err("overlong token must reject");
    let msg = format!("{err}");
    assert!(msg.contains("33 bytes"), "msg must name length: {msg}");
    assert!(
        msg.contains(&format!("{overlong:?}")),
        "msg must quote bad token: {msg}"
    );
}

/// systemd EXCLUDES `AF_FILE`, `AF_LOCAL`, `AF_ROUTE` from its
/// `RestrictAddressFamilies=` parser. Operators who write these
/// see opaque "unknown family" errors at unit-load time. The
/// validator rejects with a "use the canonical X instead"
/// hint — pin each alias and the canonical replacement it points
/// at.
#[rstest]
#[case::af_file("AF_FILE", "AF_UNIX")]
#[case::af_local("AF_LOCAL", "AF_UNIX")]
#[case::af_route("AF_ROUTE", "AF_NETLINK")]
fn validate_restrict_address_families_rejects_systemd_excluded_alias(
    #[case] alias: &str,
    #[case] canonical: &str,
) {
    let err =
        validate_restrict_address_families("hardening.restrict_address_families", &[alias.into()])
            .expect_err("systemd-excluded alias must reject");
    let msg = format!("{err}");
    assert!(
        msg.contains("excluded by systemd"),
        "msg must name the systemd exclusion: {msg}"
    );
    assert!(
        msg.contains(&format!("{alias:?}")),
        "msg must quote the alias: {msg}"
    );
    assert!(
        msg.contains(&format!("{canonical:?}")),
        "msg must point at the canonical replacement: {msg}"
    );
}

/// Multi-entry list with one bad token rejects on the bad
/// token, naming it.
#[test]
fn validate_restrict_address_families_rejects_first_bad_entry() {
    let err = validate_restrict_address_families(
        "network.restrict_address_families",
        &["AF_UNIX".into(), "BOGUS".into(), "AF_INET".into()],
    )
    .expect_err("must reject");
    let msg = format!("{err}");
    assert!(msg.contains("\"BOGUS\""), "msg must name bad token: {msg}");
}

/// `network_spec_validates_restrict_address_families`: end-to-
/// end pin that `validate_network_spec` wires the AF_* check
/// through for both Netns and Open mode.
#[test]
fn network_spec_rejects_malformed_restrict_address_families() {
    // Netns mode + bad family entry.
    let spec = crate::config::NetworkSpec {
        mode: crate::config::NetworkMode::Netns,
        allowed_egress: vec![],
        ip_allow: vec!["10.0.0.0/8".parse::<IpNet>().unwrap()],
        ip_deny: vec![],
        restrict_address_families: vec!["AF_UNIX".into(), "af_bogus".into()],
        dns: crate::config::DnsMode::default(),
        ipv6: crate::config::Ipv6Mode::default(),
    };
    let err = validate_network_spec(&spec).expect_err("must reject");
    let msg = format!("{err}");
    assert!(
        msg.contains("not a valid AF_* token"),
        "Netns: msg must name violation: {msg}"
    );
    assert!(
        msg.contains("\"af_bogus\""),
        "Netns: msg must quote bad token: {msg}"
    );

    // Open mode + bad family entry. The mode-scoped gate lets
    // restrict_address_families through to Stage 2 per-rule
    // validation, where the AF_* check runs.
    let spec_open = crate::config::NetworkSpec {
        mode: crate::config::NetworkMode::Open,
        allowed_egress: vec![],
        ip_allow: vec![],
        ip_deny: vec![],
        restrict_address_families: vec!["AF_INET".into(), "INET6".into()],
        dns: crate::config::DnsMode::default(),
        ipv6: crate::config::Ipv6Mode::default(),
    };
    let err = validate_network_spec(&spec_open).expect_err("must reject");
    let msg = format!("{err}");
    assert!(
        msg.contains("not a valid AF_* token"),
        "Open: msg must name violation: {msg}"
    );
    assert!(
        msg.contains("\"INET6\""),
        "Open: msg must quote bad token: {msg}"
    );
}

// ---- extra_capabilities (SEC-01) ---------------------------------

#[rstest]
#[case::admin("CAP_SYS_ADMIN")]
#[case::ptrace("CAP_SYS_PTRACE")]
#[case::module("CAP_SYS_MODULE")]
#[case::rawio("CAP_SYS_RAWIO")]
#[case::netraw("CAP_NET_RAW")]
fn extra_capabilities_rejects_denied(#[case] cap: &str) {
    let err =
        validate_extra_capabilities(&[cap.to_string()]).expect_err("must reject denied capability");
    let msg = format!("{err}");
    assert!(msg.contains("denied"), "{msg}");
    assert!(msg.contains(cap), "{msg}");
}

/// Lowercase / mixed-case denied-cap variants still hit the
/// deny-list (validator uppercases trimmed before comparison).
/// Pure case variants — no surrounding whitespace — bypass the
/// raw != trimmed gate and reach the deny-list check.
#[rstest]
#[case("cap_sys_admin")]
#[case("Cap_Sys_Admin")]
fn extra_capabilities_case_insensitive_against_deny_list(#[case] cap: &str) {
    let err = validate_extra_capabilities(&[cap.to_string()])
        .expect_err("must reject denied cap regardless of case");
    let msg = format!("{err}");
    assert!(
        msg.contains("CAP_SYS_ADMIN") && msg.contains("denied"),
        "{msg}"
    );
}

/// Whitespace-padded tokens reject with the "surrounding
/// whitespace" message — fires the raw != trimmed gate BEFORE
/// the trim+uppercase+deny-list check. Defends the `spec_hash`
/// stability invariant: the renderer at
/// `units::render_hardening` emits the raw token verbatim,
/// so without this gate a whitespace-padded token would produce
/// different on-disk bytes (and a different `spec_hash`) from the
/// equivalent unpadded form, triggering a spurious in-place
/// `UpdateRunner` cascade across cosmetically-equivalent TOML.
#[rstest]
#[case::space_padded(" CAP_SYS_ADMIN ")]
#[case::leading_space(" CAP_NET_BIND_SERVICE")]
#[case::trailing_tab("CAP_CHOWN\t")]
fn extra_capabilities_rejects_whitespace_padded_tokens(#[case] cap: &str) {
    let err = validate_extra_capabilities(&[cap.to_string()])
        .expect_err("whitespace-padded token must reject");
    let msg = format!("{err}");
    assert!(
        msg.contains("surrounding whitespace"),
        "msg must name the whitespace violation: {msg}"
    );
    assert!(
        msg.contains("extra_capabilities"),
        "msg must name the field: {msg}"
    );
}

#[rstest]
#[case("CAP_NET_BIND_SERVICE")]
#[case("CAP_CHOWN")]
#[case("CAP_DAC_OVERRIDE")]
#[case("CAP_AUDIT_WRITE")]
fn extra_capabilities_accepts_safe(#[case] cap: &str) {
    validate_extra_capabilities(&[cap.to_string()]).expect("must accept benign cap");
}

#[test]
fn extra_capabilities_accepts_empty_list() {
    validate_extra_capabilities(&[]).unwrap();
}

#[test]
fn extra_capabilities_rejects_empty_entry() {
    let err = validate_extra_capabilities(&[String::new()]).expect_err("must reject empty token");
    assert!(format!("{err}").contains("empty"));
}

/// `~`-prefix denylist tokens are intrinsically rejected by
/// `CAP_RE`'s `^CAP_` anchor — documents the gap that prevents
/// systemd's polarity-flip ambiguity for this field; sister to
/// `validate_extra_syscalls`' explicit `~`-prefix check.
#[rstest]
#[case("not_a_cap")]
#[case("CAP-SYS-ADMIN")]
#[case("CAP_!@#")]
#[case("SYS_ADMIN")]
#[case("~CAP_NET_BIND_SERVICE")]
#[case("~")]
fn extra_capabilities_rejects_malformed(#[case] cap: &str) {
    let err = validate_extra_capabilities(&[cap.to_string()])
        .expect_err("must reject malformed cap token");
    assert!(format!("{err}").contains("not a CAP_*"));
}

#[test]
fn extra_capabilities_first_failure_short_circuits() {
    // First entry is benign, second is denied — ensure the function
    // does NOT silently accept the second by stopping at the first.
    let caps = vec!["CAP_CHOWN".into(), "CAP_SYS_ADMIN".into()];
    let err = validate_extra_capabilities(&caps).expect_err("must reject");
    assert!(format!("{err}").contains("CAP_SYS_ADMIN"));
}

// ---- extra_syscalls (SEC-01) -------------------------------------

/// Bare syscall identifiers — lowercase ASCII letters, digits,
/// underscore — that mirror real libseccomp registry names must
/// pass. Sample covers single-word, multi-word, leading-underscore,
/// and digit-suffix forms.
#[rstest]
#[case::read("read")]
#[case::openat("openat")]
#[case::clone3("clone3")]
#[case::mmap2("mmap2")]
#[case::leading_underscore("_llseek")]
#[case::epoll_create1("epoll_create1")]
#[case::pidfd_open("pidfd_open")]
#[case::io_uring_setup("io_uring_setup")]
#[case::landlock_restrict_self("landlock_restrict_self")]
#[case::clock_gettime64("clock_gettime64")]
fn extra_syscalls_accepts_bare_names(#[case] name: &str) {
    validate_extra_syscalls(&[name.into()]).expect("valid bare syscall name must pass");
}

/// Empty list (the default) passes — no override is a valid
/// state.
#[test]
fn extra_syscalls_accepts_empty_list() {
    validate_extra_syscalls(&[]).unwrap();
}

/// The primary SEC finding: a `~`-prefix token in the operator's
/// Vec would land at position 0 after `merge_hardening`'s lex sort
/// (ASCII `~` = 0x7E sorts AFTER all alphanumerics) and silently
/// flip systemd's `SystemCallFilter=` directive from allow-list to
/// deny-list. Every variant of the `~` prefix must reject at
/// config-load.
#[rstest]
#[case::tilde_alone("~")]
#[case::tilde_name("~read")]
#[case::tilde_group("~@system-service")]
#[case::double_tilde("~~read")]
#[case::tilde_space("~ read")]
fn extra_syscalls_rejects_tilde_prefix(#[case] token: &str) {
    let err = validate_extra_syscalls(&[token.into()]).expect_err("~-prefix token must reject");
    let msg = format!("{err}");
    assert!(
        msg.contains("starts with `~`"),
        "msg must name the ~ prefix: {msg}"
    );
    assert!(
        msg.contains("extra_syscalls"),
        "msg must name the field: {msg}"
    );
    assert!(
        msg.contains(&format!("{token:?}")),
        "msg must quote the offending token: {msg}"
    );
}

/// `@group` syntax is rejected. Granting `@privileged` would carry
/// CAP_SYS_ADMIN-equivalent syscalls, bypassing the SEC-01 deny-
/// list on `extra_capabilities`.
#[rstest]
#[case::privileged("@privileged")]
#[case::raw_io("@raw-io")]
#[case::basic_io("@basic-io")]
#[case::system_service("@system-service")]
fn extra_syscalls_rejects_at_prefix(#[case] token: &str) {
    let err = validate_extra_syscalls(&[token.into()]).expect_err("@-prefix token must reject");
    let msg = format!("{err}");
    assert!(
        msg.contains("starts with `@`"),
        "msg must name the @ prefix: {msg}"
    );
    assert!(
        msg.contains(&format!("{token:?}")),
        "msg must quote the offending token: {msg}"
    );
}

/// `name:errno` annotation is rejected on a bare syscall name.
/// systemd silently drops these in allow-list mode per
/// load-fragment.c:3287-3291. Test cases use bare-name `:errno`
/// forms only — `@group:errno` would hit the earlier `@`-prefix
/// check (`extra_syscalls_rejects_at_prefix`) and never reach
/// the `:` check, so it doesn't exercise this code path.
#[rstest]
#[case::mount_eperm("mount:EPERM")]
#[case::unshare_kill("unshare:KILL")]
#[case::read_errno("read:255")]
fn extra_syscalls_rejects_errno_suffix(#[case] token: &str) {
    let err = validate_extra_syscalls(&[token.into()]).expect_err(":errno token must reject");
    let msg = format!("{err}");
    assert!(
        msg.contains("contains `:`"),
        "msg must name the `:` violation: {msg}"
    );
}

/// Empty token rejects with "is empty". An empty string (e.g.,
/// from a stray comma in TOML producing an empty string between
/// commas in the resulting Vec) fires the `is_empty` branch
/// because raw == trimmed (both empty) — bypasses the raw !=
/// trimmed whitespace gate.
#[test]
fn extra_syscalls_rejects_empty_entry() {
    let err = validate_extra_syscalls(&[String::new()]).expect_err("empty token must reject");
    let msg = format!("{err}");
    assert!(msg.contains("is empty"), "msg must say empty: {msg}");
}

/// Whitespace-padded tokens reject with the "surrounding
/// whitespace" message. Defends the `spec_hash` stability
/// invariant: the renderer at `units::render_hardening`
/// emits the raw token verbatim, so without this gate a
/// whitespace-padded token would produce different on-disk bytes
/// (and a different `spec_hash`) from the equivalent unpadded form,
/// triggering a spurious in-place `UpdateRunner` cascade across
/// cosmetically-equivalent TOML. See doc-comment in `merge.rs`
/// `merge_hardening` (the canonicalization block) for the
/// byte-equality invariant chain.
#[rstest]
#[case::space_only(" ")]
#[case::tab_only("\t")]
#[case::multiple_spaces("   ")]
#[case::leading_space(" read")]
#[case::trailing_space("read ")]
#[case::padded("  read  ")]
#[case::tab_padded("\tread\t")]
fn extra_syscalls_rejects_whitespace_padded_tokens(#[case] token: &str) {
    let err =
        validate_extra_syscalls(&[token.into()]).expect_err("whitespace-padded token must reject");
    let msg = format!("{err}");
    assert!(
        msg.contains("surrounding whitespace"),
        "msg must name the whitespace violation: {msg}"
    );
    assert!(
        msg.contains("extra_syscalls"),
        "msg must name the field: {msg}"
    );
}

/// Tokens with embedded newlines, control chars, comment markers,
/// or systemd-directive separators must reject — these would
/// either split into multiple tokens at systemd's parser or
/// inject a new directive line at unit-load time.
#[rstest]
#[case::newline("read\nDeleteMe=")]
#[case::carriage_return("read\r\nKillMode=process")]
#[case::comment_hash("#read")]
#[case::comment_semi(";read")]
#[case::equals("read=foo")]
#[case::embedded_space("read foo")]
#[case::uppercase("Read")]
#[case::dash("read-now")]
#[case::leading_digit("9read")]
#[case::asterisk("open*")]
#[case::accented("réad")]
fn extra_syscalls_rejects_malformed_shape(#[case] token: &str) {
    let err =
        validate_extra_syscalls(&[token.into()]).expect_err("malformed-shape token must reject");
    let msg = format!("{err}");
    assert!(
        msg.contains("not a valid syscall name"),
        "msg must name shape violation: {msg}"
    );
    assert!(
        msg.contains(&format!("{token:?}")) || msg.contains(token.trim()),
        "msg must quote the offending token: {msg}"
    );
}

/// Tokens beyond `SYSCALL_NAME_MAX_LEN` (64 bytes) reject, naming
/// the actual byte count. Defense-in-depth against operator-
/// pasted nonsense; real syscall names top out under 25 bytes.
#[test]
fn extra_syscalls_rejects_overlong() {
    // 65 bytes: 'a' repeated.
    let overlong = "a".repeat(65);
    assert_eq!(overlong.len(), 65);
    let err = validate_extra_syscalls(std::slice::from_ref(&overlong))
        .expect_err("overlong token must reject");
    let msg = format!("{err}");
    assert!(msg.contains("65 bytes"), "msg must name length: {msg}");
    assert!(
        msg.contains(&format!("{overlong:?}")),
        "msg must quote the bad token: {msg}"
    );
}

/// Token of exactly `SYSCALL_NAME_MAX_LEN` (64 bytes) MUST accept.
/// Boundary case — off-by-one in the length check would silently
/// reject a 64-byte token that the cap permits.
#[test]
fn extra_syscalls_accepts_at_max_length() {
    // 64 bytes: 'a' repeated.
    let at_max = "a".repeat(64);
    assert_eq!(at_max.len(), 64);
    validate_extra_syscalls(std::slice::from_ref(&at_max))
        .expect("token at max length must accept");
}

/// Multi-entry list with one bad token rejects on the bad token,
/// short-circuiting on the first failure. Pins that the validator
/// does NOT silently accept later entries by stopping at the
/// first.
#[test]
fn extra_syscalls_first_failure_short_circuits() {
    let syscalls = vec!["read".into(), "~mount".into(), "openat".into()];
    let err = validate_extra_syscalls(&syscalls).expect_err("must reject");
    let msg = format!("{err}");
    assert!(msg.contains("\"~mount\""), "msg must name bad token: {msg}");
}

// ---- extra_bind_paths (SEC-01) -----------------------------------

#[rstest]
#[case("/proc/sys")]
#[case("/proc/sys/")]
#[case("/proc/sys/net/ipv4")]
#[case("/sys/kernel/security")]
#[case("/sys/kernel/security/apparmor")]
#[case("/proc/sysrq-trigger")]
#[case("/dev/kmem")]
#[case("/dev/mem")]
fn extra_bind_paths_rejects_denied(#[case] p: &str) {
    let paths = vec![camino::Utf8PathBuf::from(p)];
    let err = validate_extra_bind_paths(&paths).expect_err("must reject denied path");
    let msg = format!("{err}");
    assert!(msg.contains("denied") && msg.contains("SEC-01"), "{msg}");
}

#[rstest]
#[case("/etc/pki/ca-trust/source/anchors/ca.pem")]
#[case("/opt/gha/extra")]
#[case("/var/cache/sccache")]
#[case("/srv/share/ro")]
fn extra_bind_paths_accepts_safe(#[case] p: &str) {
    let paths = vec![camino::Utf8PathBuf::from(p)];
    validate_extra_bind_paths(&paths).expect("must accept benign path");
}

#[test]
fn extra_bind_paths_does_not_substring_match() {
    // `/dev/memfoo` should NOT match `/dev/mem` — component-prefix only.
    let paths = vec![camino::Utf8PathBuf::from("/dev/memfoo")];
    validate_extra_bind_paths(&paths).expect("must not substring-match");
}

#[test]
fn extra_bind_paths_rejects_relative() {
    let paths = vec![camino::Utf8PathBuf::from("etc/foo")];
    let err = validate_extra_bind_paths(&paths).expect_err("must reject relative path");
    assert!(format!("{err}").contains("absolute"));
}

#[test]
fn extra_bind_paths_rejects_empty_entry() {
    let paths = vec![camino::Utf8PathBuf::from("")];
    let err = validate_extra_bind_paths(&paths).expect_err("must reject empty path");
    assert!(format!("{err}").contains("empty"));
}

#[test]
fn extra_bind_paths_accepts_empty_list() {
    validate_extra_bind_paths(&[]).unwrap();
}

// ---- hook_script (SEC-12) ----------------------------------------

/// Detect whether the test process is root WITHOUT calling unsafe.
/// `unsafe_code = "forbid"` overrides any `#[allow(unsafe_code)]`
/// (the lint level can only widen). `/proc/self` is owned by the
/// task's real UID on Linux.
fn running_as_root() -> bool {
    std::fs::metadata("/proc/self")
        .map(|m| m.uid() == 0)
        .unwrap_or(false)
}

fn mk_hook(dir: &TempDir, name: &str, content: &[u8], mode: u32) -> camino::Utf8PathBuf {
    use std::io::Write;
    use std::os::unix::fs::PermissionsExt;
    let path = dir.path().join(name);
    let mut f = std::fs::File::create(&path).unwrap();
    f.write_all(content).unwrap();
    let mut perms = f.metadata().unwrap().permissions();
    perms.set_mode(mode);
    f.set_permissions(perms).unwrap();
    camino::Utf8PathBuf::from_path_buf(path).unwrap()
}

#[test]
fn hook_script_rejects_missing() {
    let p = camino::Utf8PathBuf::from("/nonexistent/ghars/test/hook.sh");
    let err = validate_hook_script(&p).expect_err("must reject missing");
    // open(2) fails with ENOENT — the new error path goes through
    // open_no_follow_with_meta, which surfaces "open failed".
    let msg = format!("{err}");
    assert!(
        msg.contains("open failed") && msg.contains("SEC-12"),
        "{msg}"
    );
}

#[test]
fn hook_script_rejects_symlink() {
    let dir = TempDir::new().unwrap();
    let target = mk_hook(&dir, "real.sh", b"#!/bin/sh\nexit 0\n", 0o755);
    let link_path = dir.path().join("link.sh");
    std::os::unix::fs::symlink(target.as_std_path(), &link_path).unwrap();
    let link = camino::Utf8PathBuf::from_path_buf(link_path).unwrap();
    let err = validate_hook_script(&link).expect_err("must reject symlink");
    // The new O_NOFOLLOW path returns ELOOP from open(2). The
    // hint string in the Validation error mentions "symlink"; the
    // message contains "open failed". Either match confirms the
    // SEC-12 rejection is on the symlink path.
    let msg = format!("{err}");
    assert!(msg.contains("symlink") && msg.contains("SEC-12"), "{msg}");
}

#[test]
fn hook_script_rejects_directory() {
    let dir = TempDir::new().unwrap();
    let sub = dir.path().join("subdir");
    std::fs::create_dir(&sub).unwrap();
    let p = camino::Utf8PathBuf::from_path_buf(sub).unwrap();
    let err = validate_hook_script(&p).expect_err("must reject directory");
    // Directories ARE openable for read on Linux (the resulting fd
    // can be fstat'd, getdents'd, etc.). open() succeeds; the
    // "not a regular file" check fires on the metadata.
    assert!(format!("{err}").contains("regular file"));
}

/// FIFO at the hook-script path. Sister test to
/// `runner_tarball_rejects_fifo` and `prefix_rejects_fifo`. The
/// shared `open_no_follow_with_meta` helper sets `O_NONBLOCK`,
/// so opening the FIFO returns an fd without blocking on a
/// writer; the `is_file()` gate in `validate_hook_script` then
/// rejects it. The FIFO is rejected before the
/// owner-execute / uid checks fire, so this test does not need
/// a root-DAC bypass — exactly the same pattern as
/// `hook_script_rejects_directory` above (which also exercises
/// the file-type gate without root).
#[test]
fn hook_script_rejects_fifo() {
    use nix::sys::stat::Mode;
    use nix::unistd::mkfifo;
    let dir = TempDir::new().unwrap();
    let fifo_path = dir.path().join("hook.fifo");
    mkfifo(&fifo_path, Mode::S_IRUSR | Mode::S_IWUSR).unwrap();
    let p = camino::Utf8PathBuf::from_path_buf(fifo_path).unwrap();
    let err = validate_hook_script(&p).expect_err("FIFO must reject");
    let msg = format!("{err}");
    assert!(
        msg.contains("regular file"),
        "FIFO rejection must surface via the not-a-regular-file \
         branch so the operator knows the file type is wrong; \
         got: {msg}"
    );
}

#[test]
fn hook_script_rejects_relative_path() {
    let p = camino::Utf8PathBuf::from("etc/hooks/pre.sh");
    let err = validate_hook_script(&p).expect_err("must reject relative");
    let msg = format!("{err}");
    assert!(
        msg.contains("not absolute") && msg.contains("SEC-12"),
        "{msg}"
    );
}

#[test]
fn hook_script_rejects_no_owner_exec_bit() {
    let dir = TempDir::new().unwrap();
    // 0o644: rw-r--r--, no owner-exec.
    let p = mk_hook(&dir, "noexec.sh", b"#!/bin/sh\nexit 0\n", 0o644);
    let err = validate_hook_script(&p).expect_err("must reject without owner-exec");
    let msg = format!("{err}");
    // Either the missing-x check fires (when running as root, so
    // owner=0 is satisfied) or the uid check (when not running as
    // root). Both are valid SEC-12 rejections — the field-name in
    // the message ("owner-execute" vs "uid") confirms which.
    assert!(
        msg.contains("owner-execute") || msg.contains("uid"),
        "{msg}",
    );
}

#[test]
fn hook_script_rejects_non_root_owner_when_executable() {
    if running_as_root() {
        // Test irrelevant when running as root — the file we create
        // would be owned by uid 0 and pass.
        return;
    }
    let dir = TempDir::new().unwrap();
    // Owner-exec is set, but the test process is not root, so the
    // UID check fires.
    let p = mk_hook(&dir, "owned.sh", b"#!/bin/sh\nexit 0\n", 0o755);
    let err = validate_hook_script(&p).expect_err("must reject non-root owned");
    let msg = format!("{err}");
    assert!(msg.contains("uid") && msg.contains("SEC-12"), "{msg}");
}

#[test]
fn hook_script_accepts_when_root_owned_and_executable() {
    if !running_as_root() {
        // Cannot create a uid=0 file as a non-root user.
        return;
    }
    let dir = TempDir::new().unwrap();
    let p = mk_hook(&dir, "good.sh", b"#!/bin/sh\nexit 0\n", 0o700);
    validate_hook_script(&p).expect("root + 0700 + non-symlink must pass");
}

#[test]
fn hook_script_rejects_world_writable() {
    // SEC-12 hardening: a world-writable hook script (mode &
    // 0o002 != 0) lets any local user rewrite the script body.
    // The root-owned-script check above is moot if the runner
    // user can chmod its content. We must reject before the
    // unit's hook ExecStart= reads the file.
    if !running_as_root() {
        // The function rejects on uid != 0 first; we'd never
        // reach the mode check.
        return;
    }
    let dir = TempDir::new().unwrap();
    let p = mk_hook(&dir, "ww.sh", b"#!/bin/sh\nexit 0\n", 0o707);
    let err = validate_hook_script(&p).expect_err("world-writable hook script must be rejected");
    let msg = format!("{err}");
    assert!(
        msg.contains("group/world-writable") && msg.contains("SEC-12"),
        "expected world-writable rejection message; got {msg}"
    );
}

#[test]
fn hook_script_rejects_group_writable() {
    // Group-writable (0o020) is the same trust break as
    // world-writable: any member of the file's group can
    // rewrite the body. SEC-12 demands owner-only mutation.
    if !running_as_root() {
        return;
    }
    let dir = TempDir::new().unwrap();
    let p = mk_hook(&dir, "gw.sh", b"#!/bin/sh\nexit 0\n", 0o770);
    let err = validate_hook_script(&p).expect_err("group-writable hook script must be rejected");
    let msg = format!("{err}");
    assert!(
        msg.contains("group/world-writable"),
        "expected group-writable rejection message; got {msg}"
    );
}

#[test]
fn hook_script_rejects_mode_0777_explicitly() {
    // The audit finding cites "mode 0777 passes" as the
    // regression baseline. Pin: 0777 must NOT pass under the
    // new rule.
    if !running_as_root() {
        return;
    }
    let dir = TempDir::new().unwrap();
    let p = mk_hook(&dir, "777.sh", b"#!/bin/sh\nexit 0\n", 0o777);
    let err = validate_hook_script(&p).expect_err("mode 0777 hook script must be rejected");
    let msg = format!("{err}");
    assert!(msg.contains("group/world-writable"), "{msg}");
}

#[test]
fn hook_script_accepts_owner_writable_only() {
    // 0700 passes the root-owned check above and the new
    // group/world-write check (the bits below 0o100 are zero).
    // 0o755 (group/world readable, NOT writable) also passes —
    // owner-write is fine; only group/world-WRITE is forbidden.
    if !running_as_root() {
        return;
    }
    let dir = TempDir::new().unwrap();
    let p = mk_hook(&dir, "ok.sh", b"#!/bin/sh\nexit 0\n", 0o755);
    validate_hook_script(&p).expect("0755 (g/w readable + executable, NOT writable) must pass");
}

#[test]
fn hook_script_rejects_root_parented_absolute_path() {
    // SEC-12 hardening: a hook at `/foo.sh` would have parent
    // `/`, and the renderer's `BindReadOnlyPaths=<parent>`
    // line would mount the entire host into the runner
    // sandbox. Reject pre-render so the operator gets a clear
    // remediation hint pointing at "use a subdirectory".
    // Construct a concrete path under /tmp first to verify the
    // file-existence checks don't reject it before we get to
    // the parent-check, then re-route via a /-parent string.
    let path = camino::Utf8PathBuf::from("/foo.sh");
    let err = validate_hook_script(&path).expect_err("hook with parent=`/` must be rejected");
    let msg = format!("{err}");
    assert!(
        msg.contains("resolves to filesystem root") && msg.contains("SEC-12"),
        "expected root-parent rejection; got {msg}"
    );
}

#[test]
fn hook_script_rejects_parent_dir_climb_root() {
    let path = camino::Utf8PathBuf::from("/foo/../bar.sh");
    let err =
        validate_hook_script(&path).expect_err("hook with root-equivalent parent must be rejected");
    let msg = format!("{err}");
    assert!(
        msg.contains("resolves to filesystem root") && msg.contains("SEC-12"),
        "expected root-parent rejection for /foo/../bar.sh; got {msg}"
    );
}

#[test]
fn hook_script_rejects_dot_root_parent() {
    let path = camino::Utf8PathBuf::from("/./foo.sh");
    let err = validate_hook_script(&path).expect_err("hook with /. parent must be rejected");
    let msg = format!("{err}");
    assert!(
        msg.contains("resolves to filesystem root") && msg.contains("SEC-12"),
        "expected root-parent rejection for /./foo.sh; got {msg}"
    );
}

#[test]
fn hook_script_accepts_subdir_parented_path() {
    // Positive control: the same script body under a real
    // subdirectory passes the new parent check (assuming root
    // ownership + correct mode). When not running as root, the
    // validator rejects on uid != 0 first; we just verify the
    // root-parent check is NOT what fires.
    let dir = TempDir::new().unwrap();
    let p = mk_hook(&dir, "ok.sh", b"#!/bin/sh\nexit 0\n", 0o700);
    // The temp dir parent path is `/tmp/...` (not `/`), so
    // the parent check passes. Subsequent checks may reject
    // (uid != 0 when not root), but that's fine — we just
    // assert the root-parent message does NOT appear.
    let result = validate_hook_script(&p);
    if let Err(err) = &result {
        let msg = format!("{err}");
        assert!(
            !msg.contains("resolves to filesystem root"),
            "subdir-parented path must NOT trigger root-parent rejection; got {msg}"
        );
    }
}

// ---- expanded SEC-01 path denylist -------------------------------

#[rstest]
#[case::kmsg("/dev/kmsg")]
#[case::kallsyms("/dev/kallsyms")]
#[case::kcore("/proc/kcore")]
fn extra_bind_paths_rejects_new_denied_static(#[case] p: &str) {
    let paths = vec![camino::Utf8PathBuf::from(p)];
    let err = validate_extra_bind_paths(&paths).expect_err("must reject expanded deny entry");
    let msg = format!("{err}");
    assert!(msg.contains("denied") && msg.contains("SEC-01"), "{msg}");
    assert!(msg.contains(p), "error must name the offending path: {msg}");
}

#[rstest]
#[case::pid_exact("/proc/1")]
#[case::pid_trailing_slash("/proc/1/")]
#[case::pid_subdir("/proc/1/cmdline")]
#[case::pid_long("/proc/123456")]
#[case::pid_subdir_long("/proc/4242/maps")]
fn extra_bind_paths_rejects_per_pid_procfs(#[case] p: &str) {
    let paths = vec![camino::Utf8PathBuf::from(p)];
    let err = validate_extra_bind_paths(&paths).expect_err("must reject /proc/<pid>");
    let msg = format!("{err}");
    assert!(
        msg.contains("per-PID procfs") && msg.contains("SEC-01"),
        "{msg}"
    );
}

#[rstest]
#[case::sys_below_proc("/proc/sys/net/ipv4/ip_forward")]
#[case::nondigit_after_proc("/proc/self/maps")]
#[case::nondigit_at_proc_root("/proc/cpuinfo")]
#[case::not_proc_at_all("/procmon/data")]
#[case::pid_with_trailing_alpha("/proc/12abc")]
fn extra_bind_paths_per_pid_regex_does_not_overmatch(#[case] p: &str) {
    // None of these is a per-PID match. /proc/sys/... fires the
    // static deny entry; /proc/self, /proc/cpuinfo, /procmon, and
    // /proc/12abc must NOT trip the per-PID regex.
    let paths = vec![camino::Utf8PathBuf::from(p)];
    let result = validate_extra_bind_paths(&paths);
    if let Err(e) = &result {
        let msg = format!("{e}");
        assert!(
            !msg.contains("per-PID procfs"),
            "per-PID regex over-matched {p:?}: {msg}",
        );
    }
}

#[test]
fn open_no_follow_with_meta_rejects_symlink_with_eloop() {
    let dir = TempDir::new().unwrap();
    let target = dir.path().join("real");
    std::fs::write(&target, b"x").unwrap();
    let link = dir.path().join("link");
    std::os::unix::fs::symlink(&target, &link).unwrap();
    let err = open_no_follow_with_meta(&link).expect_err("must reject symlink");
    // ELOOP is the documented kernel return for O_NOFOLLOW + symlink.
    // Confirm the helper surfaces it as raw_os_error so callers can
    // branch (e.g. auth's symlink-specific hint).
    assert_eq!(err.raw_os_error(), Some(libc::ELOOP));
}

#[test]
fn open_no_follow_with_meta_returns_metadata_for_real_file() {
    let dir = TempDir::new().unwrap();
    let path = dir.path().join("real");
    std::fs::write(&path, b"hello").unwrap();
    let (file, meta) = open_no_follow_with_meta(&path).expect("real file opens");
    assert!(meta.file_type().is_file());
    assert_eq!(meta.len(), 5);
    // File handle is usable: read it back.
    use std::io::Read as _;
    let mut buf = String::new();
    let mut f = file;
    f.read_to_string(&mut buf).unwrap();
    assert_eq!(buf, "hello");
}
