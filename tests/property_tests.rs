//! Property tests for validators.rs and `systemd::render_nft_rules`.
//!
//! Default 256 cases per proptest macro (the proptest crate's default —
//! `ProptestConfig::cases`). When run with `PROPTEST_CASES=4096` (or the
//! nightly CI matrix), the count escalates without code changes.
//!
//! Why integration-test layer: `validate_runner_name`, `validate_url`,
//! `validate_memory_max`, and `render_nft_rules` are all `pub` on the
//! `ghars` crate. Internal property tests would have to be inside
//! `#[cfg(test)]` modules, but cargo-mutants and the existing test
//! plumbing prefer integration tests for properties so they run during
//! `cargo nextest run` without polluting the in-tree test count.
//!
//! Each property follows the form: generate input → exercise function →
//! assert invariant. Strategies are derived from the production regex
//! (validators.rs `IDENTIFIER_REGEX`, `URL_RE`, `MEMORY_MAX_RE`) so positive
//! cases by construction satisfy the regex; negative cases use a
//! generator that includes the rejection charset.

#![allow(clippy::unwrap_used, clippy::expect_used)]

use camino::Utf8PathBuf;
use ghars::config::{
    EffectiveNetworkBinding, EgressRule, IDENTIFIER_MAX_LEN, NetworkMode, NetworkSpec, PortSpec,
    Proto,
};
use ghars::netns::{host_veth_name, runner_veth_name};
use ghars::systemd::render_nft_rules;
use ghars::validators::{
    IFNAMSIZ, NETNS_RUNNER_NAME_MAX_LEN, validate_egress_comment, validate_memory_max,
    validate_runner_name, validate_url,
};
use ipnet::IpNet;
use proptest::prelude::*;

// --- validate_runner_name ---------------------------------------------

/// Build strings that satisfy `IDENTIFIER_REGEX = ^[a-z]([a-z0-9-]*[a-z0-9])?$`
/// AND the `IDENTIFIER_MAX_LEN` length cap.
///
/// Construction:
/// - First char ∈ `[a-z]`.
/// - Optional middle: `0..=(IDENTIFIER_MAX_LEN` - 2) chars from `[a-z0-9-]`.
/// - Last char (when length ≥ 2) ∈ `[a-z0-9]`.
///
/// Length cap = `IDENTIFIER_MAX_LEN`. Max middle = `IDENTIFIER_MAX_LEN - 2`.
fn valid_runner_name() -> impl Strategy<Value = String> {
    let middle_chars: Vec<char> = "abcdefghijklmnopqrstuvwxyz0123456789-".chars().collect();
    let first_chars: Vec<char> = "abcdefghijklmnopqrstuvwxyz".chars().collect();
    let last_chars: Vec<char> = "abcdefghijklmnopqrstuvwxyz0123456789".chars().collect();

    // Single-char branch: just a first-char letter. Clone first_chars
    // into the closure so multi can also `select` from it.
    let first_for_single = first_chars.clone();
    let single = (0..first_chars.len()).prop_map(move |i| first_for_single[i].to_string());

    // Multi-char branch: first + middle (0..=IDENTIFIER_MAX_LEN-2) + last.
    let max_middle = IDENTIFIER_MAX_LEN - 2;
    let multi = (
        proptest::sample::select(first_chars),
        proptest::collection::vec(proptest::sample::select(middle_chars), 0..=max_middle),
        proptest::sample::select(last_chars),
    )
        .prop_map(|(f, mid, l)| {
            let mut s = String::with_capacity(2 + mid.len());
            s.push(f);
            for c in mid {
                s.push(c);
            }
            s.push(l);
            s
        });

    prop_oneof![single, multi]
}

proptest! {
    #[test]
    fn runner_name_accepts_arbitrary_valid_identifier(name in valid_runner_name()) {
        // Length constraint: generator caps at 1 + (IDENTIFIER_MAX_LEN-2) + 1
        // = IDENTIFIER_MAX_LEN per the identifier-shape cap.
        prop_assert!(!name.is_empty() && name.len() <= IDENTIFIER_MAX_LEN);
        validate_runner_name(&name).map_err(|e| {
            TestCaseError::fail(format!(
                "valid identifier {name:?} rejected: {e}"
            ))
        })?;
    }

    /// Names with at least one ASCII uppercase letter are NEVER valid
    /// identifiers — the regex anchors `[a-z]` at start and `[a-z0-9-]`
    /// throughout. Inserting an uppercase ASCII letter at any position
    /// must reject. Use `\\PC` (no control) ASCII-uppercase classes.
    #[test]
    fn runner_name_rejects_any_uppercase_letter(
        // 1..=64 char string with at least one uppercase letter.
        // Max length = 33 + 1 + 30 = 64 = IDENTIFIER_MAX_LEN, so the
        // at-cap boundary is exercised.
        prefix in "[a-z]{0,33}",
        upper in "[A-Z]",
        suffix in "[a-z0-9-]{0,30}",
    ) {
        let name = format!("{prefix}{upper}{suffix}");
        if name.is_empty() || name.len() > IDENTIFIER_MAX_LEN {
            return Ok(());
        }
        let result = validate_runner_name(&name);
        prop_assert!(
            result.is_err(),
            "uppercase {upper:?} in {name:?} must reject"
        );
    }

    /// Special chars outside `[a-z0-9-]` must reject anywhere in the
    /// string. Includes underscores, dots, slashes, etc. — Python tool
    /// rejected these explicitly (`runner_x`, `runner.x`, `runner/x`).
    #[test]
    fn runner_name_rejects_special_chars(
        // Generator: prefix + special + suffix with at least one
        // non-[a-z0-9-] ASCII printable char.
        prefix in "[a-z]{0,16}",
        special in r"[_./@!#$%^&*+=,;:`'\\\| \t]",
        suffix in "[a-z0-9-]{0,16}",
    ) {
        let name = format!("{prefix}{special}{suffix}");
        if name.is_empty() {
            return Ok(());
        }
        let result = validate_runner_name(&name);
        prop_assert!(
            result.is_err(),
            "special char in {name:?} must reject"
        );
    }
}

// --- validate_url -----------------------------------------------------

/// Build well-formed `https://github.com/OWNER[/REPO][.git][/]` URLs.
/// OWNER and REPO each: first char ∈ `[A-Za-z0-9]`, rest ∈
/// `[A-Za-z0-9._-]`, length 1..32. Optional `.git` suffix and trailing
/// `/`.
fn valid_github_url() -> impl Strategy<Value = String> {
    let owner_first = "[A-Za-z0-9]";
    let owner_rest = "[A-Za-z0-9._-]{0,30}";
    let repo_first = "[A-Za-z0-9]";
    let repo_rest = "[A-Za-z0-9._-]{0,30}";

    let owner_only = (owner_first, owner_rest, prop_oneof![Just(""), Just(".git")])
        .prop_map(|(f, r, suffix)| format!("https://github.com/{f}{r}{suffix}"));

    let owner_repo = (
        owner_first,
        owner_rest,
        repo_first,
        repo_rest,
        prop_oneof![Just(""), Just(".git")],
        prop_oneof![Just(""), Just("/")],
    )
        .prop_map(|(of, or, rf, rr, s, t)| format!("https://github.com/{of}{or}/{rf}{rr}{s}{t}"));

    prop_oneof![owner_only, owner_repo]
}

proptest! {
    #[test]
    fn url_accepts_arbitrary_well_formed_github_url(u in valid_github_url()) {
        validate_url(&u).map_err(|e| {
            TestCaseError::fail(format!("valid URL {u:?} rejected: {e}"))
        })?;
    }

    /// Replacing `https://github.com` with `http://github.com` must
    /// reject — non-https schemes are forbidden (Python parity).
    #[test]
    fn url_rejects_http_scheme_for_otherwise_valid_url(u in valid_github_url()) {
        let attacker = u.replacen("https://", "http://", 1);
        let result = validate_url(&attacker);
        prop_assert!(
            result.is_err(),
            "http:// must reject regardless of path: {attacker:?}"
        );
    }

    /// Replacing `github.com` with `gitlab.com` must reject — host is
    /// pinned to github.com (Python parity: wrong-host).
    #[test]
    fn url_rejects_wrong_host_for_otherwise_valid_path(u in valid_github_url()) {
        let attacker = u.replacen("github.com", "gitlab.com", 1);
        let result = validate_url(&attacker);
        prop_assert!(
            result.is_err(),
            "gitlab.com must reject: {attacker:?}"
        );
    }

    /// Appending `?foo=bar` (query string) must reject any otherwise-
    /// valid URL.
    #[test]
    fn url_rejects_query_string_appended(u in valid_github_url()) {
        let attacker = format!("{u}?foo=bar");
        let result = validate_url(&attacker);
        prop_assert!(
            result.is_err(),
            "query string must reject: {attacker:?}"
        );
    }

    /// Appending `#frag` must reject any otherwise-valid URL.
    #[test]
    fn url_rejects_fragment_appended(u in valid_github_url()) {
        let attacker = format!("{u}#frag");
        let result = validate_url(&attacker);
        prop_assert!(
            result.is_err(),
            "fragment must reject: {attacker:?}"
        );
    }
}

// --- validate_memory_max --------------------------------------------------

/// Build `MemoryMax=` values the validator must accept:
/// - empty string,
/// - `<integer>[K|M|G|T]`, integer `1..=u32::MAX`,
/// - `<N>%`, N ∈ 1..=100,
/// - `infinity`.
fn valid_memory_max() -> impl Strategy<Value = String> {
    let empty = Just(String::new());
    let infinity = Just(String::from("infinity"));
    let integer = (
        0u32..=999_999u32,
        prop_oneof![Just(""), Just("K"), Just("M"), Just("G"), Just("T")],
    )
        .prop_map(|(n, suffix)| format!("{n}{suffix}"));
    let percent = (1u32..=100u32).prop_map(|n| format!("{n}%"));
    prop_oneof![empty, infinity, integer, percent]
}

proptest! {
    #[test]
    fn memory_max_accepts_arbitrary_well_formed_value(m in valid_memory_max()) {
        validate_memory_max(&m).map_err(|e| {
            TestCaseError::fail(format!("valid memory_max {m:?} rejected: {e}"))
        })?;
    }

    /// Decimals (`1.5G`) must reject — Python parity (only integers).
    #[test]
    fn memory_max_rejects_decimal(
        whole in 0u32..1024u32,
        frac in 1u32..1000u32,
        suffix in prop_oneof![Just("K"), Just("M"), Just("G"), Just("T")],
    ) {
        let m = format!("{whole}.{frac}{suffix}");
        let result = validate_memory_max(&m);
        prop_assert!(result.is_err(), "decimal {m:?} must reject");
    }

    /// Lowercase `infinity` is the only accepted form; uppercase /
    /// mixed case must reject.
    #[test]
    fn memory_max_rejects_non_canonical_infinity_case(
        idx in 0usize..255,
    ) {
        // Variants with at least one uppercase char.
        let variants = [
            "INFINITY", "Infinity", "InFiNiTy", "infinitY", "iNfinity", "INF",
        ];
        let pick = &variants[idx % variants.len()];
        let result = validate_memory_max(pick);
        prop_assert!(result.is_err(), "{pick:?} must reject");
    }

    /// `<N>%` outside 1..=100 must reject (0% and 101%+).
    #[test]
    fn memory_max_rejects_out_of_range_percent(n in prop_oneof![Just(0u32), 101u32..1000u32]) {
        let m = format!("{n}%");
        let result = validate_memory_max(&m);
        prop_assert!(result.is_err(), "{m:?} must reject");
    }
}

// --- render_nft_rules property tests --------------------------------------

/// Build identifier-shape strings bounded to
/// `NETNS_RUNNER_NAME_MAX_LEN`. The nft generator (and the
/// `_netns-{setup,teardown,veth}` helpers) gates on this tighter cap
/// because the rendered veth name `"ghars-{name}-h"` must fit
/// `IFNAMSIZ - 1 = 15` bytes. Property tests that feed names through
/// `render_nft_rules` MUST use this strategy — a name beyond 7 chars
/// triggers the defense-in-depth cap and the property assertion
/// fails.
fn valid_netns_runner_name() -> impl Strategy<Value = String> {
    let middle_chars: Vec<char> = "abcdefghijklmnopqrstuvwxyz0123456789-".chars().collect();
    let first_chars: Vec<char> = "abcdefghijklmnopqrstuvwxyz".chars().collect();
    let last_chars: Vec<char> = "abcdefghijklmnopqrstuvwxyz0123456789".chars().collect();

    let first_for_single = first_chars.clone();
    let single = (0..first_chars.len()).prop_map(move |i| first_for_single[i].to_string());

    // Multi-char branch: first + middle (0..=NETNS_RUNNER_NAME_MAX_LEN-2) + last.
    let max_middle = NETNS_RUNNER_NAME_MAX_LEN - 2;
    let multi = (
        proptest::sample::select(first_chars),
        proptest::collection::vec(proptest::sample::select(middle_chars), 0..=max_middle),
        proptest::sample::select(last_chars),
    )
        .prop_map(|(f, mid, l)| {
            let mut s = String::with_capacity(2 + mid.len());
            s.push(f);
            for c in mid {
                s.push(c);
            }
            s.push(l);
            s
        });

    prop_oneof![single, multi]
}

/// Build an `EgressRule` with a single-port spec. Address is a literal
/// IPv4 (matches what the Python tool's nft generator emits).
fn arbitrary_egress_rule() -> impl Strategy<Value = EgressRule> {
    (
        (1u32..=254u32, 0u32..=255u32, 0u32..=255u32, 1u32..=254u32),
        1u16..=65535u16,
        prop_oneof![Just(Proto::Tcp), Just(Proto::Udp), Just(Proto::Both)],
        // Comments only contain safe-set chars per validate_egress_comment.
        // The generator mirrors the validator's allowlist verbatim so
        // arbitrary_egress_rule emissions are guaranteed to pass that
        // gate before reaching the renderer.
        proptest::option::of("[A-Za-z0-9 _.,:/+-]{0,32}"),
    )
        .prop_map(|((a, b, c, d), port, proto, comment)| EgressRule {
            addr: format!("{a}.{b}.{c}.{d}"),
            port: PortSpec::Single(port),
            proto,
            comment,
        })
}

fn arbitrary_subnet() -> impl Strategy<Value = IpNet> {
    // /30 subnets in 10.200.x.0..256 — the design's allocator uses
    // 10.200.0.0/24 split into /30s.
    (0u8..=255u8, 0u8..=63u8).prop_map(|(b, c)| {
        let third = c * 4; // /30 boundaries: 0, 4, 8, ..., 252
        let s = format!("10.200.{b}.{third}/30");
        s.parse::<IpNet>().expect("constructed /30 must parse")
    })
}

fn netns_binding(egress: Vec<EgressRule>, subnet: IpNet) -> EffectiveNetworkBinding {
    EffectiveNetworkBinding {
        name: "buck2-isolated".into(),
        spec: NetworkSpec {
            mode: NetworkMode::Netns,
            allowed_egress: egress,
            ip_allow: vec![],
            ip_deny: vec![],
            restrict_address_families: vec![],
            dns: ghars::config::DnsMode::default(),
            ipv6: ghars::config::Ipv6Mode::default(),
        },
        subnet: Some(subnet),
    }
}

/// Count balanced `"` characters in `s`. Returns true if every
/// double-quote pair closes — the nft parser refuses unbalanced
/// quotes.
fn quotes_balanced(s: &str) -> bool {
    s.chars().filter(|c| *c == '"').count() % 2 == 0
}

proptest! {
    /// Property: the host table name embeds the runner name verbatim.
    /// (Critical — nft table names must be unique per runner; mismatch
    /// would route traffic through the wrong table.)
    #[test]
    fn nft_host_table_name_contains_runner_name(
        name in valid_netns_runner_name(),
        rules in proptest::collection::vec(arbitrary_egress_rule(), 0..=8),
        subnet in arbitrary_subnet(),
    ) {
        let binding = netns_binding(rules, subnet);
        let out = render_nft_rules(&name, &binding).unwrap();
        let expected_table = format!("table inet ghars_{name}");
        prop_assert!(
            out.host_rules.contains(&expected_table),
            "host_rules missing {expected_table:?}: {}",
            out.host_rules
        );
        let expected_ns = format!("table inet ghars_{name}_ns");
        prop_assert!(
            out.ns_rules.contains(&expected_ns),
            "ns_rules missing {expected_ns:?}: {}",
            out.ns_rules
        );
    }

    /// Property: ICMP frag-needed accept line is present in BOTH the
    /// host and ns tables for any binding (PMTU discovery requirement,
    /// Challenge 5). The line is unconditional in the renderer.
    #[test]
    fn nft_icmp_frag_needed_present_in_both_tables(
        name in valid_netns_runner_name(),
        rules in proptest::collection::vec(arbitrary_egress_rule(), 0..=8),
        subnet in arbitrary_subnet(),
    ) {
        let binding = netns_binding(rules, subnet);
        let out = render_nft_rules(&name, &binding).unwrap();
        let needle =
            "icmp type destination-unreachable icmp code frag-needed accept";
        prop_assert!(
            out.host_rules.contains(needle),
            "host missing icmp frag-needed: {}",
            out.host_rules
        );
        prop_assert!(
            out.ns_rules.contains(needle),
            "ns missing icmp frag-needed: {}",
            out.ns_rules
        );
    }

    /// Property: masquerade rule is scoped to the runner's /30 subnet
    /// only — `ip saddr <subnet>` must appear, scoping it (SEC-07).
    #[test]
    fn nft_masquerade_scoped_to_runner_subnet(
        name in valid_netns_runner_name(),
        rules in proptest::collection::vec(arbitrary_egress_rule(), 0..=4),
        subnet in arbitrary_subnet(),
    ) {
        let binding = netns_binding(rules, subnet);
        let out = render_nft_rules(&name, &binding).unwrap();
        let expected_masq = format!(
            "ip saddr {} oifname != \"ghars-{name}-*\" masquerade",
            binding.subnet.expect("netns_binding always sets subnet"),
        );
        prop_assert!(
            out.host_rules.contains(&expected_masq),
            "missing per-runner masquerade: {}\nrules: {}",
            expected_masq,
            out.host_rules
        );
        // Critical anti-property: must NOT contain a broad-scope
        // 10.0.0.0/8 masquerade — that would re-introduce SEC-07.
        prop_assert!(
            !out.host_rules.contains("ip saddr 10.0.0.0/8"),
            "broad masquerade leak: {}",
            out.host_rules
        );
    }

    /// Property: every emitted nft string literal is balanced (every
    /// `"` has a matching close). Defense against SEC-30 — a
    /// regression in `sanitize_comment_for_nft` could produce
    /// unterminated strings.
    #[test]
    fn nft_quotes_balanced_for_safe_comments(
        name in valid_netns_runner_name(),
        rules in proptest::collection::vec(arbitrary_egress_rule(), 0..=8),
        subnet in arbitrary_subnet(),
    ) {
        let binding = netns_binding(rules, subnet);
        let out = render_nft_rules(&name, &binding).unwrap();
        prop_assert!(
            quotes_balanced(&out.host_rules),
            "host_rules unbalanced quotes: {}",
            out.host_rules
        );
        prop_assert!(
            quotes_balanced(&out.ns_rules),
            "ns_rules unbalanced quotes: {}",
            out.ns_rules
        );
    }

    /// Property: validate_egress_comment REJECTS any comment that
    /// contains attacker-controlled chars (`"`, `;`, `\`, controls,
    /// shell metas). This is the SEC-30 gate. Replaces the old
    /// "sanitizer keeps quotes balanced" property — rejection is
    /// stricter than substitution because no attacker byte ever
    /// lands in the generated nft text.
    #[test]
    fn validate_egress_comment_rejects_attacker_chars(
        // Force at least one attacker char so this is a guaranteed
        // rejection. Pure regex — proptest's regex strategy refuses
        // empty alternations, so we require a leading attacker char
        // and an arbitrary attacker tail.
        attacker_comment in r"[\\;\x22\n\r\t!@#$%^&*()=][\\;\x22\n\r\t!@#$%^&*()=A-Za-z0-9 _.,:/-]{0,63}",
    ) {
        let result = validate_egress_comment(&attacker_comment);
        prop_assert!(
            result.is_err(),
            "attacker comment {attacker_comment:?} must be rejected by validate_egress_comment"
        );
    }


    /// Property: `render_nft_rules` REJECTS runner names that fail the
    /// identifier regex (SEC-35 defense in depth). Combined with the
    /// table-name property above this proves the entry-point gate.
    #[test]
    fn nft_rejects_invalid_runner_name(
        // Build candidate names that violate the regex by construction:
        // start with non-letter, contain uppercase, contain special chars.
        bad in prop_oneof![
            "[A-Z][a-z]{0,8}",       // uppercase first
            "[0-9][a-z]{0,8}",       // digit first
            "[a-z]{0,8}[_./]",       // contains _./
            "[a-z]{0,8}-",           // trailing dash
            "-[a-z]{0,8}",           // leading dash
        ],
    ) {
        let binding = netns_binding(vec![], "10.200.0.0/30".parse::<IpNet>().unwrap());
        let result = render_nft_rules(&bad, &binding);
        prop_assert!(
            result.is_err(),
            "invalid runner name {bad:?} must be rejected by render_nft_rules"
        );
    }

    /// Integration-layer pin: every name `valid_netns_runner_name`
    /// emits MUST produce a `host_veth_name` that fits the kernel's
    /// usable IFNAMSIZ window (`< IFNAMSIZ` bytes — the kernel reserves
    /// the trailing NUL). This is the public-API mirror of the in-tree
    /// property `veth_name_fits_ifnamsiz_for_every_bounded_runner_name`
    /// (netns.rs); the integration-test layer pins that the export
    /// remains stable + the cap derivation
    /// (`NETNS_RUNNER_NAME_MAX_LEN = IFNAMSIZ - 1 - VETH_NAME_OVERHEAD`)
    /// holds across crate boundaries.
    #[test]
    fn host_veth_name_fits_ifnamsiz(name in valid_netns_runner_name()) {
        let host = host_veth_name(&name);
        prop_assert!(
            host.len() < IFNAMSIZ,
            "host_veth_name({name:?}) = {host:?} ({} bytes) must fit IFNAMSIZ ({IFNAMSIZ}); \
             cap derivation `NETNS_RUNNER_NAME_MAX_LEN = IFNAMSIZ - 1 - VETH_NAME_OVERHEAD` \
             must hold",
            host.len(),
        );
    }

    /// Integration-layer pin: same property as
    /// `host_veth_name_fits_ifnamsiz` but for the runner-side veth.
    /// Both ends must fit because iproute2 / netlink rejects either
    /// with EINVAL when the byte length hits the kernel cap.
    #[test]
    fn runner_veth_name_fits_ifnamsiz(name in valid_netns_runner_name()) {
        let runner = runner_veth_name(&name);
        prop_assert!(
            runner.len() < IFNAMSIZ,
            "runner_veth_name({name:?}) = {runner:?} ({} bytes) must fit IFNAMSIZ ({IFNAMSIZ})",
            runner.len(),
        );
    }
}

/// Negative pin: an instance name beyond
/// `NETNS_RUNNER_NAME_MAX_LEN` MUST produce a veth name that overflows
/// the IFNAMSIZ usable window. Documents the cap as the
/// boundary, not just an internal constant.
///
/// `NETNS_RUNNER_NAME_MAX_LEN + 1 = 8` is the smallest shape that
/// breaks IFNAMSIZ: `"ghars-aaaaaaaa-h"` is exactly 16 bytes (the
/// kernel cap including NUL), one over the usable cap of 15. The
/// validators MUST catch this upstream so it never reaches iproute2;
/// this test is the regression guard against a refactor that silently
/// inverts the relationship between `NETNS_RUNNER_NAME_MAX_LEN` and
/// `IFNAMSIZ`.
#[test]
fn host_veth_name_overflows_ifnamsiz_at_cap_plus_one() {
    let oversize = "a".repeat(NETNS_RUNNER_NAME_MAX_LEN + 1);
    assert_eq!(
        oversize.len(),
        8,
        "drift guard: NETNS_RUNNER_NAME_MAX_LEN ({NETNS_RUNNER_NAME_MAX_LEN}) + 1 must equal 8 \
         for this assertion to mean what it claims"
    );
    let host = host_veth_name(&oversize);
    let runner = runner_veth_name(&oversize);
    assert!(
        host.len() > IFNAMSIZ - 1,
        "host_veth_name({oversize:?}) = {host:?} ({} bytes) must exceed IFNAMSIZ-1 ({}); \
         this is the overflow the netns validators are protecting against",
        host.len(),
        IFNAMSIZ - 1,
    );
    assert!(
        runner.len() > IFNAMSIZ - 1,
        "runner_veth_name({oversize:?}) = {runner:?} ({} bytes) must exceed IFNAMSIZ-1",
        runner.len(),
    );
}

// Silence unused-import warnings when proptest macros don't expand into
// every imported type (different combinations across `proptest!` blocks).
#[allow(dead_code)]
fn _references_to_keep_imports() {
    let _ = Utf8PathBuf::new();
}
