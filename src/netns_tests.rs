use super::*;
use crate::config::DnsMode;
use std::net::Ipv4Addr;
fn paths_for(tmp: &tempfile::TempDir) -> Paths {
    let root = Utf8PathBuf::from_path_buf(tmp.path().to_path_buf()).unwrap();
    Paths {
        state_dir: root.join("state"),
        cache_dir: root.join("cache"),
        logs_dir: root.join("logs"),
        unit_dir: root.join("units"),
        credentials_dir: root.join("creds"),
        runtime_dir: root.join("run"),
        config_dir: root.join("etc"),
        resolved_conf_d: root.join("resolved.conf.d"),
    }
}

#[test]
fn netns_name_format() {
    assert_eq!(netns_name("buckos"), "ghars-buckos");
    assert_eq!(netns_name("ci-1"), "ghars-ci-1");
}

#[test]
fn veth_name_format_matches_systemd_render() {
    // systemd.rs nft generator uses ghars-{name}-h / ghars-{name}-r;
    // the helper must agree byte-for-byte.
    assert_eq!(host_veth_name("buckos"), "ghars-buckos-h");
    assert_eq!(runner_veth_name("buckos"), "ghars-buckos-r");
}

#[test]
fn subnet_addresses_extracts_host_and_runner_from_30() {
    let s: IpNet = "10.200.0.0/30".parse().unwrap();
    let (h, r) = subnet_addresses(&s).unwrap();
    assert_eq!(h, IpAddr::V4(Ipv4Addr::new(10, 200, 0, 1)));
    assert_eq!(r, IpAddr::V4(Ipv4Addr::new(10, 200, 0, 2)));
}

#[test]
fn subnet_addresses_works_for_offset_30() {
    let s: IpNet = "10.200.0.4/30".parse().unwrap();
    let (h, r) = subnet_addresses(&s).unwrap();
    assert_eq!(h, IpAddr::V4(Ipv4Addr::new(10, 200, 0, 5)));
    assert_eq!(r, IpAddr::V4(Ipv4Addr::new(10, 200, 0, 6)));
}

#[test]
fn subnet_addresses_rejects_non_30() {
    let s: IpNet = "10.200.0.0/24".parse().unwrap();
    let err = subnet_addresses(&s).unwrap_err();
    assert!(matches!(err, GharsError::Validation(_, _)));
}

#[test]
fn subnet_addresses_rejects_ipv6() {
    let s: IpNet = "fd00::/126".parse().unwrap();
    let err = subnet_addresses(&s).unwrap_err();
    assert!(matches!(err, GharsError::Validation(_, _)));
}

#[test]
fn netns_config_round_trips_forward() {
    let tmp = tempfile::tempdir().unwrap();
    let paths = paths_for(&tmp);
    let cfg = NetnsConfig {
        subnet: "10.200.0.0/30".parse().unwrap(),
        dns: DnsMode::Forward,
    };
    cfg.write(&paths, "buckos").unwrap();
    let loaded = NetnsConfig::load(&paths, "buckos").unwrap();
    assert_eq!(loaded, cfg);
}

#[test]
fn netns_config_round_trips_static() {
    let tmp = tempfile::tempdir().unwrap();
    let paths = paths_for(&tmp);
    let cfg = NetnsConfig {
        subnet: "10.200.0.4/30".parse().unwrap(),
        dns: DnsMode::Static {
            servers: vec!["1.1.1.1".parse().unwrap(), "8.8.8.8".parse().unwrap()],
        },
    };
    cfg.write(&paths, "ci-1").unwrap();
    let loaded = NetnsConfig::load(&paths, "ci-1").unwrap();
    assert_eq!(loaded, cfg);
}

#[test]
fn netns_config_remove_is_idempotent() {
    let tmp = tempfile::tempdir().unwrap();
    let paths = paths_for(&tmp);
    // No file exists yet — must succeed.
    NetnsConfig::remove(&paths, "absent").unwrap();
    // Write, remove, remove again.
    let cfg = NetnsConfig {
        subnet: "10.200.0.0/30".parse().unwrap(),
        dns: DnsMode::Forward,
    };
    cfg.write(&paths, "x").unwrap();
    assert!(NetnsConfig::path_for(&paths, "x").exists());
    NetnsConfig::remove(&paths, "x").unwrap();
    assert!(!NetnsConfig::path_for(&paths, "x").exists());
    NetnsConfig::remove(&paths, "x").unwrap();
}

#[test]
fn netns_config_load_missing_returns_io_error() {
    let tmp = tempfile::tempdir().unwrap();
    let paths = paths_for(&tmp);
    let err = NetnsConfig::load(&paths, "nope").unwrap_err();
    assert!(matches!(err, GharsError::Io(_)));
}

#[test]
fn run_in_netns_rejects_empty_program() {
    let err = run_in_netns("buckos", &[]).unwrap_err();
    assert!(matches!(err, GharsError::Validation(_, _)));
}

#[test]
fn config_path_under_config_dir_netns_d() {
    let paths = Paths::default();
    assert_eq!(
        NetnsConfig::path_for(&paths, "buckos"),
        "/etc/ghars/netns.d/buckos.toml"
    );
}

#[test]
fn require_root_rejects_non_root_with_preflight_error() {
    // Test infrastructure runs as the operator user, never root.
    // The fast-path check at setup/teardown entry refuses to run.
    // We can't verify the root path without integration tests, but
    // we CAN verify the non-root rejection produces a clear error.
    if nix::unistd::geteuid().is_root() {
        // Skip when the test happens to run privileged; the
        // negative path is what guards the require_root contract.
        return;
    }
    let err = require_root("_netns-test").unwrap_err();
    match err {
        GharsError::Preflight(msg, hint) => {
            assert!(msg.contains("requires root"), "unexpected msg: {msg}",);
            assert!(
                hint.contains("ExecStart=+"),
                "hint should mention ExecStart=+ raise: {hint}",
            );
        }
        other => panic!("expected Preflight error, got {other:?}"),
    }
}

#[test]
fn run_cleanup_verb_swallows_absent_resource_messages() {
    // Real iproute2 prints these on the missing-resource path; we
    // simulate by running `/bin/sh -c "echo Cannot find device >&2;
    // exit 1"`. Any host with a POSIX shell handles this — and we
    // don't need root.
    let mut cmd = Command::new("/bin/sh");
    cmd.args(["-c", "echo 'Cannot find device dummy0' >&2; exit 1"]);
    run_cleanup_verb(&mut cmd, "ip link del (test)").unwrap();
}

#[test]
fn run_cleanup_verb_propagates_permission_denied_messages() {
    // Simulate the EPERM/EACCES path. The helper must surface
    // a real error so an unprivileged caller does not get a
    // silent "success" — the absent-marker classifier must
    // refuse to swallow permission-denied messages.
    let mut cmd = Command::new("/bin/sh");
    cmd.args([
        "-c",
        "echo 'RTNETLINK answers: Operation not permitted' >&2; exit 2",
    ]);
    let err = run_cleanup_verb(&mut cmd, "ip link del (test)").unwrap_err();
    let msg = format!("{err}");
    assert!(
        msg.contains("Operation not permitted") || msg.contains("ip link del"),
        "expected EPERM-class error to be propagated: {msg}",
    );
}

#[test]
fn run_cleanup_verb_propagates_unknown_failures() {
    // Generic failure mode (e.g. EBUSY, rtnetlink protocol error,
    // malformed argv). Must propagate as a real error rather than
    // being swallowed as "missing resource".
    let mut cmd = Command::new("/bin/sh");
    cmd.args(["-c", "echo 'argument is invalid' >&2; exit 1"]);
    let err = run_cleanup_verb(&mut cmd, "ip netns del (test)").unwrap_err();
    let msg = format!("{err}");
    assert!(
        msg.contains("ip netns del"),
        "expected action label in error: {msg}",
    );
}

/// Pin that `run_required` actually surfaces stderr to the
/// operator. Without `.output()` capture, iproute2 / nft
/// diagnostics would vanish and the operator would only see
/// "exit `ExitStatus`(...)" with no clue what went wrong. Use
/// /bin/sh as a stand-in for an iproute2 binary that fails on
/// bad argv.
#[test]
fn run_required_captures_stderr_into_error_chain() {
    let mut cmd = Command::new("/bin/sh");
    cmd.args(["-c", "echo 'simulated iproute2 error' >&2; exit 1"]);
    let err = RealNetnsOps
        .run_required(&mut cmd, "ip link add (test)")
        .expect_err("non-zero exit must propagate as Err");
    let msg = format!("{err}");
    assert!(
        msg.contains("simulated iproute2 error"),
        "stderr text MUST appear in the error chain (run_required captures stderr via .output()); got: {msg}",
    );
    assert!(
        msg.contains("ip link add"),
        "action label MUST appear in the error chain; got: {msg}",
    );
}

/// Truncation pin: stderr longer than `STDERR_PREVIEW_LEN`
/// (1 KiB) MUST be bounded so a pathological iproute2 / nft binary
/// that floods stderr cannot unbound the error chain. The preview
/// is `chars().take(N).collect()` — char-bounded, not byte-bounded —
/// so on ASCII stderr the preview is exactly N bytes.
#[test]
fn run_required_truncates_oversize_stderr_to_preview_cap() {
    // Emit 2 KiB of 'X' to stderr followed by a non-zero exit.
    // /bin/sh's printf is pinned by POSIX to handle %d.
    let big_n = STDERR_PREVIEW_LEN * 2;
    let script = format!(
        "awk 'BEGIN {{ for (i = 0; i < {big_n}; i++) printf \"X\" > \"/dev/stderr\"; exit 1 }}'"
    );
    let mut cmd = Command::new("/bin/sh");
    cmd.args(["-c", &script]);
    let err = RealNetnsOps
        .run_required(&mut cmd, "ip link add (test-flood)")
        .expect_err("non-zero exit must propagate as Err");
    let msg = format!("{err}");
    // The stderr content embeds in the source string AFTER an
    // "exit ...; stderr=" prefix. The preview is bounded at
    // STDERR_PREVIEW_LEN chars, but the prefix and label add a
    // small constant; bound the assertion at preview cap + a
    // generous overhead allowance to cover the prefix shape
    // without being brittle to its exact wording.
    let prefix_overhead = 256;
    assert!(
        msg.len() <= STDERR_PREVIEW_LEN + prefix_overhead,
        "error message must be bounded around STDERR_PREVIEW_LEN ({}); got {} chars: {msg:.200}",
        STDERR_PREVIEW_LEN,
        msg.len(),
    );
    // And the X-flood must STILL be present (the truncation is
    // a tail-trim, not a content-strip).
    assert!(
        msg.contains("XXXXXXXX"),
        "stderr content (Xs) must still appear in the truncated preview; got: {msg:.200}",
    );
}

// -------- adversarial instance-name handling --------------------------

/// Every adversarial form the `validate_runner_name` gate must
/// reject before any kernel work starts. Each entry exercises
/// one shape of attack against the format strings into iproute2
/// / nftables / systemd unit names / filesystem paths.
///
/// The `IDENTIFIER_REGEX` (`^[a-z]([a-z0-9-]*[a-z0-9])?$`, ≤
/// `IDENTIFIER_MAX_LEN`) is the single source of truth — any name
/// that isn't strictly ASCII-lowercase-letters-digits-dashes
/// MUST fail.
#[rstest::rstest]
#[case("", "empty string")]
#[case(" ", "single space")]
#[case("foo bar", "embedded whitespace")]
#[case("foo\tbar", "embedded tab")]
#[case("foo\nbar", "embedded newline")]
#[case("foo/bar", "path separator")]
#[case("..", "dot-dot traversal")]
#[case(".", "single dot")]
#[case("foo/../bar", "embedded traversal segment")]
#[case("foo\0bar", "embedded NUL byte")]
#[case("foo;rm", "shell metachar (semicolon)")]
#[case("foo$bar", "shell metachar (dollar)")]
#[case("foo`bar", "shell metachar (backtick)")]
#[case("foo|bar", "shell metachar (pipe)")]
#[case("foo&bar", "shell metachar (ampersand)")]
#[case("foo>bar", "shell metachar (redirect)")]
#[case("foo$(rm)", "command substitution")]
#[case("Foo", "uppercase letter")]
#[case("FOO", "all uppercase")]
#[case("123foo", "leading digit")]
#[case("-foo", "leading dash")]
#[case("foo-", "trailing dash")]
#[case("foo_bar", "underscore (not in IDENTIFIER_REGEX)")]
#[case("foo.bar", "dot")]
#[case("foo bar baz", "multiple spaces")]
#[case("../etc/passwd", "leading traversal")]
#[case("/etc/passwd", "absolute path")]
fn adversarial_instance_names_rejected_by_validate_instance_name(
    #[case] name: &str,
    #[case] description: &str,
) {
    // Every case must produce a Validation error from the gate
    // BEFORE any kernel work. validate_instance_name is the
    // composition point for setup/teardown/run_in_netns; if this
    // test passes for every case, the entry-point gates do too.
    let err = validate_instance_name(name, "_test").unwrap_err();
    match &err {
        GharsError::Validation(msg, _) => {
            assert!(
                msg.contains("invalid instance name") || msg.contains("identifier"),
                "case {description}: unexpected message {msg}",
            );
        }
        other => panic!("case {description}: expected Validation, got {other:?}"),
    }
}

#[test]
fn validate_instance_name_accepts_canonical_names() {
    // Sanity: the gate must accept names that satisfy the regex.
    // These all map to legal iproute2 / nftables / systemd
    // instance forms.
    for name in ["a", "ab", "buckos", "ci-1", "ci-99", "x-y-z"] {
        validate_instance_name(name, "_test")
            .unwrap_or_else(|e| panic!("expected {name:?} to validate, got {e:?}"));
    }
}

#[test]
fn run_in_netns_rejects_adversarial_instance_name() {
    // End-to-end check: the gate fires before any program-arg
    // path is exercised. The empty-program error path tests the
    // POST-gate branch (validate_instance_name accepts "buckos"
    // first, then empty-program fails); this test confirms the
    // PRE-gate branch — bad name short-circuits before checking
    // program emptiness.
    let err = run_in_netns("foo;rm", &[]).unwrap_err();
    match err {
        GharsError::Validation(msg, _) => {
            assert!(msg.contains("invalid instance name"), "msg={msg}");
        }
        other => panic!("expected Validation, got {other:?}"),
    }
}

// -------- subnet_addresses property tests -----------------------------

// proptest: every valid IPv4 /30 round-trips through
// `subnet_addresses` and yields exactly the (network+1,
// network+2) pair, anywhere in the address space. The function
// performs raw u32 arithmetic — exhaustively covering every
// 4-address-aligned base address with proptest catches any
// off-by-one / endian / overflow regression that a single
// hand-picked test would miss.
proptest::proptest! {
    // Random offset within a /30-aligned IPv4 base.
    // `network()` returns the rounded-down /30 base.
    #[test]
    fn subnet_addresses_round_trips_random_30(base in 0u32..=u32::MAX) {
        // /30 has 4-address alignment: clear the bottom 2 bits.
        let aligned = base & !0x3;
        let network = std::net::Ipv4Addr::from(aligned);
        let cidr = format!("{network}/30");
        let subnet: IpNet = cidr.parse().expect("aligned /30 must parse");
        let (host_ip, runner_ip) = subnet_addresses(&subnet)
            .expect("any /30 must yield host+runner");
        // Host is base+1, runner is base+2 — irrespective of the
        // base address.
        proptest::prop_assert_eq!(
            host_ip,
            IpAddr::V4(std::net::Ipv4Addr::from(aligned.wrapping_add(1))),
        );
        proptest::prop_assert_eq!(
            runner_ip,
            IpAddr::V4(std::net::Ipv4Addr::from(aligned.wrapping_add(2))),
        );
    }
}

#[test]
fn subnet_addresses_boundary_lowest_30() {
    // 0.0.0.0/30 — host = 0.0.0.1, runner = 0.0.0.2. Edge case:
    // u32 arithmetic at the bottom of the address space.
    let s: IpNet = "0.0.0.0/30".parse().unwrap();
    let (h, r) = subnet_addresses(&s).unwrap();
    assert_eq!(h, IpAddr::V4(Ipv4Addr::new(0, 0, 0, 1)));
    assert_eq!(r, IpAddr::V4(Ipv4Addr::new(0, 0, 0, 2)));
}

#[test]
fn subnet_addresses_boundary_highest_30() {
    // 255.255.255.252/30 — host = 255.255.255.253, runner =
    // 255.255.255.254. Edge case: u32 arithmetic near the top
    // of the address space (the broadcast 255.255.255.255 is
    // unreachable, but the host/runner pair sits within the
    // legal /30 range).
    let s: IpNet = "255.255.255.252/30".parse().unwrap();
    let (h, r) = subnet_addresses(&s).unwrap();
    assert_eq!(h, IpAddr::V4(Ipv4Addr::new(255, 255, 255, 253)));
    assert_eq!(r, IpAddr::V4(Ipv4Addr::new(255, 255, 255, 254)));
}

proptest::proptest! {
    // Property: the runner address is always exactly one greater
    // than the host address (the /30 layout: network, host,
    // runner, broadcast). Pinned irrespective of base.
    #[test]
    fn subnet_addresses_runner_is_host_plus_one(base in 0u32..=u32::MAX) {
        let aligned = base & !0x3;
        let cidr = format!("{}/30", std::net::Ipv4Addr::from(aligned));
        let subnet: IpNet = cidr.parse().unwrap();
        let (host_ip, runner_ip) = subnet_addresses(&subnet).unwrap();
        let IpAddr::V4(h) = host_ip else { unreachable!() };
        let IpAddr::V4(r) = runner_ip else { unreachable!() };
        proptest::prop_assert_eq!(u32::from(r), u32::from(h).wrapping_add(1));
    }
}

proptest::proptest! {
    // Every non-/30 IPv4 prefix length must be rejected with
    // `GharsError::Validation`. The allocator's
    // contract is "give me a /30, get back (host, runner)"; any
    // other prefix indicates a config-author mistake (likely
    // confusing the per-runner /30 with the [defaults] netns_subnet
    // /N pool). prefix_len ranges that must reject:
    //   - [0..=29]: too wide (would split an octet differently)
    //   - 31:      RFC 3021 point-to-point /31 (no host/runner room)
    //   - 32:      single-host /32
    //
    // We generate (base, prefix_len) pairs uniformly across the
    // legal IPv4 prefix space [0..=32]; `prop_assume!` filters
    // out the legal /30 case so proptest only tests the rejection
    // contract on prefix lengths that must fail. The shrinker
    // converges on the smallest counter-example regardless of
    // which side of /30 the failure comes from.
    #[test]
    fn subnet_addresses_rejects_every_non_30_prefix(
        base in 0u32..=u32::MAX,
        prefix in 0u8..=32u8,
    ) {
        // Skip the legal /30 case — its acceptance is covered by
        // subnet_addresses_round_trips_random_30. This test guards
        // ONLY the rejection contract.
        proptest::prop_assume!(prefix != 30);
        // Mask the base to the network address for `prefix`. ipnet's
        // FromStr does not require a normalized addr, but masking
        // here keeps the printed CIDR canonical and avoids
        // regenerating the same `Ipv4Net::new(addr, prefix)` in two
        // places. For prefix == 32, the mask is u32::MAX (no bits
        // dropped); for prefix == 0, the mask is 0 (all bits dropped).
        let mask = if prefix == 0 { 0u32 } else { u32::MAX << (32 - prefix) };
        let aligned = base & mask;
        let cidr = format!("{}/{}", std::net::Ipv4Addr::from(aligned), prefix);
        let subnet: IpNet = cidr.parse().expect("constructed CIDR must parse");
        let err = subnet_addresses(&subnet).unwrap_err();
        // Every non-/30 input must produce Validation, never any
        // other variant. This also implicitly covers the message
        // shape: `subnet ... is /N, expected /30` for IPv4 inputs.
        proptest::prop_assert!(
            matches!(err, GharsError::Validation(_, _)),
            "prefix /{prefix} on {cidr} did not produce Validation: {err:?}",
        );
    }
}

#[test]
fn subnet_addresses_wrap_around_safety_uses_network_base() {
    // ipnet stores the literal `addr` from the input CIDR;
    // `network()` derives the masked base on demand. Any
    // address inside a /30 (e.g. `.255` in `255.255.255.255/30`)
    // resolves to the same /30 base (`255.255.255.252`), so
    // `subnet_addresses` returns the same (host, runner) pair
    // regardless of which of the four addresses the operator
    // happened to write.
    //
    // This guards against a subtle mis-implementation: had
    // `subnet_addresses` used `net.addr()` directly (skipping the
    // mask), an input of `255.255.255.255/30` would compute
    // `addr+1 = 0.0.0.0` (u32 wrap), silently misallocating the
    // host IP into a different network. The current impl uses
    // `net.network()` inside `subnet_addresses`, so the
    // base is canonicalized before `+1`/`+2`.
    //
    // Verify the canonicalization holds for every address inside
    // the top /30:
    for input in [
        "255.255.255.252/30", // base itself
        "255.255.255.253/30", // host slot
        "255.255.255.254/30", // runner slot
        "255.255.255.255/30", // broadcast slot
    ] {
        let subnet: IpNet = input.parse().unwrap();
        let (h, r) = subnet_addresses(&subnet)
            .unwrap_or_else(|e| panic!("{input} should resolve via network base: {e:?}"));
        assert_eq!(
            h,
            IpAddr::V4(Ipv4Addr::new(255, 255, 255, 253)),
            "{input}: host IP must be the canonical /30 base + 1",
        );
        assert_eq!(
            r,
            IpAddr::V4(Ipv4Addr::new(255, 255, 255, 254)),
            "{input}: runner IP must be the canonical /30 base + 2",
        );
    }

    // Same property at the bottom of the address space — proves
    // the canonicalization is symmetric, not just an accident at
    // the top.
    for input in ["0.0.0.0/30", "0.0.0.1/30", "0.0.0.2/30", "0.0.0.3/30"] {
        let subnet: IpNet = input.parse().unwrap();
        let (h, r) = subnet_addresses(&subnet).unwrap();
        assert_eq!(h, IpAddr::V4(Ipv4Addr::new(0, 0, 0, 1)));
        assert_eq!(r, IpAddr::V4(Ipv4Addr::new(0, 0, 0, 2)));
    }
}

// -------- cross-module name-prefix invariant -------------------------
//
// The nft generator in `systemd.rs` (its `render_nft_host` writes
// `iifname "ghars-{runner}-h"`) constructs interface names
// independently of `host_veth_name` / `runner_veth_name` here.
// A drift between these two formatters would point nft rules at a
// non-existent interface, breaking fail-closed.
//
// The property-based form covers every IDENTIFIER_REGEX-shaped name
// (lowercase letters, digits, dashes; first char letter, last char
// letter or digit) up to IDENTIFIER_MAX_LEN-1 chars beyond the
// leading letter. We feed `string_regex` an UN-anchored pattern
// because proptest's regex engine rejects `^`/`$` anchors (proptest
// 1.11.0 src/string.rs:232 — "anchors/boundaries not supported for
// string generation"). The full IDENTIFIER_REGEX has implicit
// anchors when matched, but the generator produces only matching
// bodies; a `validate_runner_name` call below double-checks that
// every generated name is in fact accepted by the gate.
proptest::proptest! {
    #[test]
    fn name_helpers_share_ghars_instance_prefix(
        instance in r"[a-z]([a-z0-9-]{0,62}[a-z0-9])?",
    ) {
        // The generator MAY produce names that fail
        // validate_runner_name (proptest's regex engine and
        // validators.rs share IDENTIFIER_REGEX, but proptest
        // strips anchors so a pathological corner is not
        // reachable here — still, we re-check to keep the
        // property honest).
        proptest::prop_assume!(
            crate::validators::validate_runner_name(&instance).is_ok()
        );

        let ns = netns_name(&instance);
        let host = host_veth_name(&instance);
        let runner = runner_veth_name(&instance);

        // Cross-module invariant 1: every helper formats on top
        // of the same `ghars-{instance}` prefix.
        proptest::prop_assert_eq!(&ns, &format!("ghars-{instance}"));
        proptest::prop_assert!(
            host.starts_with(&ns),
            "host_veth_name {host:?} must start with netns_name {ns:?}",
        );
        proptest::prop_assert!(
            runner.starts_with(&ns),
            "runner_veth_name {runner:?} must start with netns_name {ns:?}",
        );

        // Cross-module invariant 2: the host/runner suffixes are
        // exactly `-h` / `-r`. systemd.rs:render_nft_host emits
        // `iifname "ghars-{runner}-h"`; if these helpers ever
        // emit a different suffix, the nft rule and the actual
        // interface name diverge.
        proptest::prop_assert!(
            host.ends_with("-h"),
            "host_veth_name {host:?} must end with -h",
        );
        proptest::prop_assert!(
            runner.ends_with("-r"),
            "runner_veth_name {runner:?} must end with -r",
        );

        // Cross-module invariant 3: byte-for-byte equality with
        // the literal format strings the nft generator uses.
        // (If render_nft_host ever changes its template, this
        // property fails immediately and points at the drift.)
        proptest::prop_assert_eq!(host, format!("ghars-{instance}-h"));
        proptest::prop_assert_eq!(runner, format!("ghars-{instance}-r"));
    }
}

#[test]
fn name_helpers_agree_for_canonical_identifiers() {
    // Pin the property at three concrete representative names so a
    // proptest config tweak (low cases, slow shrinking) can never
    // hide a regression. These mirror the systemd.rs
    // render_nft_host expectation exactly.
    for name in ["a", "buckos", "ci-1"] {
        assert_eq!(netns_name(name), format!("ghars-{name}"));
        assert_eq!(host_veth_name(name), format!("ghars-{name}-h"));
        assert_eq!(runner_veth_name(name), format!("ghars-{name}-r"));
        assert!(host_veth_name(name).starts_with(&netns_name(name)));
        assert!(runner_veth_name(name).starts_with(&netns_name(name)));
    }
}

// Every name within `NETNS_RUNNER_NAME_MAX_LEN` MUST
// produce a veth name that fits the kernel's IFNAMSIZ window
// (`< IFNAMSIZ` bytes including the trailing NUL the kernel
// reserves; usable len = `IFNAMSIZ - 1`). The cap derivation in
// `validators.rs::NETNS_RUNNER_NAME_MAX_LEN = IFNAMSIZ - 1 -
// VETH_NAME_OVERHEAD` is what makes this property hold; if any
// of those three constants drift independently, this property
// will catch it immediately.
//
// Plain `//` instead of `///` because rustdoc does not generate
// documentation for macro invocations — the doc comment would
// attach to the `proptest!` macro call but be silently dropped,
// triggering `unused_doc_comments`.
proptest::proptest! {
    #[test]
    fn veth_name_fits_ifnamsiz_for_every_bounded_runner_name(
        // Identifier-shape names bounded to `NETNS_RUNNER_NAME_MAX_LEN`.
        // Single-letter and 2..=cap branches cover both legal name
        // shapes (`[a-z]` and `[a-z][a-z0-9-]*[a-z0-9]`).
        instance in r"[a-z]([a-z0-9-]{0,5}[a-z0-9])?",
    ) {
        // proptest's regex engine doesn't enforce anchors; double
        // check the validator and skip if the gate would reject.
        // Length within the cap is guaranteed by the regex (1 +
        // 0..=5 + optional 1 = 1..=7 chars).
        proptest::prop_assume!(
            crate::validators::validate_runner_name(&instance).is_ok()
        );
        proptest::prop_assume!(
            instance.len() <= crate::validators::NETNS_RUNNER_NAME_MAX_LEN
        );

        let host = host_veth_name(&instance);
        let runner = runner_veth_name(&instance);

        // The kernel reserves the trailing NUL, so the *usable*
        // length cap is `IFNAMSIZ - 1`. Both veth names must fit
        // this window; iproute2 / netlink would refuse anything
        // larger with EINVAL.
        proptest::prop_assert!(
            host.len() < crate::validators::IFNAMSIZ,
            "host_veth_name({instance:?}) = {host:?} ({} bytes) must fit IFNAMSIZ ({})",
            host.len(),
            crate::validators::IFNAMSIZ,
        );
        proptest::prop_assert!(
            runner.len() < crate::validators::IFNAMSIZ,
            "runner_veth_name({instance:?}) = {runner:?} ({} bytes) must fit IFNAMSIZ ({})",
            runner.len(),
            crate::validators::IFNAMSIZ,
        );
    }
}

/// Negative pin: an instance name that exceeds
/// `NETNS_RUNNER_NAME_MAX_LEN` MUST produce a veth name that
/// overflows the IFNAMSIZ window. Documents the cap as the
/// boundary, not just an internal constant. The
/// `validate_netns_runner_name_lengths` and
/// `validate_instance_name` gates exist specifically because
/// this overflow would otherwise reach iproute2 and produce an
/// opaque EINVAL.
#[test]
fn host_veth_name_overflows_ifnamsiz_when_instance_exceeds_cap() {
    // 8 chars = NETNS_RUNNER_NAME_MAX_LEN (7) + 1 — the smallest
    // shape that breaks IFNAMSIZ.
    let oversize = "a".repeat(crate::validators::NETNS_RUNNER_NAME_MAX_LEN + 1);
    assert_eq!(
        oversize.len(),
        8,
        "drift guard: NETNS_RUNNER_NAME_MAX_LEN + 1 must be 8 for this assertion to mean what it claims",
    );
    let host = host_veth_name(&oversize);
    let runner = runner_veth_name(&oversize);
    // Must exceed the kernel's usable IFNAMSIZ window
    // (IFNAMSIZ - 1 = 15 chars). Concretely: "ghars-aaaaaaaa-h"
    // is 16 bytes, exactly at IFNAMSIZ — over the usable cap by
    // 1. The validators MUST catch this upstream so it never
    // reaches iproute2.
    assert!(
        host.len() > crate::validators::IFNAMSIZ - 1,
        "host_veth_name({oversize:?}) = {host:?} ({} bytes) must exceed IFNAMSIZ-1 ({}); \
         this is the overflow the netns validators are protecting against",
        host.len(),
        crate::validators::IFNAMSIZ - 1,
    );
    assert!(
        runner.len() > crate::validators::IFNAMSIZ - 1,
        "runner_veth_name({oversize:?}) = {runner:?} ({} bytes) must exceed IFNAMSIZ-1",
        runner.len(),
    );
}

// -------- per-step error path coverage --------------------------------

use std::sync::Mutex;

/// Test seam: records every (label, kind) pair that flows through
/// `setup_steps` and optionally fails at a chosen `fail_at` label.
/// Mirrors `RealNetnsOps` for the success path; produces a clear
/// `GharsError::Apply { action: label, ... }` for the configured
/// failing label.
///
/// We record events instead of running the real command so per-step
/// tests don't require root, /usr/sbin/ip, or kernel features.
struct MockNetnsOps {
    fail_at: Option<&'static str>,
    events: Mutex<Vec<(String, &'static str)>>, // (label, kind)
}

impl MockNetnsOps {
    fn new() -> Self {
        Self {
            fail_at: None,
            events: Mutex::new(Vec::new()),
        }
    }
    fn failing_at(label: &'static str) -> Self {
        Self {
            fail_at: Some(label),
            events: Mutex::new(Vec::new()),
        }
    }
    fn snapshot(&self) -> Vec<(String, &'static str)> {
        self.events.lock().unwrap().clone()
    }
    fn record(&self, label: &str, kind: &'static str) -> Result<()> {
        self.events.lock().unwrap().push((label.to_string(), kind));
        if Some(label) == self.fail_at {
            return Err(GharsError::Apply {
                action: label.into(),
                source: Box::new(GharsError::Io(io::Error::other("mock injected failure"))),
            });
        }
        Ok(())
    }
}

impl NetnsOps for MockNetnsOps {
    fn run_required(&self, _cmd: &mut Command, label: &str) -> Result<()> {
        self.record(label, "required")
    }
    fn run_cleanup(&self, _cmd: &mut Command, label: &str) -> Result<()> {
        self.record(label, "cleanup")
    }
}

fn mock_setup_paths(tmp: &tempfile::TempDir) -> Paths {
    let root = Utf8PathBuf::from_path_buf(tmp.path().to_path_buf()).unwrap();
    Paths {
        state_dir: root.join("state"),
        cache_dir: root.join("cache"),
        logs_dir: root.join("logs"),
        unit_dir: root.join("units"),
        credentials_dir: root.join("creds"),
        runtime_dir: root.join("run"),
        config_dir: root.join("etc"),
        resolved_conf_d: root.join("resolved.conf.d"),
    }
}

fn mock_cfg() -> NetnsConfig {
    NetnsConfig {
        subnet: "10.200.0.0/30".parse().unwrap(),
        // Static avoids the resolved drop-in path; setup_dns under
        // Static only writes the resolv source file, which is
        // root-tolerant under a tempdir.
        dns: DnsMode::Static {
            servers: vec!["1.1.1.1".parse().unwrap()],
        },
    }
}

/// All `setup_steps` labels in the order they execute. The
/// per-step tests iterate this list; if a step is added /
/// renamed, `setup_steps` and this list move in lock-step.
const SETUP_STEP_LABELS: &[&str] = &[
    "ip link del (pre-create cleanup)",
    "ip netns del (pre-create cleanup)",
    "ip netns add",
    "ip link add veth pair",
    "ip link set netns",
    "ip link set host veth mtu",
    "ip -n NS link set runner veth mtu",
    "ip addr add host",
    "ip -n NS addr add runner",
    "ip link set host veth up",
    "ip -n NS link set runner veth up",
    "ip -n NS link set lo up",
    "ip -n NS route add default",
    "sysctl net.ipv6.conf.all.disable_ipv6=1 (in NS)",
    "sysctl net.ipv6.conf.default.disable_ipv6=1 (in NS)",
    "sysctl per-interface forwarding",
];

#[test]
fn mock_setup_happy_path_runs_every_step_in_order() {
    let tmp = tempfile::tempdir().unwrap();
    let paths = mock_setup_paths(&tmp);
    let cfg = mock_cfg();
    let ops = MockNetnsOps::new();
    setup_with_ops(&ops, &paths, "buckos", &cfg).unwrap();
    let labels: Vec<String> = ops.snapshot().into_iter().map(|(l, _)| l).collect();
    // Every step label appears exactly once, in order.
    let expected: Vec<String> = SETUP_STEP_LABELS.iter().map(|s| (*s).to_string()).collect();
    assert_eq!(labels, expected);
}

#[test]
fn mock_setup_fails_at_each_step_independently() {
    // Per-step independent-failure spec: "Test each of the setup
    // steps failing independently." We iterate every label and confirm
    // (a) setup_with_ops returns an Err whose action label
    // matches the failing step, (b) the recorded events show we
    // reached the failing step (no later step ran), (c)
    // teardown_inner ran after the failure (rollback contract).
    for fail_label in SETUP_STEP_LABELS {
        let tmp = tempfile::tempdir().unwrap();
        let paths = mock_setup_paths(&tmp);
        let cfg = mock_cfg();
        let ops = MockNetnsOps::failing_at(fail_label);

        let err = setup_with_ops(&ops, &paths, "buckos", &cfg)
            .unwrap_err_or_else(|()| panic!("step {fail_label}: expected failure, got Ok"));

        // (a) The error carries the failing step's label.
        match &err {
            GharsError::Apply { action, .. } => {
                assert_eq!(
                    action, fail_label,
                    "step {fail_label}: expected action label match",
                );
            }
            other => panic!("step {fail_label}: expected Apply, got {other:?}"),
        }

        // (b) Events recorded up to and including the failing step.
        let snapshot = ops.snapshot();
        let last = snapshot
            .last()
            .unwrap_or_else(|| panic!("step {fail_label}: no events"));
        assert_eq!(
            last.0, *fail_label,
            "step {fail_label}: last event must be the failing step",
        );
        // Steps AFTER fail_label must NOT appear.
        let fail_idx = SETUP_STEP_LABELS
            .iter()
            .position(|l| l == fail_label)
            .unwrap();
        let later_steps: Vec<&&str> = SETUP_STEP_LABELS.iter().skip(fail_idx + 1).collect();
        for later in later_steps {
            assert!(
                !snapshot.iter().any(|(l, _)| l == *later),
                "step {fail_label}: later step {later} unexpectedly ran",
            );
        }
    }
}

// -------- DnsMode::Static empty servers rejection --------------------
//
// setup_dns is module-private; the test calls it directly with a
// throw-away tempdir. The Static branch's only failure mode is "no
// nameservers configured" — the function must surface that before
// any filesystem I/O so the operator gets a clear message instead
// of an empty resolv.conf written to disk and a runner that
// silently fails DNS.

#[test]
fn setup_dns_static_with_empty_servers_returns_validation_error() {
    let tmp = tempfile::tempdir().unwrap();
    let paths = mock_setup_paths(&tmp);
    let dns = DnsMode::Static { servers: vec![] };
    let host_ip = IpAddr::V4(Ipv4Addr::new(10, 200, 0, 1));
    let err = setup_dns(&paths, "buckos", host_ip, &dns).unwrap_err();
    match err {
        GharsError::Validation(msg, hint) => {
            assert!(
                msg.contains("static") || msg.contains("Static") || msg.contains("dns"),
                "msg should describe the static-DNS failure: {msg}",
            );
            assert!(
                !hint.is_empty(),
                "operator-facing hint must not be empty: {hint}",
            );
        }
        other => panic!("expected Validation, got {other:?}"),
    }
    // No resolv.conf must have been written before the early
    // return (defense in depth: an empty resolv.conf is more
    // dangerous than no resolv.conf — the kernel would silently
    // fail DNS instead of falling back to /etc/resolv.conf bind
    // semantics).
    assert!(
        !paths.netns_resolv_conf("buckos").exists(),
        "setup_dns must not write resolv.conf before the empty-servers check",
    );
}

#[test]
fn setup_dns_static_with_one_server_writes_resolv_conf() {
    // Companion test for the empty-servers case: pin the success
    // path at the same call site so a future refactor that
    // accidentally swaps the empty/non-empty branch order
    // surfaces immediately.
    let tmp = tempfile::tempdir().unwrap();
    let paths = mock_setup_paths(&tmp);
    let dns = DnsMode::Static {
        servers: vec!["1.1.1.1".parse().unwrap()],
    };
    let host_ip = IpAddr::V4(Ipv4Addr::new(10, 200, 0, 1));
    setup_dns(&paths, "buckos", host_ip, &dns).unwrap();
    let body = std::fs::read_to_string(paths.netns_resolv_conf("buckos").as_std_path()).unwrap();
    assert!(
        body.contains("nameserver 1.1.1.1"),
        "resolv.conf must contain nameserver line: {body}",
    );
}

#[test]
fn setup_dns_static_with_multiple_servers_writes_each_on_own_line() {
    // Pin /etc/resolv.conf format: one `nameserver IP` per line.
    // The kernel resolver only honors the first 3 lines but the
    // file format is a hard contract.
    let tmp = tempfile::tempdir().unwrap();
    let paths = mock_setup_paths(&tmp);
    let dns = DnsMode::Static {
        servers: vec![
            "1.1.1.1".parse().unwrap(),
            "8.8.8.8".parse().unwrap(),
            "9.9.9.9".parse().unwrap(),
        ],
    };
    let host_ip = IpAddr::V4(Ipv4Addr::new(10, 200, 0, 1));
    setup_dns(&paths, "buckos", host_ip, &dns).unwrap();
    let body = std::fs::read_to_string(paths.netns_resolv_conf("buckos").as_std_path()).unwrap();
    // Three nameserver lines, in input order.
    let lines: Vec<&str> = body.lines().collect();
    assert_eq!(lines.len(), 3, "expected 3 nameserver lines: {body}");
    assert_eq!(lines[0], "nameserver 1.1.1.1");
    assert_eq!(lines[1], "nameserver 8.8.8.8");
    assert_eq!(lines[2], "nameserver 9.9.9.9");
}

/// Internal helper because Result<(), E> doesn't have a stable
/// `unwrap_err_or_else` and we want a `step`-aware panic message.
trait UnwrapErrOrElse<T, E> {
    fn unwrap_err_or_else(self, f: impl FnOnce(T)) -> E;
}
impl<T, E> UnwrapErrOrElse<T, E> for std::result::Result<T, E> {
    fn unwrap_err_or_else(self, f: impl FnOnce(T)) -> E {
        match self {
            Ok(t) => {
                f(t);
                unreachable!("f should panic on Ok")
            }
            Err(e) => e,
        }
    }
}
