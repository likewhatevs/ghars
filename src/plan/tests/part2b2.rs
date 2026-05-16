//! part2b continued: end-to-end production-pipeline pins through
//! `expand_counts` + `lower_to_effective` + `render_runner_unit`.

#![allow(clippy::unwrap_used, clippy::expect_used)]

use super::*;
use crate::config::{DnsMode, EffectiveNetworkBinding, Ipv6Mode, NetworkMode, NetworkSpec};

/// End-to-end PRODUCTION-pipeline pin: drives a runner config
/// through `expand_counts` + `lower_to_effective` (the production
/// resolver chain that wraps `merge_defaults`) and asserts the
/// rendered drop-in set excludes `50-numa.conf`. Sister to the
/// `merge_defaults`→`render_runner_unit` pin above; this one verifies
/// the FULL production wiring rather than only the merge boundary.
/// A regression that re-introduced empty-string values inside
/// `lower_to_effective` AFTER the `merge_defaults` filter call
/// would slip past the merge-only integration test but fail here.
#[test]
fn lower_to_effective_some_empty_allowed_cpus_drives_render_runner_unit_to_skip_50_numa() {
    let mut runner = minimal_runner("a");
    runner.allowed_cpus = Some(String::new());
    runner.allowed_memory_nodes = Some(String::new());
    runner.runner_version = Some("2.334.0".into());
    let cfg = config_with_runners(vec![runner]);
    let expanded = expand_counts(&cfg).expect("count expansion must succeed");
    let mut eff = lower_to_effective(&expanded[0], &cfg, Arch::X86_64, cfg_source_default(), 0)
        .expect("lower_to_effective must succeed");
    eff.spec_hash = spec_hash(&eff);
    let r = crate::systemd::render_runner_unit(&eff)
        .expect("render_runner_unit must succeed for normalized spec");
    assert!(
        !r.drop_ins.contains_key("50-numa.conf"),
        "Some(empty) allowed_cpus and allowed_memory_nodes must NOT trigger 50-numa.conf emission via the lower_to_effective→render pipeline; got drop-ins: {:?}",
        r.drop_ins.keys().collect::<Vec<_>>()
    );
}

/// Parallel pin for `runner_sha256` normalization. `render_identity`
/// emits X-Ghars-Runner-Sha256 only on `Some(non-empty)` so `Some("")`
/// and `None` render identically but pre-normalization differed in
/// `spec_hash`.
#[test]
fn merge_defaults_collapses_some_empty_runner_sha256_to_none() {
    let mut runner = minimal_runner("a");
    runner.runner_sha256 = Some(String::new());
    let defaults = Defaults::default();
    let spec = merge_defaults(
        &runner,
        &defaults,
        "pat".into(),
        vec![],
        None,
        None,
        None,
        Arch::X86_64,
        cfg_source_default(),
    );
    assert_eq!(spec.runner_sha256, None);

    let mut none_runner = minimal_runner("a");
    none_runner.runner_sha256 = None;
    let none_spec = merge_defaults(
        &none_runner,
        &defaults,
        "pat".into(),
        vec![],
        None,
        None,
        None,
        Arch::X86_64,
        cfg_source_default(),
    );
    assert_eq!(
        spec_hash(&spec),
        spec_hash(&none_spec),
        "Some(empty) and None must produce identical spec_hash after normalization"
    );
}

/// Parallel pin for `runner_tarball` normalization. `render_identity`
/// emits `X-Ghars-Runner-Tarball-Hash` only on `Some(non-empty)` —
/// `Some(Utf8PathBuf::from(""))` would hash the empty string and emit
/// `sha256:e3b0c44...` while `None` emits no line at all, producing
/// different drop-in bytes from cosmetically-equivalent direct-
/// construct input. Sister to the `memory_max` + `runner_sha256`
/// normalization pattern at merge.rs. (Operator TOML cannot reach
/// this filter — `validate_runner_tarball` at config-load rejects
/// empty paths; this pin guards the defense-in-depth path for
/// direct-construct callers that bypass `cli::load`.)
#[test]
fn merge_defaults_collapses_some_empty_runner_tarball_to_none() {
    let mut runner = minimal_runner("a");
    runner.runner_tarball = Some(Utf8PathBuf::from(""));
    let defaults = Defaults::default();
    let spec = merge_defaults(
        &runner,
        &defaults,
        "pat".into(),
        vec![],
        None,
        None,
        None,
        Arch::X86_64,
        cfg_source_default(),
    );
    assert_eq!(spec.runner_tarball, None);

    let mut none_runner = minimal_runner("a");
    none_runner.runner_tarball = None;
    let none_spec = merge_defaults(
        &none_runner,
        &defaults,
        "pat".into(),
        vec![],
        None,
        None,
        None,
        Arch::X86_64,
        cfg_source_default(),
    );
    assert_eq!(
        spec_hash(&spec),
        spec_hash(&none_spec),
        "Some(empty) and None for runner_tarball must produce identical spec_hash after normalization"
    );
}

/// Pin `ProxySpec::is_empty` contract. Mirrors the field set
/// `render_proxy` early-returns Ok(None) on (units.rs `render_proxy`:
/// `http.is_none() && https.is_none() && no_proxy.is_empty() &&
/// ca_certs.is_empty()`). The `is_empty` method is what the
/// `lower_to_effective` normalization filter uses to collapse
/// `Some(empty)` to `None`.
///
/// Exercises EVERY non-empty field path individually so a typo-style
/// regression that drops one field from the && chain (e.g. duplicating
/// `http.is_none() && http.is_none() && ...` instead of going through
/// all four) fails immediately at the dropped field's assertion.
#[test]
fn proxy_spec_is_empty_matches_render_proxy_early_return() {
    let empty = crate::config::ProxySpec::default();
    assert!(empty.is_empty());

    let with_http = crate::config::ProxySpec {
        http: Some("http://proxy".into()),
        ..crate::config::ProxySpec::default()
    };
    assert!(!with_http.is_empty());

    let with_https = crate::config::ProxySpec {
        https: Some("http://proxy".into()),
        ..crate::config::ProxySpec::default()
    };
    assert!(!with_https.is_empty());

    let with_no_proxy = crate::config::ProxySpec {
        no_proxy: vec!["host".into()],
        ..crate::config::ProxySpec::default()
    };
    assert!(!with_no_proxy.is_empty());

    let with_ca_certs = crate::config::ProxySpec {
        ca_certs: vec![crate::config::CaCertBinding {
            env: "REQUESTS_CA_BUNDLE".into(),
            path: Utf8PathBuf::from("/etc/ghars/ca-bundle.pem"),
        }],
        ..crate::config::ProxySpec::default()
    };
    assert!(!with_ca_certs.is_empty());
}

/// Pin `HooksSpec::is_empty` contract. Mirrors `render_hooks`'s early-
/// return condition: `pre_job.is_none() && post_job.is_none()`.
///
/// Exercises both non-empty field paths individually so a typo-style
/// regression that drops one field from the && chain (e.g.
/// `pre_job.is_none() && pre_job.is_none()`) fails immediately at the
/// dropped field's assertion.
#[test]
fn hooks_spec_is_empty_matches_render_hooks_early_return() {
    let empty = crate::config::HooksSpec::default();
    assert!(empty.is_empty());

    let with_pre = crate::config::HooksSpec {
        pre_job: Some(Utf8PathBuf::from("/etc/ghars/hooks/pre.sh")),
        post_job: None,
    };
    assert!(!with_pre.is_empty());

    let with_post = crate::config::HooksSpec {
        pre_job: None,
        post_job: Some(Utf8PathBuf::from("/etc/ghars/hooks/post.sh")),
    };
    assert!(!with_post.is_empty());
}

/// Pin the `lower_to_effective` integration: an operator-typed
/// `[proxy]` block with all fields empty collapses to None on the
/// resulting `EffectiveRunnerSpec`, AND the `spec_hash` matches the
/// genuinely-absent (config.proxy = None) case.
/// `proxy_spec_is_empty_matches_render_proxy_early_return` above
/// pins the `is_empty` predicate in isolation; this test pins that
/// the predicate is actually plumbed into the resolver chain via
/// the `.filter(|p| !p.is_empty())` call at compute.rs. A regression
/// that removed the filter (keeping the `is_empty` method) would
/// pass the predicate test but fail here.
#[test]
fn lower_to_effective_collapses_some_empty_proxy_to_none() {
    let mut cfg_empty_proxy = config_with_runners(vec![minimal_runner("a")]);
    cfg_empty_proxy.proxy = Some(crate::config::ProxySpec::default());
    let expanded = expand_counts(&cfg_empty_proxy).expect("count expansion must succeed");
    let eff_empty = lower_to_effective(
        &expanded[0],
        &cfg_empty_proxy,
        Arch::X86_64,
        cfg_source_default(),
        0,
    )
    .expect("lower_to_effective must succeed");
    assert_eq!(
        eff_empty.proxy, None,
        "Some(empty ProxySpec) at config layer must collapse to None on EffectiveRunnerSpec"
    );

    let mut cfg_no_proxy = config_with_runners(vec![minimal_runner("a")]);
    cfg_no_proxy.proxy = None;
    let expanded_none = expand_counts(&cfg_no_proxy).expect("count expansion must succeed");
    let eff_none = lower_to_effective(
        &expanded_none[0],
        &cfg_no_proxy,
        Arch::X86_64,
        cfg_source_default(),
        0,
    )
    .expect("lower_to_effective must succeed");
    assert_eq!(
        spec_hash(&eff_empty),
        spec_hash(&eff_none),
        "Some(empty) proxy must produce identical spec_hash to None after normalization — dark input eliminated"
    );
}

// ---- dns/ipv6 fixture helper -----

/// Build an `EffectiveRunnerSpec` with a Netns network binding
/// carrying the given `dns` + `ipv6` modes. Used across the
/// dns/ipv6 round-trip + classifier tests that follow, which all
/// pin the binding shape (name=`isolated`, mode=Netns, all
/// egress/IP/family vecs empty, subnet=None) and vary only the two
/// annotation fields. Computes and stores `spec_hash` so the
/// result is render-ready.
fn spec_with_network(dns: DnsMode, ipv6: Ipv6Mode) -> EffectiveRunnerSpec {
    let defaults = Defaults::default();
    let mut spec = merge_defaults(
        &minimal_runner("a"),
        &defaults,
        "pat".into(),
        vec![],
        None,
        None,
        None,
        Arch::X86_64,
        cfg_source_default(),
    );
    spec.network = Some(EffectiveNetworkBinding {
        name: "isolated".into(),
        spec: NetworkSpec {
            mode: NetworkMode::Netns,
            allowed_egress: vec![],
            ip_allow: vec![],
            ip_deny: vec![],
            restrict_address_families: vec![],
            dns,
            ipv6,
        },
        subnet: None,
    });
    spec.spec_hash = spec_hash(&spec);
    spec
}

/// End-to-end pin for dns/ipv6 annotation contract: render
/// emits X-Ghars-Dns + X-Ghars-Ipv6 → `DiscoveredAnnotations` parser
/// round-trips them → classifier emits `FieldChange` (in-place, NOT
/// a recreate reason) when desired dns differs from discovered.
///
/// Pins the full Stage 1 chain so a regression at any layer fails
/// immediately: render-emission missing → parser sees None →
/// classifier skips → uncovered warn fires. Parser round-trip
/// broken → classifier compares None vs Some → skip. Classifier
/// arm missing → no `FieldChange` → uncovered warn fires when dns
/// is the lone change.
#[test]
fn dns_ipv6_annotations_round_trip_and_route_in_place() {
    use crate::plan::FieldChange;

    let discovered_spec = spec_with_network(DnsMode::Forward, Ipv6Mode::Disabled);
    let desired_spec = spec_with_network(
        DnsMode::Static {
            servers: vec!["1.1.1.1".parse().unwrap()],
        },
        Ipv6Mode::Disabled,
    );

    let rendered = crate::systemd::render_runner_unit(&discovered_spec).unwrap();
    let body = rendered.drop_ins.get("00-ghars.conf").unwrap();

    let anns = DiscoveredAnnotations::from_drop_in_body(body);
    assert_eq!(
        anns.dns,
        Some(DnsMode::Forward),
        "X-Ghars-Dns must round-trip through render → parse"
    );
    assert_eq!(
        anns.ipv6,
        Some(Ipv6Mode::Disabled),
        "X-Ghars-Ipv6 must round-trip through render → parse"
    );

    let mut out_changes: Vec<FieldChange> = Vec::new();
    let recreate_reasons =
        classify_recreate_reasons_from_annotations(&anns, &desired_spec, &mut out_changes);

    assert!(
        !recreate_reasons.iter().any(|r| *r == "dns" || *r == "ipv6"),
        "dns/ipv6 changes must NOT push recreate reasons (in-place only); got: {recreate_reasons:?}"
    );
    let dns_change = out_changes.iter().find(|c| c.path == "dns");
    assert!(
        dns_change.is_some(),
        "dns change must emit a FieldChange (in-place signal); got: {out_changes:?}"
    );
}

/// Round-trip pin for `DnsMode::Static { servers }` — the
/// non-trivial annotation shape carrying a server-list payload.
/// `DnsMode::Forward` renders as the literal `forward` (no payload);
/// `Static` renders as `static:<comma-csv-of-ips>` via
/// `crate::config::dns_to_annotation`. A parser bug that handles
/// Forward but not Static would slip through the sibling test
/// which only covers Forward → Static (Forward is the discovered
/// value there). Discovered = Static here forces the parser to
/// read back the payload vec.
#[test]
fn dns_static_with_servers_round_trips_through_render_parse_classify() {
    use crate::plan::FieldChange;

    let discovered_static = DnsMode::Static {
        servers: vec!["8.8.8.8".parse().unwrap(), "8.8.4.4".parse().unwrap()],
    };
    let desired_static = DnsMode::Static {
        servers: vec!["1.1.1.1".parse().unwrap()],
    };
    let discovered_spec = spec_with_network(discovered_static.clone(), Ipv6Mode::Disabled);
    let desired_spec = spec_with_network(desired_static, Ipv6Mode::Disabled);

    let rendered = crate::systemd::render_runner_unit(&discovered_spec).unwrap();
    let body = rendered.drop_ins.get("00-ghars.conf").unwrap();
    assert!(
        body.contains("\nX-Ghars-Dns=static:8.8.8.8,8.8.4.4\n"),
        "DnsMode::Static must emit `static:<comma-csv>` form; got:\n{body}"
    );

    let anns = DiscoveredAnnotations::from_drop_in_body(body);
    assert_eq!(
        anns.dns,
        Some(discovered_static),
        "X-Ghars-Dns Static payload must round-trip through render → parse with servers preserved"
    );

    let mut out_changes: Vec<FieldChange> = Vec::new();
    let recreate_reasons =
        classify_recreate_reasons_from_annotations(&anns, &desired_spec, &mut out_changes);

    assert!(
        !recreate_reasons.iter().any(|r| *r == "dns" || *r == "ipv6"),
        "Static→Static dns change must NOT push recreate reasons; got: {recreate_reasons:?}"
    );
    let dns_change = out_changes
        .iter()
        .find(|c| c.path == "dns")
        .expect("Static→Static change must emit a dns FieldChange");
    assert!(
        matches!(
            &dns_change.before,
            FieldValue::String(s) if s == "static:8.8.8.8,8.8.4.4"
        ),
        "dns FieldChange.before must use operator-facing static:csv form; got: {:?}",
        dns_change.before
    );
    assert!(
        matches!(
            &dns_change.after,
            FieldValue::String(s) if s == "static:1.1.1.1"
        ),
        "dns FieldChange.after must use operator-facing static:csv form; got: {:?}",
        dns_change.after
    );
}

/// Coverage for the ipv6 classifier arm — the sibling
/// `dns_ipv6_annotations_round_trip_and_route_in_place` only flips
/// dns, leaving ipv6 identical between discovered and desired, so
/// the ipv6 `FieldChange` branch never executes there. A future
/// regression that breaks the ipv6 comparator (e.g. wrong variant
/// match) would pass that test. Constructs the `EffectiveRunnerSpec`
/// directly so the apply-time `Ipv6Mode::Enabled` hard-error
/// (config-load gate) doesn't fire — the classifier arm itself
/// must work in both directions for the future-enabled case.
#[test]
fn ipv6_classifier_arm_routes_in_place_field_change() {
    use crate::plan::FieldChange;

    let discovered_spec = spec_with_network(DnsMode::Forward, Ipv6Mode::Disabled);
    let desired_spec = spec_with_network(DnsMode::Forward, Ipv6Mode::Enabled);

    let rendered = crate::systemd::render_runner_unit(&discovered_spec).unwrap();
    let body = rendered.drop_ins.get("00-ghars.conf").unwrap();

    let anns = DiscoveredAnnotations::from_drop_in_body(body);
    assert_eq!(anns.ipv6, Some(Ipv6Mode::Disabled));

    let mut out_changes: Vec<FieldChange> = Vec::new();
    let recreate_reasons =
        classify_recreate_reasons_from_annotations(&anns, &desired_spec, &mut out_changes);

    assert!(
        !recreate_reasons.iter().any(|r| *r == "dns" || *r == "ipv6"),
        "ipv6 change must NOT push recreate reasons; got: {recreate_reasons:?}"
    );
    let ipv6_change = out_changes
        .iter()
        .find(|c| c.path == "ipv6")
        .expect("ipv6 change must emit a FieldChange (in-place signal)");
    assert!(
        matches!(
            &ipv6_change.before,
            FieldValue::String(s) if s == "disabled"
        ),
        "ipv6 FieldChange.before must be snake_case enum string; got: {:?}",
        ipv6_change.before
    );
    assert!(
        matches!(
            &ipv6_change.after,
            FieldValue::String(s) if s == "enabled"
        ),
        "ipv6 FieldChange.after must be snake_case enum string; got: {:?}",
        ipv6_change.after
    );
}

/// Legacy-runner contract: a drop-in body without `X-Ghars-Dns` /
/// `X-Ghars-Ipv6` lines (the on-disk state of any runner created
/// before those annotations were emitted) yields
/// `DiscoveredAnnotations { dns: None, ipv6: None, .. }`. The
/// classifier MUST skip its dns/ipv6 arms in that case — otherwise
/// every legacy runner would emit a spurious dns/ipv6 `FieldChange` on
/// the first post-upgrade plan.
///
/// Routes the missing annotations into the uncovered arm (which is
/// in-place — see `compute::plan_from`'s fallback), so the in-place
/// rewrite re-establishes the drop-in including the new annotations;
/// the second plan classifies cleanly with full annotation coverage.
#[test]
fn legacy_runner_without_dns_ipv6_annotations_skips_classifier_arms() {
    use crate::plan::FieldChange;

    // Simulate a legacy drop-in body: every annotation the older
    // renderer would write EXCEPT X-Ghars-Dns and X-Ghars-Ipv6.
    let legacy_body = "\
[Unit]
X-Ghars-Managed=true
X-Ghars-Schema-Version=1
X-Ghars-Renderer-Schema=3
X-Ghars-Runner-Url=https://github.com/owner/repo
X-Ghars-Auth-Name=pat
X-Ghars-Trust-Zone=default
X-Ghars-Network-Mode=netns
X-Ghars-Labels=
X-Ghars-Caches=
";
    let anns = DiscoveredAnnotations::from_drop_in_body(legacy_body);
    assert_eq!(anns.dns, None, "annotation-absent body must yield dns=None");
    assert_eq!(
        anns.ipv6, None,
        "annotation-absent body must yield ipv6=None"
    );

    let desired_spec = spec_with_network(
        DnsMode::Static {
            servers: vec!["1.1.1.1".parse().unwrap()],
        },
        Ipv6Mode::Enabled,
    );

    let mut out_changes: Vec<FieldChange> = Vec::new();
    let _ = classify_recreate_reasons_from_annotations(&anns, &desired_spec, &mut out_changes);

    assert!(
        !out_changes.iter().any(|c| c.path == "dns"),
        "pre-fix runner (dns annotation absent) must NOT emit a dns FieldChange; got: {out_changes:?}"
    );
    assert!(
        !out_changes.iter().any(|c| c.path == "ipv6"),
        "pre-fix runner (ipv6 annotation absent) must NOT emit an ipv6 FieldChange; got: {out_changes:?}"
    );
}

/// Graceful degradation: malformed `X-Ghars-Dns` (unknown prefix
/// or unparseable IP) and `X-Ghars-Ipv6` (unknown string) parse to
/// `None`, matching the absent-annotation behavior. Operator-edited
/// drop-ins or a future schema bump that writes an incompatible
/// shape must not crash the planner or emit a spurious change —
/// they degrade to the legacy-runner path (skip → uncovered →
/// in-place rewrite re-establishes correct annotations on next
/// apply).
///
/// Non-empty unparseable input also emits a `tracing::warn!` so
/// the operator gets a journal hint instead of a silent skip; the
/// warning is asserted via `tracing-test`. Empty input stays silent
/// (treated identically to absent annotation — the legacy-runner
/// path emits no diagnostic so a fresh upgrade doesn't flood the
/// log with warns for every legacy runner discovered).
#[test]
#[tracing_test::traced_test]
fn malformed_dns_ipv6_annotations_degrade_to_none_parse() {
    let unknown_prefix_body = "\
[Unit]
X-Ghars-Dns=forwarding
X-Ghars-Ipv6=on
";
    let anns = DiscoveredAnnotations::from_drop_in_body(unknown_prefix_body);
    assert_eq!(
        anns.dns, None,
        "unknown dns prefix (`forwarding`) must parse to None, not crash"
    );
    assert_eq!(
        anns.ipv6, None,
        "unknown Ipv6Mode string (`on`) must parse to None, not crash"
    );
    assert!(
        logs_contain("unrecognized prefix"),
        "unknown dns prefix must emit a tracing::warn so operators see the malformed value"
    );
    assert!(
        logs_contain("expected `disabled` or `enabled`"),
        "unknown ipv6 value must emit a tracing::warn so operators see the malformed value"
    );

    let bad_ip_body = "\
[Unit]
X-Ghars-Dns=static:1.1.1.1,not-an-ip
X-Ghars-Ipv6=
";
    let anns = DiscoveredAnnotations::from_drop_in_body(bad_ip_body);
    assert_eq!(
        anns.dns, None,
        "`static:` with an unparseable IP token must parse to None (one bad token rejects the whole list)"
    );
    assert_eq!(
        anns.ipv6, None,
        "empty X-Ghars-Ipv6 must parse to None (no false-default to Disabled)"
    );
    assert!(
        logs_contain("unparseable IP"),
        "bad-IP-in-static-list must emit a tracing::warn so operators see the malformed value"
    );
}

/// Inverse: empty annotation value (`X-Ghars-Dns=` or `X-Ghars-Ipv6=`
/// with no payload) MUST stay silent — no `tracing::warn!`. Empty
/// is the legacy-runner / annotation-absent path; warning on every
/// legacy runner would flood the log during the first plan after
/// upgrade.
#[test]
#[tracing_test::traced_test]
fn empty_dns_ipv6_annotation_values_silent_no_warn() {
    let empty_body = "\
[Unit]
X-Ghars-Dns=
X-Ghars-Ipv6=
";
    let anns = DiscoveredAnnotations::from_drop_in_body(empty_body);
    assert_eq!(anns.dns, None);
    assert_eq!(anns.ipv6, None);
    // Assert the precise warn-substring shapes that the malformed
    // test pins as present — survives a future warn-text rephrase
    // that drops `X-Ghars-Dns` / `X-Ghars-Ipv6` literals from the
    // message text (the broader substring would silently pass even
    // if the warn DID emit).
    assert!(
        !logs_contain("unrecognized prefix"),
        "empty X-Ghars-Dns must NOT emit the unrecognized-prefix warn (legacy-runner contract)"
    );
    assert!(
        !logs_contain("unparseable IP"),
        "empty X-Ghars-Dns must NOT emit the unparseable-IP warn (legacy-runner contract)"
    );
    assert!(
        !logs_contain("expected `disabled` or `enabled`"),
        "empty X-Ghars-Ipv6 must NOT emit the unknown-value warn (legacy-runner contract)"
    );
}

/// Asymmetry-guard pin: when desired removes the network ref
/// entirely (`desired.network = None`), the dns + ipv6 classifier
/// arms MUST skip — they're `NetworkSpec` sub-fields and don't exist
/// without a network binding. Without this guard the dns arm would
/// emit `before=<discovered> → after=""` (empty-string fallback via
/// `unwrap_or_default()`) while the ipv6 arm would emit `before=
/// <discovered> → after="disabled"` (Disabled default via
/// `unwrap_or`) — asymmetric ghost-FieldChanges representing the
/// same "network removed" semantic in two different ways. The
/// network-mode classifier is the real signal for network removal;
/// dns/ipv6 are sub-field noise once network is gone.
#[test]
fn classifier_skips_dns_ipv6_when_desired_removes_network() {
    use crate::plan::FieldChange;

    let defaults = Defaults::default();
    let mut desired_spec = merge_defaults(
        &minimal_runner("a"),
        &defaults,
        "pat".into(),
        vec![],
        None,
        None,
        None,
        Arch::X86_64,
        cfg_source_default(),
    );
    assert!(
        desired_spec.network.is_none(),
        "minimal_runner has no network binding — desired.network = None"
    );
    desired_spec.spec_hash = spec_hash(&desired_spec);

    // Simulate a prior-state drop-in carrying dns + ipv6 annotations
    // (operator HAD a netns network with custom dns, now removed
    // the network ref entirely). Parses via the production
    // `from_drop_in_body` path so the discovered values match what
    // the renderer would have written on disk.
    let prior_body = "\
[Unit]
X-Ghars-Network-Mode=netns
X-Ghars-Dns=static:1.1.1.1
X-Ghars-Ipv6=enabled
";
    let anns = DiscoveredAnnotations::from_drop_in_body(prior_body);
    assert_eq!(
        anns.dns,
        Some(DnsMode::Static {
            servers: vec!["1.1.1.1".parse().unwrap()]
        }),
        "prior body must round-trip to Some(DnsMode::Static{{...}})"
    );
    assert_eq!(
        anns.ipv6,
        Some(Ipv6Mode::Enabled),
        "prior body must round-trip to Some(Ipv6Mode::Enabled)"
    );

    let mut out_changes: Vec<FieldChange> = Vec::new();
    let _ = classify_recreate_reasons_from_annotations(&anns, &desired_spec, &mut out_changes);

    assert!(
        !out_changes.iter().any(|c| c.path == "dns"),
        "dns FieldChange MUST NOT emit when desired.network = None (avoid ghost `→ \"\"`); got: {out_changes:?}"
    );
    assert!(
        !out_changes.iter().any(|c| c.path == "ipv6"),
        "ipv6 FieldChange MUST NOT emit when desired.network = None (avoid ghost `→ disabled`); got: {out_changes:?}"
    );
}

/// Inverse-direction pin: when discovered dns/ipv6 match desired,
/// the classifier MUST NOT emit `FieldChange` entries. A bug that
/// always-pushes regardless of equality would surface a noisy
/// no-op plan and pollute `out_changes`; a bug in the equality
/// check (e.g. comparing `Option<&DnsMode>` against the wrong
/// reference) would also slip in here.
#[test]
fn identical_dns_ipv6_emit_no_field_change() {
    use crate::plan::FieldChange;

    let make_spec = || {
        spec_with_network(
            DnsMode::Static {
                servers: vec!["1.1.1.1".parse().unwrap()],
            },
            Ipv6Mode::Disabled,
        )
    };
    let discovered_spec = make_spec();
    let desired_spec = make_spec();

    let rendered = crate::systemd::render_runner_unit(&discovered_spec).unwrap();
    let body = rendered.drop_ins.get("00-ghars.conf").unwrap();
    let anns = DiscoveredAnnotations::from_drop_in_body(body);
    assert_eq!(
        anns.dns,
        Some(DnsMode::Static {
            servers: vec!["1.1.1.1".parse().unwrap()]
        })
    );
    assert_eq!(anns.ipv6, Some(Ipv6Mode::Disabled));

    let mut out_changes: Vec<FieldChange> = Vec::new();
    let _ = classify_recreate_reasons_from_annotations(&anns, &desired_spec, &mut out_changes);

    assert!(
        !out_changes.iter().any(|c| c.path == "dns"),
        "identical dns must NOT emit FieldChange; got: {out_changes:?}"
    );
    assert!(
        !out_changes.iter().any(|c| c.path == "ipv6"),
        "identical ipv6 must NOT emit FieldChange; got: {out_changes:?}"
    );
}

// ---- dns/ipv6 helper-level parse-edge-cases -----------------------

/// Group A: helper-level pins for the documented but untested
/// whitespace-warn contract on `dns_from_annotation` /
/// `ipv6_from_annotation`. The doc-comments on both helpers in
/// `crate::config` promise non-empty unparseable input fires
/// `tracing::warn!` regardless of whitespace shape — pin that with
/// direct helper calls. Empty input stays silent (already pinned by
/// `empty_dns_ipv6_annotation_values_silent_no_warn`).
///
/// These are direct-call-only tests: per the helpers' doc-comments,
/// the end-to-end body-parse path is mediated by
/// `ParsedUnit::from_text`'s `value.trim()` at state.rs, which
/// silently strips whitespace before the helper sees it. The
/// whitespace-warn contract therefore only fires for hypothetical
/// non-systemd-mediated call sites (test fixtures, future synthetic
/// builders). `whitespace_in_drop_in_body_silent_due_to_upstream_trim`
/// below pins the body-parse complement explicitly.
#[test]
#[tracing_test::traced_test]
fn dns_whitespace_only_warns_at_helper_level() {
    use crate::config::dns_from_annotation;

    assert_eq!(
        dns_from_annotation(" "),
        None,
        "single-space input must parse to None (unrecognized prefix arm)"
    );
    assert_eq!(
        dns_from_annotation("\t"),
        None,
        "tab input must parse to None (unrecognized prefix arm)"
    );
    assert!(
        logs_contain("unrecognized prefix"),
        "whitespace dns input must fire the helper-level unrecognized-prefix warn"
    );
}

#[test]
#[tracing_test::traced_test]
fn ipv6_whitespace_only_warns_at_helper_level() {
    use crate::config::ipv6_from_annotation;

    assert_eq!(
        ipv6_from_annotation(" "),
        None,
        "single-space input must parse to None (unknown-value arm)"
    );
    assert_eq!(
        ipv6_from_annotation("\t"),
        None,
        "tab input must parse to None (unknown-value arm)"
    );
    assert!(
        logs_contain("expected `disabled` or `enabled`"),
        "whitespace ipv6 input must fire the helper-level unknown-value warn"
    );
}

/// Group B: end-to-end complement to the whitespace helper tests.
/// `X-Ghars-Dns= ` / `X-Ghars-Ipv6= ` in a real drop-in body MUST
/// take the silent legacy-runner path — `ParsedUnit::from_text`
/// trims whitespace from values BEFORE they reach
/// `dns_from_annotation` / `ipv6_from_annotation`, so the helper
/// sees `""` (the silent-empty arm), not the whitespace.
///
/// This pins the upstream-trim invariant from the operator's
/// perspective: a hand-edited drop-in with stray whitespace after
/// `=` does NOT flood the journal with warns on every plan, even
/// though the helper-level whitespace contract says whitespace
/// warns. The mediator (`ParsedUnit::from_text`) is load-bearing
/// here — removing its `.trim()` would silently flip body-parse
/// behavior to fire the warn for every legacy/empty annotation.
#[test]
#[tracing_test::traced_test]
fn whitespace_in_drop_in_body_silent_due_to_upstream_trim() {
    // Both annotations carry whitespace-only values (single space
    // on dns, single tab on ipv6) — different whitespace chars so a
    // regression that handled only one would surface. Both values
    // must be eaten by ParsedUnit::from_text's `value.trim()` before
    // reaching the helpers.
    //
    // Whitespace is emitted via explicit \x20 / \t escapes to
    // survive any editor or pre-commit hook that auto-strips
    // trailing whitespace from source files.
    let whitespace_body = "[Unit]\nX-Ghars-Dns=\x20\nX-Ghars-Ipv6=\t\n";
    let anns = DiscoveredAnnotations::from_drop_in_body(whitespace_body);
    assert_eq!(
        anns.dns, None,
        "whitespace-only X-Ghars-Dns body value must parse to None (via upstream-trim → silent-empty path)"
    );
    assert_eq!(
        anns.ipv6, None,
        "whitespace-only X-Ghars-Ipv6 body value must parse to None (via upstream-trim → silent-empty path)"
    );
    assert!(
        !logs_contain("unrecognized prefix"),
        "body-parsed whitespace dns must NOT fire the helper-level warn — upstream trim eats it (legacy-runner contract)"
    );
    assert!(
        !logs_contain("expected `disabled` or `enabled`"),
        "body-parsed whitespace ipv6 must NOT fire the helper-level warn — upstream trim eats it"
    );
}

/// Group A: `dns_from_annotation` parse edge cases — `static:`
/// with empty payload, single IP, leading/trailing comma, extra
/// data after `forward`. Pins behaviors that production code
/// asserts but no test exercises directly; protects against a
/// future refactor that tightens or loosens the parse boundary.
#[test]
#[tracing_test::traced_test]
fn dns_static_empty_payload_parses_to_empty_vec_silently() {
    use crate::config::{DnsMode, dns_from_annotation};

    assert_eq!(
        dns_from_annotation("static:"),
        Some(DnsMode::Static {
            servers: Vec::new(),
        }),
        "`static:` with no payload must parse to Some(Static{{servers: vec![]}}) per doc-comment contract"
    );
    assert!(
        !logs_contain("unrecognized prefix"),
        "`static:` empty payload must NOT fire unrecognized-prefix warn"
    );
    assert!(
        !logs_contain("unparseable IP"),
        "`static:` empty payload must NOT fire unparseable-IP warn"
    );
}

#[test]
#[tracing_test::traced_test]
fn dns_static_trailing_comma_rejects_with_warn() {
    use crate::config::dns_from_annotation;

    assert_eq!(
        dns_from_annotation("static:1.1.1.1,"),
        None,
        "trailing comma yields empty token → IP::parse fails → whole list rejected"
    );
    assert!(
        logs_contain("unparseable IP"),
        "trailing-comma rejection must fire the unparseable-IP warn"
    );
}

#[test]
#[tracing_test::traced_test]
fn dns_static_leading_comma_rejects_with_warn() {
    use crate::config::dns_from_annotation;

    assert_eq!(
        dns_from_annotation("static:,1.1.1.1"),
        None,
        "leading comma yields empty token → IP::parse fails → whole list rejected"
    );
    assert!(
        logs_contain("unparseable IP"),
        "leading-comma rejection must fire the unparseable-IP warn"
    );
}

#[test]
#[tracing_test::traced_test]
fn dns_forward_with_extra_data_rejects_with_warn() {
    use crate::config::dns_from_annotation;

    assert_eq!(
        dns_from_annotation("forward,extra"),
        None,
        "`forward` is matched exact-equal; suffix data must reject (not match-and-discard)"
    );
    assert!(
        logs_contain("unrecognized prefix"),
        "`forward` with suffix must fire unrecognized-prefix warn"
    );
}

#[test]
#[tracing_test::traced_test]
fn dns_case_sensitive_rejects_capitalized() {
    use crate::config::dns_from_annotation;

    assert_eq!(
        dns_from_annotation("Forward"),
        None,
        "`Forward` (capitalized) must reject — helper uses exact `s == \"forward\"` (case-sensitive)"
    );
    assert!(
        logs_contain("unrecognized prefix"),
        "case-mismatch on `Forward` must fire unrecognized-prefix warn"
    );
}

#[test]
#[tracing_test::traced_test]
fn ipv6_case_sensitive_rejects_capitalized() {
    use crate::config::ipv6_from_annotation;

    assert_eq!(
        ipv6_from_annotation("Disabled"),
        None,
        "`Disabled` (capitalized) must reject — helper uses exact pattern match (case-sensitive)"
    );
    assert_eq!(
        ipv6_from_annotation("Enabled"),
        None,
        "`Enabled` (capitalized) must reject — helper uses exact pattern match (case-sensitive)"
    );
    assert!(
        logs_contain("expected `disabled` or `enabled`"),
        "case-mismatch on ipv6 must fire unknown-value warn"
    );
}

/// Group C: classifier inverse-direction pins. Existing tests
/// cover Forward → Static (Static after default Forward) via
/// `dns_ipv6_annotations_round_trip_and_route_in_place`, and
/// Disabled → Enabled via
/// `ipv6_classifier_arm_routes_in_place_field_change`. These pin
/// the opposite directions to catch a future asymmetric refactor.
#[test]
fn classifier_routes_dns_static_to_forward_field_change() {
    use crate::plan::FieldChange;

    let discovered_spec = spec_with_network(
        DnsMode::Static {
            servers: vec!["8.8.8.8".parse().unwrap()],
        },
        Ipv6Mode::Disabled,
    );
    let desired_spec = spec_with_network(DnsMode::Forward, Ipv6Mode::Disabled);

    let rendered = crate::systemd::render_runner_unit(&discovered_spec).unwrap();
    let body = rendered.drop_ins.get("00-ghars.conf").unwrap();
    let anns = DiscoveredAnnotations::from_drop_in_body(body);
    assert_eq!(
        anns.dns,
        Some(DnsMode::Static {
            servers: vec!["8.8.8.8".parse().unwrap()],
        }),
        "discovered must round-trip to Static"
    );

    let mut out_changes: Vec<FieldChange> = Vec::new();
    let _ = classify_recreate_reasons_from_annotations(&anns, &desired_spec, &mut out_changes);

    assert!(
        out_changes.iter().any(|c| c.path == "dns"),
        "Static → Forward MUST emit a dns FieldChange (operator removing custom DNS); got: {out_changes:?}"
    );
}

#[test]
fn classifier_routes_ipv6_enabled_to_disabled_field_change() {
    use crate::plan::FieldChange;

    let discovered_spec = spec_with_network(DnsMode::Forward, Ipv6Mode::Enabled);
    let desired_spec = spec_with_network(DnsMode::Forward, Ipv6Mode::Disabled);

    let rendered = crate::systemd::render_runner_unit(&discovered_spec).unwrap();
    let body = rendered.drop_ins.get("00-ghars.conf").unwrap();
    let anns = DiscoveredAnnotations::from_drop_in_body(body);
    assert_eq!(anns.ipv6, Some(Ipv6Mode::Enabled));

    let mut out_changes: Vec<FieldChange> = Vec::new();
    let _ = classify_recreate_reasons_from_annotations(&anns, &desired_spec, &mut out_changes);

    assert!(
        out_changes.iter().any(|c| c.path == "ipv6"),
        "Enabled → Disabled MUST emit an ipv6 FieldChange; got: {out_changes:?}"
    );
}

/// Group D: round-trip Static-empty render → parse symmetry.
/// `dns_to_annotation(Static{vec![]})` emits `static:` (empty
/// payload after the colon). `dns_from_annotation("static:")`
/// returns `Some(Static{vec![]})`. Validators reject this at
/// config-load but the round-trip-safety property is independent
/// of validator policy — a hand-edited drop-in or future schema
/// change might surface this shape and the round-trip must not
/// corrupt it. Pin both halves of the symmetry.
#[test]
fn dns_static_empty_round_trips_through_render_parse() {
    use crate::config::{DnsMode, dns_from_annotation, dns_to_annotation};

    let empty_static = DnsMode::Static {
        servers: Vec::new(),
    };
    let rendered = dns_to_annotation(&empty_static);
    assert_eq!(
        rendered, "static:",
        "Static{{vec![]}} must render as exactly `static:` (no trailing CSV bytes)"
    );
    let parsed = dns_from_annotation(&rendered);
    assert_eq!(
        parsed,
        Some(empty_static),
        "rendered `static:` must round-trip back through dns_from_annotation to Static{{vec![]}}"
    );
}

/// Group C: classifier server-priority reorder pin.
/// `DnsMode::Static.servers: Vec<IpAddr>` is order-sensitive by
/// design — resolv.conf treats the server list as a priority
/// order, so swapping `[A, B]` to `[B, A]` is a semantic change
/// the operator may intentionally make to flip which resolver
/// is tried first. The classifier MUST emit a dns `FieldChange` in
/// this case. A defense-in-depth regression that added set-semantic
/// sort at the parse boundary (mirroring the labels/caches
/// canonical-order sort) would silently flatten the operator's
/// reorder intent and skip the `FieldChange`.
#[test]
fn classifier_routes_dns_static_server_reorder_field_change() {
    use crate::plan::FieldChange;

    let ip_a: std::net::IpAddr = "1.1.1.1".parse().unwrap();
    let ip_b: std::net::IpAddr = "8.8.8.8".parse().unwrap();

    let discovered_spec = spec_with_network(
        DnsMode::Static {
            servers: vec![ip_a, ip_b],
        },
        Ipv6Mode::Disabled,
    );
    let desired_spec = spec_with_network(
        DnsMode::Static {
            servers: vec![ip_b, ip_a],
        },
        Ipv6Mode::Disabled,
    );

    let rendered = crate::systemd::render_runner_unit(&discovered_spec).unwrap();
    let body = rendered.drop_ins.get("00-ghars.conf").unwrap();
    let anns = DiscoveredAnnotations::from_drop_in_body(body);
    assert_eq!(
        anns.dns,
        Some(DnsMode::Static {
            servers: vec![ip_a, ip_b],
        }),
        "discovered must round-trip preserving server order [A, B]"
    );

    let mut out_changes: Vec<FieldChange> = Vec::new();
    let _ = classify_recreate_reasons_from_annotations(&anns, &desired_spec, &mut out_changes);

    assert!(
        out_changes.iter().any(|c| c.path == "dns"),
        "Static{{[A, B]}} → Static{{[B, A]}} MUST emit a dns FieldChange — server-order \
         change is a semantic priority change for resolv.conf; a defense-in-depth set-semantic \
         sort regression would silently mask this; got: {out_changes:?}"
    );
}

/// Group A: IPv6-address payload parse pin. The renderer + parser
/// pair already supports IPv6 dns servers (`IpAddr::parse` accepts
/// both v4 and v6, and the `static:` prefix uses `:` only once as
/// the prefix-separator so subsequent `:` chars in v6 addresses
/// don't confuse `strip_prefix`), but no test exercises the v6 path.
/// A future parser tightening (e.g. token-level byte validation
/// that rejects `:` chars) would silently break IPv6 dns support.
#[test]
fn dns_static_ipv6_address_payloads_parse_ok() {
    use crate::config::{DnsMode, dns_from_annotation};

    assert_eq!(
        dns_from_annotation("static:::1"),
        Some(DnsMode::Static {
            servers: vec!["::1".parse().unwrap()],
        }),
        "IPv6 loopback `::1` must parse as a Static server"
    );
    assert_eq!(
        dns_from_annotation("static:2606:4700:4700::1111"),
        Some(DnsMode::Static {
            servers: vec!["2606:4700:4700::1111".parse().unwrap()],
        }),
        "IPv6 global unicast must parse as a Static server"
    );
    assert_eq!(
        dns_from_annotation("static:2606:4700:4700::1111,2606:4700:4700::1001"),
        Some(DnsMode::Static {
            servers: vec![
                "2606:4700:4700::1111".parse().unwrap(),
                "2606:4700:4700::1001".parse().unwrap(),
            ],
        }),
        "comma-separated IPv6 list must parse (comma is the only token boundary, `:` is part of v6 syntax)"
    );
    assert_eq!(
        dns_from_annotation("static:1.1.1.1,::1"),
        Some(DnsMode::Static {
            servers: vec!["1.1.1.1".parse().unwrap(), "::1".parse().unwrap()],
        }),
        "mixed v4 + v6 list must parse (IpAddr is the v4/v6 union type)"
    );
    assert_eq!(
        dns_from_annotation("static:::"),
        Some(DnsMode::Static {
            servers: vec!["::".parse().unwrap()],
        }),
        "`static:::` (IPv6 unspecified `::`) must parse — three colons means the `static:` prefix \
         + the v6 unspecified `::`; strip_prefix consumes exactly the first `static:`, leaving `::` for IpAddr"
    );
    assert_eq!(
        dns_from_annotation("static:0.0.0.0"),
        Some(DnsMode::Static {
            servers: vec!["0.0.0.0".parse().unwrap()],
        }),
        "`static:0.0.0.0` (IPv4 unspecified) must parse — a real operator may use 0.0.0.0 as a \
         disable-DNS sentinel; the parser must not reject it on validator-policy grounds"
    );
}

/// Parallel pin for hooks normalization at `lower_to_effective` —
/// `is_empty` predicate must be plumbed into the resolver via the
/// `.filter(|h| !h.is_empty())` call.
#[test]
fn lower_to_effective_collapses_some_empty_hooks_to_none() {
    let mut cfg_empty_hooks = config_with_runners(vec![minimal_runner("a")]);
    cfg_empty_hooks.hooks = Some(crate::config::HooksSpec::default());
    let expanded = expand_counts(&cfg_empty_hooks).expect("count expansion must succeed");
    let eff_empty = lower_to_effective(
        &expanded[0],
        &cfg_empty_hooks,
        Arch::X86_64,
        cfg_source_default(),
        0,
    )
    .expect("lower_to_effective must succeed");
    assert_eq!(
        eff_empty.hooks, None,
        "Some(empty HooksSpec) at config layer must collapse to None on EffectiveRunnerSpec"
    );

    let mut cfg_no_hooks = config_with_runners(vec![minimal_runner("a")]);
    cfg_no_hooks.hooks = None;
    let expanded_none = expand_counts(&cfg_no_hooks).expect("count expansion must succeed");
    let eff_none = lower_to_effective(
        &expanded_none[0],
        &cfg_no_hooks,
        Arch::X86_64,
        cfg_source_default(),
        0,
    )
    .expect("lower_to_effective must succeed");
    assert_eq!(
        spec_hash(&eff_empty),
        spec_hash(&eff_none),
        "Some(empty) hooks must produce identical spec_hash to None after normalization — dark input eliminated"
    );
}
