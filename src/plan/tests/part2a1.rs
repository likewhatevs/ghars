//! Test split part 2a: first half of the original `part2` module —
//! `merge_defaults` `bind_readonly_paths` Some(empty) semantics,
//! `ParsedUnit` parser tests, `spec_hash` cross-construction / TOML-
//! source / order tests, cache pool diff branches + `drift_cause` +
//! recreate-empties-drop-in-changes, `auth_name` in-place contract,
//! caches in-place contract.
//!
//! Sibling `part2b.rs` carries the noop-on-reorder + hardening-Vec
//! canonicalization tests. Split solely for file-size manageability;
//! every assertion still runs.

#![allow(clippy::unwrap_used, clippy::expect_used)]

use ipnet::IpNet;

use super::*;
use crate::config::{DnsMode, EffectiveNetworkBinding, Ipv6Mode, NetworkMode, NetworkSpec};

// --- merge_defaults: bind_readonly_paths Some(empty) semantics -----

/// `bind_readonly_paths` is `Option<Vec<Utf8PathBuf>>` to encode
/// THREE semantically-distinct states:
/// - `None` ⇒ inherit defaults (the `or_else` chain returns
///   `defaults.bind_readonly_paths`).
/// - `Some(vec![])` ⇒ replace defaults with an empty list (the
///   operator deliberately wants no entries; this overrides
///   defaults' list to nothing).
/// - `Some(vec![/a])` ⇒ override defaults with the runner's list.
///
/// Pin the middle case (Some(empty) replaces) — it's the
/// ambiguous one that a future refactor might silently flatten
/// to "Some(empty) inherits defaults". The other two are
/// covered implicitly by the existing hardening field-by-field
/// test, but the empty-vec semantics deserves its own pin.
#[test]
fn merge_defaults_bind_readonly_paths_some_empty_replaces_defaults() {
    let runner = {
        let mut r = minimal_runner("a");
        // Some(empty) — explicit override to "no readonly bind paths".
        r.hardening.bind_readonly_paths = Some(vec![]);
        r
    };
    let defaults = Defaults {
        hardening: Hardening {
            bind_readonly_paths: Some(vec![Utf8PathBuf::from("/defaults/path")]),
            ..Hardening::default()
        },
        ..Defaults::default()
    };
    let eff = merge_defaults(
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
    // Some(empty) on the runner side wins via `runner.or_else(...)`
    // — the `or_else` only fires when runner is None, so Some(vec![])
    // short-circuits and the defaults' Some([/defaults/path]) is
    // ignored. Eff is Some(empty), NOT Some([/defaults/path]).
    assert_eq!(eff.hardening.bind_readonly_paths, Some(vec![]));
}

#[test]
fn merge_defaults_bind_readonly_paths_runner_none_inherits_defaults() {
    // Sanity: complementary case to confirm the inherit path
    // also lands correctly (runner None → defaults wins).
    let runner = {
        let mut r = minimal_runner("a");
        r.hardening.bind_readonly_paths = None;
        r
    };
    let defaults = Defaults {
        hardening: Hardening {
            bind_readonly_paths: Some(vec![Utf8PathBuf::from("/defaults/path")]),
            ..Hardening::default()
        },
        ..Defaults::default()
    };
    let eff = merge_defaults(
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
    assert_eq!(
        eff.hardening.bind_readonly_paths,
        Some(vec![Utf8PathBuf::from("/defaults/path")])
    );
}

// --- ParsedUnit comprehensive parser tests -------------------------
//
// The state.rs parser is private (`struct ParsedUnit`), so these
// tests live there. This block deliberately stays empty — see
// `crate::state::tests` for the new ParsedUnit edge cases.

// --- spec_hash: cross-construction / TOML-source / order tests -----

/// Property: two specs constructed via DIFFERENT call sequences but
/// landing at the same logical value must hash identically. This
/// catches a mutant that tags hash output by construction-path
/// (e.g. encoding the merge step into the canonical JSON) instead
/// of by value alone. The two paths used here:
///   - one with explicit empty-vec defaults
///   - one with the same field set on the runner side
/// Both produce identical `EffectiveRunnerSpec` values; `spec_hash`
/// must agree.
#[test]
fn spec_hash_path_independent_when_logical_value_matches() {
    // Path A: defaults declares the labels, runner has none.
    let runner_a = minimal_runner("buckos");
    let defaults_a = Defaults {
        labels: vec!["self-hosted".into(), "linux".into()],
        ..Defaults::default()
    };
    let spec_a = merge_defaults(
        &runner_a,
        &defaults_a,
        "pat".into(),
        vec![],
        None,
        None,
        None,
        Arch::X86_64,
        cfg_source_default(),
    );
    // Path B: runner declares the labels, defaults has none.
    let runner_b = {
        let mut r = minimal_runner("buckos");
        r.labels = vec!["self-hosted".into(), "linux".into()];
        r
    };
    let defaults_b = Defaults::default();
    let spec_b = merge_defaults(
        &runner_b,
        &defaults_b,
        "pat".into(),
        vec![],
        None,
        None,
        None,
        Arch::X86_64,
        cfg_source_default(),
    );
    assert_eq!(
        spec_a, spec_b,
        "construction paths must produce equal specs"
    );
    assert_eq!(spec_hash(&spec_a), spec_hash(&spec_b));
}

/// Property: shuffling `labels` MUST NOT change the hash. Labels
/// are set-semantic for GitHub Actions runner registration —
/// workflow `runs-on: [linux, gpu]` matches a runner registered
/// with `[gpu, linux]` identically because the runner's behavior
/// is order-independent for matching workflow `runs-on:` selectors
/// once the `--labels CSV` argv is passed at registration.
/// Locally flipping `spec_hash` on a cosmetic operator reorder
/// would drive an in-place `UpdateRunner` (a hash mismatch with
/// no Stage 1 typed reason falls through the `uncovered` arm to
/// in-place rewrite + restart) for a no-op edit — an unnecessary
/// stop+start of the runner unit even though nothing functionally
/// changed.
/// Mirrors the caches canonicalization at the same function's
/// `caches.sort_by` site (paired in `lower_to_effective`).
///
/// Construct two specs with the same label SET in different ORDER
/// and assert `spec_hash` is identical. See `merge_defaults`'s
/// `labels.sort_unstable() + labels.dedup()` block for the
/// implementation site.
#[test]
fn spec_hash_unchanged_on_labels_reorder() {
    let runner1 = {
        let mut r = minimal_runner("a");
        r.labels = vec!["alpha".into(), "beta".into()];
        r
    };
    let runner2 = {
        let mut r = minimal_runner("a");
        r.labels = vec!["beta".into(), "alpha".into()];
        r
    };
    let defaults = Defaults::default();
    let spec1 = merge_defaults(
        &runner1,
        &defaults,
        "pat".into(),
        vec![],
        None,
        None,
        None,
        Arch::X86_64,
        cfg_source_default(),
    );
    let spec2 = merge_defaults(
        &runner2,
        &defaults,
        "pat".into(),
        vec![],
        None,
        None,
        None,
        Arch::X86_64,
        cfg_source_default(),
    );
    // Both labels Vecs are sorted by `merge_defaults`, so the
    // resulting EffectiveRunnerSpec.labels is `["alpha","beta"]`
    // for both runner1 and runner2. spec_hash must agree.
    assert_eq!(
        spec1.labels,
        vec!["alpha".to_string(), "beta".to_string()],
        "merge_defaults must sort labels; got: {:?}",
        spec1.labels
    );
    assert_eq!(
        spec2.labels, spec1.labels,
        "reordered TOML input must produce identical sorted labels Vec; got: {:?} vs {:?}",
        spec2.labels, spec1.labels
    );
    assert_eq!(spec_hash(&spec1), spec_hash(&spec2));
}

/// Pins TRIPLE-SORT COUPLING site 2 (`render_identity` defensive
/// re-sort at `X-Ghars-Labels=` emission). `spec_hash_unchanged_on
/// _labels_reorder` above pins site 1 (`merge_defaults`). This test
/// extends through `render_runner_unit` to assert byte-identity of
/// the identity drop-in across label permutations — so a regression
/// that drops the defensive sort in `render_identity` (or that
/// silently re-orders labels between merge and emit) fails here
/// before reaching production.
///
/// Three permutations of the same label set are constructed,
/// merged through `merge_defaults` (which sorts upstream), hashed,
/// rendered, and compared. Both the full 00-ghars.conf body and
/// the specific X-Ghars-Labels= CSV are pinned. A 4th block then
/// bypasses `merge_defaults` by directly mutating an
/// `EffectiveRunnerSpec`'s labels Vec to an unsorted order, isolating
/// site 2's defensive sort from site 1 — a regression that removes
/// only `render_identity`'s defensive sort would still pass the
/// upstream three blocks (their inputs arrive pre-sorted from
/// `merge_defaults`) but fail the bypass assertion.
#[test]
fn render_unchanged_on_labels_reorder_post_merge() {
    let mk_runner = |labels: Vec<String>| {
        let mut r = minimal_runner("a");
        r.labels = labels;
        r
    };
    let r1 = mk_runner(vec!["alpha".into(), "beta".into(), "gamma".into()]);
    let r2 = mk_runner(vec!["gamma".into(), "alpha".into(), "beta".into()]);
    let r3 = mk_runner(vec!["beta".into(), "gamma".into(), "alpha".into()]);

    let defaults = Defaults::default();
    let mk_spec = |runner: &RunnerSpec| -> EffectiveRunnerSpec {
        let mut spec = merge_defaults(
            runner,
            &defaults,
            "pat".into(),
            vec![],
            None,
            None,
            None,
            Arch::X86_64,
            cfg_source_default(),
        );
        spec.spec_hash = spec_hash(&spec);
        spec
    };
    let spec1 = mk_spec(&r1);
    let spec2 = mk_spec(&r2);
    let spec3 = mk_spec(&r3);

    assert_eq!(
        spec_hash(&spec1),
        spec_hash(&spec2),
        "permutation 1→2 spec_hash mismatch — site 1 (merge_defaults sort) regressed"
    );
    assert_eq!(
        spec_hash(&spec1),
        spec_hash(&spec3),
        "permutation 1→3 spec_hash mismatch — site 1 (merge_defaults sort) regressed"
    );

    let rendered1 = crate::systemd::render_runner_unit(&spec1).unwrap();
    let rendered2 = crate::systemd::render_runner_unit(&spec2).unwrap();
    let rendered3 = crate::systemd::render_runner_unit(&spec3).unwrap();

    assert_eq!(
        rendered1.drop_ins.get("00-ghars.conf"),
        rendered2.drop_ins.get("00-ghars.conf"),
        "permutation 1→2 produced different 00-ghars.conf bytes — \
         site 2 (render_identity defensive sort at X-Ghars-Labels=) regressed"
    );
    assert_eq!(
        rendered1.drop_ins.get("00-ghars.conf"),
        rendered3.drop_ins.get("00-ghars.conf"),
        "permutation 1→3 produced different 00-ghars.conf bytes — \
         site 2 (render_identity defensive sort at X-Ghars-Labels=) regressed"
    );

    let body = rendered1.drop_ins.get("00-ghars.conf").unwrap();
    let labels_line = body
        .lines()
        .find(|l| l.starts_with("X-Ghars-Labels="))
        .expect("00-ghars.conf must emit X-Ghars-Labels=");
    assert_eq!(
        labels_line, "X-Ghars-Labels=alpha,beta,gamma",
        "X-Ghars-Labels= must be ASCII byte-order ascending CSV regardless \
         of operator TOML order; got {labels_line:?}"
    );

    // Direct-construct bypass: prove site 2 (render_identity defensive
    // sort) fires on its own, not just downstream of site 1. The
    // assertions above route through merge_defaults which sorts upstream
    // — so a regression that removed render_identity's defensive sort
    // would be masked there (every spec arriving at render already has
    // sorted labels). Bypass merge_defaults by mutating an
    // EffectiveRunnerSpec's labels Vec directly to an unsorted order,
    // re-hash, render, and assert the X-Ghars-Labels= CSV is canonical.
    // A site-2 regression fails here with the unsorted CSV.
    let mut bypass = spec1.clone();
    bypass.labels = vec!["zebra".into(), "alpha".into(), "middle".into()];
    bypass.spec_hash = spec_hash(&bypass);
    let rendered_bypass = crate::systemd::render_runner_unit(&bypass).unwrap();
    let bypass_body = rendered_bypass.drop_ins.get("00-ghars.conf").unwrap();
    let bypass_labels_line = bypass_body
        .lines()
        .find(|l| l.starts_with("X-Ghars-Labels="))
        .expect("00-ghars.conf must emit X-Ghars-Labels=");
    assert_eq!(
        bypass_labels_line, "X-Ghars-Labels=alpha,middle,zebra",
        "site 2 (render_identity defensive sort at X-Ghars-Labels=) \
         regressed: direct-construct bypass produced non-canonical \
         CSV: {bypass_labels_line:?}"
    );
}

/// Site-3 of the labels triple-sort coupling: parse-boundary defensive
/// sort in `DiscoveredAnnotations::from_drop_in_body`'s labels parse arm.
/// `render_unchanged_on_labels_reorder_post_merge` covers sites 1 + 2
/// (`merge_defaults` source-of-truth sort + `render_identity` defensive
/// re-sort). This pair pins site 3 — the parse boundary's
/// `parsed.sort_unstable()` that runs after splitting the on-disk
/// `X-Ghars-Labels=` CSV. Without it, `DiscoveredAnnotations.labels`
/// would surface the on-disk byte order; the classifier's downstream
/// `sorted_set_field_diff` re-sorts before comparison so the
/// plan would still be correct, BUT any direct consumer that reads
/// `anns.labels` and doesn't re-sort gets non-canonical data — a
/// foot-gun for future code paths that touch the parsed annotations
/// outside the comparison hot path.
///
/// Block 1 (render → parse round-trip): renders a spec with
/// non-canonical-order labels, parses the resulting body via
/// `DiscoveredAnnotations::from_drop_in_body`, asserts `anns.labels`
/// comes back canonical-sorted. Because site 2 (`render_identity`)
/// emits canonical order, this block alone wouldn't isolate site 3 —
/// the parser would see already-sorted input.
///
/// Block 2 (hand-crafted bypass): constructs a drop-in body bytes
/// with `X-Ghars-Labels=gamma,beta,alpha` directly, bypassing render
/// entirely. The parser must re-sort to canonical alpha,beta,gamma.
/// A regression that removed the labels parse-boundary
/// `parsed.sort_unstable()` would fail this block while passing
/// Block 1.
#[test]
fn discovered_annotations_label_round_trip_canonical_sort() {
    let mut runner = minimal_runner("a");
    runner.labels = vec!["gamma".into(), "alpha".into(), "beta".into()];
    let defaults = Defaults::default();
    let mut spec = merge_defaults(
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
    spec.spec_hash = spec_hash(&spec);

    // Block 1: render → parse round-trip.
    let rendered = crate::systemd::render_runner_unit(&spec).unwrap();
    let body = rendered.drop_ins.get("00-ghars.conf").unwrap();
    let anns = DiscoveredAnnotations::from_drop_in_body(body);
    assert_eq!(
        anns.labels.as_deref(),
        Some(&["alpha".to_owned(), "beta".to_owned(), "gamma".to_owned()][..]),
        "site 3 (DiscoveredAnnotations defensive sort at parse boundary) \
         regressed in the render→parse path: rendered body parsed back to \
         non-canonical labels order; got: {:?}",
        anns.labels
    );

    // Block 2: hand-crafted body bypasses render. The renderer's
    // canonical emission (site 2) makes the round-trip block above
    // unable to detect a parser-side sort regression in isolation —
    // the parser would see already-sorted input. Construct a body
    // with non-canonical CSV order directly, parse it, and assert
    // the result is canonical.
    let bypass_body = "[Unit]\nX-Ghars-Labels=gamma,beta,alpha\n";
    let bypass_anns = DiscoveredAnnotations::from_drop_in_body(bypass_body);
    assert_eq!(
        bypass_anns.labels.as_deref(),
        Some(&["alpha".to_owned(), "beta".to_owned(), "gamma".to_owned()][..]),
        "site 3 (DiscoveredAnnotations defensive sort at parse boundary) \
         regressed: hand-crafted non-canonical body `X-Ghars-Labels=gamma,beta,alpha` \
         parsed without re-sort; got: {:?}",
        bypass_anns.labels
    );
}

/// Site-3 parity for caches: parse-boundary defensive sort in
/// `DiscoveredAnnotations::from_drop_in_body`'s caches parse arm.
/// `render_unchanged_on_caches_reorder_post_merge` covers sites
/// 1 + 2 (`lower_to_effective`'s `caches.sort_by` site +
/// `render_identity`'s defensive `cache_names` sort). This
/// pair pins site 3 — the parse boundary's `parsed.sort_unstable()`
/// that runs after splitting the on-disk `X-Ghars-Caches=` CSV.
/// Sister of `discovered_annotations_label_round_trip_canonical_sort`
/// which pins the labels parse-boundary sort in
/// `DiscoveredAnnotations::from_drop_in_body`.
///
/// Block 1 (render → parse round-trip): builds a runner with
/// non-canonical-order cache refs ["pool-z", "pool-a"], lowers via
/// the full pipeline (`expand_counts` + `lower_to_effective` which
/// fires site 1's sort), renders, parses, asserts `anns.caches`
/// comes back canonical-sorted. Because sites 1+2 pre-canonicalize
/// before render, Block 1 alone cannot isolate a site-3 regression
/// — the parser sees pre-sorted input regardless.
///
/// Block 2 (hand-crafted bypass): constructs a drop-in body bytes
/// with `X-Ghars-Caches=zebra,alpha,middle` directly, bypassing
/// render entirely. The parser must re-sort to canonical
/// alpha,middle,zebra. A regression that removed the caches
/// parse-boundary `parsed.sort_unstable()` would fail this block
/// while passing Block 1.
#[test]
fn discovered_annotations_caches_round_trip_canonical_sort() {
    use crate::config::{CacheKind, CacheMode, CachePoolSpec};

    // Block 1: render → parse round-trip.
    let mut cfg = config_with_runners(vec![minimal_runner("a")]);
    cfg.cache_pools.insert(
        "pool-a".into(),
        CachePoolSpec {
            kinds: vec![CacheKind::Ccache],
            size: "10G".into(),
            mode: CacheMode::Shared,
            trust_zone: "default".into(),
            sccache_path: None,
            sleep_path: Some("/usr/bin/sleep".into()),
        },
    );
    cfg.cache_pools.insert(
        "pool-z".into(),
        CachePoolSpec {
            kinds: vec![CacheKind::Sccache],
            size: "10G".into(),
            mode: CacheMode::Shared,
            trust_zone: "default".into(),
            sccache_path: Some("/usr/local/bin/sccache".into()),
            sleep_path: None,
        },
    );
    cfg.runners[0].caches = vec!["pool-z".into(), "pool-a".into()];
    let expanded = expand_counts(&cfg).expect("count expansion must succeed");
    let mut eff = lower_to_effective(&expanded[0], &cfg, Arch::X86_64, cfg_source_default(), 0)
        .expect("lower_to_effective must succeed");
    eff.spec_hash = spec_hash(&eff);
    let rendered = crate::systemd::render_runner_unit(&eff).unwrap();
    let body = rendered.drop_ins.get("00-ghars.conf").unwrap();
    let anns = DiscoveredAnnotations::from_drop_in_body(body);
    assert_eq!(
        anns.caches.as_deref(),
        Some(&["pool-a".to_owned(), "pool-z".to_owned()][..]),
        "site 3 (DiscoveredAnnotations defensive sort at parse boundary) \
         regressed in the render→parse path: rendered body parsed back to \
         non-canonical caches order; got: {:?}",
        anns.caches
    );

    // Block 2: hand-crafted body bypasses render. The pipeline's
    // sites 1+2 (lower_to_effective's caches.sort_by + render_identity's
    // defensive cache_names sort) pre-canonicalize the input the parser
    // sees in the render path, so Block 1 alone cannot isolate a
    // parser-side sort regression. Construct a body with non-canonical
    // CSV directly, parse it, and assert the result is canonical.
    let bypass_body = "[Unit]\nX-Ghars-Caches=zebra,alpha,middle\n";
    let bypass_anns = DiscoveredAnnotations::from_drop_in_body(bypass_body);
    assert_eq!(
        bypass_anns.caches.as_deref(),
        Some(&["alpha".to_owned(), "middle".to_owned(), "zebra".to_owned()][..]),
        "site 3 (DiscoveredAnnotations defensive sort at parse boundary) \
         regressed: hand-crafted non-canonical body `X-Ghars-Caches=zebra,alpha,middle` \
         parsed without re-sort; got: {:?}",
        bypass_anns.caches
    );
}

/// Sister regression pin to `render_unchanged_on_labels_reorder_post_merge`.
/// Caches have the same two-site defensive-sort architecture as labels:
/// site 1 sorts at the lowering layer (`lower_to_effective`'s
/// `caches.sort_by(|a, b| a.name.cmp(&b.name))` block sorts the
/// resolved Vec<EffectiveCacheBinding> by binding name); site 2
/// sorts at the rendering layer (`render_identity` builds
/// `cache_names: Vec<&str>` and calls `sort_unstable()` before
/// emit) as defense against direct-construct callers bypassing
/// the lowering sort.
///
/// Block 1 (site 1): construct a Config with 2 `cache_pools` `pool-a`
/// (ccache) + `pool-z` (sccache) — capped at 1 binding per kind by
/// the per-runner-per-kind validator; build a `RunnerSpec` whose
/// `caches` field is `["pool-z", "pool-a"]` (operator TOML in
/// lex-descending order); call `lower_to_effective` directly; assert
/// the resulting EffectiveRunnerSpec.caches binding names come out
/// as `["pool-a", "pool-z"]` (lex-ascending). A regression that
/// removes `lower_to_effective`'s `caches.sort_by` produces the
/// non-canonical order here.
///
/// Block 2 (site 2): direct-construct bypass. `merge_defaults`
/// threads the caches Vec verbatim (pinned by
/// `merge_defaults_caches_threaded_verbatim` in part1.rs), so
/// this block hand-feeds pre-sorted `EffectiveCacheBinding`
/// values into `merge_defaults` — bypassing `lower_to_effective`
/// entirely — then reverses the resulting `spec.caches` Vec to
/// lex-descending and renders. This exercises site 2 in
/// isolation: the renderer must re-sort regardless of input
/// order. Assert the emitted `X-Ghars-Caches=` CSV is byte-order
/// ascending. A regression that removes `render_identity`'s
/// defensive `cache_names` sort emits the unsorted CSV here — the
/// classifier's set-semantic sorted comparison would silently mask
/// the divergence at plan time, but `systemctl cat` would show the
/// unsorted CSV to operators.
#[test]
fn render_unchanged_on_caches_reorder_post_merge() {
    use crate::config::{CacheKind, CacheMode, CachePoolSpec, EffectiveCacheBinding};

    // Block 1: site 1 (lower_to_effective's caches.sort_by site).
    // Operator TOML places caches in non-canonical order; the
    // lowering layer must sort them by binding name. Constrained
    // to 2 pools (1 ccache + 1 sccache) by the per-runner-per-kind
    // validator; lex-descending TOML order [pool-z (sccache),
    // pool-a (ccache)] must lower to ascending [pool-a (ccache),
    // pool-z (sccache)].
    let mut cfg = config_with_runners(vec![minimal_runner("a")]);
    cfg.cache_pools.insert(
        "pool-a".into(),
        CachePoolSpec {
            kinds: vec![CacheKind::Ccache],
            size: "10G".into(),
            mode: CacheMode::Shared,
            trust_zone: "default".into(),
            sccache_path: None,
            sleep_path: Some("/usr/bin/sleep".into()),
        },
    );
    cfg.cache_pools.insert(
        "pool-z".into(),
        CachePoolSpec {
            kinds: vec![CacheKind::Sccache],
            size: "10G".into(),
            mode: CacheMode::Shared,
            trust_zone: "default".into(),
            sccache_path: Some("/usr/local/bin/sccache".into()),
            sleep_path: None,
        },
    );
    cfg.runners[0].caches = vec!["pool-z".into(), "pool-a".into()];

    let expanded = expand_counts(&cfg).expect("count expansion must succeed");
    let eff_site1 = lower_to_effective(&expanded[0], &cfg, Arch::X86_64, cfg_source_default(), 0)
        .expect("lower_to_effective must succeed");
    let lowered_names: Vec<&str> = eff_site1.caches.iter().map(|c| c.name.as_str()).collect();
    assert_eq!(
        lowered_names,
        vec!["pool-a", "pool-z"],
        "site 1 (lower_to_effective's caches.sort_by) regressed: \
         non-canonical TOML order [pool-z, pool-a] did not sort to \
         [pool-a, pool-z]; got: {lowered_names:?}"
    );

    // Also pin spec_hash permutation invariance. lower_to_effective
    // sorting the caches Vec is load-bearing for plan/apply: the
    // spec_hash digest is computed over the resolved spec, so a
    // regression that sorted the Vec but routed an additional
    // order-dependent value into spec_hash would silently flip the
    // hash across operator TOML reorders and trigger spurious
    // in-place UpdateRunner cycles. Lower a second cfg whose
    // caches are in canonical order and assert hash equality.
    let mut cfg_canonical = cfg.clone();
    cfg_canonical.runners[0].caches = vec!["pool-a".into(), "pool-z".into()];
    let expanded_canonical = expand_counts(&cfg_canonical).expect("count expansion must succeed");
    let eff_canonical = lower_to_effective(
        &expanded_canonical[0],
        &cfg_canonical,
        Arch::X86_64,
        cfg_source_default(),
        0,
    )
    .expect("lower_to_effective must succeed");
    assert_eq!(
        spec_hash(&eff_site1),
        spec_hash(&eff_canonical),
        "spec_hash differs across cache TOML permutations — lowering \
         lost permutation invariance in a way that survives the \
         lowered_names sort assertion above (some spec_hash input \
         field other than caches order regressed)"
    );

    // Block 2: site 2 (render_identity's defensive cache_names sort).
    // Direct-construct bypass — merge_defaults threads caches verbatim
    // (see merge_defaults_caches_threaded_verbatim in part1.rs), so
    // hand-feed sorted EffectiveCacheBinding values, then mutate the
    // spec.caches Vec to lex-descending; the renderer must re-sort
    // before emit.
    let defaults = Defaults::default();
    let mut spec = merge_defaults(
        &minimal_runner("a"),
        &defaults,
        "pat".into(),
        vec![
            EffectiveCacheBinding {
                name: "build".into(),
                kinds: vec![CacheKind::Ccache],
                size: "10G".into(),
                mode: CacheMode::Shared,
                trust_zone: "default".into(),
                sccache_path: None,
                sleep_path: Some("/usr/bin/sleep".into()),
                renderer_schema: crate::systemd::RENDERER_SCHEMA,
            },
            EffectiveCacheBinding {
                name: "test".into(),
                kinds: vec![CacheKind::Ccache],
                size: "5G".into(),
                mode: CacheMode::Shared,
                trust_zone: "default".into(),
                sccache_path: None,
                sleep_path: Some("/usr/bin/sleep".into()),
                renderer_schema: crate::systemd::RENDERER_SCHEMA,
            },
        ],
        None,
        None,
        None,
        Arch::X86_64,
        cfg_source_default(),
    );
    spec.spec_hash = spec_hash(&spec);

    // Bypass site 1's sort by directly reversing the Vec to put
    // "test" before "build" (lex-descending). A renderer that
    // dropped render_identity's defensive cache_names sort would
    // emit `X-Ghars-Caches=test,build` here.
    let mut bypass = spec.clone();
    bypass.caches.reverse();
    bypass.spec_hash = spec_hash(&bypass);
    assert_eq!(
        bypass
            .caches
            .iter()
            .map(|c| c.name.as_str())
            .collect::<Vec<_>>(),
        vec!["test", "build"],
        "bypass setup must place caches in lex-descending order to exercise site 2"
    );

    let rendered_bypass = crate::systemd::render_runner_unit(&bypass).unwrap();
    let bypass_body = rendered_bypass.drop_ins.get("00-ghars.conf").unwrap();
    let bypass_caches_line = bypass_body
        .lines()
        .find(|l| l.starts_with("X-Ghars-Caches="))
        .expect("00-ghars.conf must emit X-Ghars-Caches=");
    assert_eq!(
        bypass_caches_line, "X-Ghars-Caches=build,test",
        "site 2 (render_identity defensive sort at X-Ghars-Caches=) \
         regressed: direct-construct bypass with unsorted caches \
         produced non-canonical CSV: {bypass_caches_line:?}"
    );
}

/// Mirror of `render_unchanged_on_caches_reorder_post_merge` for
/// `NetworkSpec.restrict_address_families`. Two block structure:
///
/// Block 1 (site 1, `canonicalize_network_spec` in
/// `lower_to_effective`): operator TOML places families in
/// non-canonical order; the lowering layer must sort+dedup them.
/// Without this sort, the `EffectiveRunnerSpec.network.spec`
/// field flows into `spec_hash` via `serde_json` in operator order,
/// flipping the hash on cosmetic TOML reorders even though the
/// rendered drop-in body is identical (the renderer-site sort
/// fires regardless). This is the phantom-UpdateRunner gap
/// `canonicalize_network_spec` closes — sister of the
/// `canonicalize_kinds` sort that fixed the same defect class for
/// `pool.kinds`.
///
/// Block 2 (site 2, renderer-site `sort_unstable()` in
/// `render_network`): direct-construct bypass — hand-build an
/// `EffectiveNetworkBinding` with families in lex-descending
/// order. The renderer must re-sort before emit. This is the
/// defense-in-depth gate against test fixtures that bypass
/// `lower_to_effective`.
#[test]
fn render_unchanged_on_restrict_address_families_reorder_post_merge() {
    // Block 1: site 1 (canonicalize_network_spec in lower_to_effective).
    // Operator TOML places families in non-canonical order; lowering
    // must canonicalize before spec_hash sees the Vec.
    let mut cfg = config_with_runners(vec![minimal_runner("a")]);
    cfg.networks.insert(
        "net-a".into(),
        NetworkSpec {
            mode: NetworkMode::Netns,
            allowed_egress: vec![],
            ip_allow: vec![],
            ip_deny: vec![],
            restrict_address_families: vec![
                "AF_UNIX".into(),
                "AF_INET".into(),
                "AF_NETLINK".into(),
            ],
            dns: DnsMode::default(),
            ipv6: Ipv6Mode::default(),
        },
    );
    cfg.runners[0].network = Some("net-a".into());

    let expanded = expand_counts(&cfg).expect("count expansion must succeed");
    let eff_site1 = lower_to_effective(&expanded[0], &cfg, Arch::X86_64, cfg_source_default(), 0)
        .expect("lower_to_effective must succeed");
    let lowered_families: Vec<&str> = eff_site1
        .network
        .as_ref()
        .expect("netns binding must be Some")
        .spec
        .restrict_address_families
        .iter()
        .map(String::as_str)
        .collect();
    assert_eq!(
        lowered_families,
        vec!["AF_INET", "AF_NETLINK", "AF_UNIX"],
        "site 1 (canonicalize_network_spec) regressed: non-canonical \
         TOML order [AF_UNIX, AF_INET, AF_NETLINK] did not sort to \
         canonical [AF_INET, AF_NETLINK, AF_UNIX]; got: {lowered_families:?}"
    );

    // Also pin spec_hash permutation invariance — same shape as
    // the caches sister test. Lower a second cfg whose families are
    // in canonical order and assert spec_hash equality. Without the
    // upstream sort, an operator cosmetic reorder of the TOML Vec
    // would flip spec_hash and trigger a spurious in-place
    // UpdateRunner cycle with an empty drop-in body diff.
    let mut cfg_canonical = cfg.clone();
    cfg_canonical
        .networks
        .get_mut("net-a")
        .unwrap()
        .restrict_address_families = vec!["AF_INET".into(), "AF_NETLINK".into(), "AF_UNIX".into()];
    let expanded_canonical = expand_counts(&cfg_canonical).expect("count expansion must succeed");
    let eff_canonical = lower_to_effective(
        &expanded_canonical[0],
        &cfg_canonical,
        Arch::X86_64,
        cfg_source_default(),
        0,
    )
    .expect("lower_to_effective must succeed");
    assert_eq!(
        spec_hash(&eff_site1),
        spec_hash(&eff_canonical),
        "spec_hash differs across NetworkSpec.restrict_address_families \
         TOML permutations — canonicalize_network_spec lost permutation \
         invariance in a way that survives the lowered_families sort \
         assertion above (some spec_hash input field other than \
         restrict_address_families order regressed)"
    );

    // Also dedup behavior: operator-supplied duplicates must collapse.
    let mut cfg_dup = cfg.clone();
    cfg_dup
        .networks
        .get_mut("net-a")
        .unwrap()
        .restrict_address_families = vec!["AF_UNIX".into(), "AF_INET".into(), "AF_UNIX".into()];
    let expanded_dup = expand_counts(&cfg_dup).expect("count expansion must succeed");
    let eff_dup = lower_to_effective(
        &expanded_dup[0],
        &cfg_dup,
        Arch::X86_64,
        cfg_source_default(),
        0,
    )
    .expect("lower_to_effective must succeed");
    let dedup_families: Vec<&str> = eff_dup
        .network
        .as_ref()
        .expect("netns binding must be Some")
        .spec
        .restrict_address_families
        .iter()
        .map(String::as_str)
        .collect();
    assert_eq!(
        dedup_families,
        vec!["AF_INET", "AF_UNIX"],
        "canonicalize_network_spec must dedup operator-supplied duplicates, \
         got: {dedup_families:?}"
    );

    // Block 2: site 2 (renderer-site defensive sort in render_network).
    // Direct-construct bypass — hand-feed EffectiveNetworkBinding
    // with families in lex-descending order; the renderer must
    // re-sort before emit.
    let mut bypass = eff_site1.clone();
    bypass
        .network
        .as_mut()
        .unwrap()
        .spec
        .restrict_address_families = vec!["AF_UNIX".into(), "AF_NETLINK".into(), "AF_INET".into()];
    bypass.spec_hash = spec_hash(&bypass);

    let rendered_bypass = crate::systemd::render_runner_unit(&bypass).unwrap();
    let bypass_body = rendered_bypass
        .drop_ins
        .get("40-network.conf")
        .expect("40-network.conf must emit for netns binding");
    let bypass_families_line = bypass_body
        .lines()
        .find(|l| l.starts_with("RestrictAddressFamilies="))
        .expect("40-network.conf must emit RestrictAddressFamilies=");
    assert_eq!(
        bypass_families_line, "RestrictAddressFamilies=AF_INET AF_NETLINK AF_UNIX",
        "site 2 (render_network defensive sort) regressed: direct-construct \
         bypass with non-canonical Vec produced unsorted directive: \
         {bypass_families_line:?}"
    );
}

/// Sister of `render_unchanged_on_restrict_address_families_reorder_post_merge`
/// for `NetworkSpec.ip_allow` + `NetworkSpec.ip_deny`. Two-block
/// structure mirrors the sister pattern:
///
/// Block 1 (site 1, `canonicalize_network_spec` in
/// `lower_to_effective`): operator TOML places CIDRs in non-canonical
/// order; the lowering layer must sort+dedup them. Pins both
/// `lowered.spec.ip_*` content + `spec_hash` permutation invariance.
///
/// Block 2 (site 2, renderer-site sort in `render_network`):
/// direct-construct bypass — hand-build an `EffectiveNetworkBinding`
/// with CIDRs in lex-descending order. The renderer must re-sort
/// before emit. Defense-in-depth gate for callers that bypass
/// `lower_to_effective`.
///
/// `IpNet` implements `Ord` via the `ipnet` crate (sorts by binary
/// network address then by prefix length), so the canonical-lex
/// order is well-defined.
#[test]
fn render_unchanged_on_ip_allow_ip_deny_reorder_post_merge() {
    // Block 1: site 1 — operator TOML in non-canonical order.
    let mut cfg = config_with_runners(vec![minimal_runner("a")]);
    cfg.networks.insert(
        "net-a".into(),
        NetworkSpec {
            mode: NetworkMode::Netns,
            allowed_egress: vec![],
            ip_allow: vec![
                "192.168.0.0/16".parse::<IpNet>().unwrap(),
                "10.0.0.0/8".parse::<IpNet>().unwrap(),
                "172.16.0.0/12".parse::<IpNet>().unwrap(),
            ],
            ip_deny: vec![
                "10.99.0.0/16".parse::<IpNet>().unwrap(),
                "0.0.0.0/0".parse::<IpNet>().unwrap(),
            ],
            restrict_address_families: vec![],
            dns: DnsMode::default(),
            ipv6: Ipv6Mode::default(),
        },
    );
    cfg.runners[0].network = Some("net-a".into());

    let expanded = expand_counts(&cfg).expect("count expansion must succeed");
    let eff_site1 = lower_to_effective(&expanded[0], &cfg, Arch::X86_64, cfg_source_default(), 0)
        .expect("lower_to_effective must succeed");
    let net = eff_site1
        .network
        .as_ref()
        .expect("netns binding must be Some");
    // IpNet Ord: 10.0.0.0/8 < 172.16.0.0/12 < 192.168.0.0/16 by network address.
    assert_eq!(
        net.spec
            .ip_allow
            .iter()
            .map(std::string::ToString::to_string)
            .collect::<Vec<_>>(),
        vec!["10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16"],
        "site 1 (canonicalize_network_spec) regressed: ip_allow did not sort canonically; \
         got: {:?}",
        net.spec.ip_allow
    );
    // 0.0.0.0/0 < 10.99.0.0/16 by network address.
    assert_eq!(
        net.spec
            .ip_deny
            .iter()
            .map(std::string::ToString::to_string)
            .collect::<Vec<_>>(),
        vec!["0.0.0.0/0", "10.99.0.0/16"],
        "site 1 (canonicalize_network_spec) regressed: ip_deny did not sort canonically; \
         got: {:?}",
        net.spec.ip_deny
    );

    // spec_hash permutation invariance: build a second cfg with
    // ip_allow + ip_deny in canonical order, assert hashes equal.
    let mut cfg_canonical = cfg.clone();
    cfg_canonical.networks.get_mut("net-a").unwrap().ip_allow = vec![
        "10.0.0.0/8".parse::<IpNet>().unwrap(),
        "172.16.0.0/12".parse::<IpNet>().unwrap(),
        "192.168.0.0/16".parse::<IpNet>().unwrap(),
    ];
    cfg_canonical.networks.get_mut("net-a").unwrap().ip_deny = vec![
        "0.0.0.0/0".parse::<IpNet>().unwrap(),
        "10.99.0.0/16".parse::<IpNet>().unwrap(),
    ];
    let expanded_canonical = expand_counts(&cfg_canonical).expect("count expansion must succeed");
    let eff_canonical = lower_to_effective(
        &expanded_canonical[0],
        &cfg_canonical,
        Arch::X86_64,
        cfg_source_default(),
        0,
    )
    .expect("lower_to_effective must succeed");
    assert_eq!(
        spec_hash(&eff_site1),
        spec_hash(&eff_canonical),
        "spec_hash differs across NetworkSpec.ip_allow / ip_deny TOML \
         permutations — canonicalize_network_spec lost permutation \
         invariance for these fields"
    );

    // Dedup behavior: duplicates in operator TOML must collapse.
    let mut cfg_dup = cfg.clone();
    cfg_dup.networks.get_mut("net-a").unwrap().ip_allow = vec![
        "10.0.0.0/8".parse::<IpNet>().unwrap(),
        "192.168.0.0/16".parse::<IpNet>().unwrap(),
        "10.0.0.0/8".parse::<IpNet>().unwrap(),
    ];
    let expanded_dup = expand_counts(&cfg_dup).expect("count expansion must succeed");
    let eff_dup = lower_to_effective(
        &expanded_dup[0],
        &cfg_dup,
        Arch::X86_64,
        cfg_source_default(),
        0,
    )
    .expect("lower_to_effective must succeed");
    let dedup_allow: Vec<String> = eff_dup
        .network
        .as_ref()
        .unwrap()
        .spec
        .ip_allow
        .iter()
        .map(std::string::ToString::to_string)
        .collect();
    assert_eq!(
        dedup_allow,
        vec!["10.0.0.0/8", "192.168.0.0/16"],
        "canonicalize_network_spec must dedup operator-supplied duplicate CIDRs; \
         got: {dedup_allow:?}"
    );

    // Symmetric dedup pin for ip_deny — guards against a regression
    // that drops `s.ip_deny.dedup();` while keeping ip_allow's.
    let mut cfg_dup_deny = cfg.clone();
    cfg_dup_deny.networks.get_mut("net-a").unwrap().ip_deny = vec![
        "10.99.0.0/16".parse::<IpNet>().unwrap(),
        "0.0.0.0/0".parse::<IpNet>().unwrap(),
        "10.99.0.0/16".parse::<IpNet>().unwrap(),
    ];
    let expanded_dup_deny = expand_counts(&cfg_dup_deny).expect("count expansion must succeed");
    let eff_dup_deny = lower_to_effective(
        &expanded_dup_deny[0],
        &cfg_dup_deny,
        Arch::X86_64,
        cfg_source_default(),
        0,
    )
    .expect("lower_to_effective must succeed");
    let dedup_deny: Vec<String> = eff_dup_deny
        .network
        .as_ref()
        .unwrap()
        .spec
        .ip_deny
        .iter()
        .map(std::string::ToString::to_string)
        .collect();
    assert_eq!(
        dedup_deny,
        vec!["0.0.0.0/0", "10.99.0.0/16"],
        "canonicalize_network_spec must dedup operator-supplied duplicate \
         ip_deny CIDRs; got: {dedup_deny:?}"
    );

    // Block 2: site 2 — direct-construct bypass.
    let mut bypass = eff_site1.clone();
    bypass.network.as_mut().unwrap().spec.ip_allow = vec![
        "192.168.0.0/16".parse::<IpNet>().unwrap(),
        "172.16.0.0/12".parse::<IpNet>().unwrap(),
        "10.0.0.0/8".parse::<IpNet>().unwrap(),
    ];
    bypass.network.as_mut().unwrap().spec.ip_deny = vec![
        "10.99.0.0/16".parse::<IpNet>().unwrap(),
        "0.0.0.0/0".parse::<IpNet>().unwrap(),
    ];
    bypass.spec_hash = spec_hash(&bypass);

    let rendered_bypass = crate::systemd::render_runner_unit(&bypass).unwrap();
    let bypass_body = rendered_bypass
        .drop_ins
        .get("40-network.conf")
        .expect("40-network.conf must emit for netns binding");

    // Renderer must emit IPAddressAllow= lines in canonical CIDR order.
    let allow_lines: Vec<&str> = bypass_body
        .lines()
        .filter(|l| l.starts_with("IPAddressAllow="))
        .collect();
    assert_eq!(
        allow_lines,
        vec![
            "IPAddressAllow=10.0.0.0/8",
            "IPAddressAllow=172.16.0.0/12",
            "IPAddressAllow=192.168.0.0/16",
        ],
        "site 2 (render_network ip_allow defensive sort) regressed: \
         direct-construct bypass produced unsorted lines: {allow_lines:?}"
    );
    let deny_lines: Vec<&str> = bypass_body
        .lines()
        .filter(|l| l.starts_with("IPAddressDeny="))
        .collect();
    assert_eq!(
        deny_lines,
        vec!["IPAddressDeny=0.0.0.0/0", "IPAddressDeny=10.99.0.0/16",],
        "site 2 (render_network ip_deny defensive sort) regressed: \
         direct-construct bypass produced unsorted lines: {deny_lines:?}"
    );
}

/// Property: operator-supplied CIDRs with host bits set
/// (`10.0.0.5/24`) get normalized to network address
/// (`10.0.0.0/24`) by `canonicalize_network_spec` before sort+dedup.
/// systemd's PID 1 user-space masks host bits via `in_addr_mask`
/// at `systemd/src/shared/in-addr-prefix-util.c` `in_addr_prefix_add`
/// (line 102) BEFORE issuing the `bpf(2)` `BPF_MAP_UPDATE_ELEM`
/// syscall that inserts the entry into the kernel-side LPM trie,
/// so operator host bits are discarded in user-space and never
/// reach the kernel. ghars-side normalization preserves `spec_hash`
/// byte-stability across cosmetically-equivalent TOML.
///
/// Cases cover IPv4 (mid-octet, max host bits, cross-octet,
/// non-octet-aligned prefix, small-subnet boundary), the idempotent
/// already-canonical case, `/32` single-host (no host bits), `/0`
/// default route, IPv6 (typical, boundary `/128`, already-canonical).
#[test]
fn canonicalize_network_spec_normalizes_host_bits_to_zero() {
    let cases: &[(&str, &str)] = &[
        // IPv4 with host bits set
        ("10.0.0.5/24", "10.0.0.0/24"),
        ("10.0.0.255/24", "10.0.0.0/24"),
        ("192.168.42.99/16", "192.168.0.0/16"),
        ("172.16.42.42/12", "172.16.0.0/12"),
        ("10.0.0.5/30", "10.0.0.4/30"),
        // IPv4 idempotent
        ("10.0.0.0/24", "10.0.0.0/24"),
        ("10.0.0.5/32", "10.0.0.5/32"),
        ("0.0.0.0/0", "0.0.0.0/0"),
        // IPv6 with host bits set
        ("2001:db8::1234:5678/64", "2001:db8::/64"),
        // IPv6 idempotent
        ("::1/128", "::1/128"),
        ("2001:db8:abcd:ef::/64", "2001:db8:abcd:ef::/64"),
    ];
    for (input, expected) in cases {
        let mut cfg = config_with_runners(vec![minimal_runner("a")]);
        cfg.networks.insert(
            "net-a".into(),
            NetworkSpec {
                mode: NetworkMode::Netns,
                allowed_egress: vec![],
                ip_allow: vec![input.parse::<IpNet>().unwrap()],
                ip_deny: vec![],
                restrict_address_families: vec![],
                dns: DnsMode::default(),
                ipv6: Ipv6Mode::default(),
            },
        );
        cfg.runners[0].network = Some("net-a".into());
        let expanded = expand_counts(&cfg).expect("count expansion must succeed");
        let eff = lower_to_effective(&expanded[0], &cfg, Arch::X86_64, cfg_source_default(), 0)
            .expect("lower_to_effective must succeed");
        let got = eff.network.as_ref().unwrap().spec.ip_allow[0].to_string();
        assert_eq!(
            got, *expected,
            "canonicalize_network_spec must normalize host bits to zero: \
             input {input} should normalize to {expected}, got {got}"
        );
    }
}

/// Load-bearing test: operator-equivalent CIDR forms (same network,
/// different host bits) collapse to a single canonical entry after
/// trunc+sort+dedup. Without trunc-before-dedup, 3 distinct CIDR
/// strings would survive into the rendered drop-in body and the
/// `spec_hash`, defeating the cosmetic-equivalence invariant.
///
/// THE failure mode the host-bits-zero normalization closes: an
/// operator writing `[10.0.0.5/24, 10.0.0.99/24, 10.0.0.0/24]`
/// thinks they're naming a single network three different ways; the
/// validator+canonicalizer should collapse to `[10.0.0.0/24]`.
#[test]
fn canonicalize_network_spec_collapses_operator_equivalent_cidrs() {
    let mut cfg = config_with_runners(vec![minimal_runner("a")]);
    cfg.networks.insert(
        "net-a".into(),
        NetworkSpec {
            mode: NetworkMode::Netns,
            allowed_egress: vec![],
            ip_allow: vec![
                "10.0.0.5/24".parse::<IpNet>().unwrap(),
                "10.0.0.99/24".parse::<IpNet>().unwrap(),
                "10.0.0.0/24".parse::<IpNet>().unwrap(),
            ],
            ip_deny: vec![
                "172.16.42.99/16".parse::<IpNet>().unwrap(),
                "172.16.0.0/16".parse::<IpNet>().unwrap(),
            ],
            restrict_address_families: vec![],
            dns: DnsMode::default(),
            ipv6: Ipv6Mode::default(),
        },
    );
    cfg.runners[0].network = Some("net-a".into());
    let expanded = expand_counts(&cfg).expect("count expansion must succeed");
    let eff = lower_to_effective(&expanded[0], &cfg, Arch::X86_64, cfg_source_default(), 0)
        .expect("lower_to_effective must succeed");
    let allow: Vec<String> = eff
        .network
        .as_ref()
        .unwrap()
        .spec
        .ip_allow
        .iter()
        .map(std::string::ToString::to_string)
        .collect();
    assert_eq!(
        allow,
        vec!["10.0.0.0/24"],
        "trunc-before-dedup must collapse 3 operator-equivalent ip_allow \
         CIDRs to 1 canonical entry; got: {allow:?}"
    );
    let deny: Vec<String> = eff
        .network
        .as_ref()
        .unwrap()
        .spec
        .ip_deny
        .iter()
        .map(std::string::ToString::to_string)
        .collect();
    assert_eq!(
        deny,
        vec!["172.16.0.0/16"],
        "trunc-before-dedup must collapse 2 operator-equivalent ip_deny \
         CIDRs to 1 canonical entry; got: {deny:?}"
    );
}
