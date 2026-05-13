//! Test split part 2: covers `merge_defaults` `bind_readonly_paths`
//! Some(empty) semantics, `ParsedUnit` comprehensive parser tests, `spec_hash`
//! cross-construction / TOML-source / order tests,
//! cache pool diff branches + `drift_cause` + recreate-empties-drop-in-changes,
//! `auth_name` in-place contract, caches in-place contract, and hardening Vec
//! canonicalization (3 set-semantic fields). Migrated verbatim from plan.rs.

#![allow(clippy::unwrap_used, clippy::expect_used)]

use super::*;

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
        "/etc/ghars/ghars.toml".into(),
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
        "/etc/ghars/ghars.toml".into(),
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
        "/etc/ghars/ghars.toml".into(),
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
        "/etc/ghars/ghars.toml".into(),
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
        "/etc/ghars/ghars.toml".into(),
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
        "/etc/ghars/ghars.toml".into(),
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

/// Pins TRIPLE-SORT COUPLING site 2 (render_identity defensive
/// re-sort at `X-Ghars-Labels=` emission). `spec_hash_unchanged_on
/// _labels_reorder` above pins site 1 (merge_defaults). This test
/// extends through render_runner_unit to assert byte-identity of
/// the identity drop-in across label permutations — so a regression
/// that drops the defensive sort in render_identity (or that
/// silently re-orders labels between merge and emit) fails here
/// before reaching production.
///
/// Three permutations of the same label set are constructed,
/// merged through merge_defaults (which sorts upstream), hashed,
/// rendered, and compared. Both the full 00-ghars.conf body and
/// the specific X-Ghars-Labels= CSV are pinned. A 4th block then
/// bypasses merge_defaults by directly mutating an
/// EffectiveRunnerSpec's labels Vec to an unsorted order, isolating
/// site 2's defensive sort from site 1 — a regression that removes
/// only render_identity's defensive sort would still pass the
/// upstream three blocks (their inputs arrive pre-sorted from
/// merge_defaults) but fail the bypass assertion.
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
            "/etc/ghars/ghars.toml".into(),
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

/// Sister regression pin to `render_unchanged_on_labels_reorder_post_merge`.
/// Caches have the same two-site defensive-sort architecture as labels:
/// site 1 sorts at the lowering layer (`lower_to_effective` at
/// compute.rs:1092 sorts the resolved Vec<EffectiveCacheBinding> by
/// binding name); site 2 sorts at the rendering layer
/// (`render_identity` builds `cache_names: Vec<&str>` and calls
/// `sort_unstable()` at units.rs:949-951) as defense against
/// direct-construct callers bypassing the lowering sort.
///
/// Block 1 (site 1): construct a Config with 2 cache_pools `pool-a`
/// (ccache) + `pool-z` (sccache) — capped at 1 binding per kind per
/// #38's per-runner-per-kind validator; build a RunnerSpec whose
/// `caches` field is `["pool-z", "pool-a"]` (operator TOML in
/// lex-descending order); call `lower_to_effective` directly; assert
/// the resulting EffectiveRunnerSpec.caches binding names come out
/// as `["pool-a", "pool-z"]` (lex-ascending). A regression that
/// removes compute.rs:1092's sort produces the non-canonical order
/// here.
///
/// Block 2 (site 2): direct-construct bypass. `merge_defaults`
/// threads the caches Vec verbatim (pinned by
/// `merge_defaults_caches_threaded_verbatim` in part1.rs), so
/// this block hand-feeds pre-sorted `EffectiveCacheBinding`
/// values into merge_defaults — bypassing `lower_to_effective`
/// entirely — then reverses the resulting `spec.caches` Vec to
/// lex-descending and renders. This exercises site 2 in
/// isolation: the renderer must re-sort regardless of input
/// order. Assert the emitted `X-Ghars-Caches=` CSV is byte-order
/// ascending. A regression that removes units.rs:949-951's sort
/// emits the unsorted CSV here — the classifier's set-semantic
/// sorted comparison would silently mask the divergence at plan
/// time, but `systemctl cat` would show the unsorted CSV to
/// operators.
#[test]
fn render_unchanged_on_caches_reorder_post_merge() {
    use crate::config::{CacheKind, CacheMode, CachePoolSpec, EffectiveCacheBinding};

    // Block 1: site 1 (lower_to_effective sort at compute.rs:1092).
    // Operator TOML places caches in non-canonical order; the
    // lowering layer must sort them by binding name. Constrained
    // to 2 pools (1 ccache + 1 sccache) by the post-#38
    // per-runner-per-kind validator; lex-descending TOML order
    // [pool-z (sccache), pool-a (ccache)] must lower to ascending
    // [pool-a (ccache), pool-z (sccache)].
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
    let eff_site1 = lower_to_effective(
        &expanded[0],
        &cfg,
        Arch::X86_64,
        "/etc/ghars/ghars.toml".into(),
        0,
    )
    .expect("lower_to_effective must succeed");
    let lowered_names: Vec<&str> = eff_site1.caches.iter().map(|c| c.name.as_str()).collect();
    assert_eq!(
        lowered_names,
        vec!["pool-a", "pool-z"],
        "site 1 (lower_to_effective sort at compute.rs:1092) regressed: \
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
    let expanded_canonical =
        expand_counts(&cfg_canonical).expect("count expansion must succeed");
    let eff_canonical = lower_to_effective(
        &expanded_canonical[0],
        &cfg_canonical,
        Arch::X86_64,
        "/etc/ghars/ghars.toml".into(),
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

    // Block 2: site 2 (render_identity defensive sort at units.rs:949-951).
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
        "/etc/ghars/ghars.toml".into(),
    );
    spec.spec_hash = spec_hash(&spec);

    // Bypass site 1's sort by directly reversing the Vec to put
    // "test" before "build" (lex-descending). A renderer that
    // dropped the defensive sort at units.rs:949-951 would emit
    // `X-Ghars-Caches=test,build` here.
    let mut bypass = spec.clone();
    bypass.caches.reverse();
    bypass.spec_hash = spec_hash(&bypass);
    assert_eq!(
        bypass.caches.iter().map(|c| c.name.as_str()).collect::<Vec<_>>(),
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

/// Property: two TOML files that produce semantically-identical
/// configs (but with formatting differences — comments,
/// whitespace, key order across runner blocks) must lower to the
/// same `EffectiveRunnerSpec` and produce equal `spec_hash`.
/// This is the round-trip determinism guarantee — a mutant that
/// captured TOML source bytes into the hash would fail here.
#[test]
fn spec_hash_equal_for_semantically_identical_toml_sources() {
    // TOML A: sparse, no comments.
    let toml_a = r#"
[auth.pat]
kind = "pat"
token_env = "GHARS_PAT"

[[runner]]
name = "buckos"
url = "https://github.com/example/buckos"
auth = "pat"
labels = ["alpha", "beta"]
"#;
    // TOML B: same content, plus comments, whitespace, blank
    // lines — semantically identical, byte-different.
    let toml_b = r#"
# auth section
[auth.pat]
kind      = "pat"
token_env = "GHARS_PAT"   # comment

# the only runner

[[runner]]
name    = "buckos"
url     = "https://github.com/example/buckos"
auth    = "pat"
labels  = ["alpha", "beta"]
"#;
    let cfg_a: crate::config::Config = toml::from_str(toml_a).unwrap();
    let cfg_b: crate::config::Config = toml::from_str(toml_b).unwrap();
    let runner_a = &cfg_a.runners[0];
    let runner_b = &cfg_b.runners[0];
    let spec_a = merge_defaults(
        runner_a,
        &cfg_a.defaults,
        "pat".into(),
        vec![],
        None,
        None,
        None,
        Arch::X86_64,
        "/etc/ghars/ghars.toml".into(),
    );
    let spec_b = merge_defaults(
        runner_b,
        &cfg_b.defaults,
        "pat".into(),
        vec![],
        None,
        None,
        None,
        Arch::X86_64,
        "/etc/ghars/ghars.toml".into(),
    );
    assert_eq!(
        spec_hash(&spec_a),
        spec_hash(&spec_b),
        "comment/whitespace differences in TOML source must not affect spec_hash"
    );
}

// ---- cache pool diff branches + drift_cause + recreate-empties-drop-in-changes -----

/// Helper: insert a desired pool referenced by runner `a`. Mirrors
/// the inline `cfg.cache_pools.insert(...)` pattern other pool
/// tests use.
fn cfg_with_pool(name: &str, kinds: Vec<crate::config::CacheKind>) -> Config {
    let mut cfg = config_with_runners(vec![{
        let mut r = minimal_runner("a");
        r.caches = vec![name.into()];
        r
    }]);
    cfg.cache_pools.insert(
        name.into(),
        CachePoolSpec {
            kinds,
            size: "10G".into(),
            mode: CacheMode::Shared,
            trust_zone: "default".into(),
            // Pin both binaries so the plan-time auto-detect probe
            // never reads the test host's filesystem — `/usr/bin/sccache`
            // is not present on every CI image. Pinning both fields
            // (not just the relevant one) keeps this helper kind-agnostic.
            sccache_path: Some("/usr/bin/sccache".into()),
            sleep_path: Some("/usr/bin/sleep".into()),
        },
    );
    cfg
}

/// Helper: build a `DiscoveredCachePool` with the given `spec_hash` +
/// drop-in body content, and the requested Drift. Matches the
/// shape produced by `state::discover` for cache-pool drop-in
/// dirs.
fn discovered_pool(name: &str, spec_hash: &str, drift: Drift) -> crate::state::DiscoveredCachePool {
    let mut drop_ins: BTreeMap<String, String> = BTreeMap::new();
    drop_ins.insert(
        "00-ghars.conf".into(),
        format!("[Unit]\nX-Ghars-Spec-Hash={spec_hash}\n"),
    );
    // For DropInsModified payloads, also stage the unmanaged file
    // so the test's drop-in shape reflects what discover() would
    // see. Caller passes the basename via the Drift payload Vec —
    // we don't expand it here because each test fabricates Drift
    // directly.
    crate::state::DiscoveredCachePool {
        name: name.to_owned(),
        spec_hash: spec_hash.to_owned(),
        drop_ins,
        running: false,
        enabled: false,
        drift,
    }
}

/// Branch 1: `spec_hash` matches AND drift `InSync` ⇒ no
/// `UpdateCachePool` / `RemoveCachePool` emitted (`NoOp` on the pool
/// side — `plan_from` emits no action when both signals are clean).
#[test]
fn plan_cache_pool_in_sync_emits_no_pool_action() {
    let cfg = cfg_with_pool("build", vec![CacheKind::Ccache]);
    // Compute the pool's spec_hash by running into_cache_pool_plan
    // with the same desired binding. plan_from calls this path
    // internally; we mirror it so the test's discovered hash
    // matches.
    let cfg_source = empty_paths().config_dir.join("ghars.toml").to_string();
    let spec = cfg.cache_pools.get("build").unwrap();
    let plan_for_pool = into_cache_pool_plan("build".into(), spec, &cfg_source).unwrap();
    let mut actual = empty_actual();
    actual.cache_pools.insert(
        "build".into(),
        discovered_pool("build", &plan_for_pool.spec_hash, Drift::InSync),
    );
    let plan = plan_from(&cfg, &actual, &empty_paths()).unwrap();
    let pool_actions: Vec<&Action> = plan
        .actions
        .iter()
        .filter(|a| {
            matches!(
                a,
                Action::CreateCachePool(_)
                    | Action::UpdateCachePool(_)
                    | Action::RemoveCachePool(_)
            )
        })
        .collect();
    assert!(
        pool_actions.is_empty(),
        "in-sync pool must emit no pool action; got: {:?}",
        pool_actions.iter().map(|a| a.label()).collect::<Vec<_>>(),
    );
}

/// Branch 2: `spec_hash` differs ⇒ `UpdateCachePool`. Pool drift
/// stays `InSync`; the `spec_hash` mismatch alone drives the action.
#[test]
fn plan_cache_pool_update_on_spec_hash_change() {
    let cfg = cfg_with_pool("build", vec![CacheKind::Ccache]);
    let mut actual = empty_actual();
    actual.cache_pools.insert(
        "build".into(),
        discovered_pool("build", "sha256:stale", Drift::InSync),
    );
    let plan = plan_from(&cfg, &actual, &empty_paths()).unwrap();
    let updates: Vec<&CachePoolDelta> = plan
        .actions
        .iter()
        .filter_map(|a| match a {
            Action::UpdateCachePool(d) => Some(d),
            _ => None,
        })
        .collect();
    assert_eq!(updates.len(), 1);
    assert_eq!(updates[0].binding.name, "build");
}

/// Branch 3: `spec_hash` matches but drift signals `DropInsModified`
/// ⇒ `UpdateCachePool` (the gate is
/// `spec_hash != actual || !pool_in_sync`).
#[test]
fn plan_cache_pool_update_on_drift_only() {
    let cfg = cfg_with_pool("build", vec![CacheKind::Ccache]);
    let cfg_source = empty_paths().config_dir.join("ghars.toml").to_string();
    let spec = cfg.cache_pools.get("build").unwrap();
    let plan_for_pool = into_cache_pool_plan("build".into(), spec, &cfg_source).unwrap();
    let mut actual = empty_actual();
    // spec_hash matches BUT drift carries an unmanaged drop-in:
    // operator added 99-tuning.conf via `systemctl edit`.
    actual.cache_pools.insert(
        "build".into(),
        discovered_pool(
            "build",
            &plan_for_pool.spec_hash,
            Drift::DropInsModified(vec!["99-tuning.conf".into()]),
        ),
    );
    let plan = plan_from(&cfg, &actual, &empty_paths()).unwrap();
    let updates: Vec<&CachePoolDelta> = plan
        .actions
        .iter()
        .filter_map(|a| match a {
            Action::UpdateCachePool(d) => Some(d),
            _ => None,
        })
        .collect();
    assert_eq!(
        updates.len(),
        1,
        "operator drift on a hash-matched pool must trigger UpdateCachePool"
    );
}

/// Branch 4: pool present in actual but NOT referenced by any
/// desired runner ⇒ `RemoveCachePool`. Pinned by the
/// `actual.cache_pools` − `desired_pool_names` set difference in
/// `plan_from`'s cache-pool diffing block.
#[test]
fn plan_cache_pool_remove_when_orphan() {
    // No runner references the pool; cfg has runner "a" with no
    // caches. Discovered actual carries a "stale-pool" pool.
    let cfg = config_with_runners(vec![minimal_runner("a")]);
    let mut actual = empty_actual();
    actual.cache_pools.insert(
        "stale-pool".into(),
        discovered_pool("stale-pool", "sha256:dead", Drift::InSync),
    );
    let plan = plan_from(&cfg, &actual, &empty_paths()).unwrap();
    let removes: Vec<&Action> = plan
        .actions
        .iter()
        .filter(|a| matches!(a, Action::RemoveCachePool(_)))
        .collect();
    assert_eq!(removes.len(), 1);
    match removes[0] {
        Action::RemoveCachePool(name) => assert_eq!(name, "stale-pool"),
        other => panic!("expected RemoveCachePool, got {other:?}"),
    }
}

/// `drift_cause` on `UpdateRunner`: `SpecChanged` when hashes differ but
/// discovered Drift is `InSync`. Pins the
/// `(!hashes_equal, !in_sync)` match arms in `plan_from`'s
/// intersection branch (the block that emits
/// `Action::UpdateRunner` after the `NoOp` short-circuit).
#[test]
fn plan_update_runner_drift_cause_spec_changed() {
    let cfg = config_with_runners(vec![{
        let mut r = minimal_runner("a");
        r.memory_max = Some("64G".into());
        r
    }]);
    let mut old_runner = cfg.runners[0].clone();
    old_runner.memory_max = Some("32G".into());
    let mut old_spec = merge_defaults(
        &old_runner,
        &cfg.defaults,
        "pat".into(),
        vec![],
        None,
        None,
        None,
        Arch::X86_64,
        cfg_source_default(),
    );
    old_spec.spec_hash = spec_hash(&old_spec);
    let mut actual = empty_actual();
    actual
        .runners
        .insert("a".into(), discovered_for("a", &old_spec, Drift::InSync));
    let plan = plan_from(&cfg, &actual, &empty_paths()).unwrap();
    let upd = plan
        .actions
        .iter()
        .find_map(|a| match a {
            Action::UpdateRunner(d) => Some(d),
            _ => None,
        })
        .expect("expected exactly one UpdateRunner");
    assert_eq!(upd.drift_cause, DriftCause::SpecChanged);
}

/// `drift_cause`: `DriftDetected` when `spec_hash` matches but discovered
/// Drift is non-InSync. Hash equality means no config change;
/// drift means out-of-band edit. Confirms the `(false, true)`
/// arm of the `drift_cause` match in `plan_from`.
#[test]
fn plan_update_runner_drift_cause_drift_detected() {
    // Use minimal_runner unchanged on both sides so spec_hash
    // matches but the discovered runner reports DropInsModified.
    let cfg = config_with_runners(vec![minimal_runner("a")]);
    let runner = cfg.runners[0].clone();
    let mut spec = merge_defaults(
        &runner,
        &cfg.defaults,
        "pat".into(),
        vec![],
        None,
        None,
        None,
        Arch::X86_64,
        cfg_source_default(),
    );
    spec.spec_hash = spec_hash(&spec);
    let mut actual = empty_actual();
    actual.runners.insert(
        "a".into(),
        discovered_for(
            "a",
            &spec,
            Drift::DropInsModified(vec!["99-operator.conf".into()]),
        ),
    );
    let plan = plan_from(&cfg, &actual, &empty_paths()).unwrap();
    let upd = plan
        .actions
        .iter()
        .find_map(|a| match a {
            Action::UpdateRunner(d) => Some(d),
            _ => None,
        })
        .expect("expected one UpdateRunner");
    assert_eq!(upd.drift_cause, DriftCause::DriftDetected);
}

/// `drift_cause`: `SpecChangedAndDriftDetected` when BOTH hashes differ
/// AND on-disk drift is non-InSync. Confirms the `(true, true)`
/// arm of the `drift_cause` match in `plan_from`.
#[test]
fn plan_update_runner_drift_cause_spec_changed_and_drift_detected() {
    let cfg = config_with_runners(vec![{
        let mut r = minimal_runner("a");
        r.memory_max = Some("64G".into());
        r
    }]);
    let mut old_runner = cfg.runners[0].clone();
    old_runner.memory_max = Some("32G".into());
    let mut old_spec = merge_defaults(
        &old_runner,
        &cfg.defaults,
        "pat".into(),
        vec![],
        None,
        None,
        None,
        Arch::X86_64,
        cfg_source_default(),
    );
    old_spec.spec_hash = spec_hash(&old_spec);
    let mut actual = empty_actual();
    actual.runners.insert(
        "a".into(),
        discovered_for(
            "a",
            &old_spec,
            Drift::DropInsModified(vec!["99-operator.conf".into()]),
        ),
    );
    let plan = plan_from(&cfg, &actual, &empty_paths()).unwrap();
    let upd = plan
        .actions
        .iter()
        .find_map(|a| match a {
            Action::UpdateRunner(d) => Some(d),
            _ => None,
        })
        .expect("expected one UpdateRunner");
    assert_eq!(upd.drift_cause, DriftCause::SpecChangedAndDriftDetected);
}

/// recreate-class change must produce an empty `drop_in_changes`
/// payload. The recreate path drops + recreates all drop-ins
/// atomically; per-basename diff is meaningless and would mislead
/// CLI consumers. Pinned by the `requires_recreate` short-circuit
/// in `plan_from`'s (true, true) match arm — when
/// `requires_recreate` is true, `drop_in_changes` is set to
/// `Vec::new()` instead of the rendered Stage 2 diff.
#[test]
fn plan_update_runner_recreate_empties_drop_in_changes() {
    let cfg = config_with_runners(vec![{
        let mut r = minimal_runner("a");
        r.runner_version = Some("2.300.0".into());
        r
    }]);
    let mut old_runner = cfg.runners[0].clone();
    old_runner.runner_version = Some("2.200.0".into());
    let mut old_spec = merge_defaults(
        &old_runner,
        &cfg.defaults,
        "pat".into(),
        vec![],
        None,
        None,
        None,
        Arch::X86_64,
        cfg_source_default(),
    );
    old_spec.spec_hash = spec_hash(&old_spec);
    let mut actual = empty_actual();
    actual
        .runners
        .insert("a".into(), discovered_for("a", &old_spec, Drift::InSync));
    let plan = plan_from(&cfg, &actual, &empty_paths()).unwrap();
    let upd = plan
        .actions
        .iter()
        .find_map(|a| match a {
            Action::UpdateRunner(d) => Some(d),
            _ => None,
        })
        .expect("expected one UpdateRunner");
    assert!(upd.requires_recreate, "runner_version change must recreate");
    assert!(
        upd.drop_in_changes.is_empty(),
        "recreate path must empty drop_in_changes; got {:?}",
        upd.drop_in_changes
    );
}

// ---- auth_name in-place contract --------------------------------

/// Same-discriminant fixture for the auth-name in-place contract:
/// both `[auth.NAME]` blocks are `AuthSpec::Pat`, distinct
/// auth-ref names (`pat-old` → `pat-new`). Same-discriminant
/// Pat→Pat with different auth-ref names is the most common
/// operator transition (token rotation: retire one
/// `[auth.pat-old]` block, point runners at `[auth.pat-new]`),
/// distinct from the same-name `pat`→`github_app` sibling that
/// also uses two `AuthSpec::Pat` blocks but exercises the
/// auth-name strings the cross-discriminant siblings use as
/// labels.
///
/// Satisfies invariants 1-7 of `assert_auth_name_change_is_in_place`
/// (`recreate_reasons` empty, `requires_recreate=false`, single
/// `auth_name` `field_change` with expected before/after,
/// `drift_cause=SpecChanged`, no `auth_kind` leakage, Modified
/// 00-ghars.conf drop-in entry). See the helper docstring for
/// the contract.
#[test]
fn plan_update_in_place_on_auth_name_change_pat_old_to_pat_new_has_empty_recreate_reasons() {
    // Two `[auth.NAME]` blocks named `pat-old` and `pat-new`,
    // both `AuthSpec::Pat`. The runner moves from auth-ref
    // `pat-old` → `pat-new`.
    let mut auth_blocks = IndexMap::new();
    auth_blocks.insert(
        "pat-old".into(),
        AuthSpec::Pat {
            token_env: Some("GHARS_PAT_OLD".into()),
            token_file: None,
        },
    );
    auth_blocks.insert(
        "pat-new".into(),
        AuthSpec::Pat {
            token_env: Some("GHARS_PAT_NEW".into()),
            token_file: None,
        },
    );
    assert_auth_name_change_is_in_place(auth_blocks, "pat-old", "pat-new");
}

/// Same-discriminant pin: both `[auth.NAME]` blocks are
/// `AuthSpec::Interactive` — the unit variant carries no payload,
/// so the two blocks are bytewise identical except for their
/// `IndexMap` key. The classifier must still treat the auth-name
/// string change as in-place: `merge_defaults` lowers each block
/// to a bare `EffectiveRunnerSpec.auth_name` string regardless
/// of discriminant or payload, so the discovered/desired diff is
/// purely on the name string. Degenerate but load-bearing — pins
/// that the classifier never inspects upstream `AuthSpec` content
/// (which would falsely report "no change" here and skip the
/// 00-ghars.conf rewrite).
///
/// Satisfies invariants 1-7 of `assert_auth_name_change_is_in_place`.
#[test]
fn plan_update_in_place_on_auth_name_change_interactive_old_to_interactive_new_has_empty_recreate_reasons()
 {
    let mut auth_blocks = IndexMap::new();
    auth_blocks.insert("interactive-old".into(), AuthSpec::Interactive);
    auth_blocks.insert("interactive-new".into(), AuthSpec::Interactive);
    assert_auth_name_change_is_in_place(auth_blocks, "interactive-old", "interactive-new");
}

/// Same-discriminant pin: both `[auth.NAME]` blocks are
/// `AuthSpec::TokenFile` with distinct `path` fields. Operator
/// rotates the on-disk registration token file (e.g. moves
/// `/etc/ghars/reg.token` → `/etc/ghars/reg2.token`) while
/// keeping the variant. The classifier sees only the
/// auth-name string diff at the `EffectiveRunnerSpec.auth_name`
/// level and must classify in-place; the path diff in the
/// upstream `AuthSpec::TokenFile { path }` is invisible to
/// `merge_defaults` and irrelevant to the
/// `00-ghars.conf` annotation rewrite.
///
/// Satisfies invariants 1-7 of `assert_auth_name_change_is_in_place`.
#[test]
fn plan_update_in_place_on_auth_name_change_token_file_old_to_token_file_new_has_empty_recreate_reasons()
 {
    let mut auth_blocks = IndexMap::new();
    auth_blocks.insert(
        "token-file-old".into(),
        AuthSpec::TokenFile {
            path: Utf8PathBuf::from("/etc/ghars/reg.token"),
        },
    );
    auth_blocks.insert(
        "token-file-new".into(),
        AuthSpec::TokenFile {
            path: Utf8PathBuf::from("/etc/ghars/reg2.token"),
        },
    );
    assert_auth_name_change_is_in_place(auth_blocks, "token-file-old", "token-file-new");
}

/// Same-discriminant pin: both `[auth.NAME]` blocks are
/// `AuthSpec::GithubApp` with distinct `app_id`,
/// `installation_id`, AND `private_key_path` fields. Operator
/// rotates from one App to another (different `app_id`) and
/// updates the install + key alongside. Same-discriminant change
/// must classify in-place because `merge_defaults` reduces both
/// blocks to a bare `EffectiveRunnerSpec.auth_name` string;
/// `app_id`/`installation_id`/`private_key_path` differences
/// don't reach the planner.
///
/// Satisfies invariants 1-7 of `assert_auth_name_change_is_in_place`.
#[test]
fn plan_update_in_place_on_auth_name_change_github_app_old_to_github_app_new_has_empty_recreate_reasons()
 {
    let mut auth_blocks = IndexMap::new();
    auth_blocks.insert(
        "github-app-old".into(),
        AuthSpec::GithubApp {
            app_id: 11111,
            installation_id: 22222,
            private_key_path: Utf8PathBuf::from("/etc/ghars/app-old.pem"),
        },
    );
    auth_blocks.insert(
        "github-app-new".into(),
        AuthSpec::GithubApp {
            app_id: 33333,
            installation_id: 44444,
            private_key_path: Utf8PathBuf::from("/etc/ghars/app-new.pem"),
        },
    );
    assert_auth_name_change_is_in_place(auth_blocks, "github-app-old", "github-app-new");
}

/// Shared scaffold for the auth-name in-place sibling tests
/// (same-discriminant Pat→Pat, cross-discriminant Pat→GithubApp,
/// cross-discriminant GithubApp→Pat).
///
/// Sets up a `Config` with the operator-supplied `auth_blocks`,
/// points the lone runner at `desired_auth_name`, builds a
/// `DiscoveredRunner` whose `EffectiveRunnerSpec.auth_name` is
/// `discovered_auth_name` (modeling a runner registered against
/// that auth ref at a prior apply), invokes `plan_from`, and
/// runs the seven invariants every direction must satisfy:
///
/// 1. `recreate_reasons == vec![]` exactly. Any token pushed into
///    `recreate_reasons` (whether `uncovered`, `auth_name`, or a
///    new token) fails this pin.
/// 2. `requires_recreate == false` — derived from
///    `!recreate_reasons.is_empty()` at `plan_from`'s
///    spec-hash-mismatch arm, so an empty `recreate_reasons`
///    implies false here. Pinned independently because a future
///    refactor could decouple the two.
/// 3. `field_changes.len() == 1` — phantom fields signal regression.
/// 4. `field_changes` contains an `auth_name` `FieldChange` whose
///    `before` matches `FieldValue::String(discovered_auth_name)`
///    and `after` matches `FieldValue::String(desired_auth_name)`.
/// 5. `drift_cause == DriftCause::SpecChanged` — the `auth_name`
///    string diff drives a `spec_hash` mismatch with no on-disk
///    drift (the discovered drop-in is freshly rendered by
///    `discovered_for`, so `DriftDetected` cannot fire).
/// 6. `auth_kind` does NOT appear in `field_changes` —
///    `merge_defaults` strips the `AuthSpec` discriminant when
///    lowering to `EffectiveRunnerSpec.auth_name`, so the
///    classifier never observes an `auth_kind` surface and must
///    not synthesize one.
/// 7. `drop_in_changes` contains a `Modified` entry for
///    `00-ghars.conf` — `render_identity` emits the `auth_name`
///    string into the `X-Ghars-Auth-Name` annotation, so an
///    auth-name change always produces an observable drop-in
///    diff. A regression that classifies as in-place but skips
///    the file rewrite would silently leave the annotation
///    pointing at the discovered side after the apply, breaking
///    the next planner cycle's annotation-vs-config comparison.
///
/// Each caller passes its own `auth_blocks`
/// (`IndexMap<String, AuthSpec>`) so same-discriminant vs
/// cross-discriminant fixture shapes stay caller-controlled —
/// the helper does not fabricate `AuthSpec` content. The expected
/// `FieldChange` before/after are derived from the two name
/// arguments (`merge_defaults` lowers the auth ref to a bare
/// `EffectiveRunnerSpec.auth_name` string with no normalization,
/// so the rendered before/after are literal pass-through of the
/// caller-supplied names).
fn assert_auth_name_change_is_in_place(
    auth_blocks: IndexMap<String, AuthSpec>,
    discovered_auth_name: &str,
    desired_auth_name: &str,
) {
    let expected_before = FieldValue::String(discovered_auth_name.into());
    let expected_after = FieldValue::String(desired_auth_name.into());
    let mut cfg = config_with_runners(vec![{
        let mut r = minimal_runner("a");
        r.auth = Some(desired_auth_name.into());
        r
    }]);
    cfg.auth = auth_blocks;

    // Discovered runner was registered against discovered_auth_name.
    // Building the discovered spec via merge_defaults exercises the
    // production lowering path; the resulting
    // EffectiveRunnerSpec.auth_name is the bare string, matching
    // what state.rs would parse out of the on-disk
    // X-Ghars-Auth-Name annotation.
    let old_runner = cfg.runners[0].clone();
    let mut old_spec = merge_defaults(
        &old_runner,
        &cfg.defaults,
        discovered_auth_name.into(),
        vec![],
        None,
        None,
        None,
        Arch::X86_64,
        cfg_source_default(),
    );
    old_spec.spec_hash = spec_hash(&old_spec);
    let mut actual = empty_actual();
    actual
        .runners
        .insert("a".into(), discovered_for("a", &old_spec, Drift::InSync));

    let plan = plan_from(&cfg, &actual, &empty_paths()).unwrap();
    let upd = plan
        .actions
        .iter()
        .find_map(|a| match a {
            Action::UpdateRunner(d) => Some(d),
            _ => None,
        })
        .expect("auth-name change must emit UpdateRunner");

    // 1. recreate_reasons exactly empty.
    assert_eq!(
        upd.recreate_reasons,
        Vec::<&'static str>::new(),
        "auth-name change ({discovered_auth_name} → {desired_auth_name}) must \
         produce empty recreate_reasons (no \"uncovered\", no \"auth_name\", \
         nothing); got: {:?}",
        upd.recreate_reasons,
    );
    // 2. requires_recreate false.
    assert!(
        !upd.requires_recreate,
        "auth-name change ({discovered_auth_name} → {desired_auth_name}) must \
         remain in-place — requires_recreate must be false (derived from \
         plan_from's `requires_recreate = !recreate_reasons.is_empty()` gate)",
    );
    // 3. field_changes has exactly one entry.
    assert_eq!(
        upd.field_changes.len(),
        1,
        "auth_name change must be the only field_changes entry; \
         phantom fields signal regression — got: {:?}",
        upd.field_changes,
    );
    // 4. field_changes contains auth_name with correct before/after.
    let auth_name_change = upd
        .field_changes
        .iter()
        .find(|fc| fc.path == "auth_name")
        .expect("field_changes must include auth_name entry");
    assert_eq!(
        auth_name_change.before, expected_before,
        "before must reflect the discovered side's auth_name string",
    );
    assert_eq!(
        auth_name_change.after, expected_after,
        "after must reflect the desired side's auth_name string",
    );
    // 5. drift_cause is SpecChanged.
    assert_eq!(
        upd.drift_cause,
        DriftCause::SpecChanged,
        "auth-name change ({discovered_auth_name} → {desired_auth_name}) must \
         classify as SpecChanged: the auth_name string diff drives a \
         spec_hash mismatch with no on-disk drift",
    );
    // 6. auth_kind discriminant must NOT leak into field_changes.
    assert!(
        !upd.field_changes.iter().any(|fc| fc.path == "auth_kind"),
        "auth_kind must NOT appear — discriminant is stripped by \
         merge_defaults; got field_changes: {:?}",
        upd.field_changes,
    );
    // 7. 00-ghars.conf drop-in is Modified (X-Ghars-Auth-Name rewrite).
    assert!(
        upd.drop_in_changes.iter().any(|dc| {
            dc.basename == "00-ghars.conf" && matches!(dc.change, DropInChangeKind::Modified { .. })
        }),
        "auth-name change ({discovered_auth_name} → {desired_auth_name}) must \
         produce Modified 00-ghars.conf drop-in change; got: {:?}",
        upd.drop_in_changes,
    );
}

/// Shared cross-discriminant `[auth.NAME]` fixture: a `pat` block
/// of kind `AuthSpec::Pat` paired with a `github_app` block of
/// kind `AuthSpec::GithubApp`. Used by the forward
/// (`pat → github_app`) and inverse (`github_app → pat`) sibling
/// tests of the auth-name in-place contract — the two directions
/// share an identical fixture and differ only in which auth-ref
/// name appears on the discovered vs desired side.
///
/// Centralizing the construction keeps the two siblings in lock-
/// step: if the `GithubApp` content changes (e.g. `private_key_path`
/// moves to a different convention), both directions re-derive
/// from a single source.
fn auth_blocks_with_pat_and_github_app() -> IndexMap<String, AuthSpec> {
    let mut auth_blocks = IndexMap::new();
    auth_blocks.insert(
        "pat".into(),
        AuthSpec::Pat {
            token_env: Some("GHARS_PAT".into()),
            token_file: None,
        },
    );
    auth_blocks.insert(
        "github_app".into(),
        AuthSpec::GithubApp {
            app_id: 12345,
            installation_id: 67890,
            private_key_path: Utf8PathBuf::from("/etc/ghars/app.pem"),
        },
    );
    auth_blocks
}

/// Naming-vs-discriminant pin for the auth-name in-place
/// contract: the two `[auth.NAME]` blocks have different names
/// (`pat` → `github_app`) but identical `AuthSpec::Pat`
/// discriminants — the auth-name string change must drive the
/// in-place classifier on its own, with the matching discriminant
/// providing no information to the planner. Confirms the
/// classifier reads `EffectiveRunnerSpec.auth_name` (the bare
/// string after `merge_defaults` lowering) and never the upstream
/// `AuthSpec` variant.
///
/// Satisfies invariants 1-7 of `assert_auth_name_change_is_in_place`
/// (`recreate_reasons` empty, `requires_recreate=false`, single
/// `auth_name` `field_change` with expected before/after,
/// `drift_cause=SpecChanged`, no `auth_kind` leakage, Modified
/// 00-ghars.conf drop-in entry). See the helper docstring for
/// the contract; this test contributes the same-discriminant
/// fixture.
#[test]
fn plan_update_in_place_on_auth_name_change_has_empty_recreate_reasons() {
    // Two `[auth.NAME]` blocks named `pat` and `github_app`. Both
    // are AuthSpec::Pat under the hood — merge_defaults only sees
    // the auth_name string, so this is an auth-name string change
    // end-to-end.
    let mut auth_blocks = IndexMap::new();
    auth_blocks.insert(
        "pat".into(),
        AuthSpec::Pat {
            token_env: Some("GHARS_PAT".into()),
            token_file: None,
        },
    );
    auth_blocks.insert(
        "github_app".into(),
        AuthSpec::Pat {
            token_env: Some("GHARS_PAT_GHAPP".into()),
            token_file: None,
        },
    );
    assert_auth_name_change_is_in_place(auth_blocks, "pat", "github_app");
}

/// Cross-discriminant pin for the auth-name in-place contract:
/// the discovered side carries `AuthSpec::Pat`, the desired side
/// carries `AuthSpec::GithubApp`. Direction is `pat → github_app`
/// (the common operator transition: PAT for personal automation
/// → GitHub App for org-scale rollout). `merge_defaults` lowers
/// the `[auth.NAME]` block to a bare `auth_name` string, so the
/// classifier sees a pure `auth_name` string diff regardless of
/// which discriminants the two blocks carry. The same-discriminant
/// sibling test
/// `plan_update_in_place_on_auth_name_change_has_empty_recreate_reasons`
/// pins the matching-discriminant case; the
/// `github_app → pat` sibling pins the inverse direction.
///
/// Satisfies invariants 1-7 of `assert_auth_name_change_is_in_place`
/// (`recreate_reasons` empty, `requires_recreate=false`, single
/// `auth_name` `field_change` with expected before/after,
/// `drift_cause=SpecChanged`, no `auth_kind` leakage, Modified
/// 00-ghars.conf drop-in entry). See the helper docstring for
/// the contract.
#[test]
fn plan_update_in_place_on_auth_name_change_pat_to_github_app_has_empty_recreate_reasons() {
    // REAL cross-discriminant shape (Pat + GithubApp) shared with
    // the inverse-direction sibling test. The runner.auth ref
    // switches from "pat" (discovered side) to "github_app"
    // (desired side).
    assert_auth_name_change_is_in_place(auth_blocks_with_pat_and_github_app(), "pat", "github_app");
}

/// Inverse-direction cross-discriminant pin: discovered side
/// carries `AuthSpec::GithubApp`, desired side switches to
/// `AuthSpec::Pat`. Direction is `github_app → pat` — the
/// operator-rare but classifier-important rollback case
/// (App → PAT for break-glass debug or App credential rotation
/// hotfix). The forward `pat → github_app` sibling alone would
/// leave a coverage hole: a regression that inspects only one
/// direction's discriminant pair could pass forward and break
/// inverse. Pinning both directions enforces the classifier's
/// discriminant-stripping invariant symmetrically — `merge_defaults`
/// lowers the `[auth.NAME]` block to a bare `auth_name` string
/// regardless of `AuthSpec` variant.
///
/// Satisfies invariants 1-7 of `assert_auth_name_change_is_in_place`
/// (`recreate_reasons` empty, `requires_recreate=false`, single
/// `auth_name` `field_change` with expected before/after,
/// `drift_cause=SpecChanged`, no `auth_kind` leakage, Modified
/// 00-ghars.conf drop-in entry). See the helper docstring for
/// the contract.
#[test]
fn plan_update_in_place_on_auth_name_change_github_app_to_pat_has_empty_recreate_reasons() {
    // REAL cross-discriminant shape (Pat + GithubApp) shared with
    // the forward-direction sibling test. The runner.auth ref
    // switches in the OPPOSITE direction: from "github_app"
    // (discovered side) to "pat" (desired side).
    assert_auth_name_change_is_in_place(auth_blocks_with_pat_and_github_app(), "github_app", "pat");
}

/// Cross-discriminant fixture: a `pat` block (`AuthSpec::Pat`)
/// paired with an `interactive` block (`AuthSpec::Interactive`).
/// Shared by the `pat ↔ interactive` direction-pair tests so
/// both directions re-derive from a single source.
fn auth_blocks_with_pat_and_interactive() -> IndexMap<String, AuthSpec> {
    let mut auth_blocks = IndexMap::new();
    auth_blocks.insert(
        "pat".into(),
        AuthSpec::Pat {
            token_env: Some("GHARS_PAT".into()),
            token_file: None,
        },
    );
    auth_blocks.insert("interactive".into(), AuthSpec::Interactive);
    auth_blocks
}

/// Cross-discriminant fixture: a `pat` block (`AuthSpec::Pat`)
/// paired with a `token_file` block (`AuthSpec::TokenFile`).
/// Shared by the `pat ↔ token_file` direction-pair tests.
fn auth_blocks_with_pat_and_token_file() -> IndexMap<String, AuthSpec> {
    let mut auth_blocks = IndexMap::new();
    auth_blocks.insert(
        "pat".into(),
        AuthSpec::Pat {
            token_env: Some("GHARS_PAT".into()),
            token_file: None,
        },
    );
    auth_blocks.insert(
        "token_file".into(),
        AuthSpec::TokenFile {
            path: Utf8PathBuf::from("/etc/ghars/registration.token"),
        },
    );
    auth_blocks
}

/// Cross-discriminant fixture: a `github_app` block
/// (`AuthSpec::GithubApp`) paired with an `interactive` block
/// (`AuthSpec::Interactive`). Shared by the
/// `github_app ↔ interactive` direction-pair tests.
fn auth_blocks_with_github_app_and_interactive() -> IndexMap<String, AuthSpec> {
    let mut auth_blocks = IndexMap::new();
    auth_blocks.insert(
        "github_app".into(),
        AuthSpec::GithubApp {
            app_id: 12345,
            installation_id: 67890,
            private_key_path: Utf8PathBuf::from("/etc/ghars/app.pem"),
        },
    );
    auth_blocks.insert("interactive".into(), AuthSpec::Interactive);
    auth_blocks
}

/// Cross-discriminant fixture: a `github_app` block
/// (`AuthSpec::GithubApp`) paired with a `token_file` block
/// (`AuthSpec::TokenFile`). Shared by the
/// `github_app ↔ token_file` direction-pair tests.
fn auth_blocks_with_github_app_and_token_file() -> IndexMap<String, AuthSpec> {
    let mut auth_blocks = IndexMap::new();
    auth_blocks.insert(
        "github_app".into(),
        AuthSpec::GithubApp {
            app_id: 12345,
            installation_id: 67890,
            private_key_path: Utf8PathBuf::from("/etc/ghars/app.pem"),
        },
    );
    auth_blocks.insert(
        "token_file".into(),
        AuthSpec::TokenFile {
            path: Utf8PathBuf::from("/etc/ghars/registration.token"),
        },
    );
    auth_blocks
}

/// Cross-discriminant fixture: an `interactive` block
/// (`AuthSpec::Interactive`) paired with a `token_file` block
/// (`AuthSpec::TokenFile`). Shared by the
/// `interactive ↔ token_file` direction-pair tests.
fn auth_blocks_with_interactive_and_token_file() -> IndexMap<String, AuthSpec> {
    let mut auth_blocks = IndexMap::new();
    auth_blocks.insert("interactive".into(), AuthSpec::Interactive);
    auth_blocks.insert(
        "token_file".into(),
        AuthSpec::TokenFile {
            path: Utf8PathBuf::from("/etc/ghars/registration.token"),
        },
    );
    auth_blocks
}

/// Cross-discriminant pin: discovered side `AuthSpec::Pat`,
/// desired side `AuthSpec::Interactive`. Direction is
/// `pat → interactive`. Note: `AuthSpec::Interactive` is a
/// unit variant — it carries no payload fields. The
/// auth-name-in-place contract still holds because
/// `merge_defaults` strips the discriminant when lowering
/// to `EffectiveRunnerSpec.auth_name` (a bare String); the
/// classifier sees a pure `auth_name` string diff regardless of
/// whether either side has a payload. This test pins that the
/// payload-free Interactive variant participates in the
/// auth-name in-place contract identically to the
/// payload-bearing Pat / `GithubApp` / `TokenFile` variants.
///
/// Satisfies invariants 1-7 of `assert_auth_name_change_is_in_place`
/// (`recreate_reasons` empty, `requires_recreate=false`, single
/// `auth_name` `field_change` with expected before/after,
/// `drift_cause=SpecChanged`, no `auth_kind` leakage, Modified
/// 00-ghars.conf drop-in entry). See the helper docstring for
/// the contract.
#[test]
fn plan_update_in_place_on_auth_name_change_pat_to_interactive_has_empty_recreate_reasons() {
    assert_auth_name_change_is_in_place(
        auth_blocks_with_pat_and_interactive(),
        "pat",
        "interactive",
    );
}

/// Inverse-direction pin of `pat_to_interactive`: discovered
/// side `AuthSpec::Interactive`, desired side `AuthSpec::Pat`.
/// Direction is `interactive → pat`. Pinned independently
/// because a regression that inspected only one direction's
/// discriminant pair could pass forward and break inverse.
///
/// Satisfies invariants 1-7 of `assert_auth_name_change_is_in_place`.
#[test]
fn plan_update_in_place_on_auth_name_change_interactive_to_pat_has_empty_recreate_reasons() {
    assert_auth_name_change_is_in_place(
        auth_blocks_with_pat_and_interactive(),
        "interactive",
        "pat",
    );
}

/// Cross-discriminant pin: discovered side `AuthSpec::Pat`,
/// desired side `AuthSpec::TokenFile`. Direction is
/// `pat → token_file` — the operator-rare but
/// classifier-important transition (long-lived PAT
/// → short-lived pre-minted registration token). The
/// classifier must treat this as a pure `auth_name` string diff
/// despite the upstream discriminant flip.
///
/// Satisfies invariants 1-7 of `assert_auth_name_change_is_in_place`.
#[test]
fn plan_update_in_place_on_auth_name_change_pat_to_token_file_has_empty_recreate_reasons() {
    assert_auth_name_change_is_in_place(auth_blocks_with_pat_and_token_file(), "pat", "token_file");
}

/// Inverse-direction pin of `pat_to_token_file`: discovered
/// side `AuthSpec::TokenFile`, desired side `AuthSpec::Pat`.
/// Direction is `token_file → pat`.
///
/// Satisfies invariants 1-7 of `assert_auth_name_change_is_in_place`.
#[test]
fn plan_update_in_place_on_auth_name_change_token_file_to_pat_has_empty_recreate_reasons() {
    assert_auth_name_change_is_in_place(auth_blocks_with_pat_and_token_file(), "token_file", "pat");
}

/// Cross-discriminant pin: discovered side
/// `AuthSpec::GithubApp`, desired side `AuthSpec::Interactive`.
/// Direction is `github_app → interactive` — break-glass
/// debug after App credential issues.
///
/// Satisfies invariants 1-7 of `assert_auth_name_change_is_in_place`.
#[test]
fn plan_update_in_place_on_auth_name_change_github_app_to_interactive_has_empty_recreate_reasons() {
    assert_auth_name_change_is_in_place(
        auth_blocks_with_github_app_and_interactive(),
        "github_app",
        "interactive",
    );
}

/// Inverse-direction pin of `github_app_to_interactive`:
/// discovered side `AuthSpec::Interactive`, desired side
/// `AuthSpec::GithubApp`. Direction is `interactive → github_app`
/// — typical promotion from operator-pasted token to
/// org-scale App.
///
/// Satisfies invariants 1-7 of `assert_auth_name_change_is_in_place`.
#[test]
fn plan_update_in_place_on_auth_name_change_interactive_to_github_app_has_empty_recreate_reasons() {
    assert_auth_name_change_is_in_place(
        auth_blocks_with_github_app_and_interactive(),
        "interactive",
        "github_app",
    );
}

/// Cross-discriminant pin: discovered side
/// `AuthSpec::GithubApp`, desired side `AuthSpec::TokenFile`.
/// Direction is `github_app → token_file`.
///
/// Satisfies invariants 1-7 of `assert_auth_name_change_is_in_place`.
#[test]
fn plan_update_in_place_on_auth_name_change_github_app_to_token_file_has_empty_recreate_reasons() {
    assert_auth_name_change_is_in_place(
        auth_blocks_with_github_app_and_token_file(),
        "github_app",
        "token_file",
    );
}

/// Inverse-direction pin of `github_app_to_token_file`:
/// discovered side `AuthSpec::TokenFile`, desired side
/// `AuthSpec::GithubApp`. Direction is `token_file → github_app`.
///
/// Satisfies invariants 1-7 of `assert_auth_name_change_is_in_place`.
#[test]
fn plan_update_in_place_on_auth_name_change_token_file_to_github_app_has_empty_recreate_reasons() {
    assert_auth_name_change_is_in_place(
        auth_blocks_with_github_app_and_token_file(),
        "token_file",
        "github_app",
    );
}

/// Cross-discriminant pin: discovered side
/// `AuthSpec::Interactive`, desired side `AuthSpec::TokenFile`.
/// Direction is `interactive → token_file` — the operator
/// formalizes the token-paste workflow into a managed file.
///
/// Satisfies invariants 1-7 of `assert_auth_name_change_is_in_place`.
#[test]
fn plan_update_in_place_on_auth_name_change_interactive_to_token_file_has_empty_recreate_reasons() {
    assert_auth_name_change_is_in_place(
        auth_blocks_with_interactive_and_token_file(),
        "interactive",
        "token_file",
    );
}

/// Inverse-direction pin of `interactive_to_token_file`:
/// discovered side `AuthSpec::TokenFile`, desired side
/// `AuthSpec::Interactive`. Direction is `token_file → interactive`.
///
/// Satisfies invariants 1-7 of `assert_auth_name_change_is_in_place`.
#[test]
fn plan_update_in_place_on_auth_name_change_token_file_to_interactive_has_empty_recreate_reasons() {
    assert_auth_name_change_is_in_place(
        auth_blocks_with_interactive_and_token_file(),
        "token_file",
        "interactive",
    );
}

// ---- caches in-place contract -----------------------------------

/// caches change is in-place per design Part 3. The
/// caches in-place classifier branch must:
///   - record a `FieldChange` { path: "caches", before, after };
///   - NOT push to `recreate_reasons`;
///   - NOT trip the `uncovered` fallback (gated on
///     `field_changes.is_empty()` at the `spec_hash` mismatch
///     check in `plan_from`).
/// apply.rs's in-place `execute_update_runner` rewrites the
/// 30-cache-pool.conf drop-in body and cycles the unit so the
/// post-update `BindPaths` take effect; no host-state migration
/// requires the recreate path.
#[test]
fn plan_update_runner_caches_change_is_in_place_with_field_change() {
    // Two cache pools in the same trust_zone (so the runner
    // can reference either without trust_zone-validation noise).
    // Runner moves from caches=["pool-old"] → ["pool-new"].
    let mut cfg = config_with_runners(vec![{
        let mut r = minimal_runner("a");
        r.caches = vec!["pool-new".into()];
        r
    }]);
    cfg.cache_pools.insert(
        "pool-old".into(),
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
        "pool-new".into(),
        CachePoolSpec {
            kinds: vec![CacheKind::Ccache],
            size: "10G".into(),
            mode: CacheMode::Shared,
            trust_zone: "default".into(),
            sccache_path: None,
            sleep_path: Some("/usr/bin/sleep".into()),
        },
    );

    // Discovered runner was registered against pool-old.
    let mut old_runner = cfg.runners[0].clone();
    old_runner.caches = vec!["pool-old".into()];
    let old_binding = EffectiveCacheBinding {
        name: "pool-old".into(),
        kinds: vec![CacheKind::Ccache],
        size: "10G".into(),
        mode: CacheMode::Shared,
        trust_zone: "default".into(),
        sccache_path: None,
        sleep_path: Some("/usr/bin/sleep".into()),
        renderer_schema: crate::systemd::RENDERER_SCHEMA,
    };
    let mut old_spec = merge_defaults(
        &old_runner,
        &cfg.defaults,
        "pat".into(),
        vec![old_binding],
        None,
        None,
        None,
        Arch::X86_64,
        cfg_source_default(),
    );
    old_spec.spec_hash = spec_hash(&old_spec);
    let mut actual = empty_actual();
    actual
        .runners
        .insert("a".into(), discovered_for("a", &old_spec, Drift::InSync));

    let plan = plan_from(&cfg, &actual, &empty_paths()).unwrap();
    let upd = plan
        .actions
        .iter()
        .find_map(|a| match a {
            Action::UpdateRunner(d) => Some(d),
            _ => None,
        })
        .expect("caches change must emit UpdateRunner");
    assert!(
        !upd.requires_recreate,
        "caches change must be in-place; got reasons {:?}",
        upd.recreate_reasons
    );
    assert!(
        !upd.recreate_reasons.contains(&"uncovered"),
        "caches change must NOT trip uncovered fallback; got reasons {:?}",
        upd.recreate_reasons
    );
    let caches_change = upd
        .field_changes
        .iter()
        .find(|fc| fc.path == "caches")
        .expect("field_changes must include caches entry");
    assert_eq!(
        caches_change.before,
        FieldValue::List(vec!["pool-old".into()])
    );
    assert_eq!(
        caches_change.after,
        FieldValue::List(vec!["pool-new".into()])
    );
}

/// A pure caches reorder (operator rewrites
/// `caches = ["pool-b", "pool-a"]` as `caches = ["pool-a", "pool-b"]`
/// in TOML, no membership change) MUST end-to-end produce a
/// `NoOp`, not an `UpdateRunner`. Without `lower_to_effective`
/// sorting the caches Vec by name, the `spec_hash` flips on reorder
/// (Vec preserves source order in canonical JSON); after the sort,
/// both orderings produce the same spec, the same `spec_hash`, and
/// the same rendered drop-in bytes (X-Ghars-Caches=, the
/// 30-cache-pool.conf body) — so plan diff sees nothing to do.
///
/// Built end-to-end through `plan_from` so this test exercises
/// the full pipeline — `lower_to_effective` sort → `spec_hash`
/// canonical-JSON → `render_identity` X-Ghars-Caches → `render_cache_pool`
/// 30-cache-pool.conf body. A regression that dropped the sort
/// from `lower_to_effective` would trip the Stage 2 body diff
/// (the `30-cache-pool.conf` rendered for the second config would
/// iterate `spec.caches` in operator-supplied order, differing
/// from what `discovered_for` wrote for the first config) and
/// surface as an `UpdateRunner` with `any_drop_in_modified=true`.
#[test]
fn plan_noop_when_caches_reorder_only() {
    // Build a config with two cache pools in the same trust_zone
    // and a runner that references both.
    let make_cfg = |order: Vec<&str>| -> Config {
        let mut cfg = config_with_runners(vec![{
            let mut r = minimal_runner("a");
            r.caches = order.into_iter().map(String::from).collect();
            r
        }]);
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
            "pool-b".into(),
            CachePoolSpec {
                kinds: vec![CacheKind::Sccache],
                size: "10G".into(),
                mode: CacheMode::Shared,
                trust_zone: "default".into(),
                sccache_path: Some("/usr/bin/sccache".into()),
                sleep_path: None,
            },
        );
        cfg
    };

    // First config: operator wrote ["pool-b", "pool-a"]. Run
    // plan_from once with empty actual state — produces a
    // CreateRunner whose spec carries the canonical sorted spec.
    let cfg_first = make_cfg(vec!["pool-b", "pool-a"]);
    let plan_first =
        plan_from(&cfg_first, &empty_actual(), &empty_paths()).expect("first plan must succeed");
    let first_spec = plan_first
        .actions
        .iter()
        .find_map(|a| match a {
            Action::CreateRunner(rp) => Some(rp.spec.clone()),
            _ => None,
        })
        .expect("first plan must emit CreateRunner");

    // Discovered state mirrors the first config's apply: same
    // spec_hash, render_runner_unit-derived drop-ins (via
    // discovered_for), Drift::InSync.
    let mut actual = empty_actual();
    actual
        .runners
        .insert("a".into(), discovered_for("a", &first_spec, Drift::InSync));

    // Second config: operator reorders to ["pool-a", "pool-b"].
    // After lower_to_effective sorts by name, both configs lower
    // to the same EffectiveRunnerSpec → same spec_hash → no diff.
    let cfg_second = make_cfg(vec!["pool-a", "pool-b"]);
    let plan_second =
        plan_from(&cfg_second, &actual, &empty_paths()).expect("second plan must succeed");

    // The reorder must produce a NoOp, not UpdateRunner.
    let noops: Vec<_> = plan_second
        .actions
        .iter()
        .filter(|a| matches!(a, Action::NoOp(_)))
        .collect();
    let updates: Vec<_> = plan_second
        .actions
        .iter()
        .filter_map(|a| match a {
            Action::UpdateRunner(d) => Some(d),
            _ => None,
        })
        .collect();
    assert!(
        updates.is_empty(),
        "caches reorder must NOT produce UpdateRunner; got: {updates:?}"
    );
    assert_eq!(
        noops.len(),
        1,
        "caches reorder must produce exactly one NoOp; got plan: {:?}",
        plan_second.actions
    );
}

/// A pure labels reorder (operator rewrites
/// `labels = ["beta","alpha"]` as `labels = ["alpha","beta"]` in
/// TOML, no membership change) MUST end-to-end produce a `NoOp`,
/// not an `UpdateRunner`. Mirrors `plan_noop_when_caches_reorder_only`
/// for the caches treatment. Labels are set-semantic for GitHub
/// Actions runner registration — workflow `runs-on:` matches
/// against the registered label set order-independently — so a
/// cosmetic reorder must NOT drive a recreate-class `UpdateRunner`.
///
/// Without `merge_defaults` sorting `labels` by name, the
/// `spec_hash` flips on reorder (Vec preserves source order in
/// canonical JSON; Stage 1 classifier would then either fire the
/// `labels` typed reason on the annotation diff or fall through
/// to the `uncovered` in-place arm and incur an unnecessary
/// unit-restart for a no-op edit). After the sort, both orderings
/// produce the same spec, the same `spec_hash`, and the same
/// rendered `X-Ghars-Labels=` annotation, so plan diff sees
/// nothing to do.
///
/// Built end-to-end through `plan_from` so this test exercises
/// the full pipeline — `lower_to_effective` (calls `merge_defaults`)
/// → `spec_hash` canonical-JSON → `render_identity` X-Ghars-Labels.
/// A regression that dropped the sort from `merge_defaults` would
/// trip the Stage 1 classifier or the `spec_hash` mismatch and
/// surface as an `UpdateRunner` with the `labels` recreate reason.
#[test]
fn plan_noop_when_labels_reorder_only() {
    let make_cfg = |order: Vec<&str>| -> Config {
        config_with_runners(vec![{
            let mut r = minimal_runner("a");
            r.labels = order.into_iter().map(String::from).collect();
            r
        }])
    };

    // First config: operator wrote ["beta","alpha"]. Run plan_from
    // once with empty actual state — produces a CreateRunner
    // whose spec carries the canonical sorted spec.
    let cfg_first = make_cfg(vec!["beta", "alpha"]);
    let plan_first =
        plan_from(&cfg_first, &empty_actual(), &empty_paths()).expect("first plan must succeed");
    let first_spec = plan_first
        .actions
        .iter()
        .find_map(|a| match a {
            Action::CreateRunner(rp) => Some(rp.spec.clone()),
            _ => None,
        })
        .expect("first plan must emit CreateRunner");
    // Pin the canonical-sorted contract on the first spec so any
    // regression dropping the sort fails this assertion before
    // the NoOp check. Both ["beta","alpha"] and ["alpha","beta"]
    // must lower to ["alpha","beta"].
    assert_eq!(
        first_spec.labels,
        vec!["alpha".to_string(), "beta".to_string()],
        "merge_defaults must sort labels; got: {:?}",
        first_spec.labels
    );

    // Discovered state mirrors the first config's apply: same
    // spec_hash, render_runner_unit-derived drop-ins (via
    // discovered_for), Drift::InSync.
    let mut actual = empty_actual();
    actual
        .runners
        .insert("a".into(), discovered_for("a", &first_spec, Drift::InSync));

    // Second config: operator reorders to ["alpha","beta"]. After
    // merge_defaults sorts, both configs lower to the same
    // EffectiveRunnerSpec → same spec_hash → no diff.
    let cfg_second = make_cfg(vec!["alpha", "beta"]);
    let plan_second =
        plan_from(&cfg_second, &actual, &empty_paths()).expect("second plan must succeed");

    // The reorder must produce a NoOp, not UpdateRunner.
    let noops: Vec<_> = plan_second
        .actions
        .iter()
        .filter(|a| matches!(a, Action::NoOp(_)))
        .collect();
    let updates: Vec<_> = plan_second
        .actions
        .iter()
        .filter_map(|a| match a {
            Action::UpdateRunner(d) => Some(d),
            _ => None,
        })
        .collect();
    assert!(
        updates.is_empty(),
        "labels reorder must NOT produce UpdateRunner; got: {updates:?}"
    );
    assert_eq!(
        noops.len(),
        1,
        "labels reorder must produce exactly one NoOp; got plan: {:?}",
        plan_second.actions
    );
}

/// First-post-upgrade transition: a runner whose on-disk
/// `X-Ghars-Spec-Hash` was computed by a pre-canonicalization
/// `merge_defaults` (no labels sort) must produce an `UpdateRunner`
/// with `requires_recreate=false` (IN-PLACE) on the first plan run
/// after the upgrade. The in-place apply path then re-renders the
/// canonical 00-ghars.conf (with the NEW `X-Ghars-Spec-Hash`
/// annotation) and the next plan returns to `NoOp` (the steady-state
/// pinned by `plan_noop_when_labels_reorder_only` above).
///
/// Mirrors the caches-canonicalization class but exercises the
/// HASH-MISMATCH gate rather than the steady-state `NoOp` gate.
/// Routes specifically through the `uncovered` arm at the
/// `recreate_reasons` site in `plan_from`'s intersection branch:
///   - `!hashes_equal`: discovered carries the pre-canonical OLD
///     hash, desired re-hashes to NEW after `merge_defaults`
///     sorts.
///   - `recreate_reasons.is_empty()`: Stage 1 labels classifier
///     sorts BOTH sides via `sorted_set_field_diff` so the set-
///     equal labels produce no `labels` recreate reason.
///   - `field_changes.is_empty()`: same path, no `FieldChange`
///     emitted for set-equal sorted comparison.
///   - `!any_drop_in_modified`: the only Modified drop-in is
///     `00-ghars.conf` (carries `X-Ghars-Spec-Hash`), which is
///     filtered out of the in-place evidence set by the basename
///     gate at the `any_drop_in_modified` filter.
///
/// Before the uncovered-arm decoupling, the `uncovered` arm pushed a "uncovered"
/// recreate reason, forcing a destructive stop+unregister+create
/// cycle for what was effectively a labels-reorder noop. Post-fix,
/// the arm falls through to in-place: the X-Ghars-Spec-Hash
/// annotation in 00-ghars.conf gets re-rendered with the NEW hash
/// and the unit restarts to pick up the byte-changed drop-in, but
/// the runner stays registered with GitHub and any in-flight
/// workload only experiences the standard in-place restart cycle.
///
/// Fixture construction: clone the canonical spec (post-merge_-
/// defaults, labels sorted), then assign an unsorted labels Vec
/// AND recompute `spec_hash` from the unsorted-labels spec. That
/// recomputation is what makes the OLD hash distinct from NEW —
/// `spec_hash` clears the embedded hash before serializing and
/// the labels Vec is part of the canonical-JSON payload, so a
/// reordered labels Vec lands at a different SHA-256 output.
/// `discovered_for` then renders drop-ins from this pre-canonical
/// spec; `render_identity`'s defense-in-depth sort (systemd.rs)
/// re-sorts labels in the X-Ghars-Labels emission, but the OLD
/// hash persists in `X-Ghars-Spec-Hash` and on the
/// `DiscoveredRunner` field.
///
/// A regression that REMOVED the `merge_defaults` labels sort
/// would silently break this transition guarantee — the new plan
/// would compute a hash from unsorted labels matching the OLD
/// hash (no rewrite fires) and the canonicalization promise
/// (steady-state byte-identical X-Ghars-Labels) would silently
/// erode. A regression that RE-INTRODUCED the `uncovered` recreate
/// push would surface as `requires_recreate=true` here, breaking
/// the non-destructive-default contract.
#[test]
fn plan_first_post_upgrade_labels_canonicalization_emits_in_place_update() {
    // Desired: operator config with labels in some order. After
    // merge_defaults, labels sort to ["alpha","beta","middle"]
    // and spec_hash captures that canonical form (NEW).
    let cfg = config_with_runners(vec![{
        let mut r = minimal_runner("a");
        r.labels = vec!["middle".into(), "alpha".into(), "beta".into()];
        r
    }]);
    let desired_spec = merge_defaults(
        &cfg.runners[0],
        &cfg.defaults,
        "pat".into(),
        vec![],
        None,
        None,
        None,
        Arch::X86_64,
        cfg_source_default(),
    );
    // Canonical contract pin: merge_defaults must sort labels.
    // If this assertion fails, the test scaffold itself is broken
    // and the body assertions below would be evaluating against
    // a non-canonical desired spec.
    assert_eq!(
        desired_spec.labels,
        vec![
            "alpha".to_string(),
            "beta".to_string(),
            "middle".to_string()
        ],
        "merge_defaults must sort labels for the desired spec; got: {:?}",
        desired_spec.labels
    );
    let new_hash = spec_hash(&desired_spec);

    // Pre-canonical (OLD) discovered spec: same fields as
    // desired, but labels Vec is REORDERED back to a non-canonical
    // permutation BEFORE recomputing spec_hash. This simulates a
    // runner registered by a pre-canonicalization version of
    // ghars whose merge_defaults did not yet sort labels — the
    // hash that landed in `X-Ghars-Spec-Hash` was computed from
    // the operator's source order, NOT from the canonical sort.
    let mut pre_canonical_spec = desired_spec.clone();
    pre_canonical_spec.labels = vec!["middle".into(), "alpha".into(), "beta".into()];
    pre_canonical_spec.spec_hash = spec_hash(&pre_canonical_spec);
    let old_hash = pre_canonical_spec.spec_hash.clone();
    // Hash-mismatch precondition: the canonical-sort change must
    // shift the hash. If this fails, spec_hash isn't sensitive to
    // labels Vec order (e.g. a hypothetical refactor that sorted
    // inside spec_hash itself) and the rest of the test would
    // not exercise the uncovered path.
    assert_ne!(
        old_hash, new_hash,
        "pre-canonical (unsorted) spec_hash must differ from canonical (sorted) spec_hash; \
         got old={old_hash} new={new_hash}"
    );

    // Build the discovered runner: spec_hash field carries OLD
    // (the hash that pre-canonical ghars wrote into
    // X-Ghars-Spec-Hash); drop-ins are rendered from
    // pre_canonical_spec but `render_identity` defense-in-depth
    // sorts labels in the X-Ghars-Labels emission, so the
    // discovered drop-in body has SORTED labels with OLD hash.
    // That mismatch (OLD-hash + SORTED-labels) is exactly what
    // `state::discover` reads off-disk after the upgrade lands.
    let mut actual = empty_actual();
    actual.runners.insert(
        "a".into(),
        discovered_for("a", &pre_canonical_spec, Drift::InSync),
    );

    let plan = plan_from(&cfg, &actual, &empty_paths())
        .expect("plan_from must succeed for the transition fixture");

    // Single UpdateRunner action: the runner crossed the
    // canonicalization boundary and the planner must recreate it.
    let updates: Vec<&RunnerDelta> = plan
        .actions
        .iter()
        .filter_map(|a| match a {
            Action::UpdateRunner(d) => Some(d),
            _ => None,
        })
        .collect();
    assert_eq!(
        updates.len(),
        1,
        "transition must produce exactly one UpdateRunner; got plan: {:?}",
        plan.actions
    );
    let upd = updates[0];
    assert!(
        !upd.requires_recreate,
        "post-fix transition must be in-place (hash mismatch with no field-level \
         explanation routes through the uncovered arm which now falls through to \
         in-place); got reasons {:?} field_changes {:?}",
        upd.recreate_reasons, upd.field_changes
    );
    // Since the uncovered-arm decoupling the uncovered arm pushes NO recreate reason —
    // the in-place apply path takes over and rewrites the
    // 00-ghars.conf X-Ghars-Spec-Hash annotation in place.
    // A regression that re-introduced the recreate push would
    // surface as a non-empty recreate_reasons here.
    assert!(
        upd.recreate_reasons.is_empty(),
        "post-fix uncovered arm must NOT push any recreate reason; got: {:?}",
        upd.recreate_reasons
    );
    // Stage 1 must record NO labels FieldChange — the discovered
    // and desired sorted-label sets are byte-identical, so the
    // classifier's set-equal branch returns None. A FieldChange
    // here would mean the labels classifier diverged from the
    // hash classifier (canonical mismatch) on this transition.
    assert!(
        !upd.field_changes.iter().any(|c| c.path == "labels"),
        "uncovered arm must NOT carry a labels FieldChange (set-equal after sort); \
         got: {:?}",
        upd.field_changes
    );
    // Sibling pin: the `after` spec_hash on the delta carries
    // the canonical NEW hash. This is the hash apply will write
    // back to disk during the in-place rewrite, so the next plan
    // run returns to NoOp. RunnerDelta has no `before` field —
    // the OLD hash lives on the input `DiscoveredRunner` which
    // the planner consumes; we read it back from `actual`
    // directly to pin the contract end-to-end.
    assert_eq!(
        upd.after.spec_hash, new_hash,
        "delta.after.spec_hash must carry the canonical NEW hash"
    );
    assert_eq!(
        actual.runners.get("a").expect("runner present").spec_hash,
        old_hash,
        "discovered.spec_hash fixture must carry the pre-canonical OLD hash"
    );
}

/// Combined transition: a runner whose on-disk `X-Ghars-Spec-Hash`
/// was computed by a pre-canonicalization `merge_defaults` (no
/// labels sort) AND whose operator simultaneously edited an
/// in-place-class field (`memory_max`) must produce an in-place
/// `UpdateRunner` (NOT an `uncovered` recreate). The coincident
/// in-place change makes Stage 2 detect a non-`00-ghars.conf`
/// modified drop-in (`10-memory.conf`), which flips
/// `any_drop_in_modified` and bypasses the uncovered fallback gate.
///
/// Routing distinction vs the pure-labels-reorder transition above:
///   - Pure reorder: only `00-ghars.conf` is Modified (carries the
///     stale `X-Ghars-Spec-Hash`); basename filter strips it; gate
///     fires → `uncovered` recreate.
///   - Combined (HERE): `10-memory.conf` is Modified (`memory_max`
///     edit) AND survives the basename filter (in
///     `MANAGED_DROP_IN_BASENAMES`, not `00-ghars.conf`). Gate sees
///     `any_drop_in_modified=true` and skips the uncovered push.
///
/// The classifier still records NO `labels` recreate reason
/// (set-equal after sort) and NO labels `FieldChange`. The detected
/// change is the `memory_max` drop-in body, surfaced via the Stage 2
/// drop-in diff. The resulting plan uses the canonical NEW
/// `spec_hash` (sorted labels + new `memory_max`), so apply re-renders
/// the canonical 00-ghars.conf and the next plan returns to `NoOp`.
///
/// Why this case matters: an operator upgrading ghars across the
/// canonicalization boundary while ALSO editing an unrelated
/// in-place field exercises the interaction between the labels-
/// canonicalization transition and the Stage 2 in-place classifier.
/// A regression that conflated the two paths — for example, marking
/// the runner for recreate because the `spec_hash` flipped without
/// checking whether Stage 2 found a real in-place edit — would
/// surface as `requires_recreate=true` here. The combined case is
/// the narrowest fixture that catches such a regression.
#[test]
fn plan_combined_labels_canonicalization_with_inplace_edit_is_inplace_update() {
    // Desired: operator edits both labels (any order — merge_defaults
    // canonicalizes) and memory_max. After merge_defaults, labels
    // sort to ["alpha","beta","middle"] and the spec_hash captures
    // the NEW memory_max value too.
    let cfg = config_with_runners(vec![{
        let mut r = minimal_runner("a");
        r.labels = vec!["middle".into(), "alpha".into(), "beta".into()];
        r.memory_max = Some("16G".into());
        r
    }]);
    let desired_spec = merge_defaults(
        &cfg.runners[0],
        &cfg.defaults,
        "pat".into(),
        vec![],
        None,
        None,
        None,
        Arch::X86_64,
        cfg_source_default(),
    );
    // Canonical contract pin on labels sort, parity with the
    // pure-reorder transition test above.
    assert_eq!(
        desired_spec.labels,
        vec![
            "alpha".to_string(),
            "beta".to_string(),
            "middle".to_string()
        ],
        "merge_defaults must sort labels for desired spec; got: {:?}",
        desired_spec.labels
    );
    let new_hash = spec_hash(&desired_spec);

    // Pre-canonical (OLD) discovered spec: labels in non-canonical
    // permutation AND the prior memory_max value ("8G"). Recompute
    // spec_hash from this state — both the unsorted-labels and the
    // old-memory_max contribute to the hash, so the two changes
    // accumulate on the same OLD↔NEW mismatch.
    let mut pre_canonical_spec = desired_spec.clone();
    pre_canonical_spec.labels = vec!["middle".into(), "alpha".into(), "beta".into()];
    pre_canonical_spec.memory_max = Some("8G".into());
    pre_canonical_spec.spec_hash = spec_hash(&pre_canonical_spec);
    let old_hash = pre_canonical_spec.spec_hash.clone();
    // Hash-mismatch precondition. Either the labels permutation OR
    // the memory_max edit is sufficient on its own; the combined
    // fixture captures both contributing to the same mismatch.
    assert_ne!(
        old_hash, new_hash,
        "pre-canonical (unsorted-labels + old memory_max) spec_hash must differ from canonical \
         (sorted-labels + new memory_max) spec_hash; got old={old_hash} new={new_hash}"
    );

    // Discovered fixture: spec_hash field carries OLD; drop-ins are
    // rendered from `pre_canonical_spec` so:
    //   - 00-ghars.conf carries OLD spec_hash + sorted labels (the
    //     defense-in-depth sort at render_identity), which is
    //     basename-filtered out of `any_drop_in_modified`.
    //   - 10-memory.conf carries `MemoryMax=8G` (the OLD memory_max
    //     value), which differs from the desired `MemoryMax=16G`
    //     body and IS in MANAGED_DROP_IN_BASENAMES — Stage 2
    //     detects this as Modified.
    let mut actual = empty_actual();
    actual.runners.insert(
        "a".into(),
        discovered_for("a", &pre_canonical_spec, Drift::InSync),
    );

    let plan = plan_from(&cfg, &actual, &empty_paths())
        .expect("plan_from must succeed for combined transition fixture");

    // Single UpdateRunner action: routed in-place, NOT recreate.
    let updates: Vec<&RunnerDelta> = plan
        .actions
        .iter()
        .filter_map(|a| match a {
            Action::UpdateRunner(d) => Some(d),
            _ => None,
        })
        .collect();
    assert_eq!(
        updates.len(),
        1,
        "combined transition must produce exactly one UpdateRunner; got plan: {:?}",
        plan.actions
    );
    let upd = updates[0];
    // Core contract: the coincident in-place edit short-circuits
    // the `uncovered` arm's warn log — Stage 2 detected the
    // 10-memory.conf body diff, so `any_drop_in_modified` is
    // true and the warn gate (which requires all three signals
    // empty) doesn't fire. The uncovered arm itself never pushes
    // a recreate token post-fix, so a regression that re-routed
    // through it would surface in `field_changes` (a phantom
    // Stage 1 mis-classification) rather than in
    // `recreate_reasons`.
    assert!(
        !upd.requires_recreate,
        "combined transition must route in-place (Stage 2 detected memory_max diff in \
         10-memory.conf); got reasons {:?} field_changes {:?}",
        upd.recreate_reasons, upd.field_changes
    );
    assert!(
        upd.recreate_reasons.is_empty(),
        "combined transition must record NO recreate reasons; got: {:?}",
        upd.recreate_reasons
    );
    // Defense-in-depth: labels are set-equal after sort (sorted
    // before-side ⇄ sorted after-side) so the classifier records
    // NO labels FieldChange. A FieldChange here would mean the
    // labels classifier diverged from the spec_hash hash classifier
    // on this transition (canonical mismatch) and the test would
    // be exercising the wrong path.
    assert!(
        !upd.field_changes.iter().any(|c| c.path == "labels"),
        "labels must be set-equal after sort, no labels FieldChange expected; got: {:?}",
        upd.field_changes
    );
    // The new canonical spec_hash lands on the delta — apply will
    // re-render the canonical 00-ghars.conf with NEW hash, so the
    // next plan returns to NoOp.
    assert_eq!(
        upd.after.spec_hash, new_hash,
        "delta.after.spec_hash must carry the canonical NEW hash"
    );
    // Sibling pin: the discovered runner still carries the pre-
    // canonical OLD hash on the input. Mirrors the pure-reorder
    // transition test's symmetric assertion.
    assert_eq!(
        actual.runners.get("a").expect("runner present").spec_hash,
        old_hash,
        "discovered.spec_hash fixture must carry the pre-canonical OLD hash"
    );
}

// ---- hardening Vec canonicalization (3 set-semantic fields) ------

/// `merge_hardening` sorts `restrict_address_families` in place so
/// a pure operator reorder of the TOML list does not perturb the
/// rendered drop-in body or the `spec_hash`. Mirrors the caches
/// canonicalization in `lower_to_effective`. Built directly on
/// `merge_hardening` (the only
/// site that touches the post-sort spec) rather than going through
/// `lower_to_effective` so the test pins the sort regardless of
/// what other layers do downstream.
#[test]
fn merge_hardening_sorts_restrict_address_families() {
    let runner = Hardening {
        restrict_address_families: vec!["AF_UNIX".into(), "AF_NETLINK".into(), "AF_INET".into()],
        ..Hardening::default()
    };
    let merged = merge_hardening(&runner, &Hardening::default());
    assert_eq!(
        merged.restrict_address_families,
        vec!["AF_INET", "AF_NETLINK", "AF_UNIX"],
        "merge_hardening must sort restrict_address_families in place"
    );
}

/// Same contract for `extra_syscalls`. The tokens here are
/// systemd-syntax syscall names; ordering changes the drop-in body
/// (`SystemCallFilter=` line) but does NOT change the cumulative
/// allowlist semantic (consecutive lines union). Sorting is safe
/// and pins the canonical form.
#[test]
fn merge_hardening_sorts_extra_syscalls() {
    let runner = Hardening {
        extra_syscalls: vec!["rseq".into(), "clone3".into(), "memfd_create".into()],
        ..Hardening::default()
    };
    let merged = merge_hardening(&runner, &Hardening::default());
    assert_eq!(
        merged.extra_syscalls,
        vec!["clone3", "memfd_create", "rseq"],
        "merge_hardening must sort extra_syscalls in place"
    );
}

/// Same contract for `extra_capabilities`. Note this also exercises
/// the additive-merge path: defaults + runner are concatenated then
/// sorted, so the final order is alphabetic regardless of which
/// side contributed which entry.
#[test]
fn merge_hardening_sorts_extra_capabilities_after_additive_merge() {
    let defaults = Hardening {
        extra_capabilities: vec!["CAP_NET_BIND_SERVICE".into()],
        ..Hardening::default()
    };
    let runner = Hardening {
        extra_capabilities: vec!["CAP_DAC_OVERRIDE".into(), "CAP_AUDIT_WRITE".into()],
        ..Hardening::default()
    };
    let merged = merge_hardening(&runner, &defaults);
    // defaults entry + 2 runner entries, then sorted alphabetically.
    assert_eq!(
        merged.extra_capabilities,
        vec![
            "CAP_AUDIT_WRITE",
            "CAP_DAC_OVERRIDE",
            "CAP_NET_BIND_SERVICE",
        ],
        "merge_hardening must sort extra_capabilities after additive merge"
    );
}

/// `merge_hardening` deduplicates `restrict_address_families` after
/// sorting. A pick-merge path can carry duplicates from the picked
/// side (operator-supplied repeat in TOML); dedup-after-sort
/// collapses adjacent duplicates so the `spec_hash` + rendered drop-in
/// body do not drift on a pure dup edit.
#[test]
fn merge_hardening_dedupes_restrict_address_families() {
    let runner = Hardening {
        restrict_address_families: vec!["AF_UNIX".into(), "AF_INET".into(), "AF_UNIX".into()],
        ..Hardening::default()
    };
    let merged = merge_hardening(&runner, &Hardening::default());
    assert_eq!(
        merged.restrict_address_families,
        vec!["AF_INET", "AF_UNIX"],
        "merge_hardening must dedup restrict_address_families after sort"
    );
}

/// Same dedup contract for `extra_syscalls`. Pick-merge of a single
/// side that itself contains a repeat must produce a deduped
/// canonical Vec.
#[test]
fn merge_hardening_dedupes_extra_syscalls() {
    let runner = Hardening {
        extra_syscalls: vec!["clone3".into(), "rseq".into(), "clone3".into()],
        ..Hardening::default()
    };
    let merged = merge_hardening(&runner, &Hardening::default());
    assert_eq!(
        merged.extra_syscalls,
        vec!["clone3", "rseq"],
        "merge_hardening must dedup extra_syscalls after sort"
    );
}

/// `extra_capabilities` exercises the OTHER source of duplicates:
/// the additive merge concatenates defaults + runner, so an entry
/// listed on BOTH sides becomes a duplicate even if neither side
/// individually repeated. dedup-after-sort collapses it.
#[test]
fn merge_hardening_dedupes_extra_capabilities_across_additive_merge() {
    let defaults = Hardening {
        extra_capabilities: vec!["CAP_NET_BIND_SERVICE".into()],
        ..Hardening::default()
    };
    let runner = Hardening {
        extra_capabilities: vec!["CAP_NET_BIND_SERVICE".into(), "CAP_DAC_OVERRIDE".into()],
        ..Hardening::default()
    };
    let merged = merge_hardening(&runner, &defaults);
    // defaults["CAP_NET_BIND_SERVICE"] + runner["CAP_NET_BIND_SERVICE",
    // "CAP_DAC_OVERRIDE"] → after sort+dedup: 2 unique entries.
    assert_eq!(
        merged.extra_capabilities,
        vec!["CAP_DAC_OVERRIDE", "CAP_NET_BIND_SERVICE"],
        "merge_hardening must dedup extra_capabilities across the additive concat"
    );
}

/// `bind_readonly_paths` is mount-order-sensitive (overlapping
/// paths are processed sequentially, so a later mount can override
/// or fail relative to an earlier one) and MUST NOT be sorted.
/// This test pins the non-sort contract for `bind_readonly_paths`
/// — a regression that "helpfully" added `.sort()` here would
/// silently change the operator's mount-order semantics.
#[test]
fn merge_hardening_preserves_bind_readonly_paths_order() {
    let runner = Hardening {
        bind_readonly_paths: Some(vec![
            camino::Utf8PathBuf::from("/srv/z-mount"),
            camino::Utf8PathBuf::from("/srv/a-mount"),
            camino::Utf8PathBuf::from("/srv/m-mount"),
        ]),
        ..Hardening::default()
    };
    let merged = merge_hardening(&runner, &Hardening::default());
    assert_eq!(
        merged.bind_readonly_paths,
        Some(vec![
            camino::Utf8PathBuf::from("/srv/z-mount"),
            camino::Utf8PathBuf::from("/srv/a-mount"),
            camino::Utf8PathBuf::from("/srv/m-mount"),
        ]),
        "bind_readonly_paths must preserve operator-supplied mount order"
    );
}

/// `extra_bind_paths` is mount-order-sensitive for the same reason
/// as `bind_readonly_paths`. Pin the non-sort contract here too.
/// This also covers the additive-merge path for `extra_bind_paths`
/// (defaults entries land first, then runner entries — the order
/// inside each contributing list is preserved).
#[test]
fn merge_hardening_preserves_extra_bind_paths_order() {
    let defaults = Hardening {
        extra_bind_paths: vec![
            camino::Utf8PathBuf::from("/srv/zzz-default"),
            camino::Utf8PathBuf::from("/srv/aaa-default"),
        ],
        ..Hardening::default()
    };
    let runner = Hardening {
        extra_bind_paths: vec![
            camino::Utf8PathBuf::from("/srv/zzz-runner"),
            camino::Utf8PathBuf::from("/srv/aaa-runner"),
        ],
        ..Hardening::default()
    };
    let merged = merge_hardening(&runner, &defaults);
    assert_eq!(
        merged.extra_bind_paths,
        vec![
            camino::Utf8PathBuf::from("/srv/zzz-default"),
            camino::Utf8PathBuf::from("/srv/aaa-default"),
            camino::Utf8PathBuf::from("/srv/zzz-runner"),
            camino::Utf8PathBuf::from("/srv/aaa-runner"),
        ],
        "extra_bind_paths must preserve operator-supplied mount order across both layers"
    );
}

/// End-to-end: a runner whose only TOML change is a reorder of a
/// set-semantic hardening field (`restrict_address_families` here)
/// must produce a `NoOp` through `plan_from`, NOT an `UpdateRunner`.
/// Mirrors the structure of `plan_noop_when_caches_reorder_only`
/// — drives the full plan pipeline against an actual state that
/// reflects a prior apply.
#[test]
fn plan_noop_when_restrict_address_families_reorder_only() {
    let make_cfg = |order: Vec<&str>| -> Config {
        config_with_runners(vec![{
            let mut r = minimal_runner("a");
            r.hardening.restrict_address_families = order.into_iter().map(String::from).collect();
            r
        }])
    };
    let cfg_first = make_cfg(vec!["AF_UNIX", "AF_NETLINK", "AF_INET"]);
    let plan_first =
        plan_from(&cfg_first, &empty_actual(), &empty_paths()).expect("first plan must succeed");
    let first_spec = plan_first
        .actions
        .iter()
        .find_map(|a| match a {
            Action::CreateRunner(rp) => Some(rp.spec.clone()),
            _ => None,
        })
        .expect("first plan must emit CreateRunner");
    let mut actual = empty_actual();
    actual
        .runners
        .insert("a".into(), discovered_for("a", &first_spec, Drift::InSync));
    let cfg_second = make_cfg(vec!["AF_INET", "AF_UNIX", "AF_NETLINK"]);
    let plan_second =
        plan_from(&cfg_second, &actual, &empty_paths()).expect("second plan must succeed");
    let updates: Vec<_> = plan_second
        .actions
        .iter()
        .filter_map(|a| match a {
            Action::UpdateRunner(d) => Some(d),
            _ => None,
        })
        .collect();
    assert!(
        updates.is_empty(),
        "restrict_address_families reorder must NOT produce UpdateRunner; got: {updates:?}"
    );
    let noops: Vec<_> = plan_second
        .actions
        .iter()
        .filter(|a| matches!(a, Action::NoOp(_)))
        .collect();
    assert_eq!(noops.len(), 1, "expected exactly one NoOp");
}

/// Same end-to-end shape for `extra_syscalls`.
#[test]
fn plan_noop_when_extra_syscalls_reorder_only() {
    let make_cfg = |order: Vec<&str>| -> Config {
        config_with_runners(vec![{
            let mut r = minimal_runner("a");
            r.hardening.extra_syscalls = order.into_iter().map(String::from).collect();
            r
        }])
    };
    let cfg_first = make_cfg(vec!["rseq", "clone3", "memfd_create"]);
    let plan_first =
        plan_from(&cfg_first, &empty_actual(), &empty_paths()).expect("first plan must succeed");
    let first_spec = plan_first
        .actions
        .iter()
        .find_map(|a| match a {
            Action::CreateRunner(rp) => Some(rp.spec.clone()),
            _ => None,
        })
        .expect("first plan must emit CreateRunner");
    let mut actual = empty_actual();
    actual
        .runners
        .insert("a".into(), discovered_for("a", &first_spec, Drift::InSync));
    let cfg_second = make_cfg(vec!["memfd_create", "rseq", "clone3"]);
    let plan_second =
        plan_from(&cfg_second, &actual, &empty_paths()).expect("second plan must succeed");
    let updates: Vec<_> = plan_second
        .actions
        .iter()
        .filter_map(|a| match a {
            Action::UpdateRunner(d) => Some(d),
            _ => None,
        })
        .collect();
    assert!(
        updates.is_empty(),
        "extra_syscalls reorder must NOT produce UpdateRunner; got: {updates:?}"
    );
}

/// Same end-to-end shape for `extra_capabilities`.
#[test]
fn plan_noop_when_extra_capabilities_reorder_only() {
    let make_cfg = |order: Vec<&str>| -> Config {
        config_with_runners(vec![{
            let mut r = minimal_runner("a");
            r.hardening.extra_capabilities = order.into_iter().map(String::from).collect();
            r
        }])
    };
    let cfg_first = make_cfg(vec![
        "CAP_NET_BIND_SERVICE",
        "CAP_AUDIT_WRITE",
        "CAP_DAC_OVERRIDE",
    ]);
    let plan_first =
        plan_from(&cfg_first, &empty_actual(), &empty_paths()).expect("first plan must succeed");
    let first_spec = plan_first
        .actions
        .iter()
        .find_map(|a| match a {
            Action::CreateRunner(rp) => Some(rp.spec.clone()),
            _ => None,
        })
        .expect("first plan must emit CreateRunner");
    let mut actual = empty_actual();
    actual
        .runners
        .insert("a".into(), discovered_for("a", &first_spec, Drift::InSync));
    let cfg_second = make_cfg(vec![
        "CAP_DAC_OVERRIDE",
        "CAP_NET_BIND_SERVICE",
        "CAP_AUDIT_WRITE",
    ]);
    let plan_second =
        plan_from(&cfg_second, &actual, &empty_paths()).expect("second plan must succeed");
    let updates: Vec<_> = plan_second
        .actions
        .iter()
        .filter_map(|a| match a {
            Action::UpdateRunner(d) => Some(d),
            _ => None,
        })
        .collect();
    assert!(
        updates.is_empty(),
        "extra_capabilities reorder must NOT produce UpdateRunner; got: {updates:?}"
    );
}

// --- Some(empty) → None normalization at lower_to_effective layer
// (eliminates dark inputs where canonical-JSON of Some(empty)
// differs from None but render output is identical).

/// Pins memory_max normalization: an operator-typed empty string in
/// TOML collapses to None at merge_defaults, so spec_hash matches the
/// None case byte-for-byte. Without the filter, `Some("")` and `None`
/// would render identically (render_memory returns Ok(None) for empty)
/// but flip spec_hash on toggle — a dark input.
#[test]
fn merge_defaults_collapses_some_empty_memory_max_to_none() {
    let mut runner = minimal_runner("a");
    runner.memory_max = Some(String::new());
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
        "/etc/ghars/ghars.toml".into(),
    );
    assert_eq!(spec.memory_max, None);

    let mut none_runner = minimal_runner("a");
    none_runner.memory_max = None;
    let none_spec = merge_defaults(
        &none_runner,
        &defaults,
        "pat".into(),
        vec![],
        None,
        None,
        None,
        Arch::X86_64,
        "/etc/ghars/ghars.toml".into(),
    );
    assert_eq!(
        spec_hash(&spec),
        spec_hash(&none_spec),
        "Some(empty) and None must produce identical spec_hash after normalization"
    );
}

/// Parallel pin for runner_sha256 normalization. render_identity
/// emits X-Ghars-Runner-Sha256 only on `Some(non-empty)` so `Some("")`
/// and `None` render identically but pre-normalization differed in
/// spec_hash.
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
        "/etc/ghars/ghars.toml".into(),
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
        "/etc/ghars/ghars.toml".into(),
    );
    assert_eq!(
        spec_hash(&spec),
        spec_hash(&none_spec),
        "Some(empty) and None must produce identical spec_hash after normalization"
    );
}

/// Pin ProxySpec::is_empty contract. Mirrors the field set
/// `render_proxy` early-returns Ok(None) on (units.rs render_proxy:
/// `http.is_none() && https.is_none() && no_proxy.is_empty() &&
/// ca_certs.is_empty()`). The is_empty method is what the
/// lower_to_effective normalization filter uses to collapse
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

/// Pin HooksSpec::is_empty contract. Mirrors render_hooks's early-
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
/// resulting EffectiveRunnerSpec, AND the spec_hash matches the
/// genuinely-absent (config.proxy = None) case.
/// `proxy_spec_is_empty_matches_render_proxy_early_return` above
/// pins the `is_empty` predicate in isolation; this test pins that
/// the predicate is actually plumbed into the resolver chain via
/// the `.filter(|p| !p.is_empty())` call at compute.rs. A regression
/// that removed the filter (keeping the is_empty method) would
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
        "/etc/ghars/ghars.toml".into(),
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
        "/etc/ghars/ghars.toml".into(),
        0,
    )
    .expect("lower_to_effective must succeed");
    assert_eq!(
        spec_hash(&eff_empty),
        spec_hash(&eff_none),
        "Some(empty) proxy must produce identical spec_hash to None after normalization — dark input eliminated"
    );
}

/// End-to-end pin for dns/ipv6 annotation contract: render
/// emits X-Ghars-Dns + X-Ghars-Ipv6 → DiscoveredAnnotations parser
/// round-trips them → classifier emits FieldChange (in-place, NOT
/// a recreate reason) when desired dns differs from discovered.
///
/// Pins the full Stage 1 chain so a regression at any layer fails
/// immediately: render-emission missing → parser sees None →
/// classifier skips → uncovered warn fires. Parser round-trip
/// broken → classifier compares None vs Some → skip. Classifier
/// arm missing → no FieldChange → uncovered warn fires when dns
/// is the lone change.
#[test]
fn dns_ipv6_annotations_round_trip_and_route_in_place() {
    use crate::config::{
        DnsMode, EffectiveNetworkBinding, Ipv6Mode, NetworkMode, NetworkSpec,
    };
    use crate::plan::FieldChange;

    let defaults = Defaults::default();
    let mk_spec = |dns: DnsMode| -> EffectiveRunnerSpec {
        let mut spec = merge_defaults(
            &minimal_runner("a"),
            &defaults,
            "pat".into(),
            vec![],
            None,
            None,
            None,
            Arch::X86_64,
            "/etc/ghars/ghars.toml".into(),
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
                ipv6: Ipv6Mode::Disabled,
            },
            subnet: None,
        });
        spec.spec_hash = spec_hash(&spec);
        spec
    };

    let discovered_spec = mk_spec(DnsMode::Forward);
    let desired_spec = mk_spec(DnsMode::Static {
        servers: vec!["1.1.1.1".parse().unwrap()],
    });

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
    use crate::config::{
        DnsMode, EffectiveNetworkBinding, Ipv6Mode, NetworkMode, NetworkSpec,
    };
    use crate::plan::FieldChange;

    let defaults = Defaults::default();
    let mk_spec = |dns: DnsMode| -> EffectiveRunnerSpec {
        let mut spec = merge_defaults(
            &minimal_runner("a"),
            &defaults,
            "pat".into(),
            vec![],
            None,
            None,
            None,
            Arch::X86_64,
            "/etc/ghars/ghars.toml".into(),
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
                ipv6: Ipv6Mode::Disabled,
            },
            subnet: None,
        });
        spec.spec_hash = spec_hash(&spec);
        spec
    };

    let discovered_static = DnsMode::Static {
        servers: vec!["8.8.8.8".parse().unwrap(), "8.8.4.4".parse().unwrap()],
    };
    let desired_static = DnsMode::Static {
        servers: vec!["1.1.1.1".parse().unwrap()],
    };
    let discovered_spec = mk_spec(discovered_static.clone());
    let desired_spec = mk_spec(desired_static);

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
/// the ipv6 FieldChange branch never executes there. A future
/// regression that breaks the ipv6 comparator (e.g. wrong variant
/// match) would pass that test. Constructs the EffectiveRunnerSpec
/// directly so the v0.1 apply-time `Ipv6Mode::Enabled` hard-error
/// (config-load gate) doesn't fire — the classifier arm itself
/// must work in both directions for the v0.2-future case.
#[test]
fn ipv6_classifier_arm_routes_in_place_field_change() {
    use crate::config::{
        DnsMode, EffectiveNetworkBinding, Ipv6Mode, NetworkMode, NetworkSpec,
    };
    use crate::plan::FieldChange;

    let defaults = Defaults::default();
    let mk_spec = |ipv6: Ipv6Mode| -> EffectiveRunnerSpec {
        let mut spec = merge_defaults(
            &minimal_runner("a"),
            &defaults,
            "pat".into(),
            vec![],
            None,
            None,
            None,
            Arch::X86_64,
            "/etc/ghars/ghars.toml".into(),
        );
        spec.network = Some(EffectiveNetworkBinding {
            name: "isolated".into(),
            spec: NetworkSpec {
                mode: NetworkMode::Netns,
                allowed_egress: vec![],
                ip_allow: vec![],
                ip_deny: vec![],
                restrict_address_families: vec![],
                dns: DnsMode::Forward,
                ipv6,
            },
            subnet: None,
        });
        spec.spec_hash = spec_hash(&spec);
        spec
    };

    let discovered_spec = mk_spec(Ipv6Mode::Disabled);
    let desired_spec = mk_spec(Ipv6Mode::Enabled);

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
/// every legacy runner would emit a spurious dns/ipv6 FieldChange on
/// the first post-upgrade plan.
///
/// Routes the missing annotations into the uncovered arm (which is
/// in-place — see `compute::plan_from`'s fallback), so the in-place
/// rewrite re-establishes the drop-in including the new annotations;
/// the second plan classifies cleanly with full annotation coverage.
#[test]
fn legacy_runner_without_dns_ipv6_annotations_skips_classifier_arms() {
    use crate::config::{
        DnsMode, EffectiveNetworkBinding, Ipv6Mode, NetworkMode, NetworkSpec,
    };
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
    assert_eq!(anns.ipv6, None, "annotation-absent body must yield ipv6=None");

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
        "/etc/ghars/ghars.toml".into(),
    );
    desired_spec.network = Some(EffectiveNetworkBinding {
        name: "isolated".into(),
        spec: NetworkSpec {
            mode: NetworkMode::Netns,
            allowed_egress: vec![],
            ip_allow: vec![],
            ip_deny: vec![],
            restrict_address_families: vec![],
            dns: DnsMode::Static {
                servers: vec!["1.1.1.1".parse().unwrap()],
            },
            ipv6: Ipv6Mode::Enabled,
        },
        subnet: None,
    });
    desired_spec.spec_hash = spec_hash(&desired_spec);

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
/// arms MUST skip — they're NetworkSpec sub-fields and don't exist
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
    use crate::config::{DnsMode, Ipv6Mode};
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
        "/etc/ghars/ghars.toml".into(),
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
/// the classifier MUST NOT emit FieldChange entries. A bug that
/// always-pushes regardless of equality would surface a noisy
/// no-op plan and pollute `out_changes`; a bug in the equality
/// check (e.g. comparing `Option<&DnsMode>` against the wrong
/// reference) would also slip in here.
#[test]
fn identical_dns_ipv6_emit_no_field_change() {
    use crate::config::{
        DnsMode, EffectiveNetworkBinding, Ipv6Mode, NetworkMode, NetworkSpec,
    };
    use crate::plan::FieldChange;

    let defaults = Defaults::default();
    let mk_spec = || -> EffectiveRunnerSpec {
        let mut spec = merge_defaults(
            &minimal_runner("a"),
            &defaults,
            "pat".into(),
            vec![],
            None,
            None,
            None,
            Arch::X86_64,
            "/etc/ghars/ghars.toml".into(),
        );
        spec.network = Some(EffectiveNetworkBinding {
            name: "isolated".into(),
            spec: NetworkSpec {
                mode: NetworkMode::Netns,
                allowed_egress: vec![],
                ip_allow: vec![],
                ip_deny: vec![],
                restrict_address_families: vec![],
                dns: DnsMode::Static {
                    servers: vec!["1.1.1.1".parse().unwrap()],
                },
                ipv6: Ipv6Mode::Disabled,
            },
            subnet: None,
        });
        spec.spec_hash = spec_hash(&spec);
        spec
    };

    let discovered_spec = mk_spec();
    let desired_spec = mk_spec();

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
/// `ipv6_from_annotation`. Doc-comments at config.rs:1125-1144 +
/// 1179-1197 promise non-empty unparseable input fires
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
    let whitespace_body =
        "[Unit]\nX-Ghars-Dns=\x20\nX-Ghars-Ipv6=\t\n";
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
    use crate::config::{
        DnsMode, EffectiveNetworkBinding, Ipv6Mode, NetworkMode, NetworkSpec,
    };
    use crate::plan::FieldChange;

    let defaults = Defaults::default();
    let mk_with_dns = |dns: DnsMode| -> EffectiveRunnerSpec {
        let mut spec = merge_defaults(
            &minimal_runner("a"),
            &defaults,
            "pat".into(),
            vec![],
            None,
            None,
            None,
            Arch::X86_64,
            "/etc/ghars/ghars.toml".into(),
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
                ipv6: Ipv6Mode::Disabled,
            },
            subnet: None,
        });
        spec.spec_hash = spec_hash(&spec);
        spec
    };

    let discovered_spec = mk_with_dns(DnsMode::Static {
        servers: vec!["8.8.8.8".parse().unwrap()],
    });
    let desired_spec = mk_with_dns(DnsMode::Forward);

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
    use crate::config::{
        DnsMode, EffectiveNetworkBinding, Ipv6Mode, NetworkMode, NetworkSpec,
    };
    use crate::plan::FieldChange;

    let defaults = Defaults::default();
    let mk_with_ipv6 = |ipv6: Ipv6Mode| -> EffectiveRunnerSpec {
        let mut spec = merge_defaults(
            &minimal_runner("a"),
            &defaults,
            "pat".into(),
            vec![],
            None,
            None,
            None,
            Arch::X86_64,
            "/etc/ghars/ghars.toml".into(),
        );
        spec.network = Some(EffectiveNetworkBinding {
            name: "isolated".into(),
            spec: NetworkSpec {
                mode: NetworkMode::Netns,
                allowed_egress: vec![],
                ip_allow: vec![],
                ip_deny: vec![],
                restrict_address_families: vec![],
                dns: DnsMode::Forward,
                ipv6,
            },
            subnet: None,
        });
        spec.spec_hash = spec_hash(&spec);
        spec
    };

    let discovered_spec = mk_with_ipv6(Ipv6Mode::Enabled);
    let desired_spec = mk_with_ipv6(Ipv6Mode::Disabled);

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
/// is tried first. The classifier MUST emit a dns FieldChange in
/// this case. A defense-in-depth regression that added set-semantic
/// sort at the parse boundary (mirroring the labels/caches
/// canonical-order sort) would silently flatten the operator's
/// reorder intent and skip the FieldChange.
#[test]
fn classifier_routes_dns_static_server_reorder_field_change() {
    use crate::config::{
        DnsMode, EffectiveNetworkBinding, Ipv6Mode, NetworkMode, NetworkSpec,
    };
    use crate::plan::FieldChange;

    let defaults = Defaults::default();
    let mk_with_servers = |servers: Vec<std::net::IpAddr>| -> EffectiveRunnerSpec {
        let mut spec = merge_defaults(
            &minimal_runner("a"),
            &defaults,
            "pat".into(),
            vec![],
            None,
            None,
            None,
            Arch::X86_64,
            "/etc/ghars/ghars.toml".into(),
        );
        spec.network = Some(EffectiveNetworkBinding {
            name: "isolated".into(),
            spec: NetworkSpec {
                mode: NetworkMode::Netns,
                allowed_egress: vec![],
                ip_allow: vec![],
                ip_deny: vec![],
                restrict_address_families: vec![],
                dns: DnsMode::Static { servers },
                ipv6: Ipv6Mode::Disabled,
            },
            subnet: None,
        });
        spec.spec_hash = spec_hash(&spec);
        spec
    };

    let ip_a: std::net::IpAddr = "1.1.1.1".parse().unwrap();
    let ip_b: std::net::IpAddr = "8.8.8.8".parse().unwrap();

    let discovered_spec = mk_with_servers(vec![ip_a, ip_b]);
    let desired_spec = mk_with_servers(vec![ip_b, ip_a]);

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
/// pair already supports IPv6 dns servers (IpAddr::parse accepts
/// both v4 and v6, and the `static:` prefix uses `:` only once as
/// the prefix-separator so subsequent `:` chars in v6 addresses
/// don't confuse strip_prefix), but no test exercises the v6 path.
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

/// Parallel pin for hooks normalization at lower_to_effective —
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
        "/etc/ghars/ghars.toml".into(),
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
        "/etc/ghars/ghars.toml".into(),
        0,
    )
    .expect("lower_to_effective must succeed");
    assert_eq!(
        spec_hash(&eff_empty),
        spec_hash(&eff_none),
        "Some(empty) hooks must produce identical spec_hash to None after normalization — dark input eliminated"
    );
}
