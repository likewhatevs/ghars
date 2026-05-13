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
