//! Test split part 2b: noop-on-reorder + hardening-Vec canonicalization
//! tests. See `part2a.rs` for the first half of the original `part2`
//! module; split solely for file-size manageability.

#![allow(clippy::unwrap_used, clippy::expect_used)]

use super::*;
use crate::config::{DnsMode, EffectiveNetworkBinding, Ipv6Mode, NetworkMode, NetworkSpec};

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
                server_mode: crate::config::SccacheServerMode::Pooled,
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
                server_mode: crate::config::SccacheServerMode::Pooled,
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

/// Pins `memory_max` normalization: an operator-typed empty string in
/// TOML collapses to None at `merge_defaults`, so `spec_hash` matches the
/// None case byte-for-byte. Without the filter, `Some("")` and `None`
/// would render identically (`render_memory` returns Ok(None) for empty)
/// but flip `spec_hash` on toggle — a dark input.
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
        cfg_source_default(),
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
        cfg_source_default(),
    );
    assert_eq!(
        spec_hash(&spec),
        spec_hash(&none_spec),
        "Some(empty) and None must produce identical spec_hash after normalization"
    );
}

/// Parallel pins for `allowed_cpus` + `allowed_memory_nodes`
/// normalization. `render_numa` returns Ok(None) for empty strings
/// (matches `render_memory`'s pattern), so `Some("")` and `None`
/// render identically. The merge-time filter at `merge_defaults`
/// keeps `spec_hash` byte-stable across the operator-toggled
/// empty-string dark input.
#[test]
fn merge_defaults_collapses_some_empty_allowed_cpus_to_none() {
    let mut runner = minimal_runner("a");
    runner.allowed_cpus = Some(String::new());
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
    assert_eq!(spec.allowed_cpus, None);

    let mut none_runner = minimal_runner("a");
    none_runner.allowed_cpus = None;
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
        "Some(empty) and None for allowed_cpus must produce identical spec_hash"
    );
}

#[test]
fn merge_defaults_collapses_some_empty_allowed_memory_nodes_to_none() {
    let mut runner = minimal_runner("a");
    runner.allowed_memory_nodes = Some(String::new());
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
    assert_eq!(spec.allowed_memory_nodes, None);

    let mut none_runner = minimal_runner("a");
    none_runner.allowed_memory_nodes = None;
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
        "Some(empty) and None for allowed_memory_nodes must produce identical spec_hash"
    );
}

/// Combined-field interaction pin: each `.filter()` at merge.rs:201-205
/// operates on its own field; a regression that coupled them (e.g.
/// shared early-return) would not be caught by the per-field tests
/// above. Sets BOTH to `Some(empty)` and asserts both fields
/// collapse + `spec_hash` equality with the all-None baseline.
#[test]
fn merge_defaults_collapses_some_empty_allowed_cpus_and_memory_nodes_to_none() {
    let mut runner = minimal_runner("a");
    runner.allowed_cpus = Some(String::new());
    runner.allowed_memory_nodes = Some(String::new());
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
    assert_eq!(spec.allowed_cpus, None);
    assert_eq!(spec.allowed_memory_nodes, None);

    let none_runner = minimal_runner("a");
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
        "both fields Some(empty) must produce identical spec_hash to both None — combined-field normalization invariant"
    );
}

/// Mirror of `lower_to_effective_collapses_some_empty_proxy_to_none`
/// for the per-runner `allowed_cpus` field. Pins that the merge-time
/// filter at merge.rs:201 is actually reached by the
/// `lower_to_effective` resolver chain — a regression that added a
/// denormalization layer downstream of `merge_defaults` would pass
/// the `merge_defaults_*` tests above but fail here.
#[test]
fn lower_to_effective_collapses_some_empty_allowed_cpus_to_none() {
    let mut runner_empty = minimal_runner("a");
    runner_empty.allowed_cpus = Some(String::new());
    let cfg_empty = config_with_runners(vec![runner_empty]);
    let expanded = expand_counts(&cfg_empty).expect("count expansion must succeed");
    let eff_empty = lower_to_effective(
        &expanded[0],
        &cfg_empty,
        Arch::X86_64,
        cfg_source_default(),
        0,
    )
    .expect("lower_to_effective must succeed");
    assert_eq!(eff_empty.allowed_cpus, None);

    let cfg_none = config_with_runners(vec![minimal_runner("a")]);
    let expanded_none = expand_counts(&cfg_none).expect("count expansion must succeed");
    let eff_none = lower_to_effective(
        &expanded_none[0],
        &cfg_none,
        Arch::X86_64,
        cfg_source_default(),
        0,
    )
    .expect("lower_to_effective must succeed");
    assert_eq!(
        spec_hash(&eff_empty),
        spec_hash(&eff_none),
        "Some(empty) allowed_cpus at runner config must produce identical spec_hash to None after lower_to_effective normalization — wiring intact"
    );
}

/// Symmetric inverse of the test above, for `allowed_memory_nodes`.
#[test]
fn lower_to_effective_collapses_some_empty_allowed_memory_nodes_to_none() {
    let mut runner_empty = minimal_runner("a");
    runner_empty.allowed_memory_nodes = Some(String::new());
    let cfg_empty = config_with_runners(vec![runner_empty]);
    let expanded = expand_counts(&cfg_empty).expect("count expansion must succeed");
    let eff_empty = lower_to_effective(
        &expanded[0],
        &cfg_empty,
        Arch::X86_64,
        cfg_source_default(),
        0,
    )
    .expect("lower_to_effective must succeed");
    assert_eq!(eff_empty.allowed_memory_nodes, None);

    let cfg_none = config_with_runners(vec![minimal_runner("a")]);
    let expanded_none = expand_counts(&cfg_none).expect("count expansion must succeed");
    let eff_none = lower_to_effective(
        &expanded_none[0],
        &cfg_none,
        Arch::X86_64,
        cfg_source_default(),
        0,
    )
    .expect("lower_to_effective must succeed");
    assert_eq!(
        spec_hash(&eff_empty),
        spec_hash(&eff_none),
        "Some(empty) allowed_memory_nodes at runner config must produce identical spec_hash to None after lower_to_effective normalization — wiring intact"
    );
}

/// End-to-end wire-up: a runner with `allowed_cpus = Some(empty)`
/// and `allowed_memory_nodes = Some(empty)` must drive
/// `render_runner_unit` to skip the `50-numa.conf` drop-in entirely.
/// Stronger guarantee than the `merge_defaults` + `render_numa` tests
/// in isolation — pins that the merge filter is actually plumbed
/// into the renderer pipeline through `render_runner_unit`'s
/// dispatch. A regression that bypassed the merge layer in a
/// production code path between `merge_defaults` and `render_numa`
/// would fail here.
#[test]
fn merge_defaults_some_empty_allowed_cpus_drives_render_runner_unit_to_skip_50_numa() {
    let mut runner = minimal_runner("a");
    runner.allowed_cpus = Some(String::new());
    runner.allowed_memory_nodes = Some(String::new());
    runner.runner_version = Some("2.334.0".into());
    let mut spec = merge_defaults(
        &runner,
        &Defaults::default(),
        "pat".into(),
        vec![],
        None,
        None,
        None,
        Arch::X86_64,
        cfg_source_default(),
    );
    spec.spec_hash = spec_hash(&spec);
    let r = crate::systemd::render_runner_unit(&spec)
        .expect("render_runner_unit must succeed for normalized spec");
    assert!(
        !r.drop_ins.contains_key("50-numa.conf"),
        "Some(empty) allowed_cpus and allowed_memory_nodes must NOT trigger 50-numa.conf emission via the merge→render pipeline; got drop-ins: {:?}",
        r.drop_ins.keys().collect::<Vec<_>>()
    );
}
