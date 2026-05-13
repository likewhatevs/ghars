//! `plan_from` and the supporting lowering / hashing helpers that
//! materialize an [`super::Plan`] from a [`crate::config::Config`] +
//! [`crate::state::ActualState`]: count expansion, defaults merge,
//! cross-reference validation (auth, caches, network), spec-hash
//! population, intersection-branch classification (annotation Stage 1
//! + drop-in Stage 2 + uncovered fallback), cache-pool diff, and
//! orphan handling.

use std::collections::{BTreeMap, BTreeSet, HashSet};
use std::path::Path;

use camino::Utf8PathBuf;

use crate::Result;
use crate::config::{
    Arch, CacheKind, CachePoolSpec, Config, EffectiveCacheBinding, EffectiveNetworkBinding,
    EffectiveRunnerSpec, NetworkMode, RunnerSpec,
};
use crate::error::GharsError;
use crate::paths::Paths;
use crate::state::{ActualState, DiscoveredRunner, Drift};

use super::DEFAULT_TRUST_ZONE;
use super::action::Action;
use super::classify::{DiscoveredAnnotations, classify_recreate_reasons_from_annotations};
use super::expand::expand_counts;
use super::hash::{cache_pool_hash, spec_hash};
use super::merge::merge_defaults;
use super::types::{
    CachePoolDelta, CachePoolPlan, DriftCause, DropInChange, DropInChangeKind, FieldChange, Plan,
    RunnerDelta, RunnerIdentity, RunnerPlan,
};

/// First octet of the default netns subnet pool. The full pool is
/// `NETNS_POOL_BASE.0.0/24` — i.e. `10.200.0.0/24` — yielding 64 /30
/// slots (Part 9c "IP allocation"). v0.1 hardcodes this; making it
/// configurable via `[defaults] netns_subnet` is design future scope.
const NETNS_POOL_BASE: [u8; 4] = [10, 200, 0, 0];

/// Number of /30 slots in the default `/24` pool.
pub(super) const NETNS_POOL_SLOTS: usize = 64;

/// Compute the /30 subnet for the given slot index in the
/// `10.200.0.0/24` pool. Slot 0 → `10.200.0.0/30`, slot 1 →
/// `10.200.0.4/30`, ..., slot 63 → `10.200.0.252/30`.
///
/// # Errors
///
/// Returns `GharsError::Validation` when `slot_idx >= NETNS_POOL_SLOTS`,
/// which means the operator has more netns runners than the v0.1
/// hardcoded /24 pool can accommodate. The error names the runner
/// hitting the cap so the operator can identify which entry to move.
pub(super) fn netns_subnet_for_slot(slot_idx: usize, runner_name: &str) -> Result<ipnet::IpNet> {
    if slot_idx >= NETNS_POOL_SLOTS {
        return Err(GharsError::Validation(
            format!(
                "netns subnet pool 10.200.0.0/24 exhausted: runner '{runner_name}' \
                 needs slot {slot_idx} but only {NETNS_POOL_SLOTS} /30 slots fit"
            ),
            "reduce the number of netns runners (max 64 in v0.1) or split across hosts".into(),
        ));
    }
    let offset = (slot_idx as u32) * 4;
    let base = u32::from(std::net::Ipv4Addr::new(
        NETNS_POOL_BASE[0],
        NETNS_POOL_BASE[1],
        NETNS_POOL_BASE[2],
        NETNS_POOL_BASE[3],
    ));
    let net = std::net::Ipv4Addr::from(base + offset);
    let net = ipnet::Ipv4Net::new(net, 30).map_err(|e| {
        GharsError::Validation(
            format!("netns subnet construction failed for slot {slot_idx}: {e}"),
            "this is a ghars bug; please report".into(),
        )
    })?;
    Ok(ipnet::IpNet::V4(net))
}

/// Compute a [`Plan`] from desired config + discovered actual state.
///
/// v0.1 scope (Part 8 step coverage):
/// 1. `expand_counts(config)` — flatten count-blocks.
/// 2. Defaults-merge — runs in [`lower_to_effective`]. Cross-reference
///    resolution for auth, caches, network is validated and threaded
///    through.
/// 3. Release lookup — NOT done here; the unit-text generator
///    is responsible for resolving `runner_version` against the
///    releases API. Plan emits the spec with whatever
///    `runner_version` is pinned in config; if unset it stays
///    `None` and the generator decides.
/// 4. Spec hash (Part 8 step 4) — computed via [`spec_hash`].
/// 5/6. Set diff against `actual`:
///    - desired - actual ⇒ `CreateRunner`.
///    - actual - desired ⇒ `RemoveRunner` (managed unit, no matching
///      desired entry).
///    - intersection ⇒ `NoOp` if hashes match AND drift is `InSync`;
///      `UpdateRunner` otherwise. Field-level classification populates
///      `requires_recreate` + `recreate_reasons` from annotation diff;
///      hash mismatch with no identifiable Stage 1 reason and no
///      Stage 2 drop-in body diff falls back to a conservative
///      `"uncovered"` recreate reason — the reason is named
///      `uncovered` because the condition is broader than a hash
///      mismatch alone.
/// 7. Apply Part 3 `requires_recreate` policy — done in
///    [`classify_recreate_reasons_from_annotations`].
/// 8. Cache-pool diffs against the discovered set. State discovery
///    enumerates `ghars-cache@*.service` units into
///    `actual.cache_pools`; the planner unions desired (every pool
///    referenced by at least one effective spec) with actual and emits
///    `CreateCachePool` for desired-only, `RemoveCachePool` for
///    actual-only, and `UpdateCachePool` when both sides match a name
///    but the pool's `spec_hash` differs OR the discovered pool's drift
///    classification is anything other than `InSync` (so an unmanaged
///    `99-*.conf` drop-in trips an update even when the body the
///    planner cares about is unchanged). Both-match + hash-equal +
///    in-sync emits no action.
/// 9. Orphan handling — `actual.orphans` always become `RemoveRunner`
///    (matches Part 7 — managed unit, no matching desired). External
///    units are never touched. Identity reconstructed from
///    annotations + unit body when possible (apply needs `url` /
///    `auth_name` to mint a remove token).
///
/// `paths` threads through to record `config_source` on each
/// effective spec.
///
/// # Errors
///
/// Returns `GharsError::Validation` when:
/// - `expand_counts` fails (count > `MAX_COUNT`, regex mismatch, cross-
///   block name collision);
/// - a runner references an unknown auth name (no
///   `[defaults] auth` and no `[[runner]] auth`);
/// - a runner references an unknown cache pool;
/// - a runner references an unknown network;
/// - a runner's `trust_zone` doesn't match a referenced cache pool's.
#[allow(clippy::expect_used)]
pub fn plan_from(config: &Config, actual: &ActualState, paths: &Paths) -> Result<Plan> {
    let host_arch = host_arch();
    let config_source = paths.config_dir.join("ghars.toml").to_string();
    // Defense-in-depth: reject control chars in `config_source`
    // before any rendered drop-in body picks it up via
    // `render_identity`'s X-Ghars-Config-Source line or
    // `render_cache_drop_in`'s same annotation.
    // Today `paths.config_dir` is hard-coded to `/etc/ghars` via
    // `Paths::default()`, so the production path always produces a
    // control-char-free string. The validation is here anyway because:
    //   (a) any future code path that constructs a `Paths` with an
    //       operator-influenced `config_dir` (env var, future
    //       `--config-dir`, or test redirection in production)
    //       inherits the gate without bypass;
    //   (b) `render_identity` itself runs the same check at unit
    //       render time, but that's strictly inside this function
    //       (lower_to_effective → render_runner_unit), so any caller
    //       that synthesizes an `EffectiveRunnerSpec` outside
    //       `plan_from` would skip it. Validating here closes the
    //       gap before `lower_to_effective` clones the value into
    //       every effective spec.
    crate::systemd::check_identity_field("config_source", &config_source)?;

    // Step 1: count-expand.
    let expanded = expand_counts(config)?;

    // Step 2: lower each RunnerSpec → EffectiveRunnerSpec.
    //
    // The runner's index in `expanded` is the netns subnet slot
    // (sequential /30 from the 10.200.0.0/24 default pool — Part 9c
    // "IP allocation"). `slot_idx` increments for every runner
    // regardless of mode, so a runner's slot is stable across mode
    // changes within the same expanded list (promoting an Open
    // runner to Netns later does not shift other Netns runners'
    // subnets). Open-mode runners do NOT consume a /30 — the slot
    // helper is only called inside `lower_to_effective`'s Netns
    // arm — so the v0.1 64-slot /24 cap is real headroom for actual
    // netns runners, not eroded by Open-mode entries that wouldn't
    // use a subnet.
    let mut desired: BTreeMap<String, EffectiveRunnerSpec> = BTreeMap::new();
    let warnings: Vec<String> = Vec::new();
    for (slot_idx, runner) in expanded.iter().enumerate() {
        let effective =
            lower_to_effective(runner, config, host_arch, config_source.clone(), slot_idx)?;
        desired.insert(effective.name.clone(), effective);
    }

    let mut actions: Vec<Action> = Vec::new();

    // Step 5/6/7: diff desired vs actual.
    let actual_names: HashSet<&String> = actual.runners.keys().collect();
    let desired_names: HashSet<&String> = desired.keys().collect();

    // Sort for deterministic plan output (Part 8 "Within each phase,
    // runners sorted by name for determinism").
    let mut all: Vec<&String> = actual_names.union(&desired_names).copied().collect();
    all.sort();

    for name in all {
        let in_desired = desired_names.contains(name);
        let in_actual = actual_names.contains(name);
        match (in_desired, in_actual) {
            (true, false) => {
                // Pure create.
                let spec = desired
                    .get(name)
                    .expect("name was in desired_names")
                    .clone();
                actions.push(Action::CreateRunner(into_runner_plan(spec)?));
            }
            (false, true) => {
                // Pure remove (managed unit, no matching desired).
                let discovered = actual.runners.get(name).expect("name was in actual_names");
                actions.push(Action::RemoveRunner(reconstruct_identity(
                    name, discovered, paths,
                )));
            }
            (true, true) => {
                let after_spec = with_hash(
                    desired
                        .get(name)
                        .expect("name was in desired_names")
                        .clone(),
                );
                let discovered = actual.runners.get(name).expect("name was in actual_names");
                let hashes_equal = after_spec.spec_hash == discovered.spec_hash
                    && !discovered.spec_hash.is_empty();
                let in_sync = matches!(discovered.drift, Drift::InSync);

                if hashes_equal && in_sync {
                    actions.push(Action::NoOp(format!("{name}: in sync")));
                } else {
                    let annotations = DiscoveredAnnotations::from_discovered(discovered);
                    // Re-render the desired spec and diff drop-in
                    // bodies against the discovered drop-ins on disk.
                    // A change confined to drop-in bodies (memory_max,
                    // proxy, hooks, hardening, allowed_cpus, ...) is
                    // in-place safe; a change that touches the
                    // recreate-bound annotations falls through to
                    // Stage 1 above.
                    let rendered = match crate::systemd::render_runner_unit(&after_spec) {
                        Ok(r) => r,
                        Err(e) => {
                            return Err(e);
                        }
                    };

                    let mut field_changes: Vec<FieldChange> = Vec::new();
                    let mut recreate_reasons = classify_recreate_reasons_from_annotations(
                        &annotations,
                        &after_spec,
                        &mut field_changes,
                    );

                    // Stage 2: drop-in body diff. Compare each rendered
                    // basename's body against the discovered body.
                    // Iterate over the union (BTreeMap key sorted) so
                    // we catch both newly-added and removed drop-ins.
                    let mut drop_in_changes: Vec<DropInChange> = Vec::new();
                    let mut all_basenames: BTreeSet<&str> = BTreeSet::new();
                    for k in rendered.drop_ins.keys() {
                        all_basenames.insert(k.as_str());
                    }
                    for k in discovered.drop_ins.keys() {
                        all_basenames.insert(k.as_str());
                    }
                    for basename in all_basenames {
                        let in_rendered = rendered.drop_ins.get(basename);
                        let in_disk = discovered.drop_ins.get(basename);
                        let kind = match (in_rendered, in_disk) {
                            (Some(after), Some(before)) if after == before => {
                                DropInChangeKind::Preserved
                            }
                            (Some(after), Some(before)) => DropInChangeKind::Modified {
                                before: before.clone(),
                                after: after.clone(),
                            },
                            (Some(after), None) => DropInChangeKind::Created {
                                after: after.clone(),
                            },
                            (None, Some(before)) => DropInChangeKind::Removed {
                                before: before.clone(),
                            },
                            (None, None) => unreachable!("union iteration"),
                        };
                        drop_in_changes.push(DropInChange {
                            basename: basename.to_owned(),
                            change: kind,
                        });
                    }

                    // Classify as in-place
                    // when ANY managed non-`00-ghars.conf` drop-in
                    // shows a body change of one of three
                    // positively-named shapes: Created, Modified, or
                    // Removed.
                    //
                    // Gates (all three must hold for a change entry to
                    // count as in-place evidence):
                    //   1. basename != "00-ghars.conf" — its body
                    //      always changes when spec_hash changes
                    //      (carries the `X-Ghars-Spec-Hash`
                    //      annotation), so counting it would mask
                    //      recreate-class changes whose only signal
                    //      IS the hash (e.g. runner_sha256,
                    //      runner_tarball — both spec-hash inputs
                    //      that don't surface in any other drop-in
                    //      body).
                    //   2. basename ∈ MANAGED_DROP_IN_BASENAMES
                    //      (C-6) — operator drop-ins (99-*.conf
                    //      from `systemctl edit`, anything outside
                    //      the ghars-managed numbering) are NOT
                    //      in-place evidence. Without this gate, an
                    //      operator-edited `99-operator.conf` whose
                    //      body happens to differ from one apply to
                    //      the next would mask a co-occurring
                    //      recreate-class field change (e.g. labels,
                    //      runner_version) that has no
                    //      annotation source — the in-place path
                    //      would silently swallow the recreate-
                    //      class change AND blow away the operator
                    //      override during the in-place rewrite
                    //      (apply.rs preserves operator drop-ins
                    //      but not their content if the apply path
                    //      runs at all). Filtering to MANAGED here
                    //      keeps unmanaged drop-ins out of the
                    //      classification signal where they don't
                    //      belong.
                    //   3. matches Created | Modified | Removed —
                    //      three real in-place signals named
                    //      positively rather than `!Preserved`
                    //      so a future variant added to
                    //      `DropInChangeKind` doesn't silently flip
                    //      classification semantics. Preserved bytes
                    //      match on both sides (no edit). Created /
                    //      Removed each map to a per-field-family
                    //      toggle: enabling `[proxy]` Creates
                    //      `60-proxy.conf` from nothing, and clearing
                    //      `memory_max` Removes `10-memory.conf`.
                    //      Both are in-place updates per design
                    //      Part 3.
                    let any_drop_in_modified = drop_in_changes.iter().any(|c| {
                        c.basename != "00-ghars.conf"
                            && crate::state::MANAGED_DROP_IN_BASENAMES
                                .contains(&c.basename.as_str())
                            && matches!(
                                c.change,
                                DropInChangeKind::Created { .. }
                                    | DropInChangeKind::Modified { .. }
                                    | DropInChangeKind::Removed { .. }
                            )
                    });

                    // The `uncovered` recreate reason fires only
                    // when hashes differ AND Stage 1 found neither
                    // a recreate reason NOR a non-recreate FieldChange
                    // (e.g. auth_name) AND Stage 2 found nothing —
                    // which should be unreachable in a deterministic
                    // renderer. Log tracing::warn! so we surface
                    // coverage gaps.
                    //
                    // Gate on `field_changes.is_empty()` alongside
                    // `recreate_reasons.is_empty()`.
                    // classify_recreate_reasons_from_annotations
                    // records a FieldChange for auth_name without
                    // pushing a recreate reason (auth-name change is
                    // in-place per design Part 3). Without the
                    // field_changes gate, every auth-name-only change
                    // would fall through to the uncovered recreate
                    // fallback even though the classifier did detect
                    // it.
                    if !hashes_equal
                        && recreate_reasons.is_empty()
                        && field_changes.is_empty()
                        && !any_drop_in_modified
                    {
                        tracing::warn!(
                            runner = name.as_str(),
                            discovered_hash = discovered.spec_hash.as_str(),
                            desired_hash = after_spec.spec_hash.as_str(),
                            "uncovered fallback: spec_hash differs but neither Stage 1 \
                             (annotation diff) nor Stage 2 (drop-in body diff) detected the change. \
                             This indicates a coverage gap in classify_recreate_reasons or a non-\
                             deterministic renderer. Falling back to recreate."
                        );
                        recreate_reasons.push("uncovered");
                    }

                    let requires_recreate = !recreate_reasons.is_empty();

                    // Classify why this update fired.
                    //   - hashes differ → operator changed the config
                    //   - on-disk drift → out-of-band edit
                    //   - both → both signals fired
                    //
                    // The (false, false) arm is logically
                    // unreachable — the enclosing `if hashes_equal &&
                    // in_sync` short-circuit at the NoOp branch above
                    // ensures at least one of the two flags is false
                    // when control reaches here. debug_assert! pins
                    // that invariant in dev/CI builds; the release
                    // fallback returns SpecChangedAndDriftDetected so
                    // the operator sees the most-informative label
                    // (and a tracing::warn) rather than the process
                    // crashing on a coverage gap.
                    let drift_cause = match (!hashes_equal, !in_sync) {
                        (true, true) => DriftCause::SpecChangedAndDriftDetected,
                        (true, false) => DriftCause::SpecChanged,
                        (false, true) => DriftCause::DriftDetected,
                        (false, false) => {
                            debug_assert!(
                                false,
                                "drift_cause (false, false) reached for runner {name}: \
                                 NoOp short-circuit at the intersection branch should have \
                                 filtered this case",
                            );
                            tracing::warn!(
                                runner = name.as_str(),
                                "drift_cause classifier reached the unreachable \
                                 (hashes_equal=true, in_sync=true) arm — defaulting to \
                                 SpecChangedAndDriftDetected. This indicates a NoOp gating \
                                 bug; please file a ghars issue."
                            );
                            DriftCause::SpecChangedAndDriftDetected
                        }
                    };

                    // Populate effective_unit_text + drop_ins on
                    // RunnerPlan
                    // from the rendered output we already computed
                    // above. apply.rs's in-place rewrite path consumes
                    // these directly.
                    let after_plan = RunnerPlan {
                        spec_hash: after_spec.spec_hash.clone(),
                        spec: after_spec,
                        resolved_release: None,
                        effective_unit_text: rendered.template,
                        drop_ins: rendered.drop_ins,
                        env_file: rendered.env_file,
                        path_file: rendered.path_file,
                    };

                    // Recreate path collapses drop-in diff (the path
                    // is "rm + mkdir + write all from scratch", so
                    // per-basename diff isn't actionable). In-place
                    // path keeps the per-drop-in diff for the operator.
                    let drop_in_changes_payload = if requires_recreate {
                        Vec::new()
                    } else {
                        drop_in_changes
                    };

                    actions.push(Action::UpdateRunner(RunnerDelta {
                        identity: reconstruct_identity(name, discovered, paths),
                        after: after_plan,
                        requires_recreate,
                        recreate_reasons,
                        drift_cause,
                        field_changes,
                        drop_in_changes: drop_in_changes_payload,
                        // Thread the discovered caches list through
                        // to apply.rs so it can compute the
                        // added / removed pool-name diff that drives
                        // the per-action detail string. Source is
                        // the same 00-ghars.conf body the rest of
                        // Stage 1 reads from.
                        //
                        // Sort `before_caches` so operator-facing
                        // surfaces (--diff output, plan JSON, error
                        // messages that name "removed pools") see a
                        // canonical alphabetical order regardless of
                        // the order the on-disk X-Ghars-Caches=
                        // annotation happened to be written in. Apply
                        // collects this Vec into a BTreeSet at
                        // apply.rs::execute_update_runner before
                        // computing the added / removed diff, so
                        // sorting at this population site is
                        // correctness-neutral for the diff itself;
                        // it only affects display order for downstream
                        // consumers that iterate the Vec directly.
                        before_caches: annotations.caches.as_ref().map(|v| {
                            let mut sorted = v.clone();
                            sorted.sort_unstable();
                            sorted
                        }),
                        // Snapshot the discovered drop-in basenames
                        // (BTreeMap keys, already
                        // alphabetically ordered) so the recreate
                        // `--diff` path can show operator-visible
                        // drop-ins (e.g. `99-custom.conf`) that the
                        // recreate is about to delete. Always Some
                        // here — `discovered` is in scope and its
                        // `drop_ins` map is the authoritative
                        // pre-update on-disk view.
                        before_drop_in_basenames: Some(
                            discovered.drop_ins.keys().cloned().collect(),
                        ),
                    }));
                }
            }
            (false, false) => {
                // Logically unreachable (symmetric with the
                // drift-cause and cache-pool union arms below):
                // `union` is built as `actual.union(&desired)` so
                // every name in the loop is in at least one set;
                // `(false, false)` would mean a name appeared in the
                // union but neither input, which contradicts BTreeSet
                // semantics. debug_assert! pins the invariant in
                // dev/CI; the release fallback emits no action and
                // logs a tracing::warn so a coverage gap surfaces in
                // operator logs without crashing the plan.
                debug_assert!(
                    false,
                    "runner '{name}' appeared in union but neither in_actual nor in_desired: \
                     BTreeSet::union semantics violated",
                );
                tracing::warn!(
                    runner = name.as_str(),
                    "runner classifier reached the unreachable \
                     (in_actual=false, in_desired=false) arm — emitting no action. \
                     This indicates a BTreeSet::union invariant violation; please \
                     file a ghars issue."
                );
            }
        }
    }

    // Step 9: orphans surfaced upstream by callers that have both
    // sides of the comparison (state.discover itself does NOT
    // populate orphans because it lacks the desired set; see the
    // ActualState doc). Treated identically to (false, true) above
    // when present.
    for orphan in &actual.orphans {
        actions.push(Action::RemoveRunner(RunnerIdentity {
            name: orphan.name.clone(),
            url: String::new(),
            auth_name: String::new(),
            trust_zone: "default".to_owned(),
        }));
    }

    // Step 8: cache-pool diffs. State discovery enumerates
    // `ghars-cache@*.service` units into `actual.cache_pools`, so we
    // diff desired vs actual instead of always emitting
    // CreateCachePool. Three branches:
    //   - desired ∧ ¬actual                      → CreateCachePool
    //   - desired ∧ actual ∧ spec_hash differs   → UpdateCachePool
    //   - actual ∧ ¬desired                      → RemoveCachePool
    //   - desired ∧ actual ∧ spec_hash matches   → no-op (in-sync)
    //
    // BTreeMap ordering (alphabetical by pool name) is preserved so
    // plan output stays deterministic across runs.
    let referenced_pools = collect_referenced_cache_pools(&desired);
    let actual_pool_names: BTreeSet<&str> = actual.cache_pools.keys().map(String::as_str).collect();
    let desired_pool_names: BTreeSet<&str> = referenced_pools.keys().map(String::as_str).collect();
    let pool_union: BTreeSet<&str> = actual_pool_names
        .union(&desired_pool_names)
        .copied()
        .collect();
    for pool_name in pool_union {
        let in_desired = desired_pool_names.contains(pool_name);
        let in_actual = actual_pool_names.contains(pool_name);
        match (in_desired, in_actual) {
            (true, false) => {
                let spec = referenced_pools
                    .get(pool_name)
                    .expect("name was in desired_pool_names");
                actions.push(Action::CreateCachePool(into_cache_pool_plan(
                    pool_name.to_owned(),
                    spec,
                    &config_source,
                )?));
            }
            (true, true) => {
                let spec = referenced_pools
                    .get(pool_name)
                    .expect("name was in desired_pool_names");
                let plan = into_cache_pool_plan(pool_name.to_owned(), spec, &config_source)?;
                let actual_pool = actual
                    .cache_pools
                    .get(pool_name)
                    .expect("name was in actual_pool_names");
                // Also consult the discovered drift signal so
                // an operator-added unmanaged drop-in (e.g.
                // `99-tuning.conf`) triggers UpdateCachePool even when
                // the spec_hash matches. Mirrors the runner-side
                // pattern at the per-runner intersection branch above,
                // which gates NoOp on `hashes_equal && in_sync`.
                // Without this, drift on cache pools is invisible to
                // plan output until the operator also edits the
                // managed body.
                let pool_in_sync = matches!(actual_pool.drift, Drift::InSync);
                if plan.spec_hash != actual_pool.spec_hash || !pool_in_sync {
                    // Pool-kind change is a runner-membership no-op.
                    // Pool name is parameterized into the unit
                    // (`ghars-cache@NAME.service`), not into a
                    // static system group, so a kind change has no
                    // membership impact under DynamicUser. Apply
                    // just rewrites the per-pool drop-in body +
                    // restarts the cache unit. The
                    // runner-caches-list-change case (a runner's
                    // `caches = [...]` set in TOML changed) IS a
                    // separate apply path handled by
                    // execute_update_runner via per-runner drop-in
                    // body rewrite.
                    actions.push(Action::UpdateCachePool(CachePoolDelta {
                        binding: plan.binding,
                        drop_in_body: plan.drop_in_body,
                        spec_hash: plan.spec_hash,
                    }));
                }
                // Otherwise in-sync: emit no action. NoOp is reserved
                // for placeholder actions, not "this resource is fine".
            }
            (false, true) => {
                actions.push(Action::RemoveCachePool(pool_name.to_owned()));
            }
            (false, false) => {
                // Logically unreachable (symmetric with the
                // runner-union arm above) — `pool_union` is built as
                // `actual.union(desired)` so every name in the loop
                // is in at least one set; `(false, false)` would mean
                // a name appeared in the union but neither input,
                // which contradicts BTreeSet semantics. debug_assert!
                // pins the invariant in dev/CI; the release fallback
                // emits no action and logs a tracing::warn so a
                // coverage gap surfaces in operator logs without
                // crashing the apply.
                debug_assert!(
                    false,
                    "cache pool '{pool_name}' appeared in pool_union but neither in_desired \
                     nor in_actual: BTreeSet::union semantics violated",
                );
                tracing::warn!(
                    pool = pool_name,
                    "cache pool classifier reached the unreachable \
                     (in_desired=false, in_actual=false) arm — emitting no action. \
                     This indicates a BTreeSet::union invariant violation; please \
                     file a ghars issue."
                );
            }
        }
    }

    let keep_versions = config
        .defaults
        .keep_versions
        .unwrap_or(crate::config::DEFAULT_KEEP_VERSIONS)
        .max(1);

    Ok(Plan {
        actions,
        warnings,
        keep_versions,
    })
}

pub(super) fn with_hash(mut spec: EffectiveRunnerSpec) -> EffectiveRunnerSpec {
    let hash = spec_hash(&spec);
    spec.spec_hash = hash;
    spec
}

/// Build a `RunnerPlan` from an effective spec, computing the `spec_hash`
/// (if not already set) and rendering the unit text + drop-ins.
/// `RunnerPlan` carries the rendered bytes that apply.rs writes to
/// disk verbatim, instead of re-rendering.
pub(super) fn into_runner_plan(spec: EffectiveRunnerSpec) -> Result<RunnerPlan> {
    let spec_with_hash = if spec.spec_hash.is_empty() {
        with_hash(spec)
    } else {
        spec
    };
    let rendered = crate::systemd::render_runner_unit(&spec_with_hash)?;
    Ok(RunnerPlan {
        spec_hash: spec_with_hash.spec_hash.clone(),
        spec: spec_with_hash,
        resolved_release: None,
        effective_unit_text: rendered.template,
        drop_ins: rendered.drop_ins,
        env_file: rendered.env_file,
        path_file: rendered.path_file,
    })
}

pub(super) fn into_cache_pool_plan(
    name: String,
    pool: &CachePoolSpec,
    config_source: &str,
) -> Result<CachePoolPlan> {
    let (sccache_path, sleep_path) = resolve_cache_pool_paths(&name, pool)?;
    let binding = EffectiveCacheBinding {
        name,
        kinds: pool.kinds.clone(),
        size: pool.size.clone(),
        mode: pool.mode,
        trust_zone: pool.trust_zone.clone(),
        sccache_path,
        sleep_path,
    };
    let spec_hash = cache_pool_hash(&binding);
    let drop_in_body = crate::systemd::render_cache_drop_in(&binding, config_source, &spec_hash)?;
    Ok(CachePoolPlan {
        binding,
        drop_in_body,
        spec_hash,
    })
}

/// Resolve the sccache + sleep binary paths for a cache pool. Returns
/// `(sccache_path, sleep_path)` where each entry is:
/// - `Some(absolute path)` when the binary is needed for this pool's
///   `kinds` AND either the operator pinned it on the [`CachePoolSpec`]
///   OR plan-time auto-detection found it on the canonical search
///   list. Auto-detect order:
///     - sccache: `/usr/local/bin/sccache` then `/usr/bin/sccache`
///       (the `cargo install` landing then the distro-packaging
///       landing — first hit wins).
///     - sleep: `/usr/bin/sleep` then `/bin/sleep` (sleep ships in
///       coreutils which most distros place at `/usr/bin/`, with
///       `/bin/sleep` covering legacy non-merged-usr layouts).
/// - `None` when the kind is not served by this pool. The renderer
///   reads `sccache_path` only when `kinds.contains(Sccache)` and
///   `sleep_path` only when the pool is ccache-only, so leaving the
///   unused slot as `None` mirrors the renderer's branching exactly.
///
/// # Errors
///
/// Returns `GharsError::Validation` when the binary is needed
/// (kind served) and neither the operator-pinned path nor the
/// auto-detect candidates exist on disk. The error names the pool
/// and the missing binary so the operator can pick between
/// installing the package and pinning an explicit path in TOML.
fn resolve_cache_pool_paths(
    pool_name: &str,
    pool: &CachePoolSpec,
) -> Result<(Option<Utf8PathBuf>, Option<Utf8PathBuf>)> {
    let serves_sccache = pool.kinds.contains(&CacheKind::Sccache);
    // sleep is only used as the ExecStart on ccache-only pools.
    // sccache-serving pools (whether or not they also serve ccache)
    // put the sccache server on ExecStart and never invoke sleep.
    let needs_sleep = !serves_sccache;
    let sccache_path = if serves_sccache {
        Some(resolve_one_binary(
            pool_name,
            "sccache_path",
            "sccache",
            pool.sccache_path.as_deref(),
            &["/usr/local/bin/sccache", "/usr/bin/sccache"],
        )?)
    } else {
        None
    };
    let sleep_path = if needs_sleep {
        Some(resolve_one_binary(
            pool_name,
            "sleep_path",
            "sleep",
            pool.sleep_path.as_deref(),
            &["/usr/bin/sleep", "/bin/sleep"],
        )?)
    } else {
        None
    };
    Ok((sccache_path, sleep_path))
}

/// Resolve a single binary path: honor the operator-pinned value when
/// set, else probe the canonical search list in order. Validates the
/// operator pin is absolute (defense-in-depth — the config-load
/// validator owns the primary gate, this catches any caller that
/// bypasses it).
fn resolve_one_binary(
    pool_name: &str,
    field: &str,
    bin: &str,
    pinned: Option<&camino::Utf8Path>,
    candidates: &[&str],
) -> Result<Utf8PathBuf> {
    if let Some(p) = pinned {
        if !p.is_absolute() {
            return Err(GharsError::Validation(
                format!("cache_pool '{pool_name}' {field} must be absolute, got: {p}"),
                "relative paths resolve against process CWD which varies between \
                 invocations (operator shell vs. root apply); use an absolute path"
                    .into(),
            ));
        }
        return Ok(p.to_owned());
    }
    for candidate in candidates {
        if Path::new(candidate).exists() {
            return Ok(Utf8PathBuf::from(*candidate));
        }
    }
    Err(GharsError::Validation(
        format!(
            "cache_pool '{pool_name}': {bin} not found on canonical search path ({})",
            candidates.join(", ")
        ),
        format!(
            "install {bin} (e.g. `cargo install sccache` lands at /usr/local/bin; \
             distro packages land at /usr/bin) OR pin an explicit \
             absolute path with `{field} = \"/path/to/{bin}\"` in [cache_pools.{pool_name}]"
        ),
    ))
}

pub(super) fn collect_referenced_cache_pools(
    desired: &BTreeMap<String, EffectiveRunnerSpec>,
) -> BTreeMap<String, CachePoolSpec> {
    // Dedup by pool name. BTreeMap key ordering produces alphabetical
    // emit order in plan_from (matches the runner phase's
    // determinism guarantee).
    let mut out: BTreeMap<String, CachePoolSpec> = BTreeMap::new();
    let mut seen: BTreeSet<String> = BTreeSet::new();
    for spec in desired.values() {
        for binding in &spec.caches {
            if !seen.insert(binding.name.clone()) {
                continue;
            }
            // Reconstruct CachePoolSpec from the binding (lossless —
            // every field round-trips). The path fields carry through
            // as the already-resolved absolute paths from
            // `resolve_cache_pool_paths` at lower_to_effective time
            // so the downstream `into_cache_pool_plan` consumer sees
            // the same Some-value the operator's binding does (no
            // double resolution, no chance of host state drifting
            // between the runner-side and pool-side binding
            // constructions).
            out.insert(
                binding.name.clone(),
                CachePoolSpec {
                    kinds: binding.kinds.clone(),
                    size: binding.size.clone(),
                    mode: binding.mode,
                    trust_zone: binding.trust_zone.clone(),
                    sccache_path: binding.sccache_path.clone(),
                    sleep_path: binding.sleep_path.clone(),
                },
            );
        }
    }
    out
}

pub(super) fn reconstruct_identity(
    name: &str,
    discovered: &DiscoveredRunner,
    _paths: &Paths,
) -> RunnerIdentity {
    // RunnerIdentity reconstruction reads only the X-Ghars-Runner-Url,
    // X-Ghars-Auth-Name, and X-Ghars-Trust-Zone annotations from
    // `00-ghars.conf`. The user is allocated by `DynamicUser=yes`
    // at unit start (transient UID/GID, recycled at unit stop), and
    // the home directory is at `<state_dir>/<trust_zone>/ghars-<name>`
    // per Paths::runner_home — neither is operator-configurable, so
    // neither is reconstructed from annotations.
    let annotations = DiscoveredAnnotations::from_discovered(discovered);
    RunnerIdentity {
        name: name.to_owned(),
        url: annotations.url.unwrap_or_default(),
        auth_name: annotations.auth_name.unwrap_or_default(),
        trust_zone: annotations
            .trust_zone
            .filter(|t| !t.is_empty())
            .unwrap_or_else(|| "default".to_owned()),
    }
}

pub(super) fn lower_to_effective(
    runner: &RunnerSpec,
    config: &Config,
    host_arch: Arch,
    config_source: String,
    slot_idx: usize,
) -> Result<EffectiveRunnerSpec> {
    // Auth resolution.
    let auth_name = runner
        .auth
        .clone()
        .or_else(|| config.defaults.auth.clone())
        .ok_or_else(|| {
            GharsError::Validation(
                format!(
                    "runner '{}' has no auth and no [defaults] auth",
                    runner.name
                ),
                "set `auth = \"NAME\"` on the runner or in [defaults]".into(),
            )
        })?;
    if !config.auth.contains_key(&auth_name) {
        return Err(GharsError::Validation(
            format!(
                "runner '{}' references unknown auth '{auth_name}'",
                runner.name
            ),
            format!("declare an [auth.{auth_name}] block or fix the auth reference"),
        ));
    }

    // Cache resolution.
    let mut caches: Vec<EffectiveCacheBinding> = Vec::with_capacity(runner.caches.len());
    let runner_zone = if runner.trust_zone.is_empty() {
        DEFAULT_TRUST_ZONE
    } else {
        runner.trust_zone.as_str()
    };
    for cache_name in &runner.caches {
        let pool = config.cache_pools.get(cache_name).ok_or_else(|| {
            GharsError::Validation(
                format!(
                    "runner '{}' references unknown cache pool '{cache_name}'",
                    runner.name
                ),
                format!("declare a [cache_pools.{cache_name}] block or fix the caches list"),
            )
        })?;
        if pool.trust_zone != runner_zone {
            return Err(GharsError::Validation(
                format!(
                    "runner '{}' (trust_zone='{runner_zone}') cannot reference \
                     cache_pool '{cache_name}' (trust_zone='{}')",
                    runner.name, pool.trust_zone
                ),
                "split into separate pools or align trust_zones (SEC-03)".into(),
            ));
        }
        let (sccache_path, sleep_path) = resolve_cache_pool_paths(cache_name, pool)?;
        caches.push(EffectiveCacheBinding {
            name: cache_name.clone(),
            kinds: pool.kinds.clone(),
            size: pool.size.clone(),
            mode: pool.mode,
            trust_zone: pool.trust_zone.clone(),
            sccache_path,
            sleep_path,
        });
    }
    // Caches form an unordered set (group memberships are
    // unordered, cache pools provide isolated services, and apply.rs
    // reconciles via BTreeSet diff). Sort by name so every downstream
    // consumer — `spec_hash`, `render_identity`'s X-Ghars-Caches line,
    // and `render_cache_pool`'s 30-cache-pool.conf body — sees a
    // canonical order. Without this, a TOML reorder
    // `["pool-b", "pool-a"]` → `["pool-a", "pool-b"]` would flip
    // spec_hash and rewrite the 30-cache-pool.conf drop-in even though
    // membership is identical, producing a spurious in-place
    // UpdateRunner. Cache names are ASCII-only per IDENTIFIER_REGEX
    // (validators.rs), so byte-wise `Ord` agrees with operator intent.
    caches.sort_by(|a, b| a.name.cmp(&b.name));

    // SEC: a runner that binds 2+ sccache pools clobbers
    // SCCACHE_SERVER_UDS / SCCACHE_CACHE_SIZE in the rendered
    // 30-cache-pool.conf drop-in (last-writer-wins on duplicate
    // Environment= keys per systemd.exec(5)). sccache itself only
    // reads ONE server UDS, so the second-to-last pool would be
    // silently unreachable from the runner. Reject the binding at
    // plan time so the operator gets a clear remediation rather
    // than a silently-broken cache pipeline.
    let sccache_pools: Vec<&str> = caches
        .iter()
        .filter(|c| c.kinds.contains(&crate::config::CacheKind::Sccache))
        .map(|c| c.name.as_str())
        .collect();
    if sccache_pools.len() > 1 {
        return Err(GharsError::Validation(
            format!(
                "runner '{}' binds {} sccache pools ({}) — sccache \
                 supports only ONE server UDS per process; the rendered \
                 SCCACHE_SERVER_UDS would be clobbered last-writer-wins, \
                 leaving all but one pool unreachable",
                runner.name,
                sccache_pools.len(),
                sccache_pools.join(", "),
            ),
            "split the runner into multiple runners (one per sccache pool), \
             or merge the pools, or change all but one to ccache-only \
             (filesystem mode is multi-bind safe — only sccache's daemon \
             model is single-server)"
                .into(),
        ));
    }

    // Network resolution. A runner with no `network` reference (and
    // no `defaults.network`) gets `network_binding = None` — the
    // implicit-Open path with no defense-in-depth fields.
    //
    // For an explicit `[network.NAME]` reference:
    //   - `mode = "netns"` ALWAYS produces `Some(binding)` with
    //     `subnet = Some(/30)` — the namespace bind is itself the
    //     load-bearing artifact, so the binding is required even when
    //     all the cgroup-BPF policy fields are empty.
    //   - `mode = "open"` produces `Some(binding)` only when at least
    //     one of `ip_allow` / `ip_deny` / `restrict_address_families`
    //     is non-empty. An Open block with all three empty is
    //     semantically identical to "no network reference" (no
    //     namespace, no policy directives) and we collapse it back to
    //     `None`. This keeps `Some(binding)` ⇔ "there are directives
    //     to render", which matches Stage 1/Stage 2 classifier
    //     intuition AND avoids spurious spec_hash flips on no-op Open
    //     blocks.
    //
    // The /30 subnet is `Some` ONLY for Netns-mode bindings — Open-
    // mode runners have no namespace and therefore no /30 to
    // allocate, so we skip `netns_subnet_for_slot` and leave
    // `subnet = None`. This both reflects the fact (no subnet
    // exists) and preserves the v0.1 64-slot pool capacity for
    // runners that actually need a slot.
    let network_ref = runner
        .network
        .clone()
        .or_else(|| config.defaults.network.clone());
    let network_binding = match network_ref {
        Some(network_name) => {
            let spec = config.networks.get(&network_name).ok_or_else(|| {
                GharsError::Validation(
                    format!(
                        "runner '{}' references unknown network '{network_name}'",
                        runner.name
                    ),
                    format!(
                        "declare a [network.{network_name}] block or fix the network reference"
                    ),
                )
            })?;
            match spec.mode {
                NetworkMode::Netns => {
                    // Sequential /30 from the default 10.200.0.0/24
                    // pool, indexed by `slot_idx` (the runner's
                    // position in the expanded list). 64 /30 slots
                    // in a /24 = 64 max simultaneous netns runners
                    // under v0.1's hardcoded pool. Persistent
                    // [defaults] netns_subnet config is design
                    // Part 9c future scope.
                    let subnet = netns_subnet_for_slot(slot_idx, &runner.name)?;
                    Some(EffectiveNetworkBinding {
                        name: network_name,
                        spec: spec.clone(),
                        subnet: Some(subnet),
                    })
                }
                NetworkMode::Open => {
                    let has_cgroup_bpf_policy = !spec.ip_allow.is_empty()
                        || !spec.ip_deny.is_empty()
                        || !spec.restrict_address_families.is_empty();
                    if has_cgroup_bpf_policy {
                        // Open with policy: produce a binding so the
                        // renderer emits the cgroup-BPF directives.
                        // Subnet stays None (Open mode owns no /30).
                        Some(EffectiveNetworkBinding {
                            name: network_name,
                            spec: spec.clone(),
                            subnet: None,
                        })
                    } else {
                        // Open with no policy collapses to the
                        // implicit-Open shape — preserves the v0.1
                        // spec_hash for no-op Open blocks and keeps
                        // `Some(binding)` ⇔ "directives to render"
                        // as the binding semantics.
                        None
                    }
                }
            }
        }
        None => None,
    };

    // Proxy: runner.proxy overrides config.proxy entirely.
    let proxy = runner.proxy.clone().or_else(|| config.proxy.clone());
    // Hooks: runner.hooks overrides config.hooks entirely.
    let hooks = runner.hooks.clone().or_else(|| config.hooks.clone());

    // SEC-27 shared-user warning is removed — DynamicUser provisions
    // per-trust_zone identities, so the "shared UID disables
    // cross-runner isolation" failure mode is replaced by the
    // operator-explicit trust_zone declaration.

    Ok(merge_defaults(
        runner,
        &config.defaults,
        auth_name,
        caches,
        network_binding,
        proxy,
        hooks,
        host_arch,
        config_source,
    ))
}

pub(super) fn host_arch() -> Arch {
    // Fallback when defaults.arch and runner.arch are both unset.
    // x86_64 is the v0.1 reference arch; aarch64 hosts override on
    // [defaults] per Part 4 example.
    if cfg!(target_arch = "aarch64") {
        Arch::Aarch64
    } else {
        Arch::X86_64
    }
}
