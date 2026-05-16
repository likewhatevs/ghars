//! `Action` and `Disruption` — the per-step output of plan computation
//! and the worst-case disruption tag derived from each variant.

use super::types::{CachePoolDelta, CachePoolPlan, RunnerDelta, RunnerIdentity, RunnerPlan};

/// One scheduled action in a `Plan`.
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub enum Action {
    /// Create a new runner from scratch (registration + systemd unit + start).
    CreateRunner(RunnerPlan),
    /// Update an existing runner. The delta carries `requires_recreate` so
    /// `apply` knows whether to rewrite drop-ins in place or stop+remove+
    /// create.
    UpdateRunner(RunnerDelta),
    /// Stop + unregister + remove a runner.
    RemoveRunner(RunnerIdentity),
    /// Create a new cache pool (writes ghars-cache@POOL.service).
    CreateCachePool(CachePoolPlan),
    /// Update an existing cache pool (size, kinds, mode).
    UpdateCachePool(CachePoolDelta),
    /// Remove a cache pool unit + storage.
    RemoveCachePool(String),
    /// Nothing to do; carries a human-readable reason.
    NoOp(String),
}

/// Worst-case operational disruption an [`Action`] inflicts on a
/// running runner or cache pool when applied. Computed at plan time
/// so operators reading `ghars plan` can see the blast radius before
/// they approve.
///
/// "Worst-case" because plan time cannot know whether `apply` will
/// short-circuit at apply time. `execute_update_runner`'s in-place
/// path (apply.rs) skips daemon-reload + restart when every managed
/// drop-in's bytes already match disk — a route that is genuinely
/// [`Disruption::None`] when it fires but cannot be predicted from
/// the plan because the optimization keys on on-disk bytes the
/// planner does not consult. The disruption tag therefore reports
/// the maximum disruption an in-place `UpdateRunner` could cause.
///
/// Variants are ordered from least to most disruptive so callers
/// that compare or sort by severity get a consistent ordering.
/// Backed by derived `PartialOrd` / `Ord` — `None < Restart <
/// Recreate` matches variant declaration order, so callers can
/// guard with `disruption >= Disruption::Recreate` without
/// hand-rolling a comparator.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
#[non_exhaustive]
pub enum Disruption {
    /// No scheduled host mutation. `Action::NoOp` emits this; the
    /// in-place `UpdateRunner` short-circuit at
    /// `apply::execute_update_runner` lands here at apply time but
    /// is reported as [`Disruption::Restart`] from plan because the
    /// short-circuit is byte-equality-driven and not plan-visible.
    /// At apply time the short-circuit logs a `tracing::info!`
    /// "skipping daemon-reload + restart" message so the operator
    /// can confirm `apply` recognized the no-op state.
    None,
    /// Stop + start of the affected unit. Disrupts in-flight runner
    /// jobs (SIGTERM at stop) and brings the unit back up with
    /// refreshed exec credentials and any updated drop-in bodies.
    /// `apply` reaches this for every non-skip in-place
    /// `UpdateRunner` and every `UpdateCachePool`.
    Restart,
    /// Tear down + reconstruct the unit, including a GitHub-side
    /// re-registration when the action is runner-class. Strictly
    /// more disruptive than [`Disruption::Restart`] because it
    /// consumes a registration token mint (runners) or destroys
    /// host-state (cache pools: storage dir + cache-server unit).
    /// Reached by `CreateRunner`, recreate-class `UpdateRunner`,
    /// `RemoveRunner`, `CreateCachePool`, and `RemoveCachePool`.
    Recreate,
}

impl Disruption {
    /// Stable `snake_case` label for text + JSON rendering. Mirrors
    /// the `DriftCause::label` vocabulary so a single `grep recreate`
    /// finds every action surface.
    #[must_use]
    pub fn label(self) -> &'static str {
        match self {
            Self::None => "none",
            Self::Restart => "restart",
            Self::Recreate => "recreate",
        }
    }
}

impl Action {
    /// Diagnostic label for this action — used by `apply` when wrapping
    /// failures in `GharsError::Apply { action, .. }`.
    ///
    /// Load-bearing for `summary.recreates` JSON output;
    /// renames require `schema_version` bump. Format relies on
    /// entity names being paren-free per `IDENTIFIER_REGEX`
    /// (`^[a-z]([a-z0-9-]*[a-z0-9])?$`).
    #[must_use]
    pub fn label(&self) -> String {
        match self {
            Self::CreateRunner(p) => format!("CreateRunner({})", p.spec.name),
            Self::UpdateRunner(d) => format!("UpdateRunner({})", d.identity.name),
            Self::RemoveRunner(i) => format!("RemoveRunner({})", i.name),
            Self::CreateCachePool(p) => format!("CreateCachePool({})", p.binding.name),
            Self::UpdateCachePool(d) => format!("UpdateCachePool({})", d.binding.name),
            Self::RemoveCachePool(name) => format!("RemoveCachePool({name})"),
            Self::NoOp(reason) => format!("NoOp({reason})"),
        }
    }

    /// Worst-case [`Disruption`] this action inflicts when applied.
    /// See the [`Disruption`] doc-comment for why this is plan-time
    /// worst-case rather than apply-time actual.
    ///
    /// Mapping (verified against `apply.rs`):
    /// - [`Self::CreateRunner`] → `Recreate` —
    ///   `execute_create_runner` mints a registration token and runs
    ///   `config.sh` against the GitHub API; the runner unit is
    ///   constructed from scratch.
    /// - [`Self::UpdateRunner`] with `requires_recreate = true` →
    ///   `Recreate` — `execute_update_runner` calls
    ///   `execute_remove_runner` followed by `execute_create_runner`,
    ///   both of which hit the GitHub registration API.
    /// - [`Self::UpdateRunner`] with `requires_recreate = false` →
    ///   `Restart` — `execute_update_runner`'s in-place branch issues
    ///   `daemon-reload` + `stop_unit` + `start_unit` whenever any
    ///   managed file body changes. The byte-equality short-circuit
    ///   at `apply.rs::execute_update_runner` IS in-place's
    ///   [`Disruption::None`] path at apply time, but plan cannot
    ///   predict it (keys on on-disk bytes), so we report `Restart`.
    /// - [`Self::RemoveRunner`] → `Recreate` —
    ///   `execute_remove_runner` first stops + disables the unit
    ///   and tears down per-runner netns side-units (apply.rs step
    ///   1, 1b), THEN mints a removal token and calls
    ///   `config.sh remove` to deregister with GitHub (step 2),
    ///   THEN deletes the home directory (step 3+). `DynamicUser`
    ///   handles the runner's transient UID/GID lifecycle — systemd
    ///   recycles them on unit stop, so there is no system user to
    ///   delete. The GitHub-side mutation is the same disruption
    ///   class as a fresh registration, regardless of execution
    ///   order.
    /// - [`Self::CreateCachePool`] → `Recreate` —
    ///   `execute_create_cache_pool` provisions per-pool group +
    ///   storage dir + unit drop-in; the host-state construction is
    ///   the symmetric counterpart of `RemoveCachePool` and the
    ///   parity preserves the "create/remove → recreate" rule.
    /// - [`Self::UpdateCachePool`] → `Restart` — drop-in rewrite +
    ///   `daemon-reload` + `stop_unit` + `start_unit` on the
    ///   existing `ghars-cache@POOL.service`. Group + storage
    ///   identity unchanged.
    /// - [`Self::RemoveCachePool`] → `Recreate` —
    ///   `execute_remove_cache_pool` deletes the per-pool group,
    ///   storage dir, and drop-ins. Strictly more disruptive than
    ///   `Restart` because the host-state is destroyed.
    /// - [`Self::NoOp`] → `None`.
    #[must_use]
    pub fn disruption(&self) -> Disruption {
        match self {
            Self::CreateRunner(_) => Disruption::Recreate,
            Self::UpdateRunner(d) => {
                if d.requires_recreate {
                    Disruption::Recreate
                } else {
                    Disruption::Restart
                }
            }
            Self::RemoveRunner(_) => Disruption::Recreate,
            Self::CreateCachePool(_) => Disruption::Recreate,
            Self::UpdateCachePool(_) => Disruption::Restart,
            Self::RemoveCachePool(_) => Disruption::Recreate,
            Self::NoOp(_) => Disruption::None,
        }
    }
}
