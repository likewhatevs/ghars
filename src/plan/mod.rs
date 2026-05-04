//! Plan computation: diff desired config against discovered actual state
//! and emit an ordered list of `Action`s.
//!
//! Design spec: Part 3 (`plan.rs`) + Part 8 (plan/apply engine).
//!
//! This module owns four orthogonal pieces:
//!
//! 1. [`expand_counts`] — pre-plan flattening of `[[runner]]` entries
//!    with `count > 1` into one `RunnerSpec` per generated name. Auto-
//!    skips collisions with explicit `[[runner]]` blocks; errors on
//!    cross-block overlap (Part 8 "Count expansion").
//! 2. [`merge_defaults`] — produces an [`crate::config::EffectiveRunnerSpec`]
//!    from a `RunnerSpec` + `Defaults` per the Part 3 merge table (scalars
//!    override, labels concatenate-and-dedup, hardening field-by-field).
//! 3. [`spec_hash`] — canonical-JSON sha256 of an
//!    [`crate::config::EffectiveRunnerSpec`] (Part 3 spec-hash).
//! 4. [`plan_from`] — diff desired effective specs against
//!    [`crate::state::ActualState`] and emit ordered [`Action`]s applying
//!    the `requires_recreate` policy (Part 3).
//!
//! Per Part 8, `apply::sort_into_phases` re-orders the emitted actions
//! into the canonical execution order (CreateCachePool → UpdateCachePool
//! → RemoveRunner → UpdateRunner-inplace → UpdateRunner-recreate →
//! CreateRunner → RemoveCachePool → NoOp). plan_from itself emits in
//! alphabetical name order — apply owns phase ordering, plan owns
//! per-name determinism.

mod action;
mod classify;
mod compute;
mod expand;
mod hash;
mod merge;
mod types;

#[cfg(test)]
mod tests;

pub use action::{Action, Disruption};
pub use compute::plan_from;
pub use expand::{MAX_COUNT, expand_counts};
pub use hash::spec_hash;
pub use merge::merge_defaults;
pub use types::{
    CachePoolDelta, CachePoolPlan, DriftCause, DropInChange, DropInChangeKind, FieldChange,
    FieldValue, Plan, RunnerDelta, RunnerIdentity, RunnerPlan,
};

/// Default trust zone — keeps the merge in lock-step with config.rs's
/// `default_trust_zone` (SEC-03).
pub(super) const DEFAULT_TRUST_ZONE: &str = "default";
