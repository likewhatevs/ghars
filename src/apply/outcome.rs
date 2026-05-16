//! Apply-time outcome types: [`ApplyOptions`], [`ApplyOutcome`], [`ApplyResult`].
//!
//! These describe the inputs and outputs of an apply run. The
//! per-action handlers in [`super::runners`] / [`super::pools`] return
//! [`ApplyOutcome`] variants; [`super::orchestrator::apply`] aggregates
//! them into [`ApplyResult`].

use crate::error::GharsError;

use super::undo::UndoStep;

/// Options threaded through `apply` from the CLI layer.
#[derive(Debug, Clone, Default)]
pub struct ApplyOptions {
    /// `--auto-approve`: skip the y/N confirmation. Honored by the CLI;
    /// `apply()` itself does not prompt — but the field is threaded here
    /// so the Plan-print + apply sequence can short-circuit the prompt.
    pub auto_approve: bool,
    /// Stop on first action failure. `false` ⇒ keep going, surface
    /// failed actions in the `ApplyResult`.
    pub fail_fast: bool,
    /// Render artifacts but do not write them. The lock is still
    /// acquired (so concurrent `--dry-run` runs serialize) but no
    /// systemd D-Bus calls or filesystem writes occur.
    pub dry_run: bool,
    /// `--rollback-on-failure`: walk this action's [`super::undo::UndoLog`] in reverse
    /// when its execute_* handler returns `Err`. Per-action scope only
    /// — earlier successful actions are NOT undone. Each Action records
    /// a `Vec<UndoStep>`; on error the list is walked in reverse and
    /// best-effort undone. Default false.
    pub rollback_on_failure: bool,
    /// `--no-restart`: write files (drop-ins, .env, .path) but skip
    /// the in-place restart cycle (`daemon_reload` + stop + start) for
    /// `UpdateRunner` and `UpdateCachePool` actions. The running unit
    /// keeps its pre-rewrite loaded config until the operator
    /// explicitly runs `systemctl restart ghars-runner@NAME.service`
    /// (or `ghars-cache@POOL.service` equivalent). Recreate-class
    /// actions (full enumeration: `url` / `runner_version` / `labels`
    /// / `arch` / `runner_sha256` / `runner_tarball` / `network` for
    /// runners; `CreateCachePool` + `RemoveCachePool` for pools) are
    /// STRUCTURALLY undeferrable (they deregister + re-register or
    /// tear down the unit) so this flag does not affect them.
    /// `UpdateCachePool` (pool drop-in rewrite from operator
    /// `[cache_pools]` edits, including `kinds` changes) IS deferred
    /// by this flag. CAVEAT: re-apply WITHOUT `--no-restart` will
    /// see byte-matched on-disk drop-ins and take the
    /// [`ApplyOutcome::InPlaceSkipped`] / [`ApplyOutcome::PoolSkipped`]
    /// short-circuit — re-apply is NOT a remediation path; operators
    /// MUST run `systemctl restart` to clear pending state.
    /// Default false (current restart-on-apply behavior).
    pub no_restart: bool,
}

/// What happened when a single action ran. Lifted out of [`super::orchestrator::apply`]
/// so `cmd_apply` can render a per-action
/// `ok: LABEL [disruption] (detail)` line for every successful or
/// skipped action, AND a per-action
/// `fail: LABEL [disruption] (error)` line for every failed action.
/// The full [`GharsError`] chain for failed actions is also
/// preserved on [`ApplyResult::failed`] for programmatic consumers
/// that need the typed error.
///
/// Variant-to-`Disruption` correspondence (mirrors
/// [`crate::plan::Action::disruption`]):
/// - [`Self::InPlaceSkipped`]      → [`crate::plan::Disruption::None`]
///   at apply time. Plan reports `Restart` (cannot predict the
///   byte-equality short-circuit at `apply.rs::execute_update_runner`).
/// - [`Self::InPlaceRestarted`]    → [`crate::plan::Disruption::Restart`]
/// - [`Self::InPlaceRewroteNoRestart`] → [`crate::plan::Disruption::None`]
///   at apply time (the restart cycle was skipped per
///   `ApplyOptions::no_restart`; the file rewrites still happened on
///   disk, but no unit lifecycle change fired). Plan reports `Restart`
///   (cannot predict the `--no-restart` flag at plan time).
/// - [`Self::Recreated`]           → [`crate::plan::Disruption::Recreate`]
///   (single combined outcome — the inner `execute_remove_runner` +
///   `execute_create_runner` are implementation detail and do not
///   appear as separate rows in `ApplyResult::details`)
/// - [`Self::Created`]             → [`crate::plan::Disruption::Recreate`]
/// - [`Self::Removed`]             → [`crate::plan::Disruption::Recreate`]
/// - [`Self::PoolCreated`]         → [`crate::plan::Disruption::Recreate`]
/// - [`Self::PoolUpdated`]         → [`crate::plan::Disruption::Restart`]
/// - [`Self::PoolRewroteNoRestart`] → [`crate::plan::Disruption::None`]
///   at apply time (symmetric with [`Self::InPlaceRewroteNoRestart`]
///   for the cache-pool side: `ApplyOptions::no_restart` skipped the
///   pool restart cycle; the drop-in rewrite still happened).
/// - [`Self::PoolSkipped`]         → [`crate::plan::Disruption::None`]
///   at apply time. Plan reports `Restart` (cannot predict the
///   byte-equality short-circuit at `apply.rs::execute_update_cache_pool`).
///   Symmetric with [`Self::InPlaceSkipped`] for the runner-side path
///   but applies to `UpdateCachePool`.
/// - [`Self::PoolRemoved`]         → [`crate::plan::Disruption::Recreate`]
/// - [`Self::NoOp`]                → [`crate::plan::Disruption::None`]
/// - [`Self::DryRunSkipped`]       → [`crate::plan::Disruption::None`]
///   at apply time (nothing ran). `DryRunSkipped` does not record the
///   would-have-been `Disruption` — that is plan-knowable
///   (`action.disruption()` works on the original `Plan`), so the
///   operator's reference for the dry-run worst-case impact is the
///   `[recreate]`/`[restart]`/`[none]` bracket tag from plan output,
///   not the apply-time outcome row.
/// - [`Self::Failed`]              → [`crate::plan::Disruption`] of
///   the action's plan-time worst-case (the `plan_disruption` field).
///   Apply time reached an error before completion; what actually
///   mutated is per-handler-specific and may be partial. The
///   plan-time disruption is reported so the operator's
///   `[recreate]`/`[restart]`/`[none]` bracket tag remains
///   consistent across plan and apply surfaces — an `[recreate]`-
///   tagged `fail:` row signals the same blast-radius class the plan
///   would have shown.
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub enum ApplyOutcome {
    /// `execute_update_runner` in-place branch took the
    /// `files_changed == 0 && pools_added.is_empty() &&
    /// pools_removed.is_empty()` short-circuit: no daemon-
    /// reload, no stop+start. Equivalent to
    /// [`crate::plan::Disruption::None`] at apply time.
    InPlaceSkipped,
    /// `execute_update_runner` in-place branch wrote one or more
    /// managed files and / or observed one or more cache-pool
    /// membership changes, then issued daemon-reload + stop+start.
    /// `files_changed` counts the managed files whose bytes diverged
    /// from disk (unit + every drop-in basename); `pools_added` /
    /// `pools_removed` carry the cache-pool NAMES whose binding was
    /// added or removed from the runner's caches list. The Vecs are
    /// informational — cache reach is materialized by the rendered
    /// 30-cache-pool.conf drop-in's `BindPaths=` entries, not by any
    /// system-level group reconciliation. [`Self::detail`] renders a
    /// `(added: …; removed: …)` suffix when either Vec is non-empty.
    InPlaceRestarted {
        /// Number of managed files whose bytes were rewritten this
        /// apply (unit text + drop-ins). `0` with non-empty
        /// `pools_added` / `pools_removed` cannot occur — pool
        /// changes always re-render `30-cache-pool.conf`, which
        /// bumps `files_changed`.
        files_changed: usize,
        /// Cache-pool names whose binding was added to this runner's
        /// caches list since the last apply, sorted by
        /// `BTreeSet::difference` order at the construction site
        /// (apply.rs `execute_update_runner` in-place caches diff)
        /// so the rendered detail line is deterministic. Empty when
        /// the diff was a no-op or `delta.before_caches` was `None`
        /// (pre-annotation runner — no annotation to diff against).
        pools_added: Vec<String>,
        /// Cache-pool names whose binding was removed from this
        /// runner's caches list since the last apply. Sorted; empty
        /// semantics symmetric with `pools_added`.
        ///
        /// Symmetric counterpart on the cache-pool side:
        /// [`Self::PoolUpdated`] / [`Self::PoolSkipped`] intentionally
        /// lack these Vecs — pool-kind changes don't change runner-
        /// side bindings.
        pools_removed: Vec<String>,
    },
    /// `execute_update_runner` in-place branch wrote one or more
    /// managed files but `ApplyOptions::no_restart` skipped the
    /// daemon-reload + stop + start cycle. The bytes are on disk
    /// (matching what `InPlaceRestarted` would have written); the
    /// running unit keeps its pre-rewrite loaded config until the
    /// operator explicitly runs
    /// `systemctl restart ghars-runner@NAME.service`. Re-applying
    /// without `--no-restart` is NOT a remediation path — see
    /// CAVEAT below for the byte-equality short-circuit details.
    /// Field semantics mirror `InPlaceRestarted`.
    ///
    /// CAVEAT: next `ghars apply` without `--no-restart` will see
    /// byte-matched on-disk drop-ins (this apply wrote them) and
    /// take the [`Self::InPlaceSkipped`] short-circuit at
    /// `apply::update_runner::execute_update_runner` — so the deferred
    /// restart persists across re-applies until the operator
    /// explicitly invokes `systemctl restart`.
    InPlaceRewroteNoRestart {
        /// Runner name (the `{name}` segment of
        /// `ghars-runner@{name}.service`) carried on the variant so
        /// the operator-facing `detail()` string can render a
        /// copy-pasteable `systemctl restart
        /// ghars-runner@<name>.service` remediation — the only
        /// concrete remediation that actually clears the deferred
        /// state (re-applying without `--no-restart` takes the
        /// byte-equality short-circuit and leaves the runner
        /// pending, per the [`Self::InPlaceSkipped`] CAVEAT).
        name: String,
        /// Number of managed files whose bytes were rewritten this
        /// apply (unit text + drop-ins + .env/.path), same accounting
        /// as [`Self::InPlaceRestarted::files_changed`].
        files_changed: usize,
        /// Cache-pool names added since the last apply. Same shape
        /// and ordering as [`Self::InPlaceRestarted::pools_added`].
        pools_added: Vec<String>,
        /// Cache-pool names removed since the last apply. Same shape
        /// and ordering as [`Self::InPlaceRestarted::pools_removed`].
        pools_removed: Vec<String>,
    },
    /// `execute_update_runner` recreate branch — `requires_recreate
    /// = true` dispatched through `execute_remove_runner` followed
    /// by `execute_create_runner`. Their inner outcomes are flattened
    /// into this single value because the user-facing contract is
    /// one row per `Action`; the inner remove + create are
    /// implementation detail.
    Recreated,
    /// `execute_create_runner` finished — system user provisioned,
    /// home directory + runner binary installed, GitHub registration
    /// completed, unit started.
    Created,
    /// `execute_remove_runner` finished — unit stopped + disabled,
    /// GitHub deregistration completed, system user + home dir
    /// removed.
    Removed,
    /// `execute_create_cache_pool` finished — per-pool storage dir +
    /// drop-in written, ghars-cache@POOL.service started.
    PoolCreated,
    /// `execute_update_cache_pool` finished — drop-in rewritten,
    /// daemon-reload + stop + start cycled the existing
    /// ghars-cache@POOL.service.
    /// (No pool-membership Vecs — pool updates don't change runner-
    /// side bindings. See [`Self::InPlaceRestarted`] for the runner-
    /// side caches-list diff that DOES carry `pools_added` /
    /// `pools_removed`.)
    PoolUpdated,
    /// `execute_update_cache_pool` rewrote the per-pool drop-in but
    /// `ApplyOptions::no_restart` skipped the daemon-reload + stop +
    /// start cycle. Symmetric with [`Self::InPlaceRewroteNoRestart`]
    /// for the cache-pool side. Same caveat: subsequent `ghars apply`
    /// without `--no-restart` sees byte-matched bytes and takes the
    /// [`Self::PoolSkipped`] short-circuit, so deferred pool restarts
    /// persist across re-applies until manually invoked.
    PoolRewroteNoRestart {
        /// Pool name (the `{pool}` segment of
        /// `ghars-cache@{pool}.service`) carried on the variant so
        /// the operator-facing `detail()` string can render a
        /// copy-pasteable `systemctl restart
        /// ghars-cache@<pool>.service` remediation. Same rationale
        /// as [`Self::InPlaceRewroteNoRestart::name`].
        name: String,
        /// Number of managed files whose bytes were rewritten this
        /// apply. Mirrors the runner-side `files_changed` field shape.
        files_changed: usize,
    },
    /// `execute_update_cache_pool` took the byte-equality short-circuit
    /// (symmetric with [`Self::InPlaceSkipped`]): the
    /// per-pool drop-in directory already existed AND its
    /// 00-ghars.conf bytes already matched the rendered body
    /// byte-for-byte. Both conditions are required — a freshly
    /// created drop-in directory counts as a mutation (mirror of
    /// the runner-side `!drop_in_dir_existed` branch in
    /// `execute_update_runner`) and forces daemon-reload + restart
    /// even when the (yet-to-be-written) drop-in body would byte-
    /// match. When both conditions hold: no daemon-reload, no
    /// stop+start, no host mutation. Equivalent to
    /// [`crate::plan::Disruption::None`] at apply time.
    /// (No pool-membership Vecs — pool-kind changes don't change
    /// runner-side bindings. Symmetric to
    /// [`Self::InPlaceRestarted`]'s `pools_added`/`pools_removed`
    /// which DO carry runner-side caches-list diff.)
    PoolSkipped,
    /// `execute_remove_cache_pool` finished — drop-in + per-pool
    /// group + storage dir removed.
    PoolRemoved,
    /// `Action::NoOp` — the planner emitted "in sync" for this
    /// runner / pool; no host mutation scheduled. Carried into
    /// `details` so `cmd_apply` can render every action with a row,
    /// even no-ops.
    NoOp,
    /// `apply` was invoked with `ApplyOptions::dry_run = true`. The
    /// action would have routed to one of the variants above, but
    /// the dry-run gate short-circuited before the handler ran.
    DryRunSkipped,
    /// The action's `execute_*` handler returned `Err`. `apply`
    /// pushes one [`Self::Failed`] row to [`ApplyResult::details`]
    /// per failed action so the per-action audit trail
    /// covers both success and failure in a single execution-order
    /// Vec. The full [`GharsError`] chain for the same action is
    /// preserved on [`ApplyResult::failed`] for callers that need
    /// the typed error (programmatic consumers, exit-code mapping,
    /// rollback advisories). `cmd_apply` renders the row to stderr
    /// to keep the stdout/stderr split.
    Failed {
        /// Display string of the underlying [`GharsError`] (the
        /// inner `source` of the wrapping `GharsError::Apply`),
        /// captured at error-construction time. The wrapping
        /// `Apply` variant's `action` field would re-include the
        /// label that already appears in the
        /// `(label, ApplyOutcome)` tuple, so we render only the
        /// inner cause here to avoid duplication.
        ///
        /// Pre-sanitized at construction via
        /// [`crate::escape_control_chars`] so ANSI escape sequences
        /// or other C0/DEL bytes inside `GharsError::to_string()`
        /// can never reach the operator's terminal raw — see the
        /// two construction sites in `apply()` (per-action loop and
        /// post-loop `daemon_reload` synthesis). For the unsanitized
        /// original bytes (typed [`GharsError`] chain), consult the
        /// corresponding [`ApplyResult::failed`] entry — `failed[i]`
        /// and the i-th `Failed` row in `details` carry the same
        /// label, so a programmatic consumer can join them by label.
        error_summary: String,
        /// Plan-time worst-case [`crate::plan::Disruption`] for the
        /// failed action, plumbed through from `Action::disruption`
        /// at apply time. Returned by [`Self::disruption`] so the
        /// `[recreate]`/`[restart]`/`[none]` bracket tag on the
        /// `fail:` row matches the same vocabulary as plan output.
        ///
        /// For synthetic post-loop steps like `daemon_reload`,
        /// `plan_disruption` is [`crate::plan::Disruption::None`]
        /// because no `Action` exists to derive it from — the
        /// value is hand-set at the push site (see the
        /// `daemon_reload` synthesis branch in `apply()` after
        /// the per-action loop). `Manager.Reload` is a cache
        /// flush of systemd's in-memory unit-file index with no
        /// operator-visible unit transitions, so the `[none]`
        /// bracket tag accurately reports its (zero) blast
        /// radius.
        plan_disruption: crate::plan::Disruption,
    },
}

/// Append the `(added: ...; removed: ...)` pool-diff suffix to a
/// detail string. Used by both [`ApplyOutcome::InPlaceRestarted`] and
/// [`ApplyOutcome::InPlaceRewroteNoRestart`] — same operator-facing
/// suffix shape, same input-Vec semantics (BTreeSet-difference-sorted
/// pool names from `execute_update_runner` in-place caches diff).
///
/// Suffix shape:
///   no group ops:                 (no parenthetical, no-op)
///   added only:                   (added: a, b)
///   removed only:                 (removed: x, y)
///   both:                         (added: a, b; removed: x, y)
///
/// Pool names inside each comma-separated list are already sorted
/// at the construction site (`BTreeSet` difference order in
/// `execute_update_runner`). The semicolon between added/removed
/// groups distinguishes them from intra-group commas without
/// quoting.
fn append_pools_tail(s: &mut String, pools_added: &[String], pools_removed: &[String]) {
    if !pools_added.is_empty() && !pools_removed.is_empty() {
        s.push_str(&format!(
            " (added: {}; removed: {})",
            pools_added.join(", "),
            pools_removed.join(", "),
        ));
    } else if !pools_added.is_empty() {
        s.push_str(&format!(" (added: {})", pools_added.join(", ")));
    } else if !pools_removed.is_empty() {
        s.push_str(&format!(" (removed: {})", pools_removed.join(", ")));
    }
}

impl ApplyOutcome {
    /// Compact human-readable detail string for `cmd_apply`'s per-action
    /// `ok: LABEL (...)` line. The label vocabulary is stable —
    /// downstream operators may grep on these tokens. Mirrors the
    /// per-variant doc-comments above.
    #[must_use]
    pub fn detail(&self) -> String {
        match self {
            Self::InPlaceSkipped => "noop (bytes match)".into(),
            Self::InPlaceRestarted {
                files_changed,
                pools_added,
                pools_removed,
            } => {
                let group_ops = pools_added.len() + pools_removed.len();
                let mut s =
                    format!("in-place: {files_changed} file(s) changed, {group_ops} group op(s)");
                // Surface pool names when the caches-list diff was
                // non-empty so the operator sees WHICH pools moved.
                // Suffix shape + sort-order rationale documented on
                // the helper.
                append_pools_tail(&mut s, pools_added, pools_removed);
                s
            }
            Self::InPlaceRewroteNoRestart {
                name,
                files_changed,
                pools_added,
                pools_removed,
            } => {
                let group_ops = pools_added.len() + pools_removed.len();
                let mut s = format!(
                    "in-place: {files_changed} file(s) changed, {group_ops} group op(s), restart deferred (--no-restart): run `systemctl restart ghars-runner@{name}.service` to complete the rollout"
                );
                append_pools_tail(&mut s, pools_added, pools_removed);
                s
            }
            Self::Recreated => "recreated (deregister + teardown + register + start)".into(),
            Self::Created => "created (GitHub registration + unit start)".into(),
            Self::Removed => "removed (GitHub deregister + unit + home)".into(),
            Self::PoolCreated => "pool created (storage + unit)".into(),
            Self::PoolUpdated => "pool updated (drop-in rewrite + restart)".into(),
            Self::PoolRewroteNoRestart { name, files_changed } => format!(
                "pool: {files_changed} file(s) changed, restart deferred (--no-restart): run `systemctl restart ghars-cache@{name}.service` to complete the rollout"
            ),
            Self::PoolSkipped => "pool noop (drop-in bytes match)".into(),
            Self::PoolRemoved => "pool removed (storage + drop-in)".into(),
            Self::NoOp => "noop (in sync)".into(),
            Self::DryRunSkipped => "dry-run (skipped)".into(),
            Self::Failed { error_summary, .. } => error_summary.clone(),
        }
    }

    /// One-token outcome summary written into the SEC-36 audit log
    /// `outcome` field. Strictly terser than [`Self::detail`] —
    /// downstream consumers (jq pipelines, ELK ingestion) filter
    /// on these tokens. Vocabulary is closed:
    ///
    /// - `"success"` for any successful execution variant
    ///   (Created, Removed, Recreated, `PoolCreated`, `PoolUpdated`,
    ///   `PoolRemoved`, `InPlaceRestarted`)
    /// - `"deferred-restart"` for `--no-restart` opt-out variants
    ///   (`InPlaceRewroteNoRestart`, `PoolRewroteNoRestart`); distinct
    ///   from `"success"` so SOC/SRE tooling can grep for runners /
    ///   pools that need follow-up manual restart.
    /// - `"in-sync"` for byte-equality short-circuits
    ///   (`InPlaceSkipped`, `PoolSkipped`)
    /// - `"noop"` for [`Self::NoOp`] (planner emitted in-sync rows)
    /// - `"dry-run"` for [`Self::DryRunSkipped`]
    /// - The full sanitized error string for [`Self::Failed`]
    ///   (already control-char-escaped at construction)
    ///
    /// `Failed` is intentionally NOT collapsed to `"failed"` because
    /// the audit consumer needs the diagnostic to triage without
    /// re-correlating against the runtime stderr.
    #[must_use]
    pub fn audit_summary(&self) -> String {
        match self {
            Self::Created
            | Self::Removed
            | Self::Recreated
            | Self::PoolCreated
            | Self::PoolUpdated
            | Self::PoolRemoved
            | Self::InPlaceRestarted { .. } => "success".into(),
            Self::InPlaceRewroteNoRestart { .. } | Self::PoolRewroteNoRestart { .. } => {
                "deferred-restart".into()
            }
            Self::InPlaceSkipped | Self::PoolSkipped => "in-sync".into(),
            Self::NoOp => "noop".into(),
            Self::DryRunSkipped => "dry-run".into(),
            Self::Failed { error_summary, .. } => error_summary.clone(),
        }
    }

    /// Worst-case [`crate::plan::Disruption`] this outcome inflicts.
    /// Mirrors the plan-time mapping at
    /// [`crate::plan::Action::disruption`] so `cmd_apply` can render
    /// the same `[restart]` / `[recreate]` / `[none]` bracket tag
    /// the plan output uses. Operator grep on
    /// `[recreate]` in apply output now matches the same vocabulary
    /// as plan output.
    ///
    /// Mapping:
    /// - [`Self::InPlaceSkipped`] → `None` (apply-time short-circuit
    ///   reached: no host mutation actually happened)
    /// - [`Self::InPlaceRestarted`] → `Restart` (daemon-reload +
    ///   stop+start fired; matches plan-time `Restart` for in-place
    ///   `UpdateRunner`)
    /// - [`Self::InPlaceRewroteNoRestart`] → `None` (the file rewrites
    ///   happened on disk but the unit lifecycle was untouched per
    ///   `--no-restart`; the running process kept its pre-rewrite
    ///   loaded config so apply-time blast-radius is zero. Operator's
    ///   plan output would have shown `[restart]` because plan can't
    ///   predict the flag — the bracket-tag asymmetry is intentional
    ///   and analogous to the `InPlaceSkipped` plan-vs-apply gap.)
    /// - [`Self::PoolRewroteNoRestart`] → `None` (symmetric with
    ///   `InPlaceRewroteNoRestart` for the pool side)
    /// - [`Self::PoolUpdated`] → `Restart` (matches plan-time
    ///   `UpdateCachePool` mapping)
    /// - [`Self::PoolSkipped`] → `None` (apply-time short-circuit
    ///   reached on the pool-update path: drop-in bytes matched, no
    ///   host mutation actually happened. Symmetric with
    ///   `InPlaceSkipped` for the runner-update path.)
    /// - [`Self::Recreated`] / [`Self::Created`] / [`Self::Removed`]
    ///   / [`Self::PoolCreated`] / [`Self::PoolRemoved`] → `Recreate`
    ///   (full host-state lifecycle change)
    /// - [`Self::NoOp`] → `None`
    /// - [`Self::DryRunSkipped`] → `None` (no host mutation
    ///   happened; the would-have-been Disruption is NOT recorded —
    ///   the operator's reference is the bracket tag from plan
    ///   output, where `action.disruption()` is plan-knowable.
    ///   Returning `None` here truthfully reports apply-time impact.)
    /// - [`Self::Failed`] → the action's plan-time worst-case
    ///   `Disruption`, plumbed through `plan_disruption`. Apply-time
    ///   actual disruption is unknown (the handler returned `Err`
    ///   mid-execution; partial mutation is per-handler-specific),
    ///   so we report the plan-time bound to keep the bracket-tag
    ///   vocabulary consistent across plan and apply surfaces.
    #[must_use]
    pub fn disruption(&self) -> crate::plan::Disruption {
        match self {
            Self::InPlaceSkipped
            | Self::PoolSkipped
            | Self::InPlaceRewroteNoRestart { .. }
            | Self::PoolRewroteNoRestart { .. }
            | Self::NoOp
            | Self::DryRunSkipped => crate::plan::Disruption::None,
            Self::InPlaceRestarted { .. } | Self::PoolUpdated => crate::plan::Disruption::Restart,
            Self::Recreated
            | Self::Created
            | Self::Removed
            | Self::PoolCreated
            | Self::PoolRemoved => crate::plan::Disruption::Recreate,
            Self::Failed {
                plan_disruption, ..
            } => *plan_disruption,
        }
    }
}

/// Per-run outcome summary. Populated regardless of whether `apply`
/// returned `Ok` or `Err` — even on early-out the partial picture is
/// preserved so the CLI can render it.
#[derive(Debug, Default)]
#[non_exhaustive]
pub struct ApplyResult {
    /// Action labels that succeeded (`Action::label()`). See
    /// [`Self::details`] for the unified per-action rendering source.
    pub succeeded: Vec<String>,
    /// `(label, error)` pairs for actions that failed. See
    /// [`Self::details`] for the unified per-action rendering source;
    /// this Vec retains the typed [`GharsError`] chain for
    /// programmatic consumers.
    pub failed: Vec<(String, GharsError)>,
    /// Action labels that were not executed (e.g. `Action::NoOp`
    /// variants and dry-run-skipped actions; `fail_fast` short-circuit
    /// leaves later actions absent from ALL Vecs — they were never
    /// processed). See [`Self::details`] for the unified per-action
    /// rendering source.
    pub skipped: Vec<String>,
    /// `(label, outcome)` rows in execution order — one entry per
    /// action processed by the apply loop (including `NoOp`,
    /// dry-run-skipped, AND failed). "Execution order" because the
    /// loop walks the post-`sort_into_phases` slice (Part 8 phase
    /// order: `CreateCachePool` → `UpdateCachePool` → `RemoveRunner` →
    /// `UpdateRunner` → `CreateRunner` → `RemoveCachePool`), NOT plan-emit
    /// order. Actions that the loop never reached (`fail_fast`
    /// short-circuit) are absent from this Vec — they were not
    /// processed.
    ///
    /// Failed actions appear here as
    /// [`ApplyOutcome::Failed { error_summary, plan_disruption }`]
    /// rows alongside their successful / skipped peers that were
    /// processed. The full [`GharsError`] chain for the same
    /// action is also preserved on [`Self::failed`] for programmatic
    /// consumers (typed-error access, exit-code mapping). `cmd_apply`
    /// walks `details` to render every processed action's row
    /// uniformly; success rows go to stdout (`ok: LABEL ...`),
    /// failure rows go to stderr (`fail: LABEL ...`) so the
    /// stdout/stderr grep split is preserved. `NoOp` actions render as
    /// `noop: REASON [none]` on stdout (not `ok: LABEL`) — the
    /// label already carries `NoOp(REASON)`, so the verbose form
    /// would double-tag the reason. Additive alongside the existing
    /// Vecs so older programmatic consumers compile unchanged.
    pub details: Vec<(String, ApplyOutcome)>,
    /// `(label, recorded_steps)` rows — one entry per failed action,
    /// carrying the [`super::undo::UndoLog`]'s recorded mutations in insertion
    /// order (the per-action mutation manifest). `cmd_apply` walks
    /// these to render the rollback-state advisory on stderr,
    /// telling the operator what happened on disk before the action
    /// errored. Empty Vec for actions that errored before recording
    /// any step — and for the synthetic `daemon_reload` post-loop
    /// failure, which has no per-action `UndoLog` (the error is
    /// emitted after every action's `UndoLog` is dropped).
    ///
    /// Additive alongside [`Self::failed`] so older consumers
    /// compile unchanged. The ordering invariant is preserved:
    /// `failed[i].0 == failed_undo_logs[i].0` for every `i`. The
    /// advisory rendering is policy-only — apply layer is data-only,
    /// rendering lives in `cli::cmd_apply` per layering.
    pub failed_undo_logs: Vec<(String, Vec<UndoStep>)>,
}

impl ApplyResult {
    /// True ⇔ no action failed. `NoOp` / dry-run skipped do not count.
    #[must_use]
    pub fn ok(&self) -> bool {
        self.failed.is_empty()
    }
}
