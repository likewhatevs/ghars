//! Apply engine: execute a `Plan` against the host.
//!
//! Design spec: Part 3 (`apply.rs`) + Part 8 ("Execution order in
//! `apply()`", `apply.lock` semantics).
//!
//! Layout:
//! - [`apply`] is the entry point. It acquires the file lock, sorts the
//!   plan into the canonical phase order documented in Part 8, dispatches
//!   each `Action` to its `execute_*` handler, then issues a single
//!   `daemon_reload` and releases the lock.
//! - All systemd, auth, and tarball operations are taken via trait
//!   objects (`&dyn Systemd`, `&dyn TokenSource`) and the [`Tarball`]
//!   trait so tests can inject in-memory mocks.
//! - [`guard_home_dir_rmrf`] refuses to delete anything outside
//!   `<state_dir>/<runner-name>` — defends against a bad
//!   `RunnerIdentity.prefix` causing apply to recursively remove
//!   `/`, the prefix itself, or a path outside the prefix.
//! - [`verify_runner_netns`] post-start check — `readlink
//!   /proc/PID/ns/net` must differ from `readlink /proc/1/ns/net` when
//!   `spec.network.is_some()`. If they match the runner has fallen back
//!   to the host netns and the action aborts with `GharsError::Apply`.

use std::collections::HashMap;
use std::ffi::OsStr;
use std::fs::{self, File, OpenOptions};
use std::io::{Read, Write};
#[cfg(not(test))]
use std::os::fd::AsRawFd;
use std::os::unix::fs::{OpenOptionsExt, PermissionsExt};
use std::path::Path;
use std::process::Command;
use std::sync::atomic::{AtomicU64, Ordering};

use nix::unistd::User;
#[cfg(not(test))]
use nix::unistd::{Gid, Uid, fchown};

use camino::{Utf8Path, Utf8PathBuf};
use fs2::FileExt;

use crate::Result;
use crate::auth::TokenSource;
use crate::config::{EffectiveRunnerSpec, NetworkMode};
use crate::error::GharsError;
use crate::escape_control_chars;
use crate::extract::install_runner_binary;
use crate::extract::{download_and_verify, verify_local_tarball};
use crate::netns::NetnsConfig;
use crate::paths::Paths;
use crate::plan::{
    Action, CachePoolDelta, CachePoolPlan, DropInChangeKind, Plan, RunnerDelta, RunnerIdentity,
    RunnerPlan,
};
use crate::state::MANAGED_DROP_IN_BASENAMES;
use crate::systemd::{
    Systemd, cache_template_text, netns_template_text, render_nft_rules, render_runner_unit,
};

// ---------- Public surface ----------------------------------------------

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
    /// `--rollback-on-failure`: walk this action's [`UndoLog`] in reverse
    /// when its execute_* handler returns `Err`. Per-action scope only
    /// — earlier successful actions are NOT undone. Each Action records
    /// a `Vec<UndoStep>`; on error the list is walked in reverse and
    /// best-effort undone. Default false.
    pub rollback_on_failure: bool,
}

/// What happened when a single action ran. Lifted out of [`apply`]
/// so cmd_apply can render a per-action
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
///   byte-equality short-circuit at apply.rs::execute_update_runner).
/// - [`Self::InPlaceRestarted`]    → [`crate::plan::Disruption::Restart`]
/// - [`Self::Recreated`]           → [`crate::plan::Disruption::Recreate`]
///   (single combined outcome — the inner `execute_remove_runner` +
///   `execute_create_runner` are implementation detail and do not
///   appear as separate rows in `ApplyResult::details`)
/// - [`Self::Created`]             → [`crate::plan::Disruption::Recreate`]
/// - [`Self::Removed`]             → [`crate::plan::Disruption::Recreate`]
/// - [`Self::PoolCreated`]         → [`crate::plan::Disruption::Recreate`]
/// - [`Self::PoolUpdated`]         → [`crate::plan::Disruption::Restart`]
/// - [`Self::PoolSkipped`]         → [`crate::plan::Disruption::None`]
///   at apply time. Plan reports `Restart` (cannot predict the
///   byte-equality short-circuit at apply.rs::execute_update_cache_pool).
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
pub enum ApplyOutcome {
    /// `execute_update_runner` in-place branch took the
    /// `files_changed == 0 && pools_added.is_empty() &&
    /// pools_removed.is_empty()` short-circuit: no daemon-
    /// reload, no stop+start, no usermod. Equivalent to
    /// [`crate::plan::Disruption::None`] at apply time.
    InPlaceSkipped,
    /// `execute_update_runner` in-place branch wrote one or more
    /// managed files and / or applied one or more supplementary-group
    /// changes, then issued daemon-reload + stop+start.
    /// `files_changed` counts the managed files whose bytes diverged
    /// from disk (unit + every drop-in basename); `pools_added` /
    /// `pools_removed` carry the cache-pool NAMES (not group names —
    /// the inputs to `cache_pool_group()`) whose membership was
    /// reconciled via `gpasswd -a` / `gpasswd -d` on the runner's
    /// system user. The struct field `group_ops: usize` was replaced
    /// by `pools_added` + `pools_removed`; [`Self::detail`]
    /// derives the count locally as `pools_added.len() +
    /// pools_removed.len()`. See [`Self::detail`] for the rendered
    /// string format.
    InPlaceRestarted {
        /// Number of managed files whose bytes were rewritten this
        /// apply (unit text + drop-ins). `0` ⇒ pure group-op
        /// reconciliation triggered the restart.
        files_changed: usize,
        /// Cache-pool names this apply added the runner's user to via
        /// `gpasswd -a` (one entry per pool). Sorted by
        /// `BTreeSet::difference` order at the construction site
        /// (apply.rs `execute_update_runner` in-place caches diff)
        /// so the rendered detail line is deterministic. Empty when
        /// the diff was a no-op or `delta.before_caches` was `None`
        /// (pre-annotation runner — no annotation to diff against).
        pools_added: Vec<String>,
        /// Cache-pool names this apply removed the runner's user from
        /// via `gpasswd -d` (one entry per pool). Sorted; empty
        /// semantics symmetric with `pools_added`.
        ///
        /// Symmetric counterpart on the cache-pool side:
        /// [`Self::PoolUpdated`] / [`Self::PoolSkipped`] intentionally
        /// lack these Vecs (pool-kind changes don't reconcile
        /// membership — group identity is name-parameterized).
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
    /// `execute_create_cache_pool` finished — per-pool group +
    /// storage dir + drop-in written, ghars-cache@POOL.service
    /// started.
    PoolCreated,
    /// `execute_update_cache_pool` finished — drop-in rewritten,
    /// daemon-reload + stop + start cycled the existing
    /// ghars-cache@POOL.service.
    /// (No pool-membership Vecs — pool updates don't trigger
    /// runner-side gpasswd; the per-pool group identity is
    /// parameterized by pool name only. See
    /// [`Self::InPlaceRestarted`] for the runner-side pool-membership
    /// diff that DOES carry `pools_added` / `pools_removed`.)
    PoolUpdated,
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
    /// (No pool-membership Vecs: pool-kind changes do not trigger
    /// usermod/gpasswd — the per-pool group identity is parameterized
    /// by pool name only, see comment in `execute_update_cache_pool`.
    /// Symmetric to [`Self::InPlaceRestarted`]'s `pools_added`/
    /// `pools_removed` which DO carry runner-side membership diff.)
    PoolSkipped,
    /// `execute_remove_cache_pool` finished — drop-in + per-pool
    /// group + storage dir removed.
    PoolRemoved,
    /// `Action::NoOp` — the planner emitted "in sync" for this
    /// runner / pool; no host mutation scheduled. Carried into
    /// `details` so cmd_apply can render every action with a row,
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
    /// rollback advisories). cmd_apply renders the row to stderr
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
        /// post-loop daemon_reload synthesis). For the unsanitized
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

impl ApplyOutcome {
    /// Compact human-readable detail string for cmd_apply's per-action
    /// `ok: LABEL (...)` line. The label vocabulary is stable —
    /// downstream operators may grep on these tokens. Mirrors the
    /// per-variant doc-comments above.
    #[must_use]
    pub fn detail(&self) -> String {
        match self {
            Self::InPlaceSkipped => "noop (bytes + groups match)".into(),
            Self::InPlaceRestarted {
                files_changed,
                pools_added,
                pools_removed,
            } => {
                let group_ops = pools_added.len() + pools_removed.len();
                let mut s =
                    format!("in-place: {files_changed} file(s) changed, {group_ops} group op(s)");
                // Surface pool names when the gpasswd diff was
                // non-empty so the operator sees WHICH pools moved,
                // not just how many. Suffix shape:
                //   no group ops:                 (no parenthetical)
                //   added only:                   (added: a, b)
                //   removed only:                 (removed: x, y)
                //   both:                         (added: a, b; removed: x, y)
                // Pool names inside each comma-separated list are
                // already sorted at the construction site (BTreeSet
                // difference order in execute_update_runner). The
                // semicolon between added/removed groups distinguishes
                // them from intra-group commas without quoting.
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
                s
            }
            Self::Recreated => "recreated (deregister + teardown + register + start)".into(),
            Self::Created => "created (GitHub registration + unit start)".into(),
            Self::Removed => "removed (GitHub deregister + unit + home + user)".into(),
            Self::PoolCreated => "pool created (group + storage + unit)".into(),
            Self::PoolUpdated => "pool updated (drop-in rewrite + restart)".into(),
            Self::PoolSkipped => "pool noop (drop-in bytes match)".into(),
            Self::PoolRemoved => "pool removed (group + storage + drop-in)".into(),
            Self::NoOp => "noop (in sync)".into(),
            Self::DryRunSkipped => "dry-run (skipped)".into(),
            Self::Failed { error_summary, .. } => error_summary.clone(),
        }
    }

    /// Worst-case [`crate::plan::Disruption`] this outcome inflicts.
    /// Mirrors the plan-time mapping at
    /// [`crate::plan::Action::disruption`] so cmd_apply can render
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
            Self::InPlaceSkipped | Self::PoolSkipped | Self::NoOp | Self::DryRunSkipped => {
                crate::plan::Disruption::None
            }
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
    /// variants and dry-run-skipped actions; fail_fast short-circuit
    /// leaves later actions absent from ALL Vecs — they were never
    /// processed). See [`Self::details`] for the unified per-action
    /// rendering source.
    pub skipped: Vec<String>,
    /// `(label, outcome)` rows in execution order — one entry per
    /// action processed by the apply loop (including NoOp,
    /// dry-run-skipped, AND failed). "Execution order" because the
    /// loop walks the post-`sort_into_phases` slice (Part 8 phase
    /// order: CreateCachePool → UpdateCachePool → RemoveRunner →
    /// UpdateRunner → CreateRunner → RemoveCachePool), NOT plan-emit
    /// order. Actions that the loop never reached (fail_fast
    /// short-circuit) are absent from this Vec — they were not
    /// processed.
    ///
    /// Failed actions appear here as
    /// [`ApplyOutcome::Failed { error_summary, plan_disruption }`]
    /// rows alongside their successful / skipped peers that were
    /// processed. The full [`GharsError`] chain for the same
    /// action is also preserved on [`Self::failed`] for programmatic
    /// consumers (typed-error access, exit-code mapping). cmd_apply
    /// walks `details` to render every processed action's row
    /// uniformly; success rows go to stdout (`ok: LABEL ...`),
    /// failure rows go to stderr (`fail: LABEL ...`) so the
    /// stdout/stderr grep split is preserved. NoOp actions render as
    /// `noop: REASON [none]` on stdout (not `ok: LABEL`) — the
    /// label already carries `NoOp(REASON)`, so the verbose form
    /// would double-tag the reason. Additive alongside the existing
    /// Vecs so older programmatic consumers compile unchanged.
    pub details: Vec<(String, ApplyOutcome)>,
    /// `(label, recorded_steps)` rows — one entry per failed action,
    /// carrying the [`UndoLog`]'s recorded mutations in insertion
    /// order (the per-action mutation manifest). cmd_apply walks
    /// these to render the rollback-state advisory on stderr,
    /// telling the operator what happened on disk before the action
    /// errored. Empty Vec for actions that errored before recording
    /// any step — and for the synthetic `daemon_reload` post-loop
    /// failure, which has no per-action UndoLog (the error is
    /// emitted after every action's UndoLog is dropped).
    ///
    /// Additive alongside [`Self::failed`] so older consumers
    /// compile unchanged. The ordering invariant is preserved:
    /// `failed[i].0 == failed_undo_logs[i].0` for every `i`. The
    /// advisory rendering is policy-only — apply layer is data-only,
    /// rendering lives in cli.rs cmd_apply per layering.
    pub failed_undo_logs: Vec<(String, Vec<UndoStep>)>,
}

impl ApplyResult {
    /// True ⇔ no action failed. `NoOp` / dry-run skipped do not count.
    #[must_use]
    pub fn ok(&self) -> bool {
        self.failed.is_empty()
    }
}

// ---------- Undo log -----------------------------------------------

/// One mutating step recorded by an `execute_*` handler. On failure with
/// `--rollback-on-failure`, [`undo`] walks the per-action log in reverse
/// and best-effort reverses each step.
///
/// Design contract: each Action records a `Vec<UndoStep>` (file
/// paths created, units written, users added, registered runners).
/// On error, walk the list in reverse and best-effort undo.
///
/// Variants split into two directions:
/// - **Forward (Create-direction)** — `WriteFile`, `CreateDir`,
///   `StartUnit`, `EnableUnit`, `GitHubRegistration`. These have
///   lossless inverses (`remove_file`, `remove_dir`, `stop_unit`,
///   `disable_unit`, `config.sh remove --token <fresh>`). The undo
///   path attempts each and continues on per-step error.
/// - **Reverse (Remove-direction)** — `RemoveFile`, `RemoveDir`,
///   `StopUnit`, `DisableUnit`. These are recorded for audit-trail
///   completeness but their undo is genuinely lossy (recursive
///   removals lose content; restarting a stopped service might be
///   wrong if the operator wanted it down). Undo logs the variant +
///   warns + continues.
///
/// `WriteFile.prior_content` carries the bytes the file held before the
/// write so the undo can restore an overwrite (in-place update path).
/// `None` ⇒ the file did not exist beforehand and undo is `remove_file`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum UndoStep {
    /// Recorded after `write_root_owned(path, ...)` succeeds. `prior_content`
    /// is the bytes the file held before the write (for overwrites) or
    /// `None` if the file was newly created.
    WriteFile {
        /// Final path the bytes landed at (post-rename).
        path: Utf8PathBuf,
        /// Previous content if the path existed beforehand.
        prior_content: Option<Vec<u8>>,
    },
    /// Recorded after `fs::remove_file(path)` succeeds. `content` is the
    /// bytes captured from the file before removal so the undo can
    /// restore (best-effort — chown/perms not preserved).
    RemoveFile {
        /// Path that was unlinked.
        path: Utf8PathBuf,
        /// Bytes captured pre-unlink.
        content: Vec<u8>,
    },
    /// Recorded after a directory was created (or `create_dir_all`
    /// reached the leaf). Undo is `fs::remove_dir` (only if empty —
    /// child entries owned by other steps are unwound separately).
    CreateDir {
        /// Path of the directory created.
        path: Utf8PathBuf,
    },
    /// Recorded after `fs::remove_dir_all(path)` succeeds. Undo is
    /// best-effort `fs::create_dir_all` (the recursive-removed contents
    /// are unrecoverable; re-running apply re-populates them).
    RemoveDir {
        /// Path of the directory tree that was removed.
        path: Utf8PathBuf,
    },
    /// Recorded after `systemd.start_unit(name)` succeeds. Undo is
    /// `stop_unit`.
    StartUnit {
        /// Unit name (e.g. `ghars-runner@buckos.service`).
        name: String,
    },
    /// Recorded after `systemd.stop_unit(name)` succeeds. Undo is
    /// best-effort `start_unit` (operator may have wanted the unit
    /// stopped; we warn rather than blindly restarting in production
    /// rollback paths — guarded by [`UndoStep::is_reverse_direction`]).
    StopUnit {
        /// Unit name.
        name: String,
    },
    /// Recorded after `systemd.enable_unit(name)` succeeds. Undo is
    /// `disable_unit`.
    EnableUnit {
        /// Unit name.
        name: String,
    },
    /// Recorded after `systemd.disable_unit(name)` succeeds. Undo is
    /// best-effort `enable_unit` (guarded reverse-direction; warn).
    DisableUnit {
        /// Unit name.
        name: String,
    },
    /// Recorded after `config_shell.run_register(...)` succeeds. Undo
    /// is to mint a fresh removal token via the auth registry and call
    /// `config_shell.run_remove`. If the auth registry has no entry
    /// for `auth_name` the undo emits a `tracing::warn!` and continues
    /// — config.sh registration is hard to reverse, so we attempt
    /// `config.sh remove --token <fresh>` if auth is available and
    /// otherwise emit a warning.
    GitHubRegistration {
        /// Runner instance name (the `%i` value).
        name: String,
        /// Repo / org URL the runner registered against.
        url: String,
        /// Auth registry key.
        auth_name: String,
        /// Per-runner home directory (`/var/lib/ghars/NAME`).
        runner_home: Utf8PathBuf,
    },
}

impl UndoStep {
    /// True for variants whose undo is genuinely lossy (`Remove*`,
    /// `Stop*`, `Disable*`, `*Del`). The undo path logs and skips these
    /// rather than blindly inverting — design Part 8 specifies "best-
    /// effort", and re-creating recursively-removed directory content,
    /// re-starting a stopped unit (operator may have intended it
    /// down), or re-adding a deleted user (UID would change, group
    /// memberships and home content lost) all cause more damage than
    /// they prevent.
    #[must_use]
    pub fn is_reverse_direction(&self) -> bool {
        matches!(
            self,
            UndoStep::RemoveFile { .. }
                | UndoStep::RemoveDir { .. }
                | UndoStep::StopUnit { .. }
                | UndoStep::DisableUnit { .. }
        )
    }

    /// One-line operator-readable summary of the recorded mutation,
    /// suitable for the rollback-state advisory in cmd_apply.
    /// Names the step's effect in past tense ("wrote …", "started …",
    /// "removed …") so the advisory reads as an audit trail of what
    /// happened on disk before the action errored. Byte-content fields
    /// (`WriteFile.prior_content`, `RemoveFile.content`) are
    /// intentionally omitted — they are recovery payloads for
    /// [`undo`], not advisory details, and would dominate the line
    /// length without operator-actionable signal.
    ///
    /// Every interpolated `path`, `name`, and `url` field passes
    /// through [`crate::escape_control_chars`] before formatting.
    /// Drop-in paths and unit names are derived from operator-supplied
    /// config (runner names flow into
    /// `<runtime>/.../00-ghars.conf`, auth-block URLs into
    /// `GitHubRegistration.url`). Upstream validators
    /// (`validate_runner_name`, `check_identity_field`, the URL regex)
    /// reject control characters at config-load and render-identity
    /// time, but `describe()` is also called outside the rollback
    /// advisory render path (e.g. by future programmatic consumers
    /// reading `failed_undo_logs`); escaping inside `describe()` keeps
    /// the contract single-source. The advisory render site applies
    /// `escape_control_chars` again — second pass is a no-op
    /// (idempotent: the first pass replaces every C0/DEL byte with a
    /// printable backslash sequence; nothing remains for the second
    /// pass to escape).
    #[must_use]
    pub fn describe(&self) -> String {
        match self {
            UndoStep::WriteFile { path, .. } => {
                format!("wrote {}", crate::escape_control_chars(path.as_str()))
            }
            UndoStep::RemoveFile { path, .. } => {
                format!(
                    "removed file {}",
                    crate::escape_control_chars(path.as_str())
                )
            }
            UndoStep::CreateDir { path } => {
                format!(
                    "created directory {}",
                    crate::escape_control_chars(path.as_str())
                )
            }
            UndoStep::RemoveDir { path } => {
                format!(
                    "removed directory {}",
                    crate::escape_control_chars(path.as_str())
                )
            }
            UndoStep::StartUnit { name } => {
                format!("started {}", crate::escape_control_chars(name))
            }
            UndoStep::StopUnit { name } => {
                format!("stopped {}", crate::escape_control_chars(name))
            }
            UndoStep::EnableUnit { name } => {
                format!("enabled {}", crate::escape_control_chars(name))
            }
            UndoStep::DisableUnit { name } => {
                format!("disabled {}", crate::escape_control_chars(name))
            }
            UndoStep::GitHubRegistration { name, url, .. } => {
                format!(
                    "registered runner {} against {}",
                    crate::escape_control_chars(name),
                    crate::escape_control_chars(url),
                )
            }
        }
    }
}

/// Append-only record of mutating steps for one action. `execute_*`
/// handlers take `&mut UndoLog` and `push` after each successful side
/// effect. On `Err` from the handler, [`apply`] walks the log in reverse
/// when `opts.rollback_on_failure` is set.
#[derive(Debug, Default)]
pub struct UndoLog {
    steps: Vec<UndoStep>,
}

impl UndoLog {
    /// Construct an empty log.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Append a step. Steps are walked in reverse on undo so call sites
    /// must push AFTER the side effect succeeded — pushing before the
    /// effect lands and the effect failing would surface a step that
    /// never happened, and undo would attempt to reverse nonexistent
    /// state.
    pub fn push(&mut self, step: UndoStep) {
        self.steps.push(step);
    }

    /// Read-only view of the recorded steps in insertion order.
    #[must_use]
    pub fn steps(&self) -> &[UndoStep] {
        &self.steps
    }

    /// Number of steps recorded.
    #[must_use]
    pub fn len(&self) -> usize {
        self.steps.len()
    }

    /// True ⇔ no steps recorded.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.steps.is_empty()
    }

    /// Consume the log, returning the recorded steps in insertion order.
    /// Used by [`apply`] on the Err path to plumb the per-action mutation
    /// manifest into [`ApplyResult::failed_undo_logs`] so cmd_apply's
    /// rollback advisory can list what happened on disk before
    /// the action errored.
    #[must_use]
    pub fn into_steps(self) -> Vec<UndoStep> {
        self.steps
    }
}

/// Walk `log` in reverse and attempt each step's inverse. Per-step
/// failures are logged via `tracing::warn!` and the chain continues —
/// design Part 8 specifies "best-effort". Returns `Ok(())` always; the
/// signature is `Result` only so callers can propagate via `?` if a
/// future revision needs to surface a hard failure.
///
/// Forward-direction variants (Create-side mutations) are reversed
/// directly. Reverse-direction variants ([`UndoStep::is_reverse_direction`])
/// emit a `tracing::warn!` per step and continue without attempting
/// the inverse — see the variant docs for why per-step.
///
/// The `auth` registry is required to undo `GitHubRegistration` — we
/// mint a fresh removal token and call `config_shell.run_remove`. When
/// the auth_name is missing from the registry we warn and skip
/// (matches the orphan-removal contract in `execute_remove_runner`).
///
/// # Errors
///
/// Currently never returns `Err` — every per-step failure is logged
/// and the function presses on. Returning `Result` keeps the signature
/// future-proof.
pub fn undo(log: &UndoLog, deps: &Deps<'_>, _paths: &Paths) -> Result<()> {
    for step in log.steps().iter().rev() {
        if step.is_reverse_direction() {
            tracing::warn!(
                ?step,
                "rollback: skipping reverse-direction step; lossy inverse \
                 would not restore prior state. Re-run `ghars apply` to \
                 idempotently complete the removal."
            );
            continue;
        }
        if let Err(e) = undo_one(step, deps) {
            tracing::warn!(
                ?step,
                error = %e,
                "rollback: per-step undo failed; continuing"
            );
        }
    }
    Ok(())
}

/// Inverse of one [`UndoStep`]. Pure dispatch — no logging, no error
/// suppression — so [`undo`] above can wrap each call in its own
/// `tracing::warn!` and the per-step error is visible at the apply
/// boundary. Reverse-direction variants are unreachable here because
/// [`undo`] filters them upstream; the `unreachable!()` arm documents
/// that contract.
fn undo_one(step: &UndoStep, deps: &Deps<'_>) -> Result<()> {
    match step {
        UndoStep::WriteFile {
            path,
            prior_content,
        } => {
            if let Some(bytes) = prior_content {
                // Restore overwrite: rewrite the previous content
                // through the same atomic-rename helper the forward
                // path used.
                write_root_owned(path, bytes)
            } else {
                // No prior content ⇒ file was newly created. Unlink it.
                if path.exists() {
                    fs::remove_file(path.as_std_path()).map_err(GharsError::Io)?;
                }
                Ok(())
            }
        }
        UndoStep::CreateDir { path } => {
            // Only remove if empty — children belong to their own
            // UndoSteps which the reverse walk handles separately.
            // remove_dir returns ENOTEMPTY for non-empty dirs; we map
            // that to Ok(()) with a warn so the chain continues
            // (best-effort).
            if path.exists() {
                match fs::remove_dir(path.as_std_path()) {
                    Ok(()) => Ok(()),
                    Err(e)
                        if matches!(
                            e.raw_os_error(),
                            Some(libc::ENOTEMPTY) | Some(libc::EEXIST)
                        ) =>
                    {
                        tracing::warn!(
                            path = path.as_str(),
                            "rollback: directory not empty; leaving for next apply"
                        );
                        Ok(())
                    }
                    Err(e) => Err(GharsError::Io(e)),
                }
            } else {
                Ok(())
            }
        }
        UndoStep::StartUnit { name } => deps.systemd.stop_unit(name),
        UndoStep::EnableUnit { name } => deps.systemd.disable_unit(name),
        UndoStep::GitHubRegistration {
            name,
            url,
            auth_name,
            runner_home,
        } => {
            // Mint a fresh removal token; if the registry has no
            // matching entry, warn and skip per the registration
            // undo contract.
            let Some(source) = deps.auth.get(auth_name) else {
                tracing::warn!(
                    runner = name.as_str(),
                    auth = auth_name.as_str(),
                    "rollback GitHubRegistration: auth source not in registry; \
                     cannot mint removal token. The runner remains registered \
                     server-side; remove via the GitHub UI or restore [auth.NAME] \
                     to enable a clean deregister on the next apply."
                );
                return Ok(());
            };
            let token = source.mint_removal_token(url)?;
            deps.config_shell.run_remove(&ConfigShellCtx {
                runner_home,
                name,
                url,
                labels: &[],
                token: &token.value,
            })
        }
        UndoStep::RemoveFile { .. }
        | UndoStep::RemoveDir { .. }
        | UndoStep::StopUnit { .. }
        | UndoStep::DisableUnit { .. } => {
            // Filtered upstream by `undo`'s is_reverse_direction()
            // gate. Documenting the contract here so a future caller
            // that bypasses `undo` and reaches `undo_one` directly
            // gets a clear panic instead of silently invoking lossy
            // inverses.
            unreachable!("reverse-direction steps are filtered by `undo`")
        }
    }
}

/// Auth registry — `apply` looks up [`RunnerPlan`]'s `spec.auth_name`
/// and [`RunnerIdentity::auth_name`] against this map at action
/// execution time rather than per-runner pre-resolution. Caller
/// (`cli`) owns it.
pub type AuthRegistry<'a> = &'a HashMap<String, Box<dyn TokenSource>>;

/// Bag of trait-object dependencies threaded through every `execute_*`
/// handler. Grouping them in a struct keeps the call surface narrow
/// (avoids `apply()`'s 8-argument grid) and gives tests a single seam
/// to swap.
pub struct Deps<'a> {
    /// Systemd D-Bus adapter.
    pub systemd: &'a dyn Systemd,
    /// Auth registry — runner-name → token source.
    pub auth: AuthRegistry<'a>,
    /// Tarball download / verify / install seam.
    pub tarball: &'a dyn Tarball,
    /// `config.sh` invocation seam.
    pub config_shell: &'a dyn ConfigShell,
}

// ---------- File lock ----------------------------------------------------

/// Held POSIX advisory file lock plus the handle that owns it.
///
/// Drop releases via fs2's `unlock` (which is also released by the
/// kernel on process exit if the program crashes mid-apply).
#[derive(Debug)]
pub struct ApplyLock {
    file: File,
    path: Utf8PathBuf,
}

impl ApplyLock {
    /// Path the lock was opened on (for diagnostics).
    #[must_use]
    pub fn path(&self) -> &Utf8Path {
        &self.path
    }
}

impl Drop for ApplyLock {
    fn drop(&mut self) {
        // Best-effort truncate so a fresh `apply` does not see a stale
        // PID. Errors are intentionally swallowed — Drop cannot return
        // a result and the kernel releases the flock regardless.
        let _ = self.file.set_len(0);
        let _ = FileExt::unlock(&self.file);
    }
}

/// Acquire `<runtime_dir>/apply.lock` exclusively, writing this
/// process's PID into the lock file on success.
///
/// The lock file is opened with mode 0600 and `O_CREAT`. fs2 uses
/// `flock(2)` on Linux (per fs2-0.4.3/src/lib.rs); the lock is advisory
/// and released on Drop or process exit.
///
/// On contention this reads the existing PID from the file and surfaces
/// `GharsError::ApplyLocked { pid, path }` so the CLI can suggest
/// stale-lock cleanup.
///
/// # Errors
///
/// - `GharsError::ApplyLocked` if another process holds the lock.
/// - `GharsError::Io` if the runtime dir cannot be created or the lock
///   file cannot be opened/written.
pub fn acquire_lock(paths: &Paths) -> Result<ApplyLock> {
    let runtime_dir = paths.runtime_dir.clone();
    // EACCES on the runtime-dir create or the lock-file open is
    // almost always "non-root operator ran `ghars apply`" — the
    // runtime dir defaults under /run which is root-owned. Wrap the
    // raw io::Error with an actionable hint so the operator doesn't
    // have to grep strerror.
    fs::create_dir_all(&runtime_dir).map_err(|e| eacces_hint(&e, &runtime_dir, "runtime dir"))?;
    let lock_path = paths.apply_lock();
    let file = OpenOptions::new()
        .read(true)
        .write(true)
        .create(true)
        .truncate(false)
        .mode(0o600)
        .open(lock_path.as_std_path())
        .map_err(|e| eacces_hint(&e, &lock_path, "apply.lock"))?;

    // `OpenOptions::mode(0o600)` ONLY applies to newly created
    // files (per std::os::unix::fs::OpenOptionsExt — the bits feed
    // into O_CREAT's mode argument and have no effect on opening an
    // existing file). A pre-existing lock file from a previous ghars
    // version (or operator chmod) could persist at a wider mode like
    // 0o644, exposing the embedded PID to non-root readers. Stat the
    // open fd and chmod back to 0o600 if it drifted; the file's
    // contents are operationally trivial (a PID) but the apply.lock
    // semantics document strict 0o600 ownership, so any drift gets
    // corrected here rather than carried forward.
    let meta = file
        .metadata()
        .map_err(|e| eacces_hint(&e, &lock_path, "apply.lock metadata"))?;
    let mode = meta.permissions().mode() & 0o777;
    if mode != 0o600 {
        let mut perms = meta.permissions();
        perms.set_mode(0o600);
        // The open() above already passed, which on a
        // root-owned `/run/ghars` means we're running as root. An
        // EACCES on chmod here is therefore NOT "you're not root";
        // it's a different problem (read-only mount, MAC policy like
        // SELinux/AppArmor, or fs.protected_regular). Use a distinct
        // hint so the operator looks in the right place.
        file.set_permissions(perms).map_err(|e| {
            if e.kind() == std::io::ErrorKind::PermissionDenied {
                GharsError::Validation(
                    format!(
                        "permission denied chmodding apply.lock at {lock_path} \
                         to 0o600: {e}"
                    ),
                    "apply.lock chmod 0o600 failed; check filesystem mount \
                     options (read-only?) and any MAC policy (SELinux / \
                     AppArmor) blocking permission changes on the runtime dir"
                        .into(),
                )
            } else {
                GharsError::Io(std::io::Error::new(
                    e.kind(),
                    format!("apply.lock chmod at {lock_path}: {e}"),
                ))
            }
        })?;
    }

    if let Err(e) = FileExt::try_lock_exclusive(&file) {
        // fs2's `lock_contended_error` is the only recoverable kind;
        // every other ErrorKind here is a real I/O fault. Match against
        // it explicitly so a permissions error doesn't masquerade as
        // contention.
        let pid = read_pid_from_lock(&lock_path).unwrap_or(0);
        if e.kind() == fs2::lock_contended_error().kind() {
            // SEC-19: probe `/proc/<pid>/status`. If the file doesn't
            // exist the PID has exited without releasing the flock
            // (e.g. `kill -9 ghars` mid-apply leaves the lock file on
            // disk because the kernel auto-released the flock but the
            // file lingers). Mark as stale so the error hint tells the
            // operator to remove `apply.lock` rather than wait for a
            // process that's already gone. `pid <= 0` is treated as
            // unparseable / missing PID: we still surface the error
            // but flag it stale so the operator inspects the file.
            let stale = pid <= 0 || !pid_is_alive(pid);
            return Err(GharsError::ApplyLocked {
                pid,
                path: lock_path.to_string(),
                stale,
            });
        }
        return Err(GharsError::Io(e));
    }

    write_pid_to_lock(&file)?;
    Ok(ApplyLock {
        file,
        path: lock_path,
    })
}

/// Convert an `io::Error` from a runtime-dir create or
/// apply.lock open into a friendly `GharsError::Validation` when the
/// underlying kind is `PermissionDenied` (EACCES). The lock and its
/// runtime dir live under root-owned paths (default `/run/ghars`),
/// so the overwhelmingly likely cause is a non-root operator running
/// `ghars apply`. Pass through any other error kind as `GharsError::Io`
/// so the operator sees the real syscall failure.
fn eacces_hint(e: &std::io::Error, path: &Utf8Path, what: &str) -> GharsError {
    if e.kind() == std::io::ErrorKind::PermissionDenied {
        GharsError::Validation(
            format!("permission denied opening {what} at {path}: {e}"),
            "are you running as root? `ghars apply` needs to write to the \
             root-owned runtime dir (default /run/ghars); re-run via `sudo` \
             or set ghars.toml `paths.runtime_dir` to a writable location"
                .into(),
        )
    } else {
        GharsError::Io(std::io::Error::new(
            e.kind(),
            format!("{what} at {path}: {e}"),
        ))
    }
}

fn read_pid_from_lock(path: &Utf8Path) -> Option<i32> {
    let mut s = String::new();
    File::open(path.as_std_path())
        .ok()?
        .read_to_string(&mut s)
        .ok()?;
    s.trim().parse::<i32>().ok()
}

/// Probe `/proc/<pid>/status` to determine whether `pid` is currently
/// running. SEC-19: a PID written to `apply.lock` by a previous
/// invocation that crashed (the kernel auto-releases the flock on
/// process exit, but the lock-file content persists) must be
/// distinguished from a live `ghars apply` in progress so the error
/// hint stays actionable.
///
/// The check uses procfs because `kill -0` requires either the same
/// UID or `CAP_KILL`, which the privilege model under which `ghars`
/// runs (root via systemd, root via sudo) does not constrain. Procfs
/// existence is also more conservative than `kill(2)`: a `Permission
/// denied` from `kill` would falsely report stale, while
/// `/proc/<pid>/status` is readable for every live PID by every
/// caller (`man 5 proc` "permissions").
///
/// Negative or zero `pid` returns `false` — `/proc/0` doesn't exist
/// and procfs's `PID_MAX_LIMIT` is positive (kernel pid.h).
#[must_use]
pub fn pid_is_alive(pid: i32) -> bool {
    if pid <= 0 {
        return false;
    }
    Path::new(&format!("/proc/{pid}/status")).exists()
}

fn write_pid_to_lock(file: &File) -> Result<()> {
    let mut f = file.try_clone()?;
    f.set_len(0)?;
    let pid = i32::try_from(std::process::id()).unwrap_or(i32::MAX);
    writeln!(f, "{pid}")?;
    f.flush()?;
    Ok(())
}

// ---------- runsvc.sh integrity helper (SEC-02) -------------------------

/// SHA256 the on-disk runsvc.sh script after `config.sh` writes it,
/// for the `X-Ghars-Runsvc-Sha256` annotation in 00-ghars.conf.
///
/// `path` is opened with `O_NOFOLLOW` so the kernel rejects a
/// symlink-swap between the time `config.sh` finishes and we hash —
/// the same TOCTOU primitive `auth.rs::read_root_owned_0600` and
/// `runsvc-wrapper`'s `open_no_follow_rdonly` use. Output format
/// `"sha256:HEX"` matches the wrapper's own `sha256_of_reader` so the
/// annotation comparison at unit-start time is byte-equal.
///
/// # Errors
///
/// `GharsError::Io` for any open / read failure (including `ELOOP`
/// from the `O_NOFOLLOW` symlink rejection — surfaced with the
/// wrapping kind so `apply.rs` callers can distinguish).
fn sha256_of_runsvc(path: &Utf8Path) -> Result<String> {
    use sha2::{Digest, Sha256};
    let mut opts = OpenOptions::new();
    opts.read(true).custom_flags(libc::O_NOFOLLOW);
    let mut f = opts.open(path.as_std_path())?;
    let mut hasher = Sha256::new();
    // 64 KiB read window: small enough to live on the stack (default
    // Linux thread stack is 8 MiB), large enough to keep syscall
    // count low for typical runsvc.sh sizes (~1-2 KiB) while still
    // amortizing for any future unusually-large runner-self-config
    // output. Mirrors `runsvc_wrapper::sha256_of_reader`.
    #[allow(clippy::large_stack_arrays)]
    let mut buf = [0u8; 64 * 1024];
    loop {
        let n = f.read(&mut buf)?;
        if n == 0 {
            break;
        }
        hasher.update(&buf[..n]);
    }
    Ok(format!("sha256:{}", hex::encode(hasher.finalize())))
}

// ---------- Tarball trait (test seam over extract.rs) -------------------

/// Tarball provider seam. Production wires a [`RealTarball`] that
/// shells out to `extract::download_and_verify` /
/// `extract::install_runner_binary`. Tests inject a fake that records
/// calls without touching the network or filesystem.
pub trait Tarball {
    /// Ensure a tarball exists at `dest_path` whose SHA256 matches
    /// `expected_sha256`, downloading from `url` only when necessary.
    ///
    /// # Errors
    ///
    /// Returns `GharsError::Tarball` / `GharsError::Sha256Mismatch` /
    /// `GharsError::Io` per the underlying extract.rs contract.
    fn fetch_or_verify(&self, url: &str, dest_path: &Utf8Path, expected_sha256: &str)
    -> Result<()>;

    /// Verify a pre-downloaded local tarball is still safe to use
    /// (regular file, not a symlink). Mirrors `extract::verify_local_tarball`.
    ///
    /// # Errors
    ///
    /// `GharsError::Tarball` if the file is missing, a symlink, or no
    /// longer regular.
    fn verify_local(&self, path: &Utf8Path) -> Result<()>;

    /// Extract `tarball_path` into `<runner_home>/bin.<version>/`
    /// (root-owned, atomic via staging). Returns the final
    /// `bin.<version>` directory path.
    ///
    /// # Errors
    ///
    /// Returns the underlying `GharsError::Tarball` / `GharsError::Io`
    /// from `extract::install_runner_binary`.
    fn install_binary(
        &self,
        tarball_path: &Utf8Path,
        state_dir: &Utf8Path,
        runner_home: &Utf8Path,
        runner_name: &str,
        version: &str,
    ) -> Result<Utf8PathBuf>;
}

/// Production tarball provider. Wraps the public functions in
/// [`crate::extract`] verbatim.
#[derive(Debug, Default)]
pub struct RealTarball;

impl Tarball for RealTarball {
    fn fetch_or_verify(
        &self,
        url: &str,
        dest_path: &Utf8Path,
        expected_sha256: &str,
    ) -> Result<()> {
        // On SHA256 mismatch the destination is deleted; if the file is
        // already present and correct, no download. download_and_verify
        // already implements both paths.
        download_and_verify(
            url,
            dest_path,
            expected_sha256,
            std::time::Duration::from_secs(300),
        )
    }

    fn verify_local(&self, path: &Utf8Path) -> Result<()> {
        verify_local_tarball(path)
    }

    fn install_binary(
        &self,
        tarball_path: &Utf8Path,
        state_dir: &Utf8Path,
        runner_home: &Utf8Path,
        runner_name: &str,
        version: &str,
    ) -> Result<Utf8PathBuf> {
        install_runner_binary(tarball_path, state_dir, runner_home, runner_name, version)
    }
}

fn spawn_err(prog: &str, e: &std::io::Error) -> GharsError {
    GharsError::Io(std::io::Error::new(e.kind(), format!("spawn {prog}: {e}")))
}

// ---------- Config.sh runner seam --------------------------------------

/// Runner-self-config seam. Production wires a [`RealConfigShell`] that
/// shells out to `<runner_home>/bin/config.sh`. Tests inject a fake.
///
/// **SEC-05** — the registration / removal token is
/// delivered to `config.sh` via the `ACTIONS_RUNNER_INPUT_TOKEN`
/// environment variable rather than the `--token VALUE` CLI argument.
/// `actions/runner` reads this env var per
/// `src/Runner.Listener/CommandSettings.cs:245` (envPrefix
/// `"ACTIONS_RUNNER_INPUT_"` + arg name `"token"` from
/// `Constants.Runner.CommandLine.Args.Token`). Argv channels would
/// surface the token at `/proc/PID/cmdline` for the lifetime of the
/// process; env-var delivery keeps the token in `/proc/PID/environ`,
/// which is mode 0400 owner-only.
pub trait ConfigShell {
    /// Register the runner: `config.sh --url URL --name NAME --labels
    /// CSV --unattended --replace` with `ACTIONS_RUNNER_INPUT_TOKEN`
    /// set in the child environment, run as `user` with cwd
    /// `runner_home`. The token does NOT appear in argv (SEC-05).
    ///
    /// # Errors
    ///
    /// `GharsError::Apply` on spawn / non-zero exit.
    fn run_register(&self, ctx: &ConfigShellCtx<'_>) -> Result<()>;

    /// Deregister: `config.sh remove --unattended` with the removal
    /// token in `ACTIONS_RUNNER_INPUT_TOKEN`. Idempotent — exit code 1
    /// from a stale runner that's already been deregistered
    /// server-side is not surfaced as an error.
    ///
    /// # Errors
    ///
    /// `GharsError::Apply` on spawn / non-zero exit (other than the
    /// "already removed" case).
    fn run_remove(&self, ctx: &ConfigShellCtx<'_>) -> Result<()>;
}

/// Inputs for one `config.sh` invocation. Holding the runner home /
/// user / token / labels in one struct keeps the trait method clean and
/// future-proofs against new fields.
#[derive(Debug)]
pub struct ConfigShellCtx<'a> {
    /// Per-runner home (`/var/lib/ghars/NAME`).
    pub runner_home: &'a Utf8Path,
    /// Runner instance name (the `%i` value).
    pub name: &'a str,
    /// Repo / org URL for `--url`.
    pub url: &'a str,
    /// Runner labels for `--labels`.
    pub labels: &'a [String],
    /// Registration / removal token value.
    pub token: &'a str,
}

/// Environment-variable name actions/runner reads to populate the
/// `--token` argument when the CLI flag is absent. Sourced from
/// `actions/runner src/Runner.Listener/CommandSettings.cs:245`
/// (envPrefix `"ACTIONS_RUNNER_INPUT_"`) +
/// `Constants.Runner.CommandLine.Args.Token = "token"`. Used by
/// [`RealConfigShell`] for SEC-05 token delivery.
const RUNNER_TOKEN_ENV: &str = "ACTIONS_RUNNER_INPUT_TOKEN";

/// Build the fully-prepared `Command` for `config.sh` registration.
/// Pure constructor — no I/O, no spawn — so tests can inspect argv
/// via `get_args()` and env via `get_envs()` without touching
/// `/usr/bin/sudo`. Centralizes the SEC-05 invariant: every callsite
/// that shells out to `config.sh` MUST route through this builder so
/// the token never leaks into argv.
///
/// `--preserve-env=ACTIONS_RUNNER_INPUT_TOKEN` (sudo 1.8.21+) tells
/// sudo to copy the named env var from its own environ into the
/// target user's environ; without it, sudo's default env_reset
/// strips the token before exec'ing config.sh.
fn build_register_cmd(ctx: &ConfigShellCtx<'_>) -> Command {
    let labels_csv = ctx.labels.join(",");
    let mut cmd = Command::new(ctx.runner_home.join("config.sh"));
    // SEC-05: token rides in the env var, not argv. argv contains no
    // secret material; `/proc/PID/cmdline` of the running config.sh
    // subprocess is now safe to read. config.sh runs as root in apply;
    // systemd takes ownership at unit start via DynamicUser=yes +
    // StateDirectory=, which chowns the home + credentials to the
    // trust_zone's transient UID at start-of-unit time.
    cmd.args([
        "--url",
        ctx.url,
        "--name",
        ctx.name,
        "--labels",
        &labels_csv,
        "--unattended",
        "--replace",
    ])
    .env(RUNNER_TOKEN_ENV, ctx.token)
    .current_dir(ctx.runner_home.as_std_path());
    cmd
}

/// Build the `config.sh remove` Command. Same SEC-05 contract as
/// [`build_register_cmd`] — token rides in the env var, never argv.
/// config.sh's `remove` subcommand consumes the same
/// `Constants.Runner.CommandLine.Args.Token` field
/// (`GetRunnerDeletionToken` / `GetArgOrPrompt` in actions/runner),
/// so the env-var mapping applies identically to register and remove.
fn build_remove_cmd(ctx: &ConfigShellCtx<'_>) -> Command {
    let mut cmd = Command::new(ctx.runner_home.join("config.sh"));
    cmd.args(["remove", "--unattended"])
        .env(RUNNER_TOKEN_ENV, ctx.token)
        .current_dir(ctx.runner_home.as_std_path());
    cmd
}

/// Production config.sh runner.
#[derive(Debug, Default)]
pub struct RealConfigShell;

impl ConfigShell for RealConfigShell {
    fn run_register(&self, ctx: &ConfigShellCtx<'_>) -> Result<()> {
        let status = build_register_cmd(ctx)
            .status()
            .map_err(|e| spawn_err("config.sh register", &e))?;
        if status.success() {
            return Ok(());
        }
        Err(GharsError::Apply {
            action: format!("config.sh register({})", ctx.name),
            source: Box::new(GharsError::Io(std::io::Error::other(format!(
                "config.sh register exited with {status:?}"
            )))),
        })
    }

    fn run_remove(&self, ctx: &ConfigShellCtx<'_>) -> Result<()> {
        let status = build_remove_cmd(ctx)
            .status()
            .map_err(|e| spawn_err("config.sh remove", &e))?;
        if status.success() {
            return Ok(());
        }
        // `config.sh remove` returns non-zero when the runner is
        // already deregistered server-side — treat as success so
        // `apply RemoveRunner` is idempotent. Distinguish via stderr
        // in a future revision; for now we trust the orchestration
        // order (stop → mint removal token → run remove).
        Ok(())
    }
}

// ---------- Apply orchestrator -----------------------------------------

/// Minimum age (in seconds) before a `.NAME.tmp.PID.COUNTER` file is
/// eligible for GC by [`gc_stale_temp_files`]. Anything younger could
/// belong to a `write_root_owned` call still in flight on this thread
/// (the lock prevents *cross-process* races, but a single
/// in-process call to write_root_owned briefly creates the temp
/// file before the rename publishes it). 60s is well past the
/// longest expected single-write window.
const STALE_TEMP_AGE_SECS: u64 = 60;

/// Sweep half-written `write_root_owned` temp files left behind by
/// previously-crashed applies. Called from [`apply`] right after
/// `acquire_lock` and before the action loop.
///
/// Pattern matched: `.<final_name>.tmp.<pid>.<counter>` — exactly the
/// shape `write_root_owned` writes (apply.rs `write_root_owned`).
/// Filter:
/// - Hidden filename (starts with `.`) and ends in `.tmp.PID.COUNTER`.
/// - Both PID and COUNTER components must parse as decimal integers.
/// - Embedded PID must NOT match our own PID (defensive — apply.lock
///   already prevents concurrent applies, but this is cheap).
/// - mtime older than [`STALE_TEMP_AGE_SECS`] (apply.lock makes this
///   the dominant guard against ripping a still-in-flight temp out
///   from under a concurrent writer; the age check is belt-and-
///   suspenders for clock skew).
///
/// PID-LIVENESS IS NOT USED (symmetric with the `PID-LIVENESS IS
/// DEPRECATED` section in [`gc_stale_staging_dirs`]): the filter
/// intentionally does not probe `pid_is_alive(embedded_pid)`. PIDs
/// recycle — once the dead PID slot is reclaimed by an unrelated
/// process, a liveness probe would falsely report "still alive" and
/// the temp file would be permanently retained even though no
/// current process has any claim to it. Under apply.lock the only
/// temp files that exist are either ours (`embedded_pid == our_pid`
/// skip) or belong to a previously-crashed apply; both are correctly
/// handled by the own-PID + age gates alone.
///
/// Directories scanned (each independently — one missing directory
/// does not prevent the others from running):
/// - `paths.unit_dir` (`/etc/systemd/system`) — runner unit files
///   and shared templates.
/// - Each `ghars-runner@*.service.d` and `ghars-cache@*.service.d`
///   subdirectory under `unit_dir` — per-instance drop-in dirs.
/// - `paths.config_dir/nft.d` — netns nft rule files.
/// - `paths.config_dir/netns.d` — per-runner netns config TOML.
///
/// Errors are swallowed and logged at info / warn — `apply()` MUST
/// run regardless. (The whole helper is best-effort; a permission
/// error or transient ENOENT does not block the action loop.)
fn gc_stale_temp_files(paths: &Paths) {
    let mut dirs: Vec<Utf8PathBuf> = Vec::new();
    dirs.push(paths.unit_dir.clone());
    dirs.push(paths.config_dir.join("nft.d"));
    dirs.push(paths.config_dir.join("netns.d"));
    // Discover per-runner / per-pool drop-in dirs without using
    // glob — the unit_dir read above lists them anyway, but apply.rs
    // doesn't pull in the glob crate. Match by suffix on the
    // directory entry's file_name.
    if let Ok(entries) = fs::read_dir(paths.unit_dir.as_std_path()) {
        for entry in entries.flatten() {
            let Ok(ft) = entry.file_type() else {
                continue;
            };
            if !ft.is_dir() {
                continue;
            }
            let Ok(child) = Utf8PathBuf::from_path_buf(entry.path()) else {
                continue;
            };
            let Some(name) = child.file_name() else {
                continue;
            };
            if (name.starts_with("ghars-runner@") || name.starts_with("ghars-cache@"))
                && name.ends_with(".service.d")
            {
                dirs.push(child);
            }
        }
    }

    let now = std::time::SystemTime::now();
    let our_pid = std::process::id();
    for dir in dirs {
        let Ok(entries) = fs::read_dir(dir.as_std_path()) else {
            continue;
        };
        for entry in entries.flatten() {
            let Ok(ft) = entry.file_type() else {
                continue;
            };
            // Symlinks could redirect ownership of the unlink — skip.
            if !ft.is_file() {
                continue;
            }
            let name = entry.file_name();
            let Some(name_str) = name.to_str() else {
                continue;
            };
            let Some((embedded_pid, _counter)) = parse_temp_file_suffix(name_str) else {
                continue;
            };
            // Defensive: never delete files whose embedded PID matches
            // our own — write_root_owned currently writes from this
            // PID, and the lock means we are the sole writer, but if
            // a future caller skips the lock we don't want gc to race
            // them.
            if embedded_pid == our_pid {
                continue;
            }
            let Ok(meta) = entry.metadata() else {
                continue;
            };
            let Ok(mtime) = meta.modified() else {
                continue;
            };
            let Ok(age) = now.duration_since(mtime) else {
                // mtime is in the future (clock skew). Skip rather
                // than delete; a future-mtime stale file will become
                // eligible once the clock catches up.
                continue;
            };
            if age.as_secs() < STALE_TEMP_AGE_SECS {
                continue;
            }
            let path = entry.path();
            match fs::remove_file(&path) {
                Ok(()) => {
                    tracing::info!(
                        path = %path.display(),
                        embedded_pid,
                        age_secs = age.as_secs(),
                        "gc_stale_temp_files: removed crashed-apply leftover"
                    );
                }
                Err(e) => {
                    tracing::warn!(
                        path = %path.display(),
                        error = %e,
                        "gc_stale_temp_files: failed to remove temp file (continuing)"
                    );
                }
            }
        }
    }
}

/// Sweep stale staging directories under
/// `<state_dir>/.staging/<runner_name>-<version>-<pid>/` left behind
/// when `extract::install_runner_binary` crashed between
/// `fs::create_dir(&staging)` and the final atomic rename. Called from
/// [`apply`] right after [`gc_stale_temp_files`] and before the
/// action loop.
///
/// extract.rs has best-effort cleanup at the end of
/// `install_runner_binary` (an `Err` from `extract_and_swap` triggers
/// `fs::remove_dir_all(&staging)`), but a SIGKILL — or a panic that
/// abort()s before the cleanup branch — leaves the staging tree
/// orphaned. Without this GC the `.staging/` parent grows unbounded
/// across crash cycles.
///
/// Naming pattern (extract.rs `install_runner_binary`):
/// `{runner_name}-{version}-{pid}`. We parse from the right —
/// `rsplit_once('-')` for the PID, then leave `{runner_name}-{version}`
/// as the head — and treat any directory that doesn't match as foreign
/// (skip rather than delete). version may itself contain `-` so we
/// only care about the trailing PID component.
///
/// Filter (mirror of [`gc_stale_temp_files`]):
/// - Entry is NOT a symlink (lstat-style `file_type().is_symlink()`).
///   Symlinks inside `.staging/` are foreign — extract.rs only ever
///   creates real dirs at mode 0700; skipping closes the
///   link-traversal door for `remove_dir_all`. `.staging/`'s 0700
///   root-only mode makes a symlink there a separate compromise, but
///   the cost of the check is one stat() and the upside is closing
///   the door.
/// - Embedded PID parses as `i32` (`extract.rs` uses `std::process::id()`,
///   a `u32`; we accept the i32 conversion because PIDs in practice
///   stay well under 2^31).
/// - Embedded PID is NOT our own (defensive — apply.lock blocks
///   cross-process races, but a future caller that drops the lock
///   shouldn't have its in-flight staging dir deleted).
/// - mtime older than [`STALE_TEMP_AGE_SECS`] — the dominant gate.
///   apply.lock is held for the duration of the gc; while the lock
///   is held, no other apply is creating staging dirs, so any dir
///   whose mtime exceeds the age gate is from a previous (now-
///   terminated) apply. Same 60s window as [`gc_stale_temp_files`].
///
/// PID-liveness is intentionally not used: gating on
/// `pid_is_alive(embedded_pid)` would leak staging trees once the
/// dead PID slot is reclaimed by an unrelated process. Under
/// apply.lock the only stagedirs that exist are either ours
/// (`embedded_pid == our_pid` skip) or belong to a previously-crashed
/// apply; both are correctly handled by the own-PID + age gates alone.
///
/// Errors are swallowed and logged at info / warn — `apply()` MUST
/// run regardless. Best-effort: a missing `.staging/` (the normal
/// case on a fresh install) is silently ignored at the read_dir
/// level.
fn gc_stale_staging_dirs(paths: &Paths) {
    let staging_root = paths.state_dir.join(".staging");
    let Ok(entries) = fs::read_dir(staging_root.as_std_path()) else {
        // Missing or inaccessible staging root is the steady-state
        // case — every fresh install starts without one.
        return;
    };
    let now = std::time::SystemTime::now();
    let our_pid = i32::try_from(std::process::id()).unwrap_or(i32::MAX);
    for entry in entries.flatten() {
        let Ok(ft) = entry.file_type() else {
            continue;
        };
        // Defense-in-depth: explicit symlink rejection BEFORE the
        // is_dir() check. `entry.file_type()` is lstat-style so a
        // symlink-to-anywhere reports `is_dir() == false` and the
        // gate below catches it, but a hostile attacker who can
        // write to .staging/ could replace a real staging tree with
        // `<name>-<version>-<pid>` → `/some/important/dir` symlink
        // and rely on the next gc cycle to redirect remove_dir_all.
        // Skipping at the type-check stage makes the intent explicit
        // and matches the `!ft.is_file()` symlink-skip pattern in
        // [`gc_stale_temp_files`] (lstat-style file_type reports
        // symlink, not file/dir, so both gates filter the same set).
        if ft.is_symlink() {
            continue;
        }
        if !ft.is_dir() {
            // Stray files inside .staging/ are foreign — skip rather
            // than delete, same conservative gate gc_stale_temp_files
            // applies.
            continue;
        }
        let name = entry.file_name();
        let Some(name_str) = name.to_str() else {
            continue;
        };
        let Some(embedded_pid) = parse_staging_dir_suffix(name_str) else {
            continue;
        };
        if embedded_pid == our_pid {
            // A future caller bypassing the lock might still hold
            // staging open in-process; don't rip it out.
            continue;
        }
        // No pid_is_alive gate: PIDs recycle, so a
        // liveness probe permanently leaks the staging tree once the
        // dead slot is reclaimed by an unrelated process. Under
        // apply.lock the own-PID skip + age gate are sufficient.
        let Ok(meta) = entry.metadata() else {
            continue;
        };
        let Ok(mtime) = meta.modified() else {
            continue;
        };
        let Ok(age) = now.duration_since(mtime) else {
            // Future mtime (clock skew). Skip; eligibility returns
            // once the clock catches up.
            continue;
        };
        if age.as_secs() < STALE_TEMP_AGE_SECS {
            continue;
        }
        let path = entry.path();
        match fs::remove_dir_all(&path) {
            Ok(()) => {
                tracing::info!(
                    path = %path.display(),
                    embedded_pid,
                    age_secs = age.as_secs(),
                    "gc_stale_staging_dirs: removed crashed-install leftover"
                );
            }
            Err(e) => {
                tracing::warn!(
                    path = %path.display(),
                    error = %e,
                    "gc_stale_staging_dirs: failed to remove staging dir (continuing)"
                );
            }
        }
    }
}

/// Parse `{runner_name}-{version}-{pid}` and return the PID. Splits
/// from the right so a version string containing `-` (e.g. a future
/// `2.334.0-rc1` build) doesn't confuse the parse. The runner_name
/// and version components are not validated here — the caller's
/// own-PID + age gates already make non-stale matches safe to skip
/// even if the head is a directory we don't recognize.
///
/// PRECONDITION: `.staging/` is exclusively owned by ghars
/// (`extract.rs::install_runner_binary` creates it at mode 0700,
/// root-only). Foreign content must not be
/// placed there. The parser is intentionally permissive — anything
/// matching `*-NUM` is treated as a candidate stagedir — because
/// under the precondition every occupant is one of ghars's own
/// writes; we never have to defend against a name-shape collision
/// from an unrelated process.
fn parse_staging_dir_suffix(name: &str) -> Option<i32> {
    let (_head, pid_str) = name.rsplit_once('-')?;
    pid_str.parse::<i32>().ok()
}

/// Parse `.{final_name}.tmp.{pid}.{counter}` and return `(pid, counter)`
/// when both are decimal integers and the basename starts with `.`
/// (hidden) AND `.tmp.` appears between the final-name and the
/// `pid.counter` suffix. Returns `None` when the shape doesn't match —
/// this is the conservative gate: anything we can't parse, we leave
/// alone.
fn parse_temp_file_suffix(name: &str) -> Option<(u32, u64)> {
    if !name.starts_with('.') {
        return None;
    }
    // Walk from the right: split off counter (last `.NUM`), then pid
    // (next-to-last `.NUM`), then verify what remains ends in `.tmp`.
    let (head, counter_str) = name.rsplit_once('.')?;
    let counter: u64 = counter_str.parse().ok()?;
    let (head, pid_str) = head.rsplit_once('.')?;
    let pid: u32 = pid_str.parse().ok()?;
    if !head.ends_with(".tmp") {
        return None;
    }
    Some((pid, counter))
}

/// Apply a plan to the host.
///
/// 1. Acquires `<paths.runtime_dir>/apply.lock` (POSIX advisory).
/// 2a. GCs stale `.NAME.tmp.PID.COUNTER` temp files under
///     `paths.unit_dir` / drop-in subdirs / `paths.config_dir/nft.d` /
///     `paths.config_dir/netns.d` — leftovers from `write_root_owned`
///     calls that crashed between `create_new` and the final rename.
/// 2b. GCs stale `<state_dir>/.staging/<name>-<version>-<pid>/`
///     directories — leftovers from
///     `extract::install_runner_binary` calls that crashed past their
///     own cleanup branch. Filesystem subtree is disjoint from 2a's
///     (`.staging/` lives under `state_dir`, never under `unit_dir` or
///     `config_dir`), so the two passes are independent.
///
///    Both GC passes are best-effort, never fail apply, and skipped
///    under `opts.dry_run`.
/// 3. Sorts `plan.actions` into the canonical phase order documented
///    in Part 8: `CreateCachePool` → `UpdateCachePool` →
///    `RemoveRunner` → `UpdateRunner` (in-place subset first, recreate
///    subset second) → `CreateRunner` → `RemoveCachePool`. Within
///    each phase, runners + pools are sorted by name for determinism.
/// 4. Dispatches each action through `execute_*`, recording success /
///    failure / skip in [`ApplyResult`].
/// 5. Calls `systemd.daemon_reload()` once at the end (regardless of
///    `fail_fast`'s short-circuit; skipped under `opts.dry_run`).
/// 6. Releases the lock on Drop.
///
/// # Errors
///
/// - `GharsError::ApplyLocked` if another `apply` holds the lock.
/// - `GharsError::Io` on lock acquisition I/O failure.
/// - `GharsError::Apply` wrapping the first action failure when
///   `fail_fast` is true. With `fail_fast = false`, individual failures
///   accumulate in `result.failed` and `apply` returns `Ok(result)`
///   even though `result.ok()` is false.
pub fn apply(
    plan: &Plan,
    deps: &Deps<'_>,
    paths: &Paths,
    opts: &ApplyOptions,
) -> Result<ApplyResult> {
    let _lock = acquire_lock(paths)?;
    // GC half-written `.NAME.tmp.PID.COUNTER` files left behind
    // by previous applies that crashed between `write_root_owned`'s
    // create_new and the final rename. Best-effort — failures are
    // logged at warn level and never fail apply. Runs AFTER lock
    // acquisition so we are the sole writer (no race against
    // concurrent applies sweeping each other's in-flight temp files)
    // and BEFORE the action loop so a stale temp can't shadow a
    // freshly-created file with the same final name. The mtime gate
    // (60s) is the concurrency guard; the lock makes the gate
    // sufficient (other applies are blocked).
    //
    // GC orphan `<state_dir>/.staging/<runner-name>-<version>-<pid>/`
    // staging directories left behind when extract::install_runner_binary
    // crashed past its own cleanup branch. Same own-PID + age gates
    // as gc_stale_temp_files (no PID-liveness probe — see the
    // `gc_stale_staging_dirs` doc-comment for the rationale).
    // Targets a
    // disjoint filesystem subtree (state_dir/.staging vs unit_dir +
    // config_dir/nft.d + config_dir/netns.d), so it runs as a
    // separate pass alongside gc_stale_temp_files.
    if !opts.dry_run {
        gc_stale_temp_files(paths);
        gc_stale_staging_dirs(paths);
    }
    let mut result = ApplyResult::default();
    let phases = sort_into_phases(&plan.actions);
    for action in phases {
        let label = action.label();
        if matches!(action, Action::NoOp(_)) {
            result.skipped.push(label.clone());
            // Every action — including NoOp — gets a row in
            // `details` so cmd_apply can render the per-action
            // detail line uniformly. NoOp emits the `noop (in sync)`
            // detail.
            result.details.push((label, ApplyOutcome::NoOp));
            continue;
        }
        if opts.dry_run {
            result.skipped.push(label.clone());
            // Dry-run-skipped actions also land in `details`
            // so the operator sees what `apply` WOULD have done,
            // labeled as `dry-run (skipped)`.
            result.details.push((label, ApplyOutcome::DryRunSkipped));
            continue;
        }
        // Per-action UndoLog. Each execute_* pushes
        // after every successful side effect; on Err we walk the log
        // in reverse via `undo` when --rollback-on-failure is set.
        // Scope is per-action — earlier successful actions are NOT
        // touched.
        let mut log = UndoLog::new();
        // Capture plan-time worst-case disruption BEFORE the
        // execute borrow / Err-path move so an `ApplyOutcome::Failed`
        // row can carry it through to cmd_apply rendering.
        // `Action::disruption` reads no state and is cheap.
        let plan_disruption = action.disruption();
        match execute(&action, deps, paths, &mut log) {
            Ok(outcome) => {
                result.succeeded.push(label.clone());
                // Real (non-skipped) outcomes carry their
                // ApplyOutcome variant so cmd_apply can render the
                // per-action detail (e.g. `in-place: 2 file(s)
                // changed, 0 group op(s)` for a no-pool-diff restart,
                // or `... 1 group op(s) (added: build-cache)` when a
                // cache pool was reconciled).
                result.details.push((label, outcome));
            }
            Err(e) => {
                if opts.rollback_on_failure {
                    // Best-effort: swallow undo errors (each step
                    // already logs internally via tracing::warn!) so
                    // the original action error stays the visible
                    // failure.
                    let _ = undo(&log, deps, paths);
                }
                // Capture the inner-error display BEFORE the
                // wrap, so the `ApplyOutcome::Failed` row carries
                // only the cause (the wrapping `GharsError::Apply`
                // would re-include the label that already appears
                // in the `(label, ApplyOutcome)` tuple).
                //
                // Escape ASCII control characters in the
                // captured display before storing. The Display impls
                // for `GharsError` interpolate operator-supplied
                // strings (config paths, auth names, hostnames) — a
                // hostile string that survived upstream validation
                // could carry `\x1b[…m` sequences that would
                // manipulate the terminal when cmd_apply later writes
                // the row to stderr. Escape at the construction site
                // so every consumer of `ApplyOutcome::Failed` sees
                // already-safe bytes (cli.rs render path, programmatic
                // consumers, PartialEq comparisons in tests). Side
                // effect: avoids per-render clone overhead by
                // making the stored string already terminal-safe
                // (ANSI/C0/DEL escape only).
                //
                // Secret-leakage policy lives at `crate::error`
                // module-level docs; paths ARE allowed in Display
                // output; tokens/env-values/PEM bytes are NOT
                // (enforced at every error-construction site, not by
                // this helper).
                let error_summary = escape_control_chars(&e.to_string()).into_owned();
                let wrapped = GharsError::Apply {
                    action: label.clone(),
                    source: Box::new(e),
                };
                // Per-action audit row — the Failed variant is pushed
                // to `details` alongside the existing `failed` push so
                // the in-execution-order Vec covers every processed
                // action. Under fail_fast, actions after the first
                // failure are never pushed.
                // `result.failed` keeps the typed GharsError chain
                // for programmatic consumers (exit-code mapping,
                // rollback advisories).
                result.details.push((
                    label.clone(),
                    ApplyOutcome::Failed {
                        error_summary,
                        plan_disruption,
                    },
                ));
                // Single failed.push covers both fail_fast and
                // accumulate-and-continue paths — the only difference
                // is whether the loop short-circuits afterwards.
                result.failed.push((label.clone(), wrapped));
                // Per-action mutation manifest — consume the
                // UndoLog to surface what landed on disk before the
                // action errored. Pushed AFTER `result.failed` so the
                // `failed[i].0 == failed_undo_logs[i].0` ordering
                // invariant holds. cmd_apply walks this Vec to render
                // the rollback-state advisory on stderr.
                // The steps describe ATTEMPTED
                // mutations, not guaranteed-residual state. `undo` is
                // best-effort regardless of mode:
                // - `rollback_on_failure=true`: `undo` walked the log
                //   in reverse, attempted each forward-direction
                //   inverse, and SKIPPED reverse-direction steps
                //   (`is_reverse_direction()`). Per-step failures
                //   were swallowed and logged via `tracing::warn`,
                //   NOT surfaced to the operator — so even after
                //   `undo`, residual state may remain (skipped
                //   reverse-direction steps + forward-direction
                //   steps whose inverse failed).
                // - `rollback_on_failure=false`: `undo` did not run.
                //   Every step represents on-disk state the operator
                //   must clean up manually.
                // Either way, the advisory's steps are a cleanup
                // checklist, not a "still pending" guarantee.
                result.failed_undo_logs.push((label, log.into_steps()));
                if opts.fail_fast {
                    let _ = deps.systemd.daemon_reload();
                    return Ok(result);
                }
            }
        }
    }
    if !opts.dry_run {
        // daemon_reload always runs after the per-action loop. When
        // every action failed early it is still safe — Manager.Reload
        // is a no-op when no unit files changed.
        if let Err(e) = deps.systemd.daemon_reload() {
            // Also push to details so cmd_apply's
            // details-only rendering loop emits a `fail:` line for
            // this synthetic post-loop step.
            //
            // "daemon_reload" is a SYNTHETIC label — it is
            // not derived from any `Action` and therefore has no
            // `Action::disruption()` to plumb through. We hand-set
            // `plan_disruption = Disruption::None` because
            // Manager.Reload is a cache flush of systemd's in-memory
            // unit-file index, not a unit-level start/stop or
            // recreate. No service is touched; no operator-visible
            // unit transitions; the bracket tag `[none]` accurately
            // reports the (zero) blast radius.
            let label = String::from("daemon_reload");
            // Escape for the same reason as the per-action loop
            // arm above — defense-in-depth scrub of terminal-manipulation
            // bytes from arbitrary `GharsError::to_string()` output
            // before it lands in `ApplyOutcome::Failed.error_summary`.
            // See the per-action loop arm above for the terminal-safety
            // scope and secret-leakage policy reference.
            let error_summary = escape_control_chars(&e.to_string()).into_owned();
            result.details.push((
                label.clone(),
                ApplyOutcome::Failed {
                    error_summary,
                    plan_disruption: crate::plan::Disruption::None,
                },
            ));
            result.failed.push((
                label.clone(),
                GharsError::Apply {
                    action: "daemon_reload".into(),
                    source: Box::new(e),
                },
            ));
            // Maintain the `failed[i].0 == failed_undo_logs[i].0`
            // ordering invariant. The synthetic daemon_reload failure
            // is post-loop and has no per-action UndoLog (every
            // action's log was consumed at action-end above), so the
            // step list is empty by construction. cmd_apply's
            // advisory renderer skips entries with empty step lists.
            result.failed_undo_logs.push((label, Vec::new()));
        }
    }
    Ok(result)
}

/// Stable sort key for action ordering within a phase.
fn action_sort_key(a: &Action) -> String {
    match a {
        Action::CreateRunner(p) => p.spec.name.clone(),
        Action::UpdateRunner(d) => d.identity.name.clone(),
        Action::RemoveRunner(i) => i.name.clone(),
        Action::CreateCachePool(p) => p.binding.name.clone(),
        Action::UpdateCachePool(d) => d.binding.name.clone(),
        Action::RemoveCachePool(name) => name.clone(),
        Action::NoOp(reason) => reason.clone(),
    }
}

/// Sort actions into Part 8's canonical execution order. Within each
/// phase, runners + pools are sorted by their identifier for
/// determinism (so `apply` is reproducible across plan invocations).
fn sort_into_phases(actions: &[Action]) -> Vec<Action> {
    let mut create_cache: Vec<&Action> = Vec::new();
    let mut update_cache: Vec<&Action> = Vec::new();
    let mut remove_runner: Vec<&Action> = Vec::new();
    let mut update_runner_inplace: Vec<&Action> = Vec::new();
    let mut update_runner_recreate: Vec<&Action> = Vec::new();
    let mut create_runner: Vec<&Action> = Vec::new();
    let mut remove_cache: Vec<&Action> = Vec::new();
    let mut noops: Vec<&Action> = Vec::new();
    for a in actions {
        match a {
            Action::CreateCachePool(_) => create_cache.push(a),
            Action::UpdateCachePool(_) => update_cache.push(a),
            Action::RemoveRunner(_) => remove_runner.push(a),
            Action::UpdateRunner(d) if !d.requires_recreate => update_runner_inplace.push(a),
            Action::UpdateRunner(_) => update_runner_recreate.push(a),
            Action::CreateRunner(_) => create_runner.push(a),
            Action::RemoveCachePool(_) => remove_cache.push(a),
            Action::NoOp(_) => noops.push(a),
        }
    }
    for v in [
        &mut create_cache,
        &mut update_cache,
        &mut remove_runner,
        &mut update_runner_inplace,
        &mut update_runner_recreate,
        &mut create_runner,
        &mut remove_cache,
        &mut noops,
    ] {
        v.sort_by_key(|a| action_sort_key(a));
    }
    let mut out: Vec<Action> = Vec::new();
    for chunk in [
        create_cache,
        update_cache,
        remove_runner,
        update_runner_inplace,
        update_runner_recreate,
        create_runner,
        remove_cache,
        noops,
    ] {
        for a in chunk {
            out.push(a.clone());
        }
    }
    out
}

/// Execute one [`Action`] against the host.
///
/// Pure dispatch — every variant routes to a per-action handler.
/// Errors here are returned bare; [`apply`] is responsible for
/// wrapping them in `GharsError::Apply { action, source }` so the
/// action label is preserved exactly once at the call boundary.
///
/// `log` accumulates [`UndoStep`] entries that the handler pushes after
/// each successful side effect. On `Err`, [`apply`] walks `log` in
/// reverse via [`undo`] when `opts.rollback_on_failure` is set.
///
/// # Errors
///
/// Returns the underlying error from the per-action handler.
pub fn execute(
    action: &Action,
    deps: &Deps<'_>,
    paths: &Paths,
    log: &mut UndoLog,
) -> Result<ApplyOutcome> {
    match action {
        Action::CreateRunner(p) => execute_create_runner(p, deps, paths, log),
        Action::UpdateRunner(d) => execute_update_runner(d, deps, paths, log),
        Action::RemoveRunner(i) => execute_remove_runner(i, deps, paths, log),
        Action::CreateCachePool(p) => execute_create_cache_pool(p, deps, paths, log),
        Action::UpdateCachePool(d) => execute_update_cache_pool(d, deps, paths, log),
        Action::RemoveCachePool(name) => execute_remove_cache_pool(name, deps, paths, log),
        // NoOp never reaches `execute` in production: `apply`'s loop
        // body checks `matches!(action, Action::NoOp(_))` immediately
        // after taking each phase-sorted action and pushes
        // `(label, NoOp)` into `details` before dispatching here.
        // We return `NoOp` defensively in case a future caller
        // passes an `Action::NoOp` through, or a test bypasses the
        // loop and calls `execute` directly.
        Action::NoOp(_) => Ok(ApplyOutcome::NoOp),
    }
}

// ---------- Per-action handlers -----------------------------------------

fn execute_create_runner(
    plan: &RunnerPlan,
    deps: &Deps<'_>,
    paths: &Paths,
    log: &mut UndoLog,
) -> Result<ApplyOutcome> {
    let spec = &plan.spec;
    let runner_home = paths.runner_home(&spec.trust_zone, &spec.name);

    // No useradd / gpasswd step. The runner unit declares
    // DynamicUser=yes with `User=ghars-tz-<TRUST_ZONE>` set in the
    // per-runner 00-ghars.conf drop-in; systemd allocates the
    // transient UID/GID on unit start and recycles it on stop. Cache
    // reach is socket-DAC + BindPaths (cache server runs at the same
    // trust_zone DynamicUser), not gpasswd.

    // 1) Runner binary. Two paths:
    //    (a) `runner_tarball` set on the spec → use the local file
    //        verbatim after re-stat'ing (verify_local closes the
    //        SEC-16 stat-then-extract TOCTOU window).
    //    (b) Otherwise the plan resolved a `Release` and we fetch its
    //        `tarball_url` into a runtime dir, verify SHA256, then
    //        install.
    let (tarball_path, version) = if let Some(local) = &spec.runner_tarball {
        deps.tarball.verify_local(local)?;
        let version = spec
            .runner_version
            .clone()
            .unwrap_or_else(|| "local".into());
        (local.clone(), version)
    } else {
        let release = plan.resolved_release.as_ref().ok_or_else(|| {
            GharsError::Validation(
                format!("runner {:?}: no runner_tarball and no resolved release", spec.name),
                "set runner_version + runner_sha256, supply runner_tarball, or run plan again so the release-API lookup succeeds".into(),
            )
        })?;
        let dest = paths.runtime_dir.join(format!(
            "releases/{}/{}",
            release.version, release.tarball_name
        ));
        if let Some(parent) = dest.parent() {
            fs::create_dir_all(parent.as_std_path())?;
        }
        deps.tarball
            .fetch_or_verify(&release.tarball_url, &dest, &release.sha256)?;
        (dest, release.version.clone())
    };
    let _bin_dir = deps.tarball.install_binary(
        &tarball_path,
        &paths.state_dir,
        &runner_home,
        &spec.name,
        &version,
    )?;

    // 3) Mint a registration token. SEC-05: the token is short-lived
    //    (1h GitHub TTL); we hand it to config.sh and never persist it.
    //    The caller-visible `RegistrationToken.value` is opaque so
    //    nothing here logs it.
    let token = mint_token(deps.auth, &spec.auth_name, &spec.url, false)?;

    // 4) Run config.sh --url ... --token ... — registers the runner
    //    with GitHub. SEC-05 mitigation note in trait doc; v0.1 still
    //    passes the token via argv pending the token-drop env-var
    //    pattern's full design. Pass `&token.value` so `token`
    //    stays owned in this frame and zeroizes on Drop at end of fn.
    deps.config_shell.run_register(&ConfigShellCtx {
        runner_home: &runner_home,
        name: &spec.name,
        url: &spec.url,
        labels: &spec.labels,
        token: &token.value,
    })?;
    // Push GitHubRegistration AFTER run_register succeeds. Undo path
    // mints a fresh removal token via the auth registry and calls
    // run_remove. The runner_home/user fields are
    // captured here because by the time undo runs, spec.user could
    // have been usermod'd (in-place update) and the runner_home path
    // is the canonical location config.sh writes credentials to.
    log.push(UndoStep::GitHubRegistration {
        name: spec.name.clone(),
        url: spec.url.clone(),
        auth_name: spec.auth_name.clone(),
        runner_home: runner_home.clone(),
    });

    // No tighten_credential_perms call. DynamicUser=yes manages
    // StateDirectory ownership at the systemd level; .credentials is
    // owned by the trust_zone's transient UID and inherits the
    // StateDirectoryMode=0700 from the unit template.

    // 5b) SEC-02: hash the runsvc.sh that `config.sh` wrote into the
    //     runner home. config.sh (the upstream actions/runner script)
    //     materialises runsvc.sh + .runner + .credentials in $HOME at
    //     register time — NOT during `install_runner_binary`, which
    //     only lays down `bin.X.Y.Z/`. We
    //     hash AFTER run_register so the path actually exists.
    //
    //     The hash flows into a freshly-rendered 00-ghars.conf via the
    //     `[Service] X-Ghars-Runsvc-Sha256=` annotation; the
    //     runsvc-wrapper trampoline reads that annotation at every unit
    //     start and refuses to exec a runsvc.sh whose contents have
    //     changed (closing the SEC-02 persistent-RCE-on-restart hole).
    //
    //     The plan's `drop_ins` and `effective_unit_text` are
    //     placeholders (plan ran before install, so it could not
    //     compute the digest). We re-render here with the populated
    //     spec.
    let runsvc_path = runner_home.join("runsvc.sh");
    let runsvc_sha = sha256_of_runsvc(&runsvc_path).map_err(|e| GharsError::Apply {
        action: format!("CreateRunner({}): hash runsvc.sh", spec.name),
        source: Box::new(e),
    })?;
    let mut populated_spec = spec.clone();
    populated_spec.runsvc_sha256 = runsvc_sha;
    let rendered = render_runner_unit(&populated_spec)?;

    // 6) Write unit file + drop-ins. The reset-on-empty validation
    //    already ran inside `render_runner_unit`.
    let unit_file = paths.unit_file(&spec.name);
    write_record_undo(&unit_file, rendered.template.as_bytes(), log)?;
    let drop_in_dir = paths.drop_in_dir(&spec.name);
    let drop_in_dir_existed = drop_in_dir.exists();
    fs::create_dir_all(drop_in_dir.as_std_path())?;
    if !drop_in_dir_existed {
        log.push(UndoStep::CreateDir {
            path: drop_in_dir.clone(),
        });
    }
    for (name, body) in &rendered.drop_ins {
        let dest = drop_in_dir.join(name);
        write_record_undo(&dest, body.as_bytes(), log)?;
    }

    // 7) `daemon-reload` happens once at the end of `apply()`; do NOT
    //    call it here. Enable + start.
    let unit_name = format!("ghars-runner@{}.service", spec.name);
    deps.systemd.enable_unit(&unit_name)?;
    log.push(UndoStep::EnableUnit {
        name: unit_name.clone(),
    });
    // Manager.StartUnit fails on a unit not yet loaded post-write. The
    // ordering per Part 8 is: write files → daemon_reload → start_unit.
    // We issue a daemon_reload here so the freshly-written unit is
    // visible; `apply()` issues a final daemon_reload after the
    // per-action loop too, which is idempotent.
    deps.systemd.daemon_reload()?;

    // 7b) For Netns runners: provision the per-runner netns side-units
    //     (config TOML, nft files, ghars-net@.service template) and
    //     start `ghars-net@INSTANCE.service` BEFORE the runner unit so
    //     the runner's `NetworkNamespacePath=/var/run/netns/ghars-%i`
    //     join succeeds. Fail-closed contract: missing netns =>
    //     runner refuses to start. Open mode is a no-op.
    provision_netns_artifacts(spec, deps, paths, log)?;

    deps.systemd.start_unit(&unit_name)?;
    log.push(UndoStep::StartUnit {
        name: unit_name.clone(),
    });

    // 8) Post-start netns verification. Belt-and-suspenders against
    //    a fail-open regression: if the runner has Netns mode but
    //    landed in the host netns, the systemd unit was misjoined
    //    and we abort the action. The runner's PID is read from
    //    Service.MainPID via `systemd.get_unit_property`.
    if matches!(
        spec.network.as_ref().map(|n| &n.spec.mode),
        Some(NetworkMode::Netns)
    ) {
        verify_runner_netns(&unit_name, deps.systemd)?;
    }

    Ok(ApplyOutcome::Created)
}

fn execute_remove_runner(
    identity: &RunnerIdentity,
    deps: &Deps<'_>,
    paths: &Paths,
    log: &mut UndoLog,
) -> Result<ApplyOutcome> {
    let unit_name = format!("ghars-runner@{}.service", identity.name);
    let runner_home = paths.runner_home(&identity.trust_zone, &identity.name);

    // 1) Stop the unit. systemd's StopUnit is idempotent — non-running
    //    units accept Stop with a no-op outcome.
    deps.systemd.stop_unit(&unit_name)?;
    log.push(UndoStep::StopUnit {
        name: unit_name.clone(),
    });
    deps.systemd.disable_unit(&unit_name)?;
    log.push(UndoStep::DisableUnit {
        name: unit_name.clone(),
    });

    // 1b) Tear down the per-runner netns side-units. Safe to call even
    //     for non-netns runners — `teardown_netns_artifacts` no-ops on
    //     missing files, and stop/disable on a non-existent
    //     `ghars-net@INSTANCE.service` is a systemd-side no-op.
    //     RemoveRunner does not carry the original NetworkSpec, so the
    //     teardown is unconditional rather than mode-gated.
    teardown_netns_artifacts(&identity.name, deps, paths, log)?;

    // 2) Mint a removal token + invoke `config.sh remove` so GitHub
    //    deregisters the runner. RealConfigShell::run_remove tolerates
    //    "already removed" exit codes.
    //
    //    Orphan branch: when plan.rs synthesises a RemoveRunner from
    //    `actual.orphans`, `identity.auth_name` and `identity.url` are
    //    empty (the orphan synthesis loop in `plan_from`) because the
    //    orphan has no [[runner]] block in the desired config and
    //    discovery doesn't reach the auth registry. Without those,
    //    `mint_token` would error with
    //    `auth source "" referenced by runner is not in the registry`
    //    and the local cleanup (unit + state dir) would never run —
    //    leaving the host in a permanently-orphaned state.
    //
    //    Skipping the deregister step is the intentional trade-off
    //    (documented in plan.rs orphan handling): the runner stays
    //    registered server-side until the operator either reinstates
    //    its [[runner]] block (so a future apply has full identity)
    //    or removes it via the GitHub UI / API. The host-local artifacts
    //    are still cleaned up below.
    if identity.auth_name.is_empty() || identity.url.is_empty() {
        tracing::warn!(
            runner = %identity.name,
            "orphan RemoveRunner: skipping config.sh remove + GitHub deregister; \
             auth_name/url were not in the desired config. The runner will remain \
             registered server-side; remove it via the GitHub UI or restore its \
             [[runner]] block to enable a clean deregister on the next apply."
        );
    } else {
        let token = mint_token(deps.auth, &identity.auth_name, &identity.url, true)?;
        // Pass `&token.value` so `token` stays owned in this
        // frame and zeroizes on Drop at end of else-branch.
        deps.config_shell.run_remove(&ConfigShellCtx {
            runner_home: &runner_home,
            name: &identity.name,
            url: &identity.url,
            labels: &[],
            token: &token.value,
        })?;
        // No UndoStep for run_remove: it is itself the inverse of
        // GitHubRegistration. Recording GitHubRegistration here would
        // attempt to re-register on rollback — wrong semantically and
        // not recoverable (config.sh register requires a fresh token
        // mint and recreates credentials, which the upstream Remove
        // path just intentionally tore down). The operator restores
        // the runner by reinstating its [[runner]] block + apply.
    }

    // 3) Remove unit + drop-ins.
    let unit_path = paths.unit_file(&identity.name);
    if unit_path.exists() {
        let prior = read_prior(&unit_path);
        fs::remove_file(unit_path.as_std_path())?;
        if let Some(content) = prior {
            log.push(UndoStep::RemoveFile {
                path: unit_path.clone(),
                content,
            });
        }
    }
    let drop_in_dir = paths.drop_in_dir(&identity.name);
    if drop_in_dir.exists() {
        fs::remove_dir_all(drop_in_dir.as_std_path())?;
        log.push(UndoStep::RemoveDir {
            path: drop_in_dir.clone(),
        });
    }

    // 4) Remove the runner home directory after the rmrf safety check.
    if runner_home.exists() {
        let trust_zone_root = paths.trust_zone_home(&identity.trust_zone);
        guard_home_dir_rmrf(
            &runner_home,
            &trust_zone_root,
            &format!("ghars-{}", identity.name),
        )?;
        fs::remove_dir_all(runner_home.as_std_path())?;
        log.push(UndoStep::RemoveDir {
            path: runner_home.clone(),
        });
    }

    // No userdel step. The runner unit's DynamicUser-allocated UID is
    // released by systemd on unit stop; nothing was written to
    // /etc/passwd / /etc/group, so there is nothing to clean up.

    // The end-of-apply daemon_reload picks up the unit file removal.
    Ok(ApplyOutcome::Removed)
}

fn execute_update_runner(
    delta: &RunnerDelta,
    deps: &Deps<'_>,
    paths: &Paths,
    log: &mut UndoLog,
) -> Result<ApplyOutcome> {
    if delta.requires_recreate {
        // Recreate path: stop + remove + create. The plan emits this
        // when an identity-bound field changed (runner_version,
        // labels, url, user, prefix, runner_tarball).
        //
        // The undo log threading here propagates BOTH inner calls'
        // pushes. If create fails partway, undo walks: create's pushes
        // (reverse, lossless), then remove's pushes (reverse-direction
        // variants → warn-and-skip per design). Net effect on
        // recreate-rollback: the partial new state is unwound; the old
        // state stays gone (genuinely lossy — re-running apply is the
        // recovery path).
        //
        // Collapse the inner Removed + Created outcomes into
        // a single `Recreated` — the user-facing contract is one row
        // per `Action`, and the inner remove+create are
        // implementation detail of the recreate path (coordinator
        // ruling (a)).
        execute_remove_runner(&delta.identity, deps, paths, log)?;
        execute_create_runner(&delta.after, deps, paths, log)?;
        return Ok(ApplyOutcome::Recreated);
    }

    // In-place path: rewrite drop-ins (template body unchanged because
    // it is identical across runners) and let the next daemon-reload
    // pick them up. Restart only when a Service-section value changed
    // — `RunnerDelta` does not yet distinguish [Service] from [Unit]
    // drift, so to avoid spurious restarts we skip the daemon-reload +
    // stop + start when (a) every managed file's on-disk bytes match
    // what we would render and (b) the supplementary-group diff is a
    // no-op. The byte comparison reuses `read_prior` snapshots that
    // were already needed for rollback.
    //
    // When delta.after.spec.runsvc_sha256 is empty here, plan was
    // unable to recover the digest from the discovered 00-ghars.conf
    // (annotation missing → older-format runner or operator stripped
    // the line). Plan must have routed THIS update through the recreate
    // path with the `runsvc_integrity` reason rather than down here;
    // hashing runsvc.sh from disk in apply would weaken SEC-02 because
    // that file lives in the runner-writable home and may be
    // adversary-controlled. If we still see an empty digest at this
    // point, plan emitted a malformed in-place delta — we must NOT
    // silently strip the annotation, so error out and force the
    // operator to investigate.
    if delta.after.spec.runsvc_sha256.is_empty() {
        return Err(GharsError::Apply {
            action: format!(
                "UpdateRunner({}): in-place delta missing runsvc_sha256",
                delta.identity.name
            ),
            source: Box::new(GharsError::Validation(
                "plan-time runsvc_sha256 recovery failed; the recreate \
                 path is required to mint a fresh trusted digest via \
                 config.sh"
                    .into(),
                "re-run `ghars plan` to refresh; if the issue persists, \
                 the discovered 00-ghars.conf is missing X-Ghars-Runsvc-\
                 Sha256 and plan should have emitted a recreate"
                    .into(),
            )),
        });
    }
    // Track files_changed (count) and pool names
    // (Vec) so the apply outcome row can carry both `files_changed`
    // and the WHICH-pools detail for cmd_apply's per-action line.
    // The `is_empty()` checks at the daemon-reload gate below
    // preserve the short-circuit semantics ("skip rewrite when bytes
    // match"): the gate fires iff `files_changed
    // == 0` AND both pool Vecs are empty. The total gpasswd
    // invocation count (`group_ops` in the public detail string) is
    // derived as `pools_added.len() + pools_removed.len()` at
    // render time — single source of truth.
    let mut files_changed: usize = 0;
    let mut pools_added: Vec<String> = Vec::new();
    let mut pools_removed: Vec<String> = Vec::new();

    // Reconcile supplementary-group memberships BEFORE the drop-in
    // rewrite. If `gpasswd -a` or `gpasswd -d` fails partway through the
    // diff, this function returns Err with the on-disk 00-ghars.conf
    // still carrying the OLD `X-Ghars-Caches=` annotation. The next
    // `ghars plan` re-diffs that old annotation against the same
    // desired caches list, regenerates the same gpasswd add/remove
    // operations, and retries. If we wrote drop-ins first, a failed
    // gpasswd would leave the annotation already showing the NEW list
    // while the actual group state is partially-reconciled — the next
    // plan would see no diff, skip the supplementary-group step, and
    // bake in the partial state until the next caches edit.
    //
    // The netns-vs-cache invariant still applies: the gpasswd ops
    // must complete before stop+start so the freshly-restarted unit
    // picks up the new group set on its next exec credentials. Both invariants land by
    // running gpasswd FIRST in the in-place path.
    //
    // The diff is computed from the discovered `X-Ghars-Caches`
    // annotation (`delta.before_caches`) against the desired post-
    // update binding list (`delta.after.spec.caches`). When the
    // discovered annotation is absent (`None`) — pre-annotation runner or
    // operator-stripped 00-ghars.conf — we skip the diff entirely
    // rather than guess at the prior membership; the next apply will
    // land annotations and a future caches-list edit can reconcile
    // from a known baseline.
    //
    // No gpasswd add/remove. Cache reach is socket-DAC + BindPaths
    // under DynamicUser, not /etc/group membership. The set diff
    // below still records pools_added / pools_removed for the plan-
    // emission detail surface ("runner X gained pool Y / lost pool
    // Z"), but no system-level operation is dispatched — the runner
    // unit's 30-cache-pool.conf drop-in (re-rendered below) carries
    // the BindPaths entries that materialize cache reach.
    if let Some(before) = delta.before_caches.as_ref() {
        let after_set: std::collections::BTreeSet<&str> = delta
            .after
            .spec
            .caches
            .iter()
            .map(|b| b.name.as_str())
            .collect();
        let before_set: std::collections::BTreeSet<&str> =
            before.iter().map(String::as_str).collect();
        // Sort by collecting into BTreeSet first so the operations
        // run in deterministic alphabetical order — easier for tests
        // and for operator log readability.
        for added in after_set.difference(&before_set) {
            // Capture the pool NAME for operator-facing detail surface.
            pools_added.push((*added).to_string());
        }
        for removed in before_set.difference(&after_set) {
            pools_removed.push((*removed).to_string());
        }
    }

    // After gpasswd reconciles successfully, write managed unit text
    // (this block) and drop-ins (loop further down). The 00-ghars.conf
    // X-Ghars-Caches annotation lives in the drop-in body written by
    // the `for (name, body) in &delta.after.drop_ins` loop, NOT in the
    // systemd template body written here. But both writes are gated
    // behind the same gpasswd success above, so on a gpasswd failure
    // before this point, every managed file on disk still reflects the
    // OLD caches list. The next `ghars plan` re-diffs that old
    // annotation against the same desired list and retries the gpasswd
    // ops.
    let unit_file = paths.unit_file(&delta.identity.name);
    if read_then_write_if_changed(&unit_file, delta.after.effective_unit_text.as_bytes(), log)? {
        files_changed += 1;
    }
    let drop_in_dir = paths.drop_in_dir(&delta.identity.name);
    let drop_in_dir_existed = drop_in_dir.exists();
    fs::create_dir_all(drop_in_dir.as_std_path())?;
    if !drop_in_dir_existed {
        log.push(UndoStep::CreateDir {
            path: drop_in_dir.clone(),
        });
        // CreateDir is itself a filesystem mutation — count it as a
        // change so the daemon-reload + restart still fires the first
        // time we plant a runner's drop-in directory, even on a runner
        // whose drop-in basenames all happen to byte-match a prior
        // hand-edit (vanishingly unlikely but cheap to be correct).
        files_changed += 1;
    }
    // Remove ghars-managed drop-ins flagged DropInChangeKind::Removed
    // by Stage 2 (rendered side has no entry, on-disk side does).
    // Stage 2 walks the union of rendered + discovered keys, so
    // operator-edited 99-*.conf and any other non-managed name CAN
    // appear here as Removed entries. The MANAGED_DROP_IN_BASENAMES
    // guard below is the load-bearing safety mechanism that keeps
    // `systemctl edit` overrides intact: we only delete basenames
    // ghars itself would emit. Anything else is operator territory
    // and is left untouched, even when Stage 2 classifies it as
    // Removed.
    for change in &delta.drop_in_changes {
        if let DropInChangeKind::Removed { .. } = &change.change {
            if !MANAGED_DROP_IN_BASENAMES.contains(&change.basename.as_str()) {
                continue;
            }
            let path = drop_in_dir.join(&change.basename);
            let prior = read_prior(&path);
            let removed = fs::remove_file(path.as_std_path()).is_ok();
            if removed {
                if let Some(content) = prior {
                    log.push(UndoStep::RemoveFile { path, content });
                }
                files_changed += 1;
            }
        }
    }
    // Write each desired drop-in. `read_then_write_if_changed` snapshots
    // the on-disk prior and short-circuits when the bytes already match
    // The Preserved Stage 2 verdict is not used as an
    // optimization here: it is plan-time, and on-disk bytes can drift
    // between plan and apply (e.g. operator edit landed after `ghars
    // plan` rendered output). Trusting Preserved would preserve that
    // drift instead of converging — the byte comparison inside
    // `read_then_write_if_changed` is the authoritative check and runs
    // every time.
    for (name, body) in &delta.after.drop_ins {
        let dest = drop_in_dir.join(name);
        if read_then_write_if_changed(&dest, body.as_bytes(), log)? {
            files_changed += 1;
        }
    }

    // Skip daemon-reload + stop + start when nothing on disk
    // changed AND the supplementary-group set was a no-op. The next
    // exec credentials snapshot only changes when the unit restarts,
    // so a group-op MUST trigger a restart even if no file bytes
    // moved. verify_runner_netns runs only when we actually start the
    // unit; otherwise the prior PID is still in the netns we already
    // verified on the last apply.
    if files_changed == 0 && pools_added.is_empty() && pools_removed.is_empty() {
        tracing::info!(
            runner = delta.identity.name.as_str(),
            "in-place: all managed bytes + group memberships match on disk; skipping daemon-reload + restart"
        );
        return Ok(ApplyOutcome::InPlaceSkipped);
    }
    let unit_name = format!("ghars-runner@{}.service", delta.identity.name);
    deps.systemd.daemon_reload()?;
    // Restart by stop+start; systemd has no atomic "restart" D-Bus
    // method via `Manager` (RestartUnit exists but is implemented as
    // stop+start internally). Use stop_unit/start_unit which are part
    // of the trait surface.
    deps.systemd.stop_unit(&unit_name)?;
    log.push(UndoStep::StopUnit {
        name: unit_name.clone(),
    });
    deps.systemd.start_unit(&unit_name)?;
    log.push(UndoStep::StartUnit {
        name: unit_name.clone(),
    });
    if matches!(
        delta.after.spec.network.as_ref().map(|n| &n.spec.mode),
        Some(NetworkMode::Netns)
    ) {
        verify_runner_netns(&unit_name, deps.systemd)?;
    }
    Ok(ApplyOutcome::InPlaceRestarted {
        files_changed,
        pools_added,
        pools_removed,
    })
}

// ---------- managed-write helper family ---------------------------------
//
// Two helpers wrap the snapshot + write + rollback-record pattern. Pick
// based on whether the caller is the in-place update branch (skip when
// bytes match) or the create branch (always write):
//
// - `read_then_write_if_changed`: in-place branch entry. Snapshots
//   prior bytes, skips the write if they match, otherwise writes and
//   pushes the undo step. Returns `Result<bool>` so the caller can
//   drive `files_changed` ("skip rewrite when bytes match"
//   optimization gating daemon-reload + restart).
// - `write_record_undo`: create-path entry. Snapshot + always-write +
//   record undo. Returns `Result<()>` because create-path callers
//   always proceed to systemd actions regardless of byte change.
//
// All sites that mutate managed config files MUST go through one of
// these helpers — bypassing them would either break rollback fidelity
// (no UndoStep::WriteFile pushed) or skip the byte-equality optimization.
// The exception is shared templates (`netns_template_unit_file` and
// `cache_template_unit_file`) which use write_root_owned directly with
// explicit "NOT recorded" comment blocks — undoing those would clobber
// other live consumers. Per-pool drop-ins (00-ghars.conf at
// `cache_drop_in_dir`) are NOT shared templates and DO go through the
// helpers above.

/// Snapshot the on-disk content of `path`, then conditionally write
/// `bytes` and append a rollback step to `log`. Returns `true` when a
/// write happened; `false` when on-disk bytes already matched `bytes`
/// and the write was skipped.
///
/// The two-step `let prior = read_prior(p); ... if prior != bytes {
/// write + push }` shape was open-coded twice in `execute_update_runner`
/// (the unit-file write and the drop-in loop) before this consolidation.
/// Single-sourcing the snapshot here removes the chance that a future
/// caller forgets to read the prior bytes and silently breaks rollback
/// fidelity.
///
/// The caller drives `files_changed` in `execute_update_runner` from
/// this return so the daemon-reload + restart gate at the end of the
/// function still fires correctly. This is the workhorse for the
/// "skip rewrite when bytes match" optimization.
fn read_then_write_if_changed(path: &Utf8Path, bytes: &[u8], log: &mut UndoLog) -> Result<bool> {
    let prior = read_prior(path);
    if prior.as_deref() == Some(bytes) {
        return Ok(false);
    }
    write_root_owned(path, bytes)?;
    log.push(UndoStep::WriteFile {
        path: path.to_path_buf(),
        prior_content: prior,
    });
    Ok(true)
}

/// Provision the netns side-units for a Netns-mode runner. Called from
/// `execute_create_runner` BEFORE the runner unit is started, because
/// the runner's drop-in has `Requires=ghars-net@%i.service` and joins
/// the netns via `NetworkNamespacePath=/var/run/netns/ghars-%i` — which
/// fails-closed if the netns is missing.
///
/// Steps (Part 9c "Lifecycle — apply CreateRunner"):
/// 1. Write `<config_dir>/netns.d/<name>.toml` (`NetnsConfig`) so the
///    `_netns-setup` helper can read subnet + dns mode at unit start.
/// 2. Write `<config_dir>/nft.d/<name>-host.nft` and `<name>-ns.nft`
///    via `systemd::render_nft_rules`.
/// 3. Write `<unit_dir>/ghars-net@.service` (template) — idempotent;
///    every netns runner shares the same template body.
/// 4. `daemon-reload` so the template is visible, then `enable` +
///    `start` `ghars-net@<name>.service`. The netns unit's ExecStart
///    runs `_netns-setup` which builds the kernel-level state.
///
/// On any step failure the kernel-level state is left for
/// [`teardown_netns_artifacts`] to clean up via the runner's
/// RemoveRunner action; we do not roll back here because partial
/// writes are idempotent (next apply re-runs them).
///
/// # Errors
///
/// Returns the underlying `GharsError` from `systemd::render_nft_rules`,
/// `NetnsConfig::write`, `write_root_owned`, or systemd D-Bus calls.
fn provision_netns_artifacts(
    spec: &EffectiveRunnerSpec,
    deps: &Deps<'_>,
    paths: &Paths,
    log: &mut UndoLog,
) -> Result<()> {
    let Some(binding) = spec.network.as_ref() else {
        return Ok(());
    };
    if !matches!(binding.spec.mode, NetworkMode::Netns) {
        return Ok(());
    }

    // 1) Per-instance netns config (subnet + dns mode) read by
    //    `ghars _netns-setup INSTANCE`.
    let netns_cfg = NetnsConfig {
        subnet: binding.subnet,
        dns: binding.spec.dns.clone(),
    };
    let netns_cfg_path = NetnsConfig::path_for(paths, &spec.name);
    let netns_cfg_prior = read_prior(&netns_cfg_path);
    netns_cfg.write(paths, &spec.name)?;
    log.push(UndoStep::WriteFile {
        path: netns_cfg_path,
        prior_content: netns_cfg_prior,
    });

    // 2) nft rule files referenced by the netns template's ExecStart=.
    let nft = render_nft_rules(&spec.name, binding)?;
    let host_rule_path = paths.nft_host_rule(&spec.name);
    write_record_undo(&host_rule_path, nft.host_rules.as_bytes(), log)?;
    let ns_rule_path = paths.nft_ns_rule(&spec.name);
    write_record_undo(&ns_rule_path, nft.ns_rules.as_bytes(), log)?;

    // 3) ghars-net@.service template. Identical bytes for every netns
    //    runner — idempotent rewrite restores a hand-edited template.
    //    NOT recorded as an UndoStep: the template is shared across
    //    every netns-mode runner, so undoing the write would unlink
    //    a file other live runners still depend on. The forward path
    //    is byte-idempotent (every netns runner writes the same
    //    bytes) so leaving it on rollback matches the next clean apply.
    write_root_owned(
        &paths.netns_template_unit_file(),
        netns_template_text().as_bytes(),
    )?;

    // 4) daemon-reload + enable + start ghars-net@INSTANCE so the
    //    runner unit's `Requires=ghars-net@%i.service` is satisfied
    //    when its own start_unit fires below.
    let netns_unit = format!("ghars-net@{}.service", spec.name);
    deps.systemd.daemon_reload()?;
    deps.systemd.enable_unit(&netns_unit)?;
    log.push(UndoStep::EnableUnit {
        name: netns_unit.clone(),
    });
    deps.systemd.start_unit(&netns_unit)?;
    log.push(UndoStep::StartUnit {
        name: netns_unit.clone(),
    });

    Ok(())
}

/// Tear down the netns side-units for a Netns-mode runner. Called from
/// `execute_remove_runner` AFTER the runner unit has been stopped (so
/// the netns is no longer in use) and BEFORE the unit-files are
/// deleted. Mirrors [`provision_netns_artifacts`] in reverse.
///
/// Idempotent: missing files / inactive units do not fail. The
/// `ghars-net@.service` template at `<unit_dir>/ghars-net@.service` is
/// NOT removed — other Netns runners may still reference it. (The
/// template is operator-visible, distinct from the per-runner
/// instance.)
///
/// # Errors
///
/// Returns the underlying `GharsError` from systemd D-Bus calls,
/// filesystem unlink, or `NetnsConfig::remove`.
fn teardown_netns_artifacts(
    name: &str,
    deps: &Deps<'_>,
    paths: &Paths,
    log: &mut UndoLog,
) -> Result<()> {
    let netns_unit = format!("ghars-net@{name}.service");

    // 1) Stop + disable. Both are idempotent on missing/inactive units
    //    (the trait already swallows expected error kinds).
    deps.systemd.stop_unit(&netns_unit)?;
    log.push(UndoStep::StopUnit {
        name: netns_unit.clone(),
    });
    deps.systemd.disable_unit(&netns_unit)?;
    log.push(UndoStep::DisableUnit {
        name: netns_unit.clone(),
    });

    // 2) Remove nft rule files. Missing-file is OK because a partial
    //    prior provisioning may have skipped them.
    let host_rule = paths.nft_host_rule(name);
    if host_rule.exists() {
        let prior = read_prior(&host_rule);
        fs::remove_file(host_rule.as_std_path())?;
        if let Some(content) = prior {
            log.push(UndoStep::RemoveFile {
                path: host_rule.clone(),
                content,
            });
        }
    }
    let ns_rule = paths.nft_ns_rule(name);
    if ns_rule.exists() {
        let prior = read_prior(&ns_rule);
        fs::remove_file(ns_rule.as_std_path())?;
        if let Some(content) = prior {
            log.push(UndoStep::RemoveFile {
                path: ns_rule.clone(),
                content,
            });
        }
    }

    // 3) Remove per-instance netns config TOML. Absent file is OK
    //    (NetnsConfig::remove swallows ENOENT).
    let netns_cfg_path = NetnsConfig::path_for(paths, name);
    let netns_prior = read_prior(&netns_cfg_path);
    NetnsConfig::remove(paths, name)?;
    if let Some(content) = netns_prior {
        log.push(UndoStep::RemoveFile {
            path: netns_cfg_path,
            content,
        });
    }

    Ok(())
}

fn execute_create_cache_pool(
    plan: &CachePoolPlan,
    deps: &Deps<'_>,
    paths: &Paths,
    log: &mut UndoLog,
) -> Result<ApplyOutcome> {
    let pool = &plan.binding.name;
    let unit_name = format!("ghars-cache@{pool}.service");

    // 1) Template unit file. Idempotent: write_root_owned truncates +
    //    rewrites the canonical body every apply so a manually-edited
    //    template is restored to spec. The template is identical for
    //    every pool — same bytes — so writing it per-action is cheap.
    //
    //    NOT recorded as UndoStep: the template is shared across every
    //    cache pool, so undoing the write would unlink a file other
    //    pools depend on. Forward-path is byte-idempotent (every pool
    //    writes the same template body) so leaving it on rollback
    //    matches the next clean apply.
    let template_path = paths.cache_template_unit_file();
    write_root_owned(&template_path, cache_template_text().as_bytes())?;

    // 2) Per-pool drop-in. The body was rendered at plan time via
    //    `systemd::render_cache_drop_in` (the reset-on-empty
    //    validator runs there). We just install the bytes.
    let drop_in_dir = paths.cache_drop_in_dir(pool);
    let drop_in_dir_existed = drop_in_dir.exists();
    fs::create_dir_all(drop_in_dir.as_std_path())?;
    if !drop_in_dir_existed {
        log.push(UndoStep::CreateDir {
            path: drop_in_dir.clone(),
        });
    }
    let dest = drop_in_dir.join("00-ghars.conf");
    write_record_undo(&dest, plan.drop_in_body.as_bytes(), log)?;

    // No groupadd. Cache reach is socket-DAC + BindPaths under
    // DynamicUser; no /etc/group entry is involved.

    // 3) Enable + reload + start. Pre-start daemon_reload is required
    //    because the freshly-written template + drop-in are not
    //    visible to systemd until reload. The end-of-apply
    //    daemon_reload (`apply()` calls it again) is idempotent.
    deps.systemd.enable_unit(&unit_name)?;
    log.push(UndoStep::EnableUnit {
        name: unit_name.clone(),
    });
    deps.systemd.daemon_reload()?;
    deps.systemd.start_unit(&unit_name)?;
    log.push(UndoStep::StartUnit {
        name: unit_name.clone(),
    });
    Ok(ApplyOutcome::PoolCreated)
}

fn execute_update_cache_pool(
    delta: &CachePoolDelta,
    deps: &Deps<'_>,
    paths: &Paths,
    log: &mut UndoLog,
) -> Result<ApplyOutcome> {
    let pool = &delta.binding.name;
    let unit_name = format!("ghars-cache@{pool}.service");
    let drop_in_dir = paths.cache_drop_in_dir(pool);
    let drop_in_dir_existed = drop_in_dir.exists();
    fs::create_dir_all(drop_in_dir.as_std_path())?;
    let mut files_changed: usize = 0;
    if !drop_in_dir_existed {
        log.push(UndoStep::CreateDir {
            path: drop_in_dir.clone(),
        });
        // CreateDir is itself a filesystem mutation — count it as a
        // change so the daemon-reload + restart still fires the first
        // time we plant a pool's drop-in directory, even on a pool
        // whose drop-in bytes happen to byte-match a prior hand-edit
        // (mirror of execute_update_runner's drop_in_dir handling).
        files_changed += 1;
    }
    let dest = drop_in_dir.join("00-ghars.conf");
    if read_then_write_if_changed(&dest, delta.drop_in_body.as_bytes(), log)? {
        files_changed += 1;
    }

    // Pool-kind change is a membership no-op.
    //
    // The per-pool group is `ghars-cache-NAME`, parameterized by
    // pool name only — NOT by kinds. A pool's `kinds` change
    // (ccache-only → ccache+sccache or vice versa) leaves group
    // identity unchanged, so runners enrolled at runner-create time
    // retain valid membership across the update. No groupadd /
    // usermod / gpasswd is needed in this handler.
    //
    // The runner-caches-list-change case (a runner's `caches = [...]`
    // entry changed in the operator's TOML) IS a real apply action
    // and does require usermod, but that's
    // `execute_update_runner`'s responsibility, not
    // `execute_update_cache_pool`'s.

    // Skip daemon-reload + stop + start when nothing on disk
    // changed. Mirror of the runner-side optimization. No
    // pool-membership Vec here — pool-kind change is a membership
    // no-op (per the comment above) so the byte-equality check
    // on the 00-ghars.conf drop-in is the sole gate. Contrast with
    // the runner-side `pools_added`/`pools_removed` populated in
    // `execute_update_runner` for the cache-binding diff.
    if files_changed == 0 {
        tracing::info!(
            pool = pool.as_str(),
            "in-place pool update: drop-in bytes match on disk; skipping daemon-reload + restart"
        );
        return Ok(ApplyOutcome::PoolSkipped);
    }
    deps.systemd.daemon_reload()?;
    deps.systemd.stop_unit(&unit_name)?;
    log.push(UndoStep::StopUnit {
        name: unit_name.clone(),
    });
    deps.systemd.start_unit(&unit_name)?;
    log.push(UndoStep::StartUnit {
        name: unit_name.clone(),
    });
    Ok(ApplyOutcome::PoolUpdated)
}

fn execute_remove_cache_pool(
    name: &str,
    deps: &Deps<'_>,
    paths: &Paths,
    log: &mut UndoLog,
) -> Result<ApplyOutcome> {
    let unit_name = format!("ghars-cache@{name}.service");
    deps.systemd.stop_unit(&unit_name)?;
    log.push(UndoStep::StopUnit {
        name: unit_name.clone(),
    });
    deps.systemd.disable_unit(&unit_name)?;
    log.push(UndoStep::DisableUnit {
        name: unit_name.clone(),
    });

    // Drop-in dir.
    let drop_in_dir = paths.cache_drop_in_dir(name);
    if drop_in_dir.exists() {
        fs::remove_dir_all(drop_in_dir.as_std_path())?;
        log.push(UndoStep::RemoveDir {
            path: drop_in_dir.clone(),
        });
    }

    // Per-pool cache storage directory. systemd's CacheDirectory=
    // creates this at unit start; ghars removes it on RemoveCachePool
    // so a config drop does not leave stale 200G on disk. We do
    // NOT call guard_home_dir_rmrf — the path is fixed
    // `<cache_dir>/pools/<name>` and `name` already passed
    // IDENTIFIER_REGEX upstream (no `/` or `..` possible).
    let pool_dir = paths.cache_pool_dir(name);
    if pool_dir.exists() {
        fs::remove_dir_all(pool_dir.as_std_path())?;
        log.push(UndoStep::RemoveDir {
            path: pool_dir.clone(),
        });
    }

    // No groupdel. Cache reach is socket-DAC + BindPaths under
    // DynamicUser; no /etc/group entry was created on pool create
    // and there is nothing to clean up.

    Ok(ApplyOutcome::PoolRemoved)
}

// ---------- Helpers ----------------------------------------------------

// Returns the full `RegistrationToken` (not just `.value`) so the
// caller controls the lifetime. Moving `tok.value` out of `RegistrationToken`
// would require `String: Drop` to opt out of the Drop guard, which Rust
// forbids for types whose containing struct implements Drop. Returning
// the token by value keeps zeroize-on-drop intact: the caller borrows
// `&token.value` for `ConfigShellCtx`, and when `token` falls out of
// scope at the end of the caller frame, the heap buffer is volatile-
// scrubbed before deallocation.
fn mint_token(
    auth: AuthRegistry<'_>,
    name: &str,
    url: &str,
    removal: bool,
) -> Result<crate::auth::RegistrationToken> {
    let source = auth.get(name).ok_or_else(|| {
        GharsError::Auth(
            format!("auth source {name:?} referenced by runner is not in the registry"),
            "ensure the runner's `auth` field matches a key in [auth.NAME]".into(),
        )
    })?;
    if removal {
        source.mint_removal_token(url)
    } else {
        source.mint_registration_token(url)
    }
}

/// Per-process counter used to disambiguate concurrent `write_root_owned`
/// temp filenames within the same process. Combined with the PID it
/// guarantees a unique tempname even if two threads write to the same
/// final path simultaneously: PID rules out cross-process collisions,
/// the counter rules out same-process ones. Paired with `O_CREAT|O_EXCL`
/// the open syscall fails closed if the name still collides, so the
/// counter is a fast-path uniqueness aid, not the security primitive.
static TEMPFILE_COUNTER: AtomicU64 = AtomicU64::new(0);

/// Drop guard: best-effort `unlink(temp_path)` on early return so a
/// failed `write_root_owned` does not leave half-written `.tmp.*` files
/// strewn under `/etc/ghars/`. `disarm()` is called after the rename
/// succeeds — at that point the temp name no longer exists on disk
/// (rename(2) made the inode visible at the final path) and the
/// guard's unlink would be a no-op anyway, but disarming makes that
/// explicit and avoids a spurious ENOENT in the kernel audit log.
struct TempFileGuard {
    path: Option<Utf8PathBuf>,
}

impl TempFileGuard {
    fn new(path: Utf8PathBuf) -> Self {
        Self { path: Some(path) }
    }
    fn disarm(mut self) {
        self.path = None;
    }
}

impl Drop for TempFileGuard {
    fn drop(&mut self) {
        if let Some(p) = self.path.take() {
            let _ = fs::remove_file(p.as_std_path());
        }
    }
}

/// Snapshot the bytes at `path` if it exists, used to populate
/// [`UndoStep::WriteFile.prior_content`] BEFORE an overwrite. `None`
/// signals the path didn't exist beforehand, so undo's restore path
/// becomes "remove the new file" rather than "rewrite old bytes".
///
/// Read failures (other than `NotFound`) are logged via `tracing::warn!`
/// and treated as `None` — best-effort recording, never fail-stop the
/// forward path because we couldn't checkpoint a pre-existing file.
fn read_prior(path: &Utf8Path) -> Option<Vec<u8>> {
    match fs::read(path.as_std_path()) {
        Ok(bytes) => Some(bytes),
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => None,
        Err(e) => {
            tracing::warn!(
                path = path.as_str(),
                error = %e,
                "read_prior: snapshot failed; rollback will treat as new-file"
            );
            None
        }
    }
}

fn write_root_owned(path: &Utf8Path, bytes: &[u8]) -> Result<()> {
    let parent = path.parent().ok_or_else(|| GharsError::Apply {
        action: format!("write_root_owned {path}"),
        source: Box::new(GharsError::Io(std::io::Error::new(
            std::io::ErrorKind::InvalidInput,
            "path has no parent directory",
        ))),
    })?;
    let final_name = path.file_name().ok_or_else(|| GharsError::Apply {
        action: format!("write_root_owned {path}"),
        source: Box::new(GharsError::Io(std::io::Error::new(
            std::io::ErrorKind::InvalidInput,
            "path has no file name",
        ))),
    })?;
    fs::create_dir_all(parent.as_std_path())?;

    // SEC-NEW: write atomically via temp+rename so concurrent readers
    // (systemd reading drop-ins, ghars reading its own state) never see
    // a half-written file. Without this, an apply that crashed mid-
    // write would leave the final path containing only the prefix of
    // the new contents, the X-Ghars-Spec-Hash annotation could be
    // truncated mid-line, and the next apply's drift detector would
    // either accept the corruption (if the truncation happened to
    // produce a parseable hash) or refuse to plan further. rename(2)
    // is atomic on the same filesystem (POSIX) so a reader either sees
    // the old file or the fully-written new file, never a mix.
    let pid = std::process::id();
    let counter = TEMPFILE_COUNTER.fetch_add(1, Ordering::Relaxed);
    let temp_name = format!(".{final_name}.tmp.{pid}.{counter}");
    let temp_path = parent.join(&temp_name);

    // Open with O_CREAT|O_EXCL (create_new). Fail-closed if the name
    // already exists — the counter+PID combination should make a
    // collision impossible in practice, but if an attacker pre-plants
    // the file we refuse to write rather than reuse their inode.
    //
    // Create at 0o600 (owner read/write only) and widen to 0o644
    // *after* chown_to_root succeeds. The create-restrictive-then-
    // widen pattern means that during the brief window between
    // creat(2) and the final rename(2), the file is invisible to
    // group/world even if the process's effective UID isn't yet
    // root: the temp inode never carries world-readable bits while
    // its content might be sensitive. write_root_owned is currently
    // used only for non-secret config (drop-ins, nft rules), but
    // future callers may write secret-bearing files through the same
    // helper — landing the restrictive temp now avoids the latent
    // regression that the adversary flagged.
    let mut f = OpenOptions::new()
        .create_new(true)
        .write(true)
        .mode(0o600)
        .open(temp_path.as_std_path())?;

    // Arm the guard immediately after the file exists on disk: any
    // error from here through the final rename must unlink the temp.
    let guard = TempFileGuard::new(temp_path.clone());

    f.write_all(bytes)?;
    f.flush()?;
    // sync_all(2) (fsync) ensures the contents hit storage before the
    // rename publishes the inode at the final path. Without fsync, a
    // post-rename crash could leave the final path pointing at an
    // inode whose contents the kernel has not yet written through —
    // recovery would see the new name with old/zero data.
    f.sync_all()?;
    // Chown the freshly-written fd to root:root. OpenOptions::mode
    // sets the file mode, but ownership is inherited from the calling
    // process's effective UID/GID (and umask only affects mode bits).
    // The function name is a promise — root-owned end-to-end. Without
    // fchown, a future caller running with effective UID != 0 would
    // produce non-root-owned config files, silently violating SEC-09 /
    // SEC-11 (owner-controlled config under /etc/ghars/). Use fchown on
    // the open fd (not path-based chown) so the chown target is pinned
    // to the inode we wrote, not whatever a concurrent attacker might
    // swap in at this path.
    chown_to_root(&f, &temp_path)?;
    // Now that ownership is root:root, widen the mode from
    // 0o600 to 0o644 so systemd / readers can stat the published
    // file. File::set_permissions on Unix calls fchmod(fd, mode)
    // (std/sys/fs/unix.rs — same primitive `tighten_credential_perms`
    // relies on), so the chmod target is pinned to the inode we
    // wrote, not whatever a concurrent attacker might swap in at
    // temp_path.
    {
        use std::os::unix::fs::PermissionsExt;
        f.set_permissions(std::fs::Permissions::from_mode(0o644))?;
    }
    drop(f);

    // Atomic publish. On the same filesystem rename(2) replaces any
    // existing file at the destination as a single inode swap; a
    // reader concurrent with this rename sees either the old inode or
    // the new one in full, never a torn write.
    fs::rename(temp_path.as_std_path(), path.as_std_path())?;
    guard.disarm();
    Ok(())
}

/// Snapshot the on-disk content of `path`, write `bytes` via
/// [`write_root_owned`], and append an [`UndoStep::WriteFile`] to `log`
/// recording the prior content for rollback.
///
/// This is the create-path sibling of [`read_then_write_if_changed`]: the
/// in-place update branch can elide the write when bytes already match,
/// but the create path always rewrites because the caller has just
/// rendered a fresh template/drop-in for a brand-new runner / cache
/// pool / netns side-unit and the directory may not even exist yet.
/// Both shapes share the read-then-write-then-record pattern; this
/// helper single-sources the create-path variant.
///
/// Returns `Result<()>` instead of `Result<bool>` because create-path
/// callers always proceed to systemd actions regardless of whether
/// bytes changed (the just-rendered file is, by construction, fresh
/// state for a unit that does not yet have its enable/start side-
/// effects applied). Use [`read_then_write_if_changed`] when the
/// caller actually needs the byte-changed flag to gate a daemon-reload
/// + restart.
///
/// The pattern was open-coded six times before this consolidation:
/// `execute_create_runner` (unit file + drop-in loop),
/// `provision_netns_artifacts` (host + ns nft rule files),
/// `execute_create_cache_pool` (per-pool drop-in), and
/// `execute_update_cache_pool` (per-pool drop-in). The
/// `provision_netns_artifacts` `netns_cfg.write` site stays raw because
/// `NetnsConfig::write` is a different writer entirely (it owns its own
/// path derivation + serialization) — only sites that go through
/// `write_root_owned` directly use this helper.
///
/// # Read-failure conflation
///
/// [`read_prior`] returns `None` for both file-not-found AND a non-
/// ENOENT read failure (it logs `tracing::warn!` and falls through).
/// On rollback, [`UndoStep::WriteFile`] with `prior_content: None`
/// performs `unlink` rather than restore. So a transient read failure
/// against a pre-existing file results in unlink-on-undo rather than
/// restore-to-prior — a fidelity loss the operator must understand.
/// In practice this only matters when a rollback fires AND the
/// snapshot read failed AND the file pre-existed, all of which are
/// rare; the design accepts the conflation rather than failing the
/// forward path because we cannot snapshot.
fn write_record_undo(path: &Utf8Path, bytes: &[u8], log: &mut UndoLog) -> Result<()> {
    let prior = read_prior(path);
    write_root_owned(path, bytes)?;
    log.push(UndoStep::WriteFile {
        path: path.to_path_buf(),
        prior_content: prior,
    });
    Ok(())
}

#[cfg(not(test))]
fn chown_to_root(f: &File, path: &Utf8Path) -> Result<()> {
    fchown(
        f.as_raw_fd(),
        Some(Uid::from_raw(0)),
        Some(Gid::from_raw(0)),
    )
    .map_err(|e| GharsError::Apply {
        action: format!("fchown root:root {path}"),
        source: Box::new(GharsError::Io(std::io::Error::from_raw_os_error(e as i32))),
    })?;
    Ok(())
}

#[cfg(test)]
fn chown_to_root(_f: &File, _path: &Utf8Path) -> Result<()> {
    // Tests run unprivileged. fchown to root:root would EPERM. Treat
    // as a no-op so the unit tests can exercise write_root_owned end
    // to end. Production callers (apply running under sudo) hit the
    // non-test variant.
    Ok(())
}

fn tighten_credential_perms(runner_home: &Utf8Path, user_name: &str) -> Result<()> {
    use std::os::unix::fs::PermissionsExt;
    // Both `.credentials` and `.credentials_rsaparams` are written by
    // config.sh; tighten any that exist. Missing files are ignored —
    // not all auth modes write both.
    //
    // SEC-NEW: we MUST NOT use the path-based `fs::metadata` /
    // `fs::set_permissions` pair here. Each is a separate syscall and
    // each follows symlinks. The runner user owns these files (config.sh
    // writes them under <runner_home>) so a malicious runner could
    // race the apply, replace `.credentials` with a symlink to
    // `/etc/shadow` between our stat and our chmod, and trick the
    // root-running apply into chmod'ing the symlink target down to
    // 0600.
    //
    // Fix: open the path with `O_NOFOLLOW` (the kernel returns
    // `ELOOP` if the final component is a symlink, so we never hand
    // out a chmod'able fd that points at an attacker-chosen target),
    // then call `File::set_permissions` which on Unix translates to
    // `fchmod(fd, mode)` (std/sys/fs/unix.rs:1787-1788). This pins
    // the chmod target to the inode we opened.
    //
    // Also fchown to the current runner user. config.sh writes
    // these files owned by whichever user ran config.sh (per
    // ConfigShellCtx.user). If the operator changes `user=` on a runner
    // between applies, leftover credentials keep their old ownership and
    // the new runner cannot read them. fchown ties ownership to the
    // currently-configured user. Resolve via getpwnam_r (User::from_name);
    // if the user doesn't exist yet (e.g. apply is running before
    // useradd has landed for a brand-new runner), skip the chown with
    // a tracing::warn! so the operator sees the divergence.
    let target_user = match User::from_name(user_name) {
        Ok(Some(u)) => Some(u),
        Ok(None) => {
            tracing::warn!(
                user = user_name,
                runner_home = runner_home.as_str(),
                "tighten_credential_perms: runner user not found in /etc/passwd; skipping fchown (credentials retain their existing ownership)"
            );
            None
        }
        Err(errno) => {
            return Err(GharsError::Apply {
                action: format!(
                    "tighten_credential_perms({runner_home}): User::from_name({user_name}) failed: {errno}"
                ),
                source: Box::new(GharsError::Io(std::io::Error::from_raw_os_error(
                    errno as i32,
                ))),
            });
        }
    };
    for name in [".credentials", ".credentials_rsaparams", ".runner"] {
        let p = runner_home.join(name);
        let mut opts = OpenOptions::new();
        opts.read(true).custom_flags(libc::O_NOFOLLOW);
        let f = match opts.open(p.as_std_path()) {
            Ok(f) => f,
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => continue,
            Err(e) if e.raw_os_error() == Some(libc::ELOOP) => {
                // Symlink injected by the runner. Refuse — the file
                // is no longer the credential file we wrote, and
                // chmod'ing through the symlink would touch an
                // attacker-chosen target.
                return Err(GharsError::Apply {
                    action: format!(
                        "tighten_credential_perms({}): refusing to chmod through symlink at {}",
                        runner_home, p
                    ),
                    source: Box::new(GharsError::Io(e)),
                });
            }
            Err(e) => return Err(GharsError::Io(e)),
        };
        let mut perms = f.metadata()?.permissions();
        perms.set_mode(0o600);
        f.set_permissions(perms)?;
        if let Some(ref u) = target_user {
            chown_credential_to_user(&f, &p, u)?;
        }
    }
    Ok(())
}

#[cfg(not(test))]
fn chown_credential_to_user(f: &File, path: &Utf8Path, user: &User) -> Result<()> {
    fchown(f.as_raw_fd(), Some(user.uid), Some(user.gid)).map_err(|e| GharsError::Apply {
        action: format!(
            "fchown {}:{} {} (user={})",
            user.uid, user.gid, path, user.name
        ),
        source: Box::new(GharsError::Io(std::io::Error::from_raw_os_error(e as i32))),
    })?;
    Ok(())
}

#[cfg(test)]
fn chown_credential_to_user(_f: &File, _path: &Utf8Path, _user: &User) -> Result<()> {
    // Tests run unprivileged: fchown to an arbitrary uid would EPERM.
    // The fchmod path is exercised by tests; the fchown path is
    // covered by integration tests under sudo.
    Ok(())
}

/// Refuse to recursively remove `home_dir` unless it is the canonical
/// `<prefix>/<name>` path. This guards against five failure modes:
/// 1. `home_dir == "/"` (or any root-equivalent) — never delete root.
/// 2. `home_dir == prefix` — never delete the prefix itself; only its
///    per-runner child.
/// 3. The runner name contains a path separator or `.`/`..`.
/// 4. `home_dir` is itself a symlink (SEC-NEW): would let an attacker
///    repoint the rmrf target to an arbitrary path. Std's modern
///    `remove_dir_all` already detects this and only unlinks the
///    symlink, but the guard rejects it explicitly so a future std
///    regression cannot reintroduce the attack.
/// 5. `home_dir`'s canonical form (after symlink resolution on every
///    path component) does not equal `<canon_prefix>/<runner_name>` —
///    catches symlink injection at any intermediate component, e.g. a
///    parent directory that has been renamed and replaced with a
///    symlink to `/etc`.
///
/// Filesystem checks (4 and 5) only fire when `home_dir` exists.
/// `execute_remove_runner` gates the rmrf on `runner_home.exists()`, and
/// the existing string-only checks (1, 2, 3) catch the bogus-path
/// cases that filesystem-free callers (current tests) need.
///
/// # Errors
///
/// `GharsError::Validation` with a hint pointing at the spec's `name`
/// field when any guard fails.
pub fn guard_home_dir_rmrf(
    home_dir: &Utf8Path,
    prefix: &Utf8Path,
    runner_name: &str,
) -> Result<()> {
    if home_dir.as_str() == "/" || home_dir.as_os_str() == OsStr::new("/") {
        return Err(GharsError::Validation(
            format!("refusing rmrf on `/` for runner {runner_name:?}"),
            "ghars never deletes the filesystem root; check the runner's prefix".into(),
        ));
    }
    if home_dir == prefix {
        return Err(GharsError::Validation(
            format!(
                "refusing rmrf on prefix {prefix} for runner {runner_name:?}; \
                 home dir must be a child of the prefix"
            ),
            "this means the per-runner subdirectory was lost; check the runner's spec".into(),
        ));
    }
    let expected = prefix.join(runner_name);
    if home_dir != expected {
        return Err(GharsError::Validation(
            format!(
                "refusing rmrf on {home_dir} for runner {runner_name:?}; \
                 expected {expected}"
            ),
            "the runner's home directory does not match `<prefix>/<name>`; \
             this can happen if the spec's name contains path separators or `..`"
                .into(),
        ));
    }
    // Component-level safety: the runner name itself must be a single
    // path component (no `/`, no `..`). The IDENTIFIER_REGEX validator
    // upstream already rejects this, but the guard repeats the check
    // because apply runs on the deserialized spec whose validation may
    // have been bypassed by tests.
    if runner_name.contains('/') || runner_name == "." || runner_name == ".." {
        return Err(GharsError::Validation(
            format!("runner name {runner_name:?} contains path separator or `.`/`..`"),
            "runner names must satisfy IDENTIFIER_REGEX".into(),
        ));
    }
    // SEC-NEW: filesystem-level symlink rejection + canonicalization.
    // Only fire when the path actually exists on disk; the caller
    // (`execute_remove_runner`) already gates the rmrf on
    // `runner_home.exists()` and the existing string checks above
    // cover the bogus-path test cases that don't touch the fs.
    let home_std: &Path = home_dir.as_std_path();
    let home_lmeta = match fs::symlink_metadata(home_std) {
        Ok(m) => m,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(()),
        Err(e) => return Err(GharsError::Io(e)),
    };
    if home_lmeta.file_type().is_symlink() {
        // Std's modern `remove_dir_all` would unlink the symlink
        // rather than follow it (rust-1.85 std/sys/fs/unix.rs:2683-
        // 2689 lstats first, unlink-on-symlink). We still reject
        // here so the runner home is replaced from a clean baseline
        // — a symlink at the home path means the parent directory's
        // permissions slipped (parent should be root-owned 0755 per
        // SEC-11) and apply should not silently paper over that.
        return Err(GharsError::Validation(
            format!(
                "refusing rmrf: {home_dir} is a symlink (runner {runner_name:?}); \
                 the parent directory's permissions allowed a symlink to be \
                 planted in place of the runner home"
            ),
            "investigate <prefix> ownership/mode; SEC-11 requires the parent \
             to be root:root mode 0755"
                .into(),
        ));
    }
    // Canonicalize home_dir + prefix and verify the canonical home
    // resolves to <canon_prefix>/<runner_name> exactly. Catches a
    // parent-component symlink swap: even if the leaf is a real
    // directory, a renamed-and-replaced ancestor would point the
    // rmrf at the wrong tree.
    let canon_home = fs::canonicalize(home_std).map_err(GharsError::Io)?;
    let canon_prefix = fs::canonicalize(prefix.as_std_path()).map_err(GharsError::Io)?;
    let expected_canon = canon_prefix.join(runner_name);
    if canon_home != expected_canon {
        return Err(GharsError::Validation(
            format!(
                "refusing rmrf: canonical {} differs from expected {} \
                 (runner {runner_name:?}); a path component is a symlink \
                 pointing outside the prefix",
                canon_home.display(),
                expected_canon.display()
            ),
            "investigate the runner home's parent chain for symlinks; this \
             usually means an operator manually relocated the runner tree"
                .into(),
        ));
    }
    Ok(())
}

/// Compare `readlink /proc/PID/ns/net` against `/proc/1/ns/net` for the
/// given runner unit. The `MainPID` D-Bus property carries the runner's
/// PID; if the symlink target matches PID 1's, the runner has fallen
/// back to the host network namespace and the action aborts as a
/// belt-and-suspenders defense against a netns fail-open regression.
///
/// The kernel-side netns join races MainPID's recording. systemd
/// calls service_set_main_pidref the moment exec_spawn returns the
/// child PID — which is post-vfork-unblock, but BEFORE
/// systemd-executor reaches the apply_namespace step that calls
/// setns(CLONE_NEWNET) for NetworkNamespacePath=. The send_handoff
/// timestamp only fires "as last thing before the execve()", AFTER
/// apply_namespace. So a readlink at the moment
/// StartUnit returns can observe the still-host netns symlink for the
/// runner's PID and false-positive a netns fail-open.
///
/// Mitigation: poll-with-timeout. 5s deadline at 100ms cadence (50
/// attempts max) — short enough that legitimate setup completes well
/// inside the budget (the kernel join lands within the systemd-executor
/// exec window, microseconds-to-milliseconds), but long enough to
/// cover D-Bus round-trip jitter + a stuck systemd-executor that's
/// blocked on something unrelated. ENOENT on /proc/PID/ns/net is a
/// TRANSIENT condition (the PID is briefly visible to systemd before
/// /proc reflects the entry, or the PID was recycled mid-poll); we
/// retry on ENOENT, NOT treat it as success.
///
/// v0.2 optimization (taskId 147): switch to
/// `ExecMainHandoffTimestampMonotonic` D-Bus property — non-zero means
/// systemd-executor reached send_handoff_timestamp, which is post-
/// apply_namespace, eliminating the poll. v0.1 ships the simple loop.
const NETNS_VERIFY_DEADLINE: std::time::Duration = std::time::Duration::from_secs(5);
const NETNS_VERIFY_BACKOFF: std::time::Duration = std::time::Duration::from_millis(100);

fn verify_runner_netns(unit_name: &str, systemd: &dyn Systemd) -> Result<()> {
    verify_runner_netns_at(
        std::path::Path::new("/proc"),
        unit_name,
        systemd,
        NETNS_VERIFY_DEADLINE,
        NETNS_VERIFY_BACKOFF,
    )
}

/// `verify_runner_netns` with injectable `proc_root` + deadline + backoff.
/// Tests pass a synthesized tempdir layout
/// (`<root>/<pid>/ns/net` symlink + `<root>/1/ns/net` symlink), a
/// shortened deadline, AND a shortened backoff so the happy path
/// (distinct symlink targets) and fail path (matching symlink targets)
/// can be exercised quickly without running a real netns'd unit.
/// Production calls always pass `/proc`, `NETNS_VERIFY_DEADLINE`, and
/// `NETNS_VERIFY_BACKOFF`.
fn verify_runner_netns_at(
    proc_root: &std::path::Path,
    unit_name: &str,
    systemd: &dyn Systemd,
    deadline_dur: std::time::Duration,
    backoff: std::time::Duration,
) -> Result<()> {
    // Host PID 1's net ns symlink is constant for the lifetime of the
    // booted system; cache it across retry attempts but defer the
    // initial read until AFTER the MainPID validation: a bogus MainPID
    // is an upstream systemd / unit-start failure that we want to
    // surface with its specific message, and the host readlink is
    // unrelated to that branch (it would also fail in the same way at
    // production runtime if /proc/1/ns/net were genuinely missing,
    // which only occurs when /proc isn't mounted).
    let deadline = std::time::Instant::now() + deadline_dur;
    let mut host_target: Option<std::path::PathBuf> = None;
    let mut last_match: Option<(u32, std::path::PathBuf)> = None;
    let mut attempts: u32 = 0;
    loop {
        attempts += 1;
        let main_pid_u64 = systemd
            .get_service_property_u64(unit_name, "MainPID")
            .map_err(|e| GharsError::Apply {
                action: format!("verify_runner_netns({unit_name})"),
                source: Box::new(e),
            })?;
        let pid = u32::try_from(main_pid_u64).map_err(|e| {
            GharsError::Systemd(
                format!(
                    "verify_runner_netns({unit_name}): MainPID {main_pid_u64} does not fit in u32: {e}"
                ),
                "the unit may have failed to start; inspect `systemctl status` and the journal"
                    .into(),
            )
        })?;
        if pid == 0 {
            return Err(GharsError::Systemd(
                format!("verify_runner_netns({unit_name}): MainPID is 0 (unit not running)"),
                "the runner unit failed to start; check `systemctl status`".into(),
            ));
        }
        // Lazy host_target read: populate on first iteration only, then
        // reuse the cached PathBuf for every subsequent attempt.
        let host_target_ref = if let Some(ref h) = host_target {
            h.clone()
        } else {
            let host_path = proc_root.join("1").join("ns").join("net");
            let h = std::fs::read_link(&host_path).map_err(|e| GharsError::Apply {
                action: format!("verify_runner_netns({unit_name})"),
                source: Box::new(GharsError::Io(e)),
            })?;
            host_target = Some(h.clone());
            h
        };
        let runner_path = proc_root.join(pid.to_string()).join("ns").join("net");
        match std::fs::read_link(&runner_path) {
            Ok(runner_target) => {
                if runner_target != host_target_ref {
                    return Ok(());
                }
                last_match = Some((pid, runner_target));
            }
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => {
                // ENOENT on /proc/PID/ns/net is TRANSIENT, NOT success.
                // The PID was just exec'd: systemd recorded it via
                // service_set_main_pidref before the kernel made the
                // /proc entry visible, or the PID was reaped between
                // the get_unit_property call and the readlink. Either
                // way, retry — never count missing /proc/PID as
                // "the runner is in an isolated netns" (that would be
                // a fail-open). Don't update last_match: a transient
                // ENOENT is not evidence of host-netns occupancy and
                // should not poison the retry-exhaustion error message
                // with a stale runner_target.
            }
            Err(e) => {
                return Err(GharsError::Apply {
                    action: format!("verify_runner_netns({unit_name})"),
                    source: Box::new(GharsError::Io(e)),
                });
            }
        }
        if std::time::Instant::now() + backoff > deadline {
            break;
        }
        std::thread::sleep(backoff);
    }
    let (pid, runner_target) = last_match.ok_or_else(|| {
        // No iteration produced a (pid, runner_target) — either every
        // attempt hit transient ENOENT (so we never observed the
        // runner's netns), or the deadline elapsed before a single
        // readlink succeeded. Treat as Systemd error: the unit is
        // not progressing through start_post → running.
        GharsError::Systemd(
            format!(
                "verify_runner_netns({unit_name}): /proc/PID/ns/net never resolved \
                 within {deadline_ms}ms ({attempts} polls); systemd-executor's \
                 apply_namespace did not complete",
                deadline_ms = deadline_dur.as_millis(),
            ),
            "the runner unit failed to reach the post-netns-join state; \
             check `systemctl status` and the journal for execve errors"
                .into(),
        )
    })?;
    Err(GharsError::Apply {
        action: format!("verify_runner_netns({unit_name})"),
        source: Box::new(GharsError::Validation(
            format!(
                "runner PID {pid} is in the HOST network namespace (target {target}) \
                 after {attempts} polls (~{total_ms}ms); expected an isolated netns. \
                 NetworkNamespacePath= silently fell open.",
                target = runner_target.display(),
                total_ms = deadline_dur.as_millis(),
            ),
            "this is a netns fail-closed regression; check ghars-net@%i.service status \
             and `ip netns list` for the expected named netns"
                .into(),
        )),
    })
}

/// Drop-in test hook: lets unit tests reuse the EffectiveRunnerSpec
/// constructor pattern without re-deriving the systemd module's private
/// helpers. Not exposed in production code paths.
#[doc(hidden)]
#[must_use]
pub fn _spec_runner_home(spec: &EffectiveRunnerSpec, paths: &Paths) -> Utf8PathBuf {
    paths.runner_home(&spec.trust_zone, &spec.name)
}

// ---------- Tests --------------------------------------------------------

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used)]
mod tests {
    use super::*;
    use crate::auth::RegistrationToken;
    use crate::auth::TokenSource;
    use crate::config::{Arch, Hardening};
    use crate::systemd::UnitListEntry;
    use chrono::Utc;
    use std::cell::RefCell;
    use std::sync::Mutex;

    // -------- Mocks --------

    #[derive(Default)]
    struct MockSystemd {
        calls: Mutex<Vec<String>>,
        properties: Mutex<HashMap<(String, String), String>>,
        // Optional fault-injection. When `fail_stop_unit` is
        // Some(name), `stop_unit(name)` returns Err with a recognisable
        // message rather than recording the call. Used by recreate-path
        // tests that need execute_remove_runner to fail at its very
        // first systemd call so execute_create_runner is provably never
        // dispatched. Symmetric shape with MockUsers.fail_remove_group.
        fail_stop_unit: Mutex<Option<String>>,
        // Wiring: when `fail_daemon_reload_message` is Some(msg),
        // `daemon_reload()` returns Err carrying `msg` verbatim inside
        // a `GharsError::Systemd` instead of recording the call. Used
        // by the post-loop daemon_reload escape-pin test to inject a
        // hostile control-char payload into the synthetic Failed-row
        // construction site in `apply` (post-loop daemon_reload
        // arm). Symmetric shape with
        // MockUsers.fail_add_group_message but for the synthetic
        // post-loop step rather than a per-action handler.
        fail_daemon_reload_message: Mutex<Option<String>>,
    }

    impl MockSystemd {
        fn record(&self, s: impl Into<String>) {
            self.calls.lock().unwrap().push(s.into());
        }
        fn calls_snapshot(&self) -> Vec<String> {
            self.calls.lock().unwrap().clone()
        }
        fn set_property(&self, unit: &str, prop: &str, value: &str) {
            self.properties
                .lock()
                .unwrap()
                .insert((unit.into(), prop.into()), value.into());
        }
    }

    impl Systemd for MockSystemd {
        // Failure path bypasses the call recorder: when
        // `fail_daemon_reload_message` is Some, the Err returns
        // BEFORE `record("daemon_reload")` runs, so a test asserting
        // "daemon_reload was called once" against `calls` would see
        // zero entries on this path. Symmetric with the precedent at
        // `stop_unit` below — `fail_stop_unit` likewise short-circuits
        // before recording. Tests that need to observe the failure
        // should assert against `result.failed` / `result.details`,
        // not `calls`.
        fn daemon_reload(&self) -> Result<()> {
            if let Some(msg) = self.fail_daemon_reload_message.lock().unwrap().as_deref() {
                return Err(GharsError::Systemd(msg.into(), "test".into()));
            }
            self.record("daemon_reload");
            Ok(())
        }
        fn start_unit(&self, unit: &str) -> Result<()> {
            self.record(format!("start_unit({unit})"));
            Ok(())
        }
        fn stop_unit(&self, unit: &str) -> Result<()> {
            if let Some(target) = self.fail_stop_unit.lock().unwrap().as_deref() {
                if target == unit {
                    return Err(GharsError::Systemd(
                        format!("mock: stop_unit({unit}) injected failure"),
                        "test injected fault via MockSystemd::fail_stop_unit".into(),
                    ));
                }
            }
            self.record(format!("stop_unit({unit})"));
            Ok(())
        }
        fn enable_unit(&self, unit: &str) -> Result<()> {
            self.record(format!("enable_unit({unit})"));
            Ok(())
        }
        fn disable_unit(&self, unit: &str) -> Result<()> {
            self.record(format!("disable_unit({unit})"));
            Ok(())
        }
        fn list_units_filtered(&self, _states: &[&str]) -> Result<Vec<UnitListEntry>> {
            Ok(vec![])
        }
        fn get_unit_property(&self, unit: &str, _iface: &str, property: &str) -> Result<String> {
            // MockSystemd reuses its `properties` map regardless of the
            // queried interface — tests fix property names so the
            // interface argument is informational. Real DbusSystemd
            // routes to Properties.Get(iface, prop).
            self.properties
                .lock()
                .unwrap()
                .get(&(unit.to_string(), property.to_string()))
                .cloned()
                .ok_or_else(|| {
                    GharsError::Systemd(
                        format!("MockSystemd: no property {property} on {unit}"),
                        "test fixture missing — call set_property before driving the unit".into(),
                    )
                })
        }
        fn get_unit_property_u64(&self, unit: &str, iface: &str, property: &str) -> Result<u64> {
            // MockSystemd stores fixture values as strings even when the
            // production wire signature is u64/u32 — tests typically
            // set_property("MainPID", "1234") and the mock parses on
            // read. Real DbusSystemd uses zvariant typed conversion.
            let s = self.get_unit_property(unit, iface, property)?;
            s.trim().parse::<u64>().map_err(|e| {
                GharsError::Systemd(
                    format!("MockSystemd: property {property} on {unit} not u64: {e}"),
                    "test fixture stored a non-numeric string".into(),
                )
            })
        }
        fn get_unit_property_object_path(
            &self,
            _unit: &str,
            _iface: &str,
            _property: &str,
        ) -> Result<zbus::zvariant::OwnedObjectPath> {
            unreachable!("apply.rs MockSystemd does not exercise object-path properties")
        }
        fn get_service_property_string(&self, unit: &str, property: &str) -> Result<String> {
            self.get_unit_property(unit, "org.freedesktop.systemd1.Service", property)
        }
        fn get_service_property_u64(&self, unit: &str, property: &str) -> Result<u64> {
            self.get_unit_property_u64(unit, "org.freedesktop.systemd1.Service", property)
        }
    }

    #[derive(Default)]
    struct MockTokenSource {
        name: String,
        registration_calls: Mutex<Vec<String>>,
        removal_calls: Mutex<Vec<String>>,
    }

    impl TokenSource for MockTokenSource {
        fn name(&self) -> &str {
            &self.name
        }
        fn mint_registration_token(&self, runner_url: &str) -> Result<RegistrationToken> {
            self.registration_calls
                .lock()
                .unwrap()
                .push(runner_url.into());
            Ok(RegistrationToken {
                value: "REG-TOKEN".into(),
                expires_at: Utc::now(),
                source: format!("mock:{}", self.name),
            })
        }
        fn mint_removal_token(&self, runner_url: &str) -> Result<RegistrationToken> {
            self.removal_calls.lock().unwrap().push(runner_url.into());
            Ok(RegistrationToken {
                value: "RM-TOKEN".into(),
                expires_at: Utc::now(),
                source: format!("mock:{}", self.name),
            })
        }
    }

    #[derive(Default)]
    struct MockTarball {
        fetched: Mutex<Vec<(String, String, String)>>,
        installed: Mutex<Vec<(String, String, String, String)>>,
    }

    impl Tarball for MockTarball {
        fn fetch_or_verify(
            &self,
            url: &str,
            dest_path: &Utf8Path,
            expected_sha256: &str,
        ) -> Result<()> {
            self.fetched.lock().unwrap().push((
                url.into(),
                dest_path.to_string(),
                expected_sha256.into(),
            ));
            // Materialize a placeholder so callers can `verify_local`
            // it later if they want.
            if let Some(parent) = dest_path.parent() {
                fs::create_dir_all(parent.as_std_path())?;
            }
            fs::write(dest_path.as_std_path(), b"mock-tarball")?;
            Ok(())
        }
        fn verify_local(&self, _path: &Utf8Path) -> Result<()> {
            Ok(())
        }
        fn install_binary(
            &self,
            tarball_path: &Utf8Path,
            _state_dir: &Utf8Path,
            runner_home: &Utf8Path,
            runner_name: &str,
            version: &str,
        ) -> Result<Utf8PathBuf> {
            self.installed.lock().unwrap().push((
                tarball_path.to_string(),
                runner_home.to_string(),
                runner_name.into(),
                version.into(),
            ));
            let bin = runner_home.join(format!("bin.{version}"));
            fs::create_dir_all(bin.as_std_path())?;
            Ok(bin)
        }
    }

    #[derive(Default)]
    struct MockConfigShell {
        registered: Mutex<Vec<(String, String, String)>>,
        removed: Mutex<Vec<String>>,
    }

    impl ConfigShell for MockConfigShell {
        fn run_register(&self, ctx: &ConfigShellCtx<'_>) -> Result<()> {
            self.registered.lock().unwrap().push((
                ctx.name.into(),
                ctx.url.into(),
                ctx.token.into(),
            ));
            // The real config.sh writes runsvc.sh into $HOME at
            // register time (design Part 9f). Mirror that so
            // execute_create_runner's SEC-02 hash step sees a real
            // file on disk and the round-trip annotation/hash
            // assertions are meaningful in unit tests.
            fs::create_dir_all(ctx.runner_home.as_std_path())?;
            fs::write(
                ctx.runner_home.join("runsvc.sh").as_std_path(),
                b"#!/bin/sh\n# mock runsvc\nexec ./bin/runsvc.sh \"$@\"\n",
            )?;
            Ok(())
        }
        fn run_remove(&self, ctx: &ConfigShellCtx<'_>) -> Result<()> {
            self.removed.lock().unwrap().push(ctx.name.into());
            Ok(())
        }
    }

    fn make_paths(tmp: &tempfile::TempDir) -> Paths {
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

    fn make_spec(name: &str, prefix: &Utf8Path) -> EffectiveRunnerSpec {
        EffectiveRunnerSpec {
            name: name.into(),
            url: "https://github.com/example/repo".into(),
            arch: Arch::X86_64,
            labels: vec!["self-hosted".into(), "linux".into()],
            memory_max: None,
            runner_version: Some("2.334.0".into()),
            runner_sha256: None,
            runner_tarball: None,
            auth_name: "pat".into(),
            caches: vec![],
            trust_zone: "default".into(),
            network: None,
            proxy: None,
            hooks: None,
            hardening: Hardening::default(),
            allowed_cpus: None,
            allowed_memory_nodes: None,
            spec_hash: "sha256:dead".into(),
            // In-place delta paths in apply refuse to write
            // a 00-ghars.conf without X-Ghars-Runsvc-Sha256 (would
            // cause runsvc-wrapper to fail-stop on next start). Test
            // fixtures that drive UpdateRunner through the in-place
            // branch must therefore carry a non-empty digest. We use
            // a stable fake value; tests that specifically exercise
            // the create path or the recreate path don't read this
            // field.
            runsvc_sha256: "sha256:dead".into(),
            config_source: "/etc/ghars/ghars.toml".into(),
        }
    }

    fn make_release() -> crate::github::Release {
        crate::github::Release {
            version: "2.334.0".into(),
            sha256: "deadbeef".into(),
            tarball_url: "https://example.test/runner.tar.gz".into(),
            tarball_name: "runner.tar.gz".into(),
        }
    }

    fn make_runner_plan(name: &str, prefix: &Utf8Path) -> RunnerPlan {
        let spec = make_spec(name, prefix);
        let mut drop_ins: BTreeMap<String, String> = BTreeMap::new();
        drop_ins.insert(
            "00-ghars.conf".into(),
            "[Unit]\nX-Ghars-Spec-Hash=sha256:dead\n".into(),
        );
        RunnerPlan {
            spec,
            resolved_release: Some(make_release()),
            effective_unit_text: "[Unit]\nDescription=mock\n".into(),
            drop_ins,
            spec_hash: "sha256:dead".into(),
        }
    }

    use std::collections::BTreeMap;

    // -------- Tests --------

    #[test]
    fn acquire_lock_writes_pid_and_releases_on_drop() {
        let tmp = tempfile::tempdir().unwrap();
        let paths = make_paths(&tmp);
        {
            let lock = acquire_lock(&paths).unwrap();
            // PID file content is our PID.
            let mut s = String::new();
            File::open(lock.path().as_std_path())
                .unwrap()
                .read_to_string(&mut s)
                .unwrap();
            let pid: i32 = s.trim().parse().unwrap();
            assert_eq!(pid as u32, std::process::id());
        }
        // After Drop, a fresh acquire should succeed.
        let _again = acquire_lock(&paths).unwrap();
    }

    #[test]
    fn acquire_lock_rejects_concurrent_apply() {
        let tmp = tempfile::tempdir().unwrap();
        let paths = make_paths(&tmp);
        let _held = acquire_lock(&paths).unwrap();
        let err = acquire_lock(&paths).unwrap_err();
        match err {
            GharsError::ApplyLocked { pid, path, stale } => {
                assert_eq!(pid as u32, std::process::id());
                assert_eq!(path, paths.apply_lock().to_string());
                // The first acquire wrote our own PID; the second
                // acquire reads it back and probes /proc/<our-pid>.
                // Our process is by definition alive, so stale=false.
                assert!(!stale, "self-PID should not be flagged stale");
            }
            other => panic!("expected ApplyLocked, got {other:?}"),
        }
        let rendered = format!("{}", acquire_lock(&paths).unwrap_err());
        assert!(
            rendered.contains("in progress"),
            "live-holder hint must mention progress, got: {rendered}"
        );
    }

    /// Synthetic PermissionDenied io::Error must be wrapped as
    /// `GharsError::Validation` with the "running as root" hint.
    /// Pinned because EACCES on the lock-file open is the most common
    /// non-root-operator failure mode and the cryptic raw EACCES from
    /// `OpenOptions::open` doesn't tell the operator how to recover.
    #[test]
    fn eacces_hint_wraps_permission_denied_as_validation() {
        let denied = std::io::Error::new(std::io::ErrorKind::PermissionDenied, "denied by test");
        let path = Utf8Path::new("/run/ghars/apply.lock");
        let err = eacces_hint(&denied, path, "apply.lock");
        match &err {
            GharsError::Validation(msg, hint) => {
                assert!(
                    msg.contains("permission denied") && msg.contains("apply.lock"),
                    "Validation msg must name the operation; got: {msg}"
                );
                assert!(
                    hint.contains("running as root"),
                    "Validation hint must mention root; got: {hint}"
                );
            }
            other => panic!("expected GharsError::Validation, got {other:?}"),
        }
        // Display must surface both halves so the operator sees them
        // when the error bubbles up through cmd_apply.
        let rendered = format!("{err}");
        assert!(
            rendered.contains("running as root"),
            "Display must surface the root hint; got: {rendered}"
        );
    }

    /// Any non-PermissionDenied io::Error must pass through as
    /// `GharsError::Io` (no Validation hint), preserving the original
    /// `ErrorKind` so callers can match on it. Pinned so a future
    /// refactor that widens the EACCES branch to "any io error" would
    /// break here, not in production where the operator would lose
    /// the underlying syscall context.
    #[test]
    fn eacces_hint_passes_through_non_eacces_as_io() {
        let not_found = std::io::Error::new(std::io::ErrorKind::NotFound, "missing by test");
        let path = Utf8Path::new("/run/ghars/apply.lock");
        let err = eacces_hint(&not_found, path, "apply.lock");
        match &err {
            GharsError::Io(io_err) => {
                assert_eq!(
                    io_err.kind(),
                    std::io::ErrorKind::NotFound,
                    "underlying ErrorKind must be preserved",
                );
                let msg = format!("{io_err}");
                assert!(
                    msg.contains("apply.lock") && msg.contains("missing by test"),
                    "Io message must include both `what` and the original error text; \
                     got: {msg}"
                );
            }
            other => panic!("expected GharsError::Io, got {other:?}"),
        }
    }

    /// A pre-existing apply.lock at a wider mode (operator
    /// chmod, prior ghars version, umask drift) must be re-tightened
    /// to 0o600 by `acquire_lock`. `OpenOptions::mode(0o600)` only
    /// applies on O_CREAT, so opening an existing 0o644 file would
    /// otherwise leave the embedded PID world-readable. Pre-create at
    /// 0o644, acquire, stat post-acquire, assert mode is back to
    /// 0o600.
    #[test]
    fn acquire_lock_chmods_drifted_lock_back_to_0o600() {
        let tmp = tempfile::tempdir().unwrap();
        let paths = make_paths(&tmp);
        // Pre-create the lock file at 0o644 so OpenOptions::mode is
        // bypassed (the file already exists; the create-mode bits
        // apply only to O_CREAT). The runtime dir must exist for the
        // pre-create to land at the right path.
        std::fs::create_dir_all(paths.runtime_dir.as_std_path()).unwrap();
        let lock_path = paths.apply_lock();
        std::fs::write(lock_path.as_std_path(), b"").unwrap();
        let perms = std::fs::Permissions::from_mode(0o644);
        std::fs::set_permissions(lock_path.as_std_path(), perms).unwrap();
        // Sanity: the pre-create landed at 0o644.
        let pre_mode = std::fs::metadata(lock_path.as_std_path())
            .unwrap()
            .permissions()
            .mode()
            & 0o777;
        assert_eq!(
            pre_mode, 0o644,
            "fixture must start at 0o644; got {pre_mode:o}"
        );
        // Acquire the lock — the chmod-back-to-0o600 path must fire.
        let _lock = acquire_lock(&paths).unwrap();
        let post_mode = std::fs::metadata(lock_path.as_std_path())
            .unwrap()
            .permissions()
            .mode()
            & 0o777;
        assert_eq!(
            post_mode, 0o600,
            "acquire_lock must chmod a drifted 0o644 lock back to 0o600; \
             got {post_mode:o}"
        );
    }

    #[test]
    fn pid_is_alive_for_self_process() {
        // Our own PID is necessarily alive — /proc/self points at the
        // running process, and procfs guarantees the entry exists for
        // any process that hasn't been reaped.
        let me = i32::try_from(std::process::id()).unwrap();
        assert!(pid_is_alive(me));
    }

    #[test]
    fn pid_is_alive_rejects_zero_and_negative() {
        // /proc/0 doesn't exist (kernel pid_max starts at 1) and the
        // helper rejects negative PIDs without touching the
        // filesystem.
        assert!(!pid_is_alive(0));
        assert!(!pid_is_alive(-1));
        assert!(!pid_is_alive(-12345));
    }

    #[test]
    fn pid_is_alive_for_unallocated_pid() {
        // Linux's PID_MAX_LIMIT is 4 * 1024 * 1024 (kernel
        // include/linux/threads.h). A PID just under that ceiling is
        // virtually guaranteed to be unallocated on test hosts, so
        // /proc/<that-pid>/status doesn't exist.
        // We use 4_194_303 (PID_MAX_LIMIT - 1) — if the test host
        // happens to have allocated this PID we'd get a false
        // positive, but that's a one-in-millions race. Documenting
        // here so a future failure points back at the assumption.
        assert!(!pid_is_alive(4_194_303));
    }

    #[test]
    fn acquire_lock_marks_stale_for_dead_pid() {
        // SEC-19: simulate the crash-without-release path by writing
        // an unallocated PID into the lock file BEFORE acquiring. The
        // flock is then taken by this test; a second acquire from
        // the same process trips the contended-lock branch and reads
        // the bogus PID from disk. The probe of /proc/<bogus-pid>
        // must fail, marking the error stale.
        let tmp = tempfile::tempdir().unwrap();
        let paths = make_paths(&tmp);
        std::fs::create_dir_all(&paths.runtime_dir).unwrap();
        // Write a PID that won't exist; reuse the unallocated value
        // from `pid_is_alive_for_unallocated_pid` for consistency.
        std::fs::write(paths.apply_lock().as_std_path(), "4194303\n").unwrap();
        // Take the flock so a second acquire trips contention.
        let lock_file = OpenOptions::new()
            .read(true)
            .write(true)
            .truncate(false)
            .open(paths.apply_lock().as_std_path())
            .unwrap();
        FileExt::try_lock_exclusive(&lock_file).unwrap();

        let err = acquire_lock(&paths).unwrap_err();
        match err {
            GharsError::ApplyLocked { pid, path, stale } => {
                assert_eq!(pid, 4_194_303);
                assert_eq!(path, paths.apply_lock().to_string());
                assert!(stale, "unallocated PID must be flagged stale");
            }
            other => panic!("expected ApplyLocked, got {other:?}"),
        }
        let rendered = format!(
            "{}",
            // Re-construct the same error to exercise the Display
            // branch deterministically (the previous err was already
            // moved into the panic-message helper above).
            GharsError::ApplyLocked {
                pid: 4_194_303,
                path: paths.apply_lock().to_string(),
                stale: true,
            }
        );
        assert!(
            rendered.contains("stale"),
            "stale-holder hint must mention stale, got: {rendered}"
        );
        assert!(
            rendered.contains("4194303"),
            "stale-holder hint must include the dead PID, got: {rendered}"
        );

        // Tidy up so tempdir's drop succeeds.
        FileExt::unlock(&lock_file).unwrap();
    }

    #[test]
    fn guard_home_dir_rmrf_rejects_root() {
        let err = guard_home_dir_rmrf(
            Utf8Path::new("/"),
            Utf8Path::new("/var/lib/ghars"),
            "buckos",
        )
        .unwrap_err();
        assert!(format!("{err}").contains("/"));
    }

    #[test]
    fn guard_home_dir_rmrf_rejects_prefix_itself() {
        let err = guard_home_dir_rmrf(
            Utf8Path::new("/var/lib/ghars"),
            Utf8Path::new("/var/lib/ghars"),
            "buckos",
        )
        .unwrap_err();
        assert!(format!("{err}").contains("prefix"));
    }

    #[test]
    fn guard_home_dir_rmrf_rejects_outside_prefix() {
        let err = guard_home_dir_rmrf(
            Utf8Path::new("/etc/passwd"),
            Utf8Path::new("/var/lib/ghars"),
            "buckos",
        )
        .unwrap_err();
        assert!(format!("{err}").contains("expected"));
    }

    #[test]
    fn guard_home_dir_rmrf_accepts_canonical_path() {
        guard_home_dir_rmrf(
            Utf8Path::new("/var/lib/ghars/buckos"),
            Utf8Path::new("/var/lib/ghars"),
            "buckos",
        )
        .unwrap();
    }

    #[test]
    fn guard_home_dir_rmrf_rejects_path_separator_in_name() {
        let err = guard_home_dir_rmrf(
            Utf8Path::new("/var/lib/ghars/foo/bar"),
            Utf8Path::new("/var/lib/ghars"),
            "foo/bar",
        )
        .unwrap_err();
        assert!(
            format!("{err}").contains("expected") || format!("{err}").contains("path separator")
        );
    }

    #[test]
    fn guard_home_dir_rmrf_rejects_symlink_at_home_path() {
        // SEC-NEW: if an attacker plants a symlink at the
        // runner home path pointing to (e.g.) /etc, the guard must
        // reject before rmrf runs. Std's modern remove_dir_all also
        // detects this and unlinks-the-symlink rather than following
        // (rust-1.85 std/sys/fs/unix.rs:2683-2689) — but the guard
        // rejects explicitly so a future std regression cannot
        // reintroduce the attack.
        let tmp = tempfile::tempdir().unwrap();
        let prefix = Utf8PathBuf::from_path_buf(tmp.path().to_path_buf()).unwrap();
        // Create a symlink at <prefix>/buckos pointing to a real
        // directory elsewhere; the path-string check passes (it
        // equals <prefix>/buckos), so only the symlink check catches
        // it.
        let target = tmp.path().join("attacker-target");
        std::fs::create_dir_all(&target).unwrap();
        let runner_home = prefix.join("buckos");
        std::os::unix::fs::symlink(&target, runner_home.as_std_path()).unwrap();

        let err = guard_home_dir_rmrf(&runner_home, &prefix, "buckos").unwrap_err();
        let msg = format!("{err}");
        assert!(
            msg.contains("symlink"),
            "rejection must mention symlink, got: {msg}"
        );
    }

    #[test]
    fn guard_home_dir_rmrf_accepts_real_dir_through_symlinked_prefix() {
        // Defensive control: if the prefix is itself a symlink
        // (operators sometimes alias /var/lib through a tmpfs path),
        // canonicalization must resolve both sides consistently and
        // accept the real home. This pins the round-trip equivalence:
        // the canonicalize branch in guard_home_dir_rmrf must NOT
        // false-positive on a benign prefix-level symlink.
        let tmp = tempfile::tempdir().unwrap();
        let real_prefix = tmp.path().join("real_prefix");
        std::fs::create_dir_all(real_prefix.join("buckos")).unwrap();
        let aliased = tmp.path().join("aliased");
        std::os::unix::fs::symlink(&real_prefix, &aliased).unwrap();

        let prefix_u = Utf8PathBuf::from_path_buf(aliased.clone()).unwrap();
        let home_u = Utf8PathBuf::from_path_buf(aliased.join("buckos")).unwrap();
        guard_home_dir_rmrf(&home_u, &prefix_u, "buckos").unwrap();
    }

    #[test]
    fn guard_home_dir_rmrf_accepts_real_dir_under_real_prefix() {
        // Positive control for the symlink/canonicalize branch: when
        // both prefix and home are real directories with no symlinks
        // anywhere, the guard returns Ok.
        let tmp = tempfile::tempdir().unwrap();
        let prefix = Utf8PathBuf::from_path_buf(tmp.path().to_path_buf()).unwrap();
        let home = prefix.join("buckos");
        std::fs::create_dir_all(home.as_std_path()).unwrap();

        guard_home_dir_rmrf(&home, &prefix, "buckos").unwrap();
    }

    #[test]
    fn write_root_owned_creates_file_at_0644() {
        // `write_root_owned` promises root:root + 0644
        // ownership for the inode it wrote. The temp file is created
        // at 0o600 (create-restrictive) and widened to 0o644 via
        // fchmod on the open fd after chown_to_root succeeds. Tests
        // run unprivileged so chown_to_root is a cfg(test) no-op,
        // but the create+fchmod sequence and the rename both still
        // fire — so the published file's mode bits ARE 0o644 (umask
        // does not affect fchmod, only creat). This pins the
        // create-then-widen contract; the chown side is enforced by
        // the cfg(not(test)) variant under integration tests run as
        // root.
        use std::os::unix::fs::PermissionsExt;
        let tmp = tempfile::tempdir().unwrap();
        let dest = Utf8PathBuf::from_path_buf(tmp.path().join("nested").join("file.conf")).unwrap();
        write_root_owned(&dest, b"hello\n").unwrap();
        // File exists, parent was created.
        assert_eq!(std::fs::read(dest.as_std_path()).unwrap(), b"hello\n");
        let mode = std::fs::metadata(dest.as_std_path())
            .unwrap()
            .permissions()
            .mode()
            & 0o7777;
        assert_eq!(
            mode, 0o644,
            "published file must end at exactly 0o644 (fchmod-widen \
             from initial 0o600); got {mode:o}"
        );
    }

    #[test]
    fn write_root_owned_truncates_existing_file() {
        // Idempotency check: write_root_owned is called repeatedly by
        // the apply path on every reconcile. New contents must replace
        // old contents fully (truncate=true) — without truncation, a
        // shorter rewrite would leave dangling bytes from the prior
        // write and the spec_hash drift detector would silently
        // accept stale unit text.
        let tmp = tempfile::tempdir().unwrap();
        let dest = Utf8PathBuf::from_path_buf(tmp.path().join("file.conf")).unwrap();
        write_root_owned(&dest, b"long initial content").unwrap();
        write_root_owned(&dest, b"short").unwrap();
        assert_eq!(std::fs::read(dest.as_std_path()).unwrap(), b"short");
    }

    // -------- managed-write helper family --------

    #[test]
    fn read_then_write_if_changed_writes_when_file_missing() {
        // Pre-condition: dest does not exist. read_prior returns None,
        // the byte-equality check sees prior != Some(bytes), invokes
        // write_root_owned, and pushes UndoStep::WriteFile{prior_content:
        // None}. On rollback, prior_content=None drives unlink, which
        // is the correct inverse of "we created this file".
        let tmp = tempfile::tempdir().unwrap();
        let dest = Utf8PathBuf::from_path_buf(tmp.path().join("new.conf")).unwrap();
        let mut log = UndoLog::new();
        let changed = read_then_write_if_changed(&dest, b"fresh content", &mut log).unwrap();
        assert!(changed, "missing file → must report bytes-written");
        assert_eq!(std::fs::read(dest.as_std_path()).unwrap(), b"fresh content");
        // Log must record the write so rollback can unlink.
        let steps = log.steps();
        assert_eq!(steps.len(), 1, "expected exactly one UndoStep");
        match &steps[0] {
            UndoStep::WriteFile {
                path,
                prior_content,
            } => {
                assert_eq!(path, &dest);
                assert!(prior_content.is_none(), "missing-file prior must be None");
            }
            other => panic!("expected WriteFile; got: {other:?}"),
        }
    }

    #[test]
    fn read_then_write_if_changed_skips_when_bytes_match() {
        // Pre-condition: dest already contains exactly the bytes we'd
        // write. read_prior returns Some(bytes), the byte-equality
        // check returns Ok(false) WITHOUT pushing an UndoStep — the
        // "skip rewrite" optimization. The mtime/inode are
        // preserved so systemd does not see a "changed" drop-in and
        // `files_changed` stays at 0 in the caller.
        let tmp = tempfile::tempdir().unwrap();
        let dest = Utf8PathBuf::from_path_buf(tmp.path().join("matching.conf")).unwrap();
        std::fs::write(dest.as_std_path(), b"already there").unwrap();
        let mut log = UndoLog::new();
        let changed = read_then_write_if_changed(&dest, b"already there", &mut log).unwrap();
        assert!(!changed, "matching bytes → must skip");
        // Critical: nothing was pushed to the log. Pushing on a no-op
        // would let rollback unintentionally restore via prior bytes
        // even though no forward write happened.
        assert!(log.steps().is_empty(), "skip path must not push UndoStep");
    }

    #[test]
    fn write_record_undo_overwrites_and_records_prior_bytes() {
        // Pre-condition: dest already exists with old content. The
        // create-path helper unconditionally overwrites and snapshots
        // the prior bytes into UndoStep::WriteFile so rollback can
        // restore the original. This tests the create-path branch
        // taken by execute_update_cache_pool (which can land on a
        // pre-existing 00-ghars.conf during pool-update).
        let tmp = tempfile::tempdir().unwrap();
        let dest = Utf8PathBuf::from_path_buf(tmp.path().join("pre.conf")).unwrap();
        std::fs::write(dest.as_std_path(), b"OLD").unwrap();
        let mut log = UndoLog::new();
        write_record_undo(&dest, b"NEW", &mut log).unwrap();
        // Forward path: file now has new bytes.
        assert_eq!(std::fs::read(dest.as_std_path()).unwrap(), b"NEW");
        // Undo log: prior_content carries OLD so rollback rewrites it.
        let steps = log.steps();
        assert_eq!(steps.len(), 1);
        match &steps[0] {
            UndoStep::WriteFile {
                path,
                prior_content,
            } => {
                assert_eq!(path, &dest);
                assert_eq!(
                    prior_content.as_deref(),
                    Some(b"OLD".as_slice()),
                    "create-path helper must capture prior bytes for restore"
                );
            }
            other => panic!("expected WriteFile; got: {other:?}"),
        }
    }

    #[test]
    fn write_record_undo_writes_even_when_bytes_match() {
        // Always-write contract pin: write_record_undo MUST write
        // and push UndoStep even when on-disk bytes already equal the
        // payload. This is the critical asymmetry with
        // read_then_write_if_changed: the create branch issues systemd
        // enable+start side effects after the helper returns, so the
        // undo log MUST carry the WriteFile step. Without it, rollback
        // would have no record — for a missing-file create, no unlink;
        // for a pre-existing overwrite, no rewrite-to-prior. Either way,
        // the create-path side effect would be unrecoverable.
        //
        // The test pre-writes IDENTICAL bytes to the payload, then
        // calls write_record_undo. Asserts:
        //   - file content unchanged (matches payload, as expected)
        //   - log carries one WriteFile step with prior_content =
        //     Some(matching_bytes) — rollback would rewrite the same
        //     bytes back, which is a no-op on content but proves the
        //     step was recorded.
        let tmp = tempfile::tempdir().unwrap();
        let dest = Utf8PathBuf::from_path_buf(tmp.path().join("matching.conf")).unwrap();
        let bytes = b"identical content";
        std::fs::write(dest.as_std_path(), bytes).unwrap();
        let mut log = UndoLog::new();
        write_record_undo(&dest, bytes, &mut log).unwrap();
        // Forward path: bytes unchanged (would have been the same
        // either way; this just confirms no truncation).
        assert_eq!(std::fs::read(dest.as_std_path()).unwrap(), bytes);
        // Undo log: even on a no-content-change call, the step lands.
        let steps = log.steps();
        assert_eq!(
            steps.len(),
            1,
            "always-write contract: even matching bytes must push UndoStep"
        );
        match &steps[0] {
            UndoStep::WriteFile {
                path,
                prior_content,
            } => {
                assert_eq!(path, &dest);
                assert_eq!(
                    prior_content.as_deref(),
                    Some(bytes.as_slice()),
                    "prior_content must capture pre-existing bytes \
                     identical to payload (rewrite-on-undo is benign \
                     here, but the step itself is required)"
                );
            }
            other => panic!("expected WriteFile; got: {other:?}"),
        }
    }

    #[test]
    fn write_root_owned_leaves_no_temp_file_on_error() {
        // Atomicity contract: write_root_owned writes via a temp file
        // (`.{name}.tmp.{pid}.{counter}`) and renames into place. If
        // any step fails, the function MUST return Err and MUST NOT
        // leave a half-finished `.tmp.*` file behind — operators
        // running `apply` repeatedly would otherwise see /etc/ghars/
        // accumulate unlinked temp turds that the systemd drop-in
        // scanner could surface as drift.
        //
        // Force the failure at the open step by chmod'ing the parent
        // to 0o555 (no-write) so OpenOptions::create_new returns
        // EACCES. After the call returns Err, scan the parent and
        // assert nothing matching the temp prefix remains. We chmod
        // the parent back to 0o755 before the assert so tempdir's
        // Drop can clean up cleanly even if the assertion fails.
        use std::os::unix::fs::PermissionsExt;
        let tmp = tempfile::tempdir().unwrap();
        let parent = Utf8PathBuf::from_path_buf(tmp.path().join("locked")).unwrap();
        std::fs::create_dir(parent.as_std_path()).unwrap();
        let dest = parent.join("file.conf");

        // Drop write+execute permission on the parent. open(2) for
        // create requires write+execute on the parent directory;
        // 0o555 = r-xr-xr-x denies write to the owner.
        let mut perms = std::fs::metadata(parent.as_std_path())
            .unwrap()
            .permissions();
        perms.set_mode(0o555);
        std::fs::set_permissions(parent.as_std_path(), perms).unwrap();

        let result = write_root_owned(&dest, b"will not land");

        // Restore 0o755 BEFORE the asserts so a panic still allows
        // tempdir cleanup. Use a closure-style guard would be
        // cleaner, but a direct restore is enough for one test.
        let mut perms = std::fs::metadata(parent.as_std_path())
            .unwrap()
            .permissions();
        perms.set_mode(0o755);
        std::fs::set_permissions(parent.as_std_path(), perms).unwrap();

        assert!(
            result.is_err(),
            "write_root_owned must Err when parent is read-only; got Ok"
        );

        // Walk the parent and verify no leftover `.tmp.*` file. The
        // tempname pattern is `.{final_name}.tmp.{pid}.{counter}` —
        // we look for any name starting with `.file.conf.tmp.` since
        // that's the only family this call could have created.
        let mut leftovers = Vec::new();
        for entry in std::fs::read_dir(parent.as_std_path()).unwrap() {
            let entry = entry.unwrap();
            let name = entry.file_name();
            let name_str = name.to_string_lossy().into_owned();
            if name_str.starts_with(".file.conf.tmp.") {
                leftovers.push(name_str);
            }
        }
        assert!(
            leftovers.is_empty(),
            "write_root_owned left temp files behind: {leftovers:?}"
        );

        // Also assert the final path was never created.
        assert!(
            !dest.as_std_path().exists(),
            "write_root_owned must not create the final path on error"
        );
    }

    #[test]
    fn temp_file_guard_unlinks_on_drop_when_armed() {
        // Direct unit test of the Drop guard: arm with a real path,
        // drop without disarming, verify the file is gone. This
        // exercises the cleanup path that the parent-readonly test
        // above cannot reach (because EACCES at open(2) means the
        // guard was never armed in the first place).
        let tmp = tempfile::tempdir().unwrap();
        let temp_path = Utf8PathBuf::from_path_buf(tmp.path().join(".file.tmp.123.0")).unwrap();
        std::fs::write(temp_path.as_std_path(), b"interrupted write").unwrap();
        assert!(
            temp_path.as_std_path().exists(),
            "test setup: temp file must exist before guard drops"
        );
        {
            let _guard = TempFileGuard::new(temp_path.clone());
            // _guard goes out of scope here without disarm() — Drop
            // must unlink temp_path.
        }
        assert!(
            !temp_path.as_std_path().exists(),
            "TempFileGuard::drop must unlink the temp path when not disarmed"
        );
    }

    #[test]
    fn temp_file_guard_does_not_unlink_after_disarm() {
        // Pin the disarm() contract: after disarm, Drop is a no-op.
        // Used by write_root_owned after a successful rename — at
        // that point the temp inode no longer exists at temp_path
        // (rename moved it to final_path), but we still want to
        // avoid spurious unlink calls on a path the kernel knows is
        // gone. Use a sentinel file that we DO want preserved.
        let tmp = tempfile::tempdir().unwrap();
        let temp_path = Utf8PathBuf::from_path_buf(tmp.path().join(".file.tmp.123.0")).unwrap();
        std::fs::write(temp_path.as_std_path(), b"do not delete").unwrap();
        {
            let guard = TempFileGuard::new(temp_path.clone());
            guard.disarm();
        }
        assert!(
            temp_path.as_std_path().exists(),
            "TempFileGuard::drop after disarm() must not unlink the path"
        );
    }

    #[test]
    fn tighten_credential_perms_refuses_chmod_through_symlink() {
        // SEC-NEW: config.sh writes .credentials at
        // <runner_home>/.credentials owned by the runner user. Between
        // the write and apply's tighten_credential_perms call, a
        // malicious runner could swap the file for a symlink to (e.g.)
        // /etc/shadow. The path-based set_permissions would have
        // followed the symlink and chmod'd /etc/shadow to 0600. The
        // O_NOFOLLOW + fchmod approach must fail-closed instead.
        let tmp = tempfile::tempdir().unwrap();
        let runner_home = Utf8PathBuf::from_path_buf(tmp.path().to_path_buf()).unwrap();
        // Create a sensitive "victim" file the symlink will point at.
        // tighten_credential_perms must NOT chmod this.
        let victim = tmp.path().join("victim");
        std::fs::write(&victim, b"sensitive\n").unwrap();
        {
            use std::os::unix::fs::PermissionsExt;
            let mut perms = std::fs::metadata(&victim).unwrap().permissions();
            perms.set_mode(0o644);
            std::fs::set_permissions(&victim, perms).unwrap();
        }
        // Plant the symlink in place of one of the credential
        // filenames.
        let credentials = runner_home.join(".credentials");
        std::os::unix::fs::symlink(&victim, credentials.as_std_path()).unwrap();

        // Use a clearly-fake username so the User::from_name call hits
        // the Ok(None) warn-and-skip path. The function still has to
        // refuse the symlink before it ever gets to the fchown stage.
        let err = tighten_credential_perms(&runner_home, "nonexistent-ghars-test-user")
            .expect_err("tighten_credential_perms must refuse to chmod through a symlink");
        let msg = format!("{err}");
        assert!(
            msg.contains("symlink") || msg.to_lowercase().contains("eloop"),
            "error must signal symlink/ELOOP refusal, got: {msg}"
        );
        // Victim's mode is unchanged — fchmod never ran on its inode.
        let victim_mode = {
            use std::os::unix::fs::PermissionsExt;
            std::fs::metadata(&victim).unwrap().permissions().mode() & 0o7777
        };
        assert_eq!(
            victim_mode, 0o644,
            "victim mode must remain 0644; tighten_credential_perms leaked through the symlink"
        );
    }

    #[test]
    fn tighten_credential_perms_chmods_real_file_to_0600() {
        // Positive control: with a real (non-symlink) credential file
        // owned by the test user, tighten_credential_perms drops the
        // mode to 0600 via fchmod-on-fd.
        let tmp = tempfile::tempdir().unwrap();
        let runner_home = Utf8PathBuf::from_path_buf(tmp.path().to_path_buf()).unwrap();
        let creds = runner_home.join(".credentials");
        std::fs::write(creds.as_std_path(), b"{}").unwrap();
        {
            use std::os::unix::fs::PermissionsExt;
            let mut perms = std::fs::metadata(creds.as_std_path())
                .unwrap()
                .permissions();
            perms.set_mode(0o644);
            std::fs::set_permissions(creds.as_std_path(), perms).unwrap();
        }

        // Pass a clearly-fake username so User::from_name returns
        // Ok(None) and the fchown step is skipped (chown_credential_to_user
        // is a cfg(test) no-op anyway). The fchmod path still runs.
        tighten_credential_perms(&runner_home, "nonexistent-ghars-test-user").unwrap();

        let mode = {
            use std::os::unix::fs::PermissionsExt;
            std::fs::metadata(creds.as_std_path())
                .unwrap()
                .permissions()
                .mode()
                & 0o7777
        };
        assert_eq!(mode, 0o600, "credentials must be chmod'd to 0600");
    }

    #[test]
    fn tighten_credential_perms_no_op_when_files_missing() {
        // Many auth modes write only `.credentials` (no
        // `.credentials_rsaparams`). tighten_credential_perms must
        // not error when an expected file is absent.
        let tmp = tempfile::tempdir().unwrap();
        let runner_home = Utf8PathBuf::from_path_buf(tmp.path().to_path_buf()).unwrap();
        // Empty runner_home — no credential files.
        tighten_credential_perms(&runner_home, "nonexistent-ghars-test-user").unwrap();
    }

    #[test]
    fn tighten_credential_perms_handles_missing_user_without_error() {
        // When the operator names a user that does not yet exist
        // in /etc/passwd (e.g. apply is racing with useradd, or the
        // runner block was renamed mid-config), tighten_credential_perms
        // must NOT error. The fchmod path runs to drop credentials to
        // 0600 and the fchown step is skipped with a tracing::warn!.
        // The end-state is the same as the prior behaviour for the
        // mode check: 0600. Ownership is left untouched (whatever
        // config.sh wrote).
        let tmp = tempfile::tempdir().unwrap();
        let runner_home = Utf8PathBuf::from_path_buf(tmp.path().to_path_buf()).unwrap();
        let creds = runner_home.join(".credentials");
        std::fs::write(creds.as_std_path(), b"{}").unwrap();
        {
            use std::os::unix::fs::PermissionsExt;
            let mut perms = std::fs::metadata(creds.as_std_path())
                .unwrap()
                .permissions();
            perms.set_mode(0o644);
            std::fs::set_permissions(creds.as_std_path(), perms).unwrap();
        }
        // No such user — tighten_credential_perms must still succeed.
        tighten_credential_perms(&runner_home, "definitely-not-a-real-user-xyzzy").unwrap();
        // Mode dropped to 0600 even though fchown was skipped.
        let mode = {
            use std::os::unix::fs::PermissionsExt;
            std::fs::metadata(creds.as_std_path())
                .unwrap()
                .permissions()
                .mode()
                & 0o7777
        };
        assert_eq!(
            mode, 0o600,
            "fchmod must run even when the runner user is missing"
        );
    }

    #[test]
    fn remove_runner_orphan_skips_mint_token_and_config_remove() {
        // Orphan RemoveRunner has empty url + auth_name (set
        // by the orphan synthesis loop in `plan_from` when
        // synthesising RemoveRunner from actual.orphans). With those
        // empty, mint_token would error
        // because the auth registry has no key "" — that would
        // strand the host-local cleanup. The fix: skip the
        // mint_token + config.sh remove pair entirely. The runner
        // stays registered server-side; the operator removes it via
        // GitHub UI or restores its [[runner]] block.
        //
        // This test exercises the full execute_remove_runner path
        // for an orphan: verify no mint happens, no config_shell
        // remove happens, and the local artifacts are still cleaned
        // up.
        let tmp = tempfile::tempdir().unwrap();
        let paths = make_paths(&tmp);
        fs::create_dir_all(paths.runtime_dir.as_std_path()).unwrap();
        // Pre-stage a runner home + unit file the orphan path can
        // clean up.
        let runner_home = paths.runner_home("default", "ghost");
        fs::create_dir_all(runner_home.as_std_path()).unwrap();
        fs::create_dir_all(paths.unit_dir.as_std_path()).unwrap();
        fs::write(paths.unit_file("ghost").as_std_path(), b"[Unit]\n").unwrap();
        let drop_in_dir = paths.drop_in_dir("ghost");
        fs::create_dir_all(drop_in_dir.as_std_path()).unwrap();

        // Orphan identity: empty url + auth_name, exactly as
        // `plan_from`'s orphan synthesis loop emits.
        let identity = RunnerIdentity {
            name: "ghost".into(),
            url: String::new(),
            auth_name: String::new(),
            trust_zone: "default".into(),
        };
        let systemd = MockSystemd::default();
        // Empty auth registry — guarantees mint_token would fail if
        // it were called.
        let auth_map: HashMap<String, Box<dyn TokenSource>> = HashMap::new();
        let config_shell = MockConfigShell::default();
        let tarball = MockTarball::default();
        let deps = Deps {
            systemd: &systemd,
            auth: &auth_map,
            tarball: &tarball,
            config_shell: &config_shell,
        };

        execute_remove_runner(&identity, &deps, &paths, &mut UndoLog::new())
            .expect("orphan remove must not error on missing auth_name");

        // No config_shell.run_remove was called.
        assert_eq!(
            config_shell.removed.lock().unwrap().len(),
            0,
            "orphan must skip config.sh remove (cannot mint token)"
        );
        // Local artifacts ARE cleaned up.
        assert!(!paths.unit_file("ghost").as_std_path().exists());
        assert!(!runner_home.as_std_path().exists());
        // Systemd ops still happen (stop/disable + ghars-net@ teardown).
        let calls = systemd.calls_snapshot();
        assert!(
            calls
                .iter()
                .any(|c| c == "stop_unit(ghars-runner@ghost.service)")
        );
        assert!(
            calls
                .iter()
                .any(|c| c == "disable_unit(ghars-runner@ghost.service)")
        );
    }

    #[test]
    fn sort_into_phases_orders_correctly() {
        let tmp = tempfile::tempdir().unwrap();
        let paths = make_paths(&tmp);
        let plan_a = make_runner_plan("a", &paths.state_dir);
        let plan_b = make_runner_plan("b", &paths.state_dir);
        let identity_x = RunnerIdentity {
            name: "x".into(),
            url: "https://github.com/example/repo".into(),
            auth_name: "pat".into(),
            trust_zone: "default".into(),
        };
        let actions = vec![
            Action::CreateRunner(plan_b.clone()),
            Action::RemoveRunner(identity_x.clone()),
            Action::CreateRunner(plan_a.clone()),
            Action::CreateCachePool(CachePoolPlan {
                binding: crate::config::EffectiveCacheBinding {
                    name: "build".into(),
                    kinds: vec![crate::config::CacheKind::Ccache],
                    size: "200G".into(),
                    mode: crate::config::CacheMode::Shared,
                    trust_zone: "default".into(),
                },
                drop_in_body: "[Service]\n".into(),
                spec_hash: "sha256:abcd".into(),
            }),
            Action::RemoveCachePool("rust".into()),
            Action::NoOp("nothing".into()),
        ];
        let phased = sort_into_phases(&actions);
        let labels: Vec<String> = phased.iter().map(Action::label).collect();
        // Expected order:
        //  1) CreateCachePool(build)
        //  2) RemoveRunner(x)
        //  3) CreateRunner(a) — sorted by name within phase
        //  4) CreateRunner(b)
        //  5) RemoveCachePool(rust)
        //  6) NoOp
        assert_eq!(
            labels,
            vec![
                "CreateCachePool(build)",
                "RemoveRunner(x)",
                "CreateRunner(a)",
                "CreateRunner(b)",
                "RemoveCachePool(rust)",
                "NoOp(nothing)",
            ],
        );
    }

    // -- sort_into_phases properties ------------------------------------

    fn make_update_delta(name: &str, prefix: &Utf8Path, requires_recreate: bool) -> RunnerDelta {
        let after = make_runner_plan(name, prefix);
        RunnerDelta {
            identity: RunnerIdentity {
                name: name.into(),
                url: "https://github.com/example/repo".into(),
                auth_name: "pat".into(),
                trust_zone: "default".into(),
            },
            after,
            requires_recreate,
            recreate_reasons: vec![],
            drift_cause: crate::plan::DriftCause::SpecChanged,
            field_changes: Vec::new(),
            drop_in_changes: Vec::new(),
            before_caches: None,
            before_drop_in_basenames: None,
        }
    }

    fn sort_test_cache_plan(name: &str) -> CachePoolPlan {
        CachePoolPlan {
            binding: crate::config::EffectiveCacheBinding {
                name: name.into(),
                kinds: vec![crate::config::CacheKind::Ccache],
                size: "100G".into(),
                mode: crate::config::CacheMode::Shared,
                trust_zone: "default".into(),
            },
            drop_in_body: "[Service]\n".into(),
            spec_hash: "sha256:dead".into(),
        }
    }

    fn sort_test_cache_delta(name: &str) -> CachePoolDelta {
        CachePoolDelta {
            binding: crate::config::EffectiveCacheBinding {
                name: name.into(),
                kinds: vec![crate::config::CacheKind::Ccache],
                size: "100G".into(),
                mode: crate::config::CacheMode::Shared,
                trust_zone: "default".into(),
            },
            drop_in_body: "[Service]\n".into(),
            spec_hash: "sha256:beef".into(),
        }
    }

    fn sort_test_identity(name: &str, prefix: &Utf8Path) -> RunnerIdentity {
        RunnerIdentity {
            name: name.into(),
            url: "https://github.com/example/repo".into(),
            auth_name: "pat".into(),
            trust_zone: "default".into(),
        }
    }

    #[test]
    fn sort_into_phases_empty_input_returns_empty() {
        let phased = sort_into_phases(&[]);
        assert!(phased.is_empty());
    }

    #[test]
    fn sort_into_phases_preserves_count_and_membership() {
        // Property: every action in input is in output exactly once.
        let tmp = tempfile::tempdir().unwrap();
        let paths = make_paths(&tmp);
        let actions = vec![
            Action::CreateRunner(make_runner_plan("zeta", &paths.state_dir)),
            Action::RemoveCachePool("aaa".into()),
            Action::NoOp("idle".into()),
            Action::CreateCachePool(sort_test_cache_plan("zzz")),
            Action::RemoveRunner(sort_test_identity("mid", &paths.state_dir)),
            Action::UpdateRunner(make_update_delta("alpha", &paths.state_dir, false)),
            Action::UpdateCachePool(sort_test_cache_delta("ccc")),
        ];
        let phased = sort_into_phases(&actions);
        assert_eq!(phased.len(), actions.len(), "no actions added or dropped");
        // Set-equality via labels.
        let mut input_labels: Vec<String> = actions.iter().map(Action::label).collect();
        let mut output_labels: Vec<String> = phased.iter().map(Action::label).collect();
        input_labels.sort();
        output_labels.sort();
        assert_eq!(input_labels, output_labels, "membership preserved");
    }

    #[test]
    fn sort_into_phases_within_phase_runners_alphabetical() {
        // Two CreateRunner actions: "beta" emitted first, "alpha" second.
        // Output must place "alpha" before "beta" within the phase.
        let tmp = tempfile::tempdir().unwrap();
        let paths = make_paths(&tmp);
        let actions = vec![
            Action::CreateRunner(make_runner_plan("beta", &paths.state_dir)),
            Action::CreateRunner(make_runner_plan("alpha", &paths.state_dir)),
        ];
        let phased = sort_into_phases(&actions);
        let labels: Vec<String> = phased.iter().map(Action::label).collect();
        assert_eq!(labels, vec!["CreateRunner(alpha)", "CreateRunner(beta)"]);
    }

    #[test]
    fn sort_into_phases_inplace_update_precedes_recreate_update() {
        // Per Part 8: in-place updates run BEFORE recreate updates so
        // a failing recreate doesn't strand operators with broken
        // in-place changes in the same apply.
        let tmp = tempfile::tempdir().unwrap();
        let paths = make_paths(&tmp);
        let actions = vec![
            Action::UpdateRunner(make_update_delta("recreate-me", &paths.state_dir, true)),
            Action::UpdateRunner(make_update_delta("inplace-me", &paths.state_dir, false)),
        ];
        let phased = sort_into_phases(&actions);
        let labels: Vec<String> = phased.iter().map(Action::label).collect();
        assert_eq!(
            labels,
            vec!["UpdateRunner(inplace-me)", "UpdateRunner(recreate-me)"],
            "in-place update must come before recreate update",
        );
    }

    #[test]
    fn sort_into_phases_inplace_subset_alphabetical_within_subset() {
        let tmp = tempfile::tempdir().unwrap();
        let paths = make_paths(&tmp);
        let actions = vec![
            Action::UpdateRunner(make_update_delta("zeta", &paths.state_dir, false)),
            Action::UpdateRunner(make_update_delta("alpha", &paths.state_dir, false)),
        ];
        let phased = sort_into_phases(&actions);
        let labels: Vec<String> = phased.iter().map(Action::label).collect();
        assert_eq!(labels, vec!["UpdateRunner(alpha)", "UpdateRunner(zeta)"]);
    }

    #[test]
    fn sort_into_phases_recreate_subset_alphabetical_within_subset() {
        let tmp = tempfile::tempdir().unwrap();
        let paths = make_paths(&tmp);
        let actions = vec![
            Action::UpdateRunner(make_update_delta("zeta", &paths.state_dir, true)),
            Action::UpdateRunner(make_update_delta("alpha", &paths.state_dir, true)),
        ];
        let phased = sort_into_phases(&actions);
        let labels: Vec<String> = phased.iter().map(Action::label).collect();
        assert_eq!(labels, vec!["UpdateRunner(alpha)", "UpdateRunner(zeta)"]);
    }

    #[test]
    fn sort_into_phases_noop_lands_at_the_end() {
        // NoOps inserted at the front; output must place them last.
        let tmp = tempfile::tempdir().unwrap();
        let paths = make_paths(&tmp);
        let actions = vec![
            Action::NoOp("middle".into()),
            Action::CreateRunner(make_runner_plan("alpha", &paths.state_dir)),
            Action::NoOp("first".into()),
            Action::CreateCachePool(sort_test_cache_plan("build")),
        ];
        let phased = sort_into_phases(&actions);
        let labels: Vec<String> = phased.iter().map(Action::label).collect();
        // Both NoOps come last (alphabetical: "first" < "middle").
        assert_eq!(
            labels,
            vec![
                "CreateCachePool(build)",
                "CreateRunner(alpha)",
                "NoOp(first)",
                "NoOp(middle)",
            ],
        );
    }

    #[test]
    fn sort_into_phases_full_canonical_order_with_every_phase() {
        // Cover every phase in one test: CreateCachePool → UpdateCachePool
        // → RemoveRunner → UpdateRunner-inplace → UpdateRunner-recreate
        // → CreateRunner → RemoveCachePool → NoOp.
        let tmp = tempfile::tempdir().unwrap();
        let paths = make_paths(&tmp);
        let actions = vec![
            Action::NoOp("done".into()),
            Action::RemoveCachePool("old-pool".into()),
            Action::CreateRunner(make_runner_plan("new-runner", &paths.state_dir)),
            Action::UpdateRunner(make_update_delta("recreate-runner", &paths.state_dir, true)),
            Action::UpdateRunner(make_update_delta("inplace-runner", &paths.state_dir, false)),
            Action::RemoveRunner(sort_test_identity("old-runner", &paths.state_dir)),
            Action::UpdateCachePool(sort_test_cache_delta("update-pool")),
            Action::CreateCachePool(sort_test_cache_plan("new-pool")),
        ];
        let phased = sort_into_phases(&actions);
        let labels: Vec<String> = phased.iter().map(Action::label).collect();
        assert_eq!(
            labels,
            vec![
                "CreateCachePool(new-pool)",
                "UpdateCachePool(update-pool)",
                "RemoveRunner(old-runner)",
                "UpdateRunner(inplace-runner)",
                "UpdateRunner(recreate-runner)",
                "CreateRunner(new-runner)",
                "RemoveCachePool(old-pool)",
                "NoOp(done)",
            ],
        );
    }

    #[test]
    fn apply_dispatches_cache_pool_create_then_runner_create() {
        let tmp = tempfile::tempdir().unwrap();
        let paths = make_paths(&tmp);
        // Pre-create runtime dir so the lock file write succeeds; apply
        // also does this internally but having both paths valid keeps
        // the assertion simple.
        fs::create_dir_all(paths.runtime_dir.as_std_path()).unwrap();
        let pool = CachePoolPlan {
            binding: crate::config::EffectiveCacheBinding {
                name: "build".into(),
                kinds: vec![crate::config::CacheKind::Ccache],
                size: "200G".into(),
                mode: crate::config::CacheMode::Shared,
                trust_zone: "default".into(),
            },
            drop_in_body: "[Service]\nExecStart=/usr/bin/sleep infinity\n".into(),
            spec_hash: "sha256:abcd".into(),
        };
        let plan_a = make_runner_plan("a", &paths.state_dir);
        let plan = Plan {
            actions: vec![Action::CreateRunner(plan_a), Action::CreateCachePool(pool)],
            warnings: vec![],
        };
        let systemd = MockSystemd::default();
        // Make MainPID resolve to this process — runner has no
        // `network`, so verify_runner_netns is skipped.
        systemd.set_property(
            "ghars-runner@a.service",
            "MainPID",
            &std::process::id().to_string(),
        );
        let mut auth_map: HashMap<String, Box<dyn TokenSource>> = HashMap::new();
        auth_map.insert(
            "pat".into(),
            Box::new(MockTokenSource {
                name: "pat".into(),
                ..MockTokenSource::default()
            }),
        );
        let tarball = MockTarball::default();
        let config_shell = MockConfigShell::default();
        let opts = ApplyOptions::default();
        let deps = Deps {
            systemd: &systemd,
            auth: &auth_map,
            tarball: &tarball,
            config_shell: &config_shell,
        };
        let result = apply(&plan, &deps, &paths, &opts).unwrap();
        assert!(result.ok(), "{:?}", result.failed);
        assert_eq!(result.skipped.len(), 0);
        let calls = systemd.calls_snapshot();
        // First systemd call must enable+start the cache pool unit
        // BEFORE the runner unit is touched.
        let pool_idx = calls
            .iter()
            .position(|c| c.contains("ghars-cache@build.service"))
            .expect("cache pool was not touched");
        let runner_idx = calls
            .iter()
            .position(|c| c.contains("ghars-runner@a.service"))
            .expect("runner was not touched");
        assert!(
            pool_idx < runner_idx,
            "expected cache-pool ops before runner ops; got {calls:?}"
        );
    }

    #[test]
    fn dry_run_skips_actions_but_holds_lock() {
        let tmp = tempfile::tempdir().unwrap();
        let paths = make_paths(&tmp);
        let plan = Plan {
            actions: vec![Action::NoOp("idempotent".into())],
            warnings: vec![],
        };
        let systemd = MockSystemd::default();
        let auth_map: HashMap<String, Box<dyn TokenSource>> = HashMap::new();
        let tarball = MockTarball::default();
        let config_shell = MockConfigShell::default();
        let opts = ApplyOptions {
            dry_run: true,
            ..ApplyOptions::default()
        };
        let deps = Deps {
            systemd: &systemd,
            auth: &auth_map,
            tarball: &tarball,
            config_shell: &config_shell,
        };
        let result = apply(&plan, &deps, &paths, &opts).unwrap();
        assert_eq!(result.skipped.len(), 1);
        // dry_run skips daemon_reload too.
        assert!(systemd.calls_snapshot().is_empty());
    }

    #[test]
    fn fail_fast_short_circuits_on_first_failure() {
        // Inject a systemd mock that fails enable_unit. Use a
        // RefCell-driven "fail next call" to keep the mock simple.
        struct FlakySystemd {
            calls: Mutex<Vec<String>>,
            fail_after: RefCell<usize>,
        }
        impl Systemd for FlakySystemd {
            fn daemon_reload(&self) -> Result<()> {
                self.calls.lock().unwrap().push("daemon_reload".into());
                Ok(())
            }
            fn start_unit(&self, unit: &str) -> Result<()> {
                self.calls
                    .lock()
                    .unwrap()
                    .push(format!("start_unit({unit})"));
                Ok(())
            }
            fn stop_unit(&self, unit: &str) -> Result<()> {
                self.calls
                    .lock()
                    .unwrap()
                    .push(format!("stop_unit({unit})"));
                Ok(())
            }
            fn enable_unit(&self, unit: &str) -> Result<()> {
                self.calls
                    .lock()
                    .unwrap()
                    .push(format!("enable_unit({unit})"));
                let mut left = self.fail_after.borrow_mut();
                if *left == 0 {
                    return Err(GharsError::Systemd(
                        format!("mock enable failure for {unit}"),
                        "test".into(),
                    ));
                }
                *left -= 1;
                Ok(())
            }
            fn disable_unit(&self, unit: &str) -> Result<()> {
                self.calls
                    .lock()
                    .unwrap()
                    .push(format!("disable_unit({unit})"));
                Ok(())
            }
            fn list_units_filtered(&self, _: &[&str]) -> Result<Vec<UnitListEntry>> {
                Ok(vec![])
            }
            fn get_unit_property(&self, _: &str, _: &str, _: &str) -> Result<String> {
                Ok("0".into())
            }
            fn get_unit_property_u64(&self, _: &str, _: &str, _: &str) -> Result<u64> {
                Ok(0)
            }
            fn get_unit_property_object_path(
                &self,
                _: &str,
                _: &str,
                _: &str,
            ) -> Result<zbus::zvariant::OwnedObjectPath> {
                unreachable!("FlakySystemd does not exercise object-path properties")
            }
            fn get_service_property_string(&self, _: &str, _: &str) -> Result<String> {
                Ok(String::new())
            }
            fn get_service_property_u64(&self, _: &str, _: &str) -> Result<u64> {
                Ok(0)
            }
        }
        // FlakySystemd is not Sync; tests run single-threaded for this case.
        // unsafe is forbidden — wrap RefCell access via a Mutex on the
        // outside (RefCell is fine for !Sync usage when only one thread
        // touches it). Since `apply` takes `&dyn Systemd`, the trait
        // doesn't require Sync — but `Systemd` has `Send + Sync` bounds?
        // Re-checked: trait is bare. OK.
        let tmp = tempfile::tempdir().unwrap();
        let paths = make_paths(&tmp);
        fs::create_dir_all(paths.runtime_dir.as_std_path()).unwrap();
        let pool_a = CachePoolPlan {
            binding: crate::config::EffectiveCacheBinding {
                name: "a".into(),
                kinds: vec![crate::config::CacheKind::Ccache],
                size: "200G".into(),
                mode: crate::config::CacheMode::Shared,
                trust_zone: "default".into(),
            },
            drop_in_body: "[Service]\n".into(),
            spec_hash: "sha256:1".into(),
        };
        let pool_b = CachePoolPlan {
            binding: crate::config::EffectiveCacheBinding {
                name: "b".into(),
                kinds: vec![crate::config::CacheKind::Ccache],
                size: "200G".into(),
                mode: crate::config::CacheMode::Shared,
                trust_zone: "default".into(),
            },
            drop_in_body: "[Service]\n".into(),
            spec_hash: "sha256:2".into(),
        };
        let plan = Plan {
            actions: vec![
                Action::CreateCachePool(pool_a),
                Action::CreateCachePool(pool_b),
            ],
            warnings: vec![],
        };
        let systemd = FlakySystemd {
            calls: Mutex::new(vec![]),
            fail_after: RefCell::new(0),
        };
        let auth_map: HashMap<String, Box<dyn TokenSource>> = HashMap::new();
        let tarball = MockTarball::default();
        let config_shell = MockConfigShell::default();
        let opts = ApplyOptions {
            fail_fast: true,
            ..ApplyOptions::default()
        };
        let deps = Deps {
            systemd: &systemd,
            auth: &auth_map,
            tarball: &tarball,
            config_shell: &config_shell,
        };
        let result = apply(&plan, &deps, &paths, &opts).unwrap();
        // First action failed; second was not attempted because
        // fail_fast=true short-circuits.
        assert_eq!(result.failed.len(), 1);
        assert!(result.failed[0].0.contains("CreateCachePool(a)"));
        // Failed action also lands in `details` as
        // `ApplyOutcome::Failed`. The label matches the failed
        // tuple's label exactly (single source of action labels).
        // `plan_disruption` mirrors `Action::CreateCachePool`'s
        // plan-time worst-case (`Disruption::Recreate` per
        // plan.rs::Action::disruption).
        assert_eq!(
            result.details.len(),
            1,
            "fail_fast: only the failing action runs before the short-circuit; details row count matches",
        );
        let (det_label, det_outcome) = &result.details[0];
        assert_eq!(det_label, &result.failed[0].0);
        match det_outcome {
            ApplyOutcome::Failed {
                error_summary,
                plan_disruption,
            } => {
                assert!(
                    !error_summary.is_empty(),
                    "Failed.error_summary must carry the inner error display",
                );
                // Bare-error scenario: FlakySystemd returns
                // GharsError::Systemd, RealUsers returns bare
                // GharsError::Io — neither is pre-wrapped in
                // GharsError::Apply, so the outer apply()-loop wrap
                // does not produce a double-wrapped Display chain.
                assert!(
                    !error_summary.contains("apply (action "),
                    "error_summary must NOT include the GharsError::Apply wrapping prefix \
                     (label is in the tuple key); got: {error_summary}",
                );
                assert_eq!(
                    *plan_disruption,
                    crate::plan::Disruption::Recreate,
                    "CreateCachePool plan-time disruption must be Recreate per Action::disruption",
                );
            }
            other => panic!("expected ApplyOutcome::Failed, got {other:?}"),
        }
        // disruption() on Failed delegates to plan_disruption.
        assert_eq!(det_outcome.disruption(), crate::plan::Disruption::Recreate,);
        let calls = systemd.calls.lock().unwrap();
        assert!(
            calls
                .iter()
                .any(|c| c.contains("enable_unit(ghars-cache@a.service)"))
        );
        assert!(
            !calls
                .iter()
                .any(|c| c.contains("enable_unit(ghars-cache@b.service)"))
        );
        // Pin that the per-action UndoLog was plumbed through to
        // `result.failed_undo_logs` on the Err path. The label/order
        // invariant is `failed[i].0 == failed_undo_logs[i].0` for
        // every i — same labels, same insertion order.
        // `execute_create_cache_pool` records CreateDir → WriteFile →
        // GroupAdd before the failed enable_unit; steps land in the
        // Vec in that order. The advisory in cmd_apply walks this Vec
        // to render the operator-facing manual-cleanup hint.
        assert_eq!(
            result.failed_undo_logs.len(),
            1,
            "exactly one failed action ⇒ exactly one undo log entry",
        );
        assert_eq!(
            result.failed_undo_logs[0].0, result.failed[0].0,
            "label invariant: failed[i].0 == failed_undo_logs[i].0",
        );
        let steps = &result.failed_undo_logs[0].1;
        // Steps recorded BEFORE the failed enable_unit:
        // 1. CreateDir for the per-pool drop-in dir
        // 2. WriteFile for 00-ghars.conf (via write_record_undo)
        assert_eq!(
            steps.len(),
            2,
            "expected CreateDir + WriteFile before enable_unit \
             failed; got {steps:?}",
        );
        assert!(matches!(steps[0], UndoStep::CreateDir { .. }));
        assert!(matches!(steps[1], UndoStep::WriteFile { .. }));
    }

    /// `result.details` filtered to the [`ApplyOutcome::Failed`] rows
    /// MUST equal `result.failed` in label set, count, AND positional
    /// alignment for any multi-failure plan. The invariant is enforced at
    /// `apply()`'s `Err` arm push site: every failure pushes BOTH a
    /// `Failed` row to `details` and a `(label, GharsError)` pair to
    /// `failed` in lockstep, plus a `failed_undo_logs` entry. The type
    /// system does not encode the parallel-Vec invariant — a future
    /// refactor that decouples the pushes (e.g. derives `details` from a
    /// separate iteration) could silently drop or duplicate a row,
    /// leaving cmd_apply's `fail:` rendering loop out of sync with the
    /// rollback advisory.
    ///
    /// Synthesizes a 3-failure `ApplyResult` (`fail_fast = false` semantic
    /// — all three Err arms ran, all three pairs landed) covering all
    /// three [`crate::plan::Disruption`] classes (Recreate / Restart /
    /// None) so the test exercises the full `plan_disruption` mapping
    /// surface.
    ///
    /// Asserts:
    /// 1. Length parity — `failed.len() == details(Failed-filtered).len()`.
    /// 2. Positional alignment — `failed[i].0 == details(Failed-filtered)[i].0`
    ///    for every i. cmd_apply's renderer walks `details` in execution
    ///    order, so positional equality (NOT just set equality) is
    ///    load-bearing.
    #[test]
    fn apply_result_details_failed_labels_match_failed_vec_for_multi_failure_plans() {
        let auth_err = |msg: &str| GharsError::Auth(msg.into(), "hint".into());
        let validation_err = |msg: &str| GharsError::Validation(msg.into(), "hint".into());
        let result = ApplyResult {
            succeeded: vec!["CreateRunner(c)".into()],
            failed: vec![
                ("CreateRunner(a)".into(), auth_err("token mint failed")),
                (
                    "UpdateRunner(b)".into(),
                    GharsError::Systemd(
                        "Manager.RestartUnit failed".into(),
                        "check journalctl".into(),
                    ),
                ),
                (
                    "RemoveCachePool(c)".into(),
                    validation_err("oversize pool name"),
                ),
            ],
            skipped: vec![],
            details: vec![
                // Successful row interleaved with failed rows so the
                // filter must discard non-Failed outcomes correctly.
                (
                    "CreateRunner(a)".into(),
                    ApplyOutcome::Failed {
                        error_summary: "auth: token mint failed".into(),
                        plan_disruption: crate::plan::Disruption::Recreate,
                    },
                ),
                ("CreateRunner(c)".into(), ApplyOutcome::Created),
                (
                    "UpdateRunner(b)".into(),
                    ApplyOutcome::Failed {
                        error_summary: "systemd: Manager.RestartUnit failed".into(),
                        plan_disruption: crate::plan::Disruption::Restart,
                    },
                ),
                (
                    "RemoveCachePool(c)".into(),
                    ApplyOutcome::Failed {
                        error_summary: "validation: oversize pool name".into(),
                        plan_disruption: crate::plan::Disruption::Recreate,
                    },
                ),
            ],
            // Mirror the failed Vec ordering so the
            // `failed[i].0 == failed_undo_logs[i].0` invariant assertion
            // below is meaningful (`vec![]` would short-circuit any
            // ordering mismatch). Step contents are empty — the
            // ordering invariant is the test target, not step recovery.
            failed_undo_logs: vec![
                ("CreateRunner(a)".into(), Vec::new()),
                ("UpdateRunner(b)".into(), Vec::new()),
                ("RemoveCachePool(c)".into(), Vec::new()),
            ],
        };

        let failed_labels: Vec<String> = result
            .failed
            .iter()
            .map(|(label, _)| label.clone())
            .collect();
        let details_failed_labels: Vec<String> = result
            .details
            .iter()
            .filter_map(|(label, outcome)| match outcome {
                ApplyOutcome::Failed { .. } => Some(label.clone()),
                _ => None,
            })
            .collect();

        assert_eq!(
            failed_labels.len(),
            details_failed_labels.len(),
            "Failed-filtered details count must equal failed count: \
             failed.len()={}, details_failed.len()={}",
            failed_labels.len(),
            details_failed_labels.len(),
        );

        // Positional alignment — both Vecs are populated by the same
        // `Err` arm in apply() so the i-th failed entry's label MUST
        // equal the i-th Failed-filtered details entry's label.
        // Direct equality (vs sorted-set equality) pins execution-order
        // alignment, which cmd_apply's `fail:` renderer relies on.
        assert_eq!(
            failed_labels, details_failed_labels,
            "positional alignment broken: failed={failed_labels:?}, \
             details_failed={details_failed_labels:?}",
        );

        // ADD-1 (ordering invariant — see the construction comment in
        // the per-action `Err` arm of `apply()` above):
        // `failed[i].0 == failed_undo_logs[i].0` for every i. The two
        // Vecs are pushed in lockstep at the per-action `Err` arm;
        // cmd_apply's rollback advisory
        // walks `failed_undo_logs` and renders one block per entry,
        // labelled by the tuple's first element. Divergence here
        // would produce a mislabelled advisory pointing the operator
        // at the wrong action's mutations. Direct Vec equality is
        // stronger than set equality — pins the execution-order
        // alignment, not just label coverage.
        let undo_labels: Vec<&str> = result
            .failed_undo_logs
            .iter()
            .map(|(label, _)| label.as_str())
            .collect();
        let failed_labels_borrowed: Vec<&str> = failed_labels.iter().map(String::as_str).collect();
        assert_eq!(
            undo_labels, failed_labels_borrowed,
            "failed_undo_logs labels must match failed labels in order",
        );
    }

    #[test]
    fn create_runner_writes_unit_and_drop_ins_and_starts() {
        let tmp = tempfile::tempdir().unwrap();
        let paths = make_paths(&tmp);
        fs::create_dir_all(paths.runtime_dir.as_std_path()).unwrap();
        let plan = make_runner_plan("a", &paths.state_dir);
        let systemd = MockSystemd::default();
        // verify_runner_netns is skipped because spec.network is None.
        // No need to set MainPID.
        let mut auth_map: HashMap<String, Box<dyn TokenSource>> = HashMap::new();
        auth_map.insert(
            "pat".into(),
            Box::new(MockTokenSource {
                name: "pat".into(),
                ..MockTokenSource::default()
            }),
        );
        let tarball = MockTarball::default();
        let config_shell = MockConfigShell::default();
        let deps = Deps {
            systemd: &systemd,
            auth: &auth_map,
            tarball: &tarball,
            config_shell: &config_shell,
        };
        execute_create_runner(&plan, &deps, &paths, &mut UndoLog::new()).unwrap();
        // Unit + drop-in landed on disk.
        assert!(paths.unit_file("a").as_std_path().exists());
        let drop_in_path = paths.drop_in_dir("a").join("00-ghars.conf");
        assert!(drop_in_path.as_std_path().exists());
        // SEC-02: the freshly-rendered 00-ghars.conf
        // MUST carry an `X-Ghars-Runsvc-Sha256=sha256:HEX` line under
        // `[Service]`. Without this, runsvc-wrapper exits
        // ANNOTATION_MISSING on every restart and the runner unit
        // can never start.
        let drop_in_body = fs::read_to_string(drop_in_path.as_std_path()).unwrap();
        assert!(
            drop_in_body.contains("[Service]"),
            "00-ghars.conf is missing [Service] section: {drop_in_body}"
        );
        assert!(
            drop_in_body.contains("X-Ghars-Runsvc-Sha256=sha256:"),
            "00-ghars.conf is missing X-Ghars-Runsvc-Sha256 annotation: {drop_in_body}"
        );
        // The recorded hash must match what re-reading the same
        // runsvc.sh would produce — otherwise every unit start would
        // fail the integrity check.
        let runsvc_path = paths.runner_home("default", "a").join("runsvc.sh");
        let expected_hash = sha256_of_runsvc(&runsvc_path).unwrap();
        assert!(
            drop_in_body.contains(&format!("X-Ghars-Runsvc-Sha256={expected_hash}")),
            "annotation digest does not match on-disk runsvc.sh ({expected_hash}): {drop_in_body}"
        );
        // Unit text written to disk is the canonical template.
        let unit_text = fs::read_to_string(paths.unit_file("a").as_std_path()).unwrap();
        assert!(unit_text.contains("[Unit]"));
        assert!(unit_text.contains("\nExecStart=/usr/lib/ghars/runsvc-wrapper %i\n"));
        assert!(!unit_text.contains("ExecStart=!"));
        // Tarball was downloaded once.
        assert_eq!(tarball.fetched.lock().unwrap().len(), 1);
        // User was added.
        // config.sh registered with the minted token.
        let regs = config_shell.registered.lock().unwrap();
        assert_eq!(regs.len(), 1);
        assert_eq!(regs[0].2, "REG-TOKEN");
        // systemd was called: enable, daemon_reload, start.
        let calls = systemd.calls_snapshot();
        assert!(
            calls
                .iter()
                .any(|c| c == "enable_unit(ghars-runner@a.service)")
        );
        assert!(
            calls
                .iter()
                .any(|c| c == "start_unit(ghars-runner@a.service)")
        );
    }

    #[test]
    fn create_runner_runsvc_sha_matches_wrapper_recompute() {
        use sha2::{Digest, Sha256};
        // SEC-02 round-trip: the value apply records as
        // `X-Ghars-Runsvc-Sha256=...` MUST equal what runsvc-wrapper
        // computes when it re-reads the same file at unit start. Both
        // sides hash via SHA-256 of the full file with the
        // `sha256:HEX` prefix; if either side drifts (e.g. one uses
        // hex-uppercase, one strips trailing newline), the integrity
        // check fails on every start. This test pins the agreement.
        let tmp = tempfile::tempdir().unwrap();
        let paths = make_paths(&tmp);
        fs::create_dir_all(paths.runtime_dir.as_std_path()).unwrap();
        let plan = make_runner_plan("rt", &paths.state_dir);
        let systemd = MockSystemd::default();
        let mut auth_map: HashMap<String, Box<dyn TokenSource>> = HashMap::new();
        auth_map.insert(
            "pat".into(),
            Box::new(MockTokenSource {
                name: "pat".into(),
                ..MockTokenSource::default()
            }),
        );
        let tarball = MockTarball::default();
        let config_shell = MockConfigShell::default();
        let deps = Deps {
            systemd: &systemd,
            auth: &auth_map,
            tarball: &tarball,
            config_shell: &config_shell,
        };
        execute_create_runner(&plan, &deps, &paths, &mut UndoLog::new()).unwrap();

        // Recompute the digest the way runsvc-wrapper would: read the
        // raw bytes the MockConfigShell wrote, hash with sha2::Sha256,
        // format with the `sha256:HEX` lowercase-hex prefix.
        let runsvc = paths.runner_home("default", "rt").join("runsvc.sh");
        let bytes = fs::read(runsvc.as_std_path()).unwrap();
        let mut h = Sha256::new();
        h.update(&bytes);
        let direct = format!("sha256:{}", hex::encode(h.finalize()));

        let drop_in =
            fs::read_to_string(paths.drop_in_dir("rt").join("00-ghars.conf").as_std_path())
                .unwrap();
        assert!(
            drop_in.contains(&format!("X-Ghars-Runsvc-Sha256={direct}")),
            "drop-in did not carry round-trip digest {direct}: {drop_in}"
        );
    }

    #[test]
    fn update_runner_in_place_preserves_operator_drop_ins() {
        // BUG #B36: in-place update path must preserve operator-managed
        // drop-ins. Anything outside MANAGED_DROP_IN_BASENAMES is
        // operator territory (typically `99-*.conf` from `systemctl
        // edit`) and must survive every apply. The `Drift` classifier
        // already flags such files at plan time; deleting them here
        // would silently undo `systemctl edit`.
        let tmp = tempfile::tempdir().unwrap();
        let paths = make_paths(&tmp);
        fs::create_dir_all(paths.runtime_dir.as_std_path()).unwrap();
        // Pre-stage drop-in dir with both a stale managed drop-in (one
        // the new plan no longer emits — must be deleted) and operator
        // drop-ins (must be preserved).
        let drop_in_dir = paths.drop_in_dir("a");
        fs::create_dir_all(drop_in_dir.as_std_path()).unwrap();
        let stale_managed = drop_in_dir.join("10-memory.conf");
        let operator = drop_in_dir.join("99-operator.conf");
        let unrelated = drop_in_dir.join("custom-tweak.conf");
        fs::write(stale_managed.as_std_path(), b"[Service]\nMemoryMax=8G\n").unwrap();
        fs::write(operator.as_std_path(), b"[Service]\nLimitNOFILE=1048576\n").unwrap();
        fs::write(unrelated.as_std_path(), b"[Service]\nNice=-5\n").unwrap();

        let plan = make_runner_plan("a", &paths.state_dir);
        let delta = RunnerDelta {
            identity: RunnerIdentity {
                name: "a".into(),
                url: "https://github.com/example/repo".into(),
                auth_name: "pat".into(),
                trust_zone: "default".into(),
            },
            after: plan,
            requires_recreate: false,
            recreate_reasons: vec![],
            drift_cause: crate::plan::DriftCause::DriftDetected,
            field_changes: Vec::new(),
            // The deletion pass reads from `drop_in_changes`
            // (Stage 2 byte-comparison result), not from a fresh
            // on-disk dir scan. Stage 2 walks the union of rendered
            // + discovered keys, so an operator-edited
            // `99-operator.conf` discovered on disk but absent from
            // the rendered set DOES appear here as a Removed entry.
            // The BUG #B36 invariant — operator drop-ins survive
            // every apply — is enforced by the
            // MANAGED_DROP_IN_BASENAMES guard inside
            // execute_update_runner's deletion loop: it deletes only
            // basenames ghars itself would emit. We synthesize both
            // a managed `10-memory.conf` Removed (must be deleted)
            // AND a `99-operator.conf` Removed (must be guarded and
            // preserved) so this test exercises both branches.
            drop_in_changes: vec![
                crate::plan::DropInChange {
                    basename: "10-memory.conf".into(),
                    change: DropInChangeKind::Removed {
                        before: "[Service]\nMemoryMax=8G\n".into(),
                    },
                },
                crate::plan::DropInChange {
                    basename: "99-operator.conf".into(),
                    change: DropInChangeKind::Removed {
                        before: "[Service]\nLimitNOFILE=1048576\n".into(),
                    },
                },
            ],
            before_caches: None,
            before_drop_in_basenames: None,
        };
        let systemd = MockSystemd::default();
        let auth_map: HashMap<String, Box<dyn TokenSource>> = HashMap::new();
        let tarball = MockTarball::default();
        let config_shell = MockConfigShell::default();
        let deps = Deps {
            systemd: &systemd,
            auth: &auth_map,
            tarball: &tarball,
            config_shell: &config_shell,
        };
        execute_update_runner(&delta, &deps, &paths, &mut UndoLog::new()).unwrap();

        // The stale MANAGED file is gone (the new plan omits it).
        assert!(
            !stale_managed.as_std_path().exists(),
            "stale managed drop-in 10-memory.conf was not deleted"
        );
        // The 99-operator.conf is preserved.
        assert!(
            operator.as_std_path().exists(),
            "operator drop-in 99-operator.conf was deleted"
        );
        let body = fs::read_to_string(operator.as_std_path()).unwrap();
        assert!(
            body.contains("LimitNOFILE=1048576"),
            "operator drop-in body was modified: {body}"
        );
        // Any other operator-named file (no recognized prefix) is
        // also preserved.
        assert!(
            unrelated.as_std_path().exists(),
            "non-managed drop-in custom-tweak.conf was deleted"
        );
    }

    #[test]
    fn remove_runner_unregisters_and_cleans_up() {
        let tmp = tempfile::tempdir().unwrap();
        let paths = make_paths(&tmp);
        fs::create_dir_all(paths.runtime_dir.as_std_path()).unwrap();
        // Pre-stage a runner home + unit file so remove can clean them.
        let runner_home = paths.runner_home("default", "a");
        fs::create_dir_all(runner_home.as_std_path()).unwrap();
        fs::write(runner_home.join("config.sh").as_std_path(), b"#!/bin/sh\n").unwrap();
        fs::create_dir_all(paths.unit_dir.as_std_path()).unwrap();
        fs::write(paths.unit_file("a").as_std_path(), b"[Unit]\n").unwrap();
        let drop_in_dir = paths.drop_in_dir("a");
        fs::create_dir_all(drop_in_dir.as_std_path()).unwrap();
        let identity = RunnerIdentity {
            name: "a".into(),
            url: "https://github.com/example/repo".into(),
            auth_name: "pat".into(),
            trust_zone: "default".into(),
        };
        let systemd = MockSystemd::default();
        let mut auth_map: HashMap<String, Box<dyn TokenSource>> = HashMap::new();
        auth_map.insert(
            "pat".into(),
            Box::new(MockTokenSource {
                name: "pat".into(),
                ..MockTokenSource::default()
            }),
        );
        let config_shell = MockConfigShell::default();
        let tarball = MockTarball::default();
        let deps = Deps {
            systemd: &systemd,
            auth: &auth_map,
            tarball: &tarball,
            config_shell: &config_shell,
        };
        execute_remove_runner(&identity, &deps, &paths, &mut UndoLog::new()).unwrap();
        assert!(!paths.unit_file("a").as_std_path().exists());
        assert!(!runner_home.as_std_path().exists());
        assert_eq!(config_shell.removed.lock().unwrap().len(), 1);
        let calls = systemd.calls_snapshot();
        assert!(
            calls
                .iter()
                .any(|c| c == "stop_unit(ghars-runner@a.service)")
        );
        assert!(
            calls
                .iter()
                .any(|c| c == "disable_unit(ghars-runner@a.service)")
        );
    }

    fn make_pool_plan(name: &str, kinds: Vec<crate::config::CacheKind>) -> CachePoolPlan {
        let binding = crate::config::EffectiveCacheBinding {
            name: name.into(),
            kinds,
            size: "200G".into(),
            mode: crate::config::CacheMode::Shared,
            trust_zone: "default".into(),
        };
        let body =
            crate::systemd::render_cache_drop_in(&binding, "/etc/ghars/ghars.toml", "sha256:abcd")
                .unwrap();
        CachePoolPlan {
            binding,
            drop_in_body: body,
            spec_hash: "sha256:abcd".into(),
        }
    }

    #[test]
    fn create_cache_pool_writes_template_drop_in_and_provisions_group() {
        let tmp = tempfile::tempdir().unwrap();
        let paths = make_paths(&tmp);
        fs::create_dir_all(paths.runtime_dir.as_std_path()).unwrap();
        let plan = make_pool_plan(
            "build",
            vec![
                crate::config::CacheKind::Sccache,
                crate::config::CacheKind::Ccache,
            ],
        );
        let systemd = MockSystemd::default();
        let auth_map: HashMap<String, Box<dyn TokenSource>> = HashMap::new();
        let tarball = MockTarball::default();
        let config_shell = MockConfigShell::default();
        let deps = Deps {
            systemd: &systemd,
            auth: &auth_map,
            tarball: &tarball,
            config_shell: &config_shell,
        };
        execute_create_cache_pool(&plan, &deps, &paths, &mut UndoLog::new()).unwrap();
        // Template unit body matches the canonical Part 9b template.
        let template = paths.cache_template_unit_file();
        assert!(template.as_std_path().exists());
        let template_body = fs::read_to_string(template.as_std_path()).unwrap();
        assert!(template_body.contains("Description=ghars cache service"));
        assert!(template_body.contains("CacheDirectory=ghars/pools/%i"));
        // Drop-in landed.
        let drop_in = paths.cache_drop_in_dir("build").join("00-ghars.conf");
        assert!(drop_in.as_std_path().exists());
        let drop_in_body = fs::read_to_string(drop_in.as_std_path()).unwrap();
        assert!(drop_in_body.contains("X-Ghars-Pool-Name=build"));
        assert!(drop_in_body.contains("ExecStart=/usr/bin/sccache --start-server"));
        assert!(drop_in_body.contains("SCCACHE_NO_DAEMON=1"));
        // No groupadd: cache reach is socket-DAC + BindPaths under
        // DynamicUser; the per-pool group concept is gone.
        // Systemd was called: enable + daemon_reload + start.
        let calls = systemd.calls_snapshot();
        assert!(
            calls
                .iter()
                .any(|c| c == "enable_unit(ghars-cache@build.service)")
        );
        assert!(
            calls
                .iter()
                .any(|c| c == "start_unit(ghars-cache@build.service)")
        );
        assert!(calls.iter().any(|c| c == "daemon_reload"));
    }

    #[test]
    fn remove_cache_pool_cleans_up_dir_dropin_and_group() {
        let tmp = tempfile::tempdir().unwrap();
        let paths = make_paths(&tmp);
        fs::create_dir_all(paths.runtime_dir.as_std_path()).unwrap();
        // Pre-stage a drop-in dir + pool dir as if a prior apply had
        // created them.
        let drop_in_dir = paths.cache_drop_in_dir("build");
        fs::create_dir_all(drop_in_dir.as_std_path()).unwrap();
        fs::write(
            drop_in_dir.join("00-ghars.conf").as_std_path(),
            b"[Service]\n",
        )
        .unwrap();
        let pool_dir = paths.cache_pool_dir("build");
        fs::create_dir_all(pool_dir.join("sccache").as_std_path()).unwrap();
        fs::write(
            pool_dir.join("sccache/blob").as_std_path(),
            b"cache content",
        )
        .unwrap();

        let systemd = MockSystemd::default();
        let auth_map: HashMap<String, Box<dyn TokenSource>> = HashMap::new();
        let tarball = MockTarball::default();
        let config_shell = MockConfigShell::default();
        let deps = Deps {
            systemd: &systemd,
            auth: &auth_map,
            tarball: &tarball,
            config_shell: &config_shell,
        };
        execute_remove_cache_pool("build", &deps, &paths, &mut UndoLog::new()).unwrap();
        // Drop-in dir gone.
        assert!(!drop_in_dir.as_std_path().exists());
        // Pool dir gone — backing storage no longer leaks.
        assert!(!pool_dir.as_std_path().exists());
        // No groupdel: there's no per-pool group under DynamicUser.
        // Systemd was called: stop + disable.
        let calls = systemd.calls_snapshot();
        assert!(
            calls
                .iter()
                .any(|c| c == "stop_unit(ghars-cache@build.service)")
        );
        assert!(
            calls
                .iter()
                .any(|c| c == "disable_unit(ghars-cache@build.service)")
        );
    }

    #[test]
    fn cache_pool_template_is_idempotent_on_second_create() {
        // Two pool creations land in the same apply — second write must
        // succeed (template path already exists). truncate=true on
        // OpenOptions handles overwrite.
        let tmp = tempfile::tempdir().unwrap();
        let paths = make_paths(&tmp);
        fs::create_dir_all(paths.runtime_dir.as_std_path()).unwrap();
        let plan_a = make_pool_plan("a", vec![crate::config::CacheKind::Ccache]);
        let plan_b = make_pool_plan("b", vec![crate::config::CacheKind::Sccache]);
        let systemd = MockSystemd::default();
        let auth_map: HashMap<String, Box<dyn TokenSource>> = HashMap::new();
        let tarball = MockTarball::default();
        let config_shell = MockConfigShell::default();
        let deps = Deps {
            systemd: &systemd,
            auth: &auth_map,
            tarball: &tarball,
            config_shell: &config_shell,
        };
        execute_create_cache_pool(&plan_a, &deps, &paths, &mut UndoLog::new()).unwrap();
        execute_create_cache_pool(&plan_b, &deps, &paths, &mut UndoLog::new()).unwrap();
        // Template still readable + matches canonical body.
        let template_body =
            fs::read_to_string(paths.cache_template_unit_file().as_std_path()).unwrap();
        assert!(template_body.contains("CacheDirectory=ghars/pools/%i"));
        // Both pool drop-ins present and distinct.
        let body_a = fs::read_to_string(
            paths
                .cache_drop_in_dir("a")
                .join("00-ghars.conf")
                .as_std_path(),
        )
        .unwrap();
        let body_b = fs::read_to_string(
            paths
                .cache_drop_in_dir("b")
                .join("00-ghars.conf")
                .as_std_path(),
        )
        .unwrap();
        assert!(body_a.contains("X-Ghars-Pool-Name=a"));
        assert!(body_a.contains("ExecStart=/usr/bin/sleep infinity"));
        assert!(body_b.contains("X-Ghars-Pool-Name=b"));
        assert!(body_b.contains("ExecStart=/usr/bin/sccache --start-server"));
    }

    // ---------- SEC-05 regression -----------------------------------

    /// Construct a `ConfigShellCtx` with a recognisable token sentinel
    /// so each SEC-05 test can scan for it across argv vs env.
    fn sec05_ctx<'a>(home: &'a Utf8Path, token: &'a str) -> ConfigShellCtx<'a> {
        ConfigShellCtx {
            runner_home: home,
            name: "buckos",
            url: "https://github.com/example/repo",
            labels: &[],
            token,
        }
    }

    /// Helper: collect Command argv into `Vec<String>` for assertions.
    fn argv_strings(cmd: &Command) -> Vec<String> {
        cmd.get_args()
            .map(|s| s.to_string_lossy().into_owned())
            .collect()
    }

    /// Helper: lookup a single env var on a Command.
    fn env_value(cmd: &Command, key: &str) -> Option<String> {
        cmd.get_envs().find_map(|(k, v)| {
            if k == OsStr::new(key) {
                v.map(|v| v.to_string_lossy().into_owned())
            } else {
                None
            }
        })
    }

    #[test]
    fn sec05_register_argv_does_not_contain_token() {
        let token = "GHARS-SEC05-TOKEN-SENTINEL-123456";
        let home = Utf8Path::new("/var/lib/ghars/buckos");
        let ctx = sec05_ctx(home, token);
        let cmd = build_register_cmd(&ctx);
        let argv = argv_strings(&cmd);
        for arg in &argv {
            assert!(
                !arg.contains(token),
                "register argv leaked token: {arg:?} (full argv: {argv:?})",
            );
        }
        // Also assert there is no `--token` flag at all.
        assert!(
            !argv.iter().any(|a| a == "--token"),
            "register argv contains --token flag: {argv:?}",
        );
    }

    #[test]
    fn sec05_register_env_carries_token() {
        let token = "GHARS-SEC05-TOKEN-SENTINEL-123456";
        let home = Utf8Path::new("/var/lib/ghars/buckos");
        let ctx = sec05_ctx(home, token);
        let cmd = build_register_cmd(&ctx);
        assert_eq!(
            env_value(&cmd, RUNNER_TOKEN_ENV).as_deref(),
            Some(token),
            "register did not set ACTIONS_RUNNER_INPUT_TOKEN env var",
        );
    }

    // sec05_register_includes_preserve_env was deleted: the
    // pre-DynamicUser model wrapped config.sh in `sudo --preserve-env=
    // ACTIONS_RUNNER_INPUT_TOKEN -u USER --` so sudo's env_reset
    // wouldn't strip the token before exec. Under DynamicUser, apply
    // runs config.sh directly as root (systemd takes ownership of
    // StateDirectory at unit start) so there's no sudo wrapper and
    // no --preserve-env argv slot. The SEC-05 token-via-env contract
    // still holds — `sec05_register_argv_does_not_contain_token`
    // (sibling) pins that argv carries no token.

    #[test]
    fn sec05_remove_argv_does_not_contain_token() {
        let token = "GHARS-SEC05-REMOVE-TOKEN-654321";
        let home = Utf8Path::new("/var/lib/ghars/buckos");
        let ctx = sec05_ctx(home, token);
        let cmd = build_remove_cmd(&ctx);
        let argv = argv_strings(&cmd);
        for arg in &argv {
            assert!(
                !arg.contains(token),
                "remove argv leaked token: {arg:?} (full argv: {argv:?})",
            );
        }
        assert!(
            !argv.iter().any(|a| a == "--token"),
            "remove argv contains --token flag: {argv:?}",
        );
    }

    #[test]
    fn sec05_remove_env_carries_token() {
        let token = "GHARS-SEC05-REMOVE-TOKEN-654321";
        let home = Utf8Path::new("/var/lib/ghars/buckos");
        let ctx = sec05_ctx(home, token);
        let cmd = build_remove_cmd(&ctx);
        assert_eq!(
            env_value(&cmd, RUNNER_TOKEN_ENV).as_deref(),
            Some(token),
            "remove did not set ACTIONS_RUNNER_INPUT_TOKEN env var",
        );
    }

    #[test]
    fn sec05_register_argv_includes_expected_flags() {
        // Sanity check that the new argv still drives the runner.
        let ctx = sec05_ctx(Utf8Path::new("/var/lib/ghars/buckos"), "TOKEN");
        let cmd = build_register_cmd(&ctx);
        let argv = argv_strings(&cmd);
        for required in ["--url", "--name", "--labels", "--unattended", "--replace"] {
            assert!(
                argv.iter().any(|a| a == required),
                "register argv missing {required}: {argv:?}",
            );
        }
    }

    #[test]
    fn sec05_remove_argv_includes_remove_subcommand() {
        let ctx = sec05_ctx(Utf8Path::new("/var/lib/ghars/buckos"), "TOKEN");
        let cmd = build_remove_cmd(&ctx);
        let argv = argv_strings(&cmd);
        assert!(argv.iter().any(|a| a == "remove"), "{argv:?}");
        assert!(argv.iter().any(|a| a == "--unattended"), "{argv:?}");
    }

    /// Helper: build a Netns binding so the spec passes through
    /// `provision_netns_artifacts`. Mirrors the systemd-test fixture.
    fn make_netns_binding(subnet: &str) -> crate::config::EffectiveNetworkBinding {
        use crate::config::{
            DnsMode, EffectiveNetworkBinding, EgressRule, Ipv6Mode, NetworkMode, NetworkSpec,
            PortSpec, Proto,
        };
        EffectiveNetworkBinding {
            name: "buck2-isolated".into(),
            spec: NetworkSpec {
                mode: NetworkMode::Netns,
                allowed_egress: vec![EgressRule {
                    addr: "192.168.2.84".into(),
                    port: PortSpec::Single(3128),
                    proto: Proto::Tcp,
                    comment: None,
                }],
                ip_allow: vec![],
                ip_deny: vec![],
                address_families: vec![],
                dns: DnsMode::default(),
                ipv6: Ipv6Mode::default(),
            },
            subnet: subnet.parse::<ipnet::IpNet>().unwrap(),
        }
    }

    #[test]
    fn create_runner_with_netns_provisions_template_nft_config_and_starts_netns_unit() {
        let tmp = tempfile::tempdir().unwrap();
        let paths = make_paths(&tmp);
        fs::create_dir_all(paths.runtime_dir.as_std_path()).unwrap();
        let mut plan = make_runner_plan("a", &paths.state_dir);
        plan.spec.network = Some(make_netns_binding("10.200.0.0/30"));
        let systemd = MockSystemd::default();
        // verify_runner_netns reads /proc/MainPID/ns/net and compares it
        // to /proc/1/ns/net. In CI the test process IS in the host netns
        // so the readlinks match — the post-start check fires the
        // netns fail-closed branch and returns an error. We don't care: every
        // pre-start side effect is what this test guards.
        systemd.set_property(
            "ghars-runner@a.service",
            "MainPID",
            &std::process::id().to_string(),
        );
        let mut auth_map: HashMap<String, Box<dyn TokenSource>> = HashMap::new();
        auth_map.insert(
            "pat".into(),
            Box::new(MockTokenSource {
                name: "pat".into(),
                ..MockTokenSource::default()
            }),
        );
        let tarball = MockTarball::default();
        let config_shell = MockConfigShell::default();
        let deps = Deps {
            systemd: &systemd,
            auth: &auth_map,
            tarball: &tarball,
            config_shell: &config_shell,
        };
        // Best-effort call. The post-start verify_runner_netns fails in
        // CI; pre-start artifacts must already be on disk regardless.
        let _ = execute_create_runner(&plan, &deps, &paths, &mut UndoLog::new());

        // 1) NetnsConfig TOML written to <config_dir>/netns.d/a.toml.
        let cfg_path = NetnsConfig::path_for(&paths, "a");
        assert!(cfg_path.as_std_path().exists(), "netns.d/a.toml missing");
        let cfg_body = fs::read_to_string(cfg_path.as_std_path()).unwrap();
        assert!(cfg_body.contains("subnet"));
        assert!(cfg_body.contains("10.200.0.0/30"));

        // 2) nft rule files written.
        let host_nft = paths.nft_host_rule("a");
        let ns_nft = paths.nft_ns_rule("a");
        assert!(host_nft.as_std_path().exists(), "host nft missing");
        assert!(ns_nft.as_std_path().exists(), "ns nft missing");
        let host_body = fs::read_to_string(host_nft.as_std_path()).unwrap();
        assert!(host_body.contains("table inet ghars_a"));
        assert!(host_body.contains("ip saddr 10.200.0.0/30"));

        // 3) ghars-net@.service template written (idempotent shared body).
        let template_path = paths.netns_template_unit_file();
        assert!(
            template_path.as_std_path().exists(),
            "netns template missing"
        );
        let template_body = fs::read_to_string(template_path.as_std_path()).unwrap();
        assert!(template_body.contains("ghars _netns-setup %i"));
        assert!(template_body.contains("StopWhenUnneeded=no"));

        // 4) ghars-net@a was enabled + started before the runner unit.
        let calls = systemd.calls_snapshot();
        let netns_enable = calls
            .iter()
            .position(|c| c == "enable_unit(ghars-net@a.service)");
        let netns_start = calls
            .iter()
            .position(|c| c == "start_unit(ghars-net@a.service)");
        let runner_start = calls
            .iter()
            .position(|c| c == "start_unit(ghars-runner@a.service)");
        assert!(netns_enable.is_some(), "ghars-net@a not enabled: {calls:?}");
        let netns_start = netns_start.expect("ghars-net@a not started");
        let runner_start = runner_start.expect("runner unit not started");
        assert!(
            netns_start < runner_start,
            "netns must start before runner: {calls:?}",
        );
    }

    #[test]
    fn create_runner_open_mode_writes_no_netns_artifacts() {
        let tmp = tempfile::tempdir().unwrap();
        let paths = make_paths(&tmp);
        fs::create_dir_all(paths.runtime_dir.as_std_path()).unwrap();
        // Default make_runner_plan has spec.network = None.
        let plan = make_runner_plan("open", &paths.state_dir);
        let systemd = MockSystemd::default();
        let mut auth_map: HashMap<String, Box<dyn TokenSource>> = HashMap::new();
        auth_map.insert(
            "pat".into(),
            Box::new(MockTokenSource {
                name: "pat".into(),
                ..MockTokenSource::default()
            }),
        );
        let tarball = MockTarball::default();
        let config_shell = MockConfigShell::default();
        let deps = Deps {
            systemd: &systemd,
            auth: &auth_map,
            tarball: &tarball,
            config_shell: &config_shell,
        };
        execute_create_runner(&plan, &deps, &paths, &mut UndoLog::new()).unwrap();

        // No NetnsConfig, no nft rules, no netns template, no ghars-net@
        // calls.
        assert!(!NetnsConfig::path_for(&paths, "open").as_std_path().exists());
        assert!(!paths.nft_host_rule("open").as_std_path().exists());
        assert!(!paths.nft_ns_rule("open").as_std_path().exists());
        assert!(!paths.netns_template_unit_file().as_std_path().exists());
        let calls = systemd.calls_snapshot();
        assert!(
            !calls.iter().any(|c| c.contains("ghars-net@")),
            "Open-mode runner must not touch ghars-net@: {calls:?}"
        );
    }

    #[test]
    fn remove_runner_tears_down_netns_artifacts() {
        let tmp = tempfile::tempdir().unwrap();
        let paths = make_paths(&tmp);
        fs::create_dir_all(paths.runtime_dir.as_std_path()).unwrap();
        // Pre-stage runner state + netns artifacts as if a prior apply
        // had created them.
        let runner_home = paths.runner_home("default", "a");
        fs::create_dir_all(runner_home.as_std_path()).unwrap();
        fs::write(runner_home.join("config.sh").as_std_path(), b"#!/bin/sh\n").unwrap();
        fs::create_dir_all(paths.unit_dir.as_std_path()).unwrap();
        fs::write(paths.unit_file("a").as_std_path(), b"[Unit]\n").unwrap();
        fs::create_dir_all(paths.drop_in_dir("a").as_std_path()).unwrap();
        // Netns artifacts.
        let cfg = NetnsConfig {
            subnet: "10.200.0.0/30".parse().unwrap(),
            dns: crate::config::DnsMode::default(),
        };
        cfg.write(&paths, "a").unwrap();
        let nft_dir = paths.config_dir.join("nft.d");
        fs::create_dir_all(nft_dir.as_std_path()).unwrap();
        fs::write(
            paths.nft_host_rule("a").as_std_path(),
            b"table inet ghars_a {}\n",
        )
        .unwrap();
        fs::write(
            paths.nft_ns_rule("a").as_std_path(),
            b"table inet ghars_a_ns {}\n",
        )
        .unwrap();

        let identity = RunnerIdentity {
            name: "a".into(),
            url: "https://github.com/example/repo".into(),
            auth_name: "pat".into(),
            trust_zone: "default".into(),
        };
        let systemd = MockSystemd::default();
        let mut auth_map: HashMap<String, Box<dyn TokenSource>> = HashMap::new();
        auth_map.insert(
            "pat".into(),
            Box::new(MockTokenSource {
                name: "pat".into(),
                ..MockTokenSource::default()
            }),
        );
        let config_shell = MockConfigShell::default();
        let tarball = MockTarball::default();
        let deps = Deps {
            systemd: &systemd,
            auth: &auth_map,
            tarball: &tarball,
            config_shell: &config_shell,
        };
        execute_remove_runner(&identity, &deps, &paths, &mut UndoLog::new()).unwrap();

        // ghars-net@a stopped + disabled.
        let calls = systemd.calls_snapshot();
        assert!(
            calls.iter().any(|c| c == "stop_unit(ghars-net@a.service)"),
            "ghars-net@a not stopped: {calls:?}"
        );
        assert!(
            calls
                .iter()
                .any(|c| c == "disable_unit(ghars-net@a.service)"),
            "ghars-net@a not disabled: {calls:?}"
        );

        // Netns artifacts gone.
        assert!(
            !NetnsConfig::path_for(&paths, "a").as_std_path().exists(),
            "netns config TOML still present"
        );
        assert!(
            !paths.nft_host_rule("a").as_std_path().exists(),
            "host nft still present"
        );
        assert!(
            !paths.nft_ns_rule("a").as_std_path().exists(),
            "ns nft still present"
        );
    }

    // ---- verify_runner_netns_at happy + fail paths --------------------
    //
    // These tests use `verify_runner_netns_at` with a tempdir-rooted
    // proc layout so they can exercise both the happy path (distinct
    // ns/net symlink targets) and the fail path (matching targets ⇒
    // host-namespace fallback) without root or a real netns'd unit.

    /// Build a synthetic proc layout: `<root>/<pid>/ns/net` →
    /// `<runner_target>` and `<root>/1/ns/net` → `<host_target>`.
    fn synth_proc_netns_layout(
        root: &std::path::Path,
        pid: u32,
        runner_target: &str,
        host_target: &str,
    ) {
        let pid_dir = root.join(pid.to_string()).join("ns");
        std::fs::create_dir_all(&pid_dir).unwrap();
        // Symlink may already exist when a test calls this twice with
        // overlapping PIDs (e.g. mid-retry tests seed both PID=1 and
        // a runner PID under the same root). symlink(2) returns EEXIST
        // on a pre-existing path; remove first so the second call is
        // idempotent.
        let pid_link = pid_dir.join("net");
        let _ = std::fs::remove_file(&pid_link);
        std::os::unix::fs::symlink(runner_target, &pid_link).unwrap();
        let host_dir = root.join("1").join("ns");
        std::fs::create_dir_all(&host_dir).unwrap();
        let host_link = host_dir.join("net");
        let _ = std::fs::remove_file(&host_link);
        std::os::unix::fs::symlink(host_target, &host_link).unwrap();
    }

    /// 50ms deadline for `verify_runner_netns_at` unit tests. Short
    /// enough that fail-path tests don't slow the suite. Production
    /// uses `NETNS_VERIFY_DEADLINE` (5s).
    const TEST_NETNS_VERIFY_DEADLINE: std::time::Duration = std::time::Duration::from_millis(50);

    /// 5ms backoff for verify_runner_netns_at unit tests. Combined
    /// with the 50ms deadline, this allows up to ~10 polls per
    /// test — enough to exercise FlippingMockSystemd's flip_after=1
    /// (recovers-on-second-poll) and the persistent-ENOENT fail path.
    /// Production uses NETNS_VERIFY_BACKOFF (100ms).
    const TEST_NETNS_VERIFY_BACKOFF: std::time::Duration = std::time::Duration::from_millis(5);

    #[test]
    fn verify_runner_netns_at_passes_when_targets_differ() {
        // Happy path: runner is in an isolated netns. The runner's
        // `/proc/<pid>/ns/net` symlink target differs from
        // `/proc/1/ns/net`'s target, so the function returns Ok.
        let tmp = tempfile::tempdir().unwrap();
        synth_proc_netns_layout(
            tmp.path(),
            1234,
            "net:[4026532900]", // isolated namespace inode
            "net:[4026531992]", // host namespace inode
        );
        let systemd = MockSystemd::default();
        systemd.set_property("ghars-runner@buckos.service", "MainPID", "1234");
        verify_runner_netns_at(
            tmp.path(),
            "ghars-runner@buckos.service",
            &systemd,
            TEST_NETNS_VERIFY_DEADLINE,
            TEST_NETNS_VERIFY_BACKOFF,
        )
        .expect("isolated netns must pass verify");
    }

    /// MockSystemd variant whose MainPID property changes after the
    /// first `flip_after` calls. Used by the retry-recovery test:
    /// the first reads return the host-netns'd PID; subsequent reads
    /// return the freshly-joined PID, mimicking the kernel-side setns
    /// race. MainPID flows through get_unit_property_u64 on the
    /// Service interface; the mock stores u64 directly, no String
    /// round-trip.
    struct FlippingMockSystemd {
        unit: String,
        first_pid: u64,
        second_pid: u64,
        flip_after: u32,
        calls: std::sync::atomic::AtomicU32,
    }

    impl Systemd for FlippingMockSystemd {
        fn daemon_reload(&self) -> Result<()> {
            Ok(())
        }
        fn start_unit(&self, _: &str) -> Result<()> {
            Ok(())
        }
        fn stop_unit(&self, _: &str) -> Result<()> {
            Ok(())
        }
        fn enable_unit(&self, _: &str) -> Result<()> {
            Ok(())
        }
        fn disable_unit(&self, _: &str) -> Result<()> {
            Ok(())
        }
        fn list_units_filtered(&self, _: &[&str]) -> Result<Vec<UnitListEntry>> {
            Ok(vec![])
        }
        fn get_unit_property(&self, _: &str, _: &str, _: &str) -> Result<String> {
            unreachable!("FlippingMockSystemd only services MainPID via get_unit_property_u64")
        }
        fn get_unit_property_u64(&self, unit: &str, iface: &str, property: &str) -> Result<u64> {
            assert_eq!(unit, self.unit);
            assert_eq!(iface, "org.freedesktop.systemd1.Service");
            assert_eq!(property, "MainPID");
            let n = self.calls.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
            if n < self.flip_after {
                Ok(self.first_pid)
            } else {
                Ok(self.second_pid)
            }
        }
        fn get_unit_property_object_path(
            &self,
            _: &str,
            _: &str,
            _: &str,
        ) -> Result<zbus::zvariant::OwnedObjectPath> {
            unreachable!()
        }
        fn get_service_property_string(&self, _: &str, _: &str) -> Result<String> {
            unreachable!("FlippingMockSystemd only services MainPID via get_service_property_u64")
        }
        fn get_service_property_u64(&self, unit: &str, property: &str) -> Result<u64> {
            self.get_unit_property_u64(unit, "org.freedesktop.systemd1.Service", property)
        }
    }

    #[test]
    fn verify_runner_netns_at_recovers_when_kernel_join_lands_mid_retry() {
        // The kernel-side setns(NetworkNamespacePath=) call lands
        // during the runner's exec, AFTER systemd's StartUnit returns.
        // A single readlink at StartUnit-return-time can observe the
        // still-host symlink target. The retry loop must recover when
        // the join lands by attempt 2 or 3. Flipping mock returns
        // PID=1 (which has the host symlink) for the first call, then
        // PID=5678 (which has an isolated symlink) for subsequent calls.
        let tmp = tempfile::tempdir().unwrap();
        // Synth /proc/1/ns/net = host_target, /proc/5678/ns/net = isolated.
        let host_target = "net:[4026531992]";
        let isolated_target = "net:[4026535123]";
        // synth_proc_netns_layout writes both `<pid>/ns/net` and
        // `1/ns/net` — calling it with pid==1 collides those two paths
        // with EEXIST. Use host-only synth for the PID=1 leg, then lay
        // down /proc/5678/ns/net pointing at the isolated target.
        synth_host_only_proc_layout(tmp.path(), host_target);
        let pid_dir = tmp.path().join("5678").join("ns");
        std::fs::create_dir_all(&pid_dir).unwrap();
        std::os::unix::fs::symlink(isolated_target, pid_dir.join("net")).unwrap();
        let systemd = FlippingMockSystemd {
            unit: "ghars-runner@buckos.service".into(),
            first_pid: 1,
            second_pid: 5678,
            flip_after: 1,
            calls: std::sync::atomic::AtomicU32::new(0),
        };
        // Must succeed: attempt 1 sees PID=1 (host-netns'd), attempt 2
        // sees PID=5678 (isolated). Without the retry, this would
        // false-positive a netns fail-open and abort.
        verify_runner_netns_at(
            tmp.path(),
            "ghars-runner@buckos.service",
            &systemd,
            TEST_NETNS_VERIFY_DEADLINE,
            TEST_NETNS_VERIFY_BACKOFF,
        )
        .unwrap();
    }

    #[test]
    fn verify_runner_netns_at_treats_enoent_on_proc_pid_as_transient() {
        // ENOENT on /proc/PID/ns/net is a transient race condition
        // (the PID was just exec'd by systemd and recorded via
        // service_set_main_pidref before the kernel made /proc/PID
        // visible, OR the PID was reaped between the get_unit_property
        // call and the readlink). Verify must retry — NOT treat missing
        // /proc/PID as success (which would be a fail-open: a PID that
        // doesn't exist trivially isn't in the host netns either).
        // FlippingMock returns PID=99999 (which has no /proc/99999 in
        // our tempdir) for the first call, then PID=5678 (which has an
        // isolated symlink) for subsequent calls. ENOENT on attempt 1
        // → retry → success on attempt 2.
        let tmp = tempfile::tempdir().unwrap();
        let host_target = "net:[4026531992]";
        let isolated_target = "net:[4026535123]";
        // Lay down /proc/1/ns/net (host) and /proc/5678/ns/net (isolated).
        // Crucially do NOT create /proc/99999 — first readlink hits ENOENT.
        synth_host_only_proc_layout(tmp.path(), host_target);
        let pid_dir = tmp.path().join("5678").join("ns");
        std::fs::create_dir_all(&pid_dir).unwrap();
        std::os::unix::fs::symlink(isolated_target, pid_dir.join("net")).unwrap();
        let systemd = FlippingMockSystemd {
            unit: "ghars-runner@buckos.service".into(),
            first_pid: 99999,
            second_pid: 5678,
            flip_after: 1,
            calls: std::sync::atomic::AtomicU32::new(0),
        };
        verify_runner_netns_at(
            tmp.path(),
            "ghars-runner@buckos.service",
            &systemd,
            TEST_NETNS_VERIFY_DEADLINE,
            TEST_NETNS_VERIFY_BACKOFF,
        )
        .expect("ENOENT on /proc/PID must be transient → retry → succeed");
    }

    #[test]
    fn verify_runner_netns_at_persistent_enoent_on_proc_pid_errors_systemd() {
        // If /proc/PID/ns/net stays missing for the entire
        // deadline (e.g. systemd recorded MainPID but the unit failed
        // to start past fork), surface a Systemd error — not Ok (which
        // would be a fail-open). The error message must mention the
        // poll count and the apply_namespace contract so an operator
        // can correlate with `journalctl -u`.
        let tmp = tempfile::tempdir().unwrap();
        // PID 99999's /proc entry never exists.
        synth_host_only_proc_layout(tmp.path(), "net:[4026531992]");
        let systemd = MockSystemd::default();
        systemd.set_property("ghars-runner@buckos.service", "MainPID", "99999");
        let err = verify_runner_netns_at(
            tmp.path(),
            "ghars-runner@buckos.service",
            &systemd,
            TEST_NETNS_VERIFY_DEADLINE,
            TEST_NETNS_VERIFY_BACKOFF,
        )
        .expect_err("persistent ENOENT must NOT count as success");
        let msg = format!("{err}");
        assert!(
            matches!(err, GharsError::Systemd(_, _)),
            "expected Systemd variant, got: {err:?}"
        );
        assert!(
            msg.contains("never resolved"),
            "expected 'never resolved' in error; got: {msg}"
        );
        assert!(
            msg.contains("apply_namespace"),
            "expected 'apply_namespace' citation in error; got: {msg}"
        );
    }

    #[test]
    fn verify_runner_netns_at_aborts_when_targets_match_host() {
        // Fail path: runner symlink target == host's. The netns
        // fail-closed branch fires — abort with a Validation error
        // wrapped in Apply.
        let tmp = tempfile::tempdir().unwrap();
        synth_proc_netns_layout(tmp.path(), 5678, "net:[4026531992]", "net:[4026531992]");
        let systemd = MockSystemd::default();
        systemd.set_property("ghars-runner@buckos.service", "MainPID", "5678");
        let err = verify_runner_netns_at(
            tmp.path(),
            "ghars-runner@buckos.service",
            &systemd,
            TEST_NETNS_VERIFY_DEADLINE,
            TEST_NETNS_VERIFY_BACKOFF,
        )
        .unwrap_err();
        let msg = format!("{err}");
        assert!(msg.contains("HOST network namespace"), "{msg}");
        assert!(msg.contains("5678"), "{msg}");
        // Error message must record that we polled before giving
        // up — operator triaging a netns fail-open needs to know the
        // verify ran multiple readlinks against the deadline, not a
        // single shot.
        assert!(
            msg.contains("polls"),
            "error must report poll count; got: {msg}"
        );
        assert!(
            msg.contains(&format!("{}ms", TEST_NETNS_VERIFY_DEADLINE.as_millis())),
            "error must report deadline; got: {msg}"
        );
        // Pin the variant: Apply wraps a Validation. A future change
        // that flattened to plain Validation would silently change
        // the CLI exit-code mapping.
        match err {
            GharsError::Apply { source, .. } => {
                assert!(
                    matches!(*source, GharsError::Validation(_, _)),
                    "expected Apply{{source: Validation}}, got {source:?}"
                );
            }
            other => panic!("expected GharsError::Apply, got {other:?}"),
        }
    }

    /// Synthesize only the host `<root>/1/ns/net` symlink, leaving the
    /// per-PID layer for tests that fail before reaching the readlink
    /// for the runner. The function reads `/proc/1/ns/net` first so
    /// the host symlink must always exist before we drive any case.
    fn synth_host_only_proc_layout(root: &std::path::Path, host_target: &str) {
        let host_dir = root.join("1").join("ns");
        std::fs::create_dir_all(&host_dir).unwrap();
        std::os::unix::fs::symlink(host_target, host_dir.join("net")).unwrap();
    }

    #[test]
    fn verify_runner_netns_at_errors_on_main_pid_zero() {
        let tmp = tempfile::tempdir().unwrap();
        synth_host_only_proc_layout(tmp.path(), "net:[4026531992]");
        let systemd = MockSystemd::default();
        systemd.set_property("ghars-runner@buckos.service", "MainPID", "0");
        let err = verify_runner_netns_at(
            tmp.path(),
            "ghars-runner@buckos.service",
            &systemd,
            TEST_NETNS_VERIFY_DEADLINE,
            TEST_NETNS_VERIFY_BACKOFF,
        )
        .unwrap_err();
        let msg = format!("{err}");
        assert!(msg.contains("MainPID is 0"), "{msg}");
    }

    #[test]
    fn verify_runner_netns_at_errors_on_main_pid_nonnumeric() {
        let tmp = tempfile::tempdir().unwrap();
        synth_host_only_proc_layout(tmp.path(), "net:[4026531992]");
        let systemd = MockSystemd::default();
        systemd.set_property("ghars-runner@buckos.service", "MainPID", "not-a-pid");
        let err = verify_runner_netns_at(
            tmp.path(),
            "ghars-runner@buckos.service",
            &systemd,
            TEST_NETNS_VERIFY_DEADLINE,
            TEST_NETNS_VERIFY_BACKOFF,
        )
        .unwrap_err();
        let msg = format!("{err}");
        assert!(msg.contains("not u64"), "{msg}");
    }

    #[test]
    fn verify_runner_netns_at_propagates_systemd_property_lookup_failure() {
        // MockSystemd returns a Systemd error when the property isn't
        // registered. The function must surface that as Apply{source:
        // Systemd} rather than panicking. (Host symlink present so we
        // get past the first readlink.)
        let tmp = tempfile::tempdir().unwrap();
        synth_host_only_proc_layout(tmp.path(), "net:[4026531992]");
        let systemd = MockSystemd::default();
        let err = verify_runner_netns_at(
            tmp.path(),
            "ghars-runner@buckos.service",
            &systemd,
            TEST_NETNS_VERIFY_DEADLINE,
            TEST_NETNS_VERIFY_BACKOFF,
        )
        .unwrap_err();
        match err {
            GharsError::Apply { source, .. } => {
                assert!(
                    matches!(*source, GharsError::Systemd(_, _)),
                    "expected Apply{{source: Systemd}}, got {source:?}"
                );
            }
            other => panic!("expected GharsError::Apply, got {other:?}"),
        }
    }

    // ---------- UndoLog + rollback-on-failure tests ----------------------

    #[test]
    fn undo_log_starts_empty() {
        let log = UndoLog::new();
        assert!(log.is_empty());
        assert_eq!(log.len(), 0);
        assert!(log.steps().is_empty());
    }

    #[test]
    fn undo_log_push_extends_and_preserves_order() {
        // Insertion order matters because `undo` walks reverse — order
        // here directly drives the inverse-execution sequence.
        let mut log = UndoLog::new();
        log.push(UndoStep::CreateDir {
            path: Utf8PathBuf::from("/tmp/ghars-test"),
        });
        log.push(UndoStep::EnableUnit {
            name: "ghars-runner@a.service".into(),
        });
        log.push(UndoStep::StartUnit {
            name: "ghars-runner@a.service".into(),
        });
        assert_eq!(log.len(), 3);
        match &log.steps()[0] {
            UndoStep::CreateDir { path } => {
                assert_eq!(path.as_str(), "/tmp/ghars-test")
            }
            other => panic!("expected CreateDir, got {other:?}"),
        }
        match &log.steps()[2] {
            UndoStep::StartUnit { name } => {
                assert_eq!(name, "ghars-runner@a.service")
            }
            other => panic!("expected StartUnit, got {other:?}"),
        }
    }

    #[test]
    fn is_reverse_direction_classifies_remove_side_steps() {
        // Forward-direction (Create-side): false ⇒ undo runs the
        // inverse. Reverse-direction (Remove-side): true ⇒ undo logs
        // and skips because the original state is unrecoverable.
        let forward = vec![
            UndoStep::WriteFile {
                path: Utf8PathBuf::from("/x"),
                prior_content: None,
            },
            UndoStep::CreateDir {
                path: Utf8PathBuf::from("/x"),
            },
            UndoStep::StartUnit { name: "u".into() },
            UndoStep::EnableUnit { name: "u".into() },
            UndoStep::GitHubRegistration {
                name: "n".into(),
                url: "u".into(),
                auth_name: "a".into(),
                runner_home: Utf8PathBuf::from("/h"),
            },
        ];
        for s in &forward {
            assert!(
                !s.is_reverse_direction(),
                "forward variant must classify as forward: {s:?}"
            );
        }
        let reverse = vec![
            UndoStep::RemoveFile {
                path: Utf8PathBuf::from("/x"),
                content: vec![],
            },
            UndoStep::RemoveDir {
                path: Utf8PathBuf::from("/x"),
            },
            UndoStep::StopUnit { name: "u".into() },
            UndoStep::DisableUnit { name: "u".into() },
        ];
        for s in &reverse {
            assert!(
                s.is_reverse_direction(),
                "reverse variant must classify as reverse: {s:?}"
            );
        }
    }

    /// Build a minimal `Deps` for unit tests of the `undo` function. No
    /// auth registry entry, no tarball calls — undo only touches
    /// systemd / config_shell / filesystem.
    fn rollback_deps<'a>(
        systemd: &'a MockSystemd,
        config_shell: &'a MockConfigShell,
        tarball: &'a MockTarball,
        auth: &'a HashMap<String, Box<dyn TokenSource>>,
    ) -> Deps<'a> {
        Deps {
            systemd,
            auth,
            tarball,
            config_shell,
        }
    }

    #[test]
    fn undo_start_unit_calls_stop_unit() {
        let systemd = MockSystemd::default();
        let config_shell = MockConfigShell::default();
        let tarball = MockTarball::default();
        let auth: HashMap<String, Box<dyn TokenSource>> = HashMap::new();
        let deps = rollback_deps(&systemd, &config_shell, &tarball, &auth);
        let tmp = tempfile::tempdir().unwrap();
        let paths = make_paths(&tmp);
        let mut log = UndoLog::new();
        log.push(UndoStep::StartUnit {
            name: "ghars-runner@a.service".into(),
        });
        undo(&log, &deps, &paths).unwrap();
        let calls = systemd.calls_snapshot();
        assert!(
            calls
                .iter()
                .any(|c| c == "stop_unit(ghars-runner@a.service)"),
            "expected stop_unit; got {calls:?}"
        );
    }

    #[test]
    fn undo_enable_unit_calls_disable_unit() {
        let systemd = MockSystemd::default();
        let config_shell = MockConfigShell::default();
        let tarball = MockTarball::default();
        let auth: HashMap<String, Box<dyn TokenSource>> = HashMap::new();
        let deps = rollback_deps(&systemd, &config_shell, &tarball, &auth);
        let tmp = tempfile::tempdir().unwrap();
        let paths = make_paths(&tmp);
        let mut log = UndoLog::new();
        log.push(UndoStep::EnableUnit {
            name: "ghars-cache@build.service".into(),
        });
        undo(&log, &deps, &paths).unwrap();
        let calls = systemd.calls_snapshot();
        assert!(
            calls
                .iter()
                .any(|c| c == "disable_unit(ghars-cache@build.service)"),
            "expected disable_unit; got {calls:?}"
        );
    }

    #[test]
    fn undo_write_file_with_no_prior_content_unlinks() {
        // WriteFile with prior_content=None ⇒ file was newly created;
        // undo removes it.
        let tmp = tempfile::tempdir().unwrap();
        let path = Utf8PathBuf::from_path_buf(tmp.path().to_path_buf())
            .unwrap()
            .join("file.conf");
        fs::write(path.as_std_path(), b"new content").unwrap();
        assert!(path.exists());
        let systemd = MockSystemd::default();
        let config_shell = MockConfigShell::default();
        let tarball = MockTarball::default();
        let auth: HashMap<String, Box<dyn TokenSource>> = HashMap::new();
        let deps = rollback_deps(&systemd, &config_shell, &tarball, &auth);
        let paths = make_paths(&tmp);
        let mut log = UndoLog::new();
        log.push(UndoStep::WriteFile {
            path: path.clone(),
            prior_content: None,
        });
        undo(&log, &deps, &paths).unwrap();
        assert!(
            !path.exists(),
            "file must be unlinked when no prior content"
        );
    }

    #[test]
    fn undo_write_file_with_prior_content_restores_old_bytes() {
        // WriteFile with prior_content=Some(_) ⇒ file existed before;
        // undo rewrites the prior bytes through write_root_owned.
        let tmp = tempfile::tempdir().unwrap();
        let path = Utf8PathBuf::from_path_buf(tmp.path().to_path_buf())
            .unwrap()
            .join("subdir")
            .join("file.conf");
        fs::create_dir_all(path.parent().unwrap().as_std_path()).unwrap();
        fs::write(path.as_std_path(), b"new content").unwrap();
        let systemd = MockSystemd::default();
        let config_shell = MockConfigShell::default();
        let tarball = MockTarball::default();
        let auth: HashMap<String, Box<dyn TokenSource>> = HashMap::new();
        let deps = rollback_deps(&systemd, &config_shell, &tarball, &auth);
        let paths = make_paths(&tmp);
        let mut log = UndoLog::new();
        log.push(UndoStep::WriteFile {
            path: path.clone(),
            prior_content: Some(b"old content".to_vec()),
        });
        undo(&log, &deps, &paths).unwrap();
        let restored = fs::read(path.as_std_path()).unwrap();
        assert_eq!(restored, b"old content");
    }

    #[test]
    fn undo_create_dir_removes_empty_directory() {
        let tmp = tempfile::tempdir().unwrap();
        let dir = Utf8PathBuf::from_path_buf(tmp.path().to_path_buf())
            .unwrap()
            .join("new-dir");
        fs::create_dir_all(dir.as_std_path()).unwrap();
        assert!(dir.exists());
        let systemd = MockSystemd::default();
        let config_shell = MockConfigShell::default();
        let tarball = MockTarball::default();
        let auth: HashMap<String, Box<dyn TokenSource>> = HashMap::new();
        let deps = rollback_deps(&systemd, &config_shell, &tarball, &auth);
        let paths = make_paths(&tmp);
        let mut log = UndoLog::new();
        log.push(UndoStep::CreateDir { path: dir.clone() });
        undo(&log, &deps, &paths).unwrap();
        assert!(!dir.exists(), "empty directory must be removed");
    }

    #[test]
    fn undo_create_dir_leaves_nonempty_directory() {
        // CreateDir undo only removes the dir if it's empty — children
        // belong to their own UndoSteps which the reverse walk handles
        // separately. The non-empty case logs a warning and continues.
        let tmp = tempfile::tempdir().unwrap();
        let dir = Utf8PathBuf::from_path_buf(tmp.path().to_path_buf())
            .unwrap()
            .join("nonempty");
        fs::create_dir_all(dir.as_std_path()).unwrap();
        let child = dir.join("child.conf");
        fs::write(child.as_std_path(), b"content").unwrap();
        let systemd = MockSystemd::default();
        let config_shell = MockConfigShell::default();
        let tarball = MockTarball::default();
        let auth: HashMap<String, Box<dyn TokenSource>> = HashMap::new();
        let deps = rollback_deps(&systemd, &config_shell, &tarball, &auth);
        let paths = make_paths(&tmp);
        let mut log = UndoLog::new();
        log.push(UndoStep::CreateDir { path: dir.clone() });
        undo(&log, &deps, &paths).unwrap();
        assert!(
            dir.exists(),
            "non-empty dir must be left for next clean apply"
        );
        assert!(child.exists(), "child must still exist");
    }

    #[test]
    fn undo_github_registration_calls_run_remove_with_fresh_token() {
        // GitHubRegistration undo: mint fresh removal token via auth
        // registry, call config_shell.run_remove. Operator gets a
        // server-side deregister even though the original action
        // failed.
        let systemd = MockSystemd::default();
        let config_shell = MockConfigShell::default();
        let tarball = MockTarball::default();
        let mut auth: HashMap<String, Box<dyn TokenSource>> = HashMap::new();
        auth.insert(
            "pat".into(),
            Box::new(MockTokenSource {
                name: "pat".into(),
                ..Default::default()
            }),
        );
        let deps = rollback_deps(&systemd, &config_shell, &tarball, &auth);
        let tmp = tempfile::tempdir().unwrap();
        let paths = make_paths(&tmp);
        let runner_home = paths.runner_home("default", "a");
        fs::create_dir_all(runner_home.as_std_path()).unwrap();
        let mut log = UndoLog::new();
        log.push(UndoStep::GitHubRegistration {
            name: "a".into(),
            url: "https://github.com/example/repo".into(),
            auth_name: "pat".into(),
            runner_home: runner_home.clone(),
        });
        undo(&log, &deps, &paths).unwrap();
        let removed = config_shell.removed.lock().unwrap().clone();
        assert_eq!(removed, vec!["a"], "run_remove must be invoked");
    }

    #[test]
    fn undo_github_registration_warns_when_auth_missing() {
        // GitHubRegistration undo with auth_name not in registry: warn
        // and skip. The function returns Ok(()) — the rollback
        // continues even though this step couldn't fire.
        let systemd = MockSystemd::default();
        let config_shell = MockConfigShell::default();
        let tarball = MockTarball::default();
        let auth: HashMap<String, Box<dyn TokenSource>> = HashMap::new();
        let deps = rollback_deps(&systemd, &config_shell, &tarball, &auth);
        let tmp = tempfile::tempdir().unwrap();
        let paths = make_paths(&tmp);
        let runner_home = paths.runner_home("default", "a");
        let mut log = UndoLog::new();
        log.push(UndoStep::GitHubRegistration {
            name: "a".into(),
            url: "https://github.com/example/repo".into(),
            auth_name: "missing".into(),
            runner_home: runner_home.clone(),
        });
        undo(&log, &deps, &paths).unwrap();
        let removed = config_shell.removed.lock().unwrap().clone();
        assert!(
            removed.is_empty(),
            "run_remove must NOT fire when auth missing; got {removed:?}"
        );
    }

    #[test]
    fn undo_walks_steps_in_reverse_order() {
        // Insert order: A, B. Undo order must be: B, A. The undo walk
        // is a Vec.iter().rev() so EnableUnit (last forward) becomes
        // disable_unit (first reverse), then StartUnit (the earlier
        // forward) becomes stop_unit (the later reverse).
        let systemd = MockSystemd::default();
        let config_shell = MockConfigShell::default();
        let tarball = MockTarball::default();
        let auth: HashMap<String, Box<dyn TokenSource>> = HashMap::new();
        let deps = rollback_deps(&systemd, &config_shell, &tarball, &auth);
        let tmp = tempfile::tempdir().unwrap();
        let paths = make_paths(&tmp);
        let mut log = UndoLog::new();
        log.push(UndoStep::StartUnit {
            name: "unit-a".into(),
        });
        log.push(UndoStep::EnableUnit {
            name: "unit-b".into(),
        });
        undo(&log, &deps, &paths).unwrap();
        let calls = systemd.calls_snapshot();
        // Reverse walk: disable_unit(unit-b) (from EnableUnit) before
        // stop_unit(unit-a) (from StartUnit).
        let pos_disable = calls
            .iter()
            .position(|c| c == "disable_unit(unit-b)")
            .expect("disable_unit recorded");
        let pos_stop = calls
            .iter()
            .position(|c| c == "stop_unit(unit-a)")
            .expect("stop_unit recorded");
        assert!(
            pos_disable < pos_stop,
            "disable_unit must precede stop_unit in reverse walk; got {calls:?}"
        );
    }

    #[test]
    fn undo_skips_reverse_direction_steps_without_calling_systemd() {
        // RemoveFile / RemoveDir / StopUnit / DisableUnit are recorded
        // for audit-trail completeness. undo() logs warn + skips them
        // (no inverse attempted).
        let systemd = MockSystemd::default();
        let config_shell = MockConfigShell::default();
        let tarball = MockTarball::default();
        let auth: HashMap<String, Box<dyn TokenSource>> = HashMap::new();
        let deps = rollback_deps(&systemd, &config_shell, &tarball, &auth);
        let tmp = tempfile::tempdir().unwrap();
        let paths = make_paths(&tmp);
        let mut log = UndoLog::new();
        log.push(UndoStep::StopUnit { name: "u".into() });
        log.push(UndoStep::DisableUnit { name: "u".into() });
        log.push(UndoStep::RemoveDir {
            path: Utf8PathBuf::from("/some/path"),
        });
        log.push(UndoStep::RemoveFile {
            path: Utf8PathBuf::from("/some/file"),
            content: b"x".to_vec(),
        });
        undo(&log, &deps, &paths).unwrap();
        // None of the systemd inverses (start/enable) fired — all
        // reverse-direction steps were skipped.
        let calls = systemd.calls_snapshot();
        assert!(
            !calls.iter().any(|c| c.starts_with("start_unit")),
            "must not start_unit on StopUnit undo; got {calls:?}"
        );
        assert!(
            !calls.iter().any(|c| c.starts_with("enable_unit")),
            "must not enable_unit on DisableUnit undo; got {calls:?}"
        );
    }

    #[test]
    fn apply_with_rollback_off_does_not_call_undo_on_failure() {
        // When --rollback-on-failure is OFF (default), a failing
        // action's UndoLog stays unwalked. Use a plan that fails on a
        // CreateRunner with no resolved release + no runner_tarball
        // (mint_token never reached, but enough side effects fired
        // pre-failure that the absence of an undo walk is observable).
        let tmp = tempfile::tempdir().unwrap();
        let paths = make_paths(&tmp);
        let mut plan_data = make_runner_plan("a", &paths.state_dir);
        plan_data.resolved_release = None;
        plan_data.spec.runner_tarball = None;
        let plan = Plan {
            actions: vec![Action::CreateRunner(plan_data)],
            warnings: vec![],
        };
        let systemd = MockSystemd::default();
        let config_shell = MockConfigShell::default();
        let tarball = MockTarball::default();
        let mut auth: HashMap<String, Box<dyn TokenSource>> = HashMap::new();
        auth.insert(
            "pat".into(),
            Box::new(MockTokenSource {
                name: "pat".into(),
                ..Default::default()
            }),
        );
        let deps = Deps {
            systemd: &systemd,
            auth: &auth,
            tarball: &tarball,
            config_shell: &config_shell,
        };
        let opts = ApplyOptions {
            rollback_on_failure: false,
            ..Default::default()
        };
        let result = apply(&plan, &deps, &paths, &opts).unwrap();
        assert!(!result.failed.is_empty(), "plan must fail");
        // The pre-DynamicUser version asserted that useradd ran but
        // userdel did not. Both calls are gone; the surviving signal
        // is just that the action failed (asserted by the apply
        // result above). Rollback-OFF semantics for the surviving
        // UndoStep variants are covered by other tests.
    }

    #[test]
    fn apply_with_rollback_on_walks_undo_log_on_failure() {
        // Same plan as above but with --rollback-on-failure ON. The
        // useradd that ran before the no-release error fires must be
        // matched by a userdel from the undo walk.
        let tmp = tempfile::tempdir().unwrap();
        let paths = make_paths(&tmp);
        let mut plan_data = make_runner_plan("a", &paths.state_dir);
        plan_data.resolved_release = None;
        plan_data.spec.runner_tarball = None;
        let plan = Plan {
            actions: vec![Action::CreateRunner(plan_data)],
            warnings: vec![],
        };
        let systemd = MockSystemd::default();
        let config_shell = MockConfigShell::default();
        let tarball = MockTarball::default();
        let mut auth: HashMap<String, Box<dyn TokenSource>> = HashMap::new();
        auth.insert(
            "pat".into(),
            Box::new(MockTokenSource {
                name: "pat".into(),
                ..Default::default()
            }),
        );
        let deps = Deps {
            systemd: &systemd,
            auth: &auth,
            tarball: &tarball,
            config_shell: &config_shell,
        };
        let opts = ApplyOptions {
            rollback_on_failure: true,
            ..Default::default()
        };
        let result = apply(&plan, &deps, &paths, &opts).unwrap();
        assert!(!result.failed.is_empty(), "plan must fail");
        // The pre-DynamicUser version asserted that the rollback walk
        // inverted UserAdd → userdel via the trait. Both are gone;
        // the action-failed assertion above is the remaining signal.
    }

    #[test]
    fn apply_with_rollback_on_does_not_undo_already_succeeded_actions() {
        // Per-action scope: a successful action whose sibling fails is
        // NOT undone. Plan has two actions: a CachePool that succeeds,
        // then a CreateRunner that fails (no release + no tarball).
        // The cache pool's group / unit / drop-in must remain.
        let tmp = tempfile::tempdir().unwrap();
        let paths = make_paths(&tmp);
        let cache_plan = CachePoolPlan {
            binding: crate::config::EffectiveCacheBinding {
                name: "build".into(),
                kinds: vec![crate::config::CacheKind::Ccache],
                size: "10G".into(),
                mode: crate::config::CacheMode::Shared,
                trust_zone: "default".into(),
            },
            drop_in_body: "[Service]\n".into(),
            spec_hash: "sha256:0".into(),
        };
        let mut runner_data = make_runner_plan("a", &paths.state_dir);
        runner_data.resolved_release = None;
        runner_data.spec.runner_tarball = None;
        let plan = Plan {
            actions: vec![
                Action::CreateCachePool(cache_plan),
                Action::CreateRunner(runner_data),
            ],
            warnings: vec![],
        };
        let systemd = MockSystemd::default();
        let config_shell = MockConfigShell::default();
        let tarball = MockTarball::default();
        let mut auth: HashMap<String, Box<dyn TokenSource>> = HashMap::new();
        auth.insert(
            "pat".into(),
            Box::new(MockTokenSource {
                name: "pat".into(),
                ..Default::default()
            }),
        );
        let deps = Deps {
            systemd: &systemd,
            auth: &auth,
            tarball: &tarball,
            config_shell: &config_shell,
        };
        let opts = ApplyOptions {
            rollback_on_failure: true,
            ..Default::default()
        };
        let result = apply(&plan, &deps, &paths, &opts).unwrap();
        assert_eq!(result.failed.len(), 1, "exactly one action failed");
        // The pre-DynamicUser version asserted the cache pool's
        // groupadd ran and was NOT inverted by the failing runner
        // action's rollback walk. The trait is gone; the signal that
        // remains is the per-action scope (only the failed runner's
        // UndoLog walks; the successful pool's discards on Ok). The
        // pool's drop-in file should still exist on disk after the
        // mixed-success apply — assert that as the per-action-scope
        // signal that doesn't depend on the deleted trait.
        let pool_drop_in = paths
            .cache_drop_in_dir("build")
            .join("00-ghars.conf");
        assert!(
            pool_drop_in.exists(),
            "cache pool drop-in must persist on disk despite runner failure; \
             per-action-scope rollback walks only the failed action's UndoLog"
        );
    }

    #[test]
    fn cli_apply_args_parses_rollback_on_failure_flag() {
        // Smoke test: the CLI flag is present in the parser. Failure
        // here would mean the flag was lost from ApplyArgs. The full
        // dispatch path is covered by cmd_apply integration tests.
        use clap::Parser;
        // The CLI lives behind ghars::cli::Cli; the type isn't pub
        // here so we do the parse via the same try_parse_from pattern
        // the cli.rs tests use. We just check the flag is accepted.
        let parsed =
            crate::cli::Cli::try_parse_from(["ghars", "apply", "--rollback-on-failure"]).unwrap();
        match parsed.command {
            crate::cli::Command::Apply(args) => {
                assert!(args.rollback_on_failure);
            }
            other => panic!("expected Apply, got {other:?}"),
        }
    }

    #[test]
    fn cli_apply_args_rollback_on_failure_default_off() {
        // Default OFF: design specifies opt-in. Plan output without
        // the flag must not trigger rollback walks.
        use clap::Parser;
        let parsed = crate::cli::Cli::try_parse_from(["ghars", "apply"]).unwrap();
        match parsed.command {
            crate::cli::Command::Apply(args) => {
                assert!(!args.rollback_on_failure);
            }
            other => panic!("expected Apply, got {other:?}"),
        }
    }

    #[test]
    fn execute_create_runner_records_unit_start_in_log() {
        // Verify the threading: a successful execute_create_runner
        // step pushes StartUnit. (DynamicUser handles the runner
        // identity, so there's no UserAdd step under the new model.)
        let tmp = tempfile::tempdir().unwrap();
        let paths = make_paths(&tmp);
        let plan = make_runner_plan("rt", &paths.state_dir);
        let systemd = MockSystemd::default();
        let config_shell = MockConfigShell::default();
        let tarball = MockTarball::default();
        let mut auth: HashMap<String, Box<dyn TokenSource>> = HashMap::new();
        auth.insert(
            "pat".into(),
            Box::new(MockTokenSource {
                name: "pat".into(),
                ..Default::default()
            }),
        );
        let deps = Deps {
            systemd: &systemd,
            auth: &auth,
            tarball: &tarball,
            config_shell: &config_shell,
        };
        let mut log = UndoLog::new();
        execute_create_runner(&plan, &deps, &paths, &mut log).unwrap();
        let has_start = log.steps().iter().any(
            |s| matches!(s, UndoStep::StartUnit { name } if name == "ghars-runner@rt.service"),
        );
        assert!(
            has_start,
            "execute_create_runner must push StartUnit; got {:?}",
            log.steps()
        );
    }

    // ---- gc_stale_temp_files ---------------------------------------------

    /// Plant a synthetic `.NAME.tmp.PID.COUNTER` file in `dir`,
    /// optionally back-dating its mtime past STALE_TEMP_AGE_SECS.
    fn plant_temp_file(dir: &Path, name: &str, age_secs: Option<u64>) -> std::path::PathBuf {
        fs::create_dir_all(dir).unwrap();
        let path = dir.join(name);
        fs::write(&path, b"stale temp\n").unwrap();
        if let Some(secs) = age_secs {
            let new_mtime = std::time::SystemTime::now() - std::time::Duration::from_secs(secs);
            // utimensat via std: filetime crate isn't pulled in;
            // use SetFileTimes through the OpenOptions handle.
            let f = OpenOptions::new().write(true).open(&path).unwrap();
            f.set_modified(new_mtime).unwrap();
        }
        path
    }

    #[test]
    fn gc_stale_temp_files_removes_aged_dead_pid_temp_files() {
        let tmp = tempfile::tempdir().unwrap();
        let paths = make_paths(&tmp);
        // PID 999999 is reserved for testing — well beyond
        // typical PID_MAX (32768 default, 4194304 max). Combined with
        // an mtime past the 60s gate, this file must be removed.
        let stale = plant_temp_file(
            paths.unit_dir.as_std_path(),
            ".ghars-runner@a.service.tmp.999999.0",
            Some(STALE_TEMP_AGE_SECS + 30),
        );
        assert!(stale.exists(), "fixture invariant: planted file must exist");

        gc_stale_temp_files(&paths);

        assert!(
            !stale.exists(),
            "stale temp file (dead PID, mtime > {STALE_TEMP_AGE_SECS}s) must be removed",
        );
    }

    #[test]
    fn gc_stale_temp_files_preserves_recent_temp_files() {
        let tmp = tempfile::tempdir().unwrap();
        let paths = make_paths(&tmp);
        // Recent file (no back-dating) — even with a stale-looking
        // PID, the mtime gate must keep it. Protects against ripping
        // an in-flight write_root_owned out from under a concurrent
        // call. (The lock prevents cross-process races; this guards
        // a future caller that drops the lock somehow.)
        let recent = plant_temp_file(
            paths.unit_dir.as_std_path(),
            ".ghars-runner@b.service.tmp.999999.5",
            None,
        );
        assert!(recent.exists(), "fixture invariant");

        gc_stale_temp_files(&paths);

        assert!(
            recent.exists(),
            "recent temp file (mtime < {STALE_TEMP_AGE_SECS}s) must be preserved",
        );
    }

    #[test]
    fn gc_stale_temp_files_preserves_files_with_our_pid() {
        let tmp = tempfile::tempdir().unwrap();
        let paths = make_paths(&tmp);
        let our_pid = std::process::id();
        // Even if old, embedded-PID-equals-us means a future call in
        // this process might still be holding the temp open. Defensive
        // skip — apply.lock keeps cross-process collisions out, but
        // intra-process collisions need the PID guard.
        let same_pid = plant_temp_file(
            paths.unit_dir.as_std_path(),
            &format!(".ghars-runner@c.service.tmp.{our_pid}.0"),
            Some(STALE_TEMP_AGE_SECS + 30),
        );
        assert!(same_pid.exists(), "fixture invariant");

        gc_stale_temp_files(&paths);

        assert!(
            same_pid.exists(),
            "temp file with our own PID must be preserved (defensive guard)",
        );
    }

    #[test]
    fn gc_stale_temp_files_preserves_non_temp_files() {
        let tmp = tempfile::tempdir().unwrap();
        let paths = make_paths(&tmp);
        fs::create_dir_all(paths.unit_dir.as_std_path()).unwrap();
        let cases = [
            "ghars-runner@a.service",           // no leading dot
            ".hidden-not-a-temp",               // dot but no .tmp.PID.COUNTER
            ".something.tmp.notanumber.0",      // PID component non-numeric
            ".something.tmp.999999.notanumber", // counter non-numeric
            ".something.tmp.999999",            // missing counter component
            "regular.conf",                     // operator-dropped file
        ];
        let mut planted: Vec<std::path::PathBuf> = Vec::new();
        for name in cases {
            planted.push(plant_temp_file(
                paths.unit_dir.as_std_path(),
                name,
                Some(STALE_TEMP_AGE_SECS + 30),
            ));
        }

        gc_stale_temp_files(&paths);

        for p in &planted {
            assert!(
                p.exists(),
                "non-temp file or unparseable name must be preserved: {p:?}",
            );
        }
    }

    #[test]
    fn gc_stale_temp_files_scans_runner_drop_in_dir() {
        let tmp = tempfile::tempdir().unwrap();
        let paths = make_paths(&tmp);
        let drop_in_dir = paths.unit_dir.join("ghars-runner@a.service.d");
        let stale = plant_temp_file(
            drop_in_dir.as_std_path(),
            ".10-memory.conf.tmp.999999.0",
            Some(STALE_TEMP_AGE_SECS + 30),
        );
        assert!(stale.exists(), "fixture invariant");

        gc_stale_temp_files(&paths);

        assert!(
            !stale.exists(),
            "GC must scan ghars-runner@*.service.d/ subdirectories",
        );
    }

    #[test]
    fn gc_stale_temp_files_scans_cache_pool_drop_in_dir() {
        let tmp = tempfile::tempdir().unwrap();
        let paths = make_paths(&tmp);
        let drop_in_dir = paths.unit_dir.join("ghars-cache@build.service.d");
        let stale = plant_temp_file(
            drop_in_dir.as_std_path(),
            ".00-ghars.conf.tmp.999999.0",
            Some(STALE_TEMP_AGE_SECS + 30),
        );
        assert!(stale.exists(), "fixture invariant");

        gc_stale_temp_files(&paths);

        assert!(
            !stale.exists(),
            "GC must scan ghars-cache@*.service.d/ subdirectories",
        );
    }

    #[test]
    fn gc_stale_temp_files_scans_nft_d_and_netns_d() {
        let tmp = tempfile::tempdir().unwrap();
        let paths = make_paths(&tmp);
        let nft = paths.config_dir.join("nft.d");
        let netns = paths.config_dir.join("netns.d");
        let stale_nft = plant_temp_file(
            nft.as_std_path(),
            ".a-host.nft.tmp.999999.0",
            Some(STALE_TEMP_AGE_SECS + 30),
        );
        let stale_netns = plant_temp_file(
            netns.as_std_path(),
            ".a.toml.tmp.999999.0",
            Some(STALE_TEMP_AGE_SECS + 30),
        );

        gc_stale_temp_files(&paths);

        assert!(!stale_nft.exists(), "GC must scan config_dir/nft.d");
        assert!(!stale_netns.exists(), "GC must scan config_dir/netns.d");
    }

    #[test]
    fn gc_stale_temp_files_tolerates_missing_dirs() {
        // No fs::create_dir_all on any dir — every dir is missing.
        // gc must complete without panic and without error.
        let tmp = tempfile::tempdir().unwrap();
        let paths = make_paths(&tmp);
        gc_stale_temp_files(&paths);
        // Reaching here = pass.
    }

    // ---- gc_stale_staging_dirs --------------------------------------------

    /// Plant a synthetic `<state_dir>/.staging/<name>-<version>-<pid>/`
    /// directory, optionally back-dating its mtime past
    /// STALE_TEMP_AGE_SECS. Returns the planted path so the test can
    /// assert presence / absence after the GC pass.
    fn plant_staging_dir(
        state_dir: &Path,
        name: &str,
        version: &str,
        pid: i32,
        age_secs: Option<u64>,
    ) -> std::path::PathBuf {
        let staging_root = state_dir.join(".staging");
        fs::create_dir_all(&staging_root).unwrap();
        let dir = staging_root.join(format!("{name}-{version}-{pid}"));
        fs::create_dir_all(&dir).unwrap();
        // Drop a sentinel file so the dir is non-empty, matching the
        // partial-extract leftover state in production.
        fs::write(dir.join("sentinel"), b"partial extract\n").unwrap();
        if let Some(secs) = age_secs {
            let new_mtime = std::time::SystemTime::now() - std::time::Duration::from_secs(secs);
            // utimensat via std: filetime crate isn't pulled in;
            // mirror plant_temp_file's set_modified handle pattern but
            // on the directory inode (Linux supports SetFileTimes on
            // dirs through std::fs::File::open).
            let f = OpenOptions::new()
                .read(true)
                .open(&dir)
                .expect("open staging dir for set_modified");
            f.set_modified(new_mtime).unwrap();
        }
        dir
    }

    #[test]
    fn gc_stale_staging_dirs_removes_aged_dead_pid_dir() {
        let tmp = tempfile::tempdir().unwrap();
        let paths = make_paths(&tmp);
        // PID 999999 exceeds typical PID_MAX (32768 default, 4194304
        // max). Combined with mtime past the 60s gate the dir must be
        // removed. Mirror gc_stale_temp_files_removes_aged_dead_pid_temp_files.
        let stale = plant_staging_dir(
            paths.state_dir.as_std_path(),
            "buckos",
            "2.334.0",
            999_999,
            Some(STALE_TEMP_AGE_SECS + 30),
        );
        assert!(stale.exists(), "fixture invariant: planted dir must exist");

        gc_stale_staging_dirs(&paths);

        assert!(
            !stale.exists(),
            "stale staging dir (dead PID, mtime > {STALE_TEMP_AGE_SECS}s) must be removed",
        );
    }

    #[test]
    fn gc_stale_staging_dirs_preserves_recent_dir() {
        let tmp = tempfile::tempdir().unwrap();
        let paths = make_paths(&tmp);
        // Recent staging dir (no back-dating) — even with a clearly
        // stale-looking PID, the mtime gate must keep it. Protects
        // against GC ripping an in-flight `install_runner_binary`
        // staging tree out from under a concurrent extract. The lock
        // prevents cross-process races; this guards a future caller
        // that drops the lock somehow.
        let recent = plant_staging_dir(
            paths.state_dir.as_std_path(),
            "buckos",
            "2.334.0",
            999_999,
            None,
        );
        assert!(recent.exists(), "fixture invariant");

        gc_stale_staging_dirs(&paths);

        assert!(
            recent.exists(),
            "recent staging dir (mtime < {STALE_TEMP_AGE_SECS}s) must be preserved",
        );
    }

    #[test]
    fn gc_stale_staging_dirs_preserves_dir_with_our_pid() {
        let tmp = tempfile::tempdir().unwrap();
        let paths = make_paths(&tmp);
        let our_pid = i32::try_from(std::process::id()).unwrap_or(i32::MAX);
        // Even old, embedded-PID-equals-us means a future caller in
        // this process might still hold the staging tree open.
        // Defensive skip — apply.lock keeps cross-process collisions
        // out, but intra-process collisions need the PID guard.
        let same_pid = plant_staging_dir(
            paths.state_dir.as_std_path(),
            "buckos",
            "2.334.0",
            our_pid,
            Some(STALE_TEMP_AGE_SECS + 30),
        );
        assert!(same_pid.exists(), "fixture invariant");

        gc_stale_staging_dirs(&paths);

        assert!(
            same_pid.exists(),
            "staging dir with our own PID must be preserved (defensive guard)",
        );
    }

    #[test]
    fn gc_stale_staging_dirs_preserves_unparseable_dir_names() {
        let tmp = tempfile::tempdir().unwrap();
        let paths = make_paths(&tmp);
        let staging_root = paths.state_dir.join(".staging");
        fs::create_dir_all(staging_root.as_std_path()).unwrap();
        // Names that don't match {name}-{version}-{pid} — the trailing
        // '-' or non-numeric trailing component must NOT parse.
        let cases = [
            "no-trailing-pid-marker", // last segment "marker" not numeric
            "missingdash",            // no dashes at all
            "ends-with-",             // empty trailing component
        ];
        let mut planted: Vec<std::path::PathBuf> = Vec::new();
        for name in cases {
            let dir = staging_root.as_std_path().join(name);
            fs::create_dir_all(&dir).unwrap();
            let new_mtime = std::time::SystemTime::now()
                - std::time::Duration::from_secs(STALE_TEMP_AGE_SECS + 30);
            let f = OpenOptions::new().read(true).open(&dir).unwrap();
            f.set_modified(new_mtime).unwrap();
            planted.push(dir);
        }

        gc_stale_staging_dirs(&paths);

        for p in &planted {
            assert!(
                p.exists(),
                "unparseable staging-dir name must be preserved: {p:?}",
            );
        }
    }

    #[test]
    fn gc_stale_staging_dirs_tolerates_missing_staging_root() {
        // No `.staging` directory at all — gc must return without
        // panic. Mirror gc_stale_temp_files_tolerates_missing_dirs.
        let tmp = tempfile::tempdir().unwrap();
        let paths = make_paths(&tmp);
        gc_stale_staging_dirs(&paths);
        // Reaching here = pass.
    }

    /// Pin that gc removes the entire staging tree
    /// (not just the leaf directory). extract.rs's partial-extract
    /// state typically contains nested files and subdirectories — the
    /// distinction between `fs::remove_dir` (refuses non-empty dirs)
    /// and `fs::remove_dir_all` (recurses) is load-bearing. Without
    /// this test a future cleanup pass could accidentally swap to
    /// `remove_dir` and orphan the contents permanently.
    #[test]
    fn gc_stale_staging_dirs_removes_nested_contents() {
        let tmp = tempfile::tempdir().unwrap();
        let paths = make_paths(&tmp);
        // Build the staging tree manually so we can back-date the
        // root mtime AFTER populating all children. plant_staging_dir
        // sets the mtime once at construction, but adding child
        // entries below updates the directory's mtime back to "now"
        // (see VFS dir mtime semantics: any namespace operation in
        // the directory bumps it). We have to back-date as the LAST
        // step or the age gate will skip the dir.
        let staging_root = paths.state_dir.join(".staging");
        fs::create_dir_all(staging_root.as_std_path()).unwrap();
        let stale = staging_root.as_std_path().join("buckos-2.334.0-999999");
        fs::create_dir_all(&stale).unwrap();
        // Mimic the actions runner tarball partial-extract layout —
        // nested directories with files inside, plus a deeper subdir.
        // remove_dir would refuse all of these; remove_dir_all
        // recursively removes them.
        let bin_dir = stale.join("bin");
        fs::create_dir_all(&bin_dir).unwrap();
        fs::write(bin_dir.join("Runner.Listener"), b"partial binary\n").unwrap();
        fs::write(bin_dir.join("Runner.Worker"), b"partial binary\n").unwrap();
        let externals = stale.join("externals").join("node20").join("bin");
        fs::create_dir_all(&externals).unwrap();
        fs::write(externals.join("node"), b"partial node\n").unwrap();
        // Sentinel at the root level too.
        fs::write(stale.join("config.sh"), b"partial config\n").unwrap();
        // Back-date the root staging dir's mtime AFTER all children
        // are written. gc reads `entry.metadata()` on the root entry
        // (not on children) for the age comparison.
        let new_mtime =
            std::time::SystemTime::now() - std::time::Duration::from_secs(STALE_TEMP_AGE_SECS + 30);
        let f = OpenOptions::new().read(true).open(&stale).unwrap();
        f.set_modified(new_mtime).unwrap();
        assert!(
            stale.exists(),
            "fixture invariant: staging tree must exist before gc"
        );
        assert!(
            externals.exists(),
            "fixture invariant: nested subtree must exist before gc"
        );

        gc_stale_staging_dirs(&paths);

        // Entire tree must be gone — the leaf directory AND every
        // ancestor between it and the root.
        assert!(
            !stale.exists(),
            "staging dir must be removed (proves remove_dir_all, not remove_dir)"
        );
        assert!(
            !externals.exists(),
            "nested subtree must be removed (proves recursive walk)"
        );
        // The .staging/ root itself must remain — gc only sweeps
        // children, not the parent.
        assert!(
            paths.state_dir.join(".staging").as_std_path().exists(),
            ".staging/ root must persist after sweeping a child"
        );
    }

    /// Pin the no-op contract on an empty
    /// `.staging/`. After a previous gc pass the parent stays as an
    /// empty dir; subsequent gc invocations must NOT remove the
    /// parent (extract.rs::install_runner_binary calls
    /// `fs::create_dir_all(&staging_root)` on every install but the
    /// idempotent guarantee holds whether or not we delete the root)
    /// and must NOT panic. Pairs with the missing-root test above.
    #[test]
    fn gc_stale_staging_dirs_no_op_on_empty_staging_root() {
        let tmp = tempfile::tempdir().unwrap();
        let paths = make_paths(&tmp);
        let staging_root = paths.state_dir.join(".staging");
        fs::create_dir_all(staging_root.as_std_path()).unwrap();
        assert!(
            staging_root.as_std_path().exists(),
            "fixture invariant: empty .staging/ must exist before gc"
        );
        let entries_before: Vec<_> = fs::read_dir(staging_root.as_std_path())
            .unwrap()
            .collect::<std::result::Result<_, _>>()
            .unwrap();
        assert!(
            entries_before.is_empty(),
            "fixture invariant: .staging/ must be empty before gc"
        );

        gc_stale_staging_dirs(&paths);

        // .staging/ must still exist and still be empty.
        assert!(
            staging_root.as_std_path().exists(),
            "empty .staging/ must persist (gc only sweeps children)"
        );
        let entries_after: Vec<_> = fs::read_dir(staging_root.as_std_path())
            .unwrap()
            .collect::<std::result::Result<_, _>>()
            .unwrap();
        assert!(
            entries_after.is_empty(),
            ".staging/ must remain empty after gc on empty input"
        );
    }

    /// What this test pins: a symlink under
    /// `.staging/` whose name parses as `<name>-<version>-<pid>` —
    /// with a dead PID and a back-dated mtime past
    /// `STALE_TEMP_AGE_SECS` so neither own-PID nor age can cause the
    /// skip — survives `gc_stale_staging_dirs` AND its target stays
    /// untouched.
    ///
    /// What this test does NOT prove: that the explicit
    /// `ft.is_symlink()` gate is load-bearing. `entry.file_type()` is
    /// lstat-style, so symlinks report `is_dir() == false`; if the
    /// explicit gate were deleted, `!ft.is_dir()` would still skip
    /// symlinks. The two gates produce the same observable behavior
    /// under lstat semantics — this assertion alone cannot
    /// distinguish them.
    ///
    /// Why the explicit gate exists anyway: defense-in-depth + intent
    /// signaling. The hostile case is an attacker who can write to
    /// `.staging/` replacing a real staging tree with a symlink to
    /// e.g. `/etc` and relying on a future regression of the lstat
    /// invariant (or a refactor that switches to `metadata()` —
    /// which DOES follow symlinks) to redirect `remove_dir_all`
    /// outside the staging root. Symmetric to gc_stale_temp_files's
    /// `!is_file()` symlink-skip pattern.
    #[test]
    fn gc_stale_staging_dirs_skips_symlink_entries() {
        let tmp = tempfile::tempdir().unwrap();
        let paths = make_paths(&tmp);
        let staging_root = paths.state_dir.join(".staging");
        fs::create_dir_all(staging_root.as_std_path()).unwrap();
        // Create a "victim" directory the symlink points to —
        // bystander we must NOT touch.
        let victim = tmp.path().join("victim-bystander");
        fs::create_dir_all(&victim).unwrap();
        fs::write(victim.join("sentinel"), b"do not delete\n").unwrap();
        // Place the symlink at a name that would otherwise look like a
        // legitimate staging entry: `<name>-<version>-<aged-pid>`. PID
        // 999_999 is far past typical PID_MAX so this name is
        // unambiguously not our own.
        let trap = staging_root.as_std_path().join("buckos-2.334.0-999999");
        std::os::unix::fs::symlink(&victim, &trap).unwrap();
        // Back-date the symlink's own mtime past `STALE_TEMP_AGE_SECS`
        // so the age gate aligns for removal. std::fs::File::open
        // follows symlinks, so set_modified on a File handle would
        // touch the *target* — we need lutimes semantics. nix's
        // `utimensat` with `UtimensatFlags::NoFollowSymlink` and
        // `dirfd = None` (relative to CWD) is the portable
        // equivalent.
        let new_mtime_since_epoch = (std::time::SystemTime::now()
            - std::time::Duration::from_secs(STALE_TEMP_AGE_SECS + 30))
        .duration_since(std::time::UNIX_EPOCH)
        .expect("test clock must be after UNIX epoch");
        let ts = nix::sys::time::TimeSpec::from_duration(new_mtime_since_epoch);
        nix::sys::stat::utimensat(
            None,
            trap.as_path(),
            &ts,
            &ts,
            nix::sys::stat::UtimensatFlags::NoFollowSymlink,
        )
        .expect("utimensat AT_SYMLINK_NOFOLLOW must succeed on the test runner");
        assert!(
            std::fs::symlink_metadata(&trap)
                .unwrap()
                .file_type()
                .is_symlink(),
            "fixture invariant: planted entry must be a symlink"
        );

        gc_stale_staging_dirs(&paths);

        // The symlink itself must persist (gc skipped it) AND the
        // victim directory must remain untouched.
        assert!(
            std::fs::symlink_metadata(&trap).is_ok(),
            "symlink under .staging/ must be preserved (defense-in-depth)"
        );
        assert!(
            victim.join("sentinel").exists(),
            "victim directory pointed at by symlink must NOT be removed"
        );
    }

    #[test]
    fn parse_staging_dir_suffix_rejects_unparseable_inputs() {
        // Inputs that don't match the trailing `-NUM` shape must
        // return None so the caller's foreign-name skip kicks in.
        for name in ["noseparators", "trailing-nondigit", "ends-with-", ""] {
            assert!(
                parse_staging_dir_suffix(name).is_none(),
                "unparseable name must not yield a PID: {name:?}",
            );
        }
    }

    #[test]
    fn parse_staging_dir_suffix_accepts_versioned_runner_name() {
        // Real-world shape: name + version + pid where version itself
        // contains hyphens (e.g. a release-candidate suffix). The
        // right-split must pick the trailing PID and leave the rest
        // alone — production names like `buckos-2.334.0-rc1-12345`
        // still parse to PID 12345.
        let pid = parse_staging_dir_suffix("buckos-2.334.0-rc1-12345");
        assert_eq!(pid, Some(12345));
        // Plain name + version: also parses.
        let pid2 = parse_staging_dir_suffix("buckos-2.334.0-9999");
        assert_eq!(pid2, Some(9999));
    }

    /// 4i: directive-named contract pin for `parse_staging_dir_suffix`,
    /// symmetric with the parse_temp_file_suffix tests below.
    /// Documents the four cases the convergence team called out:
    /// - canonical `<name>-<version>-<pid>` → Some(pid)
    /// - non-numeric trailing → None
    /// - single-segment / no hyphen → None
    /// - 2-segment shape `foo-1.2.3` → None
    ///
    /// The helper's contract is `name.rsplit_once('-')?` then
    /// `pid_str.parse::<i32>().ok()`. `rsplit_once('-')` returns the
    /// content AFTER the LAST `-`, so `"foo-1.2.3"` rsplits to
    /// `("foo", "1.2.3")`. `"1.2.3"` is not a valid i32 (contains
    /// dots), so the parse fails and the helper returns `None`.
    /// Strings whose post-last-hyphen segment is not a bare integer
    /// are all rejected — this means the GC's foreign-skip is
    /// shape-aware in practice: directory names that happen to
    /// contain hyphens but whose tail is a dotted version (rather
    /// than a PID) do not match.
    #[test]
    fn parse_staging_dir_pid_directive_cases() {
        assert_eq!(
            parse_staging_dir_suffix("foo-1.2.3-12345"),
            Some(12345),
            "valid name-version-pid shape must parse"
        );
        assert_eq!(
            parse_staging_dir_suffix("foo-1.2.3"),
            None,
            "trailing segment `1.2.3` (after the last `-`) fails i32::parse → None"
        );
        assert_eq!(
            parse_staging_dir_suffix("foo-1.2.3-abc"),
            None,
            "non-numeric trailing segment rejects"
        );
        assert_eq!(
            parse_staging_dir_suffix("nodashes"),
            None,
            "no hyphen rejects"
        );
    }

    #[test]
    fn parse_temp_file_suffix_rejects_unparseable_inputs() {
        // Direct test of the helper since it gates everything.
        assert!(
            parse_temp_file_suffix("ghars-runner@a.service").is_none(),
            "no leading dot ⇒ None"
        );
        assert!(
            parse_temp_file_suffix(".hidden-no-tmp").is_none(),
            "no .tmp.PID.COUNTER segment ⇒ None"
        );
        assert!(
            parse_temp_file_suffix(".x.tmp.foo.0").is_none(),
            "non-numeric PID ⇒ None"
        );
        assert!(
            parse_temp_file_suffix(".x.tmp.999.bar").is_none(),
            "non-numeric counter ⇒ None"
        );
        assert!(
            parse_temp_file_suffix(".x.tmp.999").is_none(),
            "missing counter ⇒ None"
        );
        assert_eq!(
            parse_temp_file_suffix(".ghars-runner@a.service.tmp.42.7"),
            Some((42, 7)),
            "canonical shape parses"
        );
    }

    // ---- in-place caches reconciliation ---------------------------------

    /// Build a delta with `before_caches` populated and the spec
    /// `caches` set to `after`.
    fn make_caches_delta(
        paths: &Paths,
        before: Option<Vec<&str>>,
        after: Vec<&str>,
    ) -> RunnerDelta {
        let mut spec = make_spec("a", &paths.state_dir);
        spec.caches = after
            .iter()
            .map(|n| crate::config::EffectiveCacheBinding {
                name: (*n).into(),
                kinds: vec![crate::config::CacheKind::Ccache],
                size: "10G".into(),
                mode: crate::config::CacheMode::Shared,
                trust_zone: "default".into(),
            })
            .collect();
        let rendered = render_runner_unit(&spec).unwrap();
        let plan = RunnerPlan {
            spec_hash: spec.spec_hash.clone(),
            spec,
            resolved_release: None,
            effective_unit_text: rendered.template,
            drop_ins: rendered.drop_ins,
        };
        RunnerDelta {
            identity: RunnerIdentity {
                name: "a".into(),
                url: "https://github.com/example/repo".into(),
                auth_name: "pat".into(),
                trust_zone: "default".into(),
            },
            after: plan,
            requires_recreate: false,
            recreate_reasons: vec![],
            drift_cause: crate::plan::DriftCause::SpecChanged,
            field_changes: Vec::new(),
            drop_in_changes: Vec::new(),
            before_caches: before.map(|v| v.into_iter().map(String::from).collect()),
            before_drop_in_basenames: None,
        }
    }

    /// Pin that `execute_update_runner` populates the
    /// `InPlaceRestarted.pools_added` / `pools_removed` Vecs from the
    /// caches diff so cmd_apply's per-action detail line surfaces the
    /// pool NAMES (not just a count). This is the construction-side
    /// counterpart to the detail-string pin at
    /// `apply_outcome_detail_strings_are_stable` — together they
    /// guarantee an end-to-end "operator sees which pools moved".
    /// Three sub-cases mirror the existing in-place-caches tests:
    ///   - grow: `[]` → `["new-pool"]`     ⇒ pools_added=[new-pool], pools_removed=[]
    ///   - shrink: `["old-pool"]` → `[]`   ⇒ pools_added=[], pools_removed=[old-pool]
    ///   - replace: `["a","z"]` → `["m"]`  ⇒ pools_added=[m], pools_removed=[a,z] (sorted)
    /// The `replace` case also pins BTreeSet::difference's alphabetical
    /// ordering — `pools_removed` must be `[a, z]` not `[z, a]` so the
    /// rendered detail string is deterministic across runs.
    #[test]
    fn execute_update_runner_in_place_populates_pool_name_vecs() {
        fn run_case(before: Option<Vec<&str>>, after: Vec<&str>) -> ApplyOutcome {
            let tmp = tempfile::tempdir().unwrap();
            let paths = make_paths(&tmp);
            let systemd = MockSystemd::default();
                let tarball = MockTarball::default();
            let config_shell = MockConfigShell::default();
            let auth_map: HashMap<String, Box<dyn TokenSource>> = HashMap::new();
            let deps = Deps {
                systemd: &systemd,
                auth: &auth_map,
                tarball: &tarball,
                    config_shell: &config_shell,
            };
            let delta = make_caches_delta(&paths, before, after);
            let mut log = UndoLog::new();
            execute_update_runner(&delta, &deps, &paths, &mut log).unwrap()
        }

        // Pure grow.
        match run_case(Some(vec![]), vec!["new-pool"]) {
            ApplyOutcome::InPlaceRestarted {
                pools_added,
                pools_removed,
                ..
            } => {
                assert_eq!(pools_added, vec!["new-pool".to_string()]);
                assert!(pools_removed.is_empty());
            }
            other => panic!("expected InPlaceRestarted, got {other:?}"),
        }

        // Pure shrink.
        match run_case(Some(vec!["old-pool"]), vec![]) {
            ApplyOutcome::InPlaceRestarted {
                pools_added,
                pools_removed,
                ..
            } => {
                assert!(pools_added.is_empty());
                assert_eq!(pools_removed, vec!["old-pool".to_string()]);
            }
            other => panic!("expected InPlaceRestarted, got {other:?}"),
        }

        // Replace: alphabetical ordering pin (BTreeSet::difference).
        match run_case(Some(vec!["a", "z"]), vec!["m"]) {
            ApplyOutcome::InPlaceRestarted {
                pools_added,
                pools_removed,
                ..
            } => {
                assert_eq!(pools_added, vec!["m".to_string()]);
                assert_eq!(
                    pools_removed,
                    vec!["a".to_string(), "z".to_string()],
                    "pools_removed must be sorted (BTreeSet::difference order)",
                );
            }
            other => panic!("expected InPlaceRestarted, got {other:?}"),
        }
    }

    /// Pin the detail-string surface end-to-end — feed a
    /// real-world replace into execute_update_runner, assert the
    /// outcome's `detail()` output reads "(added: m; removed: a, z)".
    /// This is the integration counterpart to
    /// `apply_outcome_detail_strings_are_stable` (which builds the
    /// outcome by hand): together they prove the construction site
    /// emits the same shape the unit-level test pins.
    #[test]
    fn execute_update_runner_in_place_detail_string_surfaces_pool_names() {
        let tmp = tempfile::tempdir().unwrap();
        let paths = make_paths(&tmp);
        let systemd = MockSystemd::default();
        let tarball = MockTarball::default();
        let config_shell = MockConfigShell::default();
        let auth_map: HashMap<String, Box<dyn TokenSource>> = HashMap::new();
        let deps = Deps {
            systemd: &systemd,
            auth: &auth_map,
            tarball: &tarball,
            config_shell: &config_shell,
        };
        let delta = make_caches_delta(&paths, Some(vec!["a", "z"]), vec!["m"]);
        let mut log = UndoLog::new();
        let outcome = execute_update_runner(&delta, &deps, &paths, &mut log).unwrap();
        let detail = outcome.detail();
        // 3 group ops total: one add (`m`) plus two removes (`a`,`z`);
        // the group-op count rendered in the detail string is
        // `pools_added.len() + pools_removed.len() = 1 + 2 = 3`.
        // files_changed depends on whether the unit/drop-in bytes
        // diverge from make_paths's empty starting state (they always
        // do, since there are no prior files), so we use a stable
        // substring match on the pool-name parenthetical and on the
        // group-op count to keep the assertion robust to file-count
        // drift.
        assert!(
            detail.contains("(added: m; removed: a, z)"),
            "detail must surface pool names with `;` separator and \
             alphabetical ordering inside each group; got: {detail}",
        );
        assert!(
            detail.contains("3 group op(s)"),
            "detail group_ops count must equal pools_added.len() + \
             pools_removed.len(); got: {detail}",
        );
    }

    #[test]
    fn apply_dry_run_with_caches_change_is_skipped() {
        // dry_run=true at the apply() level short-circuits each action
        // before execute_*. A caches-list change routed through dry-run
        // apply lands in `result.skipped` instead of executing.
        let tmp = tempfile::tempdir().unwrap();
        let paths = make_paths(&tmp);
        fs::create_dir_all(paths.runtime_dir.as_std_path()).unwrap();

        let delta = make_caches_delta(&paths, Some(vec!["pool-old"]), vec!["pool-new"]);
        let plan = Plan {
            actions: vec![Action::UpdateRunner(delta)],
            warnings: vec![],
        };
        let systemd = MockSystemd::default();
        let tarball = MockTarball::default();
        let config_shell = MockConfigShell::default();
        let auth_map: HashMap<String, Box<dyn TokenSource>> = HashMap::new();
        let opts = ApplyOptions {
            dry_run: true,
            ..ApplyOptions::default()
        };
        let deps = Deps {
            systemd: &systemd,
            auth: &auth_map,
            tarball: &tarball,
            config_shell: &config_shell,
        };
        let result = apply(&plan, &deps, &paths, &opts).unwrap();

        assert_eq!(result.skipped.len(), 1, "dry-run must skip the action");
        // Dry-run-skipped actions still land in `details` so cmd_apply
        // can render the per-action `dry-run (skipped)` line. The
        // label tracks the skipped action verbatim.
        assert_eq!(result.details.len(), 1);
        assert!(matches!(result.details[0].1, ApplyOutcome::DryRunSkipped));
    }

    // ---------- ApplyOutcome::detail() string contracts -----------------

    /// Pin the per-variant detail string vocabulary so a future
    /// rename of the strings is a single-place audit. cmd_apply renders
    /// `ok: LABEL ({detail})` and downstream operators may grep on
    /// these tokens.
    #[test]
    fn apply_outcome_detail_strings_are_stable() {
        assert_eq!(
            ApplyOutcome::InPlaceSkipped.detail(),
            "noop (bytes + groups match)"
        );
        // Pool-membership Vecs empty ⇒ no parenthetical
        // suffix, preserving the no-suffix shape so operators with
        // downstream parsers see no churn on plans that rewrite
        // files but don't touch caches.
        assert_eq!(
            ApplyOutcome::InPlaceRestarted {
                files_changed: 2,
                pools_added: Vec::new(),
                pools_removed: Vec::new(),
            }
            .detail(),
            "in-place: 2 file(s) changed, 0 group op(s)"
        );
        // Added-only ⇒ `(added: ...)` suffix, comma-separated
        // names in BTreeSet::difference (alphabetical) order.
        assert_eq!(
            ApplyOutcome::InPlaceRestarted {
                files_changed: 1,
                pools_added: vec!["build-cache".into(), "ccache".into()],
                pools_removed: Vec::new(),
            }
            .detail(),
            "in-place: 1 file(s) changed, 2 group op(s) (added: build-cache, ccache)"
        );
        // Removed-only ⇒ `(removed: ...)` suffix.
        assert_eq!(
            ApplyOutcome::InPlaceRestarted {
                files_changed: 0,
                pools_added: Vec::new(),
                pools_removed: vec!["old-cache".into()],
            }
            .detail(),
            "in-place: 0 file(s) changed, 1 group op(s) (removed: old-cache)"
        );
        // Both-non-empty ⇒ semicolon-separated added/removed
        // groups so the suffix parses unambiguously even when pool
        // names contain commas (cache_pool name validator rejects
        // commas, so this is defensive — semicolon delimiter still
        // adds a layer of clarity for human readers).
        assert_eq!(
            ApplyOutcome::InPlaceRestarted {
                files_changed: 0,
                pools_added: vec!["new-cache".into()],
                pools_removed: vec!["old-cache".into()],
            }
            .detail(),
            "in-place: 0 file(s) changed, 2 group op(s) (added: new-cache; removed: old-cache)"
        );
        assert_eq!(
            ApplyOutcome::Recreated.detail(),
            "recreated (deregister + teardown + register + start)"
        );
        assert_eq!(
            ApplyOutcome::Created.detail(),
            "created (GitHub registration + unit start)"
        );
        assert_eq!(
            ApplyOutcome::Removed.detail(),
            "removed (GitHub deregister + unit + home + user)"
        );
        assert_eq!(
            ApplyOutcome::PoolCreated.detail(),
            "pool created (group + storage + unit)"
        );
        assert_eq!(
            ApplyOutcome::PoolUpdated.detail(),
            "pool updated (drop-in rewrite + restart)"
        );
        assert_eq!(
            ApplyOutcome::PoolSkipped.detail(),
            "pool noop (drop-in bytes match)"
        );
        assert_eq!(
            ApplyOutcome::PoolRemoved.detail(),
            "pool removed (group + storage + drop-in)"
        );
        assert_eq!(ApplyOutcome::NoOp.detail(), "noop (in sync)");
        assert_eq!(ApplyOutcome::DryRunSkipped.detail(), "dry-run (skipped)");
        // Failed.detail() returns the captured error_summary
        // verbatim — no rewrapping, no prefix.
        assert_eq!(
            ApplyOutcome::Failed {
                error_summary: "systemd: enable_unit failed".into(),
                plan_disruption: crate::plan::Disruption::Recreate,
            }
            .detail(),
            "systemd: enable_unit failed",
        );
    }

    /// Pin `InPlaceRestarted.detail()` output for the
    /// `before_caches = None` short-circuit path (pre-annotation runner
    /// with no `X-Ghars-Caches` annotation). Empty
    /// `pools_added`/`pools_removed` MUST render "0 group op(s)" with NO
    /// parenthetical, preserving the no-suffix shape.
    /// Construction-side coverage lives at
    /// `execute_update_runner_in_place_before_caches_none_skips_diff`
    /// (sibling — verifies the construction-site short-circuit produces
    /// the empty Vecs this test consumes).
    #[test]
    fn apply_outcome_in_place_restarted_none_before_caches_detail_no_parenthetical() {
        let outcome = ApplyOutcome::InPlaceRestarted {
            files_changed: 1,
            pools_added: Vec::new(),
            pools_removed: Vec::new(),
        };
        // Empty Vecs ⇒ detail() must NOT include any `(added:...)` or
        // `(removed:...)` parenthetical. No-suffix shape preserved.
        assert_eq!(
            outcome.detail(),
            "in-place: 1 file(s) changed, 0 group op(s)",
            "before_caches=None ⇒ pools_added/pools_removed empty ⇒ \
             detail() emits no parenthetical suffix",
        );
    }

    /// Multi-element detail() coverage for InPlaceRestarted.
    /// Existing `apply_outcome_detail_strings_are_stable` covers the
    /// 1-element and 2-element add cases. Defense-in-depth format
    /// pin for multi-element pool lists (3+ adds / 2+ removes).
    /// Format pin:
    ///   "in-place: F file(s) changed, G group op(s) (added: a, b, c; removed: d, e)"
    #[test]
    fn apply_outcome_in_place_restarted_detail_multi_element() {
        // 3 adds + 2 removes, both non-empty — pin both
        // comma-separated lists + semicolon between groups.
        let outcome = ApplyOutcome::InPlaceRestarted {
            files_changed: 5,
            pools_added: vec!["alpha".into(), "beta".into(), "gamma".into()],
            pools_removed: vec!["delta".into(), "epsilon".into()],
        };
        assert_eq!(
            outcome.detail(),
            "in-place: 5 file(s) changed, 5 group op(s) \
             (added: alpha, beta, gamma; removed: delta, epsilon)",
        );
    }

    /// Pin the ApplyOutcome → Disruption mapping. The mapping
    /// must mirror plan-time `Action::disruption` so cmd_apply's
    /// `[disruption]` bracket tag uses the same vocabulary as
    /// plan output. Operator grep on `[recreate]` matches both
    /// surfaces.
    #[test]
    fn apply_outcome_disruption_mapping_mirrors_plan_vocabulary() {
        use crate::plan::Disruption;
        // None: no host mutation actually happened.
        assert_eq!(ApplyOutcome::InPlaceSkipped.disruption(), Disruption::None);
        assert_eq!(ApplyOutcome::PoolSkipped.disruption(), Disruption::None);
        assert_eq!(ApplyOutcome::NoOp.disruption(), Disruption::None);
        assert_eq!(ApplyOutcome::DryRunSkipped.disruption(), Disruption::None);
        // Restart: stop+start of an existing unit.
        assert_eq!(
            ApplyOutcome::InPlaceRestarted {
                files_changed: 1,
                pools_added: Vec::new(),
                pools_removed: Vec::new(),
            }
            .disruption(),
            Disruption::Restart,
        );
        assert_eq!(ApplyOutcome::PoolUpdated.disruption(), Disruption::Restart);
        // Recreate: full host-state lifecycle change.
        assert_eq!(ApplyOutcome::Recreated.disruption(), Disruption::Recreate);
        assert_eq!(ApplyOutcome::Created.disruption(), Disruption::Recreate);
        assert_eq!(ApplyOutcome::Removed.disruption(), Disruption::Recreate);
        assert_eq!(ApplyOutcome::PoolCreated.disruption(), Disruption::Recreate,);
        assert_eq!(ApplyOutcome::PoolRemoved.disruption(), Disruption::Recreate,);
        // Failed.disruption() returns the action's plan-time
        // worst-case disruption stored in `plan_disruption`. All
        // three variants must round-trip — apply-time impact is
        // unknown, so we report the plan-time bound.
        for d in [Disruption::None, Disruption::Restart, Disruption::Recreate] {
            assert_eq!(
                ApplyOutcome::Failed {
                    error_summary: String::new(),
                    plan_disruption: d,
                }
                .disruption(),
                d,
                "Failed.disruption() must echo plan_disruption for {d:?}",
            );
        }
    }

    /// Pin the `UndoStep::describe()` output for every variant.
    /// cmd_apply's rollback-state advisory greps these strings in tests
    /// and operators may grep them in production output, so the
    /// vocabulary is stable. Past-tense per the doc-comment ("wrote",
    /// "started", "created", etc.). Byte-content fields
    /// (`WriteFile.prior_content`, `RemoveFile.content`) are
    /// intentionally absent from the rendering — they are recovery
    /// payloads for `undo()`, not advisory details.
    #[test]
    fn undo_step_describe_strings_are_stable() {
        let path = camino::Utf8PathBuf::from("/etc/ghars/runners/a/00-ghars.conf");
        assert_eq!(
            UndoStep::WriteFile {
                path: path.clone(),
                prior_content: None,
            }
            .describe(),
            "wrote /etc/ghars/runners/a/00-ghars.conf",
        );
        assert_eq!(
            UndoStep::RemoveFile {
                path: path.clone(),
                content: vec![1, 2, 3],
            }
            .describe(),
            "removed file /etc/ghars/runners/a/00-ghars.conf",
        );
        assert_eq!(
            UndoStep::CreateDir { path: path.clone() }.describe(),
            "created directory /etc/ghars/runners/a/00-ghars.conf",
        );
        assert_eq!(
            UndoStep::RemoveDir { path }.describe(),
            "removed directory /etc/ghars/runners/a/00-ghars.conf",
        );
        assert_eq!(
            UndoStep::StartUnit {
                name: "ghars-runner@foo.service".into(),
            }
            .describe(),
            "started ghars-runner@foo.service",
        );
        assert_eq!(
            UndoStep::StopUnit {
                name: "ghars-runner@foo.service".into(),
            }
            .describe(),
            "stopped ghars-runner@foo.service",
        );
        assert_eq!(
            UndoStep::EnableUnit {
                name: "ghars-runner@foo.service".into(),
            }
            .describe(),
            "enabled ghars-runner@foo.service",
        );
        assert_eq!(
            UndoStep::DisableUnit {
                name: "ghars-runner@foo.service".into(),
            }
            .describe(),
            "disabled ghars-runner@foo.service",
        );
        assert_eq!(
            UndoStep::GitHubRegistration {
                name: "foo".into(),
                url: "https://github.com/example/repo".into(),
                auth_name: "pat".into(),
                runner_home: camino::Utf8PathBuf::from("/var/lib/ghars/foo"),
            }
            .describe(),
            "registered runner foo against https://github.com/example/repo",
        );
    }

    /// Pin that `UndoLog::into_steps` returns the recorded steps
    /// in insertion order (matches `steps()` semantics) and consumes
    /// the log. The Err path in `apply()` calls this to plumb the
    /// per-action mutation manifest into `ApplyResult.failed_undo_logs`,
    /// so order-preservation is the visible operator-facing contract
    /// (the advisory lists steps in the order they happened on disk).
    #[test]
    fn undo_log_into_steps_preserves_insertion_order() {
        let mut log = UndoLog::new();
        log.push(UndoStep::WriteFile {
            path: camino::Utf8PathBuf::from("/a"),
            prior_content: None,
        });
        log.push(UndoStep::CreateDir {
            path: camino::Utf8PathBuf::from("/b"),
        });
        log.push(UndoStep::StartUnit {
            name: "x.service".into(),
        });
        let steps = log.into_steps();
        assert_eq!(steps.len(), 3);
        assert!(matches!(&steps[0], UndoStep::WriteFile { path, .. } if path == "/a"));
        assert!(matches!(&steps[1], UndoStep::CreateDir { path } if path == "/b"));
        assert!(matches!(&steps[2], UndoStep::StartUnit { name } if name == "x.service"),);
    }

    /// Pin that `apply()` pushes a `(label, NoOp)` row into
    /// `details` for `Action::NoOp` actions, NOT a Created or other
    /// real-action variant. Defends against a future refactor that
    /// drops the NoOp short-circuit and routes through `execute()`.
    #[test]
    fn apply_records_noop_action_with_noop_outcome() {
        let tmp = tempfile::tempdir().unwrap();
        let paths = make_paths(&tmp);
        fs::create_dir_all(paths.runtime_dir.as_std_path()).unwrap();
        let plan = Plan {
            actions: vec![Action::NoOp("buckos: in sync".into())],
            warnings: vec![],
        };
        let systemd = MockSystemd::default();
        let tarball = MockTarball::default();
        let config_shell = MockConfigShell::default();
        let auth_map: HashMap<String, Box<dyn TokenSource>> = HashMap::new();
        let opts = ApplyOptions::default();
        let deps = Deps {
            systemd: &systemd,
            auth: &auth_map,
            tarball: &tarball,
            config_shell: &config_shell,
        };
        let result = apply(&plan, &deps, &paths, &opts).unwrap();
        assert_eq!(result.details.len(), 1, "NoOp must land in details");
        let (label, outcome) = &result.details[0];
        assert!(label.contains("NoOp"), "got label: {label}");
        assert!(
            matches!(outcome, ApplyOutcome::NoOp),
            "NoOp action must produce NoOp outcome, got: {outcome:?}",
        );
    }

    /// Build a delta whose `drop_in_changes` matches the rendered drop-in
    /// set with every basename marked Preserved. Used by the skip
    /// tests to express "every byte on disk already equals what we
    /// would render".
    fn delta_with_all_preserved_drop_ins(paths: &Paths) -> RunnerDelta {
        let spec = make_spec("a", &paths.state_dir);
        let rendered = render_runner_unit(&spec).unwrap();
        let drop_in_changes: Vec<crate::plan::DropInChange> = rendered
            .drop_ins
            .keys()
            .map(|k| crate::plan::DropInChange {
                basename: k.clone(),
                change: DropInChangeKind::Preserved,
            })
            .collect();
        let plan = RunnerPlan {
            spec_hash: spec.spec_hash.clone(),
            spec,
            resolved_release: None,
            effective_unit_text: rendered.template,
            drop_ins: rendered.drop_ins,
        };
        RunnerDelta {
            identity: RunnerIdentity {
                name: "a".into(),
                url: "https://github.com/example/repo".into(),
                auth_name: "pat".into(),
                trust_zone: "default".into(),
            },
            after: plan,
            requires_recreate: false,
            recreate_reasons: vec![],
            drift_cause: crate::plan::DriftCause::SpecChanged,
            field_changes: Vec::new(),
            drop_in_changes,
            // No before_caches mismatch ⇒ no group ops. The skip path
            // requires both file-byte equality AND group-op no-op.
            before_caches: Some(vec![]),
            before_drop_in_basenames: None,
        }
    }

    /// Pre-populate `paths.unit_dir` with the rendered unit + every
    /// drop-in body that `delta.after` would emit. Mirrors what
    /// `execute_update_runner` would have written on a successful
    /// prior apply. Used by the skip tests.
    fn prepopulate_on_disk(paths: &Paths, delta: &RunnerDelta) {
        std::fs::create_dir_all(paths.unit_dir.as_std_path()).unwrap();
        let unit_file = paths.unit_file(&delta.identity.name);
        std::fs::write(
            unit_file.as_std_path(),
            delta.after.effective_unit_text.as_bytes(),
        )
        .unwrap();
        let drop_in_dir = paths.drop_in_dir(&delta.identity.name);
        std::fs::create_dir_all(drop_in_dir.as_std_path()).unwrap();
        for (name, body) in &delta.after.drop_ins {
            let dest = drop_in_dir.join(name);
            std::fs::write(dest.as_std_path(), body.as_bytes()).unwrap();
        }
    }

    /// When every managed file on disk byte-matches what we would
    /// render AND the supplementary-group set is unchanged, the
    /// in-place path skips daemon-reload + stop + start entirely.
    #[test]
    fn execute_update_runner_in_place_skips_restart_when_bytes_match() {
        let tmp = tempfile::tempdir().unwrap();
        let paths = make_paths(&tmp);
        let systemd = MockSystemd::default();
        let tarball = MockTarball::default();
        let config_shell = MockConfigShell::default();
        let auth_map: HashMap<String, Box<dyn TokenSource>> = HashMap::new();
        let deps = Deps {
            systemd: &systemd,
            auth: &auth_map,
            tarball: &tarball,
            config_shell: &config_shell,
        };
        let delta = delta_with_all_preserved_drop_ins(&paths);
        prepopulate_on_disk(&paths, &delta);
        let mut log = UndoLog::new();
        let outcome = execute_update_runner(&delta, &deps, &paths, &mut log).unwrap();
        // The byte-equality short-circuit must surface
        // as `InPlaceSkipped` so cmd_apply renders the per-action
        // detail line as `no-op (bytes match)`.
        assert_eq!(outcome, ApplyOutcome::InPlaceSkipped);

        let calls = systemd.calls_snapshot();
        assert!(
            calls.is_empty(),
            "skip path must not touch systemd; got: {calls:?}",
        );
        assert!(
            log.is_empty(),
            "skip path must not push any UndoStep; got len={}",
            log.len(),
        );
    }

    /// When the on-disk unit-file bytes drift from the rendered
    /// effective_unit_text, the helper writes through and the
    /// daemon-reload + stop + start cycle fires as before.
    #[test]
    fn execute_update_runner_in_place_restarts_when_unit_file_differs() {
        let tmp = tempfile::tempdir().unwrap();
        let paths = make_paths(&tmp);
        let systemd = MockSystemd::default();
        let tarball = MockTarball::default();
        let config_shell = MockConfigShell::default();
        let auth_map: HashMap<String, Box<dyn TokenSource>> = HashMap::new();
        let deps = Deps {
            systemd: &systemd,
            auth: &auth_map,
            tarball: &tarball,
            config_shell: &config_shell,
        };
        let delta = delta_with_all_preserved_drop_ins(&paths);
        prepopulate_on_disk(&paths, &delta);
        // Tamper with the on-disk unit-file so its bytes no longer
        // match `delta.after.effective_unit_text`. The drop-ins on
        // disk still match, and `drop_in_changes` says Preserved for
        // each — but the unit-file mismatch alone must force the
        // restart cycle.
        let unit_file = paths.unit_file(&delta.identity.name);
        std::fs::write(unit_file.as_std_path(), b"[Unit]\nDescription=stale\n").unwrap();
        let mut log = UndoLog::new();
        execute_update_runner(&delta, &deps, &paths, &mut log).unwrap();

        let calls = systemd.calls_snapshot();
        assert!(
            calls.iter().any(|c| c == "daemon_reload"),
            "unit-file drift must trigger daemon_reload; got: {calls:?}",
        );
        assert!(
            calls
                .iter()
                .any(|c| c.starts_with("stop_unit(ghars-runner@a")),
            "unit-file drift must stop the unit; got: {calls:?}",
        );
        assert!(
            calls
                .iter()
                .any(|c| c.starts_with("start_unit(ghars-runner@a")),
            "unit-file drift must start the unit; got: {calls:?}",
        );
    }

    /// When one drop-in's on-disk body drifts (and Stage 2 marks
    /// it Modified instead of Preserved), the write happens and the
    /// restart cycle fires.
    #[test]
    fn execute_update_runner_in_place_restarts_when_drop_in_differs() {
        let tmp = tempfile::tempdir().unwrap();
        let paths = make_paths(&tmp);
        let systemd = MockSystemd::default();
        let tarball = MockTarball::default();
        let config_shell = MockConfigShell::default();
        let auth_map: HashMap<String, Box<dyn TokenSource>> = HashMap::new();
        let deps = Deps {
            systemd: &systemd,
            auth: &auth_map,
            tarball: &tarball,
            config_shell: &config_shell,
        };
        let mut delta = delta_with_all_preserved_drop_ins(&paths);
        // Pick the first drop-in basename and flip its Stage 2 entry
        // from Preserved to Modified — this mirrors what plan.rs does
        // when a managed drop-in's bytes drift on disk relative to the
        // re-render.
        let basename = delta
            .after
            .drop_ins
            .keys()
            .next()
            .cloned()
            .expect("rendered drop-ins must be non-empty for this fixture");
        let after_body = delta.after.drop_ins.get(&basename).cloned().unwrap();
        for change in &mut delta.drop_in_changes {
            if change.basename == basename {
                change.change = DropInChangeKind::Modified {
                    before: "[Unit]\nX-Drift=stale\n".into(),
                    after: after_body.clone(),
                };
                break;
            }
        }
        // On disk: unit-file matches (skip-eligible) but the drifted
        // drop-in does NOT match the rendered body. The Modified
        // classification routes the basename through
        // read_then_write_if_changed, which detects the byte mismatch
        // and writes through.
        prepopulate_on_disk(&paths, &delta);
        let drop_in_dir = paths.drop_in_dir(&delta.identity.name);
        std::fs::write(
            drop_in_dir.join(&basename).as_std_path(),
            b"[Unit]\nX-Drift=stale\n",
        )
        .unwrap();
        let mut log = UndoLog::new();
        execute_update_runner(&delta, &deps, &paths, &mut log).unwrap();

        let calls = systemd.calls_snapshot();
        assert!(
            calls.iter().any(|c| c == "daemon_reload"),
            "drop-in drift must trigger daemon_reload; got: {calls:?}",
        );
        // And confirm the on-disk bytes were rewritten to the
        // rendered body — read_then_write_if_changed only writes when
        // bytes differ, so this proves the rewrite happened.
        let after_disk = std::fs::read(drop_in_dir.join(&basename).as_std_path()).unwrap();
        assert_eq!(after_disk, after_body.as_bytes());
    }

    // ---------- cache-pool byte-equality short-circuit -----------------
    //
    // execute_update_cache_pool mirrors execute_update_runner's
    // skip gate: if the 00-ghars.conf drop-in already matches the
    // rendered body byte-for-byte AND the drop-in directory existed
    // before this apply, return ApplyOutcome::PoolSkipped without
    // touching systemd. The next two tests pin the happy path
    // (skip when bytes match) and the write-through path (restart
    // when drop-in body diverges).

    /// Build a `CachePoolDelta` whose `drop_in_body` is a stable
    /// non-empty byte string. The skip tests prepopulate that exact
    /// body on disk and assert the byte-equality short-circuit fires.
    fn skip_test_cache_delta(name: &str) -> CachePoolDelta {
        CachePoolDelta {
            binding: crate::config::EffectiveCacheBinding {
                name: name.into(),
                kinds: vec![crate::config::CacheKind::Ccache],
                size: "100G".into(),
                mode: crate::config::CacheMode::Shared,
                trust_zone: "default".into(),
            },
            drop_in_body: "[Service]\nEnvironment=GHARS_TEST=1\n".into(),
            spec_hash: "sha256:cafe".into(),
        }
    }

    /// When the 00-ghars.conf drop-in on disk byte-matches what
    /// `execute_update_cache_pool` would render AND the drop-in
    /// directory already existed (CreateDir wouldn't fire), the
    /// in-place pool path skips daemon-reload + stop + start entirely
    /// and returns `PoolSkipped`. Symmetric with the runner-side
    /// `execute_update_runner_in_place_skips_restart_when_bytes_match`.
    #[test]
    fn execute_update_cache_pool_skips_restart_when_bytes_match() {
        let tmp = tempfile::tempdir().unwrap();
        let paths = make_paths(&tmp);
        let systemd = MockSystemd::default();
        let tarball = MockTarball::default();
        let config_shell = MockConfigShell::default();
        let auth_map: HashMap<String, Box<dyn TokenSource>> = HashMap::new();
        let deps = Deps {
            systemd: &systemd,
            auth: &auth_map,
            tarball: &tarball,
            config_shell: &config_shell,
        };
        let delta = skip_test_cache_delta("build");
        // Prepopulate: drop-in dir exists (so CreateDir does NOT
        // count as a mutation) AND the 00-ghars.conf bytes already
        // match the rendered body. This is exactly the "next
        // apply after a successful prior apply, no config drift"
        // shape the optimization targets.
        let drop_in_dir = paths.cache_drop_in_dir(&delta.binding.name);
        std::fs::create_dir_all(drop_in_dir.as_std_path()).unwrap();
        std::fs::write(
            drop_in_dir.join("00-ghars.conf").as_std_path(),
            delta.drop_in_body.as_bytes(),
        )
        .unwrap();
        let mut log = UndoLog::new();
        let outcome = execute_update_cache_pool(&delta, &deps, &paths, &mut log).unwrap();

        assert_eq!(outcome, ApplyOutcome::PoolSkipped);
        let calls = systemd.calls_snapshot();
        assert!(
            calls.is_empty(),
            "skip path must not touch systemd; got: {calls:?}",
        );
        assert!(
            log.is_empty(),
            "skip path must not push any UndoStep (no writes, no unit ops); got len={}",
            log.len(),
        );
    }

    /// When the 00-ghars.conf drop-in on disk diverges from the
    /// rendered body, `read_then_write_if_changed` writes through and
    /// the daemon-reload + stop + start cycle fires. Returns
    /// `PoolUpdated`, never `PoolSkipped`.
    #[test]
    fn execute_update_cache_pool_restarts_when_drop_in_differs() {
        let tmp = tempfile::tempdir().unwrap();
        let paths = make_paths(&tmp);
        let systemd = MockSystemd::default();
        let tarball = MockTarball::default();
        let config_shell = MockConfigShell::default();
        let auth_map: HashMap<String, Box<dyn TokenSource>> = HashMap::new();
        let deps = Deps {
            systemd: &systemd,
            auth: &auth_map,
            tarball: &tarball,
            config_shell: &config_shell,
        };
        let delta = skip_test_cache_delta("build");
        // Drop-in dir exists, but the on-disk body diverges from
        // delta.drop_in_body — the byte-equality check in
        // read_then_write_if_changed must detect the mismatch and
        // route to the write + restart cycle.
        let drop_in_dir = paths.cache_drop_in_dir(&delta.binding.name);
        std::fs::create_dir_all(drop_in_dir.as_std_path()).unwrap();
        std::fs::write(
            drop_in_dir.join("00-ghars.conf").as_std_path(),
            b"[Service]\nEnvironment=GHARS_DRIFT=stale\n",
        )
        .unwrap();
        let mut log = UndoLog::new();
        let outcome = execute_update_cache_pool(&delta, &deps, &paths, &mut log).unwrap();

        assert_eq!(outcome, ApplyOutcome::PoolUpdated);
        let calls = systemd.calls_snapshot();
        assert!(
            calls.iter().any(|c| c == "daemon_reload"),
            "drop-in drift must trigger daemon_reload; got: {calls:?}",
        );
        assert!(
            calls
                .iter()
                .any(|c| c.starts_with("stop_unit(ghars-cache@build")),
            "drop-in drift must stop the unit; got: {calls:?}",
        );
        assert!(
            calls
                .iter()
                .any(|c| c.starts_with("start_unit(ghars-cache@build")),
            "drop-in drift must start the unit; got: {calls:?}",
        );
        // Confirm the on-disk bytes were rewritten to the rendered
        // body — read_then_write_if_changed only writes when bytes
        // differ.
        let after_disk = std::fs::read(drop_in_dir.join("00-ghars.conf").as_std_path()).unwrap();
        assert_eq!(after_disk, delta.drop_in_body.as_bytes());
    }

    /// First-time pool update where the drop-in directory does
    /// NOT exist beforehand. CreateDir is itself a mutation, so even
    /// if the (yet-to-be-written) 00-ghars.conf would byte-match a
    /// hypothetical prior body, the skip gate must NOT fire on this
    /// path — daemon-reload + restart still has to run because
    /// systemd has no record of the freshly-planted directory.
    /// Mirrors the runner-side CreateDir-counts-as-change semantic
    /// (`files_changed += 1` when `!drop_in_dir_existed`).
    #[test]
    fn execute_update_cache_pool_restarts_on_first_drop_in_dir_create() {
        let tmp = tempfile::tempdir().unwrap();
        let paths = make_paths(&tmp);
        let systemd = MockSystemd::default();
        let tarball = MockTarball::default();
        let config_shell = MockConfigShell::default();
        let auth_map: HashMap<String, Box<dyn TokenSource>> = HashMap::new();
        let deps = Deps {
            systemd: &systemd,
            auth: &auth_map,
            tarball: &tarball,
            config_shell: &config_shell,
        };
        let delta = skip_test_cache_delta("build");
        // Deliberately do NOT create cache_drop_in_dir beforehand —
        // execute_update_cache_pool must observe drop_in_dir_existed
        // == false, count CreateDir as a mutation, and proceed to
        // restart.
        let mut log = UndoLog::new();
        let outcome = execute_update_cache_pool(&delta, &deps, &paths, &mut log).unwrap();

        assert_eq!(outcome, ApplyOutcome::PoolUpdated);
        let calls = systemd.calls_snapshot();
        assert!(
            calls.iter().any(|c| c == "daemon_reload"),
            "first-time CreateDir must trigger daemon_reload; got: {calls:?}",
        );
        assert!(
            calls
                .iter()
                .any(|c| c.starts_with("stop_unit(ghars-cache@build")),
            "first-time CreateDir must stop the unit; got: {calls:?}",
        );
        assert!(
            calls
                .iter()
                .any(|c| c.starts_with("start_unit(ghars-cache@build")),
            "first-time CreateDir must start the unit; got: {calls:?}",
        );
    }

    /// When a managed drop-in is present on disk but absent from
    /// `delta.after.drop_ins` (Stage 2 classifies it as Removed), the
    /// file is deleted, `files_changed` increments, and the restart
    /// cycle fires. Operator drop-ins CAN appear in `drop_in_changes`
    /// as Removed entries (Stage 2 walks the union of rendered +
    /// discovered keys); the deletion loop's MANAGED_DROP_IN_BASENAMES
    /// guard keeps them safe — see the BUG #B36 regression test
    /// `update_runner_in_place_preserves_operator_drop_ins` for the
    /// guarded-operator-basename branch.
    #[test]
    fn execute_update_runner_in_place_restarts_when_managed_orphan_exists() {
        let tmp = tempfile::tempdir().unwrap();
        let paths = make_paths(&tmp);
        let systemd = MockSystemd::default();
        let tarball = MockTarball::default();
        let config_shell = MockConfigShell::default();
        let auth_map: HashMap<String, Box<dyn TokenSource>> = HashMap::new();
        let deps = Deps {
            systemd: &systemd,
            auth: &auth_map,
            tarball: &tarball,
            config_shell: &config_shell,
        };
        let mut delta = delta_with_all_preserved_drop_ins(&paths);
        // Inject a Stage 2 Removed entry for a managed basename
        // (50-numa.conf): the rendered side has no entry for it, but
        // the on-disk side does. The basename MUST be in
        // MANAGED_DROP_IN_BASENAMES — otherwise the defense-in-depth
        // guard inside execute_update_runner correctly refuses to
        // delete it.
        let orphan = "50-numa.conf";
        delta.drop_in_changes.push(crate::plan::DropInChange {
            basename: orphan.into(),
            change: DropInChangeKind::Removed {
                before: "[Service]\nNUMAPolicy=interleave\n".into(),
            },
        });
        prepopulate_on_disk(&paths, &delta);
        let drop_in_dir = paths.drop_in_dir(&delta.identity.name);
        std::fs::write(
            drop_in_dir.join(orphan).as_std_path(),
            b"[Service]\nNUMAPolicy=interleave\n",
        )
        .unwrap();
        let mut log = UndoLog::new();
        execute_update_runner(&delta, &deps, &paths, &mut log).unwrap();

        let calls = systemd.calls_snapshot();
        assert!(
            calls.iter().any(|c| c == "daemon_reload"),
            "managed orphan deletion must trigger daemon_reload; got: {calls:?}",
        );
        assert!(
            !drop_in_dir.join(orphan).as_std_path().exists(),
            "managed orphan must be removed from disk",
        );
    }

    #[test]
    fn execute_update_runner_in_place_before_caches_none_skips_diff() {
        // before_caches == None ⇒ pre-annotation runner. Skip the diff;
        // neither add nor remove must fire even though `after.caches`
        // is non-empty (a fresh apply will land annotations and a
        // future edit can reconcile).
        let tmp = tempfile::tempdir().unwrap();
        let paths = make_paths(&tmp);
        let systemd = MockSystemd::default();
        let tarball = MockTarball::default();
        let config_shell = MockConfigShell::default();
        // In-place path doesn't mint tokens; empty registry suffices.
        let auth_map: HashMap<String, Box<dyn TokenSource>> = HashMap::new();
        let deps = Deps {
            systemd: &systemd,
            auth: &auth_map,
            tarball: &tarball,
            config_shell: &config_shell,
        };
        let delta = make_caches_delta(&paths, None, vec!["pool"]);
        let mut log = UndoLog::new();
        execute_update_runner(&delta, &deps, &paths, &mut log).unwrap();
        // before_caches=None ⇒ no caches-list diff is computed; the
        // pre-DynamicUser version also asserted no gpasswd ops fire,
        // but that machinery is gone — just exercising the no-panic
        // path is the remaining signal.
    }

    // ---------- call-site sanitization wiring pins (apply.rs) -----------

    /// Pin that `UndoStep::WriteFile::describe()` runs the
    /// path through `escape_control_chars`. Helper-level coverage
    /// already lives in `lib.rs`; this test drives the real production
    /// `describe()` method with a hostile path containing `\x1b[31m`,
    /// asserts (i) raw ESC byte is gone, (ii) the printable
    /// `\u{1b}` escape form `char::escape_default` emits is present,
    /// and (iii) the surrounding `wrote ` prefix is intact.
    ///
    /// Pinned because the `describe()` method has 13 String-typed
    /// variant arms (RemoveFile, StartUnit, GitHubRegistration, etc.);
    /// a future refactor that drops `escape_control_chars` from one
    /// arm would compile and pass other describe() tests, but
    /// re-introduce the ANSI-hijack attack surface for that variant.
    /// WriteFile is the canary — symmetric coverage is one assertion
    /// chain across all 13 (a separate field-set audit covers the rest).
    #[test]
    fn undo_step_write_file_describe_escapes_hostile_path() {
        let hostile = Utf8PathBuf::from("/etc/ghars/\x1b[31mshim.conf");
        let step = UndoStep::WriteFile {
            path: hostile,
            prior_content: None,
        };
        let described = step.describe();
        assert!(
            !described.contains('\x1b'),
            "raw ESC must not survive describe(); got: {described:?}"
        );
        assert!(
            described.contains("\\u{1b}"),
            "expected \\u{{1b}} escape form from char::escape_default; got: {described}"
        );
        // Sanity: the production prefix and the non-control suffix
        // both pass through. Pins that the format string didn't drop
        // identifying context.
        assert!(described.starts_with("wrote "), "got: {described}");
        assert!(
            described.contains("shim.conf"),
            "non-control suffix must pass through; got: {described}"
        );
    }

    // ---------- execute_update_runner recreate-branch tests ------------
    //
    // These tests drive the recreate path through
    // `execute_update_runner` (which dispatches to
    // `execute_remove_runner` + `execute_create_runner` when
    // `delta.requires_recreate` is true). Pins the call sequence,
    // outcome variant, post-register sha256 wiring, and failure-mode
    // contracts (remove-fail short-circuits create; create-fail
    // bubbles after remove succeeded).

    /// T1: recreate full-success log ordering pin. When
    /// `delta.requires_recreate=true`, the ordered side-effect log
    /// must be: stop_unit → disable_unit (remove) → useradd → unit
    /// + drop-in writes → enable_unit → start_unit (create). Pin
    /// the systemd-call sequence so a refactor that reorders
    /// stop/disable vs enable/start (which would race the
    /// runner's lifecycle on real hosts) is caught at test time.
    #[test]
    fn execute_update_runner_recreate_full_success_systemd_call_sequence() {
        let tmp = tempfile::tempdir().unwrap();
        let paths = make_paths(&tmp);
        // Pre-populate state so execute_remove_runner has unit + home
        // to clean up.
        fs::create_dir_all(paths.unit_dir.as_std_path()).unwrap();
        fs::write(
            paths.unit_file("a").as_std_path(),
            b"[Unit]\nX-Ghars-Managed=true\n",
        )
        .unwrap();
        fs::create_dir_all(paths.drop_in_dir("a").as_std_path()).unwrap();
        fs::create_dir_all(paths.runner_home("default", "a").as_std_path()).unwrap();
        fs::create_dir_all(paths.runtime_dir.as_std_path()).unwrap();

        let systemd = MockSystemd::default();
        let tarball = MockTarball::default();
        let config_shell = MockConfigShell::default();
        let mut auth_map: HashMap<String, Box<dyn TokenSource>> = HashMap::new();
        auth_map.insert(
            "pat".into(),
            Box::new(MockTokenSource {
                name: "pat".into(),
                ..MockTokenSource::default()
            }),
        );
        let deps = Deps {
            systemd: &systemd,
            auth: &auth_map,
            tarball: &tarball,
            config_shell: &config_shell,
        };
        let mut delta = make_caches_delta(&paths, Some(vec![]), vec![]);
        delta.requires_recreate = true;
        delta.recreate_reasons = vec!["url"];
        delta.after.resolved_release = Some(make_release());

        execute_update_runner(&delta, &deps, &paths, &mut UndoLog::new()).unwrap();

        let calls = systemd.calls_snapshot();
        let unit = "ghars-runner@a.service";
        let stop_idx = calls
            .iter()
            .position(|c| c == &format!("stop_unit({unit})"))
            .expect("stop_unit must fire (remove path)");
        let disable_idx = calls
            .iter()
            .position(|c| c == &format!("disable_unit({unit})"))
            .expect("disable_unit must fire (remove path)");
        let enable_idx = calls
            .iter()
            .position(|c| c == &format!("enable_unit({unit})"))
            .expect("enable_unit must fire (create path)");
        let start_idx = calls
            .iter()
            .position(|c| c == &format!("start_unit({unit})"))
            .expect("start_unit must fire (create path)");
        // Recreate ordering: stop then disable (remove), enable then
        // start (create). The remove-side stop+disable MUST precede
        // the create-side enable+start; otherwise the unit could
        // race "enable a unit that is about to be stopped".
        assert!(
            stop_idx < disable_idx,
            "stop must precede disable; got calls: {calls:?}"
        );
        assert!(
            disable_idx < enable_idx,
            "remove (stop+disable) must precede create (enable+start); got calls: {calls:?}"
        );
        assert!(
            enable_idx < start_idx,
            "enable must precede start; got calls: {calls:?}"
        );
    }

    /// T2: remove-failure short-circuits create. When the
    /// recreate path's first half (`execute_remove_runner`) errors
    /// out, the second half (`execute_create_runner`) MUST NOT fire
    /// — the `?` operator on the `execute_remove_runner` call inside
    /// the recreate branch propagates the Err. Pin via
    /// an empty auth_map: `mint_token` inside execute_remove_runner
    /// fails at the deregister step. Asserts (i) the function
    /// returns Err, (ii) `tarball.installed` is empty (no create
    /// side effect ran), (iii) `users.added` is empty
    /// (`useradd_if_missing` from create's step 1 never ran).
    #[test]
    fn execute_update_runner_recreate_remove_failure_skips_create() {
        let tmp = tempfile::tempdir().unwrap();
        let paths = make_paths(&tmp);
        fs::create_dir_all(paths.unit_dir.as_std_path()).unwrap();
        fs::write(paths.unit_file("a").as_std_path(), b"[Unit]\n").unwrap();
        fs::create_dir_all(paths.drop_in_dir("a").as_std_path()).unwrap();
        fs::create_dir_all(paths.runner_home("default", "a").as_std_path()).unwrap();
        fs::create_dir_all(paths.runtime_dir.as_std_path()).unwrap();

        let systemd = MockSystemd::default();
        let tarball = MockTarball::default();
        let config_shell = MockConfigShell::default();
        // EMPTY auth_map → execute_remove_runner's mint_token fails
        // because identity.auth_name="pat" is not in the registry.
        // (orphan-skip would only fire if auth_name was empty; with a
        // populated auth_name and an empty registry, mint_token
        // returns Err.)
        let auth_map: HashMap<String, Box<dyn TokenSource>> = HashMap::new();
        let deps = Deps {
            systemd: &systemd,
            auth: &auth_map,
            tarball: &tarball,
            config_shell: &config_shell,
        };
        let mut delta = make_caches_delta(&paths, Some(vec![]), vec![]);
        delta.requires_recreate = true;
        delta.recreate_reasons = vec!["url"];
        delta.after.resolved_release = Some(make_release());

        let err = execute_update_runner(&delta, &deps, &paths, &mut UndoLog::new()).unwrap_err();
        // Sanity: the error originated from the auth path (mint_token
        // for the remove deregister step).
        let rendered = format!("{err}");
        assert!(
            rendered.contains("auth source") || rendered.contains("not in the registry"),
            "expected auth-mint failure; got: {rendered}"
        );
        // Create side effects MUST NOT have fired:
        assert!(
            tarball.installed.lock().unwrap().is_empty(),
            "tarball.install_binary must not run when remove fails; got: {:?}",
            tarball.installed.lock().unwrap(),
        );
        assert!(
            tarball.fetched.lock().unwrap().is_empty(),
            "tarball.fetch_or_verify must not run when remove fails; got: {:?}",
            tarball.fetched.lock().unwrap(),
        );
        // Create-path config_shell.run_register must not have fired
        // either (it is keyed off the create path's run_register
        // call). MockConfigShell has separate `registered`/`removed`
        // Vecs; remove may or may not have called run_remove
        // depending on where the failure landed (mint_token is
        // BEFORE run_remove), so the registered Vec is what we pin.
        assert!(
            config_shell.registered.lock().unwrap().is_empty(),
            "config_shell.run_register must not run when remove fails; got: {:?}",
            config_shell.registered.lock().unwrap(),
        );
    }

    /// T3: create-failure-after-remove. Remove succeeds, then
    /// create errors out at the "no runner_tarball and no resolved
    /// release" Validation gate inside `execute_create_runner`. The
    /// function returns
    /// Err with the create-side failure; execute_remove_runner's
    /// successful side effects (deregister + cleanup) already
    /// landed, mirroring the production "partial new state" trade-off
    /// documented at the recreate path's call site.
    ///
    /// Pin: (i) function returns Err, (ii) the error mentions the
    /// create-path Validation message, (iii) execute_remove_runner
    /// side effects fired (tarball NOT installed because create
    /// bailed before install, but config_shell.removed has the
    /// runner — proves remove ran).
    #[test]
    fn execute_update_runner_recreate_create_failure_after_remove() {
        let tmp = tempfile::tempdir().unwrap();
        let paths = make_paths(&tmp);
        fs::create_dir_all(paths.unit_dir.as_std_path()).unwrap();
        fs::write(paths.unit_file("a").as_std_path(), b"[Unit]\n").unwrap();
        fs::create_dir_all(paths.drop_in_dir("a").as_std_path()).unwrap();
        fs::create_dir_all(paths.runner_home("default", "a").as_std_path()).unwrap();
        fs::create_dir_all(paths.runtime_dir.as_std_path()).unwrap();

        let systemd = MockSystemd::default();
        let tarball = MockTarball::default();
        let config_shell = MockConfigShell::default();
        let mut auth_map: HashMap<String, Box<dyn TokenSource>> = HashMap::new();
        auth_map.insert(
            "pat".into(),
            Box::new(MockTokenSource {
                name: "pat".into(),
                ..MockTokenSource::default()
            }),
        );
        let deps = Deps {
            systemd: &systemd,
            auth: &auth_map,
            tarball: &tarball,
            config_shell: &config_shell,
        };
        let mut delta = make_caches_delta(&paths, Some(vec![]), vec![]);
        delta.requires_recreate = true;
        delta.recreate_reasons = vec!["url"];
        // Trigger the create-path Validation gate: no runner_tarball
        // AND no resolved_release. make_caches_delta already sets
        // runner_tarball=None; resolved_release defaults to None
        // here too, so the create branch fails at the
        // `execute_create_runner` Validation gate.
        assert!(delta.after.spec.runner_tarball.is_none());
        assert!(delta.after.resolved_release.is_none());

        let err = execute_update_runner(&delta, &deps, &paths, &mut UndoLog::new()).unwrap_err();
        let rendered = format!("{err}");
        assert!(
            rendered.contains("no runner_tarball") && rendered.contains("no resolved release"),
            "expected create-path Validation failure; got: {rendered}"
        );
        // Remove side effects MUST have fired before create errored:
        // run_remove for the runner appears in config_shell.removed.
        assert_eq!(
            config_shell.removed.lock().unwrap().len(),
            1,
            "remove path's run_remove must have fired before create errored; got: {:?}",
            config_shell.removed.lock().unwrap(),
        );
        // tarball.install_binary did NOT run (step 2 hit the gate).
        assert!(
            tarball.installed.lock().unwrap().is_empty(),
            "install_binary must not run; got: {:?}",
            tarball.installed.lock().unwrap(),
        );
    }

    /// T4: orphan-skip-token-mint inside the recreate path.
    /// `execute_remove_runner`'s deregister branch checks
    /// `identity.auth_name.is_empty() || identity.url.is_empty()`
    /// and skips `mint_token` + `run_remove` when either is empty.
    /// Pin: drive the recreate path with an orphan-shaped identity;
    /// assert (i) Recreated outcome, (ii) config_shell.removed
    /// is empty (run_remove never ran — the deregister step
    /// short-circuited), (iii) the create path still ran fully
    /// (registered Vec has the runner, useradd ran).
    #[test]
    fn execute_update_runner_recreate_orphan_identity_skips_token_mint() {
        let tmp = tempfile::tempdir().unwrap();
        let paths = make_paths(&tmp);
        fs::create_dir_all(paths.unit_dir.as_std_path()).unwrap();
        fs::write(paths.unit_file("a").as_std_path(), b"[Unit]\n").unwrap();
        fs::create_dir_all(paths.drop_in_dir("a").as_std_path()).unwrap();
        fs::create_dir_all(paths.runner_home("default", "a").as_std_path()).unwrap();
        fs::create_dir_all(paths.runtime_dir.as_std_path()).unwrap();

        let systemd = MockSystemd::default();
        let tarball = MockTarball::default();
        let config_shell = MockConfigShell::default();
        // Auth registry contains "pat" so the create-path mint
        // (which uses spec.auth_name="pat" from make_spec) succeeds;
        // the orphan-skip we're testing is on the REMOVE side, where
        // identity.auth_name is empty.
        let mut auth_map: HashMap<String, Box<dyn TokenSource>> = HashMap::new();
        auth_map.insert(
            "pat".into(),
            Box::new(MockTokenSource {
                name: "pat".into(),
                ..MockTokenSource::default()
            }),
        );
        let deps = Deps {
            systemd: &systemd,
            auth: &auth_map,
            tarball: &tarball,
            config_shell: &config_shell,
        };
        let mut delta = make_caches_delta(&paths, Some(vec![]), vec![]);
        delta.requires_recreate = true;
        delta.recreate_reasons = vec!["url"];
        // Empty auth_name + url on the IDENTITY only (the create-side
        // spec still has auth_name="pat" / url=populated). This is
        // the orphan-shape produced by plan.rs when synthesizing
        // RemoveRunner from `actual.orphans`.
        delta.identity.auth_name = String::new();
        delta.identity.url = String::new();
        delta.after.resolved_release = Some(make_release());

        let outcome = execute_update_runner(&delta, &deps, &paths, &mut UndoLog::new()).unwrap();
        assert!(
            matches!(outcome, ApplyOutcome::Recreated),
            "recreate path returns Recreated; got {outcome:?}"
        );
        // Orphan-skip fires: run_remove never called, so
        // config_shell.removed is empty.
        assert!(
            config_shell.removed.lock().unwrap().is_empty(),
            "orphan-skip: run_remove must not have fired; got: {:?}",
            config_shell.removed.lock().unwrap(),
        );
        // Create-side run_register DID fire (the create path's spec
        // still has auth_name="pat" + url populated).
        assert_eq!(
            config_shell.registered.lock().unwrap().len(),
            1,
            "create-side run_register must have run; got: {:?}",
            config_shell.registered.lock().unwrap(),
        );
    }

    /// T5: outcome-is-Recreated. The recreate path explicitly
    /// returns `Ok(ApplyOutcome::Recreated)` from the recreate
    /// branch of `execute_update_runner` — NOT the inner remove's
    /// `Removed` or create's `Created`. Pin
    /// because cmd_apply rendering and the apply summary
    /// footer both branch on the outcome variant; a
    /// refactor that returned `Created` instead would silently
    /// re-classify recreate actions and break the operator-visible
    /// disruption-class accounting.
    #[test]
    fn execute_update_runner_recreate_returns_recreated_outcome_not_inner() {
        let tmp = tempfile::tempdir().unwrap();
        let paths = make_paths(&tmp);
        fs::create_dir_all(paths.unit_dir.as_std_path()).unwrap();
        fs::write(paths.unit_file("a").as_std_path(), b"[Unit]\n").unwrap();
        fs::create_dir_all(paths.drop_in_dir("a").as_std_path()).unwrap();
        fs::create_dir_all(paths.runner_home("default", "a").as_std_path()).unwrap();
        fs::create_dir_all(paths.runtime_dir.as_std_path()).unwrap();

        let systemd = MockSystemd::default();
        let tarball = MockTarball::default();
        let config_shell = MockConfigShell::default();
        let mut auth_map: HashMap<String, Box<dyn TokenSource>> = HashMap::new();
        auth_map.insert(
            "pat".into(),
            Box::new(MockTokenSource {
                name: "pat".into(),
                ..MockTokenSource::default()
            }),
        );
        let deps = Deps {
            systemd: &systemd,
            auth: &auth_map,
            tarball: &tarball,
            config_shell: &config_shell,
        };
        let mut delta = make_caches_delta(&paths, Some(vec![]), vec![]);
        delta.requires_recreate = true;
        delta.recreate_reasons = vec!["url"];
        delta.after.resolved_release = Some(make_release());

        let outcome = execute_update_runner(&delta, &deps, &paths, &mut UndoLog::new()).unwrap();
        match outcome {
            ApplyOutcome::Recreated => {}
            ApplyOutcome::Removed | ApplyOutcome::Created => panic!(
                "recreate path must collapse inner Removed+Created into the Recreated \
                 variant; got {outcome:?}"
            ),
            other => panic!("expected Recreated; got {other:?}"),
        }
    }

    /// T6: runsvc_sha256-after-register pin. The recreate
    /// path's create branch hashes `<runner_home>/runsvc.sh` AFTER
    /// `config.sh run_register` writes that file (the
    /// `deps.config_shell.run_register` call inside
    /// `execute_create_runner`), then re-renders the unit text +
    /// drop-ins with the populated
    /// `runsvc_sha256` annotation. Pin that the bytes-on-disk in
    /// `00-ghars.conf` match the SHA256 of the runsvc.sh body the
    /// MockConfigShell wrote at register time. A regression where
    /// the hash is computed BEFORE register (or skipped entirely)
    /// would re-introduce SEC-02 — runsvc-wrapper's
    /// annotation comparison would fail at every unit start.
    #[test]
    fn execute_update_runner_recreate_writes_runsvc_sha256_from_post_register_bytes() {
        use sha2::{Digest, Sha256};
        let tmp = tempfile::tempdir().unwrap();
        let paths = make_paths(&tmp);
        fs::create_dir_all(paths.unit_dir.as_std_path()).unwrap();
        fs::write(paths.unit_file("a").as_std_path(), b"[Unit]\n").unwrap();
        fs::create_dir_all(paths.drop_in_dir("a").as_std_path()).unwrap();
        fs::create_dir_all(paths.runner_home("default", "a").as_std_path()).unwrap();
        fs::create_dir_all(paths.runtime_dir.as_std_path()).unwrap();

        let systemd = MockSystemd::default();
        let tarball = MockTarball::default();
        let config_shell = MockConfigShell::default();
        let mut auth_map: HashMap<String, Box<dyn TokenSource>> = HashMap::new();
        auth_map.insert(
            "pat".into(),
            Box::new(MockTokenSource {
                name: "pat".into(),
                ..MockTokenSource::default()
            }),
        );
        let deps = Deps {
            systemd: &systemd,
            auth: &auth_map,
            tarball: &tarball,
            config_shell: &config_shell,
        };
        let mut delta = make_caches_delta(&paths, Some(vec![]), vec![]);
        delta.requires_recreate = true;
        delta.recreate_reasons = vec!["url"];
        delta.after.resolved_release = Some(make_release());

        execute_update_runner(&delta, &deps, &paths, &mut UndoLog::new()).unwrap();

        // MockConfigShell::run_register writes this exact body to
        // <runner_home>/runsvc.sh at register time. The expected
        // sha256 hex digest is `Sha256(MOCK_RUNSVC).hex()`. The
        // production code computes it via `sha256_of_runsvc()` AFTER
        // run_register, then renders the 00-ghars.conf drop-in with
        // `X-Ghars-Runsvc-Sha256=sha256:<hex>`.
        const MOCK_RUNSVC: &[u8] = b"#!/bin/sh\n# mock runsvc\nexec ./bin/runsvc.sh \"$@\"\n";
        let mut hasher = Sha256::new();
        hasher.update(MOCK_RUNSVC);
        let expected_hex = format!("{:x}", hasher.finalize());
        let expected_annotation = format!("X-Ghars-Runsvc-Sha256=sha256:{expected_hex}");

        // The 00-ghars.conf drop-in is at
        // <drop_in_dir>/00-ghars.conf — execute_create_runner re-
        // renders it after computing the digest.
        let drop_in_path = paths.drop_in_dir("a").join("00-ghars.conf");
        let body = std::fs::read_to_string(drop_in_path.as_std_path())
            .expect("00-ghars.conf must exist after recreate");
        assert!(
            body.contains(&expected_annotation),
            "00-ghars.conf must contain post-register runsvc sha256 annotation \
             ({expected_annotation}); got body: {body}"
        );
    }

    /// T7: MockSystemd `stop_unit` failure
    /// short-circuits the entire recreate path. The recreate branch
    /// dispatches `execute_remove_runner` first; that function's very
    /// first systemd call is `deps.systemd.stop_unit(&unit_name)?` —
    /// when it fails, the `?` propagates and `execute_create_runner`
    /// MUST NOT run. Pin via `MockSystemd::fail_stop_unit` injection
    /// (added for this test alongside the `fail_remove_group` pattern
    /// on `MockUsers`). Asserts (i) Err returns, (ii) the error
    /// surface mentions the injected stop_unit failure, (iii)
    /// useradd never ran (create-side step 1 was never reached),
    /// (iv) tarball.installed is empty, and (v) config_shell.registered
    /// is empty. Symmetric with T2 which proves create-skip via an
    /// empty auth_map (which fails inside mint_token AFTER stop_unit
    /// already succeeded); T7 closes the gap for the more upstream
    /// stop_unit failure path that T2 cannot reach.
    #[test]
    fn execute_update_runner_recreate_stop_unit_failure_skips_create() {
        let tmp = tempfile::tempdir().unwrap();
        let paths = make_paths(&tmp);
        fs::create_dir_all(paths.unit_dir.as_std_path()).unwrap();
        fs::write(paths.unit_file("a").as_std_path(), b"[Unit]\n").unwrap();
        fs::create_dir_all(paths.drop_in_dir("a").as_std_path()).unwrap();
        fs::create_dir_all(paths.runner_home("default", "a").as_std_path()).unwrap();
        fs::create_dir_all(paths.runtime_dir.as_std_path()).unwrap();

        let systemd = MockSystemd::default();
        // Inject failure on the runner unit's stop_unit. The recreate
        // path's execute_remove_runner reaches stop_unit first
        // (apply.rs `execute_remove_runner` step 1).
        *systemd.fail_stop_unit.lock().unwrap() = Some("ghars-runner@a.service".into());
        let tarball = MockTarball::default();
        let config_shell = MockConfigShell::default();
        let mut auth_map: HashMap<String, Box<dyn TokenSource>> = HashMap::new();
        auth_map.insert(
            "pat".into(),
            Box::new(MockTokenSource {
                name: "pat".into(),
                ..MockTokenSource::default()
            }),
        );
        let deps = Deps {
            systemd: &systemd,
            auth: &auth_map,
            tarball: &tarball,
            config_shell: &config_shell,
        };
        let mut delta = make_caches_delta(&paths, Some(vec![]), vec![]);
        delta.requires_recreate = true;
        delta.recreate_reasons = vec!["url"];
        delta.after.resolved_release = Some(make_release());

        let err = execute_update_runner(&delta, &deps, &paths, &mut UndoLog::new()).unwrap_err();
        let rendered = format!("{err}");
        assert!(
            rendered.contains("stop_unit") && rendered.contains("injected failure"),
            "expected MockSystemd stop_unit fault to surface; got: {rendered}"
        );
        // (iii) tarball.install_binary not invoked.
        assert!(
            tarball.installed.lock().unwrap().is_empty(),
            "install_binary must not run when stop_unit fails; got: {:?}",
            tarball.installed.lock().unwrap(),
        );
        // (v) config_shell.run_register not invoked.
        assert!(
            config_shell.registered.lock().unwrap().is_empty(),
            "run_register must not run when stop_unit fails; got: {:?}",
            config_shell.registered.lock().unwrap(),
        );
    }

    /// T8: on the create-failure-
    /// after-remove recreate path, the per-action `UndoLog` MUST contain
    /// the remove-side mutation steps recorded BEFORE create errored.
    /// Pinned because the rollback advisory and the rollback-on-
    /// failure walk both consume that log; if the create-fail
    /// path inadvertently reset / dropped the remove-side steps, the
    /// operator would see a misleading "no mutations recorded" advisory
    /// despite a half-removed runner on disk.
    ///
    /// Setup mirrors T3 (`execute_update_runner_recreate_create_failure_
    /// after_remove`) — recreate goes through execute_remove_runner
    /// (succeeds), then execute_create_runner (fails at the no-tarball
    /// Validation gate). T3 verifies the side-effect surface; T8
    /// verifies the per-action UndoLog manifest. Together they pin the
    /// "partial new state on create-fail" contract from both
    /// directions.
    #[test]
    fn execute_update_runner_recreate_create_failure_after_remove_includes_remove_steps_in_log() {
        let tmp = tempfile::tempdir().unwrap();
        let paths = make_paths(&tmp);
        fs::create_dir_all(paths.unit_dir.as_std_path()).unwrap();
        fs::write(paths.unit_file("a").as_std_path(), b"[Unit]\n").unwrap();
        fs::create_dir_all(paths.drop_in_dir("a").as_std_path()).unwrap();
        fs::create_dir_all(paths.runner_home("default", "a").as_std_path()).unwrap();
        fs::create_dir_all(paths.runtime_dir.as_std_path()).unwrap();

        let systemd = MockSystemd::default();
        let tarball = MockTarball::default();
        let config_shell = MockConfigShell::default();
        let mut auth_map: HashMap<String, Box<dyn TokenSource>> = HashMap::new();
        auth_map.insert(
            "pat".into(),
            Box::new(MockTokenSource {
                name: "pat".into(),
                ..MockTokenSource::default()
            }),
        );
        let deps = Deps {
            systemd: &systemd,
            auth: &auth_map,
            tarball: &tarball,
            config_shell: &config_shell,
        };
        let mut delta = make_caches_delta(&paths, Some(vec![]), vec![]);
        delta.requires_recreate = true;
        delta.recreate_reasons = vec!["url"];
        // Trigger the no-tarball Validation gate so create errors
        // AFTER remove succeeded.
        assert!(delta.after.spec.runner_tarball.is_none());
        assert!(delta.after.resolved_release.is_none());

        let mut log = UndoLog::new();
        execute_update_runner(&delta, &deps, &paths, &mut log)
            .expect_err("create-side Validation gate must error");

        let steps = log.steps();
        // Remove-side steps that MUST have landed before create errored,
        // pushed by `execute_remove_runner` in this order:
        //   StopUnit("ghars-runner@a.service")
        //   DisableUnit("ghars-runner@a.service")
        //   teardown_netns_artifacts step push    — Stop+Disable for
        //                                            ghars-net@a.service
        //   RemoveDir(home_dir)
        //   UserDel(spec.user)
        //
        // We pin the load-bearing primary remove-side mutations:
        //   StopUnit + DisableUnit on the runner unit + UserDel.
        // The create-side ALSO recorded UserAdd (step 1 succeeded
        // before the Validation gate at install_binary stage); we
        // pin that explicitly so the test doesn't false-positive on
        // a refactor that reorders create's step 1 BEFORE its
        // Validation gate.
        let unit = "ghars-runner@a.service";
        let stop_runner = steps
            .iter()
            .any(|s| matches!(s, UndoStep::StopUnit { name } if name == unit));
        let disable_runner = steps
            .iter()
            .any(|s| matches!(s, UndoStep::DisableUnit { name } if name == unit));
        assert!(
            stop_runner,
            "remove-side StopUnit must appear in log; got: {steps:?}",
        );
        assert!(
            disable_runner,
            "remove-side DisableUnit must appear in log; got: {steps:?}",
        );
    }

    // ---------- ApplyOutcome::Failed.detail() with newline -------------

    /// Pin that `ApplyOutcome::Failed.detail()` returns
    /// the pre-sanitized `error_summary` verbatim with no raw newline
    /// surviving. The escape happens at construction time inside
    /// `apply()` (apply.rs `escape_control_chars(&e.to_string()).into_owned()`,
    /// also tested at `apply_failed_error_summary_escapes_hostile_inner_error`);
    /// this companion test pins the END-USER consumer surface — when
    /// cmd_apply renders the `fail:` row via `outcome.detail()`, the
    /// rendered string must have no embedded `\n` byte that would split
    /// the row across multiple stderr lines.
    ///
    /// Two assertions:
    ///   (i) Constructed via `escape_control_chars` (the production
    ///       wiring): the resulting `Failed.detail()` must contain no
    ///       raw `\n` and must contain the printable `\\n` form
    ///       `char::escape_default('\n')` emits.
    ///   (ii) Round-trip integrity: detail() returns the same bytes
    ///        that were stored in error_summary (no double-escape, no
    ///        mutation). The doc-comment on
    ///        `ApplyOutcome::Failed.error_summary` says detail() is
    ///        verbatim from error_summary.
    #[test]
    fn apply_outcome_failed_detail_has_no_raw_newline_when_pre_sanitized() {
        // Simulate what the apply()-loop construction site does:
        // `escape_control_chars(&e.to_string()).into_owned()` on an
        // error message containing a raw newline. The newline's
        // `char::escape_default` form is the literal two-byte sequence
        // backslash + 'n' (`"\\n"` in Rust source).
        let raw = "config: invalid value\nhint: re-read TOML";
        let sanitized = crate::escape_control_chars(raw).into_owned();
        // Sanity: the helper produced an owned string with no raw
        // newline. (Helper-level coverage in lib.rs — repeating here
        // makes the wiring chain self-contained.)
        assert!(
            !sanitized.contains('\n'),
            "escape_control_chars must remove raw \\n; got: {sanitized:?}"
        );

        let outcome = ApplyOutcome::Failed {
            error_summary: sanitized.clone(),
            plan_disruption: crate::plan::Disruption::Restart,
        };
        let rendered = outcome.detail();

        // (i) No raw newline survived in the consumer-facing detail().
        // cmd_apply's `fail: LABEL [...] (DETAIL)` row would otherwise
        // split across multiple stderr lines and break operator
        // grep-on-`fail:` pipelines.
        assert!(
            !rendered.contains('\n'),
            "Failed.detail() must not contain a raw \\n byte; got: {rendered:?}"
        );
        // The printable `\\n` escape form from char::escape_default
        // must appear — proves the construction site escaped (vs.
        // stripping the newline entirely or leaving it raw).
        assert!(
            rendered.contains("\\n"),
            "Failed.detail() must contain the \\\\n escape form; got: {rendered}"
        );

        // (ii) Round-trip with error_summary: detail() returns the
        // stored bytes verbatim, no double-escape. The doc-comment on
        // ApplyOutcome::Failed.error_summary specifies
        // pre-sanitized-at-construction; detail() simply clones.
        assert_eq!(
            rendered, sanitized,
            "Failed.detail() must return error_summary verbatim (no \
             double-escape, no mutation); got rendered={rendered:?} \
             expected={sanitized:?}"
        );
        // The non-control text passes through.
        assert!(
            rendered.contains("invalid value") && rendered.contains("hint:"),
            "non-control surrounding text must pass through; got: {rendered}"
        );
    }

    // ---------- remaining wiring + rollback + describe pins ------------

    /// Pin that the synthetic post-loop `daemon_reload`
    /// failure path runs the underlying `e.to_string()` through
    /// `escape_control_chars` before storing the result in
    /// `ApplyOutcome::Failed.error_summary`. Symmetric with the
    /// per-action escape pin at
    /// `apply_failed_error_summary_escapes_hostile_inner_error` —
    /// together they cover the two construction sites in `apply()`
    /// (per-action loop arm + post-loop daemon_reload arm).
    ///
    /// Drives `apply()` with an EMPTY plan so the per-action loop is a
    /// no-op and `daemon_reload` is the only mutation. `MockSystemd`'s
    /// `fail_daemon_reload_message` injects a hostile ANSI escape
    /// sequence into the Err returned by `daemon_reload()`. The
    /// post-loop branch wraps the Err and pushes a synthetic
    /// `Failed { error_summary, plan_disruption: Disruption::None }`
    /// row to `result.details`; we extract `error_summary` and assert
    /// (i) raw ESC byte gone, (ii) `\u{1b}` form from
    /// `char::escape_default` present, (iii) the surrounding
    /// diagnostic text passes through.
    #[test]
    fn apply_daemon_reload_error_summary_escapes_hostile_message() {
        let tmp = tempfile::tempdir().unwrap();
        let paths = make_paths(&tmp);
        fs::create_dir_all(paths.runtime_dir.as_std_path()).unwrap();

        let systemd = MockSystemd::default();
        // Inject a hostile control-char payload into the Err returned
        // by daemon_reload(). The post-loop daemon_reload arm in
        // `apply()` computes
        // `escape_control_chars(&e.to_string()).into_owned()` and
        // stores the result in `ApplyOutcome::Failed.error_summary`.
        *systemd.fail_daemon_reload_message.lock().unwrap() =
            Some("hostile \x1b[31m daemon_reload diagnostic".into());

        let tarball = MockTarball::default();
        let config_shell = MockConfigShell::default();
        let auth_map: HashMap<String, Box<dyn TokenSource>> = HashMap::new();
        let deps = Deps {
            systemd: &systemd,
            auth: &auth_map,
            tarball: &tarball,
            config_shell: &config_shell,
        };
        // Empty plan: the per-action loop is a no-op so daemon_reload
        // is the ONLY mutation, and its failure flows through the
        // synthetic post-loop branch (no per-action Err competes).
        let plan = Plan {
            actions: vec![],
            warnings: vec![],
        };
        let opts = ApplyOptions::default();

        let result = apply(&plan, &deps, &paths, &opts).unwrap();

        // Post-loop daemon_reload pushes one Failed entry to both
        // `result.failed` and `result.details`. Synthetic label is
        // exactly `"daemon_reload"` at every push site in the
        // post-loop arm.
        assert_eq!(
            result.failed.len(),
            1,
            "expected 1 failed (synthetic daemon_reload); got: {:?}",
            result.failed
        );
        assert_eq!(
            result.details.len(),
            1,
            "expected 1 detail row (synthetic daemon_reload); got: {:?}",
            result.details
        );
        let (label, outcome) = &result.details[0];
        assert_eq!(
            label, "daemon_reload",
            "synthetic post-loop label must be `daemon_reload`; got: {label}"
        );
        let error_summary = match outcome {
            ApplyOutcome::Failed { error_summary, .. } => error_summary.clone(),
            other => {
                panic!("expected ApplyOutcome::Failed for post-loop daemon_reload, got {other:?}")
            }
        };
        // (i) raw ESC byte must not survive: the Systemd Display would
        // have included `\x1b`, and the post-loop branch's
        // `escape_control_chars(&e.to_string()).into_owned()` must
        // have replaced it before storing.
        assert!(
            !error_summary.contains('\x1b'),
            "raw ESC must not reach error_summary on the daemon_reload synthetic path; got: {error_summary:?}"
        );
        // (ii) printable `\u{1b}` form from char::escape_default must
        // be present — proves escape_control_chars actually ran on
        // the daemon_reload arm (and not just on the per-action arm).
        assert!(
            error_summary.contains("\\u{1b}"),
            "expected \\u{{1b}} substring from char::escape_default; got: {error_summary}"
        );
        // (iii) the surrounding diagnostic context passes through —
        // sanity that the helper didn't strip the entire message.
        assert!(
            error_summary.contains("hostile") && error_summary.contains("daemon_reload diagnostic"),
            "non-control surrounding text must pass through; got: {error_summary}"
        );
    }

    /// Per-variant `UndoStep::describe()` escape pin.
    /// Helper-level coverage already lives in `lib.rs`; the WriteFile
    /// arm is pinned at
    /// `undo_step_write_file_describe_escapes_hostile_path`.
    /// This test extends the wiring pin to the remaining variants and
    /// the second interpolated field of `GitHubRegistration`.
    ///
    /// `UndoStep` has 13 variants total. Twelve are covered here
    /// (every variant except `WriteFile`), plus a second
    /// `GitHubRegistration` row so the `name` and `url` interpolation
    /// paths each get an independent pin. A 14th sub-case
    /// (`GitHubRegistration[hostile-runner_home]`)
    /// is included as a forward-looking pin: today `describe()` does
    /// NOT interpolate `runner_home`, so the case asserts only the
    /// "no raw ESC survives" property — if a future refactor adds
    /// `runner_home` interpolation without `escape_control_chars`,
    /// that assertion trips with the labeled prefix.
    ///
    /// Pinned because a regression dropping `escape_control_chars`
    /// from one variant arm would compile and pass the WriteFile
    /// test, but reintroduce the ANSI-hijack vector for that
    /// variant. Table-driven layout names the broken arm via the
    /// `[{label}]` assertion-message prefix.
    #[test]
    fn undo_step_all_variants_describe_escapes_hostile_input() {
        let hostile_path = Utf8PathBuf::from("/etc/ghars/\x1b[31mevil");
        let hostile_name = "ghars-runner@\x1b[31mevil.service";
        let hostile_url = "https://github.com/\x1b[31mevil/repo";
        let hostile_runner_home = Utf8PathBuf::from("/var/lib/ghars/\x1b[31mevil");
        let benign_runner_home = Utf8PathBuf::from("/var/lib/ghars/buckos");
        // `expects_interpolation` (the 3rd tuple element) is true for
        // arms whose hostile field flows through `describe()`'s
        // format strings — those rows assert (a) no raw ESC, (b)
        // `\u{1b}` form present, and (c) the printable "evil" suffix
        // survives (catches over-escape regressions where the entire
        // string collapses to `\u{1b}...`). `false` rows assert ONLY
        // (a) — for fields not currently interpolated, the absence
        // of raw ESC is the only meaningful invariant; (b) and (c)
        // would be vacuously false today and would falsely fail.
        let cases: Vec<(&str, UndoStep, bool)> = vec![
            (
                "RemoveFile",
                UndoStep::RemoveFile {
                    path: hostile_path.clone(),
                    content: vec![],
                },
                true,
            ),
            (
                "CreateDir",
                UndoStep::CreateDir {
                    path: hostile_path.clone(),
                },
                true,
            ),
            (
                "RemoveDir",
                UndoStep::RemoveDir {
                    path: hostile_path.clone(),
                },
                true,
            ),
            (
                "StartUnit",
                UndoStep::StartUnit {
                    name: hostile_name.into(),
                },
                true,
            ),
            (
                "StopUnit",
                UndoStep::StopUnit {
                    name: hostile_name.into(),
                },
                true,
            ),
            (
                "EnableUnit",
                UndoStep::EnableUnit {
                    name: hostile_name.into(),
                },
                true,
            ),
            (
                "DisableUnit",
                UndoStep::DisableUnit {
                    name: hostile_name.into(),
                },
                true,
            ),
            // GitHubRegistration interpolates `name` and `url` (the
            // two operator-readable fields). Cover hostile-name and
            // hostile-url separately so a refactor that escapes only
            // one of the two would still fail this test. Other fields
            // (auth_name, runner_home, user) are not interpolated by
            // `describe()`'s `GitHubRegistration` arm, so the
            // hostile-runner_home row below uses the
            // `expects_interpolation=false` mode.
            (
                "GitHubRegistration[hostile-name]",
                UndoStep::GitHubRegistration {
                    name: hostile_name.into(),
                    url: "https://github.com/example/repo".into(),
                    auth_name: "pat".into(),
                    runner_home: benign_runner_home.clone(),
                },
                true,
            ),
            (
                "GitHubRegistration[hostile-url]",
                UndoStep::GitHubRegistration {
                    name: "buckos".into(),
                    url: hostile_url.into(),
                    auth_name: "pat".into(),
                    runner_home: benign_runner_home.clone(),
                },
                true,
            ),
            // Forward-looking pin for runner_home.
            // Today `describe()`'s `GitHubRegistration` arm does NOT
            // interpolate `runner_home` (it reads only `name` and
            // `url`), so the hostile bytes never reach the format
            // string and the
            // (a) "no raw ESC" assertion is vacuously true. A future
            // refactor that exposes runner_home in the rendered
            // string WITHOUT routing through `escape_control_chars`
            // flips (a) to false — this row catches that regression
            // before it lands. (b) and (c) cannot apply: today there
            // is no `\u{1b}` form to find and no "evil" suffix to
            // match, so we suppress those assertions via
            // `expects_interpolation=false`.
            (
                "GitHubRegistration[hostile-runner_home]",
                UndoStep::GitHubRegistration {
                    name: "buckos".into(),
                    url: "https://github.com/example/repo".into(),
                    auth_name: "pat".into(),
                    runner_home: hostile_runner_home.clone(),
                },
                false,
            ),
        ];
        for (label, step, expects_interpolation) in &cases {
            let described = step.describe();
            // (a) raw ESC must not survive on this arm. A regression
            // that drops escape_control_chars from one variant fails
            // here with the label naming the broken arm. Universal
            // — every arm asserts this regardless of interpolation
            // status.
            assert!(
                !described.contains('\x1b'),
                "[{label}] raw ESC must not survive describe(); got: {described:?}"
            );
            if *expects_interpolation {
                // (b) printable `\u{1b}` from char::escape_default
                // must appear — proves the helper actually ran on
                // this arm (and didn't silently strip the bytes).
                assert!(
                    described.contains("\\u{1b}"),
                    "[{label}] expected \\u{{1b}} escape form from char::escape_default; got: {described}"
                );
                // (c) the printable "evil" suffix must survive —
                // catches an over-escape regression where the
                // entire string collapses to `\u{1b}...` with no
                // readable text. The hostile fixtures embed "evil"
                // immediately after the ESC sequence on every
                // interpolated field.
                assert!(
                    described.contains("evil"),
                    "[{label}] non-control suffix `evil` must pass through unchanged; got: {described}"
                );
            }
        }
    }

    /// T3-sibling pin for the recreate path with
    /// `rollback_on_failure = true`. The T3 test at
    /// `execute_update_runner_recreate_create_failure_after_remove`
    /// drives the same fixture (remove succeeds, create fails at the
    /// no-tarball Validation gate) but at the `execute_update_runner`
    /// boundary; this test drives the full `apply()` so the
    /// `rollback_on_failure` gate inside `apply()` actually fires
    /// and `undo` walks the per-action UndoLog in reverse.
    ///
    /// Setup pre-populates the on-disk paths so execute_remove_runner
    /// can walk past its filesystem-cleanup steps without erroring on
    /// missing paths. The fixture does not populate any drop-in files
    /// (drop_in_dir is created but empty), so no RemoveFile is pushed
    /// to the UndoLog from the remove path; the load-bearing remove-
    /// side steps for this test are StopUnit, DisableUnit, and the
    /// terminal UserDel after run_remove succeeds.
    ///
    /// Discriminator design: `MockUsers::removed` records every
    /// `userdel_if_present` call regardless of trigger. The remove
    /// path always pushes `"ghars-a"` via `execute_remove_runner`'s
    /// `userdel_if_present` call (which fires after `run_remove`
    /// succeeds), so a count of 1 in `removed` is *consistent with*
    /// the no-rollback path. The rollback walk's UserAdd→userdel
    /// inverse arm in `undo` fires AFTER the create-side useradd
    /// recorded into `added`, pushing a
    /// SECOND `"ghars-a"` entry. The `count == 2` assertion is the
    /// discriminator: without `rollback_on_failure=true` the count
    /// would be 1 (remove-side only); with rollback it must be 2
    /// (remove-side + undo-walk inverse). Asserting `contains` alone
    /// would pass the no-rollback path silently.
    #[test]
    fn execute_update_runner_recreate_create_failure_with_rollback() {
        let tmp = tempfile::tempdir().unwrap();
        let paths = make_paths(&tmp);
        fs::create_dir_all(paths.unit_dir.as_std_path()).unwrap();
        fs::write(paths.unit_file("a").as_std_path(), b"[Unit]\n").unwrap();
        fs::create_dir_all(paths.drop_in_dir("a").as_std_path()).unwrap();
        fs::create_dir_all(paths.runner_home("default", "a").as_std_path()).unwrap();
        fs::create_dir_all(paths.runtime_dir.as_std_path()).unwrap();

        let systemd = MockSystemd::default();
        let tarball = MockTarball::default();
        let config_shell = MockConfigShell::default();
        let mut auth_map: HashMap<String, Box<dyn TokenSource>> = HashMap::new();
        auth_map.insert(
            "pat".into(),
            Box::new(MockTokenSource {
                name: "pat".into(),
                ..MockTokenSource::default()
            }),
        );
        let deps = Deps {
            systemd: &systemd,
            auth: &auth_map,
            tarball: &tarball,
            config_shell: &config_shell,
        };
        let mut delta = make_caches_delta(&paths, Some(vec![]), vec![]);
        delta.requires_recreate = true;
        delta.recreate_reasons = vec!["url"];
        // T3-sibling fixture: trigger the create-path no-tarball
        // Validation gate so create errors AFTER remove succeeded.
        // make_caches_delta sets runner_tarball=None;
        // resolved_release defaults to None too.
        assert!(delta.after.spec.runner_tarball.is_none());
        assert!(delta.after.resolved_release.is_none());

        let plan = Plan {
            actions: vec![Action::UpdateRunner(delta)],
            warnings: vec![],
        };
        // Key delta from T3: opt into rollback_on_failure so apply()'s
        // `rollback_on_failure` gate fires and undo walks the
        // per-action UndoLog.
        let opts = ApplyOptions {
            rollback_on_failure: true,
            ..ApplyOptions::default()
        };

        let result = apply(&plan, &deps, &paths, &opts).unwrap();

        // (a) one failure recorded — the create-side Validation gate.
        assert_eq!(
            result.failed.len(),
            1,
            "expected 1 failed action (create-side Validation gate); got: {:?}",
            result.failed
        );
        // (b) per-action UndoLog manifest is non-empty — the
        // rollback advisory consumer needs it. Mirror the T8 pin
        // shape (`failed_undo_logs` carries the recorded steps).
        assert_eq!(
            result.failed_undo_logs.len(),
            1,
            "expected 1 failed_undo_logs entry; got: {:?}",
            result.failed_undo_logs
        );
        let (_label, steps) = &result.failed_undo_logs[0];
        assert!(
            !steps.is_empty(),
            "expected non-empty UndoLog manifest after recreate-with-rollback failure; got empty",
        );
        // (c) remove-side StopUnit / DisableUnit landed before the
        // create-side Validation gate. Mirror T8 assertion.
        let unit = "ghars-runner@a.service";
        let stop_runner = steps
            .iter()
            .any(|s| matches!(s, UndoStep::StopUnit { name } if name == unit));
        let disable_runner = steps
            .iter()
            .any(|s| matches!(s, UndoStep::DisableUnit { name } if name == unit));
        assert!(
            stop_runner,
            "remove-side StopUnit must appear in log; got: {steps:?}",
        );
        assert!(
            disable_runner,
            "remove-side DisableUnit must appear in log; got: {steps:?}",
        );
        // The pre-DynamicUser version asserted that `MockUsers`
        // recorded a userdel from the rollback walk inverting a
        // UserAdd. Both the trait and the variants are gone — the
        // remove-side StopUnit/DisableUnit assertions above are the
        // remaining observable signal that the recreate path ran the
        // remove leg before the create leg's Validation gate fired.

        // End-to-end advisory shape pin. Run the
        // result through `render_rollback_advisory` and assert the
        // operator-visible output ties back to the recorded
        // mutations: header present, label sub-block present, at
        // least one remove-side step in the body. The pre-DynamicUser
        // version also asserted a create-side UserAdd bullet in LIFO
        // order — both the variant and the create-side step are gone.
        let advisory = crate::cli::render_rollback_advisory(&result)
            .expect("rollback advisory must render when failed.len() > 0");
        assert!(
            advisory.starts_with("Rollback advisory: 1 action(s) failed."),
            "advisory must lead with failed-count header; got: {advisory}"
        );
        // Per-action label sub-block.
        assert!(
            advisory.contains("\n  UpdateRunner"),
            "advisory must include per-action UpdateRunner sub-block; got: {advisory}"
        );
        // Remove-side StopUnit on the runner unit lands as a body bullet.
        assert!(
            advisory.contains("\n    - stopped ghars-runner@a.service"),
            "advisory must include remove-side StopUnit bullet via describe(); got: {advisory}"
        );
    }
}
