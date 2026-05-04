//! Top-level [`apply`] entry point + [`execute`] action dispatcher.

use crate::Result;
use crate::error::GharsError;
use crate::escape_control_chars;
use crate::paths::Paths;
use crate::plan::{Action, Plan};

use super::audit::write_audit_log_entry;
use super::gc::{gc_stale_staging_dirs, gc_stale_temp_files};
use super::lock::acquire_lock;
use super::outcome::{ApplyOptions, ApplyOutcome, ApplyResult};
use super::phases::sort_into_phases;
use super::pools::{
    execute_create_cache_pool, execute_remove_cache_pool, execute_update_cache_pool,
};
use super::runners::{execute_create_runner, execute_remove_runner, execute_update_runner};
use super::undo::{Deps, UndoLog, undo};

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
        match execute(&action, deps, paths, &mut log, plan.keep_versions) {
            Ok(outcome) => {
                // SEC-36 audit log entry — emitted per-action AFTER
                // the side effects have landed but BEFORE the
                // per-action result row is recorded, so the audit
                // trail is durable on disk even if the host crashes
                // before the in-process Vec is observed by the
                // caller. Audit writes are best-effort: a failure
                // here MUST NOT propagate (would override a
                // successful action with a logging failure). The
                // outcome string is the variant's `audit_summary()`
                // (terse, control-char-safe).
                write_audit_log_entry(paths, &label, &outcome.audit_summary());
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
                // SEC-36 audit log entry — failure path. The
                // `outcome` field carries the control-char-safe
                // error display so downstream consumers (jq
                // pipelines, ELK ingestion) see exactly the same
                // diagnostic the operator saw on stderr. Best-
                // effort: a logging failure must not change the
                // failure-handling path below.
                write_audit_log_entry(paths, &label, &error_summary);
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

/// Execute one [`Action`] against the host.
///
/// Pure dispatch — every variant routes to a per-action handler.
/// Errors here are returned bare; [`apply`] is responsible for
/// wrapping them in `GharsError::Apply { action, source }` so the
/// action label is preserved exactly once at the call boundary.
///
/// `log` accumulates [`super::undo::UndoStep`] entries that the handler pushes after
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
    keep_versions: u32,
) -> Result<ApplyOutcome> {
    match action {
        Action::CreateRunner(p) => execute_create_runner(p, deps, paths, log, keep_versions),
        Action::UpdateRunner(d) => execute_update_runner(d, deps, paths, log, keep_versions),
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
