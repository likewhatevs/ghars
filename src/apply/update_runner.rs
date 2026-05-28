//! `execute_update_runner` — in-place + recreate paths for the
//! `UpdateRunner` action. Split out of `runners.rs` to keep that
//! file under the maintainability threshold; helpers shared with
//! `execute_create_runner` / `execute_remove_runner` remain there.

use std::fs;

use crate::Result;
use crate::config::NetworkMode;
use crate::error::GharsError;
use crate::paths::Paths;
use crate::plan::{DropInChangeKind, RunnerDelta};
use crate::state::MANAGED_DROP_IN_BASENAMES;

use super::netns::verify_runner_netns;
use super::outcome::ApplyOutcome;
use super::runners::{
    chmod_record_undo, execute_create_runner, execute_remove_runner, restore_operator_drop_ins,
    snapshot_operator_drop_ins, write_env_path_files,
};
use super::undo::{Deps, UndoLog, UndoStep};
use super::writes::{read_prior, read_then_write_if_changed};
use std::os::unix::fs::PermissionsExt;

pub(super) fn execute_update_runner(
    delta: &RunnerDelta,
    deps: &Deps<'_>,
    paths: &Paths,
    log: &mut UndoLog,
    keep_versions: u32,
    no_restart: bool,
) -> Result<ApplyOutcome> {
    if delta.requires_recreate {
        // Recreate path: stop + remove + create. The plan emits this
        // when an identity-bound field changed (`url`, `runner_version`,
        // `labels`, `arch`, `runner_sha256`, `runner_tarball`, `network`).
        //
        // The undo log threading here propagates BOTH inner calls'
        // pushes. If create fails partway, undo walks: create's pushes
        // (reverse, lossless), then remove's pushes (reverse-direction
        // variants → warn-and-skip per design). Net effect on
        // recreate-rollback: the partial new state is unwound; the old
        // state stays gone (genuinely lossy — re-running apply is the
        // recovery path).
        //
        // Collapse the inner `Removed` + `Created` outcomes into
        // a single `Recreated` — the user-facing contract is one row
        // per `Action`, and the inner remove+create are
        // implementation detail of the recreate path.
        // Snapshot operator-territory drop-ins (basenames NOT in
        // `MANAGED_DROP_IN_BASENAMES` — typically `99-*.conf` from
        // `systemctl edit`) BEFORE `execute_remove_runner` wipes
        // `drop_in_dir` via `fs::remove_dir_all`.
        // Without this snapshot, the operator's override file
        // vanishes on remove and never comes back on create
        // (`execute_create_runner` only emits managed basenames).
        // Operators reporting "my `systemctl edit` override
        // disappeared after a `runner_version` bump" hit this class.
        //
        // The snapshot reads file bodies into memory before the
        // wipe; the restore re-writes them post-create with the
        // same byte content + ownership via `write_record_undo`,
        // so the recreate cascade preserves operator overrides
        // end-to-end. In-place updates already preserve them via
        // the `MANAGED_DROP_IN_BASENAMES` guard at the deletion
        // loop in `execute_update_runner` (covered by
        // `update_runner_in_place_preserves_operator_drop_ins`).
        let recreate_drop_in_dir = paths.drop_in_dir(&delta.identity.name);
        let operator_drop_ins = snapshot_operator_drop_ins(&recreate_drop_in_dir);
        execute_remove_runner(&delta.identity, deps, paths, log)?;
        execute_create_runner(&delta.after, deps, paths, log, keep_versions)?;
        restore_operator_drop_ins(&recreate_drop_in_dir, &operator_drop_ins, log)?;
        return Ok(ApplyOutcome::Recreated);
    }

    // In-place path: rewrite drop-ins (template body unchanged because
    // it is identical across runners) and let the next `daemon-reload`
    // pick them up. Restart only when a `[Service]`-section value changed
    // — `RunnerDelta` does not yet distinguish `[Service]` from `[Unit]`
    // drift, so to avoid spurious restarts we skip the `daemon-reload` +
    // stop + start when (a) every managed file's on-disk bytes match
    // what we would render and (b) the caches-list diff is empty.
    // The byte comparison reuses `read_prior` snapshots that were
    // already needed for rollback.
    // Track `files_changed` (count) and pool names
    // (Vec) so the apply outcome row can carry both `files_changed`
    // and the WHICH-pools detail for `cmd_apply`'s per-action line.
    // The `is_empty()` checks at the `daemon-reload` gate below
    // preserve the short-circuit semantics ("skip rewrite when bytes
    // match"): the gate fires iff `files_changed == 0` AND both
    // pool Vecs are empty. The public-detail "group op(s)" count
    // is `pools_added.len() + pools_removed.len()` at render time
    // — operator-visible vocabulary is retained for compatibility
    // with existing log scrapes; no system-level group operation
    // is dispatched.
    let mut files_changed: usize = 0;
    let mut pools_added: Vec<String> = Vec::new();
    let mut pools_removed: Vec<String> = Vec::new();

    // Compute the caches-list diff for the operator-facing
    // "added: …; removed: …" detail string.
    //
    // No system-level group reconciliation runs here. Cache reach
    // is materialized by socket-DAC + `BindPaths` under `DynamicUser`
    // (cache server runs at the same `trust_zone` `DynamicUser` as the
    // runner), not by `/etc/group` membership. The set diff below
    // captures `pools_added` / `pools_removed` purely for the
    // detail surface ("runner X gained pool Y / lost pool Z");
    // the runner unit's `30-cache-pool.conf` drop-in (re-rendered
    // below) carries the `BindPaths` entries that actually grant
    // pool access.
    //
    // The diff is computed from the discovered `X-Ghars-Caches`
    // annotation (`delta.before_caches`) against the desired
    // post-update binding list (`delta.after.spec.caches`). When
    // the discovered annotation is absent (`None`) — pre-annotation
    // runner or operator-stripped `00-ghars.conf` — we skip the diff
    // entirely rather than guess at the prior membership; the next
    // apply will land annotations and a future caches-list edit
    // can reconcile from a known baseline.
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
        // Sort by collecting into `BTreeSet` first so the operations
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

    // Write managed unit text (this block) and drop-ins (loop
    // further down). The `00-ghars.conf` `X-Ghars-Caches` annotation
    // lives in the drop-in body written by the `for (name, body)
    // in &delta.after.drop_ins` loop, NOT in the systemd template
    // body written here.
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
        // `CreateDir` is itself a filesystem mutation — count it as a
        // change so the `daemon-reload` + restart still fires the first
        // time we plant a runner's drop-in directory, even on a runner
        // whose drop-in basenames all happen to byte-match a prior
        // hand-edit (vanishingly unlikely but cheap to be correct).
        files_changed += 1;
    }
    // Remove ghars-managed drop-ins flagged `DropInChangeKind::Removed`
    // by Stage 2 (rendered side has no entry, on-disk side does).
    // Stage 2 walks the union of rendered + discovered keys, so
    // operator-edited `99-*.conf` and any other non-managed name CAN
    // appear here as `Removed` entries. The `MANAGED_DROP_IN_BASENAMES`
    // guard below is the load-bearing safety mechanism that keeps
    // `systemctl edit` overrides intact: we only delete basenames
    // ghars itself would emit. Anything else is operator territory
    // and is left untouched, even when Stage 2 classifies it as
    // `Removed`.
    for change in &delta.drop_in_changes {
        if let DropInChangeKind::Removed { .. } = &change.change {
            if !MANAGED_DROP_IN_BASENAMES.contains(&change.basename.as_str()) {
                continue;
            }
            let path = drop_in_dir.join(&change.basename);
            let prior = read_prior(&path);
            // Differentiate "file is missing" (`ENOENT` — already
            // removed, treat as no-op success) from any other I/O
            // failure (`EACCES` on read-only mount, `EBUSY` on a held
            // descriptor, `EROFS`, etc. — the file is still present
            // and the convergence target was NOT reached). The
            // pre-fix `is_ok()` collapsed every `Err` into a silent
            // skip, so a real `EACCES` would let `apply` claim
            // success while leaving the stale drop-in on disk.
            match fs::remove_file(path.as_std_path()) {
                Ok(()) => {
                    if let Some(content) = prior {
                        log.push(UndoStep::RemoveFile { path, content });
                    }
                    files_changed += 1;
                }
                Err(e) if e.kind() == std::io::ErrorKind::NotFound => {
                    // Already gone — operator concurrently removed
                    // or Stage 2 saw a race. Convergence target is
                    // satisfied, no `UndoStep` to push (nothing to
                    // restore), no `files_changed` bump (we did NOT
                    // mutate disk this apply).
                }
                Err(e) => return Err(GharsError::Io(e)),
            }
        }
    }
    // Write each desired drop-in. `read_then_write_if_changed` snapshots
    // the on-disk prior and short-circuits when the bytes already match
    // The `Preserved` Stage 2 verdict is not used as an
    // optimization here: it is plan-time, and on-disk bytes can drift
    // between plan and apply (e.g. operator edit landed after `ghars
    // plan` rendered output). Trusting `Preserved` would preserve that
    // drift instead of converging — the byte comparison inside
    // `read_then_write_if_changed` is the authoritative check and runs
    // every time.
    for (name, body) in &delta.after.drop_ins {
        let dest = drop_in_dir.join(name);
        if read_then_write_if_changed(&dest, body.as_bytes(), log)? {
            files_changed += 1;
        }
    }

    // Materialize the trust-zone-shared `.ccache` dir if the
    // in-place update ADDED a ccache binding (or refreshed an existing
    // one). Without this, an operator who edits a no-cache runner to
    // add `caches = ["build"]` (a ccache pool) gets the new drop-in
    // body + `.env` emission (`CCACHE_DIR=/var/lib/ghars/<TZ>/.ccache`,
    // gated on `has_ccache` in `render_runner_env_file`) but the dir on
    // disk was never created — workflow steps' ccache wrappers would
    // try to write to a non-existent path. The `if !exists()` gate
    // around the create + chmod is load-bearing (not redundant
    // idempotency): a pre-existing `.ccache` from a sibling runner's
    // prior `CreateRunner` apply was already chowned + tightened to
    // 0o770 by `chown_and_tighten_runner_state`; re-chmodding to
    // 0o777 here would mode-thrash the sibling's post-`StartUnit`
    // tightening and re-widen world access on a shared dir that
    // another running runner is reading. Regression-pinned at
    // `caches_tests::execute_update_runner_in_place_populates_pool_name_vecs`
    // (pre-stages 0o770, asserts mode stays 0o770 after this block).
    // The reverse direction (removing the last ccache binding) leaves
    // a stale empty dir; harmless (no env var points at it anymore
    // once the renderer's `has_ccache` gate drops the emission) and
    // avoids cross-runner racy rmdir (another runner in the same
    // `trust_zone` may still need the dir).
    //
    // KNOWN GAP: the freshly-created `.ccache` here stays root-owned
    // at 0o777 because `execute_update_runner` does NOT call
    // `chown_and_tighten_runner_state` post-`StartUnit` (only
    // `execute_create_runner` does, at the
    // `chown_and_tighten_runner_state` call site in
    // `execute_create_runner`).
    // The dir is functionally writable by the `DynamicUser` via the
    // world bit, but the ownership posture diverges from the
    // `CreateRunner` path (which produces DynamicUser-owned 0o770).
    // Self-heals on the next `CreateRunner` in the same `trust_zone`.
    let after_has_ccache = delta
        .after
        .spec
        .caches
        .iter()
        .any(|b| b.kinds.contains(&crate::config::CacheKind::Ccache));
    if after_has_ccache {
        let tz_dir_inplace = paths.state_dir.join(&delta.identity.trust_zone);
        let ccache_dir_inplace = tz_dir_inplace.join(".ccache");
        if !ccache_dir_inplace.as_std_path().exists() {
            fs::create_dir_all(ccache_dir_inplace.as_std_path())?;
            chmod_record_undo(&ccache_dir_inplace, 0o777, ".ccache (in-place)", log)?;
        }
    }

    // Rewrite `.env` and `.path`. `CreateRunner` writes them once, but
    // in-place updates that change env-affecting fields (cache binding
    // flip, future operator-declared env vars) would otherwise leave
    // the systemd `Environment=` directives (rewritten in the drop-in
    // loop above; LAYER 1, reaches the `Runner.Listener` process) and
    // the workflow-step env (via `Runner.Listener`'s `LoadAndSetEnv` at
    // process start, which reads `.env` once; LAYER 2) out of sync.
    //
    // The pure-function producers `render_runner_env_file` and
    // `render_runner_path_file` consume only `EffectiveRunnerSpec`
    // fields (no `runner_version`), so the bytes here are byte-identical
    // to what `CreateRunner` wrote for the same spec. The byte-compare
    // in `read_then_write_if_changed` makes this a no-op when nothing
    // changed.
    //
    // `bin_dir` is computed from `delta.after.spec.runner_version`
    // directly rather than `find_active_bin_dir`'s mtime sort: in-place
    // updates never change `runner_version` (that's a recreate-class
    // field), so the running runner's bin dir matches the desired
    // spec's version. An empty `runner_version` here means plan emitted
    // a malformed in-place delta — fail loudly rather than silently
    // skip the `.env`/`.path` rewrite.
    let runner_home = paths.runner_home(&delta.identity.trust_zone, &delta.identity.name);
    let version = delta.after.spec.runner_version.as_deref().ok_or_else(|| GharsError::Apply {
        action: format!("UpdateRunner({}): rewrite .env/.path", delta.identity.name),
        source: Box::new(GharsError::Validation(
            "in-place delta missing runner_version; cannot locate bin dir for .env/.path rewrite".into(),
            format!(
                "the runner's 00-ghars.conf is missing the X-Ghars-Effective-Version \
                 annotation (operator-stripped, pre-annotation legacy runner, or invalid \
                 value). Fix by: (a) set `runner_version = \"X.Y.Z\"` in ghars.toml to \
                 match the installed version (check with \
                 `ls /var/lib/ghars/<TRUST_ZONE>/ghars-{name}/bin.*`), OR (b) remove the \
                 runner from ghars.toml and re-add it so a fresh CreateRunner re-fetches \
                 the latest release from the GitHub API",
                name = delta.identity.name,
            ),
        )),
    })?;
    let bin_dir = runner_home.join(format!("bin.{version}"));
    files_changed += write_env_path_files(
        &bin_dir,
        delta.after.env_file.as_bytes(),
        delta.after.path_file.as_bytes(),
        log,
        true,
    )?;

    // Rewrite the per-runner cleanup script. Symmetric with
    // `execute_create_runner`'s write — the in-place update path needs
    // to refresh the script whenever its bytes drift (e.g. operator
    // added/removed `[hooks].post_job`, flipped
    // `[hooks].cleanup_workdir`, or a runner version bump rebakes
    // the `_work/` root path). Three states:
    //
    //   1. Empty rendered body (`cleanup_workdir = false`) AND
    //      script exists on disk → unlink it. The operator flipped
    //      cleanup off, so the now-orphan script (no longer wired
    //      from `70-hooks.conf`) is dead bytes; remove for hygiene.
    //   2. Empty rendered body AND script absent → no-op.
    //   3. Non-empty rendered body → `read_then_write_if_changed`
    //      byte-compares and no-ops when content matches.
    //      `chmod_record_undo` to 0o755 brings a partially-wrong
    //      mode back to the executable+root-owned posture
    //      (no-op on byte-match).
    //
    // `files_changed` is NOT bumped for any of these mutations.
    // `files_changed` gates `daemon-reload` + `stop_unit` +
    // `start_unit` at the bottom of this fn — those are the cost
    // of reloading systemd unit-file bytes and restarting the
    // runner process. The cleanup script is invoked per-job by
    // actions/runner (`bash -e <path>`), NOT loaded into the
    // running runner process at unit start, so a body / mode /
    // existence change does not require a runner restart — the
    // next `ACTIONS_RUNNER_HOOK_JOB_COMPLETED` invocation reads
    // whatever bytes the file holds at that moment. Wiring
    // changes (the env var pointing at the script) live in
    // `70-hooks.conf` which IS in the drop-in loop above and DOES
    // bump `files_changed` correctly. Excluding cleanup-script
    // mutations here avoids a spurious daemon-reload + restart
    // bounce when the only edit is `[hooks].post_job` flipping.
    let cleanup_script_path = paths
        .runner_cleanup_script(&delta.identity.trust_zone, &delta.identity.name);
    if delta.after.cleanup_script.is_empty() {
        if cleanup_script_path.as_std_path().exists() {
            let prior = read_prior(&cleanup_script_path);
            fs::remove_file(cleanup_script_path.as_std_path())?;
            if let Some(content) = prior {
                log.push(UndoStep::RemoveFile {
                    path: cleanup_script_path.clone(),
                    content,
                });
            }
        }
    } else {
        let _ = read_then_write_if_changed(
            &cleanup_script_path,
            delta.after.cleanup_script.as_bytes(),
            log,
        )?;
        if cleanup_script_path.as_std_path().exists() {
            let current_mode = fs::metadata(cleanup_script_path.as_std_path())?
                .permissions()
                .mode()
                & 0o7777;
            if current_mode != 0o755 {
                chmod_record_undo(
                    &cleanup_script_path,
                    0o755,
                    "ghars-cleanup.sh",
                    log,
                )?;
            }
        }
    }

    // Skip `daemon-reload` + stop + start when nothing on disk
    // changed AND the caches-list diff was empty. A non-empty
    // `pools_added`/`pools_removed` implies the `30-cache-pool.conf`
    // drop-in was re-rendered (its body changed when bindings
    // changed), so `files_changed > 0` in that case — but the
    // pool-Vec checks below stay as belt-and-suspenders so a
    // future code path that records pool changes without
    // re-rendering can't slip past the restart gate.
    // `verify_runner_netns` runs only when we actually start the
    // unit; otherwise the prior PID is still in the netns we
    // already verified on the last apply.
    if files_changed == 0 && pools_added.is_empty() && pools_removed.is_empty() {
        tracing::info!(
            runner = delta.identity.name.as_str(),
            "in-place: all managed bytes match on disk and caches list is unchanged; skipping daemon-reload + restart"
        );
        return Ok(ApplyOutcome::InPlaceSkipped);
    }
    // `--no-restart` opt-out: files (drop-ins, `.env`, `.path`) were
    // already written above; skip the `daemon-reload` + stop + start
    // cycle so the running unit keeps its pre-rewrite loaded config
    // until the operator manually restarts via `systemctl restart
    // ghars-runner@NAME.service` or re-runs apply without the flag.
    // CAVEAT: re-apply without `--no-restart` will see byte-matched
    // on-disk drop-ins (this apply wrote them) and take the
    // `InPlaceSkipped` short-circuit above, so the deferred restart
    // persists across re-applies until an explicit
    // `systemctl restart` invocation. The end-of-apply
    // `daemon_reload` at `orchestrator::apply` still fires —
    // it's a cache-flush of systemd's unit-file index, no unit
    // lifecycle change, so it's harmless to running workloads.
    if no_restart {
        return Ok(ApplyOutcome::InPlaceRewroteNoRestart {
            name: delta.identity.name.clone(),
            files_changed,
            pools_added,
            pools_removed,
        });
    }
    let unit_name = crate::paths::runner_unit_name(&delta.identity.name);
    // Ensure every cache pool directory referenced by this runner's
    // BindPaths= exists before restart. Symmetric with the
    // execute_create_runner guard — covers in-place updates that
    // add a new sccache binding to an existing runner.
    for cache_binding in &delta.after.spec.caches {
        let pool_dir = paths.cache_pool_dir(&cache_binding.name);
        fs::create_dir_all(pool_dir.as_std_path())?;
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
