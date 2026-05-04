//! Cache-pool action handlers: create / update / remove.

use std::fs;

use crate::Result;
use crate::paths::Paths;
use crate::plan::{CachePoolDelta, CachePoolPlan};
use crate::systemd::cache_template_text;

use super::outcome::ApplyOutcome;
use super::rmrf::guard_home_dir_rmrf;
use super::undo::{Deps, UndoLog, UndoStep};
use super::writes::{read_then_write_if_changed, write_record_undo, write_root_owned};

pub(super) fn execute_create_cache_pool(
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

pub(super) fn execute_update_cache_pool(
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

    // No runner-side reconciliation runs in this handler. A pool's
    // `kinds` change (ccache-only → ccache+sccache or vice versa)
    // is fully expressed by the per-pool drop-in body that this
    // handler just rewrote; runners that reference the pool see
    // the new behavior on their next restart. The runner-caches-
    // list-change case (a runner's `caches = [...]` entry changed
    // in the operator's TOML) is `execute_update_runner`'s
    // responsibility, not `execute_update_cache_pool`'s.

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

pub(super) fn execute_remove_cache_pool(
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
    // so a config drop does not leave stale 200G on disk.
    //
    // Defense-in-depth via guard_home_dir_rmrf, symmetric with
    // execute_remove_runner. The pool name already passes
    // IDENTIFIER_REGEX at config-load (no `/` or `..` possible) and
    // the path is constructed from a fixed prefix
    // `<cache_dir>/pools` + the validated name, so a regression
    // would have to slip past TWO upstream gates AND change the
    // path-construction shape to escape. The guard catches that
    // shape change at the rmrf boundary — it asserts the
    // pool_dir is the literal `<prefix>/<name>` join and rejects
    // symlinks at the dir itself.
    let pool_dir = paths.cache_pool_dir(name);
    if pool_dir.exists() {
        let pool_root = paths.cache_pool_root();
        guard_home_dir_rmrf(&pool_dir, &pool_root, name)?;
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
