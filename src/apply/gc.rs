//! Stale-temp/staging directory garbage collection.
//!
//! Both passes are best-effort, called from
//! [`super::orchestrator::apply`] right after `acquire_lock` so the
//! lock makes "no other apply running" the dominant invariant; the
//! age gate (60s) is belt-and-suspenders for clock skew.

use std::fs;

use camino::Utf8PathBuf;

use crate::paths::Paths;

/// Minimum age (in seconds) before a `.NAME.tmp.PID.COUNTER` file is
/// eligible for GC by [`gc_stale_temp_files`]. Anything younger could
/// belong to a `write_root_owned` call still in flight on this thread
/// (the lock prevents *cross-process* races, but a single
/// in-process call to `write_root_owned` briefly creates the temp
/// file before the rename publishes it). 60s is well past the
/// longest expected single-write window.
pub(super) const STALE_TEMP_AGE_SECS: u64 = 60;

/// Sweep half-written `write_root_owned` temp files left behind by
/// previously-crashed applies. Called from
/// [`super::orchestrator::apply`] right after `acquire_lock` and before
/// the action loop.
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
/// PID-LIVENESS IS NOT USED (symmetric with the `PID-liveness is
/// intentionally not used` section in [`gc_stale_staging_dirs`]): the
/// filter intentionally does not probe `pid_is_alive(embedded_pid)`. PIDs
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
pub(super) fn gc_stale_temp_files(paths: &Paths) {
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
/// [`super::orchestrator::apply`] right after [`gc_stale_temp_files`]
/// and before the action loop.
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
///   the cost of the check is one `stat()` and the upside is closing
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
/// case on a fresh install) is silently ignored at the `read_dir`
/// level.
pub(super) fn gc_stale_staging_dirs(paths: &Paths) {
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
/// `2.334.0-rc1` build) doesn't confuse the parse. The `runner_name`
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
pub(super) fn parse_staging_dir_suffix(name: &str) -> Option<i32> {
    let (_head, pid_str) = name.rsplit_once('-')?;
    pid_str.parse::<i32>().ok()
}

/// Parse `.{final_name}.tmp.{pid}.{counter}` and return `(pid, counter)`
/// when both are decimal integers and the basename starts with `.`
/// (hidden) AND `.tmp.` appears between the final-name and the
/// `pid.counter` suffix. Returns `None` when the shape doesn't match —
/// this is the conservative gate: anything we can't parse, we leave
/// alone.
pub(super) fn parse_temp_file_suffix(name: &str) -> Option<(u32, u64)> {
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
