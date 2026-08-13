//! Per-runner action handlers: create / remove / update (in-place + recreate).

use std::fs;
use std::os::unix::fs::{FileTypeExt, OpenOptionsExt, PermissionsExt};

use crate::Result;
use crate::config::NetworkMode;
use crate::error::GharsError;
use crate::paths::Paths;
use crate::plan::{RunnerIdentity, RunnerPlan};
use crate::state::MANAGED_DROP_IN_BASENAMES;
use crate::systemd::render_runner_unit;

use super::netns::{provision_netns_artifacts, teardown_netns_artifacts, verify_runner_netns};
use super::outcome::ApplyOutcome;
use super::rmrf::guard_home_dir_rmrf;
use super::shell::ConfigShellCtx;
use super::undo::{Deps, UndoLog, UndoStep};
use super::writes::{mint_token, read_prior, read_then_write_if_changed, write_record_undo};
use camino::Utf8PathBuf;

/// chmod a path while recording the pre-call mode in the undo log
/// so a rollback after a later step's failure can restore the
/// previous mode.
///
/// SYMLINK SAFETY (PRIMARY DEFENSE): the helper opens the path
/// with `O_RDONLY | O_NOFOLLOW` BEFORE chmod'ing it. `O_NOFOLLOW`
/// causes the kernel to return ELOOP if the path is itself a
/// symlink, so a symlink target is rejected ATOMICALLY at open
/// time — no lstat-then-chmod race window. The chmod runs
/// against `/proc/self/fd/{fd}`, a kernel-magic path that
/// resolves to the file the fd points to; the `O_NOFOLLOW`
/// binding at open time means no subsequent path-resolution race
/// can redirect the chmod to a different inode. Closes the
/// planted-symlink vector a compromised sibling `DynamicUser` in
/// the same `trust_zone` could otherwise exploit (e.g. planting
/// `runner_home/.credentials*` as a symlink to `/etc/shadow`).
///
/// `O_RDONLY` is the access mode; apply runs as root so it
/// always succeeds against the target's DAC. `O_PATH` would be
/// lighter-weight but Linux rejects chmod via
/// `/proc/self/fd/{fd}` when fd was opened `O_PATH` (returns
/// ENOTSUP). `lchmod` is not in Rust's std, and
/// `fchmodat2(..., AT_SYMLINK_NOFOLLOW)` was only added to Linux
/// in 6.6, so `O_RDONLY+O_NOFOLLOW` + /proc/self/fd is the
/// portable safe form for kernels >=4.x.
///
/// Defense in depth: the Stage 1 clamp of `runner_home` to
/// 0o755 in `execute_create_runner` denies sibling
/// `DynamicUser` writes during the apply window; the pre-Stage-1
/// entry sweep at `sweep_runner_home_for_planted_entries`
/// catches PRE-existing planted entries; this `O_NOFOLLOW`
/// helper catches anything that slips past both.
///
/// `prior_mode` is masked to `0o7777` — the standard permission
/// bits including setuid / setgid / sticky. The pre-call mode is
/// read via `metadata` on the opened fd's /proc/self/fd/{fd}
/// path (fstat-equivalent on the fd target), atomic with the
/// chmod. Caller is responsible for ensuring the path exists
/// (the helper propagates ENOENT from the open call).
///
/// `context` is a short operator-readable label identifying the
/// call site within `execute_create_runner` (e.g. `"tz_dir"`,
/// `"runner_home (Stage 1)"`, `".credentials_rsaparams"`). It
/// surfaces in the action label of the `GharsError` on failure so
/// an operator reading the diagnostic can immediately tell which
/// of the helper's eight call sites errored. The runner name is
/// also included so multi-runner applies disambiguate per
/// failing runner.
///
/// `SetMode` `UndoLog` push is GATED on `prior_mode != mode`: a
/// no-op chmod (re-apply against an unchanged on-disk state)
/// records nothing. This keeps the rollback advisory free of
/// noise lines that describe chmod-to-current-mode operations.
pub(super) fn chmod_record_undo(
    path: &camino::Utf8Path,
    mode: u32,
    context: &str,
    log: &mut UndoLog,
) -> crate::Result<()> {
    // Open with `O_RDONLY` + `O_NOFOLLOW`: returns `ELOOP` if path is a
    // symlink (refuses symlink targets atomically; no path-
    // resolution race between an `lstat` and a `chmod`). Apply runs
    // as root, so `O_RDONLY` succeeds against any file or directory
    // owned by anyone. `O_PATH` would be lighter-weight but Linux
    // does not let `chmod` operate on `/proc/self/fd/{fd}` when fd
    // was opened `O_PATH` (returns `ENOTSUP`), so `O_RDONLY` is the
    // simplest portable form.
    // `O_NONBLOCK` defense-in-depth: a FIFO at the `chmod` target
    // would otherwise block `open(O_RDONLY)` until a writer
    // appears, hanging apply indefinitely. Even though
    // `sweep_runner_home_for_planted_entries` rejects FIFOs at
    // `runner_home`'s direct children, adding `O_NONBLOCK` here is
    // free and covers any future `chmod` target outside the
    // sweep's scope (e.g. `tz_dir`, `.ktstr`, `.ccache` — currently
    // root-owned but defended against a future regression
    // weakening the parent dir mode).
    let fd = match std::fs::OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_NOFOLLOW | libc::O_NONBLOCK)
        .open(path.as_std_path())
    {
        Ok(fd) => fd,
        Err(e) if e.raw_os_error() == Some(libc::ELOOP) => {
            return Err(GharsError::Apply {
                action: format!("chmod {context} at {path}"),
                source: Box::new(GharsError::Validation(
                    format!(
                        "refusing to chmod through symlink at {path} \
                         (context: {context}) — path-based chmod would \
                         apply mode to the symlink target rather than the \
                         symlink itself"
                    ),
                    "an attacker-planted symlink (stale from a failed \
                     earlier apply or a compromised sibling DynamicUser \
                     in the same trust_zone) is present at the chmod \
                     target. Remove the symlink and re-run apply"
                        .into(),
                )),
            });
        }
        Err(e) => {
            return Err(GharsError::Apply {
                action: format!("chmod {context} at {path}"),
                source: Box::new(GharsError::Io(e)),
            });
        }
    };
    // Read prior mode via `fstat` on the fd (atomic with the open;
    // no path-resolution race). `std::fs::File::metadata` wraps
    // `fstat` under the hood -- the call inspects the inode bound
    // to the fd at open time, not whatever lives at the path now.
    let prior_mode = fd.metadata()?.permissions().mode() & 0o7777;
    // Direct `fchmod` on the fd: no `/proc/self/fd` round-trip. The fd
    // was opened `O_RDONLY` + `O_NOFOLLOW` + `O_NONBLOCK` so the inode is
    // pinned and symlink-refused atomically. `fchmod` operates on the
    // pinned inode regardless of what path resolution would now
    // produce, closing the same `lstat` -> `chmod` TOCTOU window the
    // `/proc/self/fd` pattern closed -- with one fewer syscall and no
    // dependency on `/proc` being mounted (containers / chroots that
    // omit `/proc` would have `ENOTSUP`'d the old pattern's
    // `/proc/self/fd` chmod silently).
    //
    // `Mode::from_bits_retain` accepts any u32 (caller passes 0o755,
    // 0o770, 0o600, 0o700, 0o711, etc. — all subset of 0o7777
    // permission bits, but `from_bits_retain` is the future-proof
    // choice if a caller ever needs to set setuid / setgid / sticky
    // beyond what nix's `Mode` bitflags enumerates).
    nix::sys::stat::fchmod(
        &fd,
        nix::sys::stat::Mode::from_bits_retain(mode as nix::sys::stat::mode_t),
    )
    .map_err(|e| GharsError::Apply {
        action: format!("chmod {context} at {path}"),
        source: Box::new(GharsError::Io(std::io::Error::from_raw_os_error(e as i32))),
    })?;
    drop(fd);
    // Gate the `UndoLog` push on a non-trivial mode change. A
    // no-op `chmod` (current mode == requested mode) on a re-apply
    // would otherwise pollute the rollback advisory with chmod-
    // restore lines that describe restoring the mode to its
    // current value.
    if prior_mode != mode {
        log.push(UndoStep::SetMode {
            path: path.to_path_buf(),
            prior_mode,
        });
    }
    Ok(())
}

/// Pre-apply sweep of `runner_home` direct children. Refuses to
/// proceed if any entry is a symlink, FIFO, device file, or
/// socket. These can only arise from a sibling `DynamicUser`
/// planting them during a prior failed apply's 0o777 window OR
/// from operator manual intervention.
///
/// Why a sweep is needed even with `chmod_record_undo`'s
/// `O_NOFOLLOW`: `config.sh` runs BEFORE the post-`config.sh`
/// chmod loop and uses .NET `File.WriteAllText` (no `O_NOFOLLOW`)
/// — if a planted symlink exists at `runner_home/.credentials*`,
/// `config.sh` writes OAuth credentials + RSA private key through
/// the symlink to an attacker target before the chmod loop runs
/// and notices. The credentials are already exfiltrated by then.
///
/// Why also reject FIFO/device/socket: opening a FIFO with
/// `O_RDONLY` blocks until a writer opens — apply would hang
/// indefinitely in `chmod_record_undo`. Devices and sockets have
/// similar uncovered semantics through path-based file ops.
///
/// Why direct children only (not recursive): a recursive walk
/// has TOCTOU-during-walk problems of its own. The chmod and
/// config.sh code paths only touch direct children of
/// `runner_home` (`.runner`, `.credentials*`, `tmp`) plus
/// the bin.X.Y.Z/ subtree (which is laid down by
/// `install_binary` after this sweep with mode bits from the
/// tarball headers). Deeper paths are not on the attack
/// surface.
fn sweep_runner_home_for_planted_entries(home: &std::path::Path) -> crate::Result<()> {
    let entries = match fs::read_dir(home) {
        Ok(e) => e,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(()),
        Err(e) => return Err(GharsError::Io(e)),
    };
    for entry in entries {
        let entry = entry?;
        let path = entry.path();
        let meta = fs::symlink_metadata(&path)?;
        let ft = meta.file_type();
        if !ft.is_file() && !ft.is_dir() {
            let kind = if ft.is_symlink() {
                "symlink"
            } else if ft.is_fifo() {
                "FIFO"
            } else if ft.is_block_device() {
                "block device"
            } else if ft.is_char_device() {
                "char device"
            } else if ft.is_socket() {
                "socket"
            } else {
                "non-regular entry"
            };
            return Err(GharsError::Apply {
                action: format!("pre-apply sweep of {}", home.display()),
                source: Box::new(GharsError::Validation(
                    format!(
                        "refusing to proceed: planted {} at {} — \
                         config.sh would write credentials through it \
                         before the chmod loop can refuse",
                        kind,
                        path.display()
                    ),
                    "investigate runner_home: a sibling DynamicUser in \
                     the same trust_zone may have planted this entry \
                     during a prior failed apply's 0o777 window. Remove \
                     the entry and re-run apply"
                        .into(),
                )),
            });
        }
    }
    Ok(())
}

/// fchown a path while recording the pre-call uid/gid in the undo
/// log so a rollback after a later step's failure can restore the
/// previous ownership.
///
/// Uses the same `O_RDONLY` + `O_NOFOLLOW` + `O_NONBLOCK` open pattern as
/// `chmod_record_undo`. The `fchown` then operates on the fd
/// directly via `nix::unistd::fchown` — no `/proc/self/fd` round-
/// trip needed because `fchown` is a direct file-descriptor syscall.
/// The fd binds the inode at open time with `O_NOFOLLOW` protection,
/// so no path-resolution race can redirect the `chown` to a
/// different inode.
///
/// `uid` and `gid` are the new owner/group. ghars passes the
/// DynamicUser-allocated UID (queried from systemd's D-Bus
/// interface) for both fields — systemd's `DynamicUser` model uses
/// UID==GID when there's no `/etc/passwd` entry (verified at
/// systemd `src/core/dynamic-user.c:459-461` — `*ret_gid = num`
/// when the gid wasn't separately allocated).
///
/// `context` mirrors `chmod_record_undo`'s parameter: a short
/// operator-readable label identifying the call site for the
/// error wrapper.
///
/// The `UndoLog` push is gated on `(prior_uid, prior_gid) != (uid,
/// gid)` so no-op re-chowns (re-apply over an already-chowned
/// tree) don't pollute the rollback advisory.
pub(super) fn fchown_record_undo(
    path: &camino::Utf8Path,
    uid: u32,
    gid: u32,
    context: &str,
    log: &mut UndoLog,
) -> crate::Result<()> {
    use std::os::unix::fs::MetadataExt;
    let fd = match std::fs::OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_NOFOLLOW | libc::O_NONBLOCK)
        .open(path.as_std_path())
    {
        Ok(fd) => fd,
        Err(e) if e.raw_os_error() == Some(libc::ELOOP) => {
            return Err(GharsError::Apply {
                action: format!("chown {context} at {path}"),
                source: Box::new(GharsError::Validation(
                    format!(
                        "refusing to chown through symlink at {path} \
                         (context: {context}) — path-based chown would \
                         apply ownership to the symlink target rather \
                         than the symlink itself"
                    ),
                    "an attacker-planted symlink (stale from a failed \
                     earlier apply or a compromised sibling DynamicUser \
                     in the same trust_zone) is present at the chown \
                     target. Remove the symlink and re-run apply"
                        .into(),
                )),
            });
        }
        Err(e) => {
            return Err(GharsError::Apply {
                action: format!("chown {context} at {path}"),
                source: Box::new(GharsError::Io(e)),
            });
        }
    };
    // Read the pre-call uid/gid via `fstat` on the already-open fd
    // (atomic with the open — no path-resolution race, and no
    // dependency on /proc which can be missing in chroots and
    // minimal containers).
    let meta = fd.metadata().map_err(|e| GharsError::Apply {
        action: format!("chown {context} at {path}"),
        source: Box::new(GharsError::Io(e)),
    })?;
    let prior_uid = meta.uid();
    let prior_gid = meta.gid();
    nix::unistd::fchown(
        &fd,
        Some(nix::unistd::Uid::from_raw(uid)),
        Some(nix::unistd::Gid::from_raw(gid)),
    )
    .map_err(|e| GharsError::Apply {
        action: format!("chown {context} at {path}"),
        source: Box::new(GharsError::Io(std::io::Error::from_raw_os_error(e as i32))),
    })?;
    drop(fd);
    if (prior_uid, prior_gid) != (uid, gid) {
        log.push(UndoStep::SetOwner {
            path: path.to_path_buf(),
            prior_uid,
            prior_gid,
        });
    }
    Ok(())
}

/// `fchown` the runner's writable set to the `DynamicUser`-allocated
/// UID, then chmod tighten modes to `DynamicUser`-only access.
///
/// **Ordering invariant**: chown ALL paths first, THEN chmod
/// tighten ALL paths. Tightening first would leave files at the
/// tightened mode while still owned by root, blocking the runner
/// from credential read during the window between the two passes.
///
/// Target modes: `runner_home` / `runner_tmp` → 0o700; `.ktstr` /
/// `.ccache` → 0o770 (group reserved for future trust-zone share);
/// `.runner` / `.credentials*` → 0o600.
///
/// Gating: `.ccache` skipped when `ccache_dir = None` (caller's
/// spec-time gate); credential files (`.runner`, `.credentials`,
/// `.credentials_rsaparams`) existence-gated inside the helper
/// because `config.sh` output varies by auth mechanism.
#[allow(clippy::too_many_arguments)]
pub(super) fn chown_and_tighten_runner_state(
    runner_home: &camino::Utf8Path,
    runner_tmp: &camino::Utf8Path,
    ktstr_dir: &camino::Utf8Path,
    ccache_dir: Option<&camino::Utf8Path>,
    bin_dir: &camino::Utf8Path,
    uid: u32,
    gid: u32,
    log: &mut UndoLog,
) -> crate::Result<()> {
    // `fchown` every path the DynamicUser needs to read/write. The
    // helper uses `O_NOFOLLOW` + `O_NONBLOCK` + `nix::unistd::fchown` so
    // symlink targets, FIFOs, devices, and sockets at the chown
    // target are refused atomically with the open.
    //
    // Production callers pass `(uid, gid)` where `gid == uid` (the
    // DynamicUser invariant; see `dynamic-user.c:459-461`). Tests
    // pass `(test_process_uid, test_process_gid)` so non-root chown
    // doesn't trip on the gid-change-needs-`CAP_CHOWN` unless-caller-
    // is-in-the-group-set rule.
    //
    // `ccache_dir` is `Option` because the dir is only created when
    // this runner has at least one `cache_pool` binding with ccache
    // kind (gated in `execute_create_runner`). Passing None here
    // skips the `.ccache` `fchown` + chmod-tighten so non-ccache
    // runners don't touch a dir that doesn't exist for their spec.
    fchown_record_undo(runner_home, uid, gid, "runner_home", log)?;
    fchown_record_undo(runner_tmp, uid, gid, "runner_tmp", log)?;
    fchown_record_undo(ktstr_dir, uid, gid, ".ktstr", log)?;
    if let Some(ccache_dir) = ccache_dir {
        fchown_record_undo(ccache_dir, uid, gid, ".ccache", log)?;
    }
    // bin_dir itself: the DynamicUser needs write access to create
    // _work/ (workflow execution) and _diag/ (listener logs). The
    // DynamicUser already owns runner_home (chowned above) so there
    // is no additional security exposure — the DynamicUser can
    // already manipulate entries in runner_home.
    fchown_record_undo(bin_dir, uid, gid, "bin_dir", log)?;
    // _diag/ is created by config.sh (as root) during registration.
    // chown it so the listener can write log files on subsequent
    // starts.
    let diag_dir = bin_dir.join("_diag");
    if diag_dir.as_std_path().exists() {
        fchown_record_undo(&diag_dir, uid, gid, "_diag", log)?;
        if let Ok(entries) = fs::read_dir(diag_dir.as_std_path()) {
            for entry in entries.flatten() {
                if let Ok(p) = camino::Utf8PathBuf::try_from(entry.path()) {
                    fchown_record_undo(&p, uid, gid, "_diag entry", log)?;
                }
            }
        }
    }
    // Runner.Listener resolves its Root from the assembly location
    // (bin_dir/bin/Runner.Listener.dll), so config.sh writes
    // credential files into bin_dir — not runner_home.
    for basename in [".runner", ".credentials", ".credentials_rsaparams"] {
        let path = bin_dir.join(basename);
        if path.as_std_path().exists() {
            fchown_record_undo(&path, uid, gid, basename, log)?;
        }
    }

    // Tighten modes now that ownership is the `DynamicUser`.
    chmod_record_undo(runner_home, 0o700, "runner_home (tighten)", log)?;
    chmod_record_undo(runner_tmp, 0o700, "runner_tmp (tighten)", log)?;
    chmod_record_undo(ktstr_dir, 0o770, ".ktstr (tighten)", log)?;
    if let Some(ccache_dir) = ccache_dir {
        chmod_record_undo(ccache_dir, 0o770, ".ccache (tighten)", log)?;
    }
    for basename in [".runner", ".credentials", ".credentials_rsaparams"] {
        let path = bin_dir.join(basename);
        if path.as_std_path().exists() {
            chmod_record_undo(&path, 0o600, basename, log)?;
        }
    }

    Ok(())
}

/// Snapshot operator-territory drop-in bodies (basenames NOT in
/// `MANAGED_DROP_IN_BASENAMES`, typically `99-*.conf` from
/// `systemctl edit`) before the recreate path wipes
/// `drop_in_dir`. Returns `(basename, body_bytes)` pairs to feed
/// `restore_operator_drop_ins` post-create. Read failures are
/// logged via `tracing::warn` and skipped — they don't fail the
/// recreate (the operator override is lost, but the recreate
/// proceeds; a hard error here would block the version bump
/// driving the recreate).
pub(super) fn snapshot_operator_drop_ins(drop_in_dir: &camino::Utf8Path) -> Vec<(String, Vec<u8>)> {
    let Ok(read_dir) = std::fs::read_dir(drop_in_dir.as_std_path()) else {
        return Vec::new();
    };
    let mut snapshot = Vec::new();
    for entry in read_dir.flatten() {
        let file_name = entry.file_name();
        let basename = file_name.to_string_lossy().into_owned();
        if MANAGED_DROP_IN_BASENAMES.contains(&basename.as_str()) {
            continue;
        }
        match std::fs::read(entry.path()) {
            Ok(content) => snapshot.push((basename, content)),
            Err(e) => {
                tracing::warn!(
                    drop_in = %basename,
                    error = %e,
                    "failed to snapshot operator drop-in before recreate; \
                     override will be lost on the post-create restore"
                );
            }
        }
    }
    snapshot
}

/// Restore operator-territory drop-ins captured by
/// `snapshot_operator_drop_ins` after the recreate's
/// `execute_create_runner` finishes. Uses `write_record_undo`
/// so the restored files are tracked in the undo log — a
/// rollback post-restore unlinks them, leaving the runner with
/// only managed drop-ins (matching the create-path baseline).
pub(super) fn restore_operator_drop_ins(
    drop_in_dir: &camino::Utf8Path,
    snapshot: &[(String, Vec<u8>)],
    log: &mut UndoLog,
) -> crate::Result<()> {
    for (basename, content) in snapshot {
        let path = drop_in_dir.join(basename);
        write_record_undo(&path, content, log)?;
    }
    Ok(())
}

/// Write the runner's `bin_dir/.env` and `bin_dir/.path` files in a
/// single call, returning the number of files whose on-disk bytes
/// changed (0 or 2 for `conditional = false` since every write counts
/// as a change vs the pre-write absent state; 0..=2 for `conditional
/// = true`). Both files always written via the same writer per call.
///
/// `conditional = false`: `CreateRunner` path. Every `CreateRunner`
/// writes fresh `.env` / `.path` content; `write_record_undo` snapshots
/// `prior_content = None` (file doesn't exist yet) and pushes
/// `UndoStep::WriteFile` so a partial-create rollback unlinks the
/// file rather than restoring prior content (see the call site
/// doc-comment for the operator-facing degraded-mode implication).
///
/// `conditional = true`: in-place `UpdateRunner` path.
/// `read_then_write_if_changed` byte-compares the rendered content
/// against the on-disk file and writes only when they differ; the
/// caller uses the returned count to decide whether to trigger
/// daemon-reload + restart (a no-op rewrite skips the cycle).
///
/// Centralizes the `bin_dir.join(".env")` / `bin_dir.join(".path")`
/// path arithmetic so both code paths can't drift in basename or
/// directory derivation (the LAYER 1/2 .env/.path content is the
/// load-bearing channel for workflow-step env per `EnvironmentSpec`
/// at config.rs; basename drift between paths would invisibly
/// orphan operator-declared env vars at apply time).
pub(super) fn write_env_path_files(
    bin_dir: &camino::Utf8Path,
    env_file_body: &[u8],
    path_file_body: &[u8],
    log: &mut UndoLog,
    conditional: bool,
) -> crate::Result<usize> {
    let env_path = bin_dir.join(".env");
    let path_path = bin_dir.join(".path");
    if conditional {
        let mut changed = 0;
        if read_then_write_if_changed(&path_path, path_file_body, log)? {
            changed += 1;
        }
        if read_then_write_if_changed(&env_path, env_file_body, log)? {
            changed += 1;
        }
        Ok(changed)
    } else {
        write_record_undo(&path_path, path_file_body, log)?;
        write_record_undo(&env_path, env_file_body, log)?;
        Ok(2)
    }
}

/// Find the most recent `bin.X.Y.Z/` directory under `runner_home` that
/// contains config.sh. Used by remove/undo paths that need to run
/// config.sh but don't have the version from a plan.
///
/// Ordering: sort by directory mtime, newest first. mtime mirrors the
/// retention pruner in `extract::prune_old_bin_versions` so this helper
/// and the pruner agree on which version is "current". Lexicographic
/// sort would mis-order across version-string transitions where digit
/// width changes (e.g. `bin.2.334.0` sorts BEFORE `bin.2.34.0`); mtime
/// is install-time-correct regardless of version-string shape.
pub(super) fn find_active_bin_dir(runner_home: &camino::Utf8Path) -> crate::Result<Utf8PathBuf> {
    let mut candidates: Vec<(std::time::SystemTime, Utf8PathBuf)> = Vec::new();
    if let Ok(entries) = fs::read_dir(runner_home.as_std_path()) {
        for entry in entries.flatten() {
            let name = entry.file_name();
            let name_str = name.to_string_lossy();
            if name_str.starts_with("bin.")
                && entry.path().join("config.sh").exists()
                && let Ok(utf8) = Utf8PathBuf::try_from(entry.path())
                && let Ok(meta) = entry.metadata()
                && let Ok(mtime) = meta.modified()
            {
                candidates.push((mtime, utf8));
            }
        }
    }
    candidates.sort_by(|a, b| a.0.cmp(&b.0));
    candidates
        .pop()
        .map(|(_, p)| p)
        .ok_or_else(|| GharsError::Apply {
            action: format!("find config.sh under {runner_home}"),
            source: Box::new(GharsError::Io(std::io::Error::new(
                std::io::ErrorKind::NotFound,
                format!("no bin.*/config.sh found under {runner_home}"),
            ))),
        })
}

pub(super) fn execute_create_runner(
    plan: &RunnerPlan,
    deps: &Deps<'_>,
    paths: &Paths,
    log: &mut UndoLog,
    keep_versions: u32,
) -> Result<ApplyOutcome> {
    let spec = &plan.spec;
    let runner_home = paths.runner_home(&spec.trust_zone, &spec.name);

    // Trust-zone parent dir. 0o755 = root rwx, others r-x:
    // DynamicUser can descend AND enumerate. Runner.Listener's
    // ValidateExecutePermission calls Directory.InternalEnumeratePaths
    // on every ancestor, which needs read, not just execute.
    let tz_dir = paths.state_dir.join(&spec.trust_zone);
    fs::create_dir_all(tz_dir.as_std_path())?;
    chmod_record_undo(&tz_dir, 0o755, "tz_dir", log)?;

    // Clean up stale DynamicUser symlinks from previous runs.
    let home_std = runner_home.as_std_path();
    if let Ok(meta) = fs::symlink_metadata(home_std)
        && meta.file_type().is_symlink()
    {
        let _ = fs::remove_file(home_std);
    }
    fs::create_dir_all(home_std)?;

    // Pre-Stage-1 entry sweep: refuse to proceed if any direct child
    // of `runner_home` is a symlink, FIFO, device file, or socket.
    // `chmod_record_undo`'s `O_NOFOLLOW` defense catches a symlink at
    // a CHMOD TARGET path, but `config.sh` runs BEFORE the credential-
    // file chmod loop and uses .NET `File.WriteAllText` (no `O_NOFOLLOW`)
    // — if a sibling `DynamicUser` planted `runner_home/.credentials*`
    // as a symlink during a prior failed apply's 0o777 window,
    // `config.sh` would write OAuth credentials + RSA private key
    // through the symlink to an attacker target BEFORE the post-
    // `config.sh` `chmod_record_undo` loop runs and notices. The
    // credentials are already exfiltrated by then.
    //
    // The sweep enumerates `runner_home`'s direct children via
    // `symlink_metadata` (`lstat` — does NOT follow), refuses to
    // proceed if any are non-regular-non-dir. FIFO/device/socket
    // entries would also cause apply to block on subsequent reads
    // (FIFO open with `O_RDONLY` blocks until a writer opens, hanging
    // apply indefinitely).
    //
    // Recursive sweep would introduce TOCTOU-during-walk — we
    // intentionally stay non-recursive. Only direct children matter:
    // `config.sh` and the post-`config.sh` chmod loop write at
    // `runner_home/.runner` / `.credentials` / `.credentials_rsaparams`,
    // and `chmod` `runner_home/tmp` + `runner_home` itself. Deeper paths
    // aren't touched by either code path.
    sweep_runner_home_for_planted_entries(home_std)?;

    // Stage 1 of `runner_home` chmod: clamp to 0o755 (root rwx, others
    // r-x) for the duration of apply. Defense-in-depth on top of
    // `chmod_record_undo`'s `O_NOFOLLOW`: even if a future regression
    // weakened the helper's symlink refusal, the 0o755 clamp denies
    // sibling `DynamicUser` write access to `runner_home` so they
    // cannot plant new symlinks DURING apply between the pre-
    // Stage-1 sweep above and Stage 2 below. The pre-Stage-1 sweep
    // catches PRE-existing planted entries; Stage 1 prevents NEW
    // planting during the apply window.
    //
    // The dir needs to be traversable by root throughout — `install_binary`
    // writes `bin.X.Y.Z/` under it, `config.sh` writes `.runner` /
    // `.credentials*` into it, ghars chmods those files after.
    //
    // Stage 2 below (just before `deps.systemd.start_unit`) re-opens
    // `runner_home` to 0o777 so the `DynamicUser` allocated at unit
    // start time can create `_work/`, `_diag/`, and operator toolchain
    // caches:
    //   - `Runner.Listener` creating `_work/` (`Runner.cs:418`).
    //   - `HostTraceListener` creating `_diag/` (`HostTraceListener.cs:29`).
    //   - workflow steps writing job artifacts under `_work/`.
    //   - operator/runner-toolchain caches (`~/.cargo`, `~/.npm`, `~/.config`, ...).
    // 0o777 is the right unit-runtime mode under the current
    // architecture: the `DynamicUser` UID is not NSS-resolvable on
    // systemd<256, so chown-by-name fails and `Manager.RefUid` is the
    // narrower alternative once the runner unit has started.
    chmod_record_undo(&runner_home, 0o755, "runner_home (Stage 1)", log)?;

    // Per-runner tmp dir so `TMPDIR` points somewhere the `sccache` server
    // can reach (`PrivateTmp` isolates `/tmp` per unit). Safe to `chmod`
    // 0o777 here because `runner_home` is currently 0o755 — no sibling
    // `DynamicUser` can plant `runner_home/tmp` as a symlink between
    // our `create_dir_all` and `chmod`.
    let runner_tmp = runner_home.join("tmp");
    fs::create_dir_all(runner_tmp.as_std_path())?;
    chmod_record_undo(&runner_tmp, 0o777, "runner_tmp", log)?;

    // Shared `.ktstr` directory at the trust-zone level. All runners in the
    // same trust_zone bind this path into their sandbox for `KTSTR_LOCK_DIR`
    // and `KTSTR_CACHE_DIR`. Mode 0777 so the `DynamicUser` (allocated at
    // unit-start time, unknown at apply time) can write to it; actual
    // isolation is at the trust-zone UID layer (different trust zones get
    // different UIDs).
    let ktstr_dir = tz_dir.join(".ktstr");
    fs::create_dir_all(ktstr_dir.as_std_path())?;
    chmod_record_undo(&ktstr_dir, 0o777, ".ktstr", log)?;
    // `.ccache` dir is trust-zone-shared but only used when at least
    // one `cache_pool` with `kinds` containing `ccache` is bound to this
    // runner. The renderer at `systemd::render_runner_env_file` gates
    // its `CCACHE_DIR=` `.env` emission on the same `has_ccache`
    // predicate — keeping the two symmetric: if the dir isn't
    // created, the env var pointing at it isn't emitted, so the
    // unconditional `ccache` wrappers in `PATH` don't intercept `gcc`
    // calls and try to write into a non-existent path. Runners with
    // no `ccache` binding fall through to `ccache`'s XDG default
    // (`HOME/.ccache` → `runner_home`, per-runner ephemeral). Gating
    // creation here keeps trust zones with zero `ccache` runners free
    // of an empty `.ccache`. `create_dir_all` is idempotent so
    // multiple `ccache`-binding runners in the same trust_zone
    // converge to one shared dir.
    let ccache_dir = tz_dir.join(".ccache");
    let has_ccache = spec
        .caches
        .iter()
        .any(|b| b.kinds.contains(&crate::config::CacheKind::Ccache));
    if has_ccache {
        fs::create_dir_all(ccache_dir.as_std_path())?;
        chmod_record_undo(&ccache_dir, 0o777, ".ccache", log)?;
    }

    // No `useradd` / `gpasswd` step. The runner unit declares
    // `DynamicUser=yes` with `User=ghars-tz-<TRUST_ZONE>` set in the
    // per-runner `00-ghars.conf` drop-in; systemd allocates the
    // transient UID/GID on unit start and recycles it on stop. Cache
    // reach is socket-DAC + `BindPaths` (cache server runs at the same
    // trust_zone `DynamicUser`), not `gpasswd`.

    // 1) Runner binary. Two paths:
    //    (a) `runner_tarball` set on the spec → use the local file
    //        verbatim after re-stat'ing (`verify_local` closes the
    //        SEC-16 stat-then-extract TOCTOU window).
    //    (b) Otherwise the plan resolved a `Release` and we fetch its
    //        `tarball_url` into a runtime dir, verify SHA256, then
    //        install.
    let (tarball_path, version) = if let Some(local) = &spec.runner_tarball {
        deps.tarball.verify_local(local)?;
        // `spec.runner_version` is guaranteed `Some` by `lower_to_effective`:
        // the tarball+no-version gate at `compute.rs` rejects this
        // combination at plan time. `expect()` over `unwrap_or_else`
        // makes a regression that re-introduces the silent "local"
        // fallback surface as a loud panic rather than installing
        // into `bin.local/` while the unit drop-in references
        // `bin.latest/` (the pre-fix broken-from-birth shape).
        #[allow(clippy::expect_used)]
        let version = spec.runner_version.clone().expect(
            "tarball-pinned spec.runner_version: guaranteed Some by \
                 lower_to_effective's tarball+no-version validation gate",
        );
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
    let bin_dir = deps.tarball.install_binary(
        &tarball_path,
        &paths.state_dir,
        &runner_home,
        &spec.name,
        &version,
    )?;

    // 2b) Retention prune (Part 9f). After the fresh
    //     `bin.<version>/` tree has been laid down, prune older
    //     `bin.X.Y.Z/` trees in the runner home so disk usage stays
    //     bounded. The pruner keeps the `keep_versions` most-recent
    //     by mtime plus whatever any operator-created
    //     `runner_home/bin` symlink resolves to (defense in depth
    //     against mtime touches and against operator-managed
    //     symlinks ghars itself no longer creates). Pruning is
    //     best-effort: per-entry failures are logged and counted,
    //     never propagated, so a failed cleanup doesn't sink the
    //     whole `CreateRunner` action. Errors from the call itself
    //     (`read_dir` failure on `runner_home`, or `keep_versions = 0`)
    //     DO propagate — those indicate a structural problem the
    //     operator should see.
    let _pruned = deps
        .tarball
        .prune_old_versions(&runner_home, keep_versions)?;

    // 3) Mint a registration token. SEC-05: the token is short-lived
    //    (1h GitHub TTL); we hand it to `config.sh` and never persist it.
    //    The caller-visible `RegistrationToken.value` is opaque so
    //    nothing here logs it.
    let token = mint_token(deps.auth, &spec.auth_name, &spec.url, false)?;

    // 4) Run `config.sh --url ... --token ...` — registers the runner
    //    with GitHub. SEC-05 mitigation note in trait doc; today
    //    still passes the token via `argv` pending the token-drop
    //    env-var pattern's full design. Pass `&token.value` so
    //    `token` stays owned in this frame and zeroizes on `Drop`
    //    at end of fn.
    deps.config_shell.run_register(&ConfigShellCtx {
        runner_home: &runner_home,
        bin_dir: &bin_dir,
        name: &spec.name,
        url: &spec.url,
        labels: &spec.labels,
        token: &token.value,
    })?;
    // Push `GitHubRegistration` AFTER `run_register` succeeds. Undo
    // path mints a fresh removal token via the auth registry and
    // calls `run_remove`. The `runner_home` is captured here because
    // it is the canonical location `config.sh` writes credentials
    // to, and we want the undo to target this exact path even if
    // the spec is mutated between push-time and undo-time.
    log.push(UndoStep::GitHubRegistration {
        name: spec.name.clone(),
        url: spec.url.clone(),
        auth_name: spec.auth_name.clone(),
        runner_home: runner_home.clone(),
    });

    // No `tighten_credential_perms` call. `DynamicUser=yes` manages
    // `StateDirectory` ownership at the systemd level; `.credentials` is
    // owned by the `trust_zone`'s transient UID and inherits the
    // `StateDirectoryMode=0700` from the unit template.

    // 5b) Re-render the unit text against the resolved spec. The
    // plan-time render in `into_runner_plan` happened BEFORE
    // `resolve_plan_releases` populated `spec.runner_version` from
    // the API for implicit-latest runners, so the plan-time preview
    // showed a "latest" placeholder in `WorkingDirectory=` / `ExecStart=`
    // / `ConditionPathExists=`. By apply time, `resolve_plan_releases`
    // (`cli/cmd_apply.rs`) has filled `spec.runner_version` from the
    // resolved release, so re-rendering here pins the actual version
    // into the drop-in body that lands on disk. The legacy populate
    // block that filled `runner_version` from `plan.resolved_release`
    // here is gone — `resolve_plan_releases` now owns the spec-level
    // fill so this site reads the same field uniformly.
    //
    // `spec_hash` is also recomputed against the resolved spec so the
    // on-disk `X-Ghars-Spec-Hash` annotation matches the canonical-JSON
    // hash of what's actually rendered to disk. Without this
    // recompute, the on-disk `X-Ghars-Spec-Hash` would remain the
    // plan-time hash computed with `runner_version=None` for
    // implicit-latest runners, while the rendered drop-in body bytes
    // use `bin.X.Y.Z` paths from the resolved version. The resulting
    // hash-vs-bytes mismatch breaks the invariant downstream plan
    // classifiers rely on, with consequences that depend on the
    // discovered `X-Ghars-Effective-Version` annotation state: the
    // intersection-arm version-fill in `lower_to_effective` fires
    // when the annotation is well-formed, producing a spurious in-place
    // `UpdateRunner` cycle because the candidate hash (computed against
    // the annotation-filled `runner_version`) and the on-disk hash
    // (frozen at plan-time `None`) disagree; skips when the annotation
    // is empty or invalid, silently accepting the divergence as a
    // permanent NoOp. Either consequence is wrong. Recomputing pins
    // the contract that the on-disk hash reflects the spec actually
    // rendered to disk; the intersection arm then reads
    // `X-Ghars-Effective-Version` from the annotation, fills
    // `runner_version` on the candidate BEFORE its hash computation,
    // and produces a matching candidate hash on the next plan.
    let mut resolved_spec = spec.clone();
    resolved_spec.runner_version = Some(version.clone());
    resolved_spec.spec_hash = crate::plan::spec_hash(&resolved_spec);
    let rendered = render_runner_unit(&resolved_spec)?;

    // 5c) Write `.path` and `.env` into the versioned bin dir.
    //   - `.path`: read once by `runsvc.sh` (`export PATH=\`cat .path\``)
    //     at runner-process start; inherited across exec by every
    //     worker / workflow-step subprocess.
    //   - `.env`: read once by `Runner.Listener`'s `LoadAndSetEnv`
    //     (`src/Runner.Listener/Program.cs` `Main`) at process start,
    //     each `KEY=VALUE` set via `Environment.SetEnvironmentVariable`;
    //     workflow steps inherit through worker fork+exec.
    //
    // These reach workflow steps via the parent-process env, distinct
    // from the systemd `Environment=` directives in `00-ghars.conf` /
    // `30-cache-pool.conf` (LAYER 1, bind to the systemd unit process).
    // Bytes are computed by the pure functions
    // `render_runner_env_file` / `render_runner_path_file` so the
    // in-place `UpdateRunner` path produces byte-identical content for
    // the same spec (no `runner_version` interpolation in either
    // producer).
    //
    // Rollback semantics for the create-path: `write_record_undo`
    // snapshots `prior_content` via `read_prior(path)`. For a
    // `CreateRunner` (fresh runner), `.env` and `.path` do not exist on
    // disk yet, so `read_prior` returns `None`. The pushed
    // `UndoStep::WriteFile` with `prior_content: None` performs
    // `unlink` on rollback, NOT a restore to prior content (there
    // was none). A partial `CreateRunner` failure that triggers
    // rollback therefore leaves the runner without `.env`/`.path` on
    // disk. If `actions/runner`'s `env.sh` fires on the runner unit
    // before a successful re-apply, it writes its OWN minimal `.env`
    // / `.path` content (no ccache wrappers, no KTSTR_* env, no
    // operator-declared environment.vars) — workflow steps that
    // depend on those framework env vars run in degraded mode until
    // the operator re-runs `ghars apply` to restore the ghars-
    // emitted bytes.
    write_env_path_files(
        &bin_dir,
        rendered.env_file.as_bytes(),
        rendered.path_file.as_bytes(),
        log,
        false,
    )?;

    // 5c-bis) Write the per-runner job-completed cleanup script
    // (when enabled). actions/runner invokes this via
    // `Environment=ACTIONS_RUNNER_HOOK_JOB_COMPLETED=` (wired by
    // `70-hooks.conf` when `[hooks].cleanup_workdir` is enabled —
    // the default). The script body chains the operator's
    // `[hooks].post_job` first if configured, then wipes per-job
    // disk state.
    //
    // Lives in `runner_home/ghars-cleanup.sh` (not under the
    // versioned `bin.X.Y.Z/` subtree) so it survives runner version
    // upgrades without rewrites — `Paths::runner_cleanup_script`
    // documents the same rationale. The script body itself bakes
    // the version-specific `_work/` path, so it IS regenerated on
    // every apply; the location just stays stable.
    //
    // `write_record_undo` writes via `write_root_owned` which sets
    // mode 0o644 (root:root). `chmod_record_undo` to 0o755 makes
    // it world-executable so the runner's DynamicUser-allocated UID
    // can exec it. Both writes land before
    // `chown_and_tighten_runner_state` (which only touches the
    // narrow writable set — runner_home, runner_tmp, .ktstr,
    // .ccache, bin_dir, _diag, credentials), so the cleanup script
    // stays root:root after apply. World-x is sufficient for the
    // DynamicUser to invoke it; root ownership keeps the runner
    // from rewriting the script under itself.
    //
    // When `cleanup_workdir = false`, `rendered.cleanup_script` is
    // empty (per `render_cleanup_script`'s early-return). Skip the
    // write — `render_hooks` wires `JOB_COMPLETED` directly to the
    // operator post_job (or omits it), so there's no script to
    // write.
    if !rendered.cleanup_script.is_empty() {
        let cleanup_script_path = paths.runner_cleanup_script(&spec.trust_zone, &spec.name);
        write_record_undo(
            &cleanup_script_path,
            rendered.cleanup_script.as_bytes(),
            log,
        )?;
        chmod_record_undo(&cleanup_script_path, 0o755, "ghars-cleanup.sh", log)?;
    }

    // 5d) Normalize post-`config.sh` file modes to DynamicUser-READ.
    // Upstream `actions/runner` writes three files in `runner_home`:
    //   - `.runner` — runner identity JSON (`IOUtil.SaveObject` ->
    //     `File.WriteAllText`; mode is `0o666 & ~umask`, so 0o644 with
    //     the default 0o022 umask, but could be 0o600 if ghars was
    //     invoked with a non-default umask like 0o077).
    //   - `.credentials` — OAuth credentials JSON (same call shape;
    //     same umask exposure).
    //   - `.credentials_rsaparams` — RSA private key. Upstream
    //     explicitly `chmod 600` in
    //     `src/Runner.Listener/Configuration/RSAFileKeyManager.cs:33`
    //     (the RSA key signs OAuth assertions for credential
    //     refresh), so this file lands at 0o600 regardless of
    //     umask.
    //
    // All three are root:root after `config.sh` (which ghars invokes
    // as root). The runner unit runs under `DynamicUser`; the
    // DynamicUser-allocated UID is in neither the owner nor any
    // group of root, so 0o600 / 0o640 are unreadable to it. Without
    // a normalize step, a non-default umask on the ghars host
    // breaks credential refresh and the runner stops accepting
    // jobs.
    //
    // Force 0o644 (owner rw, world r) on each file unconditionally
    // — defense-in-depth that does not depend on the
    // ghars-process-inherited umask being 0o022. Pre-exec umask
    // pinning via `CommandExt::pre_exec` (which requires unsafe,
    // forbidden by workspace lint) was the original plan, but
    // post-hoc `chmod` is the cleaner mechanism here: it works
    // regardless of WHICH process wrote the file (`config.sh`,
    // a future helper, an upstream-runner-version that adds a
    // new credential file with its own explicit `chmod`) AND
    // doesn't mutate process-global umask state that other code
    // paths in the same apply may depend on. `nix::sys::stat::umask`
    // exposes a safe wrapper (would unblock the pre-exec plan)
    // but using it process-wide has the same multi-writer
    // ambiguity — post-hoc `chmod` is the right level.
    //
    // Files missing on disk are tolerated as a no-op — `config.sh`
    // may legitimately omit `.credentials_rsaparams` on a
    // PAT-authenticated runner, or skip a write if registration
    // takes a path that doesn't materialize the file.
    //
    // The `bin.X.Y.Z/` tree (extracted by `deps.tarball.install_binary`
    // above) keeps the modes the tarball headers wrote — 0o755 for
    // `runsvc.sh` / `Runner.Listener` / native binaries, 0o644 for
    // managed assemblies, 0o644 for the `.env` / `.path` files
    // `write_record_undo` just laid down. Do NOT add a recursive
    // chmod cascade here: a path-based `fs::set_permissions` walk
    // follows symlinks (`chmod(2)`, not `lchmod`) and combined with
    // root + operator-writable subtree could chmod `/etc/*` → 0o777
    // through a planted symlink. Touch only the specific files this
    // helper knows about, via the symlink-refusing `chmod_record_undo`
    // (`O_NOFOLLOW`).
    let mut normalized = Vec::with_capacity(3);
    for basename in [".runner", ".credentials", ".credentials_rsaparams"] {
        // Runner.Listener resolves its Root from the assembly location
        // (bin_dir/bin/Runner.Listener.dll), so config.sh writes
        // credential files into bin_dir — not runner_home.
        let path = bin_dir.join(basename);
        if path.as_std_path().exists() {
            chmod_record_undo(&path, 0o644, basename, log)?;
            normalized.push(basename);
        }
    }
    // Operator visibility: surface the per-`CreateRunner` credential
    // normalization so an operator running under non-default umask
    // can see ghars corrected modes. `tracing::debug!` keeps it out
    // of the default log surface; opt in via `RUST_LOG=ghars=debug`.
    tracing::debug!(
        runner = %spec.name,
        normalized = ?normalized,
        "normalized config.sh credential file modes to 0o644 (DynamicUser READ)"
    );

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
    let unit_name = crate::paths::runner_unit_name(&spec.name);
    deps.systemd.enable_unit(&unit_name)?;
    log.push(UndoStep::EnableUnit {
        name: unit_name.clone(),
    });
    // `Manager.StartUnit` fails on a unit not yet loaded post-write. The
    // ordering per Part 8 is: write files → `daemon_reload` → `start_unit`.
    // We issue a `daemon_reload` here so the freshly-written unit is
    // visible; `apply()` issues a final `daemon_reload` after the
    // per-action loop too, which is idempotent.
    deps.systemd.daemon_reload()?;

    // 7b) For Netns runners: provision the per-runner netns side-units
    //     (config TOML, nft files, `ghars-net@.service` template) and
    //     start `ghars-net@INSTANCE.service` BEFORE the runner unit so
    //     the runner's `NetworkNamespacePath=/var/run/netns/ghars-%i`
    //     join succeeds. Fail-closed contract: missing netns =>
    //     runner refuses to start. Open mode is a no-op.
    provision_netns_artifacts(spec, deps, paths, log)?;

    // Stage 2 of `runner_home` chmod: open to 0o777 so the
    // `DynamicUser` allocated at unit start can write `_work/`,
    // `_diag/`, and toolchain caches under the per-runner home.
    // This is the LAST mutation under `runner_home` before the unit
    // starts, so no later chmod follows a sibling-DynamicUser-
    // planted symlink (the only file-mode mutations between here
    // and `start_unit` are systemd unit / drop-in writes outside
    // `runner_home`).
    chmod_record_undo(&runner_home, 0o777, "runner_home (Stage 2)", log)?;

    // 7c) Ensure every cache pool directory referenced by this runner's
    //     BindPaths= exists on disk. The pool dir is normally created by
    //     systemd's CacheDirectory= at cache-unit start, and phase
    //     ordering (CreateCachePool before CreateRunner) covers fresh
    //     deploys. But re-deploys where the pool storage was cleaned up
    //     while the pool's systemd config is in-sync (NoOp) leave a
    //     dangling BindPaths= target — systemd fails at NAMESPACE step
    //     with "No such file or directory" before the runner process
    //     even forks. Idempotent mkdir here closes the gap.
    for cache_binding in &spec.caches {
        let pool_dir = paths.cache_pool_dir(&cache_binding.name);
        fs::create_dir_all(pool_dir.as_std_path())?;
    }

    deps.systemd.start_unit(&unit_name)?;
    log.push(UndoStep::StartUnit {
        name: unit_name.clone(),
    });

    // 8) Post-start: chown `runner_home` and the trust-zone-shared
    // dirs + credential files to the DynamicUser-allocated UID,
    // then tighten modes to DynamicUser-only access.
    //
    // Gated on running-as-root. Production `ghars apply` always
    // runs as root (`CAP_CHOWN` required + many other capabilities
    // for systemd D-Bus, file ownership management, etc.) so the
    // gate is normally taken. Non-root invocations (operator
    // running `ghars apply` without sudo, test harnesses) hit
    // the warn-and-skip arm: the runner starts with the wider
    // apply-time modes (0o777 `runner_home`, 0o644 credentials)
    // but ownership stays root:root. The runner unit won't be
    // able to read its credentials in that case, so non-root
    // apply is best-effort for dry-run / development; production
    // requires root.
    //
    // SystemD's `Manager.LookupDynamicUserByName(name) → uid`
    // returns `BUS_ERROR_NO_SUCH_DYNAMIC_USER` until the unit's
    // `ExecStart` child has run `dynamic_user_realize` (verified
    // against systemd `src/core/exec-invoke.c:5401` +
    // `src/core/dynamic-user.c:333-464`). For a FIRST-IN-TRUST-ZONE
    // runner, that hasn't happened yet at `start_unit` return time —
    // `Manager.StartUnit` only enqueues the job, doesn't wait for
    // the child fork to complete. Poll with backoff: 10ms doubling
    // to 100ms cap, total budget 5s. If the poll times out, the
    // runner unit probably failed to start; surface a typed
    // `GharsError::Apply` with operator-actionable remediation.
    //
    // For subsequent runners in the same trust zone (sharing the
    // `User=ghars-tz-X` name), the UID is already allocated and
    // the first poll returns immediately.
    //
    // GID equals UID for `DynamicUser` without a `/etc/passwd` entry
    // (verified at `dynamic-user.c:459-461`: `*ret_gid = num`
    // in the no-passwd-entry branch). Use the same value for
    // both `fchown` args.
    if nix::unistd::geteuid().is_root() {
        let trust_zone_user = format!(
            "{}{}",
            crate::validators::TRUST_ZONE_USER_PREFIX,
            spec.trust_zone
        );
        let uid = poll_dynamic_user_uid(deps.systemd, &trust_zone_user)?;
        tracing::debug!(
            runner = %spec.name,
            trust_zone = %spec.trust_zone,
            trust_zone_user = %trust_zone_user,
            uid,
            "DynamicUser UID resolved post-start; chowning narrow writable set"
        );
        // `DynamicUser` without a `/etc/passwd` entry: gid == uid
        // (systemd `src/core/dynamic-user.c:459-461` sets
        // `*ret_gid = num` in the no-passwd-entry branch).
        chown_and_tighten_runner_state(
            &runner_home,
            &runner_tmp,
            &ktstr_dir,
            has_ccache.then_some(ccache_dir.as_path()),
            &bin_dir,
            uid,
            uid,
            log,
        )?;
    } else {
        tracing::warn!(
            runner = %spec.name,
            "non-root apply: skipping post-start chown + mode tighten. \
             Runner started with wider apply-time modes (runner_home 0o777, \
             credentials 0o644). Re-run as root to apply production-grade \
             narrow DynamicUser-owned ownership + modes. Without root, the \
             runner unit cannot read credentials owned by root and credential \
             refresh will fail."
        );
    }

    // 9) Post-start netns verification. Belt-and-suspenders against
    //    a fail-open regression: if the runner has Netns mode but
    //    landed in the host netns, the systemd unit was misjoined
    //    and we abort the action. The runner's PID is read from
    //    `Service.MainPID` via `systemd.get_unit_property`.
    if matches!(
        spec.network.as_ref().map(|n| &n.spec.mode),
        Some(NetworkMode::Netns)
    ) {
        verify_runner_netns(&unit_name, deps.systemd)?;
    }

    Ok(ApplyOutcome::Created)
}

/// Poll `systemd.lookup_dynamic_user_by_name` with exponential
/// backoff (10ms doubling to 100ms cap, 5s total budget) until
/// the `DynamicUser` name allocates or the budget is exhausted.
///
/// systemd's Manager.LookupDynamicUserByName returns
/// `BUS_ERROR_NO_SUCH_DYNAMIC_USER` until the unit's `ExecStart`
/// child runs `dynamic_user_realize` and registers the name. The
/// poll budget accommodates the typical fork+realize latency
/// (tens of ms in practice) plus headroom for slow-start machines.
pub(super) fn poll_dynamic_user_uid(
    systemd: &dyn crate::systemd::Systemd,
    name: &str,
) -> crate::Result<u32> {
    poll_dynamic_user_uid_with_budget(systemd, name, std::time::Duration::from_secs(5))
}

/// Inner form of [`poll_dynamic_user_uid`] that accepts an explicit
/// budget. Production callers go through `poll_dynamic_user_uid`
/// (5s budget); tests use this directly with a small budget
/// (e.g. 50ms) to cover the timeout-failure error path without
/// stalling the test suite for the full production budget.
///
/// The 5s production default is documented in
/// `poll_dynamic_user_uid`'s doc-comment + on the static `Duration`
/// literal at the wrapper above. Don't change one without the
/// other — the wrapper's literal IS the production budget.
pub(super) fn poll_dynamic_user_uid_with_budget(
    systemd: &dyn crate::systemd::Systemd,
    name: &str,
    budget: std::time::Duration,
) -> crate::Result<u32> {
    use std::time::{Duration, Instant};
    let start = Instant::now();
    let mut interval = Duration::from_millis(10);
    let mut iterations: u32 = 0;
    loop {
        iterations += 1;
        if let Some(uid) = systemd.lookup_dynamic_user_by_name(name)? {
            // Observability per-CreateRunner. Lets operators
            // confirm the 5s budget and the doc-comment's
            // "tens of ms" typical claim against fleet
            // production data via `RUST_LOG=ghars=info`.
            // Subsequent runners in the same trust zone
            // typically resolve on iteration 1 (zero-iterations-
            // of-sleep) because the DynamicUser name is
            // already realized; only the first runner per
            // trust zone after a cold boot hits the
            // realize-side socket-population wait.
            let elapsed = start.elapsed();
            tracing::info!(
                trust_zone_user = %name,
                uid,
                iterations,
                elapsed_ms = elapsed.as_millis() as u64,
                "DynamicUser UID resolved via Manager.LookupDynamicUserByName"
            );
            return Ok(uid);
        }
        if start.elapsed() >= budget {
            return Err(GharsError::Apply {
                action: format!("resolve DynamicUser UID for {name}"),
                source: Box::new(GharsError::Systemd(
                    format!(
                        "Manager.LookupDynamicUserByName({name}) returned \
                         NoSuchDynamicUser for {budget:?} — the runner unit \
                         likely failed to start or systemd is unhealthy"
                    ),
                    "inspect `systemctl status ghars-runner@*.service` and \
                     the unit's journal. If the unit started successfully, \
                     this may be a systemd D-Bus latency issue — re-run \
                     apply and report if it persists."
                        .into(),
                )),
            });
        }
        std::thread::sleep(interval);
        interval = (interval * 2).min(Duration::from_millis(100));
    }
}

pub(super) fn execute_remove_runner(
    identity: &RunnerIdentity,
    deps: &Deps<'_>,
    paths: &Paths,
    log: &mut UndoLog,
) -> Result<ApplyOutcome> {
    let unit_name = crate::paths::runner_unit_name(&identity.name);
    let runner_home = paths.runner_home(&identity.trust_zone, &identity.name);

    // 1) Stop the unit. systemd's `StopUnit` is idempotent — non-running
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
    //     `RemoveRunner` does not carry the original `NetworkSpec`, so the
    //     teardown is unconditional rather than mode-gated.
    teardown_netns_artifacts(&identity.name, deps, paths, log)?;

    // 2) Mint a removal token + invoke `config.sh remove` so GitHub
    //    deregisters the runner. `RealConfigShell::run_remove` tolerates
    //    "already removed" exit codes.
    //
    //    Orphan branch: when `plan.rs` synthesises a `RemoveRunner` from
    //    `actual.orphans`, `identity.auth_name` and `identity.url` are
    //    empty (the orphan synthesis loop in `plan_from`) because the
    //    orphan has no `[[runner]]` block in the desired config and
    //    discovery doesn't reach the auth registry. Without those,
    //    `mint_token` would error with
    //    `auth source "" referenced by runner is not in the registry`
    //    and the local cleanup (unit + state dir) would never run —
    //    leaving the host in a permanently-orphaned state.
    //
    //    Skipping the deregister step is the intentional trade-off
    //    (documented in `plan.rs` orphan handling): the runner stays
    //    registered server-side until the operator either reinstates
    //    its `[[runner]]` block (so a future apply has full identity)
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
        // Best-effort deregister: tolerate missing bin dir (stale
        // runner from a failed apply) and `config.sh remove` failure
        // (runner already deleted from GitHub UI). The host-local
        // cleanup below runs regardless.
        match find_active_bin_dir(&runner_home) {
            Ok(remove_bin_dir) => {
                if let Err(e) = deps.config_shell.run_remove(&ConfigShellCtx {
                    runner_home: &runner_home,
                    bin_dir: &remove_bin_dir,
                    name: &identity.name,
                    url: &identity.url,
                    labels: &[],
                    token: &token.value,
                }) {
                    tracing::warn!(
                        runner = %identity.name,
                        error = %e,
                        "config.sh remove failed; runner may already be \
                         deregistered on GitHub. Continuing with local cleanup."
                    );
                }
            }
            Err(e) => {
                tracing::warn!(
                    runner = %identity.name,
                    error = %e,
                    "no bin dir with config.sh found; skipping GitHub \
                     deregister. Runner may still be registered server-side."
                );
            }
        }
        // No `UndoStep` for `run_remove`: it is itself the inverse of
        // `GitHubRegistration`. Recording `GitHubRegistration` here would
        // attempt to re-register on rollback — wrong semantically and
        // not recoverable (`config.sh register` requires a fresh token
        // mint and recreates credentials, which the upstream Remove
        // path just intentionally tore down). The operator restores
        // the runner by reinstating its `[[runner]]` block + apply.
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

    // No `userdel` step. The runner unit's DynamicUser-allocated UID is
    // released by systemd on unit stop; nothing was written to
    // `/etc/passwd` / `/etc/group`, so there is nothing to clean up.

    // The end-of-apply `daemon_reload` picks up the unit file removal.
    Ok(ApplyOutcome::Removed)
}
