//! `apply.lock` POSIX advisory file lock and PID liveness probe.
//!
//! [`acquire_lock`] is called at the top of [`super::orchestrator::apply`]
//! before any side effects. The returned [`ApplyLock`] holds the
//! file open for the duration of the apply; Drop releases it.

use std::fs::{self, File, OpenOptions};
use std::io::{Read, Write};
use std::os::unix::fs::{OpenOptionsExt, PermissionsExt};
use std::path::Path;

use camino::{Utf8Path, Utf8PathBuf};
use fs4::FileExt;

use crate::Result;
use crate::error::GharsError;
use crate::paths::Paths;

/// Held POSIX advisory file lock plus the handle that owns it.
///
/// Drop releases via fs4's `unlock` (which is also released by the
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
        // Release the flock. The kernel also releases it on process
        // exit if Drop never runs. No truncate here: the next
        // `acquire_lock` calls `write_pid_to_lock` which truncates
        // before writing, so any leftover PID is overwritten anyway.
        let _ = FileExt::unlock(&self.file);
    }
}

/// Acquire `<runtime_dir>/apply.lock` exclusively, writing this
/// process's PID into the lock file on success.
///
/// The lock file is opened with mode 0600 and `O_CREAT`. fs4 uses
/// `flock(2)` on Linux via rustix; the lock is advisory and released
/// on Drop or process exit.
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

    match FileExt::try_lock(&file) {
        Ok(()) => {}
        Err(fs4::TryLockError::WouldBlock) => {
            // SEC-19: probe `/proc/<pid>/status`. If the file doesn't
            // exist the PID has exited without releasing the flock
            // (e.g. `kill -9 ghars` mid-apply leaves the lock file on
            // disk because the kernel auto-released the flock but the
            // file lingers). Mark as stale so the error hint tells the
            // operator to remove `apply.lock` rather than wait for a
            // process that's already gone. `pid <= 0` is treated as
            // unparseable / missing PID: we still surface the error
            // but flag it stale so the operator inspects the file.
            let pid = read_pid_from_lock(&lock_path).unwrap_or(0);
            let stale = pid <= 0 || !pid_is_alive(pid);
            return Err(GharsError::ApplyLocked {
                pid,
                path: lock_path.to_string(),
                stale,
            });
        }
        Err(fs4::TryLockError::Error(e)) => return Err(GharsError::Io(e)),
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
pub(super) fn eacces_hint(e: &std::io::Error, path: &Utf8Path, what: &str) -> GharsError {
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

pub(super) fn read_pid_from_lock(path: &Utf8Path) -> Option<i32> {
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
