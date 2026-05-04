//! Tests for `apply::lock` (apply.lock acquisition + PID liveness).

use std::fs::{File, OpenOptions};
use std::io::Read;
use std::os::unix::fs::PermissionsExt;

use camino::Utf8Path;
use fs2::FileExt;

use crate::error::GharsError;

use super::super::lock::{acquire_lock, eacces_hint, pid_is_alive};
use super::common::make_paths;

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

/// Synthetic `PermissionDenied` `io::Error` must be wrapped as
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

/// Any non-PermissionDenied `io::Error` must pass through as
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
/// applies on `O_CREAT`, so opening an existing 0o644 file would
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
