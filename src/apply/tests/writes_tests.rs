//! Tests for `apply::writes` (atomic file writes + read-then-write
//! helpers + the TempFileGuard drop guard).

use std::os::unix::fs::PermissionsExt;

use camino::Utf8PathBuf;

use super::super::undo::{UndoLog, UndoStep};
use super::super::writes::{
    TempFileGuard, read_then_write_if_changed, write_record_undo, write_root_owned,
};

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
