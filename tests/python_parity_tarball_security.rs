//! Tarball extraction security tests.
//!
//! 1. Python parity (lines 2815-2937): basic + path-traversal + symlink/
//!    hardlink escape + setuid strip + char/block/fifo rejection.
//!    These mirror the Python tarball test set; the unit tests in
//!    `extract.rs` already cover most cases via the `safe_member_filter`
//!    surface, but the Python suite framed several at the
//!    `extract_tarball` level (whole-archive errors). The tests below
//!    exercise the same end-to-end path.
//!
//! 2. Adversary's NEW.B2 finding — symlink-after-extract attack: an
//!    attacker tarball contains:
//!      a. regular file `foo`,
//!      b. symlink `foo/bar` → `../../../etc/passwd`,
//!      c. regular file `foo/bar/something`.
//!    Without per-component ELOOP enforcement on the extract side, step
//!    (c) traverses through the symlink (b) and writes outside the
//!    extraction root.
//!
//!    The current `extract_tarball` implementation calls `archive.set_
//!    overwrite(true)` and relies on `safe_member_filter` to reject
//!    individual entries, plus `tar::Entry::unpack_in` to refuse
//!    out-of-root paths. We test that the FULL chained attack is
//!    rejected: either the symlink entry itself fails the safe-member
//!    filter (because the link target contains `..`), OR a subsequent
//!    write through the symlink is blocked by the unpacker — but never
//!    both written and written outside the extraction root.

#![allow(clippy::unwrap_used, clippy::expect_used)]

use camino::Utf8PathBuf;
use ghars::extract::extract_tarball;
use std::fs;
use std::io::Write;

fn build_tar_gz(entries: &[(&[u8], tar::EntryType, &[u8], u32, &[u8])]) -> Vec<u8> {
    let mut tar_buf: Vec<u8> = Vec::new();
    {
        let mut builder = tar::Builder::new(&mut tar_buf);
        for (name, kind, link, mode, contents) in entries {
            let mut header = tar::Header::new_old();
            header.set_size(contents.len() as u64);
            header.set_mode(*mode);
            header.set_uid(0);
            header.set_gid(0);
            header.set_mtime(0);
            header.set_entry_type(*kind);
            header.as_old_mut().name[..name.len()].copy_from_slice(name);
            if !link.is_empty() {
                header.set_link_name_literal(link).unwrap();
            }
            header.set_cksum();
            builder.append(&header, *contents).unwrap();
        }
        builder.finish().unwrap();
    }
    let mut gz_buf: Vec<u8> = Vec::new();
    {
        let mut encoder = flate2::write::GzEncoder::new(&mut gz_buf, flate2::Compression::fast());
        encoder.write_all(&tar_buf).unwrap();
        encoder.finish().unwrap();
    }
    gz_buf
}

fn write_tar(tmp: &tempfile::TempDir, name: &str, gz: &[u8]) -> Utf8PathBuf {
    let p = Utf8PathBuf::from_path_buf(tmp.path().join(name)).unwrap();
    fs::write(&p, gz).unwrap();
    p
}

fn dest_dir(tmp: &tempfile::TempDir, name: &str) -> Utf8PathBuf {
    let d = Utf8PathBuf::from_path_buf(tmp.path().join(name)).unwrap();
    fs::create_dir(&d).unwrap();
    d
}

#[test]
fn extract_tarball_basic_runner_layout() {
    // Python parity: test_extract_tarball_basic.
    let tmp = tempfile::tempdir().unwrap();
    let gz = build_tar_gz(&[
        (
            b"runner/config.sh",
            tar::EntryType::Regular,
            b"",
            0o755,
            b"#!/bin/bash\n",
        ),
        (
            b"runner/bin/Runner.Listener",
            tar::EntryType::Regular,
            b"",
            0o755,
            b"elf binary",
        ),
    ]);
    let tarball = write_tar(&tmp, "t.tar.gz", &gz);
    let out = dest_dir(&tmp, "out");
    extract_tarball(&tarball, &out).unwrap();
    assert_eq!(
        fs::read(out.join("runner/config.sh")).unwrap(),
        b"#!/bin/bash\n"
    );
    assert_eq!(
        fs::read(out.join("runner/bin/Runner.Listener")).unwrap(),
        b"elf binary"
    );
}

#[test]
fn extract_tarball_rejects_absolute_path() {
    // Python parity: test_extract_tarball_rejects_absolute_path.
    let tmp = tempfile::tempdir().unwrap();
    let gz = build_tar_gz(&[(b"/etc/passwd", tar::EntryType::Regular, b"", 0o644, b"x")]);
    let tarball = write_tar(&tmp, "t.tar.gz", &gz);
    let out = dest_dir(&tmp, "out");
    let err = extract_tarball(&tarball, &out).unwrap_err();
    assert!(err.to_string().contains("unsafe member path"));
    assert!(!std::path::Path::new("/etc/passwd-test-marker").exists());
}

#[test]
fn extract_tarball_rejects_path_traversal() {
    // Python parity: test_extract_tarball_rejects_path_traversal.
    let tmp = tempfile::tempdir().unwrap();
    let gz = build_tar_gz(&[(b"../evil", tar::EntryType::Regular, b"", 0o644, b"x")]);
    let tarball = write_tar(&tmp, "t.tar.gz", &gz);
    let out = dest_dir(&tmp, "out");
    let err = extract_tarball(&tarball, &out).unwrap_err();
    assert!(err.to_string().contains("unsafe member path"));
    // No file landed outside the extraction root.
    assert!(!tmp.path().join("evil").exists());
}

#[test]
fn extract_tarball_rejects_symlink_escape() {
    // Python parity: test_extract_tarball_rejects_symlink_escape.
    let tmp = tempfile::tempdir().unwrap();
    let gz = build_tar_gz(&[(
        b"bad-symlink",
        tar::EntryType::Symlink,
        b"/etc/passwd",
        0o777,
        b"",
    )]);
    let tarball = write_tar(&tmp, "t.tar.gz", &gz);
    let out = dest_dir(&tmp, "out");
    let err = extract_tarball(&tarball, &out).unwrap_err();
    assert!(
        err.to_string().contains("absolute link target"),
        "{err}"
    );
    assert!(!out.join("bad-symlink").exists());
}

#[test]
fn extract_tarball_rejects_hardlink_escape() {
    // Python parity: test_extract_tarball_rejects_hardlink_escape.
    let tmp = tempfile::tempdir().unwrap();
    let gz = build_tar_gz(&[
        (b"real", tar::EntryType::Regular, b"", 0o644, b""),
        (
            b"bad-hardlink",
            tar::EntryType::Link,
            b"../../../etc/passwd",
            0o644,
            b"",
        ),
    ]);
    let tarball = write_tar(&tmp, "t.tar.gz", &gz);
    let out = dest_dir(&tmp, "out");
    let err = extract_tarball(&tarball, &out).unwrap_err();
    assert!(err.to_string().contains("unsafe link target"));
}

#[test]
fn extract_tarball_strips_setuid_setgid_bits() {
    // Python parity: test_extract_tarball_strips_setuid.
    use std::os::unix::fs::PermissionsExt;
    let tmp = tempfile::tempdir().unwrap();
    // 0o4755 = setuid + rwxr-xr-x.
    let gz = build_tar_gz(&[(
        b"runner/suid-bin",
        tar::EntryType::Regular,
        b"",
        0o4755,
        b"ELF",
    )]);
    let tarball = write_tar(&tmp, "t.tar.gz", &gz);
    let out = dest_dir(&tmp, "out");
    extract_tarball(&tarball, &out).unwrap();
    let bin = out.join("runner/suid-bin");
    assert!(bin.is_file());
    let mode = fs::metadata(&bin).unwrap().permissions().mode();
    assert_eq!(mode & 0o4000, 0, "setuid bit must be stripped");
    assert_eq!(mode & 0o2000, 0, "setgid bit must be stripped");
}

#[test]
fn extract_tarball_rejects_fifo_member() {
    // Python parity: test_extract_tarball_rejects_fifo_member.
    let tmp = tempfile::tempdir().unwrap();
    let gz = build_tar_gz(&[(b"runner/fifo", tar::EntryType::Fifo, b"", 0o644, b"")]);
    let tarball = write_tar(&tmp, "t.tar.gz", &gz);
    let out = dest_dir(&tmp, "out");
    let err = extract_tarball(&tarball, &out).unwrap_err();
    assert!(err.to_string().contains("unsupported special file"));
}

#[test]
fn extract_tarball_rejects_chrdev_member() {
    // Python parity: test_extract_tarball_rejects_chrdev_member.
    let tmp = tempfile::tempdir().unwrap();
    let gz = build_tar_gz(&[(b"runner/nullish", tar::EntryType::Char, b"", 0o644, b"")]);
    let tarball = write_tar(&tmp, "t.tar.gz", &gz);
    let out = dest_dir(&tmp, "out");
    let err = extract_tarball(&tarball, &out).unwrap_err();
    assert!(err.to_string().contains("unsupported special file"));
}

#[test]
fn extract_tarball_rejects_blkdev_member() {
    // Python parity: test_extract_tarball_rejects_blkdev_member.
    let tmp = tempfile::tempdir().unwrap();
    let gz = build_tar_gz(&[(b"runner/disk", tar::EntryType::Block, b"", 0o644, b"")]);
    let tarball = write_tar(&tmp, "t.tar.gz", &gz);
    let out = dest_dir(&tmp, "out");
    let err = extract_tarball(&tarball, &out).unwrap_err();
    assert!(err.to_string().contains("unsupported special file"));
}

// -- Adversary's NEW.B2 finding: symlink-after-extract attack chain ----

#[test]
fn extract_tarball_rejects_symlink_after_extract_attack() {
    // The attack chain: (a) extract a regular file `foo/marker`,
    // (b) extract a symlink `foo/bar` → `../../../tmp/escape`,
    // (c) extract a regular file `foo/bar/something`.
    //
    // The CRITICAL invariant: nothing must land outside the extraction
    // root, regardless of which entry trips the safety check first.
    //
    // The current safe_member_filter rejects link targets containing
    // `..`, which catches step (b) before (c) runs. This test pins
    // that behavior — and additionally verifies the "outside the root"
    // marker file does NOT exist after the extract attempt.
    let tmp = tempfile::tempdir().unwrap();
    let attack_target_path = tmp.path().join("escape-marker");
    let attack_target_str = attack_target_path.to_string_lossy().into_owned();

    // The link target uses `..` traversal that the safe-member filter
    // must reject. We craft `../../escape-marker` so the resolved path
    // would land inside `tmp` — close enough to make the assertion
    // meaningful but never written.
    let traversal_target = b"../../escape-marker";

    let gz = build_tar_gz(&[
        // Step (a) — innocent-looking regular file at `foo/marker`.
        (
            b"foo/marker",
            tar::EntryType::Regular,
            b"",
            0o644,
            b"innocent",
        ),
        // Step (b) — the attack symlink. Path itself is safe; the
        // LINK TARGET contains `..` which our filter rejects.
        (
            b"foo/bar",
            tar::EntryType::Symlink,
            traversal_target,
            0o777,
            b"",
        ),
        // Step (c) — write through the would-be symlink. Never runs
        // because (b) trips the filter first; if the filter ever
        // regresses, this entry would write outside the root.
        (
            b"foo/bar/something",
            tar::EntryType::Regular,
            b"",
            0o644,
            b"escaped",
        ),
    ]);
    let tarball = write_tar(&tmp, "attack.tar.gz", &gz);
    let out = dest_dir(&tmp, "out");

    let err = extract_tarball(&tarball, &out).unwrap_err();
    let msg = err.to_string();
    // We accept either failure mode the implementation surfaces today:
    // the link-target filter (`unsafe link target`), or the unpacker's
    // path-normalization rejection. What we DON'T accept is silent
    // success.
    assert!(
        msg.contains("unsafe link target")
            || msg.contains("rejected by tar")
            || msg.contains("unsafe member path"),
        "extract must reject the symlink-after-extract attack: {msg}"
    );

    // The marker MUST NOT exist outside the extraction root. Even if
    // future implementations switch to per-entry openat() with
    // O_NOFOLLOW per component, the invariant holds.
    assert!(
        !std::path::Path::new(&attack_target_str).exists(),
        "attacker should not have written outside extraction root"
    );
    // And `foo/bar` must not be a symlink inside the dest (the filter
    // refused to extract it).
    let bar = out.join("foo/bar");
    if bar.exists() {
        let meta = fs::symlink_metadata(&bar).unwrap();
        assert!(
            !meta.file_type().is_symlink(),
            "filter must reject the symlink before it lands"
        );
    }
}

#[test]
fn extract_tarball_rejects_symlink_to_relative_dotdot() {
    // Same family as above but minimal: a single symlink with `..` in
    // the target. The filter must reject without writing the link.
    let tmp = tempfile::tempdir().unwrap();
    let gz = build_tar_gz(&[(
        b"link",
        tar::EntryType::Symlink,
        b"../../etc/shadow",
        0o777,
        b"",
    )]);
    let tarball = write_tar(&tmp, "t.tar.gz", &gz);
    let out = dest_dir(&tmp, "out");
    let err = extract_tarball(&tarball, &out).unwrap_err();
    assert!(err.to_string().contains("unsafe link target"));
    assert!(!out.join("link").exists());
}

#[test]
fn extract_tarball_rejects_overlapping_symlink_then_regular_file() {
    // Variant of the attack: file written first, then a same-named
    // symlink overwrites it (set_overwrite=true is enabled in extract.rs
    // for this reason). We assert the filter still catches the symlink.
    let tmp = tempfile::tempdir().unwrap();
    let gz = build_tar_gz(&[
        (b"foo", tar::EntryType::Regular, b"", 0o644, b"data"),
        (b"foo", tar::EntryType::Symlink, b"/etc/passwd", 0o777, b""),
    ]);
    let tarball = write_tar(&tmp, "t.tar.gz", &gz);
    let out = dest_dir(&tmp, "out");
    let err = extract_tarball(&tarball, &out).unwrap_err();
    // Same-named symlink overwrite uses an ABSOLUTE target
    // (`/etc/passwd`), so the filter rejects with "absolute link target".
    assert!(
        err.to_string().contains("absolute link target"),
        "{err}"
    );
}

#[test]
fn extract_tarball_handles_directory_entries() {
    // Sanity: a tarball with explicit directory entries before files
    // inside them must extract successfully. The Python tool tested
    // this implicitly via test_extract_tarball_basic; we add an
    // explicit directory-entry case here.
    let tmp = tempfile::tempdir().unwrap();
    let gz = build_tar_gz(&[
        (b"runner/", tar::EntryType::Directory, b"", 0o755, b""),
        (b"runner/bin/", tar::EntryType::Directory, b"", 0o755, b""),
        (
            b"runner/bin/run.sh",
            tar::EntryType::Regular,
            b"",
            0o755,
            b"#!/bin/sh\n",
        ),
    ]);
    let tarball = write_tar(&tmp, "t.tar.gz", &gz);
    let out = dest_dir(&tmp, "out");
    extract_tarball(&tarball, &out).unwrap();
    assert!(out.join("runner/bin/run.sh").is_file());
}
