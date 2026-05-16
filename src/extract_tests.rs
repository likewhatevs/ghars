use super::*;
use std::cell::Cell;
use std::io::Cursor;

thread_local! {
    /// `cfg(test)` test seam: when `Some(errno)`, the seam
    /// helper [`renameat2_exchange_with_test_seam`] returns that errno
    /// synthetically instead of invoking the real syscall.
    /// Per-thread storage means parallel test threads each have
    /// their own forcing — no Mutex needed. Tests opt in via the
    /// [`ForcedRenameAt2Errno`] RAII guard, which sets and
    /// clears the cell scoped to the test body.
    pub(super) static FORCED_RENAMEAT2_ERRNO:
        Cell<Option<nix::errno::Errno>> = const { Cell::new(None) };
}

/// RAII guard: sets [`FORCED_RENAMEAT2_ERRNO`] on the current
/// thread on construction and clears it on Drop. Tests use
/// `let _g = ForcedRenameAt2Errno::new(Errno::EINVAL);` to
/// scope the forcing to a single test body. Drop runs even on
/// panic, so a failing test does not leak the forcing into
/// later tests on the same thread.
struct ForcedRenameAt2Errno;

impl ForcedRenameAt2Errno {
    fn new(e: nix::errno::Errno) -> Self {
        FORCED_RENAMEAT2_ERRNO.with(|c| c.set(Some(e)));
        Self
    }
}

impl Drop for ForcedRenameAt2Errno {
    fn drop(&mut self) {
        FORCED_RENAMEAT2_ERRNO.with(|c| c.set(None));
    }
}

/// Build an in-memory `.tar.gz` from a list of synthetic entries.
/// Each entry is `(name_bytes, EntryType, link_target_bytes_or_empty,
/// mode, contents)`.
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

fn first_entry_filter(gz_bytes: &[u8]) -> Result<FilterDecision> {
    let cursor = Cursor::new(gz_bytes.to_vec());
    let gz = flate2::read::GzDecoder::new(cursor);
    let mut archive = tar::Archive::new(gz);
    let mut entries = archive.entries().unwrap();
    let entry = entries.next().expect("at least one entry").unwrap();
    safe_member_filter(&entry)
}

#[test]
fn filter_accepts_regular_file() {
    let gz = build_tar_gz(&[(
        b"actions-runner/runsvc.sh",
        tar::EntryType::Regular,
        b"",
        0o755,
        b"hi",
    )]);
    let decision = first_entry_filter(&gz).unwrap();
    assert_eq!(decision, FilterDecision::Allow);
}

#[test]
fn filter_accepts_setuid_setgid_sticky_modes() {
    // 0o7777 = setuid + setgid + sticky + rwxrwxrwx. The tar crate's
    // unprivileged unpack strips setuid/setgid via
    // `set_preserve_permissions(false)`-style defaults — see
    // tar-rs's permissions masking logic in `entry.rs::_set_perms`.
    // The filter is authoritative for path/typeflag rejection only.
    let gz = build_tar_gz(&[(b"runsvc.sh", tar::EntryType::Regular, b"", 0o7777, b"")]);
    let decision = first_entry_filter(&gz).unwrap();
    assert_eq!(decision, FilterDecision::Allow);
}

#[test]
fn filter_rejects_absolute_member_path() {
    let gz = build_tar_gz(&[(b"/etc/passwd", tar::EntryType::Regular, b"", 0o644, b"x")]);
    let err = first_entry_filter(&gz).unwrap_err();
    let msg = err.to_string();
    assert!(msg.contains("unsafe member path"), "msg={msg}");
    assert!(msg.contains("/etc/passwd"), "msg={msg}");
}

#[test]
fn filter_rejects_parent_dir_traversal() {
    let gz = build_tar_gz(&[(b"../etc/passwd", tar::EntryType::Regular, b"", 0o644, b"x")]);
    let err = first_entry_filter(&gz).unwrap_err();
    assert!(err.to_string().contains("unsafe member path"));
}

#[test]
fn filter_rejects_dotdot_inside_member_path() {
    let gz = build_tar_gz(&[(b"a/../b", tar::EntryType::Regular, b"", 0o644, b"x")]);
    let err = first_entry_filter(&gz).unwrap_err();
    assert!(err.to_string().contains("unsafe member path"));
}

#[test]
fn filter_rejects_absolute_symlink_target() {
    let gz = build_tar_gz(&[(b"link", tar::EntryType::Symlink, b"/etc/shadow", 0o777, b"")]);
    let err = first_entry_filter(&gz).unwrap_err();
    assert!(err.to_string().contains("absolute link target"), "{err}");
}

#[test]
fn filter_rejects_dotdot_symlink_target() {
    let gz = build_tar_gz(&[(
        b"link",
        tar::EntryType::Symlink,
        b"../../etc/shadow",
        0o777,
        b"",
    )]);
    let err = first_entry_filter(&gz).unwrap_err();
    assert!(err.to_string().contains("unsafe link target"));
}

#[test]
fn filter_rejects_absolute_hardlink_target() {
    let gz = build_tar_gz(&[(b"hl", tar::EntryType::Link, b"/etc/passwd", 0o644, b"")]);
    let err = first_entry_filter(&gz).unwrap_err();
    assert!(err.to_string().contains("absolute link target"), "{err}");
}

#[test]
fn filter_rejects_char_device() {
    let gz = build_tar_gz(&[(b"dev_zero", tar::EntryType::Char, b"", 0o644, b"")]);
    let err = first_entry_filter(&gz).unwrap_err();
    let msg = err.to_string();
    assert!(msg.contains("unsupported special file"), "msg={msg}");
}

#[test]
fn filter_rejects_block_device() {
    let gz = build_tar_gz(&[(b"dev_block", tar::EntryType::Block, b"", 0o644, b"")]);
    let err = first_entry_filter(&gz).unwrap_err();
    assert!(err.to_string().contains("unsupported special file"));
}

#[test]
fn filter_rejects_fifo() {
    let gz = build_tar_gz(&[(b"fifo", tar::EntryType::Fifo, b"", 0o644, b"")]);
    let err = first_entry_filter(&gz).unwrap_err();
    assert!(err.to_string().contains("unsupported special file"));
}

#[test]
fn extract_tarball_unpacks_safe_archive() {
    let tmp = tempfile::tempdir().unwrap();
    let tarball_path = Utf8PathBuf::from_path_buf(tmp.path().join("safe.tar.gz")).unwrap();
    let gz = build_tar_gz(&[
        (
            b"runner/run.sh",
            tar::EntryType::Regular,
            b"",
            0o755,
            b"#!/bin/sh\nexec true\n",
        ),
        (
            b"runner/README",
            tar::EntryType::Regular,
            b"",
            0o644,
            b"hello",
        ),
    ]);
    fs::write(&tarball_path, gz).unwrap();

    let dest = Utf8PathBuf::from_path_buf(tmp.path().join("dest")).unwrap();
    extract_tarball(&tarball_path, &dest).unwrap();
    assert!(dest.join("runner/run.sh").exists());
    assert_eq!(
        fs::read_to_string(dest.join("runner/README")).unwrap(),
        "hello"
    );
}

#[test]
fn extract_tarball_aborts_on_unsafe_entry() {
    let tmp = tempfile::tempdir().unwrap();
    let tarball_path = Utf8PathBuf::from_path_buf(tmp.path().join("evil.tar.gz")).unwrap();
    let gz = build_tar_gz(&[
        (b"good.txt", tar::EntryType::Regular, b"", 0o644, b"ok"),
        (
            b"escape",
            tar::EntryType::Symlink,
            b"/etc/shadow",
            0o777,
            b"",
        ),
    ]);
    fs::write(&tarball_path, gz).unwrap();

    let dest = Utf8PathBuf::from_path_buf(tmp.path().join("dest")).unwrap();
    let err = extract_tarball(&tarball_path, &dest).unwrap_err();
    assert!(err.to_string().contains("absolute link target"), "{err}");
}

#[test]
fn sha256_of_known_vector() {
    let tmp = tempfile::tempdir().unwrap();
    let path = Utf8PathBuf::from_path_buf(tmp.path().join("vec.bin")).unwrap();
    fs::write(&path, b"hello world").unwrap();
    // SHA-256 of "hello world".
    let expected = "b94d27b9934d3e08a52e52d7da7dabfac484efe37a5380ee9088f7ace2efcde9";
    assert_eq!(sha256_of(&path).unwrap(), expected);
}

#[test]
fn sha256_streaming_handles_multi_chunk_input() {
    let tmp = tempfile::tempdir().unwrap();
    let path = Utf8PathBuf::from_path_buf(tmp.path().join("big.bin")).unwrap();
    // 200 KiB so we exercise multiple 64KiB reads.
    let body: Vec<u8> = (0..200 * 1024).map(|i| (i % 251) as u8).collect();
    fs::write(&path, &body).unwrap();
    let mut hasher = Sha256::new();
    hasher.update(&body);
    let expected = hex::encode(hasher.finalize());
    assert_eq!(sha256_of(&path).unwrap(), expected);
}

#[test]
fn download_and_verify_deletes_file_on_mismatch() {
    let mut server = mockito::Server::new();
    let body = b"corrupt";
    let m = server
        .mock("GET", "/runner.tar.gz")
        .with_status(200)
        .with_body(body)
        .create();

    let tmp = tempfile::tempdir().unwrap();
    let dest = Utf8PathBuf::from_path_buf(tmp.path().join("runner.tar.gz")).unwrap();
    let url = format!("{}/runner.tar.gz", server.url());

    let bogus_sha = "0".repeat(64);
    let err = download_and_verify(&url, &dest, &bogus_sha, Duration::from_secs(10)).unwrap_err();
    match err {
        GharsError::Sha256Mismatch { .. } => {}
        other => panic!("expected Sha256Mismatch, got {other:?}"),
    }
    assert!(!dest.exists(), "dest should be unlinked on mismatch");
    m.assert();
}

#[test]
fn download_and_verify_returns_sha256_mismatch_with_path_field_set() {
    // Pin the structured fields the warn path consumes —
    // `path: dest.to_string()` is what the operator sees in the
    // warn breadcrumb when the unlink itself fails. A
    // regression that drops the path field would orphan the
    // diagnostic.
    let mut server = mockito::Server::new();
    let body = b"corrupt-body";
    let m = server
        .mock("GET", "/runner-path.tar.gz")
        .with_status(200)
        .with_body(body)
        .create();
    let tmp = tempfile::tempdir().unwrap();
    let dest = Utf8PathBuf::from_path_buf(tmp.path().join("runner-path.tar.gz")).unwrap();
    let url = format!("{}/runner-path.tar.gz", server.url());
    let bogus_sha = "f".repeat(64);
    let err = download_and_verify(&url, &dest, &bogus_sha, Duration::from_secs(10)).unwrap_err();
    match err {
        GharsError::Sha256Mismatch { path, .. } => {
            assert_eq!(
                path,
                dest.to_string(),
                "Sha256Mismatch.path must surface the dest the operator sees"
            );
        }
        other => panic!("expected Sha256Mismatch, got {other:?}"),
    }
    m.assert();
}

#[test]
fn download_and_verify_accepts_uppercase_expected() {
    let mut server = mockito::Server::new();
    let body = b"hello world";
    let m = server
        .mock("GET", "/x")
        .with_status(200)
        .with_body(body)
        .create();

    let tmp = tempfile::tempdir().unwrap();
    let dest = Utf8PathBuf::from_path_buf(tmp.path().join("x")).unwrap();
    let url = format!("{}/x", server.url());
    // Uppercase hex digest; comparison is case-insensitive.
    let expected_upper = "B94D27B9934D3E08A52E52D7DA7DABFAC484EFE37A5380EE9088F7ACE2EFCDE9";
    download_and_verify(&url, &dest, expected_upper, Duration::from_secs(10)).unwrap();
    assert!(dest.exists());
    m.assert();
}

#[test]
fn http_download_propagates_http_error() {
    let mut server = mockito::Server::new();
    let m = server.mock("GET", "/nope").with_status(404).create();
    let tmp = tempfile::tempdir().unwrap();
    let dest = Utf8PathBuf::from_path_buf(tmp.path().join("nope")).unwrap();
    let url = format!("{}/nope", server.url());

    let err = http_download(&url, &dest, Duration::from_secs(10)).unwrap_err();
    match err {
        GharsError::Tarball(msg, hint) => {
            assert!(msg.contains("download failed"), "msg={msg}");
            // http_download error sites pre-date the structured-hint
            // surface; they encode operator guidance into the message
            // body. The hint field stays None so the message keeps
            // its existing single-line shape and log-scrape behavior.
            assert!(
                hint.is_none(),
                "http_download Tarball variants must keep hint=None; got: {hint:?}"
            );
            assert!(
                msg.contains("download failed (404 Not Found)"),
                "msg must use parenthetical `({{status}}):` format with full StatusCode Display (parity with github.rs); got: {msg}"
            );
            assert!(
                msg.ends_with(&format!(": {url}")),
                "msg must end with ': {{url}}' for log-parser parity; got: {msg}"
            );
        }
        other => panic!("expected Tarball, got {other:?}"),
    }
    m.assert();
}

/// Cross-surface parity pin: both `extract.rs::http_download` and
/// `github.rs::fetch_latest_release_at` must produce the same
/// `(404 Not Found)` parenthetical for an HTTP error status, so a
/// single log-scrape rule covers both download surfaces. Drives a
/// 404 through each surface against its own mockito server and
/// asserts both error messages contain the identical parenthetical
/// substring. A regression that splits the format on either side
/// (e.g. extract.rs reverting to "HTTP {chain}" or github.rs
/// switching to numeric-only `(404)`) surfaces here.
#[test]
fn http_status_parenthetical_is_identical_across_extract_and_github() {
    const PARENTHETICAL: &str = "(404 Not Found)";

    let mut extract_server = mockito::Server::new();
    let extract_mock = extract_server
        .mock("GET", "/nope")
        .with_status(404)
        .create();
    let extract_tmp = tempfile::tempdir().unwrap();
    let extract_dest = Utf8PathBuf::from_path_buf(extract_tmp.path().join("nope")).unwrap();
    let extract_url = format!("{}/nope", extract_server.url());
    let extract_err =
        http_download(&extract_url, &extract_dest, Duration::from_secs(10)).unwrap_err();
    let extract_msg = match extract_err {
        GharsError::Tarball(msg, _) => msg,
        other => panic!("expected Tarball, got {other:?}"),
    };
    extract_mock.assert();

    let mut github_server = mockito::Server::new();
    let github_mock = github_server
        .mock("GET", "/repos/actions/runner/releases/latest")
        .with_status(404)
        .with_body("not found")
        .create();
    let github_url = format!(
        "{}/repos/actions/runner/releases/latest",
        github_server.url()
    );
    let client = crate::github::build_blocking_client(None).unwrap();
    let github_err =
        crate::github::fetch_latest_release_at(&client, &github_url, crate::config::Arch::X86_64)
            .unwrap_err();
    let github_msg = match github_err {
        GharsError::GitHub(msg, _) => msg,
        other => panic!("expected GitHub, got {other:?}"),
    };
    github_mock.assert();

    assert!(
        extract_msg.starts_with("download failed (404 Not Found):"),
        "extract.rs msg must start with 'download failed (404 Not Found):'; got: {extract_msg}"
    );
    assert!(
        github_msg.starts_with("GitHub API request failed (404 Not Found):"),
        "github.rs msg must start with 'GitHub API request failed (404 Not Found):'; got: {github_msg}"
    );
    // Both surfaces emit the same `(404 Not Found)` parenthetical
    // — log-scrape regex parity.
    assert!(extract_msg.contains(PARENTHETICAL));
    assert!(github_msg.contains(PARENTHETICAL));
}

#[test]
fn verify_local_tarball_rejects_symlink() {
    let tmp = tempfile::tempdir().unwrap();
    let target = Utf8PathBuf::from_path_buf(tmp.path().join("real.tar.gz")).unwrap();
    fs::write(&target, b"x").unwrap();
    let link = Utf8PathBuf::from_path_buf(tmp.path().join("link.tar.gz")).unwrap();
    std::os::unix::fs::symlink(&target, &link).unwrap();

    let err = verify_local_tarball(&link).unwrap_err();
    assert!(err.to_string().contains("symlink"));
}

#[test]
fn verify_local_tarball_rejects_missing() {
    let tmp = tempfile::tempdir().unwrap();
    let path = Utf8PathBuf::from_path_buf(tmp.path().join("nope")).unwrap();
    let err = verify_local_tarball(&path).unwrap_err();
    // Post-SEC-16: open(O_NOFOLLOW) returns ENOENT; the message
    // surfaces as "cannot be opened: <path>: No such file ...".
    let msg = err.to_string();
    assert!(
        msg.contains("cannot be opened") && msg.contains("nope"),
        "expected open-failure message; got: {msg}"
    );
}

#[test]
fn verify_local_tarball_accepts_regular_file() {
    let tmp = tempfile::tempdir().unwrap();
    let path = Utf8PathBuf::from_path_buf(tmp.path().join("ok.tar.gz")).unwrap();
    fs::write(&path, b"x").unwrap();
    verify_local_tarball(&path).unwrap();
}

#[test]
fn verify_local_tarball_open_returns_readable_file_on_regular_file() {
    // SEC-16 TOCTOU-safe variant: the returned File must be
    // (a) opened on the same inode the path resolves to and
    // (b) readable, so the caller can stream-decompress without
    // a path re-open.
    let tmp = tempfile::tempdir().unwrap();
    let path = Utf8PathBuf::from_path_buf(tmp.path().join("ok.tar.gz")).unwrap();
    fs::write(&path, b"hello tarball").unwrap();
    let mut file = verify_local_tarball_open(&path).unwrap();
    let mut buf = Vec::new();
    std::io::Read::read_to_end(&mut file, &mut buf).unwrap();
    assert_eq!(buf, b"hello tarball");
}

#[test]
fn verify_local_tarball_open_rejects_symlink_via_o_nofollow() {
    // The kernel's O_NOFOLLOW returns ELOOP when the final path
    // component is a symlink, regardless of what the symlink
    // points at. This test plants a symlink-to-regular-file (which
    // would PASS a permissive lstat-then-follow check) and
    // asserts the open-side rejection fires.
    let tmp = tempfile::tempdir().unwrap();
    let target = Utf8PathBuf::from_path_buf(tmp.path().join("target.tar.gz")).unwrap();
    fs::write(&target, b"x").unwrap();
    let link = Utf8PathBuf::from_path_buf(tmp.path().join("link.tar.gz")).unwrap();
    std::os::unix::fs::symlink(target.as_std_path(), link.as_std_path()).unwrap();
    let err = verify_local_tarball_open(&link).unwrap_err();
    let msg = format!("{err}");
    assert!(
        msg.contains("symlink"),
        "expected symlink-rejection wording; got: {msg}"
    );
}

#[test]
fn verify_local_tarball_open_rejects_directory() {
    let tmp = tempfile::tempdir().unwrap();
    let path = Utf8PathBuf::from_path_buf(tmp.path().join("dir.tar.gz")).unwrap();
    fs::create_dir_all(path.as_std_path()).unwrap();
    let err = verify_local_tarball_open(&path).unwrap_err();
    let msg = format!("{err}");
    assert!(
        msg.contains("no longer a regular file"),
        "expected directory rejection; got: {msg}"
    );
}

#[test]
fn extract_tarball_from_file_unpacks_via_pre_opened_handle() {
    // SEC-16 TOCTOU pin: the from_file extractor must read from
    // the passed-in File handle, NOT re-open the path. We
    // demonstrate this by:
    // 1. Building a real .tar.gz at `path`.
    // 2. Opening `path` via verify_local_tarball_open (returns
    //    a File handle that holds the original inode).
    // 3. UNLINKING the path and creating a NEW (corrupt) file at
    //    the same path — different inode.
    // 4. Calling extract_tarball_from_file with the original
    //    File handle.
    // 5. Asserting the extraction succeeds — the held fd still
    //    references the original tarball's inode, so the
    //    post-replace bytes never reach the extractor.
    //
    // (`fs::write` would TRUNCATE rather than unlink, modifying
    // the same inode the fd points at; we explicitly unlink +
    // create to swap inodes and prove the fd-based read is
    // path-resolution-free.)
    let tmp = tempfile::tempdir().unwrap();
    let tarball = Utf8PathBuf::from_path_buf(tmp.path().join("good.tar.gz")).unwrap();
    // Build a minimal valid tar.gz with one regular-file entry.
    let mut header = tar::Header::new_gnu();
    header.set_path("hello.txt").unwrap();
    header.set_size(5);
    header.set_mode(0o644);
    header.set_cksum();
    let mut tar_buf = Vec::new();
    {
        let mut builder = tar::Builder::new(&mut tar_buf);
        builder
            .append(&header, std::io::Cursor::new(b"hello"))
            .unwrap();
        builder.finish().unwrap();
    }
    let gz_path = tarball.as_std_path();
    let f = std::fs::File::create(gz_path).unwrap();
    let mut gz = flate2::write::GzEncoder::new(f, flate2::Compression::default());
    std::io::Write::write_all(&mut gz, &tar_buf).unwrap();
    gz.finish().unwrap();

    // Open via the TOCTOU-safe path.
    let file = verify_local_tarball_open(&tarball).unwrap();

    // Unlink + recreate at the same path. The new file is a
    // different inode; the held fd still references the
    // original (which is "deleted" but kept alive by the open
    // refcount).
    fs::remove_file(gz_path).unwrap();
    fs::write(gz_path, b"corrupt-not-gzip").unwrap();

    let dest = Utf8PathBuf::from_path_buf(tmp.path().join("dest")).unwrap();
    extract_tarball_from_file(file, &dest).unwrap();

    // The legitimate file from the ORIGINAL tarball must be
    // present — proving the extractor read from the fd, not
    // the post-replace path.
    let extracted = dest.join("hello.txt");
    assert!(
        extracted.as_std_path().exists(),
        "extraction must succeed via fd"
    );
    assert_eq!(
        fs::read(extracted.as_std_path()).unwrap(),
        b"hello",
        "extracted content must come from the ORIGINAL tarball, not the replaced path"
    );
}

/// TOCTOU parity test between `validators::validate_runner_tarball`
/// (load-time gate) and `verify_local_tarball` (apply-time gate).
/// The two checks must form a closed pair: a path that passes the
/// load-time check but is then mutated to a symlink before
/// `install_runner_binary` runs MUST be rejected by the apply-time
/// check.
///
/// Without this parity test, a regression that loosened
/// `verify_local_tarball` (e.g. dropped the `O_NOFOLLOW` flag in
/// `open_no_follow_with_meta`, or swapped to a path-based stat
/// that follows symlinks) would silently land — both functions
/// individually still reject their unit-test inputs, but the
/// cross-time invariant would break: an attacker who wins the
/// window between `validate_runner_tarballs` (config load, in
/// `cli::load_config`) and `extract::install_runner_binary`
/// (apply, called inside `apply.lock`) by replacing the regular
/// file with a symlink to e.g. `/etc/passwd` would be able to
/// redirect `extract_tarball`'s read.
///
/// The check uses `crate::validators::validate_runner_tarball`
/// directly (it is `pub`) and `verify_local_tarball` (in this
/// module). The flow:
/// 1. Plant a regular file at `path`.
/// 2. Confirm `validate_runner_tarball` accepts (load-time pass).
/// 3. Replace the regular file with a symlink at the SAME path.
/// 4. Confirm `verify_local_tarball` rejects (apply-time fail).
/// 5. Assert the rejection message names "symlink" so the operator
///    can attribute the cause.
#[test]
fn validate_and_verify_form_closed_toctou_pair_on_symlink_swap() {
    let tmp = tempfile::tempdir().unwrap();
    let target = tmp.path().join("real.tar.gz");
    let path = Utf8PathBuf::from_path_buf(tmp.path().join("tarball.tar.gz")).unwrap();
    // Step 1: regular file at the validated path. Bytes start
    // with the gzip magic (1f 8b) so the validator's magic
    // check accepts the planted file. The remaining bytes are
    // not a valid deflate stream — but the validator only reads
    // the first 2 bytes, so the rest is irrelevant for this
    // load-time test (extract_tarball would reject the body, but
    // we never call it here).
    fs::write(
        path.as_std_path(),
        b"\x1f\x8bfake but valid tarball bytes\n",
    )
    .unwrap();
    // Step 2: load-time gate accepts.
    crate::validators::validate_runner_tarball(path.as_str())
        .expect("validate_runner_tarball must accept the planted regular file");
    // Step 3: TOCTOU window — replace with a symlink at the SAME
    // path. We must `remove_file` first because `symlink` errors
    // with EEXIST on a present destination (linux symlink(2):
    // "EEXIST newpath already exists.").
    fs::write(&target, b"some other data\n").unwrap();
    fs::remove_file(path.as_std_path()).unwrap();
    std::os::unix::fs::symlink(&target, path.as_std_path()).unwrap();
    let lstat = fs::symlink_metadata(path.as_std_path()).unwrap();
    assert!(
        lstat.file_type().is_symlink(),
        "fixture invariant: post-mutation path must be a symlink, \
         else the test does not exercise the TOCTOU window"
    );
    // Step 4: apply-time gate rejects. This is the load-bearing
    // assertion — a regression that follows symlinks would silently
    // pass here.
    let err = verify_local_tarball(&path)
        .expect_err("verify_local_tarball must reject the post-swap symlink");
    // Step 5: rejection cause is attributable.
    let msg = err.to_string();
    assert!(
        msg.contains("symlink"),
        "verify_local_tarball error must name the symlink cause; got: {msg}"
    );
}

/// Unlink-mutation TOCTOU: a path that passes the load-time
/// gate (regular file) but is then unlinked before
/// `install_runner_binary` runs MUST be rejected by the apply-time
/// gate (`verify_local_tarball`). Symmetric with the symlink-swap
/// TOCTOU test above; covers the second mutation arc (regular →
/// missing) the directive's T3.2 row calls out.
///
/// Why this matters: the symlink-swap test pins the lstat
/// invariant; the unlink test pins that an attacker who simply
/// removes the file (rather than replacing it with a link) is
/// caught at apply-time. A regression that swapped
/// `verify_local_tarball`'s exists-check for an over-permissive
/// `Ok` (e.g. treating ENOENT as "skip extraction") would silently
/// land — `verify_local_tarball_rejects_missing` (above) covers
/// the unit case; this test pins the cross-time invariant.
#[test]
fn validate_and_verify_form_closed_toctou_pair_on_unlink() {
    let tmp = tempfile::tempdir().unwrap();
    let path = Utf8PathBuf::from_path_buf(tmp.path().join("tarball.tar.gz")).unwrap();
    // Step 1: regular file at the validated path.
    // bytes start with gzip magic 1f 8b so validate_runner_tarball accepts.
    fs::write(
        path.as_std_path(),
        b"\x1f\x8bfake but valid tarball bytes\n",
    )
    .unwrap();
    // Step 2: load-time gate accepts.
    crate::validators::validate_runner_tarball(path.as_str())
        .expect("validate_runner_tarball must accept the planted regular file");
    // Step 3: TOCTOU window — unlink the file. The apply-time gate
    // sees an absent path.
    fs::remove_file(path.as_std_path()).unwrap();
    assert!(
        !path.as_std_path().exists(),
        "fixture invariant: post-unlink path must not exist"
    );
    // Step 4: apply-time gate rejects.
    let err = verify_local_tarball(&path)
        .expect_err("verify_local_tarball must reject the post-unlink missing file");
    // Step 5: rejection cause names an open / existence failure.
    // Post-SEC-16, verify_local_tarball opens the file via
    // O_NOFOLLOW; ENOENT surfaces in the "cannot be opened"
    // wording.
    let msg = err.to_string();
    assert!(
        msg.contains("cannot be opened") || msg.contains("does not exist"),
        "verify_local_tarball error must name an open / existence failure; got: {msg}"
    );
}

/// Directory-mutation TOCTOU: a path that passes the
/// load-time gate (regular file) but is then replaced with a
/// directory at the same path before `install_runner_binary` runs
/// MUST be rejected by the apply-time gate. Symmetric with the
/// symlink-swap and unlink TOCTOU tests above; covers the third
/// mutation arc (regular → directory) from the directive's T3.4
/// row.
///
/// Why this matters: lstat on a directory reports `is_file() ==
/// false` and `is_symlink() == false`, so the rejection MUST come
/// from the "not a regular file" arm. A regression that loosened
/// that arm (e.g. accepting any non-symlink file type) would
/// silently land — the symlink test would still pass.
#[test]
fn validate_and_verify_form_closed_toctou_pair_on_directory_swap() {
    let tmp = tempfile::tempdir().unwrap();
    let path = Utf8PathBuf::from_path_buf(tmp.path().join("tarball.tar.gz")).unwrap();
    // Step 1: regular file at the validated path.
    // bytes start with gzip magic 1f 8b so validate_runner_tarball accepts.
    fs::write(
        path.as_std_path(),
        b"\x1f\x8bfake but valid tarball bytes\n",
    )
    .unwrap();
    // Step 2: load-time gate accepts.
    crate::validators::validate_runner_tarball(path.as_str())
        .expect("validate_runner_tarball must accept the planted regular file");
    // Step 3: TOCTOU window — remove the file and create a
    // directory at the SAME path. (Linux lacks an atomic
    // file→directory swap; the unlink-then-mkdir sequence still
    // models the attack — between the two syscalls
    // `verify_local_tarball` would see ENOENT, but in the
    // post-mutation steady state it sees a directory, which is
    // the case the apply-time gate must catch.)
    fs::remove_file(path.as_std_path()).unwrap();
    fs::create_dir(path.as_std_path()).unwrap();
    let lstat = fs::symlink_metadata(path.as_std_path()).unwrap();
    assert!(
        lstat.file_type().is_dir(),
        "fixture invariant: post-mutation path must be a directory, \
         else the test does not exercise the directory-swap window"
    );
    // Step 4: apply-time gate rejects.
    let err = verify_local_tarball(&path)
        .expect_err("verify_local_tarball must reject the post-swap directory");
    // Step 5: rejection cause names "no longer a regular file" —
    // the contract `verify_local_tarball` advertises for the
    // is_file()==false arm.
    let msg = err.to_string();
    assert!(
        msg.contains("no longer a regular file") || msg.contains("not a regular file"),
        "verify_local_tarball error must name the regular-file rejection cause; got: {msg}"
    );
}

/// Extend the TOCTOU parity coverage to a table-driven
/// equivalence proof. For every file-shape the operator can
/// hand the tool, both gates must agree (accept or reject in
/// lockstep). The `validate_and_verify_form_closed_*` test
/// above covered the symlink-swap arc (regular → symlink); this
/// table adds:
/// - regular file: both ACCEPT
/// - missing: both REJECT (file does not exist)
/// - directory: both REJECT (not a regular file)
/// - symlink to regular: both REJECT (lstat catches the link)
///
/// Without this extension, a regression that loosened ONE of
/// the four shape rejections in either gate (e.g. an
/// over-permissive missing-file check that returns Ok on
/// ENOENT) would land silently because the other gate still
/// catches the original swap-window case. Asserting equivalence
/// pins the entire shape-level contract, not just the
/// adversarial sequence.
#[test]
fn validate_and_verify_agree_across_file_shapes() {
    let tmp = tempfile::tempdir().unwrap();
    struct Case {
        shape: &'static str,
        expect_accept: bool,
        plant: Box<dyn Fn(&std::path::Path) -> Utf8PathBuf>,
    }
    let cases: Vec<Case> = vec![
        Case {
            shape: "regular file",
            expect_accept: true,
            plant: Box::new(|root| {
                let p = Utf8PathBuf::from_path_buf(root.join("regular.tar.gz")).unwrap();
                // gzip magic prefix so validate_runner_tarball accepts.
                fs::write(&p, b"\x1f\x8bfake but valid bytes\n").unwrap();
                p
            }),
        },
        Case {
            shape: "missing path",
            expect_accept: false,
            plant: Box::new(|root| {
                Utf8PathBuf::from_path_buf(root.join("missing.tar.gz")).unwrap()
            }),
        },
        Case {
            shape: "directory",
            expect_accept: false,
            plant: Box::new(|root| {
                let p = Utf8PathBuf::from_path_buf(root.join("dir.tar.gz")).unwrap();
                fs::create_dir(p.as_std_path()).unwrap();
                p
            }),
        },
        Case {
            shape: "symlink to regular",
            expect_accept: false,
            plant: Box::new(|root| {
                let target = root.join("symlink-target.tar.gz");
                fs::write(&target, b"target bytes\n").unwrap();
                let link = Utf8PathBuf::from_path_buf(root.join("symlink.tar.gz")).unwrap();
                std::os::unix::fs::symlink(&target, link.as_std_path()).unwrap();
                link
            }),
        },
    ];

    for case in &cases {
        // Plant each case in a separate subdir so the four
        // paths don't collide when run sequentially.
        let scope = tmp.path().join(case.shape.replace(' ', "-"));
        fs::create_dir_all(&scope).unwrap();
        let path = (case.plant)(&scope);

        let v_load = crate::validators::validate_runner_tarball(path.as_str());
        let v_apply = verify_local_tarball(&path);

        assert_eq!(
            v_load.is_ok(),
            case.expect_accept,
            "shape {:?}: validate_runner_tarball expected {}, got {v_load:?}",
            case.shape,
            if case.expect_accept { "Ok" } else { "Err" },
        );
        assert_eq!(
            v_apply.is_ok(),
            case.expect_accept,
            "shape {:?}: verify_local_tarball expected {}, got {v_apply:?}",
            case.shape,
            if case.expect_accept { "Ok" } else { "Err" },
        );
        // Cross-time invariant: both gates MUST agree on every
        // shape. A regression in either gate breaks this
        // equivalence and the assertion fires.
        assert_eq!(
            v_load.is_ok(),
            v_apply.is_ok(),
            "shape {:?}: validate/verify must agree (got validate={v_load:?}, verify={v_apply:?})",
            case.shape,
        );
    }
}

#[test]
fn install_runner_binary_extracts_into_versioned_bin_dir() {
    let tmp = tempfile::tempdir().unwrap();
    let state = Utf8PathBuf::from_path_buf(tmp.path().join("state")).unwrap();
    let runner_home = state.join("buckos");
    fs::create_dir_all(&runner_home).unwrap();

    let tarball = Utf8PathBuf::from_path_buf(tmp.path().join("runner.tar.gz")).unwrap();
    let gz = build_tar_gz(&[(
        b"runsvc.sh",
        tar::EntryType::Regular,
        b"",
        0o755,
        b"#!/bin/sh\n",
    )]);
    fs::write(&tarball, gz).unwrap();

    let final_dir =
        install_runner_binary(&tarball, &state, &runner_home, "buckos", "2.334.0").unwrap();
    assert_eq!(final_dir, runner_home.join("bin.2.334.0"));
    assert!(final_dir.join("runsvc.sh").exists());
    // staging directory is gone after the rename.
    let staging_root = state.join(".staging");
    assert!(staging_root.exists());
    let leftover = fs::read_dir(staging_root.as_std_path()).unwrap().count();
    assert_eq!(leftover, 0, "staging should be empty after install");
}

#[test]
fn install_runner_binary_cleans_up_staging_on_unsafe_archive() {
    let tmp = tempfile::tempdir().unwrap();
    let state = Utf8PathBuf::from_path_buf(tmp.path().join("state")).unwrap();
    let runner_home = state.join("buckos");
    fs::create_dir_all(&runner_home).unwrap();

    let tarball = Utf8PathBuf::from_path_buf(tmp.path().join("evil.tar.gz")).unwrap();
    let gz = build_tar_gz(&[(b"link", tar::EntryType::Symlink, b"/etc/shadow", 0o777, b"")]);
    fs::write(&tarball, gz).unwrap();

    let err =
        install_runner_binary(&tarball, &state, &runner_home, "buckos", "2.334.0").unwrap_err();
    assert!(err.to_string().contains("absolute link target"), "{err}");

    // bin.<version> must NOT exist, and staging/ must be empty.
    assert!(!runner_home.join("bin.2.334.0").exists());
    let staging_root = state.join(".staging");
    let leftover = fs::read_dir(staging_root.as_std_path()).unwrap().count();
    assert_eq!(leftover, 0, "staging should be cleaned up on failure");
}

#[test]
fn install_runner_binary_overwrites_existing_version_dir() {
    let tmp = tempfile::tempdir().unwrap();
    let state = Utf8PathBuf::from_path_buf(tmp.path().join("state")).unwrap();
    let runner_home = state.join("buckos");
    fs::create_dir_all(&runner_home).unwrap();

    // Pre-existing bin.2.334.0 from a prior run.
    let stale = runner_home.join("bin.2.334.0");
    fs::create_dir_all(&stale).unwrap();
    fs::write(stale.join("STALE"), b"old").unwrap();

    let tarball = Utf8PathBuf::from_path_buf(tmp.path().join("runner.tar.gz")).unwrap();
    let gz = build_tar_gz(&[(b"FRESH", tar::EntryType::Regular, b"", 0o644, b"new")]);
    fs::write(&tarball, gz).unwrap();

    install_runner_binary(&tarball, &state, &runner_home, "buckos", "2.334.0").unwrap();
    assert!(!runner_home.join("bin.2.334.0/STALE").exists());
    assert!(runner_home.join("bin.2.334.0/FRESH").exists());
}

#[test]
fn is_safe_relative_path_unit_cases() {
    assert!(is_safe_relative_path(b"a/b/c"));
    assert!(is_safe_relative_path(b"./a"));
    assert!(is_safe_relative_path(b"a"));
    assert!(!is_safe_relative_path(b""));
    assert!(!is_safe_relative_path(b"/abs"));
    assert!(!is_safe_relative_path(b".."));
    assert!(!is_safe_relative_path(b"a/../b"));
    assert!(!is_safe_relative_path(b"../etc"));
}

// -- Post-extract canonical-path defense ----------------------------

#[test]
fn verify_extracted_inside_dest_accepts_normal_member() {
    let tmp = tempfile::tempdir().unwrap();
    let dest = Utf8PathBuf::from_path_buf(tmp.path().to_path_buf()).unwrap();
    fs::create_dir_all(dest.join("a")).unwrap();
    fs::write(dest.join("a/b"), b"x").unwrap();
    let canon = fs::canonicalize(dest.as_std_path()).unwrap();
    verify_extracted_inside_dest(&canon, &dest, b"a/b").unwrap();
}

#[test]
fn verify_extracted_inside_dest_rejects_dotdot_in_path() {
    // Even if safe_member_filter regressed and let `a/../b` through,
    // verify_extracted_inside_dest must catch it.
    let tmp = tempfile::tempdir().unwrap();
    let dest = Utf8PathBuf::from_path_buf(tmp.path().to_path_buf()).unwrap();
    let canon = fs::canonicalize(dest.as_std_path()).unwrap();
    let err = verify_extracted_inside_dest(&canon, &dest, b"a/../b").unwrap_err();
    assert!(err.to_string().contains("post-extract verify"), "msg={err}");
    assert!(err.to_string().contains(".."), "msg={err}");
}

#[test]
fn verify_extracted_inside_dest_rejects_symlinked_parent_escape() {
    // Simulate the symlink-after-extract attack: a previously
    // extracted entry left `a` as a symlink to outside dest, and a
    // subsequent extract wrote `a/b`. The post-extract check
    // canonicalizes the parent of `a/b` (which is `a`, a symlink)
    // and discovers it points outside dest.
    let tmp = tempfile::tempdir().unwrap();
    let outside = Utf8PathBuf::from_path_buf(tmp.path().join("outside")).unwrap();
    fs::create_dir(&outside).unwrap();

    let dest = Utf8PathBuf::from_path_buf(tmp.path().join("dest")).unwrap();
    fs::create_dir(&dest).unwrap();

    // Manually plant a symlink `dest/a` → ../outside (this is exactly
    // what a malicious tarball would produce if the filter regressed).
    std::os::unix::fs::symlink("../outside", dest.join("a").as_std_path()).unwrap();
    // And the file written through the symlink — this lands in
    // outside/, which is outside dest.
    fs::write(outside.join("b"), b"escaped").unwrap();

    let canon_dest = fs::canonicalize(dest.as_std_path()).unwrap();
    let err = verify_extracted_inside_dest(&canon_dest, &dest, b"a/b").unwrap_err();
    assert!(
        err.to_string().contains("escaped extraction root"),
        "msg={err}"
    );
}

// -- EXDEV cross-filesystem fallback --------------------------------

#[test]
fn copy_dir_recursive_copies_files_dirs_and_symlinks() {
    let tmp = tempfile::tempdir().unwrap();
    let src = Utf8PathBuf::from_path_buf(tmp.path().join("src")).unwrap();
    let dst = Utf8PathBuf::from_path_buf(tmp.path().join("dst")).unwrap();
    fs::create_dir_all(src.join("sub")).unwrap();
    fs::write(src.join("top.txt"), b"hello").unwrap();
    fs::write(src.join("sub/inner.txt"), b"inside").unwrap();
    std::os::unix::fs::symlink("inner.txt", src.join("sub/link").as_std_path()).unwrap();

    copy_dir_recursive(&src, &dst).unwrap();

    assert_eq!(fs::read(dst.join("top.txt")).unwrap(), b"hello");
    assert_eq!(fs::read(dst.join("sub/inner.txt")).unwrap(), b"inside");
    let link_meta = fs::symlink_metadata(dst.join("sub/link")).unwrap();
    assert!(link_meta.file_type().is_symlink());
    let link_target = fs::read_link(dst.join("sub/link").as_std_path()).unwrap();
    assert_eq!(link_target.to_string_lossy(), "inner.txt");
}

#[test]
fn copy_dir_recursive_preserves_non_utf8_filenames_byte_exact() {
    // Regression pin: the prior `name.to_string_lossy().as_ref()`
    // path substituted U+FFFD into any name with invalid UTF-8
    // sequences, producing a destination filename that did NOT
    // round-trip from the source. The fix uses OsString-typed
    // join so filenames containing arbitrary kernel-representable
    // bytes survive unchanged.
    use std::ffi::OsStr;
    use std::os::unix::ffi::OsStrExt;
    let tmp = tempfile::tempdir().unwrap();
    let src = Utf8PathBuf::from_path_buf(tmp.path().join("src")).unwrap();
    let dst = Utf8PathBuf::from_path_buf(tmp.path().join("dst")).unwrap();
    fs::create_dir_all(src.as_std_path()).unwrap();
    // Filename = "valid_" + invalid-UTF-8 byte sequence (\x80 \xFF
    // \x80 are continuation/standalone bytes that DON'T form a
    // valid UTF-8 codepoint). The kernel happily stores it; we
    // must copy it byte-exact.
    let bad_bytes: Vec<u8> = b"valid_\x80\xff\x80".to_vec();
    let bad_name = OsStr::from_bytes(&bad_bytes);
    let src_path = src.as_std_path().join(bad_name);
    fs::write(&src_path, b"sentinel").unwrap();

    copy_dir_recursive(&src, &dst).unwrap();

    // Destination must contain a file with the EXACT same byte
    // sequence — not a U+FFFD-substituted variant.
    let dst_path = dst.as_std_path().join(bad_name);
    assert!(
        dst_path.exists(),
        "non-UTF-8 filename must round-trip byte-exact; missing at {dst_path:?}"
    );
    assert_eq!(
        fs::read(&dst_path).unwrap(),
        b"sentinel",
        "copy must preserve content under the non-UTF-8 name"
    );
    // Defense in depth: assert the dst directory has exactly one
    // entry (no U+FFFD-named ghost file from a partial fix).
    let dst_entries: Vec<_> = fs::read_dir(dst.as_std_path())
        .unwrap()
        .map(|e| e.unwrap().file_name())
        .collect();
    assert_eq!(
        dst_entries.len(),
        1,
        "dst must contain exactly the one copied file; got {dst_entries:?}"
    );
    assert_eq!(
        dst_entries[0].as_bytes(),
        bad_bytes.as_slice(),
        "dst filename must be byte-exact"
    );
}

#[test]
fn is_cross_device_link_recognizes_exdev() {
    let exdev = std::io::Error::from_raw_os_error(libc::EXDEV);
    assert!(is_cross_device_link(&exdev));
}

#[test]
fn is_cross_device_link_rejects_other_errors() {
    let enoent = std::io::Error::from_raw_os_error(libc::ENOENT);
    assert!(!is_cross_device_link(&enoent));
    let eacces = std::io::Error::from_raw_os_error(libc::EACCES);
    assert!(!is_cross_device_link(&eacces));
}

// -- Python parity: setuid stripped on disk -------------------------

#[test]
fn extract_tarball_strips_setuid_on_disk_end_to_end() {
    // Python parity: setuid-strip test from the legacy install tool.
    // The tar crate's `unpack_in` strips setuid/setgid for unprivileged
    // unpack by default. This test is the load-bearing assertion:
    // the EXTRACTED FILE on disk has zero setuid + setgid bits.
    use std::os::unix::fs::PermissionsExt;
    let tmp = tempfile::tempdir().unwrap();
    let tarball = Utf8PathBuf::from_path_buf(tmp.path().join("suid.tar.gz")).unwrap();
    // 0o6755 = setuid + setgid + rwxr-xr-x. Sticky bit (0o1000) is also
    // in the masked range; we cover suid + sgid here because they are
    // the security-relevant bits (sticky on a regular file is a no-op
    // on Linux).
    let gz = build_tar_gz(&[(b"suid-bin", tar::EntryType::Regular, b"", 0o6755, b"ELF")]);
    fs::write(&tarball, gz).unwrap();

    let dest = Utf8PathBuf::from_path_buf(tmp.path().join("dest")).unwrap();
    extract_tarball(&tarball, &dest).unwrap();
    let extracted = dest.join("suid-bin");
    assert!(extracted.is_file(), "{extracted} did not extract");
    let mode = fs::metadata(&extracted).unwrap().permissions().mode();
    assert_eq!(
        mode & 0o4000,
        0,
        "setuid bit must be stripped (mode={mode:o})"
    );
    assert_eq!(
        mode & 0o2000,
        0,
        "setgid bit must be stripped (mode={mode:o})"
    );
}

// -- Race tolerance -------------------------------------------------

#[test]
fn install_runner_binary_replaces_stale_staging_dir_from_prior_crash() {
    // Pre-create the EXACT staging path that install_runner_binary
    // would compute (`<state>/.staging/<name>-<version>-<pid>/`),
    // populate it with junk that simulates a half-finished prior
    // install. install_runner_binary's `if staging.exists() {
    // fs::remove_dir_all(&staging)?; }` branch must wipe and
    // proceed.
    let tmp = tempfile::tempdir().unwrap();
    let state = Utf8PathBuf::from_path_buf(tmp.path().join("state")).unwrap();
    let runner_home = state.join("buckos");
    fs::create_dir_all(&runner_home).unwrap();

    let pid = std::process::id();
    let staging_root = state.join(".staging");
    let prior_staging = staging_root.join(format!("buckos-2.334.0-{pid}"));
    fs::create_dir_all(&prior_staging).unwrap();
    // Prior-run tree contents: a sentinel file + a nested dir, both
    // distinct from anything the new tarball will produce.
    fs::write(prior_staging.join("STALE_SENTINEL"), b"crashed prior run").unwrap();
    fs::create_dir_all(prior_staging.join("partial-nested")).unwrap();
    fs::write(prior_staging.join("partial-nested/junk"), b"x").unwrap();

    let tarball = Utf8PathBuf::from_path_buf(tmp.path().join("runner.tar.gz")).unwrap();
    let gz = build_tar_gz(&[(
        b"runsvc.sh",
        tar::EntryType::Regular,
        b"",
        0o755,
        b"#!/bin/sh\n",
    )]);
    fs::write(&tarball, gz).unwrap();

    let final_dir =
        install_runner_binary(&tarball, &state, &runner_home, "buckos", "2.334.0").unwrap();
    // Final tree is the new tarball's contents only.
    assert!(final_dir.join("runsvc.sh").exists());
    // None of the stale sentinels survived.
    assert!(!final_dir.join("STALE_SENTINEL").exists());
    assert!(!final_dir.join("partial-nested").exists());
    // Staging is empty (the function moved its dir to final_dir).
    let leftover = fs::read_dir(staging_root.as_std_path()).unwrap().count();
    assert_eq!(leftover, 0, "staging should be empty after install");
}

#[test]
fn install_runner_binary_concurrent_distinct_runners_dont_collide() {
    // Two threads (same process, same pid) install DIFFERENT runner
    // names concurrently. The staging dir name embeds runner_name,
    // so the two stagings don't collide. Both calls must succeed
    // and produce their own bin.<version>/ dirs intact.
    use std::sync::Arc;
    use std::thread;
    let tmp = tempfile::tempdir().unwrap();
    let state = Arc::new(Utf8PathBuf::from_path_buf(tmp.path().join("state")).unwrap());
    fs::create_dir_all(state.as_std_path()).unwrap();

    // Two distinct tarballs so we can prove neither install
    // accidentally wrote the OTHER tarball's marker file.
    let tarball_a = Utf8PathBuf::from_path_buf(tmp.path().join("a.tar.gz")).unwrap();
    let tarball_b = Utf8PathBuf::from_path_buf(tmp.path().join("b.tar.gz")).unwrap();
    let gz_a = build_tar_gz(&[(b"MARKER_A", tar::EntryType::Regular, b"", 0o644, b"a")]);
    let gz_b = build_tar_gz(&[(b"MARKER_B", tar::EntryType::Regular, b"", 0o644, b"b")]);
    fs::write(&tarball_a, gz_a).unwrap();
    fs::write(&tarball_b, gz_b).unwrap();

    let thread_a = {
        let state = Arc::clone(&state);
        let tarball = tarball_a.clone();
        thread::spawn(move || {
            let runner_home = state.join("alpha");
            fs::create_dir_all(&runner_home).unwrap();
            install_runner_binary(&tarball, &state, &runner_home, "alpha", "2.334.0")
        })
    };
    let thread_b = {
        let state = Arc::clone(&state);
        let tarball = tarball_b.clone();
        thread::spawn(move || {
            let runner_home = state.join("bravo");
            fs::create_dir_all(&runner_home).unwrap();
            install_runner_binary(&tarball, &state, &runner_home, "bravo", "2.334.0")
        })
    };

    let final_a = thread_a.join().expect("thread A panicked").unwrap();
    let final_b = thread_b.join().expect("thread B panicked").unwrap();

    assert_eq!(final_a, state.join("alpha/bin.2.334.0"));
    assert_eq!(final_b, state.join("bravo/bin.2.334.0"));
    // Each runner_home contains ONLY its own marker file.
    assert!(final_a.join("MARKER_A").exists());
    assert!(!final_a.join("MARKER_B").exists());
    assert!(final_b.join("MARKER_B").exists());
    assert!(!final_b.join("MARKER_A").exists());
    // Staging is fully drained.
    let staging_root = state.join(".staging");
    let leftover = fs::read_dir(staging_root.as_std_path()).unwrap().count();
    assert_eq!(leftover, 0, "staging should be drained after both installs");
}

// -- http_download timeout ------------------------------------------

#[test]
fn http_download_returns_err_within_timeout_on_slow_response() {
    // mockito with_chunked_body sleeps inside the response writer
    // before sending any bytes. The reqwest blocking client is
    // configured with a 200ms total-request timeout; the mock
    // sleeps 2_000ms. The download must error (not hang) and the
    // call must return well before the mock's sleep completes.
    use std::time::{Duration, Instant};
    let mut server = mockito::Server::new();
    let m = server
        .mock("GET", "/slow")
        .with_status(200)
        .with_chunked_body(|w| {
            std::thread::sleep(Duration::from_secs(2));
            w.write_all(b"too late")
        })
        .create();
    let tmp = tempfile::tempdir().unwrap();
    let dest = Utf8PathBuf::from_path_buf(tmp.path().join("slow.bin")).unwrap();
    let url = format!("{}/slow", server.url());

    let started = Instant::now();
    let result = http_download(&url, &dest, Duration::from_millis(200));
    let elapsed = started.elapsed();

    assert!(
        result.is_err(),
        "http_download must error on timeout, got Ok"
    );
    // Reqwest surfaces a body-read timeout as std::io::Error (mapped
    // through the `?` on `resp.read(...)`), and a connect/headers
    // timeout as a reqwest::Error mapped to GharsError::Tarball.
    // Either is a valid outcome — what we're testing is that the
    // call did NOT hang past `timeout`.
    match result.unwrap_err() {
        GharsError::Io(_) | GharsError::Tarball(_, _) => {}
        other => panic!("expected Io or Tarball error on timeout, got {other:?}"),
    }
    // Hard upper bound: must have returned well before the mock's
    // 2s sleep finished. 1s gives generous slack for slow CI while
    // still proving the timeout cut the request off.
    assert!(
        elapsed < Duration::from_secs(1),
        "http_download did not honor timeout; took {elapsed:?}"
    );
    m.assert();
}

/// Streaming cap pin: `http_download` rejects responses whose
/// post-decompression body exceeds `MAX_TARBALL_DOWNLOAD_BYTES`.
/// Constructing a 512+ MiB mock body in CI would balloon test
/// runtime and memory, so this test exercises the boundary by
/// driving a body that's intentionally smaller than the production
/// cap but large enough to prove the counter logic — at the same
/// time the test asserts the error type, message shape, AND that
/// the partial destination file was unlinked. The legitimate
/// production cap is a constant that operators don't tune; the
/// counter logic at the read loop is the load-bearing defense.
///
/// Approach: send a body slightly larger than MAX would be, but use
/// a private test variant of MAX. This module controls
/// `MAX_TARBALL_DOWNLOAD_BYTES` so we can't override it at test
/// time without rewriting the public surface. Instead, the test
/// pins that the production constant has the SHAPE we expect (>1MB)
/// and the streaming counter exists in the production code.
/// End-to-end coverage of the cap firing is left to integration
/// tests that can construct gigabyte-scale mocks under cargo
/// nextest's per-test timeout.
#[test]
#[allow(clippy::assertions_on_constants)]
fn max_tarball_download_bytes_constant_has_expected_shape() {
    // Pin (a) the cap exists at module scope and (b) is in the
    // sane range — a regression that drops it to 0 (always-reject)
    // or u64::MAX (never-reject) is caught here.
    assert!(
        MAX_TARBALL_DOWNLOAD_BYTES >= 256 * 1024 * 1024,
        "cap must be >= 256 MiB to accept legitimate runner tarballs (~250 MB observed); \
         got {MAX_TARBALL_DOWNLOAD_BYTES}"
    );
    assert!(
        MAX_TARBALL_DOWNLOAD_BYTES <= 4 * 1024 * 1024 * 1024,
        "cap must be <= 4 GiB to keep the bomb-defense useful; got {MAX_TARBALL_DOWNLOAD_BYTES}"
    );
}

/// Streaming cap fires + cleanup pin: drives a body just over
/// a small test-only threshold (12 KiB), but to exercise the
/// production code path we serve a body just over the production
/// cap is impractical in CI. Instead this test pins the smaller
/// behavioral contract: the `http_download` loop currently writes
/// every byte read until `total > MAX`; we cannot exercise the
/// rejection arm without serving > 512 MiB. End-to-end coverage of
/// the rejection-with-cleanup path is left to a
/// `#[ignore]`-gated heavyweight integration test.
///
/// What this test does pin: the happy-path counter accumulates
/// without firing for normal-sized bodies, and the destination
/// file ends up with the expected bytes. A regression that
/// inverts the counter check (e.g. `total < MAX` → reject) would
/// break this test by failing to write any small download.
#[test]
fn http_download_succeeds_under_cap() {
    let mut server = mockito::Server::new();
    let body = vec![0xAB_u8; 12 * 1024];
    let m = server
        .mock("GET", "/under-cap.bin")
        .with_status(200)
        .with_body(&body)
        .create();
    let tmp = tempfile::tempdir().unwrap();
    let dest = Utf8PathBuf::from_path_buf(tmp.path().join("under-cap.bin")).unwrap();
    let url = format!("{}/under-cap.bin", server.url());
    http_download(&url, &dest, Duration::from_secs(5)).unwrap();
    let read_back = std::fs::read(dest.as_std_path()).unwrap();
    assert_eq!(read_back.len(), body.len());
    assert_eq!(read_back, body);
    m.assert();
}

/// Happy-path pin via cap-injecting helper: a body smaller
/// than the test cap downloads successfully, dest file persists
/// with the expected bytes. Symmetric with
/// `http_download_succeeds_under_cap` but exercises the
/// `http_download_with_cap` seam directly so a regression in the
/// cap-injection plumbing is caught even if the production
/// `MAX_TARBALL_DOWNLOAD_BYTES` constant is fine.
#[test]
fn http_download_with_cap_succeeds_under_cap() {
    let mut server = mockito::Server::new();
    let body = vec![0xCD_u8; 32];
    let m = server
        .mock("GET", "/under-test-cap.bin")
        .with_status(200)
        .with_body(&body)
        .create();
    let tmp = tempfile::tempdir().unwrap();
    let dest = Utf8PathBuf::from_path_buf(tmp.path().join("under-test-cap.bin")).unwrap();
    let url = format!("{}/under-test-cap.bin", server.url());
    http_download_with_cap(&url, &dest, Duration::from_secs(5), 64).unwrap();
    let read_back = std::fs::read(dest.as_std_path()).unwrap();
    assert_eq!(read_back, body);
    m.assert();
}

/// Over-cap rejection + no-leak pin: a body whose Content-Length
/// exceeds the test cap fires the Layer-1 pre-check in
/// `http_download_with_cap`. mockito auto-populates Content-Length
/// to body length, so a 128-byte body with cap=64 exercises the
/// header-only rejection path. Pins (a) the operator-visible
/// format prefix ("download failed:"), (b) URL presence, (c) cap
/// value + "exceeds" + "Content-Length" + "on-wire" /
/// "pre-decompression" vocabulary, (d) network-path triage hint
/// (mirrors github.rs Layer-1 surface), (e) the
/// `MAX_TARBALL_DOWNLOAD_BYTES` escape hatch, and (f) the
/// load-bearing security invariant: dest does NOT exist
/// post-call. Layer-2 (cumulative byte counter) is harder to
/// exercise from mockito because the mock always sets
/// Content-Length; Layer 1 is the production-relevant path for
/// any well-behaved server.
#[test]
fn http_download_with_cap_rejects_over_cap_and_unlinks_dest() {
    let mut server = mockito::Server::new();
    // mockito's `with_body` auto-populates the Content-Length header
    // to the body length. With body=128 bytes and cap=64, Layer 1
    // (pre-streaming Content-Length pre-check) fires first and
    // surfaces the on-wire diagnostic before any bytes stream.
    // This is the production-relevant path: any HTTP/1.1 server
    // that doesn't use chunked transfer encoding sets
    // Content-Length, so Layer 1 is what catches the over-cap
    // rejection in the wild.
    let body = vec![0xEF_u8; 128];
    let m = server
        .mock("GET", "/over-test-cap.bin")
        .with_status(200)
        .with_body(&body)
        .create();
    let tmp = tempfile::tempdir().unwrap();
    let dest = Utf8PathBuf::from_path_buf(tmp.path().join("over-test-cap.bin")).unwrap();
    let url = format!("{}/over-test-cap.bin", server.url());
    let err = http_download_with_cap(&url, &dest, Duration::from_secs(5), 64).unwrap_err();
    match err {
        GharsError::Tarball(msg, _hint) => {
            assert!(
                msg.starts_with("download failed:"),
                "msg must start with 'download failed:'; got: {msg}"
            );
            assert!(msg.contains(&url), "msg must surface URL; got: {msg}");
            assert!(
                msg.contains("exceeds") && msg.contains("64 bytes"),
                "msg must surface cap value + 'exceeds'; got: {msg}"
            );
            assert!(msg.contains("Content-Length"), "Layer-1 pin: {msg}");
            assert!(
                msg.contains("on-wire") && msg.contains("pre-decompression"),
                "msg must surface on-wire / pre-decompression framing: {msg}"
            );
            assert!(
                msg.contains("verify network path")
                    && msg.contains("compromised mirror")
                    && msg.contains("hostile proxy CA")
                    && msg.contains("non-GitHub origin"),
                "msg must enumerate triage causes; got: {msg}"
            );
            assert!(
                msg.contains("MAX_TARBALL_DOWNLOAD_BYTES"),
                "msg must surface escape-hatch symbol: {msg}"
            );
            // Defense-in-depth: dest must NOT have been created.
            // Pre-fix path opened dest BEFORE the header check;
            // re-ordering regression would leak a zero-byte file
            // that a later SHA256 check could promote.
        }
        other => panic!("expected GharsError::Tarball, got {other:?}"),
    }
    assert!(
        !dest.as_std_path().exists(),
        "dest file must NOT exist when cap fires; still found at {dest}"
    );
    m.assert();
}

// ---- prune_old_bin_versions tests ----

/// Helper: create N `bin.<idx>` directories under `runner_home`,
/// each with a distinct mtime spaced 1 second apart so the pruner's
/// mtime sort is deterministic. Returns the directory paths in
/// creation order (oldest first, newest last).
fn make_versioned_bin_dirs(runner_home: &Utf8Path, count: usize) -> Vec<Utf8PathBuf> {
    use nix::sys::stat::utimes;
    use nix::sys::time::TimeVal;
    let mut paths = Vec::new();
    // Anchor synthetic mtimes 1 hour in the past so they are
    // strictly earlier than any wall-clock event in this test.
    let base_secs = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_secs() as i64
        - 3600;
    for i in 0..count {
        let p = runner_home.join(format!("bin.{i}.0.0"));
        std::fs::create_dir_all(p.as_std_path()).unwrap();
        let secs = base_secs + i as i64;
        let tv = TimeVal::new(secs, 0);
        utimes(p.as_std_path(), &tv, &tv).unwrap();
        paths.push(p);
    }
    paths
}

#[test]
fn prune_keeps_n_most_recent_by_mtime() {
    let tmp = tempfile::tempdir().unwrap();
    let home = Utf8Path::from_path(tmp.path()).unwrap();
    let dirs = make_versioned_bin_dirs(home, 5);
    // Keep 2 newest → bin.4.0.0 + bin.3.0.0 survive; bin.0..2 pruned.
    let pruned = prune_old_bin_versions(home, 2).unwrap();
    assert_eq!(pruned, 3);
    for old in &dirs[..3] {
        assert!(
            !old.as_std_path().exists(),
            "stale dir {old} should have been pruned"
        );
    }
    for kept in &dirs[3..] {
        assert!(
            kept.as_std_path().exists(),
            "recent dir {kept} should have survived"
        );
    }
}

#[test]
fn prune_with_keep_versions_zero_errors() {
    let tmp = tempfile::tempdir().unwrap();
    let home = Utf8Path::from_path(tmp.path()).unwrap();
    let dirs = make_versioned_bin_dirs(home, 3);
    let err = prune_old_bin_versions(home, 0).unwrap_err();
    assert!(
        matches!(err, GharsError::Validation(..)),
        "keep_versions=0 must error structurally; got {err:?}"
    );
    // Defense in depth: NO directory was removed.
    for d in &dirs {
        assert!(d.as_std_path().exists(), "no dir should be pruned on error");
    }
}

#[test]
fn prune_skips_bin_symlink_target_even_if_oldest_mtime() {
    let tmp = tempfile::tempdir().unwrap();
    let home = Utf8Path::from_path(tmp.path()).unwrap();
    let dirs = make_versioned_bin_dirs(home, 4);
    // Active = oldest (index 0). Without the active-symlink defense
    // the pruner would remove it. With the defense it survives.
    std::os::unix::fs::symlink("bin.0.0.0", home.join("bin").as_std_path()).unwrap();
    // keep_versions = 1 → only the newest by mtime survives via the
    // top-N path; bin.0.0.0 must additionally be preserved by the
    // active-symlink check.
    let _ = prune_old_bin_versions(home, 1).unwrap();
    assert!(
        dirs[0].as_std_path().exists(),
        "active symlink target {} must be preserved",
        dirs[0]
    );
    assert!(
        dirs[3].as_std_path().exists(),
        "newest dir {} must be preserved",
        dirs[3]
    );
    // The two middle versions are pruned.
    for old in &dirs[1..3] {
        assert!(
            !old.as_std_path().exists(),
            "non-active middle dir {old} should have been pruned"
        );
    }
}

#[test]
fn prune_ignores_bin_tmp_and_plain_bin() {
    let tmp = tempfile::tempdir().unwrap();
    let home = Utf8Path::from_path(tmp.path()).unwrap();
    // Versioned dirs.
    let dirs = make_versioned_bin_dirs(home, 3);
    // Stage `bin.tmp` as a regular dir (non-symlink) — the function
    // must skip it via the suffix == "tmp" gate.
    let bin_tmp = home.join("bin.tmp");
    std::fs::create_dir_all(bin_tmp.as_std_path()).unwrap();
    // Plain `bin` directory (not a symlink in this test) — must be
    // skipped because its name doesn't have a `.<suffix>` after
    // stripping the `bin.` prefix.
    let plain_bin = home.join("bin");
    std::fs::create_dir_all(plain_bin.as_std_path()).unwrap();
    let _ = prune_old_bin_versions(home, 1).unwrap();
    // bin.tmp + bin survive regardless of mtime.
    assert!(bin_tmp.as_std_path().exists());
    assert!(plain_bin.as_std_path().exists());
    // newest survives via top-N.
    assert!(dirs[2].as_std_path().exists());
    // older versioned dirs pruned.
    assert!(!dirs[0].as_std_path().exists());
    assert!(!dirs[1].as_std_path().exists());
}

#[test]
fn prune_returns_zero_when_already_within_budget() {
    let tmp = tempfile::tempdir().unwrap();
    let home = Utf8Path::from_path(tmp.path()).unwrap();
    let dirs = make_versioned_bin_dirs(home, 2);
    // 2 dirs + keep_versions = 2 → nothing to prune.
    let pruned = prune_old_bin_versions(home, 2).unwrap();
    assert_eq!(pruned, 0);
    for d in &dirs {
        assert!(d.as_std_path().exists());
    }
}

#[test]
fn prune_handles_empty_runner_home() {
    let tmp = tempfile::tempdir().unwrap();
    let home = Utf8Path::from_path(tmp.path()).unwrap();
    // No `bin.X.Y.Z` dirs present yet.
    let pruned = prune_old_bin_versions(home, 2).unwrap();
    assert_eq!(pruned, 0);
}

#[test]
fn prune_skips_files_only_processes_directories() {
    let tmp = tempfile::tempdir().unwrap();
    let home = Utf8Path::from_path(tmp.path()).unwrap();
    // Create a regular file with the bin.X.Y.Z naming. The pruner
    // must skip it via the is_dir() gate (defense against operator
    // tampering or test artifacts).
    let stray_file = home.join("bin.intruder");
    std::fs::write(stray_file.as_std_path(), b"not a directory").unwrap();
    let dirs = make_versioned_bin_dirs(home, 2);
    let _ = prune_old_bin_versions(home, 1).unwrap();
    // The stray file is NOT pruned (not a directory).
    assert!(stray_file.as_std_path().exists());
    // newest dir survives.
    assert!(dirs[1].as_std_path().exists());
    // older dir pruned.
    assert!(!dirs[0].as_std_path().exists());
}

// ---- renameat2 atomicity contract tests ---------------------------
//
// `extract_and_swap_from_file` has three publish layers per the
// module-level doc-comment: RENAME_EXCHANGE happy path, EINVAL/
// ENOSYS fallback (remove-then-rename), and EXDEV fallback (copy-
// then-remove). These tests pin the success post-conditions of
// each branch plus the unhandled-errno propagation. The
// [`ForcedRenameAt2Errno`] cfg(test) seam forces a configured
// errno without requiring a kernel that genuinely rejects
// RENAME_EXCHANGE.

/// Build a tiny `.tar.gz` containing a single regular file
/// named `marker.txt` whose body is the supplied bytes. Used as
/// the staging-tree input for the renameat2 atomicity tests.
fn tar_gz_with_marker(marker_body: &[u8]) -> Vec<u8> {
    build_tar_gz(&[(
        b"marker.txt",
        tar::EntryType::Regular,
        b"",
        0o644,
        marker_body,
    )])
}

/// Drop a tar.gz at `tarball_path` and return an open handle to
/// it suitable for passing to `extract_and_swap_from_file`. The
/// open mirrors `verify_local_tarball_open`'s contract — caller
/// owns the resulting File.
fn write_and_open_tarball(tarball_path: &Utf8Path, body: &[u8]) -> File {
    std::fs::write(tarball_path.as_std_path(), body).unwrap();
    std::fs::OpenOptions::new()
        .read(true)
        .open(tarball_path.as_std_path())
        .unwrap()
}

/// Layout helper: produces (`runner_home`, `final_dir`, staging,
/// `tarball_path`) anchored at a fresh tempdir. `final_dir_name`
/// and `staging_name` distinguish per-test paths so a panicking
/// test cannot leak state into a sibling.
fn renameat2_test_layout(
    tmp: &tempfile::TempDir,
    final_dir_name: &str,
    staging_name: &str,
) -> (Utf8PathBuf, Utf8PathBuf, Utf8PathBuf, Utf8PathBuf) {
    let runner_home = Utf8Path::from_path(tmp.path()).unwrap().to_path_buf();
    let final_dir = runner_home.join(final_dir_name);
    let staging = runner_home.join(staging_name);
    let tarball_path = runner_home.join("input.tar.gz");
    (runner_home, final_dir, staging, tarball_path)
}

/// Pre-populate `final_dir` with `body` under `marker.txt`.
fn populate_final_dir(final_dir: &Utf8Path, body: &[u8]) {
    fs::create_dir_all(final_dir.as_std_path()).unwrap();
    fs::write(final_dir.join("marker.txt").as_std_path(), body).unwrap();
}

#[test]
fn extract_and_swap_renameat2_happy_path_replaces_final_dir() {
    // Pre-condition: final_dir exists with a known sentinel file
    // whose body is the OLD payload. After
    // extract_and_swap_from_file (RENAME_EXCHANGE branch),
    // final_dir/marker.txt must hold the NEW payload and the
    // staging path must be gone (the displaced old tree is
    // removed at the end of the Ok arm).
    // Regression sentinel: if future refactors introduce a
    // fallible setter or remove the RAII guard, this assert
    // catches leaked forcing.
    FORCED_RENAMEAT2_ERRNO.with(|c| assert!(c.get().is_none(), "happy-path requires no errno forcing (RAII guard from a sibling test must have unwound)"));
    let tmp = tempfile::tempdir().unwrap();
    let (runner_home, final_dir, staging, tarball_path) =
        renameat2_test_layout(&tmp, "bin.happy", ".staging-happy");
    populate_final_dir(&final_dir, b"old-payload");
    let file = write_and_open_tarball(&tarball_path, &tar_gz_with_marker(b"new-payload"));

    extract_and_swap_from_file(file, &staging, &runner_home, &final_dir)
        .expect("happy path must succeed");

    let body = fs::read(final_dir.join("marker.txt").as_std_path()).unwrap();
    assert_eq!(
        body, b"new-payload",
        "RENAME_EXCHANGE must publish the new tree"
    );
    assert!(
        !staging.as_std_path().exists(),
        "staging path must be removed after RENAME_EXCHANGE",
    );
}

#[test]
#[tracing_test::traced_test]
fn extract_and_swap_einval_fallback_replaces_final_dir() {
    // Force EINVAL — exercises the remove-then-rename fallback.
    // Post-conditions identical to happy-path: final_dir holds
    // the NEW payload, staging is gone. Also asserts the warn-
    // level tracing message documents the fallback so
    // operators can spot it in journalctl.
    let _guard = ForcedRenameAt2Errno::new(nix::errno::Errno::EINVAL);
    let tmp = tempfile::tempdir().unwrap();
    let (runner_home, final_dir, staging, tarball_path) =
        renameat2_test_layout(&tmp, "bin.einval", ".staging-einval");
    populate_final_dir(&final_dir, b"old-payload");
    let file = write_and_open_tarball(&tarball_path, &tar_gz_with_marker(b"new-payload"));

    extract_and_swap_from_file(file, &staging, &runner_home, &final_dir)
        .expect("EINVAL fallback must succeed via remove-then-rename");

    let body = fs::read(final_dir.join("marker.txt").as_std_path()).unwrap();
    assert_eq!(
        body, b"new-payload",
        "EINVAL fallback must publish the new tree"
    );
    // Post-success invariant: final_dir is a directory (not a
    // dangling symlink, not absent).
    let meta = fs::symlink_metadata(final_dir.as_std_path()).unwrap();
    assert!(meta.file_type().is_dir(), "final_dir must be a directory");
    assert!(
        !staging.as_std_path().exists(),
        "staging path must be removed after EINVAL fallback",
    );
    // Operator-facing trace: production warns when this branch
    // fires so `journalctl -p warning` surfaces the fallback
    // even when the apply succeeds. Pin the message substring
    // so a future tracing refactor can't silently drop it.
    assert!(
        logs_contain("falling back to remove-then-rename"),
        "EINVAL fallback must emit a tracing::warn",
    );
}

#[test]
#[tracing_test::traced_test]
fn extract_and_swap_enosys_fallback_replaces_final_dir() {
    // Force ENOSYS — same fallback arm as EINVAL
    // (`Err(EINVAL) | Err(ENOSYS)` in the match), exercises the
    // older-kernel branch where renameat2 is not implemented at
    // all. Post-conditions identical, and the same warn message
    // fires.
    let _guard = ForcedRenameAt2Errno::new(nix::errno::Errno::ENOSYS);
    let tmp = tempfile::tempdir().unwrap();
    let (runner_home, final_dir, staging, tarball_path) =
        renameat2_test_layout(&tmp, "bin.enosys", ".staging-enosys");
    populate_final_dir(&final_dir, b"old-payload");
    let file = write_and_open_tarball(&tarball_path, &tar_gz_with_marker(b"new-payload"));

    extract_and_swap_from_file(file, &staging, &runner_home, &final_dir)
        .expect("ENOSYS fallback must succeed via remove-then-rename");

    let body = fs::read(final_dir.join("marker.txt").as_std_path()).unwrap();
    assert_eq!(
        body, b"new-payload",
        "ENOSYS fallback must publish the new tree"
    );
    assert!(
        !staging.as_std_path().exists(),
        "staging path must be removed after ENOSYS fallback",
    );
    assert!(
        logs_contain("falling back to remove-then-rename"),
        "ENOSYS fallback must emit a tracing::warn",
    );
}

#[test]
#[tracing_test::traced_test]
fn extract_and_swap_exdev_fallback_uses_copy_then_remove() {
    // Force EXDEV — exercises the cross-filesystem branch, which
    // calls `fs::remove_dir_all(final_dir)` then
    // `copy_dir_recursive(staging, final_dir)` then
    // `fs::remove_dir_all(staging)`. Same post-conditions: new
    // payload at final_dir, staging gone. (The actual underlying
    // filesystem is single-FS in this test; the seam fakes EXDEV
    // so the copy branch is exercised regardless.) The warn-
    // level tracing message MUST distinguish this branch from
    // the EINVAL/ENOSYS branch so journalctl readers know whether
    // a copy or a rename happened.
    let _guard = ForcedRenameAt2Errno::new(nix::errno::Errno::EXDEV);
    let tmp = tempfile::tempdir().unwrap();
    let (runner_home, final_dir, staging, tarball_path) =
        renameat2_test_layout(&tmp, "bin.exdev", ".staging-exdev");
    populate_final_dir(&final_dir, b"old-payload");
    let file = write_and_open_tarball(&tarball_path, &tar_gz_with_marker(b"new-payload"));

    extract_and_swap_from_file(file, &staging, &runner_home, &final_dir)
        .expect("EXDEV fallback must succeed via copy-then-remove");

    let body = fs::read(final_dir.join("marker.txt").as_std_path()).unwrap();
    assert_eq!(
        body, b"new-payload",
        "EXDEV fallback must publish the new tree"
    );
    assert!(
        !staging.as_std_path().exists(),
        "staging path must be removed after EXDEV fallback",
    );
    assert!(
        logs_contain("cross-filesystem upgrade"),
        "EXDEV fallback must emit a distinguishable tracing::warn",
    );
}

#[test]
fn extract_and_swap_fresh_install_skips_renameat2() {
    // final_dir does NOT exist — fresh-install branch takes
    // `fs::rename` directly without ever calling renameat2.
    // Forcing EINVAL through the seam must NOT affect this path:
    // the test asserts success even though the seam would have
    // returned EINVAL if it had been reached.
    let _guard = ForcedRenameAt2Errno::new(nix::errno::Errno::EINVAL);
    let tmp = tempfile::tempdir().unwrap();
    let (runner_home, final_dir, staging, tarball_path) =
        renameat2_test_layout(&tmp, "bin.fresh", ".staging-fresh");
    // final_dir intentionally NOT pre-populated.
    let file = write_and_open_tarball(&tarball_path, &tar_gz_with_marker(b"fresh-payload"));

    extract_and_swap_from_file(file, &staging, &runner_home, &final_dir)
        .expect("fresh-install path must not touch renameat2");

    let body = fs::read(final_dir.join("marker.txt").as_std_path()).unwrap();
    assert_eq!(body, b"fresh-payload");
    assert!(
        !staging.as_std_path().exists(),
        "staging path must be gone (renamed to final_dir)",
    );
}

#[test]
fn extract_and_swap_propagates_unhandled_renameat2_errno() {
    // Force EACCES — not in the match's
    // `EINVAL | ENOSYS | EXDEV` set. The catch-all `Err(e)` arm
    // returns `GharsError::Io(e.into())` and aborts the publish.
    // Post-condition: final_dir still holds the OLD payload
    // (no overwrite occurred) and the function returns Err.
    let _guard = ForcedRenameAt2Errno::new(nix::errno::Errno::EACCES);
    let tmp = tempfile::tempdir().unwrap();
    let (runner_home, final_dir, staging, tarball_path) =
        renameat2_test_layout(&tmp, "bin.eacces", ".staging-eacces");
    populate_final_dir(&final_dir, b"old-payload");
    let file = write_and_open_tarball(&tarball_path, &tar_gz_with_marker(b"new-payload"));

    let outcome = extract_and_swap_from_file(file, &staging, &runner_home, &final_dir);
    assert!(
        outcome.is_err(),
        "unhandled errno (EACCES) must propagate as Err",
    );
    // OLD payload survives the failed swap. Either the
    // RENAME_EXCHANGE branch did not commit (we never reached
    // remove_dir_all) or the function aborted before any
    // mutation. The catch-all `Err(e) => return Err(...)` arm
    // happens BEFORE any mutation in the RENAME_EXCHANGE branch,
    // so final_dir's contents must be untouched.
    let body = fs::read(final_dir.join("marker.txt").as_std_path()).unwrap();
    assert_eq!(
        body, b"old-payload",
        "unhandled-errno path must NOT mutate final_dir",
    );
}
