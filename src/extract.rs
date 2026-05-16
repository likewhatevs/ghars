//! Streaming download + sha256 verify + tar.gz extract with safe filter.
//!
//! Design spec: Part 11 (behavioral edge cases) + Part 9f (versioned bin/) +
//! Part 17 SEC-09/SEC-10/SEC-31/SEC-33.
//!
//! Behavior ports the legacy Python install tool:
//! - `http_download` streams via reqwest blocking 64KiB chunks with a finite
//!   timeout (matches Python `httpx.stream` + `HTTP_DOWNLOAD_TIMEOUT`).
//! - `sha256_of` reads in 64KiB chunks, returns lowercase hex.
//! - `download_and_verify` deletes the dest file on SHA256 mismatch
//!   and compares case-insensitively.
//! - `safe_member_filter` rejects path traversal, symlink/hardlink escape,
//!   and device/fifo/char/block entries. Mode stripping (setuid/setgid/
//!   sticky) and uid/gid inheritance happen via tar-rs `Archive` defaults
//!   (`preserve_permissions = false`, `preserve_ownerships = false`),
//!   not via the filter itself (SEC-10).
//! - `install_runner_binary` (Part 9f + SEC-09/SEC-33) extracts into a
//!   root-owned staging dir under `<state_dir>/.staging/`, then atomically
//!   renames into `bin.<version>/` under runner home. Root-owned end to end.
//! - `verify_local_tarball` (SEC-16 residual) re-stats the
//!   operator-supplied `runner_tarball` config field at use time,
//!   refusing if it has become a symlink or non-regular file between
//!   validation and use.

use crate::error::{format_error_chain, human_bytes};
use crate::{GharsError, Result, USER_AGENT};
use camino::{Utf8Path, Utf8PathBuf};
use sha2::{Digest, Sha256};
use std::fs::{self, File};
use std::io::{Read, Write};
use std::time::Duration;

const CHUNK_SIZE: usize = 65_536;

/// Hard cap on bytes streamed by `http_download`.
///
/// The actions/runner Linux tarball runs ~250 MiB (x64 + arm64 weigh in
/// at ~245 MB and ~210 MB respectively, observed at v2.334.0). 512 MiB
/// gives ~2x headroom over the legitimate maximum.
///
/// Why this cap is load-bearing:
///   - `http_download` streams the response into a destination file via
///     a 64 KiB chunk loop. With the `gzip` reqwest feature enabled
///     (Cargo.toml), a hostile origin can serve a small compressed
///     payload that decompresses to terabytes; the chunked loop has no
///     intrinsic upper bound on bytes written.
///   - The cap is enforced as a cumulative byte counter inside the
///     read loop; once `total > MAX`, the partial file is unlinked and
///     `GharsError::Tarball` is raised. The unlink mirrors the
///     post-failure `fs::remove_file` cleanup in
///     `download_and_verify` (the SHA256-mismatch arm) so a
///     half-written destination cannot be promoted by a later SHA256
///     check.
///   - 512 MiB is generous against the current ~200 MiB upstream tarballs;
///     leaves headroom for future runner binaries without churning the cap.
const MAX_TARBALL_DOWNLOAD_BYTES: u64 = 512 * 1024 * 1024;

/// Stream-download `url` into `dest`, with `timeout` capping the total
/// per-request time. Body is written in 64KiB chunks; nothing is held
/// fully in memory.
///
/// Enforces a `MAX_TARBALL_DOWNLOAD_BYTES` cap on cumulative bytes
/// streamed. The cap defends against compression-bomb responses (reqwest's
/// `gzip` feature auto-decompresses on the read path; an attacker who
/// can inject HTTP responses can decompress a small payload to terabytes
/// without the streaming loop noticing). On overflow the partial
/// destination file is unlinked before returning the error so a
/// half-written file cannot be promoted by a subsequent SHA256 check.
///
/// # Errors
///
/// - `GharsError::Tarball` if the HTTP response is non-2xx, the request
///   fails, the client cannot be built, OR the response body exceeds
///   `MAX_TARBALL_DOWNLOAD_BYTES` post-decompression.
/// - `GharsError::Io` if the destination file cannot be created or written.
pub fn http_download(url: &str, dest: &Utf8Path, timeout: Duration) -> Result<()> {
    http_download_with_cap(url, dest, timeout, MAX_TARBALL_DOWNLOAD_BYTES)
}

/// Production wraps this with `MAX_TARBALL_DOWNLOAD_BYTES`.
/// Tests can call this directly with a small `max_bytes` (e.g. 64) to
/// exercise the cap-firing branch + unlink-on-overflow cleanup
/// without serving a 512 MiB body.
fn http_download_with_cap(
    url: &str,
    dest: &Utf8Path,
    timeout: Duration,
    max_bytes: u64,
) -> Result<()> {
    // Walk the full source chain on every io::Error / reqwest::Error so
    // an operator triaging a TLS/DNS/transport failure on tarball
    // download sees the inner cause (e.g. rustls reason code,
    // hyper transport reason) and not just the outer Display layer.
    // Bare `?` on `io::Error` invokes `From<io::Error> for GharsError`
    // which uses the default Display — that drops nested causes. Each
    // I/O site below wraps explicitly via `format_error_chain`.
    let client = reqwest::blocking::Client::builder()
        .user_agent(USER_AGENT)
        .timeout(timeout)
        .connect_timeout(timeout)
        .build()
        .map_err(|e| {
            GharsError::Tarball(
                format!(
                    "download failed: client build: {chain}: {url}",
                    chain = format_error_chain(&e)
                ),
                None,
            )
        })?;

    let mut resp = client.get(url).send().map_err(|e| {
        GharsError::Tarball(
            format!(
                "download failed: {chain}: {url}",
                chain = format_error_chain(&e)
            ),
            None,
        )
    })?;

    let status = resp.status();
    if !status.is_success() {
        return Err(GharsError::Tarball(
            format!("download failed ({status}): {url}"),
            None,
        ));
    }

    // Layer 1: raw Content-Length header pre-check via the shared
    // `http_cap::content_length_exceeds` helper. Reject before
    // opening `dest` so a zero-byte partial file cannot be promoted
    // by a later step. Malformed Content-Length falls through to
    // Layer 2 streaming backstop (the cumulative byte counter inside
    // the chunk loop).
    if let Some(cl) = crate::http_cap::content_length_exceeds(resp.headers(), max_bytes) {
        return Err(GharsError::Tarball(
            format!(
                "download failed: {url}: Content-Length {cl_h} ({cl} bytes) exceeds {max_h} ({max_bytes} bytes); \
                             the on-wire (pre-decompression) Content-Length is suspiciously large; \
                             verify network path (compromised mirror, hostile proxy CA, or non-GitHub \
                             origin); if the upstream payload is legitimately this large, file a \
                             ghars issue to raise MAX_TARBALL_DOWNLOAD_BYTES",
                cl_h = human_bytes(cl),
                max_h = human_bytes(max_bytes)
            ),
            None,
        ));
    }

    let mut out = File::create(dest).map_err(|e| {
        GharsError::Tarball(
            format!(
                "download failed: create {dest}: {chain}: {url}",
                chain = format_error_chain(&e)
            ),
            None,
        )
    })?;
    let mut buf = vec![0u8; CHUNK_SIZE];
    let mut total: u64 = 0;
    loop {
        let n = resp.read(&mut buf).map_err(|e| {
            GharsError::Tarball(
                format!(
                    "download failed: read: {chain}: {url}",
                    chain = format_error_chain(&e)
                ),
                None,
            )
        })?;
        if n == 0 {
            break;
        }
        // post-decompression cumulative byte counter. Saturating
        // add keeps the comparison sound in the impossible 2^64-byte
        // edge case; the cap fires far below that.
        total = total.saturating_add(n as u64);
        if total > max_bytes {
            // Drop the file handle BEFORE unlinking so the inode is
            // released cleanly on every Unix; otherwise the unlink
            // succeeds but disk space stays held until the fd closes.
            drop(out);
            // tracing::warn! on cleanup failure so the operator knows
            // the partial download remains on disk. Returning the
            // cap-fire error is more important than the cleanup
            // error — a stale partial file is recoverable, but the
            // operator must see why the download was rejected — so we
            // log rather than propagate. Without this log the
            // ENOSPC / EACCES that prevented cleanup vanishes
            // silently and the operator wonders why a `dest` that
            // "should" be gone is still occupying space.
            if let Err(rm_err) = fs::remove_file(dest) {
                tracing::warn!(
                    dest = %dest,
                    error = %format_error_chain(&rm_err),
                    "failed to remove partial download after cap fire; \
                     partial file remains on disk"
                );
            }
            return Err(GharsError::Tarball(
                format!(
                    "download failed: {url}: response body exceeds {max_h} ({max_bytes} bytes) \
                     post-decompression; the post-decompression body is larger than expected; \
                     this can indicate a deliberately-crafted payload OR a legitimately large \
                     upstream response; verify network path (compromised mirror, hostile proxy \
                     CA, or non-GitHub origin); if the upstream payload is legitimately this \
                     large, file a ghars issue to raise MAX_TARBALL_DOWNLOAD_BYTES",
                    max_h = human_bytes(max_bytes)
                ),
                None,
            ));
        }
        out.write_all(&buf[..n]).map_err(|e| {
            GharsError::Tarball(
                format!(
                    "download failed: write {dest}: {chain}: {url}",
                    chain = format_error_chain(&e)
                ),
                None,
            )
        })?;
    }
    out.flush().map_err(|e| {
        GharsError::Tarball(
            format!(
                "download failed: flush {dest}: {chain}: {url}",
                chain = format_error_chain(&e)
            ),
            None,
        )
    })?;
    Ok(())
}

/// Compute the SHA-256 digest of `path` as 64 lowercase hex characters,
/// reading in 64KiB chunks.
///
/// # Errors
///
/// `GharsError::Io` if the file cannot be opened or read.
pub fn sha256_of(path: &Utf8Path) -> Result<String> {
    let mut f = File::open(path)?;
    let mut hasher = Sha256::new();
    let mut buf = vec![0u8; CHUNK_SIZE];
    loop {
        let n = f.read(&mut buf)?;
        if n == 0 {
            break;
        }
        hasher.update(&buf[..n]);
    }
    Ok(hex::encode(hasher.finalize()))
}

/// Download `url` to `dest` and verify its SHA-256 matches `expected_sha256`.
/// Comparison is case-insensitive; both sides are lowercased before
/// comparing. On mismatch, `dest` is deleted before returning the error.
///
/// # Errors
///
/// - Whatever [`http_download`] or [`sha256_of`] returns on transport / IO failure.
/// - `GharsError::Sha256Mismatch` if the digest does not match. The
///   destination file is unlinked before the error is returned (matches
///   the legacy Python install tool's behavior).
pub fn download_and_verify(
    url: &str,
    dest: &Utf8Path,
    expected_sha256: &str,
    timeout: Duration,
) -> Result<()> {
    http_download(url, dest, timeout)?;
    let actual = sha256_of(dest)?;
    let expected_lc = expected_sha256.to_ascii_lowercase();
    let actual_lc = actual.to_ascii_lowercase();
    if actual_lc != expected_lc {
        // tracing::warn! on cleanup failure so the operator knows the
        // mismatched payload remains on disk. The Sha256Mismatch error
        // is the operator's primary signal — a stale dest file is
        // recoverable but the operator must see WHY the file was
        // rejected — so we log the unlink failure rather than mask
        // the mismatch by propagating the cleanup error. Without this
        // log an EACCES / EROFS / ENOSPC that prevents cleanup
        // vanishes silently and the operator wonders why a `dest`
        // that "should be gone" still occupies space.
        if let Err(rm_err) = fs::remove_file(dest) {
            tracing::warn!(
                dest = %dest,
                error = %format_error_chain(&rm_err),
                "failed to remove sha256-mismatched download; \
                 mismatched file remains on disk and must be \
                 deleted manually before re-running install"
            );
        }
        return Err(GharsError::Sha256Mismatch {
            path: dest.to_string(),
            expected: expected_lc,
            actual: actual_lc,
        });
    }
    Ok(())
}

/// Outcome of running [`safe_member_filter`] on a tarball entry.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FilterDecision {
    /// Member is safe to extract; the caller may proceed with `unpack_in`.
    ///
    /// Mode masking: the tar crate's `unpack_in` honors the
    /// header's mode minus setuid/setgid/sticky by default — see
    /// tar-rs's permissions masking logic in `entry.rs::_set_perms`,
    /// which is what ghars uses (`set_preserve_ownerships` stays
    /// unset).
    Allow,
    /// Member must be skipped (PAX/GNU extension headers). Not an error;
    /// the tar crate handles these internally on the next iteration but
    /// we emit a decision so callers can be explicit.
    Skip,
}

/// Validate one tarball entry against the safe-extraction policy ported
/// from the legacy Python install tool:
///
/// - Reject device / fifo / char / block entries (typeflag 3, 4, 6).
/// - Reject member paths that are absolute or contain `..` components.
/// - Reject symlink / hardlink targets that are absolute or contain `..`.
///
/// Mode masking (setuid/setgid/sticky stripping) is NOT performed by
/// this function — it happens at unpack time via tar-rs's
/// `preserve_permissions = false` default (see [`FilterDecision::Allow`]).
///
/// uid / gid forcing happens at unpack time (the tar crate ignores
/// header-recorded uid/gid by default; ghars never enables
/// `set_preserve_ownerships`, so the file is created with the calling
/// process's uid/gid — matching `tar --no-same-owner`). The original
/// Python implementation forced `member.uid = os.getuid()` for the same
/// effect; in Rust the equivalent is "do not set `preserve_ownerships`".
///
/// # Errors
///
/// `GharsError::Tarball` with an actionable message describing which
/// rule was violated and the offending member name / link target.
pub fn safe_member_filter<R: Read>(entry: &tar::Entry<'_, R>) -> Result<FilterDecision> {
    use tar::EntryType as E;

    let kind = entry.header().entry_type();
    let path_bytes = entry.path_bytes();
    let name = String::from_utf8_lossy(&path_bytes).into_owned();

    if kind.is_pax_global_extensions()
        || kind.is_pax_local_extensions()
        || kind.is_gnu_longname()
        || kind.is_gnu_longlink()
    {
        return Ok(FilterDecision::Skip);
    }

    match kind {
        E::Char | E::Block | E::Fifo => {
            return Err(GharsError::Tarball(
                format!("tarball contains unsupported special file: {name} (type={kind:?})"),
                None,
            ));
        }
        _ => {}
    }

    if !is_safe_relative_path(&path_bytes) {
        return Err(GharsError::Tarball(
            format!("tarball contains unsafe member path: {name}"),
            None,
        ));
    }

    if kind.is_symlink() || kind.is_hard_link() {
        let link_bytes = entry.link_name_bytes().ok_or_else(|| {
            GharsError::Tarball(format!("link entry without target: {name}"), None)
        })?;
        let target = String::from_utf8_lossy(&link_bytes);
        // Absolute link targets always escape.
        if link_bytes.first() == Some(&b'/') {
            return Err(GharsError::Tarball(
                format!("tarball contains absolute link target in {name}: {target}"),
                None,
            ));
        }
        // Relative targets with `..` are allowed if resolving them
        // from the link's directory stays within the tree. The
        // actions/runner tarball legitimately uses `../lib/...`
        // targets for node symlinks.
        if !is_safe_resolved_link(&path_bytes, &link_bytes) {
            return Err(GharsError::Tarball(
                format!("tarball contains unsafe link target in {name}: {target}"),
                None,
            ));
        }
    }

    Ok(FilterDecision::Allow)
}

/// True if resolving `link_target` from the directory containing
/// `link_path` stays within the tarball tree (never goes above the
/// root). Both paths are relative; `link_target` may contain `..`.
fn is_safe_resolved_link(link_path: &[u8], link_target: &[u8]) -> bool {
    if link_target.is_empty() {
        return false;
    }
    // Start from the link's parent directory.
    let link_str = String::from_utf8_lossy(link_path);
    let target_str = String::from_utf8_lossy(link_target);
    let mut components: Vec<&str> = Vec::new();
    // Add link's directory components (everything before the last `/`).
    if let Some(parent) = std::path::Path::new(link_str.as_ref()).parent() {
        for c in parent.components() {
            if let std::path::Component::Normal(s) = c
                && let Some(s) = s.to_str()
            {
                components.push(s);
            }
        }
    }
    // Resolve the target path against the link's directory.
    for part in target_str.split('/') {
        match part {
            "" | "." => {}
            ".." => {
                if components.is_empty() {
                    // Would go above the tarball root -- escape.
                    return false;
                }
                components.pop();
            }
            _ => components.push(part),
        }
    }
    true
}

/// True if `bytes` is a relative path with no `..` components and no
/// leading `/`. Empty inputs are rejected as a safety belt; the tar
/// reader sees that at most as a degenerate header which we don't trust.
fn is_safe_relative_path(bytes: &[u8]) -> bool {
    if bytes.is_empty() {
        return false;
    }
    if bytes.first() == Some(&b'/') {
        return false;
    }
    for component in bytes.split(|&b| b == b'/') {
        if component == b".." {
            return false;
        }
    }
    true
}

/// Extract a `.tar.gz` from `tarball` into `dest`, applying
/// [`safe_member_filter`] to every entry and refusing to extract entries
/// that fail the filter.
///
/// Defense in depth against the symlink-after-extract attack:
///
/// 1. [`safe_member_filter`] rejects any entry whose member path or
///    link target is absolute or contains `..`. This is the primary
///    defense.
/// 2. `tar::Entry::unpack_in` canonicalizes the parent of every member
///    before writing via `tar::entry::EntryFields::validate_inside_dst`.
///    Any pre-extracted symlink in the staging tree that points
///    outside dest is detected when the next member's parent path is
///    canonicalized.
/// 3. After every successful unpack, this function additionally
///    canonicalizes the rendered path's parent and asserts it stays
///    inside the canonical dest. This catches a future filter
///    regression or a tar-crate bug that lets an entry through layer
///    1 + 2 — a third independent gate.
///
/// Mode and ownership rules (matches the legacy Python install tool):
///
/// - `Archive` is constructed with `preserve_permissions = false` (the
///   crate default), which causes `tar::entry::_set_perms` to write
///   `mode & 0o777` to the file. That is bit-equivalent to the Python
///   tool's `mode & 0o777 & ~0o7000` because 0o7000 lies entirely outside
///   0o777, so setuid/setgid/sticky are stripped by construction.
/// - `preserve_ownerships = false` (default) means the file is created
///   with the calling process's uid/gid, matching `member.uid = os.getuid()`.
///
/// # Errors
///
/// - `GharsError::Tarball` if the archive contains an unsafe member, or
///   if the post-extract path-containment check detects an escape.
/// - `GharsError::Io` for IO failures (open, read, write, mkdir).
pub fn extract_tarball(tarball: &Utf8Path, dest: &Utf8Path) -> Result<()> {
    let f = File::open(tarball)?;
    extract_tarball_from_file(f, dest)
}

/// SEC-16: extract a tarball from an already-opened File handle.
///
/// Equivalent to [`extract_tarball`] but reads from a pre-opened
/// `File` instead of re-opening the path. Used by
/// [`install_runner_binary`] to close the lstat-then-extract TOCTOU
/// window: the path is opened ONCE under `O_NOFOLLOW` (rejecting
/// symlinks at open time + reading metadata via fstat on the same
/// inode), and the resulting File is threaded through to extraction
/// so the bytes the extractor reads are guaranteed to be from the
/// inode that was lstat-validated. A path-based re-open between
/// validation and extraction would let an attacker swap the file
/// contents (or replace the path with a symlink) between the two
/// syscalls.
///
/// # Errors
///
/// Same as [`extract_tarball`] — propagates Tarball / Io variants.
pub fn extract_tarball_from_file(tarball: File, dest: &Utf8Path) -> Result<()> {
    fs::create_dir_all(dest)?;
    let gz = flate2::read::GzDecoder::new(tarball);
    let mut archive = tar::Archive::new(gz);
    archive.set_overwrite(true);

    let canon_dest = fs::canonicalize(dest.as_std_path()).map_err(|e| {
        GharsError::Tarball(
            format!("cannot canonicalize extraction root {dest}: {e}"),
            None,
        )
    })?;

    let entries = archive.entries()?;
    for entry in entries {
        let mut entry = entry?;
        let decision = safe_member_filter(&entry)?;
        match decision {
            FilterDecision::Skip => continue,
            FilterDecision::Allow => {}
        }
        let path_bytes = entry.path_bytes().into_owned();
        let unpacked = entry
            .unpack_in(dest.as_std_path())
            .map_err(|e| GharsError::Tarball(format!("unpack: {e}"), None))?;
        if !unpacked {
            return Err(GharsError::Tarball(
                format!(
                    "entry rejected by tar crate path normalization: {}",
                    String::from_utf8_lossy(&path_bytes)
                ),
                None,
            ));
        }
        verify_extracted_inside_dest(&canon_dest, dest, &path_bytes)?;
    }
    // Batch directory fsync: walk the staging tree and fsync each
    // directory. This makes the directory entries (the child-name →
    // inode mappings) durable across a crash so a recovery sees the
    // same tree shape we just unpacked. Per-file fsync omitted — cost
    // (~3000 fsyncs for a typical actions-runner tarball) exceeds
    // benefit given that install_runner_binary re-extracts
    // unconditionally on next apply, so a half-durable file inside
    // staging is self-healed by the operator's next `ghars apply`.
    fsync_dir_tree(dest);
    Ok(())
}

/// Defense-in-depth post-extract check: verify the entry just unpacked
/// landed inside `canon_dest`. Walks `dest`-relative components from the
/// rendered path, then canonicalizes the parent directory (which exists
/// because `unpack_in` succeeded) and asserts it starts with the canonical
/// extraction root. Catches a hypothetical future filter regression or
/// tar-crate path-normalization bug; the primary defense remains
/// [`safe_member_filter`].
fn verify_extracted_inside_dest(
    canon_dest: &std::path::Path,
    dest: &Utf8Path,
    member_path_bytes: &[u8],
) -> Result<()> {
    use std::os::unix::ffi::OsStrExt;
    use std::path::{Component, PathBuf};
    let raw_os = std::ffi::OsStr::from_bytes(member_path_bytes);
    let raw = std::path::Path::new(raw_os);
    // Skip entries that resolve to the extraction root itself (e.g.
    // `./` or `.`). These are the tarball's root directory entry and
    // don't extract content outside dest. Their parent is dest's
    // parent, which would fail the starts_with check.
    let has_normal = raw
        .components()
        .any(|c| matches!(c, Component::Normal(_)));
    if !has_normal {
        return Ok(());
    }
    let mut rendered: PathBuf = dest.as_std_path().to_path_buf();
    for part in raw.components() {
        match part {
            Component::Prefix(..) | Component::RootDir | Component::CurDir => {}
            Component::ParentDir => {
                return Err(GharsError::Tarball(
                    format!(
                        "post-extract verify: member path contains `..` after filter accepted it: {}",
                        String::from_utf8_lossy(member_path_bytes)
                    ),
                    None,
                ));
            }
            Component::Normal(p) => rendered.push(p),
        }
    }
    let Some(parent) = rendered.parent() else {
        return Ok(());
    };
    let canon_parent = fs::canonicalize(parent).map_err(|e| {
        GharsError::Tarball(
            format!(
                "post-extract verify: canonicalize {} failed: {e}",
                parent.display()
            ),
            None,
        )
    })?;
    if !canon_parent.starts_with(canon_dest) {
        let escaped_path = String::from_utf8_lossy(member_path_bytes).into_owned();
        let _ = fs::remove_file(&rendered);
        let _ = fs::remove_dir(&rendered);
        return Err(GharsError::Tarball(
            format!(
                "post-extract verify: member {escaped_path} escaped extraction root \
                 (canonical parent {} not under {})",
                canon_parent.display(),
                canon_dest.display()
            ),
            None,
        ));
    }
    Ok(())
}

/// Verify the operator-supplied `runner_tarball` path is still a
/// regular file (not a symlink) at use time, closing the SEC-16
/// residual TOCTOU window. Validators check this at parse time;
/// this function re-checks just before extraction.
///
/// # Errors
///
/// `GharsError::Tarball` if the path is now a symlink, missing, or not a
/// regular file.
pub fn verify_local_tarball(path: &Utf8Path) -> Result<()> {
    // Drops the File handle immediately; preserves the
    // `Result<()>`-returning surface for callers that only need a
    // pre-flight gate (apply.rs::execute_create_runner uses this
    // before the actual install). install_runner_binary calls
    // `verify_local_tarball_open` instead so the validated fd
    // threads through to the extractor.
    verify_local_tarball_open(path).map(|_file| ())
}

/// TOCTOU-safe variant of [`verify_local_tarball`] that returns the
/// opened File so the caller can pass it to
/// [`extract_tarball_from_file`] without re-opening the path. The
/// path is opened with `O_NOFOLLOW` (kernel rejects symlinks at
/// open time) and the regular-file gate reads metadata via fstat on
/// the same inode — so the File handle the caller receives
/// describes the same inode that passed validation. A subsequent
/// path-based re-open would let an attacker swap the file (or the
/// path's resolution) between the two syscalls.
///
/// # Errors
///
/// `GharsError::Tarball` if the path is now a symlink, missing, or
/// not a regular file.
pub fn verify_local_tarball_open(path: &Utf8Path) -> Result<File> {
    let (file, meta) =
        crate::validators::open_no_follow_with_meta(path.as_std_path()).map_err(|e| {
            // ELOOP from O_NOFOLLOW is the symlink-rejection path —
            // surface it specifically so the operator doesn't conflate
            // it with a missing-file error.
            if e.raw_os_error() == Some(libc::ELOOP) {
                GharsError::Tarball(
                    format!("runner_tarball is now a symlink (was not at validation time): {path}"),
                    None,
                )
            } else {
                GharsError::Tarball(
                    format!("runner_tarball cannot be opened: {path}: {e}"),
                    None,
                )
            }
        })?;
    if !meta.is_file() {
        return Err(GharsError::Tarball(
            format!("runner_tarball is no longer a regular file: {path}"),
            None,
        ));
    }
    Ok(file)
}

/// Install a runner tarball into `runner_home/bin.<version>/` via the
/// extract-as-root + atomic-rename pattern (SEC-09 / SEC-33).
///
/// **Concurrency contract:** MUST be called under `apply.lock`
/// (acquired in `apply::apply`). `apply::gc_stale_staging_dirs`
/// assumes exclusive access to `<state_dir>/.staging/` under that
/// lock — concurrent callers would race the GC's age-and-PID gates
/// and risk having an in-flight staging tree GC'd from underneath
/// them. Direct callers outside `apply::apply` (CLI helpers,
/// integration tests, future hidden subcommands) MUST acquire the
/// lock first or vouch in their own doc-comment that the GC is not
/// running.
///
/// 1. Assert the calling process is EUID 0 (defense-in-depth: SEC-09
///    requires the staging tree and final `bin.X.Y.Z/` to be root-owned
///    end-to-end). The check is skipped under `cfg(test)` so unit tests
///    can drive the function as a normal user.
/// 2. Create a private staging directory under
///    `<state_dir>/.staging/<runner-name>-<version>-<pid>/` with mode 0700.
/// 3. Verify and extract the tarball into staging via [`extract_tarball`].
/// 4. Publish staging at `<runner_home>/bin.<version>/` via
///    [`extract_and_swap_from_file`]: atomic
///    `renameat2(RENAME_EXCHANGE)` on upgrade (existing
///    `bin.<version>/` is swapped with the staging tree, then the
///    displaced old tree is removed), plain `rename(2)` on fresh
///    install. On upgrade, EINVAL/ENOSYS (legacy kernel/FS without
///    `RENAME_EXCHANGE`) falls back to remove-then-rename, and EXDEV
///    (cross-filesystem) falls back to remove-then-copy-then-remove.
///    Both fallbacks emit `tracing::warn` so operators see the
///    degraded path.
///
/// `state_dir` is the parent under which `.staging/` lives (the design
/// pins this to `/var/lib/ghars/.staging/`; tests redirect both
/// `state_dir` and `runner_home` to a tempdir). `runner_home` is the
/// per-runner home directory
/// (`/var/lib/ghars/<trust_zone>/ghars-<runner-name>/`, per
/// `paths::Paths::runner_home`).
///
/// On success the staging directory has been moved and is no longer
/// present. On any failure the staging directory is best-effort removed
/// before propagating the error so an aborted apply does not leave
/// orphan trees in `.staging/`.
///
/// On success the freshly-installed tree lives directly at
/// `runner_home/bin.<version>/` — there is no `bin` symlink and no
/// post-install swap step. Apply.rs runs `config.sh` from
/// `runner_home/config.sh` (the runner-shipped script the tar
/// contains at the home root); `apply::build_register_cmd` sets
/// `Command::current_dir` to `runner_home` so `config.sh` resolves
/// relative paths (including its default `_work` directory) against
/// the runner home.
///
/// # Errors
///
/// - `GharsError::Preflight` if the calling process is not root (release
///   builds only).
/// - `GharsError::Tarball` for malformed archives or filter violations.
/// - `GharsError::Io` for IO failures (mkdir, rename, open).
pub fn install_runner_binary(
    tarball_path: &Utf8Path,
    state_dir: &Utf8Path,
    runner_home: &Utf8Path,
    runner_name: &str,
    version: &str,
) -> Result<Utf8PathBuf> {
    require_root_for_install()?;
    // SEC-16: open the tarball once (under O_NOFOLLOW + fstat) and
    // thread the resulting File through to extraction. The pre-fix
    // path called verify_local_tarball (lstat by path) and then
    // re-opened the path inside extract_tarball — between those two
    // syscalls an attacker could swap the file or replace the path
    // with a symlink, defeating the lstat gate.
    let tarball_file = verify_local_tarball_open(tarball_path)?;

    let staging_root = state_dir.join(".staging");
    fs::create_dir_all(&staging_root)?;
    set_dir_mode(&staging_root, 0o700)?;

    let pid = std::process::id();
    let staging = staging_root.join(format!("{runner_name}-{version}-{pid}"));
    if staging.exists() {
        fs::remove_dir_all(&staging)?;
    }
    fs::create_dir(&staging)?;
    set_dir_mode(&staging, 0o700)?;

    let final_dir = runner_home.join(format!("bin.{version}"));
    let outcome = extract_and_swap_from_file(tarball_file, &staging, runner_home, &final_dir);
    if outcome.is_err() {
        let _ = fs::remove_dir_all(&staging);
    }
    outcome?;
    // DynamicUser runs as a non-root UID. The staging dir was 0700
    // (root-only during extraction for SEC-09). Open it up so the
    // runner process can read the binary tree at runtime.
    set_dir_mode(&final_dir, 0o755)?;
    Ok(final_dir)
}

/// SEC-09 / SEC-33 defense-in-depth: refuse to extract from a non-root
/// process. apply.rs's preflight gates this at the program level; the
/// per-call check here protects against direct API misuse from tests or
/// future call sites that bypass preflight. Skipped under `cfg(test)`
/// so the in-module test suite can run unprivileged.
#[cfg(not(test))]
fn require_root_for_install() -> Result<()> {
    if nix::unistd::geteuid().is_root() {
        Ok(())
    } else {
        Err(GharsError::Preflight(
            "install_runner_binary called as non-root".into(),
            "ghars apply must be invoked with sudo so the bin.X.Y.Z tree is root-owned end-to-end (SEC-09 / SEC-33); rerun with sudo or use --dry-run".into(),
        ))
    }
}

#[cfg(test)]
fn require_root_for_install() -> Result<()> {
    Ok(())
}

/// Prune old `bin.X.Y.Z/` directories under `runner_home`, keeping
/// the `keep_versions` most-recent by mtime plus the directory any
/// operator-created `bin` symlink currently resolves to (always
/// preserved regardless of mtime ordering).
///
/// Design Part 9f retention semantics:
/// - Directory candidates: any entry matching `bin.<rest>` where
///   `<rest>` is non-empty and `<rest>` is NOT `tmp`. Plain `bin`
///   (no suffix) and `bin.tmp` are excluded automatically by the
///   prefix-then-non-empty-non-tmp shape: ghars no longer creates
///   either name, but the pruner defensively skips both shapes in
///   case an operator placed one there.
/// - Sort by mtime descending (newest first); keep the first
///   `keep_versions` entries plus whatever any operator-created `bin`
///   symlink points at (defense in depth: if a sysadmin `touch`'d
///   an older tree, mtime ordering would otherwise prune it; we
///   conservatively skip-protect anything they explicitly pointed
///   at).
/// - Remove the rest via `fs::remove_dir_all`. Failures on individual
///   directories are aggregated and the function continues — pruning
///   is best-effort cleanup, not an integrity gate. Returns
///   `Ok(prune_count)` describing how many trees were removed.
///
/// `keep_versions` MUST be at least 1 (a value of 0 would prune the
/// just-installed bin tree). The plan layer (`plan.rs::plan_from`)
/// enforces this by clamping `Defaults.keep_versions` via
/// `unwrap_or(DEFAULT_KEEP_VERSIONS).max(1)` before the value reaches
/// apply.
///
/// # Errors
///
/// `GharsError::Io` only on `read_dir(runner_home)` failure (cannot
/// proceed without an entry list). Per-entry failures are logged and
/// counted but do not propagate.
pub fn prune_old_bin_versions(runner_home: &Utf8Path, keep_versions: u32) -> Result<usize> {
    if keep_versions == 0 {
        return Err(GharsError::Validation(
            "prune_old_bin_versions called with keep_versions=0".into(),
            "keep_versions must be >= 1; 0 would prune the just-installed bin tree (set Defaults.keep_versions = 1 or higher, or omit for the default of 2)".into(),
        ));
    }
    let active_target: Option<Utf8PathBuf> = match fs::read_link(runner_home.join("bin")) {
        Ok(target) => {
            // ghars no longer creates a `bin` symlink, so this
            // branch only fires when an operator placed one. A
            // relative target (e.g. `bin.2.334.0`) is joined against
            // runner_home for absolute comparison against
            // `entry.path()`. Non-UTF-8 targets are dropped: we
            // conservatively refuse to skip-protect a path we cannot
            // round-trip through the comparison logic.
            let abs = if target.is_absolute() {
                target
            } else {
                runner_home.as_std_path().join(target)
            };
            Utf8PathBuf::from_path_buf(abs).ok()
        }
        Err(_) => None,
    };

    let entries = fs::read_dir(runner_home.as_std_path())?;
    let mut versioned: Vec<(Utf8PathBuf, std::time::SystemTime)> = Vec::new();
    for entry in entries.flatten() {
        let Some(name) = entry.file_name().to_str().map(str::to_owned) else {
            continue;
        };
        // Match `bin.<non-empty-suffix>` where suffix != "tmp". Plain
        // `bin` (no dot) is excluded by the strip_prefix check; `bin.tmp`
        // is excluded because operators sometimes use that name for
        // staging trees and ghars must not prune it.
        let Some(suffix) = name.strip_prefix("bin.") else {
            continue;
        };
        if suffix.is_empty() || suffix == "tmp" {
            continue;
        }
        // Use symlink_metadata (lstat) so symlinks are excluded from
        // the candidate set entirely. entry.metadata() follows
        // symlinks: an attacker-planted `bin.evil → /etc` would
        // otherwise have metadata() report /etc's metadata
        // (is_dir() = true), the symlink would enter the prune
        // candidate set. Although std's remove_dir_all is
        // hardened to unlink-only on symlinks (Rust 1.62+), the
        // inclusion is still wrong — same TOCTOU-via-symlink class
        // as a path-based recursive chmod would expose.
        let meta = match fs::symlink_metadata(entry.path()) {
            Ok(m) => m,
            Err(_) => continue,
        };
        if !meta.is_dir() {
            continue;
        }
        let mtime = meta.modified().unwrap_or(std::time::SystemTime::UNIX_EPOCH);
        let path = match Utf8PathBuf::from_path_buf(entry.path()) {
            Ok(p) => p,
            Err(_) => continue,
        };
        versioned.push((path, mtime));
    }

    // Sort newest-first.
    versioned.sort_by(|a, b| b.1.cmp(&a.1));

    let keep_n = keep_versions as usize;
    let mut pruned = 0usize;
    for (path, _) in versioned.iter().skip(keep_n) {
        if active_target
            .as_deref()
            .is_some_and(|t| paths_equal(t, path))
        {
            // Defense-in-depth: if a sysadmin touched an older bin
            // tree so its mtime exceeds the current install's, the
            // active symlink target would otherwise sort outside the
            // top-N. Skip removal unconditionally for the active
            // target.
            continue;
        }
        if let Err(e) = fs::remove_dir_all(path.as_std_path()) {
            // Best-effort cleanup; record but do not propagate. The
            // operator's next apply will retry.
            tracing::warn!(
                path = %path,
                error = %e,
                "prune_old_bin_versions: failed to remove old bin tree"
            );
            continue;
        }
        pruned += 1;
    }
    Ok(pruned)
}

/// Compare two paths for equality after canonicalizing trailing
/// slashes. We avoid `fs::canonicalize` (would resolve symlinks and
/// fail for missing paths); for our purposes a byte-equal check
/// after normalization is sufficient because both inputs come from
/// trusted construction (`read_link` result + `read_dir` entry path).
fn paths_equal(a: &Utf8Path, b: &Utf8Path) -> bool {
    a.as_str().trim_end_matches('/') == b.as_str().trim_end_matches('/')
}

/// Marker for `RENAME_EXCHANGE` that compiles on every `target_env`.
/// nix 0.29 gates `RenameFlags` behind `target_env = "gnu"`;
/// this zero-sized stand-in avoids the conditional-compile issue
/// on musl while keeping the call site explicit about intent.
struct RenameExchange;

/// `cfg(test)`-only test seam over the `renameat2(RENAME_EXCHANGE)`
/// upgrade-in-place path. When the thread-local
/// [`tests::FORCED_RENAMEAT2_ERRNO`] cell is set, returns the
/// configured synthetic `Errno` (drives the EINVAL, ENOSYS, EXDEV,
/// or unhandled-errno branches of [`extract_and_swap_from_file`]
/// without requiring a kernel that actually rejects the call).
/// Per-thread state means parallel tests cannot interfere — each
/// test sets its own forcing on its own thread, and no global lock
/// is needed. Production builds compile a no-op shim that delegates
/// to the real syscall on gnu and to a synthetic `ENOSYS` on musl
/// (routing musl targets through the existing remove-then-rename
/// fallback at compile time, since `nix::fcntl::renameat2` is gated
/// behind `target_env = "gnu"` in nix 0.29).
#[cfg(test)]
fn renameat2_exchange_with_test_seam(
    old_path: &std::path::Path,
    new_path: &std::path::Path,
    _flag: RenameExchange,
) -> nix::Result<()> {
    if let Some(forced) = tests::FORCED_RENAMEAT2_ERRNO.with(std::cell::Cell::get) {
        return Err(forced);
    }
    renameat2_exchange_real(old_path, new_path)
}

#[cfg(not(test))]
#[inline(always)]
fn renameat2_exchange_with_test_seam(
    old_path: &std::path::Path,
    new_path: &std::path::Path,
    _flag: RenameExchange,
) -> nix::Result<()> {
    renameat2_exchange_real(old_path, new_path)
}

/// Real `renameat2(RENAME_EXCHANGE)` invocation, routed at compile
/// time. On gnu, delegate to `nix::fcntl::renameat2` (which wraps
/// `libc::renameat2` — only available on glibc). On any other libc
/// (musl, android, …), `nix::fcntl::renameat2` is not compiled so
/// we synthesize `Errno::ENOSYS`; the caller handles that errno by
/// falling back to remove-then-rename. The `unsafe_code = "forbid"`
/// lint rules out a direct `libc::syscall(SYS_renameat2, ...)`
/// invocation here, and `libc::renameat2` itself is gated to glibc
/// in libc 0.2.x — pulling rustix just for this one call would
/// add a substantial dependency for no atomicity benefit on musl:
/// apply.rs holds the global `apply.lock` and stops the runner unit
/// before [`extract_and_swap_from_file`] runs, so the brief
/// absent-final window in the fallback is unobservable.
#[cfg(target_env = "gnu")]
#[inline]
fn renameat2_exchange_real(
    old_path: &std::path::Path,
    new_path: &std::path::Path,
) -> nix::Result<()> {
    // nix 0.31 dropped the `Option<RawFd>` arity in favor of `AsFd`.
    // Open `/` as the dir-fd for both ends so the calls reference an
    // absolute starting point — the actual filesystem locations come
    // from `old_path` / `new_path` which are absolute. Keeping the
    // workspace `unsafe_code = "forbid"` lint intact rules out the
    // `BorrowedFd::borrow_raw(AT_FDCWD)` alternative.
    let dirfd = std::fs::File::open("/")
        .map_err(|e| nix::errno::Errno::from_raw(e.raw_os_error().unwrap_or(libc::EIO)))?;
    nix::fcntl::renameat2(
        &dirfd,
        old_path,
        &dirfd,
        new_path,
        nix::fcntl::RenameFlags::RENAME_EXCHANGE,
    )
}

#[cfg(not(target_env = "gnu"))]
#[inline]
fn renameat2_exchange_real(
    _old_path: &std::path::Path,
    _new_path: &std::path::Path,
) -> nix::Result<()> {
    // Non-glibc target_env (musl, etc.). nix 0.29's renameat2 is
    // gnu-only; libc 0.2.x's `renameat2` symbol is also glibc-only.
    // Synthesizing ENOSYS routes [`extract_and_swap_from_file`]
    // through its existing remove-then-rename fallback, which is
    // safe under apply.lock + stopped runner unit.
    Err(nix::errno::Errno::ENOSYS)
}

/// Extract `tarball_path` into `staging`, then publish the staged tree
/// at `final_dir`. Three layers: (1) fresh install via plain `rename(2)`,
/// (2) upgrade-in-place via `renameat2(RENAME_EXCHANGE)` on glibc
/// targets (musl synthesizes `ENOSYS` at compile time, routing through
/// the fallback), (3) fallbacks for `EINVAL`/`ENOSYS` (remove-then-rename)
/// and `EXDEV` (copy-then-remove). The brief absent-final window in
/// the fallback is unobservable under `apply.lock` + stopped runner unit.
///
/// SEC-16 TOCTOU-safe: takes an already-opened tarball `File` and
/// threads it through to [`extract_tarball_from_file`] so the path is
/// not re-resolved between open-time validation and the read.
fn extract_and_swap_from_file(
    tarball_file: File,
    staging: &Utf8Path,
    runner_home: &Utf8Path,
    final_dir: &Utf8Path,
) -> Result<()> {
    extract_tarball_from_file(tarball_file, staging)?;
    fs::create_dir_all(runner_home)?;

    if final_dir.exists() {
        // Upgrade-in-place: atomically swap staging ↔ final_dir.
        // After RENAME_EXCHANGE, the OLD tree is at staging and the
        // new tree is at final_dir; we remove the displaced old tree.
        match renameat2_exchange_with_test_seam(
            staging.as_std_path(),
            final_dir.as_std_path(),
            RenameExchange,
        ) {
            Ok(()) => {
                fs::remove_dir_all(staging)?;
            }
            Err(nix::errno::Errno::EINVAL | nix::errno::Errno::ENOSYS) => {
                // Kernel < 3.15 or the filesystem doesn't implement
                // RENAME_EXCHANGE. Degrade to remove-then-rename:
                // there is a brief window where final_dir is absent,
                // but apply.rs's apply.lock + stopped runner unit
                // prevent any reader from observing it.
                tracing::warn!(
                    final_dir = %final_dir,
                    "renameat2(RENAME_EXCHANGE) unsupported on this kernel/FS; falling back to remove-then-rename (brief absent-final window covered by apply.lock)"
                );
                fs::remove_dir_all(final_dir)?;
                if let Err(e) = fs::rename(staging, final_dir) {
                    if is_cross_device_link(&e) {
                        copy_dir_recursive(staging, final_dir)?;
                        fs::remove_dir_all(staging)?;
                    } else {
                        return Err(GharsError::Io(e));
                    }
                }
            }
            Err(nix::errno::Errno::EXDEV) => {
                // staging and final_dir are on different
                // filesystems. RENAME_EXCHANGE cannot move data
                // across filesystems any more than rename can. Same
                // copy+remove fallback as for plain rename. Like
                // the EINVAL/ENOSYS arm above, this path has a
                // brief absent-final window between the
                // remove_dir_all and the copy completing — apply.rs
                // holds the global apply.lock and stops the runner
                // unit before this function runs, so no reader
                // observes the gap.
                tracing::warn!(
                    staging = %staging,
                    final_dir = %final_dir,
                    "cross-filesystem upgrade: falling back to copy-then-rename (brief absent-final window covered by apply.lock)"
                );
                fs::remove_dir_all(final_dir)?;
                copy_dir_recursive(staging, final_dir)?;
                fs::remove_dir_all(staging)?;
            }
            Err(e) => {
                return Err(GharsError::Io(e.into()));
            }
        }
    } else {
        // Fresh install: plain rename, with EXDEV fallback.
        match fs::rename(staging, final_dir) {
            Ok(()) => {}
            Err(e) if is_cross_device_link(&e) => {
                copy_dir_recursive(staging, final_dir)?;
                fs::remove_dir_all(staging)?;
            }
            Err(e) => return Err(GharsError::Io(e)),
        }
    }

    // Fsync both parent directories: runner_home (where the new
    // bin.<version>/ entry now lives) and staging.parent() (where
    // the staging entry was created and then either removed or, in
    // the RENAME_EXCHANGE path, repointed at the displaced old
    // tree before being rmdir'd). Both entries must survive a
    // crash for recovery to see consistent state.
    //
    // runner_home's fsync failure propagates: bin.<version>/ IS on
    // disk, but recovery may not see it without the metadata
    // journal flush, so the operator should see the error. The
    // staging-parent fsync failure is logged but not propagated:
    // staging is transient and orphan cleanup is handled by the
    // next install_runner_binary's pre-existing-staging removal
    // (extract.rs::install_runner_binary).
    fsync_directory(runner_home).map_err(|e| {
        tracing::warn!(
            runner_home = %runner_home,
            error = %e,
            "runner_home fsync failed after publishing bin.<version>/ — tree is on disk, retry safe"
        );
        e
    })?;
    if let Some(staging_parent) = staging.parent()
        && let Err(e) = fsync_directory(staging_parent)
    {
        tracing::warn!(
            staging_parent = %staging_parent,
            error = %e,
            "staging-parent fsync failed; staging cleanup is best-effort and the next apply removes any orphan"
        );
    }
    Ok(())
}

/// Open `path` as a directory under `O_NOFOLLOW | O_DIRECTORY` and
/// `sync_all` it. Used to make a directory's entry-list durable
/// after rename/remove modifies it. Errors propagate as
/// `GharsError::Io`. The flag pair pins intent: callers always pass
/// a directory they just wrote into and never want a symlink
/// resolved at this step.
fn fsync_directory(path: &Utf8Path) -> Result<()> {
    use std::os::unix::fs::OpenOptionsExt;
    std::fs::OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_NOFOLLOW | libc::O_DIRECTORY)
        .open(path.as_std_path())
        .and_then(|f| f.sync_all())
        .map_err(GharsError::Io)
}

/// Recursively fsync every directory under `root` (inclusive).
///
/// Used after [`extract_tarball_from_file`] writes the staging tree
/// to make directory entries durable across a crash: each directory
/// inode's child-list is flushed via [`fsync_directory`]. Per-file
/// fsync is intentionally omitted — see the call site for the cost/
/// benefit reasoning. Failures on individual directories are logged
/// at `warn` level and the walk continues; the worst case is a
/// non-durable child entry, which apply.rs's self-healing
/// re-extract covers on the next run.
///
/// Uses path-based `fs::read_dir` rather than fd-relative
/// operations: identical safety posture to [`copy_dir_recursive`]
/// — the staging tree is root-owned under `apply.lock` and
/// cannot be attacker-rewritten between the type-check and the
/// fsync.
fn fsync_dir_tree(root: &Utf8Path) {
    if let Err(e) = fsync_directory(root) {
        tracing::warn!(
            path = %root,
            error = %e,
            "fsync_dir_tree: root directory fsync failed; staging tree durability degraded but next apply re-extracts"
        );
    }
    let entries = match fs::read_dir(root.as_std_path()) {
        Ok(it) => it,
        Err(e) => {
            tracing::warn!(
                path = %root,
                error = %e,
                "fsync_dir_tree: read_dir failed; subtree fsync skipped (next apply re-extracts)"
            );
            return;
        }
    };
    for entry in entries.flatten() {
        let Ok(ftype) = entry.file_type() else {
            continue;
        };
        // Only recurse into real directories — skip symlinks (lstat-
        // style), regular files, and special inodes. Symlinks under
        // the staging tree exist (tar archives carry them) but we
        // do not follow them: their target is either inside the
        // tree (already covered by the recursion) or outside (the
        // safe_member_filter already rejected absolute / `..`
        // targets, but a symlink whose target points sideways
        // across the tree would still exist; following it could
        // double-fsync or hit a dangling link).
        if !ftype.is_dir() {
            continue;
        }
        let Ok(child_utf8) = Utf8PathBuf::from_path_buf(entry.path()) else {
            // Non-UTF-8 child name — should not occur for the
            // tar-crate-filtered inputs ghars accepts, but skipping
            // is the conservative choice.
            continue;
        };
        fsync_dir_tree(&child_utf8);
    }
}

/// True iff `e` is `EXDEV` ("Invalid cross-device link"). This is the
/// `rename(2)` errno when the source and destination paths are on
/// different mounted filesystems.
fn is_cross_device_link(e: &std::io::Error) -> bool {
    e.raw_os_error() == Some(libc::EXDEV)
}

/// Recursively copy `src` directory tree to `dst`. Preserves files,
/// directories, and symlinks (using `lchown`-style copy: read symlink
/// target with `read_link`, recreate at dest). Used as the EXDEV fallback
/// in [`extract_and_swap_from_file`] when source/dest are on different
/// filesystems.
///
/// # Safety precondition
///
/// `src` MUST be a root-owned directory under `apply.lock`; do NOT call
/// from contexts where `src` can be attacker-controlled. The walk uses
/// path-based stat (`fs::symlink_metadata` + `fs::read_dir`) rather than
/// fd-relative operations, so an attacker who can rewrite `src` between
/// the type check and the read could redirect the copy. The current call
/// site (`extract_and_swap_from_file`) feeds a freshly-extracted staging
/// tree owned by root under `<state_dir>/.staging/<runner-name>-…/`,
/// guarded by the global `apply.lock`, which satisfies the precondition.
///
/// Both `src` and `dst` must be root-owned paths under `apply.lock`. The
/// current call site passes staging (src) and `runner_home/bin.<version>/`
/// (dst); both are root-owned and gated by the global `apply.lock`.
///
/// Mode is preserved for regular files via `fs::copy` (which calls
/// `copy_file_range`/`sendfile` and copies metadata on Linux). Setuid/
/// setgid/sticky bits were already stripped by [`extract_tarball`] (via
/// the tar crate's default `mode & 0o777` write); the copy here cannot
/// re-introduce them because the source files don't have those bits.
fn copy_dir_recursive(src: &Utf8Path, dst: &Utf8Path) -> Result<()> {
    use std::os::unix::fs::PermissionsExt;
    let src_meta = fs::symlink_metadata(src)?;
    fs::create_dir_all(dst)?;
    let perms = fs::Permissions::from_mode(src_meta.permissions().mode() & 0o777);
    fs::set_permissions(dst, perms)?;
    for entry in fs::read_dir(src)? {
        let entry = entry?;
        let name = entry.file_name();
        // Use OsString-based join via the std PathBuf surface so
        // non-UTF-8 filenames round-trip byte-exactly. The previous
        // `name.to_string_lossy()` substituted U+FFFD for invalid
        // sequences, producing a destination filename that did NOT
        // match the source — silently corrupting the copy. Tarball
        // extracts under our `safe_member_filter` only emit ASCII
        // names today, but the EXDEV cross-FS fallback path is
        // generic and must not damage any name the kernel can
        // represent.
        let from = src.as_std_path().join(&name);
        let to = dst.as_std_path().join(&name);
        let ftype = entry.file_type()?;
        if ftype.is_dir() {
            // Both subtrees must be representable as Utf8Path for
            // the recursive call. Tarball outputs are ASCII, so
            // this is a no-op in production; the lossy fallback is
            // confined to the recurse boundary and emits a
            // structured error rather than substituting U+FFFD.
            let from_utf8 = Utf8PathBuf::from_path_buf(from).map_err(|p| {
                GharsError::Tarball(
                    format!("non-UTF-8 directory name in tarball: {}", p.display()),
                    None,
                )
            })?;
            let to_utf8 = Utf8PathBuf::from_path_buf(to).map_err(|p| {
                GharsError::Tarball(
                    format!("non-UTF-8 directory name in tarball: {}", p.display()),
                    None,
                )
            })?;
            copy_dir_recursive(&from_utf8, &to_utf8)?;
        } else if ftype.is_symlink() {
            let target = fs::read_link(&from)?;
            std::os::unix::fs::symlink(&target, &to)?;
        } else {
            fs::copy(&from, &to)?;
        }
    }
    Ok(())
}

#[cfg(unix)]
fn set_dir_mode(path: &Utf8Path, mode: u32) -> Result<()> {
    use std::os::unix::fs::PermissionsExt;
    let perms = fs::Permissions::from_mode(mode);
    fs::set_permissions(path, perms)?;
    Ok(())
}

#[cfg(not(unix))]
fn set_dir_mode(_path: &Utf8Path, _mode: u32) -> Result<()> {
    Ok(())
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used)]
#[path = "extract_tests.rs"]
mod tests;
