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
///   - 512 MiB is generous; v0.2 may shrink this to 350 MiB once the
///     observed legitimate maximum is monitored over multiple releases.
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

    // Layer 1: raw Content-Length header pre-check, mirroring
    // `github::http_get_payload_with_cap`. `resp.content_length()` returns
    // None for gzipped responses (reqwest's gzip feature decodes
    // transparently and zeros the size hint), so we read the header
    // directly to get the on-wire (pre-decompression) size before any
    // bytes are streamed. A `Content-Length` larger than `max_bytes`
    // signals either a hostile origin or a legitimately-large payload;
    // in either case we reject before opening `dest` so a zero-byte
    // partial file cannot be promoted by a later step.
    // Malformed Content-Length silently falls through to Layer 2 streaming
    // backstop (the cumulative byte counter inside the chunk loop).
    if let Some(cl_header) = resp.headers().get(reqwest::header::CONTENT_LENGTH)
        && let Ok(cl_str) = cl_header.to_str()
        && let Ok(cl) = cl_str.parse::<u64>()
        && cl > max_bytes
    {
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
            if let std::path::Component::Normal(s) = c {
                if let Some(s) = s.to_str() {
                    components.push(s);
                }
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
        // candidate set, and although std's remove_dir_all is
        // hardened to unlink-only on symlinks (Rust 1.62+), the
        // inclusion is still wrong — same TOCTOU-via-symlink class
        // as the deleted set_tree_permissions cascade.
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
    nix::fcntl::renameat2(
        None,
        old_path,
        None,
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
mod tests {
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
            let mut encoder =
                flate2::write::GzEncoder::new(&mut gz_buf, flate2::Compression::fast());
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
        assert!(
            err.to_string().contains("absolute link target"),
            "{err}"
        );
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
        assert!(
            err.to_string().contains("absolute link target"),
            "{err}"
        );
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
        assert!(
            err.to_string().contains("absolute link target"),
            "{err}"
        );
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
        let err =
            download_and_verify(&url, &dest, &bogus_sha, Duration::from_secs(10)).unwrap_err();
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
        let err =
            download_and_verify(&url, &dest, &bogus_sha, Duration::from_secs(10)).unwrap_err();
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
        let github_err = crate::github::fetch_latest_release_at(
            &client,
            &github_url,
            crate::config::Arch::X86_64,
        )
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
        assert!(
            err.to_string().contains("absolute link target"),
            "{err}"
        );

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
}
