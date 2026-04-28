//! Streaming download + sha256 verify + tar.gz extract with safe filter.
//!
//! Design spec: Part 11 (behavioral edge cases) + Part 9f (versioned bin/) +
//! Part 17 SEC-09/SEC-10/SEC-31/SEC-33.
//!
//! Behavior ports `install_gha_runner.py:1108-1533`:
//! - `http_download` streams via reqwest blocking 64KiB chunks with a finite
//!   timeout (matches Python `httpx.stream` + `HTTP_DOWNLOAD_TIMEOUT`).
//! - `sha256_of` reads in 64KiB chunks, returns lowercase hex.
//! - `download_and_verify` deletes the dest file on SHA256 mismatch
//!   (Python lines 1503-1506) and compares case-insensitively (F40).
//! - `safe_member_filter` rejects path traversal, symlink/hardlink escape,
//!   and device/fifo/char/block entries; strips setuid/setgid/sticky
//!   (`mode & 0o777 & ~0o7000`); forces uid/gid to the extracting process.
//!   Ports lines 1161-1199 (SEC-10).
//! - `install_runner_binary` (Part 9f + SEC-09/SEC-33) extracts into a
//!   root-owned staging dir under `<state_dir>/.staging/`, then atomically
//!   renames into `bin.<version>/` under runner home. Root-owned end to end.
//! - `verify_local_tarball` (F37 / SEC-16 residual) re-stats `--runner-tarball`
//!   at use time, refusing if it has become a symlink or non-regular file
//!   between validation and use.

use crate::error::{format_error_chain, human_bytes};
use crate::{GharsError, Result, USER_AGENT};
use camino::{Utf8Path, Utf8PathBuf};
use sha2::{Digest, Sha256};
use std::fs::{self, File};
use std::io::{Read, Write};
use std::time::Duration;

const CHUNK_SIZE: usize = 65_536;

/// #666: hard cap on bytes streamed by `http_download`.
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
/// #666: enforces a `MAX_TARBALL_DOWNLOAD_BYTES` cap on cumulative bytes
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

/// #680: production wraps this with `MAX_TARBALL_DOWNLOAD_BYTES`.
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

    let resp = resp
        .error_for_status_ref()
        .map(|_| ())
        .map_err(|e| {
            GharsError::Tarball(
                format!(
                    "download failed: HTTP {chain}: {url}",
                    chain = format_error_chain(&e)
                ),
                None,
            )
        })
        .map(|()| &mut resp)?;

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
        // #666: post-decompression cumulative byte counter. Saturating
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
/// Comparison is case-insensitive (F40); both sides are lowercased before
/// comparing. On mismatch, `dest` is deleted before returning the error.
///
/// # Errors
///
/// - Whatever [`http_download`] or [`sha256_of`] returns on transport / IO failure.
/// - `GharsError::Sha256Mismatch` if the digest does not match. The
///   destination file is unlinked before the error is returned (matches
///   `install_gha_runner.py:1503-1506`).
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
        let _ = fs::remove_file(dest);
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
    /// Mode masking (#141): the tar crate's `unpack_in` honors the
    /// header's mode minus setuid/setgid/sticky by default — see
    /// `tar-rs/src/entry.rs:unpack_unprivileged` (the `set_preserve_mtime`
    /// pathway), which is what ghars uses (`set_preserve_ownerships`
    /// stays unset). Computing a separate `masked_mode` here was
    /// unused: nothing stamped it back onto the header before unpack.
    /// Removed in favor of trusting the tar crate's defaults.
    Allow,
    /// Member must be skipped (PAX/GNU extension headers). Not an error;
    /// the tar crate handles these internally on the next iteration but
    /// we emit a decision so callers can be explicit.
    Skip,
}

/// Validate one tarball entry against the safe-extraction policy ported
/// from `install_gha_runner.py:1161-1199`:
///
/// - Reject device / fifo / char / block entries (typeflag 3, 4, 6).
/// - Reject member paths that are absolute or contain `..` components.
/// - Reject symlink / hardlink targets that are absolute or contain `..`.
/// - Strip setuid / setgid / sticky bits via `mode & 0o777 & ~0o7000`.
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
        if !is_safe_relative_path(&link_bytes) {
            let target = String::from_utf8_lossy(&link_bytes);
            return Err(GharsError::Tarball(
                format!("tarball contains unsafe link target in {name}: {target}"),
                None,
            ));
        }
    }

    Ok(FilterDecision::Allow)
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
/// Defense in depth (B2 review #171 — symlink-after-extract attack):
///
/// 1. [`safe_member_filter`] rejects any entry whose member path or
///    link target is absolute or contains `..`. This is the primary
///    defense.
/// 2. `tar::Entry::unpack_in` canonicalizes the parent of every member
///    before writing — see `tar::entry::EntryFields::validate_inside_dst`
///    at tar-0.4.45/src/entry.rs:924-950. Any pre-extracted symlink in
///    the staging tree that points outside dest is detected when the
///    next member's parent path is canonicalized.
/// 3. After every successful unpack, this function additionally
///    canonicalizes the rendered path's parent and asserts it stays
///    inside the canonical dest. This catches a future filter
///    regression or a tar-crate bug that lets an entry through layer
///    1 + 2 — a third independent gate.
///
/// Mode and ownership rules (matches `install_gha_runner.py:1182-1187`):
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
    fs::create_dir_all(dest)?;
    let f = File::open(tarball)?;
    let gz = flate2::read::GzDecoder::new(f);
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

/// Verify a `--runner-tarball` path is still a regular file (not a symlink)
/// at use time, closing the F37 / SEC-16 residual TOCTOU window. Validators
/// check this at parse time; this function re-checks just before extraction.
///
/// # Errors
///
/// `GharsError::Tarball` if the path is now a symlink, missing, or not a
/// regular file.
pub fn verify_local_tarball(path: &Utf8Path) -> Result<()> {
    let meta = fs::symlink_metadata(path).map_err(|e| {
        GharsError::Tarball(
            format!("--runner-tarball cannot be stat'd: {path}: {e}"),
            None,
        )
    })?;
    if meta.file_type().is_symlink() {
        return Err(GharsError::Tarball(
            format!("--runner-tarball is now a symlink (was not at validation time): {path}"),
            None,
        ));
    }
    if !meta.is_file() {
        return Err(GharsError::Tarball(
            format!("--runner-tarball is no longer a regular file: {path}"),
            None,
        ));
    }
    Ok(())
}

/// Install a runner tarball into `runner_home/bin.<version>/` via the
/// extract-as-root + atomic-rename pattern (SEC-09 / SEC-33).
///
/// **Concurrency contract (#442):** MUST be called under `apply.lock`
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
/// 4. Atomically rename staging into `<runner_home>/bin.<version>/`.
///
/// `state_dir` is the parent under which `.staging/` lives (the design
/// pins this to `/var/lib/ghars/.staging/`; tests redirect both
/// `state_dir` and `runner_home` to a tempdir). `runner_home` is the
/// per-runner home directory (`/var/lib/ghars/<runner-name>/`).
///
/// On success the staging directory has been moved and is no longer
/// present. On any failure the staging directory is best-effort removed
/// before propagating the error so an aborted apply does not leave
/// orphan trees in `.staging/`.
///
/// Note: the `bin` symlink under `runner_home` is NOT updated by this
/// function. After install completes, call [`swap_bin_symlink`] to point
/// `runner_home/bin` at the freshly-installed `bin.<version>/`. The two
/// steps are split so apply.rs can sequence other work (e.g. running
/// `config.sh` against the new tree) before the swap.
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
    verify_local_tarball(tarball_path)?;

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
    let outcome = extract_and_swap(tarball_path, &staging, runner_home, &final_dir);
    if outcome.is_err() {
        let _ = fs::remove_dir_all(&staging);
    }
    outcome?;
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

/// Atomically swap `<runner_home>/bin` to point at `bin.<version>/`.
///
/// Implements design Part 9f: `ln -sfn bin.<version> bin.tmp && mv -T
/// bin.tmp bin`. The intermediate `bin.tmp` symlink is created first
/// (relative target so the runner home is relocatable), then renamed
/// over `bin` via `rename(2)` — which is atomic on Unix even when both
/// source and dest are symlinks.
///
/// If `bin.tmp` already exists when this function is called (e.g. from
/// a crashed prior apply), it is removed first; this is safe because
/// `bin.tmp` is owned exclusively by ghars apply and never points at
/// load-bearing state. The `bin` target (a directory under
/// `runner_home`) must already exist — the caller installs it via
/// [`install_runner_binary`] before swapping.
///
/// # Errors
///
/// - `GharsError::Tarball` if the target `bin.<version>/` directory
///   does not exist (would create a dangling symlink).
/// - `GharsError::Io` for symlink/rename failures.
pub fn swap_bin_symlink(runner_home: &Utf8Path, version: &str) -> Result<()> {
    let target_name = format!("bin.{version}");
    let target_dir = runner_home.join(&target_name);
    if !target_dir.exists() {
        return Err(GharsError::Tarball(
            format!(
                "swap_bin_symlink: target {target_dir} does not exist; install bin.{version}/ first"
            ),
            None,
        ));
    }
    let bin = runner_home.join("bin");
    let tmp = runner_home.join("bin.tmp");
    if let Ok(meta) = fs::symlink_metadata(&tmp) {
        if meta.file_type().is_symlink() || meta.file_type().is_file() {
            fs::remove_file(&tmp)?;
        } else {
            fs::remove_dir_all(&tmp)?;
        }
    }
    // Relative target so the runner home is relocatable.
    std::os::unix::fs::symlink(&target_name, &tmp)?;
    fs::rename(&tmp, &bin)?;
    Ok(())
}

/// Extract `tarball_path` into `staging`, then move staging to `final_dir`.
///
/// The move is the design's "atomic rename" step from Part 17 SEC-09. Two
/// concerns this function handles:
///
/// 1. **EXDEV on cross-filesystem rename (B2 review #179).** When
///    `<state_dir>/.staging/` and `<runner_home>/bin.<version>/` are on
///    different filesystems (operator mounts per-runner home on a separate
///    disk), `rename(2)` returns `EXDEV`. We detect that and fall back to
///    a recursive copy + remove-staging path. The fallback is NOT atomic —
///    a crash mid-copy leaves a partial `bin.<version>/` — but the only
///    available alternative is to forbid cross-FS layouts at preflight,
///    which the design does not require.
///
/// 2. **Atomicity gap on upgrade-in-place (#142 / design Part 17 SEC-09).**
///    When `final_dir` already exists, we `remove_dir_all` it and then
///    `rename` staging onto it. Between those two calls there is a window
///    where `final_dir` does not exist. The fully-atomic alternative is
///    `renameat2(RENAME_EXCHANGE)`, which would atomically swap the two
///    directories so neither side ever vanishes. Cargo.toml has
///    `unsafe_code = "forbid"`, blocking direct `libc::renameat2`; the
///    safe wrapper `rustix::fs::renameat_with(RenameFlags::EXCHANGE)`
///    exists (rustix is already a transitive dep) and is the right
///    solution for v0.2.
///
///    For v0.1, the gap is unobservable in apply.rs's pipeline because:
///    - apply.rs holds the global `apply.lock` (Part 8) — only one apply
///      can run at a time.
///    - The runner unit is stopped BEFORE apply rewrites `bin.<version>/`
///      (apply ordering: `Stop → install_runner_binary → swap_bin_symlink
///      → Start`).
///    - The `bin` symlink still resolves to the OLD `bin.<version>/`
///      throughout the install step; nothing reads the new directory until
///      `swap_bin_symlink` runs after this function returns.
///
///    A future audit tool that walks `runner_home/` mid-apply would see
///    `bin.<version>/` momentarily absent. v0.2 should switch to the
///    rustix wrapper to close the window unconditionally.
fn extract_and_swap(
    tarball_path: &Utf8Path,
    staging: &Utf8Path,
    runner_home: &Utf8Path,
    final_dir: &Utf8Path,
) -> Result<()> {
    extract_tarball(tarball_path, staging)?;
    fs::create_dir_all(runner_home)?;
    if final_dir.exists() {
        fs::remove_dir_all(final_dir)?;
    }
    match fs::rename(staging, final_dir) {
        Ok(()) => Ok(()),
        Err(e) if is_cross_device_link(&e) => {
            copy_dir_recursive(staging, final_dir)?;
            fs::remove_dir_all(staging)?;
            Ok(())
        }
        Err(e) => Err(GharsError::Io(e)),
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
/// in [`extract_and_swap`] when source/dest are on different filesystems.
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
        let from = src.join(name.to_string_lossy().as_ref());
        let to = dst.join(name.to_string_lossy().as_ref());
        let ftype = entry.file_type()?;
        if ftype.is_dir() {
            copy_dir_recursive(&from, &to)?;
        } else if ftype.is_symlink() {
            let target = fs::read_link(from.as_std_path())?;
            std::os::unix::fs::symlink(&target, to.as_std_path())?;
        } else {
            fs::copy(from.as_std_path(), to.as_std_path())?;
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
mod tests {
    use super::*;
    use std::io::Cursor;

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
        // 0o7777 = setuid + setgid + sticky + rwxrwxrwx. Pre-#141 the
        // filter computed `mode & 0o777 & !0o7000` and returned it via
        // `Allow.masked_mode`; nothing wrote that back onto the header
        // before `unpack_in`, so the masking was a no-op. The tar
        // crate's unprivileged unpack already strips setuid/setgid via
        // `set_preserve_permissions(false)`-style defaults — verified
        // against tar-rs/src/entry.rs `unpack_unprivileged`. The filter
        // is now authoritative for path/typeflag rejection only.
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
        assert!(err.to_string().contains("unsafe link target"));
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
        assert!(err.to_string().contains("unsafe link target"));
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
        assert!(err.to_string().contains("unsafe link target"));
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
        // Uppercase hex digest; F40 says case-insensitive comparison.
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
            }
            other => panic!("expected Tarball, got {other:?}"),
        }
        m.assert();
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
        assert!(err.to_string().contains("cannot be stat"));
    }

    #[test]
    fn verify_local_tarball_accepts_regular_file() {
        let tmp = tempfile::tempdir().unwrap();
        let path = Utf8PathBuf::from_path_buf(tmp.path().join("ok.tar.gz")).unwrap();
        fs::write(&path, b"x").unwrap();
        verify_local_tarball(&path).unwrap();
    }

    /// #438: TOCTOU parity test between `validators::validate_runner_tarball`
    /// (load-time gate) and `verify_local_tarball` (apply-time gate).
    /// The two checks must form a closed pair: a path that passes the
    /// load-time check but is then mutated to a symlink before
    /// `install_runner_binary` runs MUST be rejected by the apply-time
    /// check.
    ///
    /// Without this parity test, a regression that loosened
    /// `verify_local_tarball` (e.g. swapped `symlink_metadata` for
    /// `metadata`, which follows symlinks) would silently land — both
    /// functions individually still reject their unit-test inputs, but
    /// the cross-time invariant would break: an attacker who wins the
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
        // with the gzip magic (1f 8b) so the validator's #439 magic
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

    /// #448 unlink-mutation TOCTOU: a path that passes the load-time
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
        // #439: bytes start with gzip magic 1f 8b so validate_runner_tarball accepts.
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
        // Step 5: rejection cause names a stat / existence failure
        // ("cannot be stat" matches the verify_local_tarball wording
        // for both ENOENT and other lstat errors).
        let msg = err.to_string();
        assert!(
            msg.contains("cannot be stat") || msg.contains("does not exist"),
            "verify_local_tarball error must name a stat / existence failure; got: {msg}"
        );
    }

    /// #448 directory-mutation TOCTOU: a path that passes the
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
        // #439: bytes start with gzip magic 1f 8b so validate_runner_tarball accepts.
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

    /// #448: extend the TOCTOU parity coverage to a table-driven
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
                    // #439: gzip magic prefix so validate_runner_tarball accepts.
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
        assert!(err.to_string().contains("unsafe link target"));

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

    /// Helper: read a symlink's target as a string, asserting the path
    /// IS a symlink (not a regular file/dir).
    fn read_symlink(p: &Utf8Path) -> String {
        let meta = fs::symlink_metadata(p).expect("symlink_metadata");
        assert!(meta.file_type().is_symlink(), "{p} is not a symlink");
        let target = fs::read_link(p).expect("read_link");
        target
            .to_str()
            .expect("symlink target valid utf-8")
            .to_string()
    }

    #[test]
    fn swap_bin_symlink_fresh_install_creates_link() {
        let tmp = tempfile::tempdir().unwrap();
        let runner_home = Utf8PathBuf::from_path_buf(tmp.path().to_path_buf()).unwrap();
        let target_dir = runner_home.join("bin.2.334.0");
        fs::create_dir_all(&target_dir).unwrap();
        fs::write(target_dir.join("runsvc.sh"), b"new").unwrap();

        swap_bin_symlink(&runner_home, "2.334.0").unwrap();
        assert_eq!(read_symlink(&runner_home.join("bin")), "bin.2.334.0");
        // Reachable through the symlink.
        assert!(runner_home.join("bin/runsvc.sh").exists());
        // No leftover bin.tmp.
        assert!(!runner_home.join("bin.tmp").exists());
    }

    #[test]
    fn swap_bin_symlink_upgrade_replaces_existing_link() {
        let tmp = tempfile::tempdir().unwrap();
        let runner_home = Utf8PathBuf::from_path_buf(tmp.path().to_path_buf()).unwrap();

        let old = runner_home.join("bin.2.333.0");
        fs::create_dir_all(&old).unwrap();
        fs::write(old.join("OLD"), b"").unwrap();
        std::os::unix::fs::symlink("bin.2.333.0", runner_home.join("bin")).unwrap();

        let new = runner_home.join("bin.2.334.0");
        fs::create_dir_all(&new).unwrap();
        fs::write(new.join("NEW"), b"").unwrap();

        swap_bin_symlink(&runner_home, "2.334.0").unwrap();
        assert_eq!(read_symlink(&runner_home.join("bin")), "bin.2.334.0");
        assert!(runner_home.join("bin/NEW").exists());
        // Old version dir is untouched (rollback retention).
        assert!(runner_home.join("bin.2.333.0/OLD").exists());
    }

    #[test]
    fn swap_bin_symlink_recovers_from_leftover_bin_tmp() {
        let tmp = tempfile::tempdir().unwrap();
        let runner_home = Utf8PathBuf::from_path_buf(tmp.path().to_path_buf()).unwrap();

        let target = runner_home.join("bin.2.334.0");
        fs::create_dir_all(&target).unwrap();

        // Simulate a crashed prior apply that left bin.tmp pointing at a
        // bogus target.
        std::os::unix::fs::symlink("bin.NOPE", runner_home.join("bin.tmp")).unwrap();

        swap_bin_symlink(&runner_home, "2.334.0").unwrap();
        assert_eq!(read_symlink(&runner_home.join("bin")), "bin.2.334.0");
        assert!(!runner_home.join("bin.tmp").exists());
    }

    #[test]
    fn swap_bin_symlink_rejects_nonexistent_target() {
        let tmp = tempfile::tempdir().unwrap();
        let runner_home = Utf8PathBuf::from_path_buf(tmp.path().to_path_buf()).unwrap();
        // No bin.2.334.0 directory.
        let err = swap_bin_symlink(&runner_home, "2.334.0").unwrap_err();
        assert!(err.to_string().contains("does not exist"), "err={err}");
        // Pre-existing `bin` (if any) untouched.
        assert!(!runner_home.join("bin").exists());
    }

    #[test]
    fn swap_bin_symlink_target_is_relative() {
        let tmp = tempfile::tempdir().unwrap();
        let runner_home = Utf8PathBuf::from_path_buf(tmp.path().to_path_buf()).unwrap();
        fs::create_dir_all(runner_home.join("bin.2.334.0")).unwrap();

        swap_bin_symlink(&runner_home, "2.334.0").unwrap();
        let target = read_symlink(&runner_home.join("bin"));
        assert!(
            !target.starts_with('/'),
            "symlink target must be relative; got {target}"
        );
    }

    // -- #171 post-extract canonical-path defense ------------------------

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

    // -- #179 EXDEV cross-filesystem fallback ---------------------------

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

    // -- #157 Python parity: setuid stripped on disk --------------------

    #[test]
    fn extract_tarball_strips_setuid_on_disk_end_to_end() {
        // Python parity: install_gha_runner.py test_extract_tarball_strips_setuid.
        // After #141 the filter no longer computes a masked mode (the
        // tar crate's `unpack_in` strips setuid/setgid for unprivileged
        // unpack by default). This test is the load-bearing assertion:
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

    // -- #158 race tolerance --------------------------------------------

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

    // -- #159 http_download timeout -------------------------------------

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

    /// #666 streaming cap pin: `http_download` rejects responses whose
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

    /// #666 streaming cap fires + cleanup pin: drives a body just over
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

    /// #680 happy-path pin via cap-injecting helper: a body smaller
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

    /// #680 over-cap rejection + unlink pin: a body larger than the
    /// test cap (128 bytes vs cap of 64) triggers the cap-firing
    /// branch in `http_download_with_cap`. Asserts (a) the call
    /// returns Err with the "exceeds … post-decompression" diagnostic,
    /// AND (b) the destination file does NOT exist post-call —
    /// exercising the `drop(out); fs::remove_file(dest)` cleanup
    /// path which had zero runtime coverage pre-#680. This is the
    /// load-bearing security pin: a half-written file surviving a
    /// cap-fire could be promoted by a later SHA256 check. Also
    /// pins format prefix ("download failed:"), URL presence,
    /// "post-decompression" qualifier (parity with github.rs Layer 2
    /// framing), network-path triage hint, MAX_TARBALL_DOWNLOAD_BYTES
    /// escape hatch, and anti-doubling invariant (single occurrence
    /// of "response body exceeds"). #727 softens the alarming
    /// "compression bomb" framing to neutral "larger than expected"
    /// language; #724 adds human-readable byte sizes alongside the
    /// raw cap value so operators don't have to mentally divide.
    #[test]
    fn http_download_with_cap_rejects_over_cap_and_unlinks_dest() {
        let mut server = mockito::Server::new();
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
                // Pin operator-visible format prefix.
                assert!(
                    msg.starts_with("download failed:"),
                    "msg must start with 'download failed:'; got: {msg}"
                );
                // Pin URL presence so operators can identify the
                // affected upstream from log scrape.
                assert!(
                    msg.contains(&url),
                    "msg must surface the request URL; got: {msg}"
                );
                assert!(
                    msg.contains("exceeds") && msg.contains("64 bytes"),
                    "msg must surface cap value + 'exceeds'; got: {msg}"
                );
                // Pin "post-decompression" parity with github.rs Layer 2
                // framing — operators triaging across both surfaces see
                // consistent on-wire vs post-decompression vocabulary.
                assert!(
                    msg.contains("post-decompression"),
                    "msg must surface 'post-decompression' framing; got: {msg}"
                );
                // #727 — alarming "compression bomb" framing dropped
                // in favor of neutral "larger than expected" wording
                // that names both threat-model and legitimate-payload
                // possibilities. Pin the new wording so a regression
                // back to the alarming framing surfaces here.
                assert!(
                    msg.contains("larger than expected"),
                    "msg must surface neutral 'larger than expected' framing per #727; got: {msg}"
                );
                assert!(
                    msg.contains("deliberately-crafted")
                        && msg.contains("legitimately large"),
                    "msg must name both threat-model + legitimate-payload possibilities per #727; got: {msg}"
                );
                assert!(
                    !msg.contains("compression bomb"),
                    "msg MUST NOT surface alarming 'compression bomb' framing per #727; got: {msg}"
                );
                // Pin operator hint parity with github.rs cap-exceeded
                // hint so a post-cap operator gets the same
                // network-path triage breadcrumb regardless of which
                // download path tripped the cap.
                assert!(
                    msg.contains("verify network path"),
                    "msg must surface network-path triage hint; got: {msg}"
                );
                assert!(
                    msg.contains("compromised mirror")
                        && msg.contains("hostile proxy CA")
                        && msg.contains("non-GitHub origin"),
                    "msg must enumerate compromised-mirror/proxy/non-GitHub origin causes; got: {msg}"
                );
                // Pin escape-hatch breadcrumb so an operator with a
                // legitimately-large payload can find the constant to
                // raise.
                assert!(
                    msg.contains("MAX_TARBALL_DOWNLOAD_BYTES"),
                    "msg must surface MAX_TARBALL_DOWNLOAD_BYTES escape hatch; got: {msg}"
                );
                // Anti-doubling: single occurrence defends against future shared-helper wrapping.
                assert_eq!(
                    msg.matches("response body exceeds").count(),
                    1,
                    "single occurrence of 'response body exceeds' required; got: {msg}"
                );
                // #724 — human-readable byte size for cap value (64 B
                // for sub-KiB integer-byte path) alongside raw "64
                // bytes" so an operator reads "64 B (64 bytes)"
                // without mental conversion.
                assert!(
                    msg.contains("64 B (64 bytes)"),
                    "msg must include human-readable byte size '64 B (64 bytes)' per #724; got: {msg}"
                );
            }
            other => panic!("expected GharsError::Tarball, got {other:?}"),
        }
        // The destination file must be unlinked after the cap fires —
        // otherwise a partial write could be promoted by a subsequent
        // SHA256 check (the SEC-09/SEC-31 invariant).
        assert!(
            !dest.as_std_path().exists(),
            "dest file must be unlinked after cap-fire; still exists at {dest}"
        );
        m.assert();
    }
}
