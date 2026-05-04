//! Atomic root-owned file writes plus the read-then-write helpers
//! that drive the in-place / create-path managed file mutations.
//!
//! Two helpers wrap the snapshot + write + rollback-record pattern. Pick
//! based on whether the caller is the in-place update branch (skip when
//! bytes match) or the create branch (always write):
//!
//! - `read_then_write_if_changed`: in-place branch entry. Snapshots
//!   prior bytes, skips the write if they match, otherwise writes and
//!   pushes the undo step. Returns `Result<bool>` so the caller can
//!   drive `files_changed` ("skip rewrite when bytes match"
//!   optimization gating daemon-reload + restart).
//! - `write_record_undo`: create-path entry. Snapshot + always-write +
//!   record undo. Returns `Result<()>` because create-path callers
//!   always proceed to systemd actions regardless of byte change.
//!
//! All sites that mutate managed config files MUST go through one of
//! these helpers — bypassing them would either break rollback fidelity
//! (no `UndoStep::WriteFile` pushed) or skip the byte-equality optimization.
//! The exception is shared templates (`netns_template_unit_file` and
//! `cache_template_unit_file`) which use `write_root_owned` directly with
//! explicit "NOT recorded" comment blocks — undoing those would clobber
//! other live consumers. Per-pool drop-ins (00-ghars.conf at
//! `cache_drop_in_dir`) are NOT shared templates and DO go through the
//! helpers above.

use std::fs::{self, File, OpenOptions};
use std::io::Write;
#[cfg(not(test))]
use std::os::fd::AsRawFd;
use std::os::unix::fs::OpenOptionsExt;
use std::sync::atomic::{AtomicU64, Ordering};

#[cfg(not(test))]
use nix::unistd::{Gid, Uid, fchown};

use camino::{Utf8Path, Utf8PathBuf};

use crate::Result;
use crate::config::EffectiveRunnerSpec;
use crate::error::GharsError;
use crate::paths::Paths;

use super::undo::{AuthRegistry, UndoLog, UndoStep};

// Returns the full `RegistrationToken` (not just `.value`) so the
// caller controls the lifetime. Moving `tok.value` out of `RegistrationToken`
// would require `String: Drop` to opt out of the Drop guard, which Rust
// forbids for types whose containing struct implements Drop. Returning
// the token by value keeps zeroize-on-drop intact: the caller borrows
// `&token.value` for `ConfigShellCtx`, and when `token` falls out of
// scope at the end of the caller frame, the heap buffer is volatile-
// scrubbed before deallocation.
pub(super) fn mint_token(
    auth: AuthRegistry<'_>,
    name: &str,
    url: &str,
    removal: bool,
) -> Result<crate::auth::RegistrationToken> {
    let source = auth.get(name).ok_or_else(|| {
        GharsError::Auth(
            format!("auth source {name:?} referenced by runner is not in the registry"),
            "ensure the runner's `auth` field matches a key in [auth.NAME]".into(),
        )
    })?;
    if removal {
        source.mint_removal_token(url)
    } else {
        source.mint_registration_token(url)
    }
}

/// Per-process counter used to disambiguate concurrent `write_root_owned`
/// temp filenames within the same process. Combined with the PID it
/// guarantees a unique tempname even if two threads write to the same
/// final path simultaneously: PID rules out cross-process collisions,
/// the counter rules out same-process ones. Paired with `O_CREAT|O_EXCL`
/// the open syscall fails closed if the name still collides, so the
/// counter is a fast-path uniqueness aid, not the security primitive.
static TEMPFILE_COUNTER: AtomicU64 = AtomicU64::new(0);

/// Drop guard: best-effort `unlink(temp_path)` on early return so a
/// failed `write_root_owned` does not leave half-written `.tmp.*` files
/// strewn under `/etc/ghars/`. `disarm()` is called after the rename
/// succeeds — at that point the temp name no longer exists on disk
/// (rename(2) made the inode visible at the final path) and the
/// guard's unlink would be a no-op anyway, but disarming makes that
/// explicit and avoids a spurious ENOENT in the kernel audit log.
pub(super) struct TempFileGuard {
    path: Option<Utf8PathBuf>,
}

impl TempFileGuard {
    pub(super) fn new(path: Utf8PathBuf) -> Self {
        Self { path: Some(path) }
    }
    pub(super) fn disarm(mut self) {
        self.path = None;
    }
}

impl Drop for TempFileGuard {
    fn drop(&mut self) {
        if let Some(p) = self.path.take() {
            let _ = fs::remove_file(p.as_std_path());
        }
    }
}

/// Snapshot the bytes at `path` if it exists, used to populate
/// [`UndoStep::WriteFile.prior_content`] BEFORE an overwrite. `None`
/// signals the path didn't exist beforehand, so undo's restore path
/// becomes "remove the new file" rather than "rewrite old bytes".
///
/// Read failures (other than `NotFound`) are logged via `tracing::warn!`
/// and treated as `None` — best-effort recording, never fail-stop the
/// forward path because we couldn't checkpoint a pre-existing file.
pub(super) fn read_prior(path: &Utf8Path) -> Option<Vec<u8>> {
    match fs::read(path.as_std_path()) {
        Ok(bytes) => Some(bytes),
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => None,
        Err(e) => {
            tracing::warn!(
                path = path.as_str(),
                error = %e,
                "read_prior: snapshot failed; rollback will treat as new-file"
            );
            None
        }
    }
}

pub(super) fn write_root_owned(path: &Utf8Path, bytes: &[u8]) -> Result<()> {
    let parent = path.parent().ok_or_else(|| GharsError::Apply {
        action: format!("write_root_owned {path}"),
        source: Box::new(GharsError::Io(std::io::Error::new(
            std::io::ErrorKind::InvalidInput,
            "path has no parent directory",
        ))),
    })?;
    let final_name = path.file_name().ok_or_else(|| GharsError::Apply {
        action: format!("write_root_owned {path}"),
        source: Box::new(GharsError::Io(std::io::Error::new(
            std::io::ErrorKind::InvalidInput,
            "path has no file name",
        ))),
    })?;
    fs::create_dir_all(parent.as_std_path())?;

    // SEC-NEW: write atomically via temp+rename so concurrent readers
    // (systemd reading drop-ins, ghars reading its own state) never see
    // a half-written file. Without this, an apply that crashed mid-
    // write would leave the final path containing only the prefix of
    // the new contents, the X-Ghars-Spec-Hash annotation could be
    // truncated mid-line, and the next apply's drift detector would
    // either accept the corruption (if the truncation happened to
    // produce a parseable hash) or refuse to plan further. rename(2)
    // is atomic on the same filesystem (POSIX) so a reader either sees
    // the old file or the fully-written new file, never a mix.
    let pid = std::process::id();
    let counter = TEMPFILE_COUNTER.fetch_add(1, Ordering::Relaxed);
    let temp_name = format!(".{final_name}.tmp.{pid}.{counter}");
    let temp_path = parent.join(&temp_name);

    // Open with O_CREAT|O_EXCL (create_new). Fail-closed if the name
    // already exists — the counter+PID combination should make a
    // collision impossible in practice, but if an attacker pre-plants
    // the file we refuse to write rather than reuse their inode.
    //
    // Create at 0o600 (owner read/write only) and widen to 0o644
    // *after* chown_to_root succeeds. The create-restrictive-then-
    // widen pattern means that during the brief window between
    // creat(2) and the final rename(2), the file is invisible to
    // group/world even if the process's effective UID isn't yet
    // root: the temp inode never carries world-readable bits while
    // its content might be sensitive. write_root_owned is currently
    // used only for non-secret config (drop-ins, nft rules), but
    // future callers may write secret-bearing files through the same
    // helper — landing the restrictive temp now avoids the latent
    // regression that the adversary flagged.
    let mut f = OpenOptions::new()
        .create_new(true)
        .write(true)
        .mode(0o600)
        .open(temp_path.as_std_path())?;

    // Arm the guard immediately after the file exists on disk: any
    // error from here through the final rename must unlink the temp.
    let guard = TempFileGuard::new(temp_path.clone());

    f.write_all(bytes)?;
    f.flush()?;
    // sync_all(2) on the open fd makes the FILE CONTENTS durable
    // before rename publishes the inode at the final path. Pairs with
    // the parent-dir fsync after rename: the data fsync flushes
    // contents through to storage, the parent-dir fsync flushes the
    // rename itself. Without the data fsync, a post-rename crash
    // could leave the final path pointing at an inode whose contents
    // the kernel has not yet written through — recovery would see
    // the new name with old/zero data.
    f.sync_all()?;
    // Chown the freshly-written fd to root:root. OpenOptions::mode
    // sets the file mode, but ownership is inherited from the calling
    // process's effective UID/GID (and umask only affects mode bits).
    // The function name is a promise — root-owned end-to-end. Without
    // fchown, a future caller running with effective UID != 0 would
    // produce non-root-owned config files, silently violating SEC-09 /
    // SEC-11 (owner-controlled config under /etc/ghars/). Use fchown on
    // the open fd (not path-based chown) so the chown target is pinned
    // to the inode we wrote, not whatever a concurrent attacker might
    // swap in at this path.
    chown_to_root(&f, &temp_path)?;
    // Now that ownership is root:root, widen the mode from
    // 0o600 to 0o644 so systemd / readers can stat the published
    // file. File::set_permissions on Unix calls fchmod(fd, mode), so
    // the chmod target is pinned to the inode we wrote, not whatever a
    // concurrent attacker might swap in at temp_path.
    {
        use std::os::unix::fs::PermissionsExt;
        f.set_permissions(std::fs::Permissions::from_mode(0o644))?;
    }
    drop(f);

    // Atomic publish. On the same filesystem rename(2) replaces any
    // existing file at the destination as a single inode swap; a
    // reader concurrent with this rename sees either the old inode or
    // the new one in full, never a torn write.
    fs::rename(temp_path.as_std_path(), path.as_std_path())?;
    guard.disarm();
    // fsync parent dir for durable publish: rename(2) updates the
    // in-memory directory entry but the change may not survive a
    // crash until the parent inode's metadata journal flushes. This
    // fsync forces that flush so recovery sees the new dirent.
    // O_NOFOLLOW | O_DIRECTORY pin intent: parent is always a
    // directory we just wrote into, never a symlink. The warn fires
    // only after rename succeeds — file IS published, retry safe —
    // so operators on degraded storage can distinguish the
    // post-publish fsync failure from a pre-rename failure.
    std::fs::OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_NOFOLLOW | libc::O_DIRECTORY)
        .open(parent.as_std_path())
        .and_then(|f| f.sync_all())
        .map_err(|e| {
            tracing::warn!(
                %path,
                error = %e,
                "parent-dir fsync failed after publishing — file is on disk, retry safe"
            );
            e
        })?;
    Ok(())
}

/// Snapshot the on-disk content of `path`, then conditionally write
/// `bytes` and append a rollback step to `log`. Returns `true` when a
/// write happened; `false` when on-disk bytes already matched `bytes`
/// and the write was skipped.
///
/// The two-step `let prior = read_prior(p); ... if prior != bytes {
/// write + push }` shape was open-coded twice in `execute_update_runner`
/// (the unit-file write and the drop-in loop) before this consolidation.
/// Single-sourcing the snapshot here removes the chance that a future
/// caller forgets to read the prior bytes and silently breaks rollback
/// fidelity.
///
/// The caller drives `files_changed` in `execute_update_runner` from
/// this return so the daemon-reload + restart gate at the end of the
/// function still fires correctly. This is the workhorse for the
/// "skip rewrite when bytes match" optimization.
pub(super) fn read_then_write_if_changed(
    path: &Utf8Path,
    bytes: &[u8],
    log: &mut UndoLog,
) -> Result<bool> {
    let prior = read_prior(path);
    if prior.as_deref() == Some(bytes) {
        return Ok(false);
    }
    write_root_owned(path, bytes)?;
    log.push(UndoStep::WriteFile {
        path: path.to_path_buf(),
        prior_content: prior,
    });
    Ok(true)
}

/// Snapshot the on-disk content of `path`, write `bytes` via
/// [`write_root_owned`], and append an [`UndoStep::WriteFile`] to `log`
/// recording the prior content for rollback.
///
/// This is the create-path sibling of [`read_then_write_if_changed`]: the
/// in-place update branch can elide the write when bytes already match,
/// but the create path always rewrites because the caller has just
/// rendered a fresh template/drop-in for a brand-new runner / cache
/// pool / netns side-unit and the directory may not even exist yet.
/// Both shapes share the read-then-write-then-record pattern; this
/// helper single-sources the create-path variant.
///
/// Returns `Result<()>` instead of `Result<bool>` because create-path
/// callers always proceed to systemd actions regardless of whether
/// bytes changed (the just-rendered file is, by construction, fresh
/// state for a unit that does not yet have its enable/start side-
/// effects applied). Use [`read_then_write_if_changed`] when the
/// caller actually needs the byte-changed flag to gate a daemon-reload
/// + restart.
///
/// The pattern was open-coded six times before this consolidation:
/// `execute_create_runner` (unit file + drop-in loop),
/// `provision_netns_artifacts` (host + ns nft rule files),
/// `execute_create_cache_pool` (per-pool drop-in), and
/// `execute_update_cache_pool` (per-pool drop-in). The
/// `provision_netns_artifacts` `netns_cfg.write` site stays raw because
/// `NetnsConfig::write` is a different writer entirely (it owns its own
/// path derivation + serialization) — only sites that go through
/// `write_root_owned` directly use this helper.
///
/// # Read-failure conflation
///
/// [`read_prior`] returns `None` for both file-not-found AND a non-
/// ENOENT read failure (it logs `tracing::warn!` and falls through).
/// On rollback, [`UndoStep::WriteFile`] with `prior_content: None`
/// performs `unlink` rather than restore. So a transient read failure
/// against a pre-existing file results in unlink-on-undo rather than
/// restore-to-prior — a fidelity loss the operator must understand.
/// In practice this only matters when a rollback fires AND the
/// snapshot read failed AND the file pre-existed, all of which are
/// rare; the design accepts the conflation rather than failing the
/// forward path because we cannot snapshot.
pub(super) fn write_record_undo(path: &Utf8Path, bytes: &[u8], log: &mut UndoLog) -> Result<()> {
    let prior = read_prior(path);
    write_root_owned(path, bytes)?;
    log.push(UndoStep::WriteFile {
        path: path.to_path_buf(),
        prior_content: prior,
    });
    Ok(())
}

#[cfg(not(test))]
fn chown_to_root(f: &File, path: &Utf8Path) -> Result<()> {
    fchown(
        f.as_raw_fd(),
        Some(Uid::from_raw(0)),
        Some(Gid::from_raw(0)),
    )
    .map_err(|e| GharsError::Apply {
        action: format!("fchown root:root {path}"),
        source: Box::new(GharsError::Io(std::io::Error::from_raw_os_error(e as i32))),
    })?;
    Ok(())
}

#[cfg(test)]
fn chown_to_root(_f: &File, _path: &Utf8Path) -> Result<()> {
    // Tests run unprivileged. fchown to root:root would EPERM. Treat
    // as a no-op so the unit tests can exercise write_root_owned end
    // to end. Production callers (apply running under sudo) hit the
    // non-test variant.
    Ok(())
}

/// Drop-in test hook: lets unit tests reuse the EffectiveRunnerSpec
/// constructor pattern without re-deriving the systemd module's private
/// helpers. Not exposed in production code paths.
#[doc(hidden)]
#[must_use]
pub fn _spec_runner_home(spec: &EffectiveRunnerSpec, paths: &Paths) -> Utf8PathBuf {
    paths.runner_home(&spec.trust_zone, &spec.name)
}
