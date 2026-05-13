//! Per-action undo log: [`UndoStep`], [`UndoLog`], and the [`undo`] walker.
//!
//! Each `execute_*` handler takes `&mut UndoLog` and pushes a step
//! after every successful side effect. On `Err` from the handler with
//! `--rollback-on-failure`, [`super::orchestrator::apply`] walks the
//! log in reverse via [`undo`].

use std::collections::HashMap;
use std::fs;

use camino::Utf8PathBuf;

use crate::Result;
use crate::auth::TokenSource;
use crate::error::GharsError;
use crate::paths::Paths;
use crate::systemd::Systemd;

use super::shell::{ConfigShell, ConfigShellCtx};
use super::tarball::Tarball;
use super::writes::write_root_owned;

/// One mutating step recorded by an `execute_*` handler. On failure with
/// `--rollback-on-failure`, [`undo`] walks the per-action log in reverse
/// and best-effort reverses each step.
///
/// Design contract: each Action records a `Vec<UndoStep>` (file
/// paths created, units written, users added, registered runners).
/// On error, walk the list in reverse and best-effort undo.
///
/// Variants split into two directions:
/// - **Forward (Create-direction)** — `WriteFile`, `CreateDir`,
///   `StartUnit`, `EnableUnit`, `GitHubRegistration`. These have
///   lossless inverses (`remove_file`, `remove_dir`, `stop_unit`,
///   `disable_unit`, `config.sh remove --token <fresh>`). The undo
///   path attempts each and continues on per-step error.
/// - **Reverse (Remove-direction)** — `RemoveFile`, `RemoveDir`,
///   `StopUnit`, `DisableUnit`. These are recorded for audit-trail
///   completeness but their undo is genuinely lossy (recursive
///   removals lose content; restarting a stopped service might be
///   wrong if the operator wanted it down). Undo logs the variant +
///   warns + continues.
///
/// `WriteFile.prior_content` carries the bytes the file held before the
/// write so the undo can restore an overwrite (in-place update path).
/// `None` ⇒ the file did not exist beforehand and undo is `remove_file`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum UndoStep {
    /// Recorded after `write_root_owned(path, ...)` succeeds. `prior_content`
    /// is the bytes the file held before the write (for overwrites) or
    /// `None` if the file was newly created.
    WriteFile {
        /// Final path the bytes landed at (post-rename).
        path: Utf8PathBuf,
        /// Previous content if the path existed beforehand.
        prior_content: Option<Vec<u8>>,
    },
    /// Recorded after `fs::remove_file(path)` succeeds. `content` is the
    /// bytes captured from the file before removal so the undo can
    /// restore (best-effort — chown/perms not preserved).
    RemoveFile {
        /// Path that was unlinked.
        path: Utf8PathBuf,
        /// Bytes captured pre-unlink.
        content: Vec<u8>,
    },
    /// Recorded after a directory was created (or `create_dir_all`
    /// reached the leaf). Undo is `fs::remove_dir` (only if empty —
    /// child entries owned by other steps are unwound separately).
    CreateDir {
        /// Path of the directory created.
        path: Utf8PathBuf,
    },
    /// Recorded after `fs::remove_dir_all(path)` succeeds. Undo is
    /// best-effort `fs::create_dir_all` (the recursive-removed contents
    /// are unrecoverable; re-running apply re-populates them).
    RemoveDir {
        /// Path of the directory tree that was removed.
        path: Utf8PathBuf,
    },
    /// Recorded after `systemd.start_unit(name)` succeeds. Undo is
    /// `stop_unit`.
    StartUnit {
        /// Unit name (e.g. `ghars-runner@buckos.service`).
        name: String,
    },
    /// Recorded after `systemd.stop_unit(name)` succeeds. Undo is
    /// best-effort `start_unit` (operator may have wanted the unit
    /// stopped; we warn rather than blindly restarting in production
    /// rollback paths — guarded by [`UndoStep::is_reverse_direction`]).
    StopUnit {
        /// Unit name.
        name: String,
    },
    /// Recorded after `systemd.enable_unit(name)` succeeds. Undo is
    /// `disable_unit`.
    EnableUnit {
        /// Unit name.
        name: String,
    },
    /// Recorded after `systemd.disable_unit(name)` succeeds. Undo is
    /// best-effort `enable_unit` (guarded reverse-direction; warn).
    DisableUnit {
        /// Unit name.
        name: String,
    },
    /// Recorded after `config_shell.run_register(...)` succeeds. Undo
    /// is to mint a fresh removal token via the auth registry and call
    /// `config_shell.run_remove`. If the auth registry has no entry
    /// for `auth_name` the undo emits a `tracing::warn!` and continues
    /// — config.sh registration is hard to reverse, so we attempt
    /// `config.sh remove --token <fresh>` if auth is available and
    /// otherwise emit a warning.
    GitHubRegistration {
        /// Runner instance name (the `%i` value).
        name: String,
        /// Repo / org URL the runner registered against.
        url: String,
        /// Auth registry key.
        auth_name: String,
        /// Per-runner home directory
        /// (`/var/lib/ghars/<TRUST_ZONE>/ghars-<NAME>`).
        runner_home: Utf8PathBuf,
    },
    /// Recorded after `fs::set_permissions(path, mode)` succeeds.
    /// `prior_mode` is the file's mode bits BEFORE the chmod, masked
    /// to `0o7777` (the standard permission bits including setuid /
    /// setgid / sticky); used by undo to restore the pre-call state
    /// when rollback fires. Used by `chmod_record_undo` in
    /// `runners.rs::execute_create_runner`; the helper centralizes
    /// O_NOFOLLOW symlink-refusal + prior-mode capture + UndoLog
    /// push so future chmod call sites inherit all three guarantees
    /// automatically without needing to be enumerated in this doc.
    SetMode {
        /// Path whose mode was changed.
        path: Utf8PathBuf,
        /// Mode bits before the chmod call (masked to `0o7777`).
        prior_mode: u32,
    },
    /// Recorded after `fchown(fd, uid, gid)` succeeds. `prior_uid` and
    /// `prior_gid` are the file's owner/group BEFORE the fchown; used
    /// by undo to restore the pre-call ownership when rollback fires.
    /// Used by `fchown_record_undo` in `runners.rs::execute_create_runner`
    /// to chown the runner's writable set (runner_home, runner_home/tmp,
    /// .ktstr, .ccache, credential files) to the DynamicUser-allocated
    /// UID. The helper centralizes O_NOFOLLOW symlink-refusal +
    /// prior-ownership capture + UndoLog push so future chown call
    /// sites inherit all three guarantees automatically.
    SetOwner {
        /// Path whose owner / group was changed.
        path: Utf8PathBuf,
        /// uid before the fchown call.
        prior_uid: u32,
        /// gid before the fchown call.
        prior_gid: u32,
    },
}

impl UndoStep {
    /// True for variants whose undo is genuinely lossy (`Remove*`,
    /// `Stop*`, `Disable*`, `*Del`). The undo path logs and skips these
    /// rather than blindly inverting — design Part 8 specifies "best-
    /// effort", and re-creating recursively-removed directory content,
    /// re-starting a stopped unit (operator may have intended it
    /// down), or re-adding a deleted user (UID would change, group
    /// memberships and home content lost) all cause more damage than
    /// they prevent.
    #[must_use]
    pub fn is_reverse_direction(&self) -> bool {
        matches!(
            self,
            UndoStep::RemoveFile { .. }
                | UndoStep::RemoveDir { .. }
                | UndoStep::StopUnit { .. }
                | UndoStep::DisableUnit { .. }
        )
    }

    /// One-line operator-readable summary of the recorded mutation,
    /// suitable for the rollback-state advisory in `cmd_apply`.
    /// Names the step's effect in past tense ("wrote …", "started …",
    /// "removed …") so the advisory reads as an audit trail of what
    /// happened on disk before the action errored. Byte-content fields
    /// (`WriteFile.prior_content`, `RemoveFile.content`) are
    /// intentionally omitted — they are recovery payloads for
    /// [`undo`], not advisory details, and would dominate the line
    /// length without operator-actionable signal.
    ///
    /// Every interpolated `path`, `name`, and `url` field passes
    /// through [`crate::escape_control_chars`] before formatting.
    /// Drop-in paths and unit names are derived from operator-supplied
    /// config (runner names flow into
    /// `<runtime>/.../00-ghars.conf`, repo/org URLs into
    /// `GitHubRegistration.url`). Upstream validators
    /// (`validate_runner_name`, `check_identity_field`, the URL regex)
    /// reject control characters at config-load and render-identity
    /// time, but `describe()` is also called outside the rollback
    /// advisory render path (e.g. by future programmatic consumers
    /// reading `failed_undo_logs`); escaping inside `describe()` keeps
    /// the contract single-source. The advisory render site applies
    /// `escape_control_chars` again — second pass is a no-op
    /// (idempotent: the first pass replaces every C0/DEL byte with a
    /// printable backslash sequence; nothing remains for the second
    /// pass to escape).
    #[must_use]
    pub fn describe(&self) -> String {
        match self {
            UndoStep::WriteFile { path, .. } => {
                format!("wrote {}", crate::escape_control_chars(path.as_str()))
            }
            UndoStep::RemoveFile { path, .. } => {
                format!(
                    "removed file {}",
                    crate::escape_control_chars(path.as_str())
                )
            }
            UndoStep::CreateDir { path } => {
                format!(
                    "created directory {}",
                    crate::escape_control_chars(path.as_str())
                )
            }
            UndoStep::RemoveDir { path } => {
                format!(
                    "removed directory {}",
                    crate::escape_control_chars(path.as_str())
                )
            }
            UndoStep::StartUnit { name } => {
                format!("started {}", crate::escape_control_chars(name))
            }
            UndoStep::StopUnit { name } => {
                format!("stopped {}", crate::escape_control_chars(name))
            }
            UndoStep::EnableUnit { name } => {
                format!("enabled {}", crate::escape_control_chars(name))
            }
            UndoStep::DisableUnit { name } => {
                format!("disabled {}", crate::escape_control_chars(name))
            }
            UndoStep::GitHubRegistration { name, url, .. } => {
                format!(
                    "registered runner {} against {}",
                    crate::escape_control_chars(name),
                    crate::escape_control_chars(url),
                )
            }
            UndoStep::SetMode { path, prior_mode } => {
                format!(
                    "chmod {} (was 0o{:o})",
                    crate::escape_control_chars(path.as_str()),
                    prior_mode
                )
            }
            UndoStep::SetOwner {
                path,
                prior_uid,
                prior_gid,
            } => {
                format!(
                    "chown {} (was {}:{})",
                    crate::escape_control_chars(path.as_str()),
                    prior_uid,
                    prior_gid
                )
            }
        }
    }
}

/// Append-only record of mutating steps for one action. `execute_*`
/// handlers take `&mut UndoLog` and `push` after each successful side
/// effect. On `Err` from the handler, [`super::orchestrator::apply`]
/// walks the log in reverse when `opts.rollback_on_failure` is set.
#[derive(Debug, Default)]
pub struct UndoLog {
    steps: Vec<UndoStep>,
}

impl UndoLog {
    /// Construct an empty log.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Append a step. Steps are walked in reverse on undo so call sites
    /// must push AFTER the side effect succeeded — pushing before the
    /// effect lands and the effect failing would surface a step that
    /// never happened, and undo would attempt to reverse nonexistent
    /// state.
    pub fn push(&mut self, step: UndoStep) {
        self.steps.push(step);
    }

    /// Read-only view of the recorded steps in insertion order.
    #[must_use]
    pub fn steps(&self) -> &[UndoStep] {
        &self.steps
    }

    /// Number of steps recorded.
    #[must_use]
    pub fn len(&self) -> usize {
        self.steps.len()
    }

    /// True ⇔ no steps recorded.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.steps.is_empty()
    }

    /// Consume the log, returning the recorded steps in insertion order.
    /// Used by [`super::orchestrator::apply`] on the Err path to plumb
    /// the per-action mutation manifest into
    /// [`super::outcome::ApplyResult::failed_undo_logs`] so `cmd_apply`'s
    /// rollback advisory can list what happened on disk before
    /// the action errored.
    #[must_use]
    pub fn into_steps(self) -> Vec<UndoStep> {
        self.steps
    }
}

/// Auth registry — `apply` looks up [`crate::plan::RunnerPlan`]'s `spec.auth_name`
/// and [`crate::plan::RunnerIdentity::auth_name`] against this map at action
/// execution time rather than per-runner pre-resolution. Caller
/// (`cli`) owns it.
pub type AuthRegistry<'a> = &'a HashMap<String, Box<dyn TokenSource>>;

/// Bag of trait-object dependencies threaded through every `execute_*`
/// handler. Grouping them in a struct keeps the call surface narrow
/// (avoids `apply()`'s 8-argument grid) and gives tests a single seam
/// to swap.
pub struct Deps<'a> {
    /// Systemd D-Bus adapter.
    pub systemd: &'a dyn Systemd,
    /// Auth registry — runner-name → token source.
    pub auth: AuthRegistry<'a>,
    /// Tarball download / verify / install seam.
    pub tarball: &'a dyn Tarball,
    /// `config.sh` invocation seam.
    pub config_shell: &'a dyn ConfigShell,
}

/// Walk `log` in reverse and attempt each step's inverse. Per-step
/// failures are logged via `tracing::warn!` and the chain continues —
/// design Part 8 specifies "best-effort". Returns `Ok(())` always; the
/// signature is `Result` only so callers can propagate via `?` if a
/// future revision needs to surface a hard failure.
///
/// Forward-direction variants (Create-side mutations) are reversed
/// directly. Reverse-direction variants ([`UndoStep::is_reverse_direction`])
/// emit a `tracing::warn!` per step and continue without attempting
/// the inverse — see the variant docs for why per-step.
///
/// The `auth` registry is required to undo `GitHubRegistration` — we
/// mint a fresh removal token and call `config_shell.run_remove`. When
/// the `auth_name` is missing from the registry we warn and skip
/// (matches the orphan-removal contract in `execute_remove_runner`).
///
/// # Errors
///
/// Currently never returns `Err` — every per-step failure is logged
/// and the function presses on. Returning `Result` keeps the signature
/// future-proof.
pub fn undo(log: &UndoLog, deps: &Deps<'_>, _paths: &Paths) -> Result<()> {
    for step in log.steps().iter().rev() {
        if step.is_reverse_direction() {
            tracing::warn!(
                ?step,
                "rollback: skipping reverse-direction step; lossy inverse \
                 would not restore prior state. Re-run `ghars apply` to \
                 idempotently complete the removal."
            );
            continue;
        }
        if let Err(e) = undo_one(step, deps) {
            tracing::warn!(
                ?step,
                error = %e,
                "rollback: per-step undo failed; continuing"
            );
        }
    }
    Ok(())
}

/// Inverse of one [`UndoStep`]. Pure dispatch — no logging, no error
/// suppression — so [`undo`] above can wrap each call in its own
/// `tracing::warn!` and the per-step error is visible at the apply
/// boundary. Reverse-direction variants are unreachable here because
/// [`undo`] filters them upstream; the `unreachable!()` arm documents
/// that contract.
fn undo_one(step: &UndoStep, deps: &Deps<'_>) -> Result<()> {
    match step {
        UndoStep::WriteFile {
            path,
            prior_content,
        } => {
            if let Some(bytes) = prior_content {
                // Restore overwrite: rewrite the previous content
                // through the same atomic-rename helper the forward
                // path used.
                write_root_owned(path, bytes)
            } else {
                // No prior content ⇒ file was newly created. Unlink it.
                if path.exists() {
                    fs::remove_file(path.as_std_path()).map_err(GharsError::Io)?;
                }
                Ok(())
            }
        }
        UndoStep::CreateDir { path } => {
            // Only remove if empty — children belong to their own
            // UndoSteps which the reverse walk handles separately.
            // remove_dir returns ENOTEMPTY for non-empty dirs; we map
            // that to Ok(()) with a warn so the chain continues
            // (best-effort).
            if path.exists() {
                match fs::remove_dir(path.as_std_path()) {
                    Ok(()) => Ok(()),
                    Err(e) if matches!(e.raw_os_error(), Some(libc::ENOTEMPTY | libc::EEXIST)) => {
                        tracing::warn!(
                            path = path.as_str(),
                            "rollback: directory not empty; leaving for next apply"
                        );
                        Ok(())
                    }
                    Err(e) => Err(GharsError::Io(e)),
                }
            } else {
                Ok(())
            }
        }
        UndoStep::StartUnit { name } => deps.systemd.stop_unit(name),
        UndoStep::EnableUnit { name } => deps.systemd.disable_unit(name),
        UndoStep::GitHubRegistration {
            name,
            url,
            auth_name,
            runner_home,
        } => {
            // Mint a fresh removal token; if the registry has no
            // matching entry, warn and skip per the registration
            // undo contract.
            let Some(source) = deps.auth.get(auth_name) else {
                tracing::warn!(
                    runner = name.as_str(),
                    auth = auth_name.as_str(),
                    "rollback GitHubRegistration: auth source not in registry; \
                     cannot mint removal token. The runner remains registered \
                     server-side; remove via the GitHub UI or restore [auth.NAME] \
                     to enable a clean deregister on the next apply."
                );
                return Ok(());
            };
            let token = source.mint_removal_token(url)?;
            let undo_bin_dir = super::runners::find_active_bin_dir(runner_home)?;
            deps.config_shell.run_remove(&ConfigShellCtx {
                runner_home,
                bin_dir: &undo_bin_dir,
                name,
                url,
                labels: &[],
                token: &token.value,
            })
        }
        UndoStep::SetMode { path, prior_mode } => {
            use std::os::fd::AsRawFd;
            use std::os::unix::fs::{OpenOptionsExt, PermissionsExt};
            // Restore the pre-call mode. Two tolerated edge cases:
            //
            //   1. ENOENT: the path may have been removed by a
            //      later UndoStep's reverse (e.g. an
            //      UndoStep::WriteFile undoing a creation of the
            //      path before this SetMode reversal runs in the
            //      outer reverse walk).
            //
            //   2. The path is now a symlink: the forward
            //      `chmod_record_undo` in runners.rs refuses
            //      symlinks at chmod time, but between the forward
            //      chmod and this rollback, a malicious sibling
            //      DynamicUser in the same trust_zone could have
            //      raced to swap the path with a symlink to a
            //      sensitive root-owned target (e.g. /etc/shadow,
            //      /etc/passwd). Without this symlink check, the
            //      rollback would silently chmod that target to
            //      `prior_mode` (could lock out non-root users or
            //      otherwise damage system state). Warn and skip;
            //      mode restoration is best-effort during rollback
            //      anyway (see the function-level docstring).
            //
            // The implementation uses the same O_RDONLY + O_NOFOLLOW
            // pattern as `chmod_record_undo`, so both the symlink-
            // refusal AND the chmod are atomic with the open: no
            // path-resolution race between the lstat-equivalent
            // (the open with O_NOFOLLOW) and the chmod. fchmod
            // operates directly on the fd -- no /proc/self/fd
            // round-trip, one fewer syscall, no dependency on /proc
            // being mounted.
            match std::fs::OpenOptions::new()
                .read(true)
                .custom_flags(libc::O_NOFOLLOW)
                .open(path.as_std_path())
            {
                Ok(fd) => nix::sys::stat::fchmod(
                    fd.as_raw_fd(),
                    nix::sys::stat::Mode::from_bits_retain(
                        *prior_mode as nix::sys::stat::mode_t,
                    ),
                )
                .map_err(|e| GharsError::Io(std::io::Error::from_raw_os_error(e as i32))),
                Err(e) if e.raw_os_error() == Some(libc::ELOOP) => {
                    tracing::warn!(
                        path = path.as_str(),
                        "rollback SetMode: path is now a symlink (not at \
                         forward chmod time); refusing to chmod-through to \
                         the symlink target. Manual intervention may be \
                         needed if rollback completeness matters; this skip \
                         is the safe default."
                    );
                    Ok(())
                }
                Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(()),
                Err(e) => Err(GharsError::Io(e)),
            }
        }
        UndoStep::SetOwner {
            path,
            prior_uid,
            prior_gid,
        } => {
            use std::os::fd::AsRawFd;
            use std::os::unix::fs::OpenOptionsExt;
            // Mirror SetMode's rollback semantics: use the same
            // O_RDONLY + O_NOFOLLOW + O_NONBLOCK open pattern so a
            // sibling-DynamicUser-raced symlink swap between forward
            // chown and reverse chown doesn't redirect the rollback
            // to a different inode. ENOENT (path removed by an
            // earlier reverse step) and ELOOP (symlink swap)
            // tolerated; other I/O errors propagate.
            //
            // fchown takes a RawFd directly — no /proc/self/fd
            // round-trip needed because fchown is a direct
            // file-descriptor syscall (unlike fchmod via /proc which
            // chmod_record_undo uses due to ENOTSUP on O_PATH fds;
            // here we use plain O_RDONLY anyway, so fchown is the
            // natural shape).
            match std::fs::OpenOptions::new()
                .read(true)
                .custom_flags(libc::O_NOFOLLOW | libc::O_NONBLOCK)
                .open(path.as_std_path())
            {
                Ok(fd) => nix::unistd::fchown(
                    fd.as_raw_fd(),
                    Some(nix::unistd::Uid::from_raw(*prior_uid)),
                    Some(nix::unistd::Gid::from_raw(*prior_gid)),
                )
                .map_err(|e| {
                    GharsError::Io(std::io::Error::from_raw_os_error(e as i32))
                }),
                Err(e) if e.raw_os_error() == Some(libc::ELOOP) => {
                    tracing::warn!(
                        path = path.as_str(),
                        "rollback SetOwner: path is now a symlink (not at \
                         forward chown time); refusing to chown-through to \
                         the symlink target. Manual intervention may be \
                         needed if rollback completeness matters; this skip \
                         is the safe default."
                    );
                    Ok(())
                }
                Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(()),
                Err(e) => Err(GharsError::Io(e)),
            }
        }
        UndoStep::RemoveFile { .. }
        | UndoStep::RemoveDir { .. }
        | UndoStep::StopUnit { .. }
        | UndoStep::DisableUnit { .. } => {
            // Filtered upstream by `undo`'s is_reverse_direction()
            // gate. Documenting the contract here so a future caller
            // that bypasses `undo` and reaches `undo_one` directly
            // gets a clear panic instead of silently invoking lossy
            // inverses.
            unreachable!("reverse-direction steps are filtered by `undo`")
        }
    }
}
