//! Per-runner action handlers: create / remove / update (in-place + recreate).

use std::fs;
use std::os::fd::AsRawFd;
use std::os::unix::fs::{FileTypeExt, OpenOptionsExt, PermissionsExt};

use crate::Result;
use crate::config::NetworkMode;
use crate::error::GharsError;
use crate::paths::Paths;
use crate::plan::{DropInChangeKind, RunnerDelta, RunnerIdentity, RunnerPlan};
use crate::state::MANAGED_DROP_IN_BASENAMES;
use crate::systemd::render_runner_unit;

use super::netns::{provision_netns_artifacts, teardown_netns_artifacts, verify_runner_netns};
use super::outcome::ApplyOutcome;
use super::rmrf::guard_home_dir_rmrf;
use super::shell::ConfigShellCtx;
use super::undo::{Deps, UndoLog, UndoStep};
use super::writes::{mint_token, read_prior, read_then_write_if_changed, write_record_undo};
use camino::Utf8PathBuf;

/// chmod a path while recording the pre-call mode in the undo log
/// so a rollback after a later step's failure can restore the
/// previous mode.
///
/// SYMLINK SAFETY (PRIMARY DEFENSE): the helper opens the path
/// with `O_RDONLY | O_NOFOLLOW` BEFORE chmod'ing it. `O_NOFOLLOW`
/// causes the kernel to return ELOOP if the path is itself a
/// symlink, so a symlink target is rejected ATOMICALLY at open
/// time — no lstat-then-chmod race window. The chmod then runs
/// against the path `/proc/self/fd/{fd}` — a kernel-magic path
/// that resolves to the file the fd points to. Because the fd
/// was bound at open time with O_NOFOLLOW protection, no
/// subsequent path-resolution race can redirect the chmod to a
/// different inode. This closes the planted-symlink vector that
/// the deleted `set_tree_permissions` cascade exposed (a
/// compromised sibling DynamicUser in the same trust_zone,
/// which shares the trust-zone-allocated UID, planting
/// `runner_home/tmp` or `runner_home/.credentials*` as a symlink
/// to a sensitive root-owned path like `/etc/shadow`).
///
/// `O_RDONLY` is the access mode; apply runs as root so it
/// always succeeds against the target's DAC. `O_PATH` would be
/// lighter-weight but Linux rejects chmod via
/// `/proc/self/fd/{fd}` when fd was opened O_PATH (returns
/// ENOTSUP — the O_PATH handle is too "lightweight" for
/// metadata mutation). `lchmod` is not in Rust's std, and the
/// `fchmodat2(..., AT_SYMLINK_NOFOLLOW)` syscall (which is what
/// glibc 2.38+ routes `fchmodat(..., AT_SYMLINK_NOFOLLOW)` to)
/// was only added to Linux in 6.6 (commit 09da082b07bb), so the
/// O_RDONLY+O_NOFOLLOW + /proc/self/fd pattern is the portable
/// safe form for kernels >=4.x.
///
/// The Stage 1 clamp of `runner_home` to 0o755 in
/// `execute_create_runner` is a SECONDARY defense layer: even if
/// a hypothetical regression weakened the O_NOFOLLOW open here,
/// a sibling DynamicUser could not write to runner_home (mode
/// 0o755 root:root) during apply and so could not plant a
/// symlink at any of the chmod sites under it. The pre-Stage-1
/// entry sweep at `sweep_runner_home_for_planted_entries`
/// catches PRE-existing planted entries; Stage 1 prevents NEW
/// planting during the apply window; this O_NOFOLLOW helper
/// catches anything that slips past both.
///
/// `prior_mode` is masked to `0o7777` — the standard permission
/// bits including setuid / setgid / sticky. The pre-call mode is
/// read via `metadata` on the opened fd's /proc/self/fd/{fd}
/// path (fstat-equivalent on the fd target), atomic with the
/// chmod. Caller is responsible for ensuring the path exists
/// (the helper propagates ENOENT from the open call).
///
/// `context` is a short operator-readable label identifying the
/// call site within `execute_create_runner` (e.g. `"tz_dir"`,
/// `"runner_home (Stage 1)"`, `".credentials_rsaparams"`). It
/// surfaces in the action label of the GharsError on failure so
/// an operator reading the diagnostic can immediately tell which
/// of the helper's eight call sites errored. The runner name is
/// also included so multi-runner applies disambiguate per
/// failing runner.
///
/// SetMode UndoLog push is GATED on `prior_mode != mode`: a
/// no-op chmod (re-apply against an unchanged on-disk state)
/// records nothing. This keeps the rollback advisory free of
/// noise lines that describe chmod-to-current-mode operations.
fn chmod_record_undo(
    path: &camino::Utf8Path,
    mode: u32,
    context: &str,
    log: &mut UndoLog,
) -> crate::Result<()> {
    // Open with O_RDONLY + O_NOFOLLOW: returns ELOOP if path is a
    // symlink (refuses symlink targets atomically; no path-
    // resolution race between an lstat and a chmod). Apply runs
    // as root, so O_RDONLY succeeds against any file or directory
    // owned by anyone. O_PATH would be lighter-weight but Linux
    // does not let chmod operate on /proc/self/fd/{fd} when fd
    // was opened O_PATH (returns ENOTSUP), so O_RDONLY is the
    // simplest portable form.
    // O_NONBLOCK defense-in-depth: a FIFO at the chmod target
    // would otherwise block `open(O_RDONLY)` until a writer
    // appears, hanging apply indefinitely. Even though
    // `sweep_runner_home_for_planted_entries` rejects FIFOs at
    // runner_home's direct children, adding O_NONBLOCK here is
    // free and covers any future chmod target outside the
    // sweep's scope (e.g. tz_dir, .ktstr, .ccache — currently
    // root-owned but defended against a future regression
    // weakening the parent dir mode).
    let fd = match std::fs::OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_NOFOLLOW | libc::O_NONBLOCK)
        .open(path.as_std_path())
    {
        Ok(fd) => fd,
        Err(e) if e.raw_os_error() == Some(libc::ELOOP) => {
            return Err(GharsError::Apply {
                action: format!("chmod {context} at {path}"),
                source: Box::new(GharsError::Validation(
                    format!(
                        "refusing to chmod through symlink at {path} \
                         (context: {context}) — path-based chmod would \
                         apply mode to the symlink target rather than the \
                         symlink itself"
                    ),
                    "an attacker-planted symlink (stale from a failed \
                     earlier apply or a compromised sibling DynamicUser \
                     in the same trust_zone) is present at the chmod \
                     target. Remove the symlink and re-run apply"
                        .into(),
                )),
            });
        }
        Err(e) => {
            return Err(GharsError::Apply {
                action: format!("chmod {context} at {path}"),
                source: Box::new(GharsError::Io(e)),
            });
        }
    };
    // Re-open the fd target through /proc/self/fd/{fd}, atomic
    // with the open above (no path-resolution race). metadata()
    // here follows the proc magic symlink to the fd target.
    let proc_path = format!("/proc/self/fd/{}", fd.as_raw_fd());
    let prior_mode = fs::metadata(&proc_path)?.permissions().mode() & 0o7777;
    fs::set_permissions(&proc_path, std::fs::Permissions::from_mode(mode))?;
    // fd drops here, closing the kernel handle. The /proc/self/fd
    // pathname becomes invalid after this point — any later code
    // accessing it would see ENOENT.
    drop(fd);
    // Gate the UndoLog push on a non-trivial mode change. A
    // no-op chmod (current mode == requested mode) on a re-apply
    // would otherwise pollute the rollback advisory with chmod-
    // restore lines that describe restoring the mode to its
    // current value.
    if prior_mode != mode {
        log.push(UndoStep::SetMode {
            path: path.to_path_buf(),
            prior_mode,
        });
    }
    Ok(())
}

/// Pre-apply sweep of `runner_home` direct children. Refuses to
/// proceed if any entry is a symlink, FIFO, device file, or
/// socket. These can only arise from a sibling DynamicUser
/// planting them during a prior failed apply's 0o777 window OR
/// from operator manual intervention.
///
/// Why a sweep is needed even with chmod_record_undo's
/// O_NOFOLLOW: `config.sh` runs BEFORE the post-config.sh
/// chmod loop and uses .NET `File.WriteAllText` (no O_NOFOLLOW)
/// — if a planted symlink exists at `runner_home/.credentials*`,
/// config.sh writes OAuth credentials + RSA private key through
/// the symlink to an attacker target before the chmod loop runs
/// and notices. The credentials are already exfiltrated by then.
///
/// Why also reject FIFO/device/socket: opening a FIFO with
/// `O_RDONLY` blocks until a writer opens — apply would hang
/// indefinitely in chmod_record_undo. Devices and sockets have
/// similar uncovered semantics through path-based file ops.
///
/// Why direct children only (not recursive): the recursive
/// approach is what the deleted `set_tree_permissions` cascade
/// did, and it has TOCTOU-during-walk problems of its own. The
/// chmod and config.sh code paths only touch direct children
/// of runner_home (`.runner`, `.credentials*`, `tmp`) plus
/// the bin.X.Y.Z/ subtree (which is laid down by
/// `install_binary` after this sweep with mode bits from the
/// tarball headers). Deeper paths are not on the attack
/// surface.
fn sweep_runner_home_for_planted_entries(home: &std::path::Path) -> crate::Result<()> {
    let entries = match fs::read_dir(home) {
        Ok(e) => e,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(()),
        Err(e) => return Err(GharsError::Io(e)),
    };
    for entry in entries {
        let entry = entry?;
        let path = entry.path();
        let meta = fs::symlink_metadata(&path)?;
        let ft = meta.file_type();
        if !ft.is_file() && !ft.is_dir() {
            let kind = if ft.is_symlink() {
                "symlink"
            } else if ft.is_fifo() {
                "FIFO"
            } else if ft.is_block_device() {
                "block device"
            } else if ft.is_char_device() {
                "char device"
            } else if ft.is_socket() {
                "socket"
            } else {
                "non-regular entry"
            };
            return Err(GharsError::Apply {
                action: format!("pre-apply sweep of {}", home.display()),
                source: Box::new(GharsError::Validation(
                    format!(
                        "refusing to proceed: planted {} at {} — \
                         config.sh would write credentials through it \
                         before the chmod loop can refuse",
                        kind,
                        path.display()
                    ),
                    "investigate runner_home: a sibling DynamicUser in \
                     the same trust_zone may have planted this entry \
                     during a prior failed apply's 0o777 window. Remove \
                     the entry and re-run apply"
                        .into(),
                )),
            });
        }
    }
    Ok(())
}

/// Find the most recent `bin.X.Y.Z/` directory under runner_home that
/// contains config.sh. Used by remove/undo paths that need to run
/// config.sh but don't have the version from a plan.
pub(super) fn find_active_bin_dir(runner_home: &camino::Utf8Path) -> crate::Result<Utf8PathBuf> {
    let mut candidates: Vec<Utf8PathBuf> = Vec::new();
    if let Ok(entries) = fs::read_dir(runner_home.as_std_path()) {
        for entry in entries.flatten() {
            let name = entry.file_name();
            let name_str = name.to_string_lossy();
            if name_str.starts_with("bin.") && entry.path().join("config.sh").exists() {
                if let Ok(utf8) = Utf8PathBuf::try_from(entry.path()) {
                    candidates.push(utf8);
                }
            }
        }
    }
    candidates.sort();
    candidates.pop().ok_or_else(|| {
        GharsError::Apply {
            action: format!("find config.sh under {runner_home}"),
            source: Box::new(GharsError::Io(std::io::Error::new(
                std::io::ErrorKind::NotFound,
                format!("no bin.*/config.sh found under {runner_home}"),
            ))),
        }
    })
}

pub(super) fn execute_create_runner(
    plan: &RunnerPlan,
    deps: &Deps<'_>,
    paths: &Paths,
    log: &mut UndoLog,
    keep_versions: u32,
) -> Result<ApplyOutcome> {
    let spec = &plan.spec;
    let runner_home = paths.runner_home(&spec.trust_zone, &spec.name);

    // Trust-zone parent dir. fs::create_dir_all is idempotent and
    // creates it as a side effect of the .ktstr / .ccache calls
    // below, but making it explicit closes the gap if those children
    // become conditional. 0o711 = root rwx, others execute-only:
    // DynamicUser can descend into /var/lib/ghars/{tz}/ghars-{name}/
    // and /var/lib/ghars/{tz}/.ktstr/ etc. but can NOT `ls` the
    // trust-zone dir. Belt for out-of-sandbox processes; the systemd
    // BindPaths inside the runner sandbox only surface the runner's
    // own trust_zone path anyway.
    let tz_dir = paths.state_dir.join(&spec.trust_zone);
    fs::create_dir_all(tz_dir.as_std_path())?;
    chmod_record_undo(&tz_dir, 0o711, "tz_dir", log)?;

    // Clean up stale DynamicUser symlinks from previous runs.
    let home_std = runner_home.as_std_path();
    if let Ok(meta) = fs::symlink_metadata(home_std) {
        if meta.file_type().is_symlink() {
            let _ = fs::remove_file(home_std);
        }
    }
    fs::create_dir_all(home_std)?;

    // Pre-Stage-1 entry sweep: refuse to proceed if any direct child
    // of runner_home is a symlink, FIFO, device file, or socket.
    // chmod_record_undo's O_NOFOLLOW defense catches a symlink at
    // a CHMOD TARGET path, but config.sh runs BEFORE the credential-
    // file chmod loop and uses .NET File.WriteAllText (no O_NOFOLLOW)
    // — if a sibling DynamicUser planted runner_home/.credentials*
    // as a symlink during a prior failed apply's 0o777 window,
    // config.sh would write OAuth credentials + RSA private key
    // through the symlink to an attacker target BEFORE the post-
    // config.sh chmod_record_undo loop runs and notices. The
    // credentials are already exfiltrated by then.
    //
    // The sweep enumerates runner_home's direct children via
    // symlink_metadata (lstat — does NOT follow), refuses to
    // proceed if any are non-regular-non-dir. FIFO/device/socket
    // entries would also cause apply to block on subsequent reads
    // (FIFO open with O_RDONLY blocks until a writer opens, hanging
    // apply indefinitely).
    //
    // Recursive sweep would re-introduce the same TOCTOU-during-
    // walk class as the deleted set_tree_permissions cascade — we
    // intentionally stay non-recursive. Only direct children matter:
    // config.sh and the post-config.sh chmod loop write at
    // runner_home/.runner / .credentials / .credentials_rsaparams,
    // and chmod runner_home/tmp + runner_home itself. Deeper paths
    // aren't touched by either code path.
    sweep_runner_home_for_planted_entries(home_std)?;

    // Stage 1 of runner_home chmod: clamp to 0o755 (root rwx, others
    // r-x) for the duration of apply. Defense-in-depth on top of
    // chmod_record_undo's O_NOFOLLOW: even if a future regression
    // weakened the helper's symlink refusal, the 0o755 clamp denies
    // sibling DynamicUser write access to runner_home so they
    // cannot plant new symlinks DURING apply between the pre-
    // Stage-1 sweep above and Stage 2 below. The pre-Stage-1 sweep
    // catches PRE-existing planted entries; Stage 1 prevents NEW
    // planting during the apply window.
    //
    // The dir needs to be traversable by root throughout — install_
    // binary writes bin.X.Y.Z/ under it, config.sh writes .runner /
    // .credentials* into it, ghars chmods those files after.
    //
    // Stage 2 below (just before deps.systemd.start_unit) re-opens
    // runner_home to 0o777 so the DynamicUser allocated at unit
    // start time can create _work/, _diag/, and operator toolchain
    // caches:
    //   - Runner.Listener creating `_work/` (Runner.cs:418).
    //   - HostTraceListener creating `_diag/` (HostTraceListener.cs:29).
    //   - workflow steps writing job artifacts under `_work/`.
    //   - operator/runner-toolchain caches (~/.cargo, ~/.npm, ~/.config, ...).
    // 0o777 is the right unit-runtime mode under the current
    // architecture: the DynamicUser UID is not NSS-resolvable on
    // systemd<256, so chown-by-name fails and Manager.RefUid is the
    // narrower alternative once the runner unit has started.
    chmod_record_undo(&runner_home, 0o755, "runner_home (Stage 1)", log)?;

    // Per-runner tmp dir so TMPDIR points somewhere the sccache server
    // can reach (PrivateTmp isolates /tmp per unit). Safe to chmod
    // 0o777 here because runner_home is currently 0o755 — no sibling
    // DynamicUser can plant `runner_home/tmp` as a symlink between
    // our create_dir_all and chmod.
    let runner_tmp = runner_home.join("tmp");
    fs::create_dir_all(runner_tmp.as_std_path())?;
    chmod_record_undo(&runner_tmp, 0o777, "runner_tmp", log)?;

    // Shared .ktstr directory at the trust-zone level. All runners in the
    // same trust_zone bind this path into their sandbox for KTSTR_LOCK_DIR
    // and KTSTR_CACHE_DIR. Mode 0777 so the DynamicUser (allocated at
    // unit-start time, unknown at apply time) can write to it; actual
    // isolation is at the trust-zone UID layer (different trust zones get
    // different UIDs).
    let ktstr_dir = tz_dir.join(".ktstr");
    fs::create_dir_all(ktstr_dir.as_std_path())?;
    chmod_record_undo(&ktstr_dir, 0o777, ".ktstr", log)?;
    let ccache_dir = tz_dir.join(".ccache");
    fs::create_dir_all(ccache_dir.as_std_path())?;
    chmod_record_undo(&ccache_dir, 0o777, ".ccache", log)?;

    // No useradd / gpasswd step. The runner unit declares
    // DynamicUser=yes with `User=ghars-tz-<TRUST_ZONE>` set in the
    // per-runner 00-ghars.conf drop-in; systemd allocates the
    // transient UID/GID on unit start and recycles it on stop. Cache
    // reach is socket-DAC + BindPaths (cache server runs at the same
    // trust_zone DynamicUser), not gpasswd.

    // 1) Runner binary. Two paths:
    //    (a) `runner_tarball` set on the spec → use the local file
    //        verbatim after re-stat'ing (verify_local closes the
    //        SEC-16 stat-then-extract TOCTOU window).
    //    (b) Otherwise the plan resolved a `Release` and we fetch its
    //        `tarball_url` into a runtime dir, verify SHA256, then
    //        install.
    let (tarball_path, version) = if let Some(local) = &spec.runner_tarball {
        deps.tarball.verify_local(local)?;
        // spec.runner_version is guaranteed Some by lower_to_effective:
        // the tarball+no-version gate at compute.rs rejects this
        // combination at plan time. expect() over unwrap_or_else
        // makes a regression that re-introduces the silent "local"
        // fallback surface as a loud panic rather than installing
        // into bin.local/ while the unit drop-in references
        // bin.latest/ (the pre-fix broken-from-birth shape).
        let version = spec
            .runner_version
            .clone()
            .expect(
                "tarball-pinned spec.runner_version: guaranteed Some by \
                 lower_to_effective's tarball+no-version validation gate",
            );
        (local.clone(), version)
    } else {
        let release = plan.resolved_release.as_ref().ok_or_else(|| {
            GharsError::Validation(
                format!("runner {:?}: no runner_tarball and no resolved release", spec.name),
                "set runner_version + runner_sha256, supply runner_tarball, or run plan again so the release-API lookup succeeds".into(),
            )
        })?;
        let dest = paths.runtime_dir.join(format!(
            "releases/{}/{}",
            release.version, release.tarball_name
        ));
        if let Some(parent) = dest.parent() {
            fs::create_dir_all(parent.as_std_path())?;
        }
        deps.tarball
            .fetch_or_verify(&release.tarball_url, &dest, &release.sha256)?;
        (dest, release.version.clone())
    };
    let bin_dir = deps.tarball.install_binary(
        &tarball_path,
        &paths.state_dir,
        &runner_home,
        &spec.name,
        &version,
    )?;

    // 2b) Retention prune (Part 9f). After the fresh
    //     `bin.<version>/` tree has been laid down, prune older
    //     `bin.X.Y.Z/` trees in the runner home so disk usage stays
    //     bounded. The pruner keeps the `keep_versions` most-recent
    //     by mtime plus whatever any operator-created
    //     `runner_home/bin` symlink resolves to (defense in depth
    //     against mtime touches and against operator-managed
    //     symlinks ghars itself no longer creates). Pruning is
    //     best-effort: per-entry failures are logged and counted,
    //     never propagated, so a failed cleanup doesn't sink the
    //     whole CreateRunner action. Errors from the call itself
    //     (read_dir failure on runner_home, or keep_versions = 0)
    //     DO propagate — those indicate a structural problem the
    //     operator should see.
    let _pruned = deps
        .tarball
        .prune_old_versions(&runner_home, keep_versions)?;

    // 3) Mint a registration token. SEC-05: the token is short-lived
    //    (1h GitHub TTL); we hand it to config.sh and never persist it.
    //    The caller-visible `RegistrationToken.value` is opaque so
    //    nothing here logs it.
    let token = mint_token(deps.auth, &spec.auth_name, &spec.url, false)?;

    // 4) Run config.sh --url ... --token ... — registers the runner
    //    with GitHub. SEC-05 mitigation note in trait doc; v0.1 still
    //    passes the token via argv pending the token-drop env-var
    //    pattern's full design. Pass `&token.value` so `token`
    //    stays owned in this frame and zeroizes on Drop at end of fn.
    deps.config_shell.run_register(&ConfigShellCtx {
        runner_home: &runner_home,
        bin_dir: &bin_dir,
        name: &spec.name,
        url: &spec.url,
        labels: &spec.labels,
        token: &token.value,
    })?;
    // Push GitHubRegistration AFTER run_register succeeds. Undo
    // path mints a fresh removal token via the auth registry and
    // calls run_remove. The runner_home is captured here because
    // it is the canonical location config.sh writes credentials
    // to, and we want the undo to target this exact path even if
    // the spec is mutated between push-time and undo-time.
    log.push(UndoStep::GitHubRegistration {
        name: spec.name.clone(),
        url: spec.url.clone(),
        auth_name: spec.auth_name.clone(),
        runner_home: runner_home.clone(),
    });

    // No tighten_credential_perms call. DynamicUser=yes manages
    // StateDirectory ownership at the systemd level; .credentials is
    // owned by the trust_zone's transient UID and inherits the
    // StateDirectoryMode=0700 from the unit template.

    // 5b) Re-render the unit text against the resolved spec. The
    // plan-time render in `into_runner_plan` happened BEFORE
    // `resolve_plan_releases` populated `spec.runner_version` from
    // the API for implicit-latest runners, so the plan-time preview
    // showed a "latest" placeholder in WorkingDirectory= / ExecStart=
    // / ConditionPathExists=. By apply time, resolve_plan_releases
    // (cli/cmd_apply.rs) has filled `spec.runner_version` from the
    // resolved release, so re-rendering here pins the actual version
    // into the drop-in body that lands on disk. The legacy populate
    // block that filled `runner_version` from `plan.resolved_release`
    // here is gone — resolve_plan_releases now owns the spec-level
    // fill so this site reads the same field uniformly.
    let rendered = render_runner_unit(spec)?;

    // 5c) Write .path and .env into the versioned bin dir.
    //   - `.path`: read once by runsvc.sh (`export PATH=\`cat .path\``)
    //     at runner-process start; inherited across exec by every
    //     worker / workflow-step subprocess.
    //   - `.env`: read once by Runner.Listener's LoadAndSetEnv
    //     (`src/Runner.Listener/Program.cs` Main) at process start,
    //     each `KEY=VALUE` set via Environment.SetEnvironmentVariable;
    //     workflow steps inherit through worker fork+exec.
    //
    // These reach workflow steps via the parent-process env, distinct
    // from the systemd `Environment=` directives in 00-ghars.conf /
    // 30-cache-pool.conf (LAYER 1, bind to the systemd unit process).
    // Bytes are computed by the pure functions
    // `render_runner_env_file` / `render_runner_path_file` so the
    // in-place UpdateRunner path produces byte-identical content for
    // the same spec (no runner_version interpolation in either
    // producer).
    write_record_undo(&bin_dir.join(".path"), rendered.path_file.as_bytes(), log)?;
    write_record_undo(&bin_dir.join(".env"), rendered.env_file.as_bytes(), log)?;

    // 5d) Normalize post-config.sh file modes to DynamicUser-READ.
    // Upstream actions/runner writes three files in runner_home:
    //   - `.runner` — runner identity JSON (IOUtil.SaveObject ->
    //     File.WriteAllText; mode is 0o666 & ~umask, so 0o644 with
    //     the default 0o022 umask, but could be 0o600 if ghars was
    //     invoked with a non-default umask like 0o077).
    //   - `.credentials` — OAuth credentials JSON (same call shape;
    //     same umask exposure).
    //   - `.credentials_rsaparams` — RSA private key. Upstream
    //     explicitly `chmod 600` in
    //     src/Runner.Listener/Configuration/RSAFileKeyManager.cs:33
    //     (the RSA key signs OAuth assertions for credential
    //     refresh), so this file lands at 0o600 regardless of
    //     umask.
    //
    // All three are root:root after config.sh (which ghars invokes
    // as root). The runner unit runs under DynamicUser; the
    // DynamicUser-allocated UID is in neither the owner nor any
    // group of root, so 0o600 / 0o640 are unreadable to it. Without
    // a normalize step, a non-default umask on the ghars host
    // breaks credential refresh and the runner stops accepting
    // jobs.
    //
    // Force 0o644 (owner rw, world r) on each file unconditionally
    // — defense-in-depth that does not depend on the
    // ghars-process-inherited umask being 0o022. Pre-exec umask
    // pinning via CommandExt::pre_exec (which requires unsafe,
    // forbidden by workspace lint) was the original plan, but
    // post-hoc chmod is the cleaner mechanism here: it works
    // regardless of WHICH process wrote the file (config.sh,
    // a future helper, an upstream-runner-version that adds a
    // new credential file with its own explicit chmod) AND
    // doesn't mutate process-global umask state that other code
    // paths in the same apply may depend on. nix::sys::stat::umask
    // exposes a safe wrapper (would unblock the pre-exec plan)
    // but using it process-wide has the same multi-writer
    // ambiguity — post-hoc chmod is the right level.
    //
    // Files missing on disk are tolerated as a no-op — config.sh
    // may legitimately omit `.credentials_rsaparams` on a
    // PAT-authenticated runner, or skip a write if registration
    // takes a path that doesn't materialize the file.
    //
    // The bin.X.Y.Z/ tree (extracted by deps.tarball.install_binary
    // above) keeps the modes the tarball headers wrote — 0o755 for
    // runsvc.sh / Runner.Listener / native binaries, 0o644 for
    // managed assemblies, 0o644 for the .env / .path files
    // write_record_undo just laid down. The pre-fix
    // `set_tree_permissions(tz_dir, 0o777)` cascade opened ALL of
    // these to 0o777, making runsvc.sh world-writable — a
    // workflow-step-RCE persistence vector. With the cascade gone,
    // those modes stay correct.
    //
    // The cascade also used path-based `fs::set_permissions` which
    // follows symlinks (it's chmod(2), not lchmod). Combined with
    // the recursive walk and ghars-runs-as-root, an operator-
    // writable path under runner_home with a planted symlink to,
    // e.g., /etc would have caused root to chmod /etc/* → 0o777, a
    // full local privilege escalation — the well-known
    // TOCTOU-during-recursive-chmod-on-operator-writable-trees
    // vulnerability class. The deletion closes the class by
    // construction (no walk → no follow), not by trying to walk
    // safely.
    let mut normalized = Vec::with_capacity(3);
    for basename in [".runner", ".credentials", ".credentials_rsaparams"] {
        let path = runner_home.join(basename);
        if path.as_std_path().exists() {
            chmod_record_undo(&path, 0o644, basename, log)?;
            normalized.push(basename);
        }
    }
    // Operator visibility: surface the per-CreateRunner credential
    // normalization so an operator running under non-default umask
    // can see ghars corrected modes. tracing::debug! keeps it out
    // of the default log surface; opt in via `RUST_LOG=ghars=debug`.
    tracing::debug!(
        runner = %spec.name,
        normalized = ?normalized,
        "normalized config.sh credential file modes to 0o644 (DynamicUser READ)"
    );

    // 6) Write unit file + drop-ins. The reset-on-empty validation
    //    already ran inside `render_runner_unit`.
    let unit_file = paths.unit_file(&spec.name);
    write_record_undo(&unit_file, rendered.template.as_bytes(), log)?;
    let drop_in_dir = paths.drop_in_dir(&spec.name);
    let drop_in_dir_existed = drop_in_dir.exists();
    fs::create_dir_all(drop_in_dir.as_std_path())?;
    if !drop_in_dir_existed {
        log.push(UndoStep::CreateDir {
            path: drop_in_dir.clone(),
        });
    }
    for (name, body) in &rendered.drop_ins {
        let dest = drop_in_dir.join(name);
        write_record_undo(&dest, body.as_bytes(), log)?;
    }

    // 7) `daemon-reload` happens once at the end of `apply()`; do NOT
    //    call it here. Enable + start.
    let unit_name = format!("ghars-runner@{}.service", spec.name);
    deps.systemd.enable_unit(&unit_name)?;
    log.push(UndoStep::EnableUnit {
        name: unit_name.clone(),
    });
    // Manager.StartUnit fails on a unit not yet loaded post-write. The
    // ordering per Part 8 is: write files → daemon_reload → start_unit.
    // We issue a daemon_reload here so the freshly-written unit is
    // visible; `apply()` issues a final daemon_reload after the
    // per-action loop too, which is idempotent.
    deps.systemd.daemon_reload()?;

    // 7b) For Netns runners: provision the per-runner netns side-units
    //     (config TOML, nft files, ghars-net@.service template) and
    //     start `ghars-net@INSTANCE.service` BEFORE the runner unit so
    //     the runner's `NetworkNamespacePath=/var/run/netns/ghars-%i`
    //     join succeeds. Fail-closed contract: missing netns =>
    //     runner refuses to start. Open mode is a no-op.
    provision_netns_artifacts(spec, deps, paths, log)?;

    // Stage 2 of runner_home chmod: open to 0o777 so the
    // DynamicUser allocated at unit start can write `_work/`,
    // `_diag/`, and toolchain caches under the per-runner home.
    // This is the LAST mutation under runner_home before the unit
    // starts, so no later chmod follows a sibling-DynamicUser-
    // planted symlink (the only file-mode mutations between here
    // and start_unit are systemd unit / drop-in writes outside
    // runner_home).
    chmod_record_undo(&runner_home, 0o777, "runner_home (Stage 2)", log)?;

    deps.systemd.start_unit(&unit_name)?;
    log.push(UndoStep::StartUnit {
        name: unit_name.clone(),
    });

    // 8) Post-start netns verification. Belt-and-suspenders against
    //    a fail-open regression: if the runner has Netns mode but
    //    landed in the host netns, the systemd unit was misjoined
    //    and we abort the action. The runner's PID is read from
    //    Service.MainPID via `systemd.get_unit_property`.
    if matches!(
        spec.network.as_ref().map(|n| &n.spec.mode),
        Some(NetworkMode::Netns)
    ) {
        verify_runner_netns(&unit_name, deps.systemd)?;
    }

    Ok(ApplyOutcome::Created)
}

pub(super) fn execute_remove_runner(
    identity: &RunnerIdentity,
    deps: &Deps<'_>,
    paths: &Paths,
    log: &mut UndoLog,
) -> Result<ApplyOutcome> {
    let unit_name = format!("ghars-runner@{}.service", identity.name);
    let runner_home = paths.runner_home(&identity.trust_zone, &identity.name);

    // 1) Stop the unit. systemd's StopUnit is idempotent — non-running
    //    units accept Stop with a no-op outcome.
    deps.systemd.stop_unit(&unit_name)?;
    log.push(UndoStep::StopUnit {
        name: unit_name.clone(),
    });
    deps.systemd.disable_unit(&unit_name)?;
    log.push(UndoStep::DisableUnit {
        name: unit_name.clone(),
    });

    // 1b) Tear down the per-runner netns side-units. Safe to call even
    //     for non-netns runners — `teardown_netns_artifacts` no-ops on
    //     missing files, and stop/disable on a non-existent
    //     `ghars-net@INSTANCE.service` is a systemd-side no-op.
    //     RemoveRunner does not carry the original NetworkSpec, so the
    //     teardown is unconditional rather than mode-gated.
    teardown_netns_artifacts(&identity.name, deps, paths, log)?;

    // 2) Mint a removal token + invoke `config.sh remove` so GitHub
    //    deregisters the runner. RealConfigShell::run_remove tolerates
    //    "already removed" exit codes.
    //
    //    Orphan branch: when plan.rs synthesises a RemoveRunner from
    //    `actual.orphans`, `identity.auth_name` and `identity.url` are
    //    empty (the orphan synthesis loop in `plan_from`) because the
    //    orphan has no [[runner]] block in the desired config and
    //    discovery doesn't reach the auth registry. Without those,
    //    `mint_token` would error with
    //    `auth source "" referenced by runner is not in the registry`
    //    and the local cleanup (unit + state dir) would never run —
    //    leaving the host in a permanently-orphaned state.
    //
    //    Skipping the deregister step is the intentional trade-off
    //    (documented in plan.rs orphan handling): the runner stays
    //    registered server-side until the operator either reinstates
    //    its [[runner]] block (so a future apply has full identity)
    //    or removes it via the GitHub UI / API. The host-local artifacts
    //    are still cleaned up below.
    if identity.auth_name.is_empty() || identity.url.is_empty() {
        tracing::warn!(
            runner = %identity.name,
            "orphan RemoveRunner: skipping config.sh remove + GitHub deregister; \
             auth_name/url were not in the desired config. The runner will remain \
             registered server-side; remove it via the GitHub UI or restore its \
             [[runner]] block to enable a clean deregister on the next apply."
        );
    } else {
        let token = mint_token(deps.auth, &identity.auth_name, &identity.url, true)?;
        // Best-effort deregister: tolerate missing bin dir (stale
        // runner from a failed apply) and config.sh remove failure
        // (runner already deleted from GitHub UI). The host-local
        // cleanup below runs regardless.
        match find_active_bin_dir(&runner_home) {
            Ok(remove_bin_dir) => {
                if let Err(e) = deps.config_shell.run_remove(&ConfigShellCtx {
                    runner_home: &runner_home,
                    bin_dir: &remove_bin_dir,
                    name: &identity.name,
                    url: &identity.url,
                    labels: &[],
                    token: &token.value,
                }) {
                    tracing::warn!(
                        runner = %identity.name,
                        error = %e,
                        "config.sh remove failed; runner may already be \
                         deregistered on GitHub. Continuing with local cleanup."
                    );
                }
            }
            Err(e) => {
                tracing::warn!(
                    runner = %identity.name,
                    error = %e,
                    "no bin dir with config.sh found; skipping GitHub \
                     deregister. Runner may still be registered server-side."
                );
            }
        }
        // No UndoStep for run_remove: it is itself the inverse of
        // GitHubRegistration. Recording GitHubRegistration here would
        // attempt to re-register on rollback — wrong semantically and
        // not recoverable (config.sh register requires a fresh token
        // mint and recreates credentials, which the upstream Remove
        // path just intentionally tore down). The operator restores
        // the runner by reinstating its [[runner]] block + apply.
    }

    // 3) Remove unit + drop-ins.
    let unit_path = paths.unit_file(&identity.name);
    if unit_path.exists() {
        let prior = read_prior(&unit_path);
        fs::remove_file(unit_path.as_std_path())?;
        if let Some(content) = prior {
            log.push(UndoStep::RemoveFile {
                path: unit_path.clone(),
                content,
            });
        }
    }
    let drop_in_dir = paths.drop_in_dir(&identity.name);
    if drop_in_dir.exists() {
        fs::remove_dir_all(drop_in_dir.as_std_path())?;
        log.push(UndoStep::RemoveDir {
            path: drop_in_dir.clone(),
        });
    }

    // 4) Remove the runner home directory after the rmrf safety check.
    if runner_home.exists() {
        let trust_zone_root = paths.trust_zone_home(&identity.trust_zone);
        guard_home_dir_rmrf(
            &runner_home,
            &trust_zone_root,
            &format!("ghars-{}", identity.name),
        )?;
        fs::remove_dir_all(runner_home.as_std_path())?;
        log.push(UndoStep::RemoveDir {
            path: runner_home.clone(),
        });
    }

    // No userdel step. The runner unit's DynamicUser-allocated UID is
    // released by systemd on unit stop; nothing was written to
    // /etc/passwd / /etc/group, so there is nothing to clean up.

    // The end-of-apply daemon_reload picks up the unit file removal.
    Ok(ApplyOutcome::Removed)
}

pub(super) fn execute_update_runner(
    delta: &RunnerDelta,
    deps: &Deps<'_>,
    paths: &Paths,
    log: &mut UndoLog,
    keep_versions: u32,
) -> Result<ApplyOutcome> {
    if delta.requires_recreate {
        // Recreate path: stop + remove + create. The plan emits this
        // when an identity-bound field changed (url, runner_version,
        // labels, arch, runner_sha256, runner_tarball, network).
        //
        // The undo log threading here propagates BOTH inner calls'
        // pushes. If create fails partway, undo walks: create's pushes
        // (reverse, lossless), then remove's pushes (reverse-direction
        // variants → warn-and-skip per design). Net effect on
        // recreate-rollback: the partial new state is unwound; the old
        // state stays gone (genuinely lossy — re-running apply is the
        // recovery path).
        //
        // Collapse the inner Removed + Created outcomes into
        // a single `Recreated` — the user-facing contract is one row
        // per `Action`, and the inner remove+create are
        // implementation detail of the recreate path.
        execute_remove_runner(&delta.identity, deps, paths, log)?;
        execute_create_runner(&delta.after, deps, paths, log, keep_versions)?;
        return Ok(ApplyOutcome::Recreated);
    }

    // In-place path: rewrite drop-ins (template body unchanged because
    // it is identical across runners) and let the next daemon-reload
    // pick them up. Restart only when a Service-section value changed
    // — `RunnerDelta` does not yet distinguish [Service] from [Unit]
    // drift, so to avoid spurious restarts we skip the daemon-reload +
    // stop + start when (a) every managed file's on-disk bytes match
    // what we would render and (b) the caches-list diff is empty.
    // The byte comparison reuses `read_prior` snapshots that were
    // already needed for rollback.
    // Track files_changed (count) and pool names
    // (Vec) so the apply outcome row can carry both `files_changed`
    // and the WHICH-pools detail for cmd_apply's per-action line.
    // The `is_empty()` checks at the daemon-reload gate below
    // preserve the short-circuit semantics ("skip rewrite when bytes
    // match"): the gate fires iff `files_changed == 0` AND both
    // pool Vecs are empty. The public-detail "group op(s)" count
    // is `pools_added.len() + pools_removed.len()` at render time
    // — operator-visible vocabulary is retained for compatibility
    // with existing log scrapes; no system-level group operation
    // is dispatched.
    let mut files_changed: usize = 0;
    let mut pools_added: Vec<String> = Vec::new();
    let mut pools_removed: Vec<String> = Vec::new();

    // Compute the caches-list diff for the operator-facing
    // "added: …; removed: …" detail string.
    //
    // No system-level group reconciliation runs here. Cache reach
    // is materialized by socket-DAC + BindPaths under DynamicUser
    // (cache server runs at the same trust_zone DynamicUser as the
    // runner), not by /etc/group membership. The set diff below
    // captures `pools_added` / `pools_removed` purely for the
    // detail surface ("runner X gained pool Y / lost pool Z");
    // the runner unit's 30-cache-pool.conf drop-in (re-rendered
    // below) carries the BindPaths entries that actually grant
    // pool access.
    //
    // The diff is computed from the discovered `X-Ghars-Caches`
    // annotation (`delta.before_caches`) against the desired
    // post-update binding list (`delta.after.spec.caches`). When
    // the discovered annotation is absent (`None`) — pre-annotation
    // runner or operator-stripped 00-ghars.conf — we skip the diff
    // entirely rather than guess at the prior membership; the next
    // apply will land annotations and a future caches-list edit
    // can reconcile from a known baseline.
    if let Some(before) = delta.before_caches.as_ref() {
        let after_set: std::collections::BTreeSet<&str> = delta
            .after
            .spec
            .caches
            .iter()
            .map(|b| b.name.as_str())
            .collect();
        let before_set: std::collections::BTreeSet<&str> =
            before.iter().map(String::as_str).collect();
        // Sort by collecting into BTreeSet first so the operations
        // run in deterministic alphabetical order — easier for tests
        // and for operator log readability.
        for added in after_set.difference(&before_set) {
            // Capture the pool NAME for operator-facing detail surface.
            pools_added.push((*added).to_string());
        }
        for removed in before_set.difference(&after_set) {
            pools_removed.push((*removed).to_string());
        }
    }

    // Write managed unit text (this block) and drop-ins (loop
    // further down). The 00-ghars.conf X-Ghars-Caches annotation
    // lives in the drop-in body written by the `for (name, body)
    // in &delta.after.drop_ins` loop, NOT in the systemd template
    // body written here.
    let unit_file = paths.unit_file(&delta.identity.name);
    if read_then_write_if_changed(&unit_file, delta.after.effective_unit_text.as_bytes(), log)? {
        files_changed += 1;
    }
    let drop_in_dir = paths.drop_in_dir(&delta.identity.name);
    let drop_in_dir_existed = drop_in_dir.exists();
    fs::create_dir_all(drop_in_dir.as_std_path())?;
    if !drop_in_dir_existed {
        log.push(UndoStep::CreateDir {
            path: drop_in_dir.clone(),
        });
        // CreateDir is itself a filesystem mutation — count it as a
        // change so the daemon-reload + restart still fires the first
        // time we plant a runner's drop-in directory, even on a runner
        // whose drop-in basenames all happen to byte-match a prior
        // hand-edit (vanishingly unlikely but cheap to be correct).
        files_changed += 1;
    }
    // Remove ghars-managed drop-ins flagged DropInChangeKind::Removed
    // by Stage 2 (rendered side has no entry, on-disk side does).
    // Stage 2 walks the union of rendered + discovered keys, so
    // operator-edited 99-*.conf and any other non-managed name CAN
    // appear here as Removed entries. The MANAGED_DROP_IN_BASENAMES
    // guard below is the load-bearing safety mechanism that keeps
    // `systemctl edit` overrides intact: we only delete basenames
    // ghars itself would emit. Anything else is operator territory
    // and is left untouched, even when Stage 2 classifies it as
    // Removed.
    for change in &delta.drop_in_changes {
        if let DropInChangeKind::Removed { .. } = &change.change {
            if !MANAGED_DROP_IN_BASENAMES.contains(&change.basename.as_str()) {
                continue;
            }
            let path = drop_in_dir.join(&change.basename);
            let prior = read_prior(&path);
            // Differentiate "file is missing" (ENOENT — already
            // removed, treat as no-op success) from any other I/O
            // failure (EACCES on read-only mount, EBUSY on a held
            // descriptor, EROFS, etc. — the file is still present
            // and the convergence target was NOT reached). The
            // pre-fix `is_ok()` collapsed every Err into a silent
            // skip, so a real EACCES would let `apply` claim
            // success while leaving the stale drop-in on disk.
            match fs::remove_file(path.as_std_path()) {
                Ok(()) => {
                    if let Some(content) = prior {
                        log.push(UndoStep::RemoveFile { path, content });
                    }
                    files_changed += 1;
                }
                Err(e) if e.kind() == std::io::ErrorKind::NotFound => {
                    // Already gone — operator concurrently removed
                    // or Stage 2 saw a race. Convergence target is
                    // satisfied, no UndoStep to push (nothing to
                    // restore), no files_changed bump (we did NOT
                    // mutate disk this apply).
                }
                Err(e) => return Err(GharsError::Io(e)),
            }
        }
    }
    // Write each desired drop-in. `read_then_write_if_changed` snapshots
    // the on-disk prior and short-circuits when the bytes already match
    // The Preserved Stage 2 verdict is not used as an
    // optimization here: it is plan-time, and on-disk bytes can drift
    // between plan and apply (e.g. operator edit landed after `ghars
    // plan` rendered output). Trusting Preserved would preserve that
    // drift instead of converging — the byte comparison inside
    // `read_then_write_if_changed` is the authoritative check and runs
    // every time.
    for (name, body) in &delta.after.drop_ins {
        let dest = drop_in_dir.join(name);
        if read_then_write_if_changed(&dest, body.as_bytes(), log)? {
            files_changed += 1;
        }
    }

    // Rewrite .env and .path. CreateRunner writes them once, but
    // in-place updates that change env-affecting fields (cache binding
    // flip, future operator-declared env vars) would otherwise leave
    // the systemd Environment= directives (rewritten in the drop-in
    // loop above; LAYER 1, reaches the Runner.Listener process) and
    // the workflow-step env (via Runner.Listener's LoadAndSetEnv at
    // process start, which reads .env once; LAYER 2) out of sync.
    //
    // The pure-function producers `render_runner_env_file` and
    // `render_runner_path_file` consume only EffectiveRunnerSpec
    // fields (no runner_version), so the bytes here are byte-identical
    // to what CreateRunner wrote for the same spec. The byte-compare
    // in read_then_write_if_changed makes this a no-op when nothing
    // changed.
    //
    // bin_dir is computed from delta.after.spec.runner_version
    // directly rather than find_active_bin_dir's lex-sort: in-place
    // updates never change runner_version (that's a recreate-class
    // field), so the running runner's bin dir matches the desired
    // spec's version. An empty runner_version here means plan emitted
    // a malformed in-place delta — fail loudly rather than silently
    // skip the .env/.path rewrite.
    let runner_home = paths.runner_home(&delta.identity.trust_zone, &delta.identity.name);
    let version = delta.after.spec.runner_version.as_deref().ok_or_else(|| GharsError::Apply {
        action: format!("UpdateRunner({}): rewrite .env/.path", delta.identity.name),
        source: Box::new(GharsError::Validation(
            "in-place delta missing runner_version; cannot locate bin dir for .env/.path rewrite".into(),
            format!(
                "the runner's 00-ghars.conf is missing the X-Ghars-Effective-Version \
                 annotation (operator-stripped, pre-annotation legacy runner, or invalid \
                 value). Fix by: (a) set `runner_version = \"X.Y.Z\"` in ghars.toml to \
                 match the installed version (check with \
                 `ls /var/lib/ghars/<TRUST_ZONE>/ghars-{name}/bin.*`), OR (b) remove the \
                 runner from ghars.toml and re-add it so a fresh CreateRunner re-fetches \
                 the latest release from the GitHub API",
                name = delta.identity.name,
            ),
        )),
    })?;
    let bin_dir = runner_home.join(format!("bin.{version}"));
    if read_then_write_if_changed(
        &bin_dir.join(".path"),
        delta.after.path_file.as_bytes(),
        log,
    )? {
        files_changed += 1;
    }
    if read_then_write_if_changed(
        &bin_dir.join(".env"),
        delta.after.env_file.as_bytes(),
        log,
    )? {
        files_changed += 1;
    }

    // Skip daemon-reload + stop + start when nothing on disk
    // changed AND the caches-list diff was empty. A non-empty
    // pools_added/pools_removed implies the 30-cache-pool.conf
    // drop-in was re-rendered (its body changed when bindings
    // changed), so files_changed > 0 in that case — but the
    // pool-Vec checks below stay as belt-and-suspenders so a
    // future code path that records pool changes without
    // re-rendering can't slip past the restart gate.
    // verify_runner_netns runs only when we actually start the
    // unit; otherwise the prior PID is still in the netns we
    // already verified on the last apply.
    if files_changed == 0 && pools_added.is_empty() && pools_removed.is_empty() {
        tracing::info!(
            runner = delta.identity.name.as_str(),
            "in-place: all managed bytes match on disk and caches list is unchanged; skipping daemon-reload + restart"
        );
        return Ok(ApplyOutcome::InPlaceSkipped);
    }
    let unit_name = format!("ghars-runner@{}.service", delta.identity.name);
    deps.systemd.daemon_reload()?;
    // Restart by stop+start; systemd has no atomic "restart" D-Bus
    // method via `Manager` (RestartUnit exists but is implemented as
    // stop+start internally). Use stop_unit/start_unit which are part
    // of the trait surface.
    deps.systemd.stop_unit(&unit_name)?;
    log.push(UndoStep::StopUnit {
        name: unit_name.clone(),
    });
    deps.systemd.start_unit(&unit_name)?;
    log.push(UndoStep::StartUnit {
        name: unit_name.clone(),
    });
    if matches!(
        delta.after.spec.network.as_ref().map(|n| &n.spec.mode),
        Some(NetworkMode::Netns)
    ) {
        verify_runner_netns(&unit_name, deps.systemd)?;
    }
    Ok(ApplyOutcome::InPlaceRestarted {
        files_changed,
        pools_added,
        pools_removed,
    })
}
