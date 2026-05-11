//! Per-runner action handlers: create / remove / update (in-place + recreate).

use std::fs;

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
use super::tarball::sha256_of_runsvc;
use super::undo::{Deps, UndoLog, UndoStep};
use super::writes::{mint_token, read_prior, read_then_write_if_changed, write_record_undo};
use camino::Utf8PathBuf;

/// Find runsvc.sh inside the extracted bin directory. The runner
/// tarball may place it at the root (`bin_dir/runsvc.sh`) or inside
/// the bin subdirectory (`bin_dir/bin/runsvc.sh`).
fn find_runsvc_sh(bin_dir: &camino::Utf8Path) -> crate::Result<Utf8PathBuf> {
    for candidate in &["runsvc.sh", "bin/runsvc.sh"] {
        let path = bin_dir.join(candidate);
        if path.as_std_path().exists() {
            return Ok(path);
        }
    }
    Err(GharsError::Apply {
        action: format!("find runsvc.sh under {bin_dir}"),
        source: Box::new(GharsError::Io(std::io::Error::new(
            std::io::ErrorKind::NotFound,
            format!("no runsvc.sh found under {bin_dir} or {bin_dir}/bin/"),
        ))),
    })
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

    // Clean up stale DynamicUser symlinks from previous runs.
    let home_std = runner_home.as_std_path();
    if let Ok(meta) = fs::symlink_metadata(home_std) {
        if meta.file_type().is_symlink() {
            let _ = fs::remove_file(home_std);
        }
    }
    fs::create_dir_all(home_std)?;

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
        let version = spec
            .runner_version
            .clone()
            .unwrap_or_else(|| "local".into());
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

    // 5b) SEC-02: hash the runsvc.sh that `config.sh` wrote into the
    //     runner home. config.sh (the upstream actions/runner script)
    //     materialises runsvc.sh + .runner + .credentials in $HOME at
    //     register time — NOT during `install_runner_binary`, which
    //     only lays down `bin.X.Y.Z/`. We
    //     hash AFTER run_register so the path actually exists.
    //
    //     The hash flows into a freshly-rendered 00-ghars.conf via the
    //     `[Service] X-Ghars-Runsvc-Sha256=` annotation; the
    //     runsvc-wrapper trampoline reads that annotation at every unit
    //     start and refuses to exec a runsvc.sh whose contents have
    //     changed (closing the SEC-02 persistent-RCE-on-restart hole).
    //
    //     The plan's `drop_ins` and `effective_unit_text` are
    //     placeholders (plan ran before install, so it could not
    //     compute the digest). We re-render here with the populated
    //     spec.
    // config.sh / the tarball places runsvc.sh somewhere under bin_dir.
    // Find it, then copy to runner_home/runsvc.sh where the
    // runsvc-wrapper expects it at runtime (O_NOFOLLOW -- no symlinks).
    let runsvc_source = find_runsvc_sh(&bin_dir)?;
    let runsvc_path = runner_home.join("runsvc.sh");
    fs::copy(runsvc_source.as_std_path(), runsvc_path.as_std_path())?;
    let runsvc_sha = sha256_of_runsvc(&runsvc_path).map_err(|e| GharsError::Apply {
        action: format!("CreateRunner({}): hash runsvc.sh", spec.name),
        source: Box::new(e),
    })?;
    let mut populated_spec = spec.clone();
    populated_spec.runsvc_sha256 = runsvc_sha;
    // Set runner_version from the resolved release so the rendered
    // WorkingDirectory points at the correct bin.X.Y.Z/ directory.
    if populated_spec.runner_version.is_none() {
        if let Some(ref release) = plan.resolved_release {
            populated_spec.runner_version = Some(release.version.clone());
        }
    }
    let rendered = render_runner_unit(&populated_spec)?;

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
    //
    // When delta.after.spec.runsvc_sha256 is empty here, plan was
    // unable to recover the digest from the discovered 00-ghars.conf
    // (annotation missing → older-format runner or operator stripped
    // the line). Plan must have routed THIS update through the recreate
    // path with the `runsvc_integrity` reason rather than down here;
    // hashing runsvc.sh from disk in apply would weaken SEC-02 because
    // that file lives in the runner-writable home and may be
    // adversary-controlled. If we still see an empty digest at this
    // point, plan emitted a malformed in-place delta — we must NOT
    // silently strip the annotation, so error out and force the
    // operator to investigate.
    if delta.after.spec.runsvc_sha256.is_empty() {
        return Err(GharsError::Apply {
            action: format!(
                "UpdateRunner({}): in-place delta missing runsvc_sha256",
                delta.identity.name
            ),
            source: Box::new(GharsError::Validation(
                "plan-time runsvc_sha256 recovery failed; the recreate \
                 path is required to mint a fresh trusted digest via \
                 config.sh"
                    .into(),
                "re-run `ghars plan` to refresh; if the issue persists, \
                 the discovered 00-ghars.conf is missing X-Ghars-Runsvc-\
                 Sha256 and plan should have emitted a recreate"
                    .into(),
            )),
        });
    }
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
