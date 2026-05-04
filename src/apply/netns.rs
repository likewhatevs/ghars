//! Per-runner netns side-unit provisioning + post-start verification.
//!
//! `provision_netns_artifacts` writes the netns config TOML, nft
//! rules, and `ghars-net@.service` template, then enables + starts
//! `ghars-net@INSTANCE.service` BEFORE the runner unit so the runner's
//! `NetworkNamespacePath=` join succeeds.
//!
//! `verify_runner_netns` is a post-start belt-and-suspenders check:
//! `readlink /proc/PID/ns/net` must differ from PID 1's; if they
//! match, the unit fell back to the host netns and the action aborts.

use std::fs;

use crate::Result;
use crate::config::{EffectiveRunnerSpec, NetworkMode};
use crate::error::GharsError;
use crate::netns::NetnsConfig;
use crate::paths::Paths;
use crate::systemd::{Systemd, netns_template_text, render_nft_rules};

use super::undo::{Deps, UndoLog, UndoStep};
use super::writes::{read_prior, write_record_undo, write_root_owned};

/// Provision the netns side-units for a Netns-mode runner. Called from
/// `execute_create_runner` BEFORE the runner unit is started, because
/// the runner's drop-in has `Requires=ghars-net@%i.service` and joins
/// the netns via `NetworkNamespacePath=/var/run/netns/ghars-%i` — which
/// fails-closed if the netns is missing.
///
/// Steps (Part 9c "Lifecycle — apply CreateRunner"):
/// 1. Write `<config_dir>/netns.d/<name>.toml` (`NetnsConfig`) so the
///    `_netns-setup` helper can read subnet + dns mode at unit start.
/// 2. Write `<config_dir>/nft.d/<name>-host.nft` and `<name>-ns.nft`
///    via `systemd::render_nft_rules`.
/// 3. Write `<unit_dir>/ghars-net@.service` (template) — idempotent;
///    every netns runner shares the same template body.
/// 4. `daemon-reload` so the template is visible, then `enable` +
///    `start` `ghars-net@<name>.service`. The netns unit's ExecStart
///    runs `_netns-setup` which builds the kernel-level state.
///
/// On any step failure the kernel-level state is left for
/// [`teardown_netns_artifacts`] to clean up via the runner's
/// RemoveRunner action; we do not roll back here because partial
/// writes are idempotent (next apply re-runs them).
///
/// # Errors
///
/// Returns the underlying `GharsError` from `systemd::render_nft_rules`,
/// `NetnsConfig::write`, `write_root_owned`, or systemd D-Bus calls.
pub(super) fn provision_netns_artifacts(
    spec: &EffectiveRunnerSpec,
    deps: &Deps<'_>,
    paths: &Paths,
    log: &mut UndoLog,
) -> Result<()> {
    let Some(binding) = spec.network.as_ref() else {
        return Ok(());
    };
    if !matches!(binding.spec.mode, NetworkMode::Netns) {
        return Ok(());
    }

    // 1) Per-instance netns config (subnet + dns mode) read by
    //    `ghars _netns-setup INSTANCE`.
    let netns_cfg = NetnsConfig {
        subnet: binding.subnet,
        dns: binding.spec.dns.clone(),
    };
    let netns_cfg_path = NetnsConfig::path_for(paths, &spec.name);
    let netns_cfg_prior = read_prior(&netns_cfg_path);
    netns_cfg.write(paths, &spec.name)?;
    log.push(UndoStep::WriteFile {
        path: netns_cfg_path,
        prior_content: netns_cfg_prior,
    });

    // 2) nft rule files referenced by the netns template's ExecStart=.
    let nft = render_nft_rules(&spec.name, binding)?;
    let host_rule_path = paths.nft_host_rule(&spec.name);
    write_record_undo(&host_rule_path, nft.host_rules.as_bytes(), log)?;
    let ns_rule_path = paths.nft_ns_rule(&spec.name);
    write_record_undo(&ns_rule_path, nft.ns_rules.as_bytes(), log)?;

    // 3) ghars-net@.service template. Identical bytes for every netns
    //    runner — idempotent rewrite restores a hand-edited template.
    //    NOT recorded as an UndoStep: the template is shared across
    //    every netns-mode runner, so undoing the write would unlink
    //    a file other live runners still depend on. The forward path
    //    is byte-idempotent (every netns runner writes the same
    //    bytes) so leaving it on rollback matches the next clean apply.
    write_root_owned(
        &paths.netns_template_unit_file(),
        netns_template_text().as_bytes(),
    )?;

    // 4) daemon-reload + enable + start ghars-net@INSTANCE so the
    //    runner unit's `Requires=ghars-net@%i.service` is satisfied
    //    when its own start_unit fires below.
    let netns_unit = format!("ghars-net@{}.service", spec.name);
    deps.systemd.daemon_reload()?;
    deps.systemd.enable_unit(&netns_unit)?;
    log.push(UndoStep::EnableUnit {
        name: netns_unit.clone(),
    });
    deps.systemd.start_unit(&netns_unit)?;
    log.push(UndoStep::StartUnit {
        name: netns_unit.clone(),
    });

    Ok(())
}

/// Tear down the netns side-units for a Netns-mode runner. Called from
/// `execute_remove_runner` AFTER the runner unit has been stopped (so
/// the netns is no longer in use) and BEFORE the unit-files are
/// deleted. Mirrors [`provision_netns_artifacts`] in reverse.
///
/// Idempotent: missing files / inactive units do not fail. The
/// `ghars-net@.service` template at `<unit_dir>/ghars-net@.service` is
/// NOT removed — other Netns runners may still reference it. (The
/// template is operator-visible, distinct from the per-runner
/// instance.)
///
/// # Errors
///
/// Returns the underlying `GharsError` from systemd D-Bus calls,
/// filesystem unlink, or `NetnsConfig::remove`.
pub(super) fn teardown_netns_artifacts(
    name: &str,
    deps: &Deps<'_>,
    paths: &Paths,
    log: &mut UndoLog,
) -> Result<()> {
    let netns_unit = format!("ghars-net@{name}.service");

    // 1) Stop + disable. systemd's StopUnit and DisableUnitFiles are
    //    idempotent at the D-Bus level — calling them on an inactive
    //    unit or one without an enable symlink succeeds with a no-op
    //    outcome. The trait propagates any D-Bus error verbatim via
    //    map_err; teardown only relies on the kernel-level no-op
    //    semantics, not on apply.rs swallowing error kinds.
    deps.systemd.stop_unit(&netns_unit)?;
    log.push(UndoStep::StopUnit {
        name: netns_unit.clone(),
    });
    deps.systemd.disable_unit(&netns_unit)?;
    log.push(UndoStep::DisableUnit {
        name: netns_unit.clone(),
    });

    // 2) Remove nft rule files. Missing-file is OK because a partial
    //    prior provisioning may have skipped them.
    let host_rule = paths.nft_host_rule(name);
    if host_rule.exists() {
        let prior = read_prior(&host_rule);
        fs::remove_file(host_rule.as_std_path())?;
        if let Some(content) = prior {
            log.push(UndoStep::RemoveFile {
                path: host_rule.clone(),
                content,
            });
        }
    }
    let ns_rule = paths.nft_ns_rule(name);
    if ns_rule.exists() {
        let prior = read_prior(&ns_rule);
        fs::remove_file(ns_rule.as_std_path())?;
        if let Some(content) = prior {
            log.push(UndoStep::RemoveFile {
                path: ns_rule.clone(),
                content,
            });
        }
    }

    // 3) Remove per-instance netns config TOML. Absent file is OK
    //    (NetnsConfig::remove swallows ENOENT).
    let netns_cfg_path = NetnsConfig::path_for(paths, name);
    let netns_prior = read_prior(&netns_cfg_path);
    NetnsConfig::remove(paths, name)?;
    if let Some(content) = netns_prior {
        log.push(UndoStep::RemoveFile {
            path: netns_cfg_path,
            content,
        });
    }

    Ok(())
}

/// Compare `readlink /proc/PID/ns/net` against `/proc/1/ns/net` for the
/// given runner unit. The `MainPID` D-Bus property carries the runner's
/// PID; if the symlink target matches PID 1's, the runner has fallen
/// back to the host network namespace and the action aborts as a
/// belt-and-suspenders defense against a netns fail-open regression.
///
/// The kernel-side netns join races MainPID's recording. systemd
/// calls service_set_main_pidref the moment exec_spawn returns the
/// child PID — which is post-vfork-unblock, but BEFORE
/// systemd-executor reaches the setup_namespace step that calls
/// setns(CLONE_NEWNET) for NetworkNamespacePath=. The send_handoff
/// timestamp only fires "as last thing before the execve()", AFTER
/// setup_namespace. So a readlink at the moment
/// StartUnit returns can observe the still-host netns symlink for the
/// runner's PID and false-positive a netns fail-open.
///
/// Mitigation: poll-with-timeout. 5s deadline at 100ms cadence (50
/// attempts max) — short enough that legitimate setup completes well
/// inside the budget (the kernel join lands within the systemd-executor
/// exec window, microseconds-to-milliseconds), but long enough to
/// cover D-Bus round-trip jitter + a stuck systemd-executor that's
/// blocked on something unrelated. ENOENT on /proc/PID/ns/net is a
/// TRANSIENT condition (the PID is briefly visible to systemd before
/// /proc reflects the entry, or the PID was recycled mid-poll); we
/// retry on ENOENT, NOT treat it as success.
///
/// v0.2 optimization: switch to
/// `ExecMainHandoffTimestampMonotonic` D-Bus property — non-zero means
/// systemd-executor reached send_handoff_timestamp, which is post-
/// setup_namespace, eliminating the poll. v0.1 ships the simple loop.
const NETNS_VERIFY_DEADLINE: std::time::Duration = std::time::Duration::from_secs(5);
const NETNS_VERIFY_BACKOFF: std::time::Duration = std::time::Duration::from_millis(100);

pub(super) fn verify_runner_netns(unit_name: &str, systemd: &dyn Systemd) -> Result<()> {
    verify_runner_netns_at(
        std::path::Path::new("/proc"),
        unit_name,
        systemd,
        NETNS_VERIFY_DEADLINE,
        NETNS_VERIFY_BACKOFF,
    )
}

/// `verify_runner_netns` with injectable `proc_root` + deadline + backoff.
/// Tests pass a synthesized tempdir layout
/// (`<root>/<pid>/ns/net` symlink + `<root>/1/ns/net` symlink), a
/// shortened deadline, AND a shortened backoff so the happy path
/// (distinct symlink targets) and fail path (matching symlink targets)
/// can be exercised quickly without running a real netns'd unit.
/// Production calls always pass `/proc`, `NETNS_VERIFY_DEADLINE`, and
/// `NETNS_VERIFY_BACKOFF`.
pub(super) fn verify_runner_netns_at(
    proc_root: &std::path::Path,
    unit_name: &str,
    systemd: &dyn Systemd,
    deadline_dur: std::time::Duration,
    backoff: std::time::Duration,
) -> Result<()> {
    // Host PID 1's net ns symlink is constant for the lifetime of the
    // booted system; cache it across retry attempts but defer the
    // initial read until AFTER the MainPID validation: a bogus MainPID
    // is an upstream systemd / unit-start failure that we want to
    // surface with its specific message, and the host readlink is
    // unrelated to that branch (it would also fail in the same way at
    // production runtime if /proc/1/ns/net were genuinely missing,
    // which only occurs when /proc isn't mounted).
    let deadline = std::time::Instant::now() + deadline_dur;
    let mut host_target: Option<std::path::PathBuf> = None;
    let mut last_match: Option<(u32, std::path::PathBuf)> = None;
    let mut attempts: u32 = 0;
    loop {
        attempts += 1;
        let main_pid_u64 = systemd
            .get_service_property_u64(unit_name, "MainPID")
            .map_err(|e| GharsError::Apply {
                action: format!("verify_runner_netns({unit_name})"),
                source: Box::new(e),
            })?;
        let pid = u32::try_from(main_pid_u64).map_err(|e| {
            GharsError::Systemd(
                format!(
                    "verify_runner_netns({unit_name}): MainPID {main_pid_u64} does not fit in u32: {e}"
                ),
                "the unit may have failed to start; inspect `systemctl status` and the journal"
                    .into(),
            )
        })?;
        if pid == 0 {
            return Err(GharsError::Systemd(
                format!("verify_runner_netns({unit_name}): MainPID is 0 (unit not running)"),
                "the runner unit failed to start; check `systemctl status`".into(),
            ));
        }
        // Lazy host_target read: populate on first iteration only, then
        // reuse the cached PathBuf for every subsequent attempt.
        let host_target_ref = if let Some(ref h) = host_target {
            h.clone()
        } else {
            let host_path = proc_root.join("1").join("ns").join("net");
            let h = std::fs::read_link(&host_path).map_err(|e| GharsError::Apply {
                action: format!("verify_runner_netns({unit_name})"),
                source: Box::new(GharsError::Io(e)),
            })?;
            host_target = Some(h.clone());
            h
        };
        let runner_path = proc_root.join(pid.to_string()).join("ns").join("net");
        match std::fs::read_link(&runner_path) {
            Ok(runner_target) => {
                if runner_target != host_target_ref {
                    return Ok(());
                }
                last_match = Some((pid, runner_target));
            }
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => {
                // ENOENT on /proc/PID/ns/net is TRANSIENT, NOT success.
                // The PID was just exec'd: systemd recorded it via
                // service_set_main_pidref before the kernel made the
                // /proc entry visible, or the PID was reaped between
                // the get_unit_property call and the readlink. Either
                // way, retry — never count missing /proc/PID as
                // "the runner is in an isolated netns" (that would be
                // a fail-open). Don't update last_match: a transient
                // ENOENT is not evidence of host-netns occupancy and
                // should not poison the retry-exhaustion error message
                // with a stale runner_target.
            }
            Err(e) => {
                return Err(GharsError::Apply {
                    action: format!("verify_runner_netns({unit_name})"),
                    source: Box::new(GharsError::Io(e)),
                });
            }
        }
        if std::time::Instant::now() + backoff > deadline {
            break;
        }
        std::thread::sleep(backoff);
    }
    let (pid, runner_target) = last_match.ok_or_else(|| {
        // No iteration produced a (pid, runner_target) — either every
        // attempt hit transient ENOENT (so we never observed the
        // runner's netns), or the deadline elapsed before a single
        // readlink succeeded. Treat as Systemd error: the unit is
        // not progressing through start_post → running.
        GharsError::Systemd(
            format!(
                "verify_runner_netns({unit_name}): /proc/PID/ns/net never resolved \
                 within {deadline_ms}ms ({attempts} polls); systemd-executor's \
                 setup_namespace did not complete",
                deadline_ms = deadline_dur.as_millis(),
            ),
            "the runner unit failed to reach the post-netns-join state; \
             check `systemctl status` and the journal for execve errors"
                .into(),
        )
    })?;
    Err(GharsError::Apply {
        action: format!("verify_runner_netns({unit_name})"),
        source: Box::new(GharsError::Validation(
            format!(
                "runner PID {pid} is in the HOST network namespace (target {target}) \
                 after {attempts} polls (~{total_ms}ms); expected an isolated netns. \
                 NetworkNamespacePath= silently fell open.",
                target = runner_target.display(),
                total_ms = deadline_dur.as_millis(),
            ),
            "this is a netns fail-closed regression; check ghars-net@%i.service status \
             and `ip netns list` for the expected named netns"
                .into(),
        )),
    })
}
