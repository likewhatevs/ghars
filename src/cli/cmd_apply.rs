//! `ghars apply` command handler + the interactive y/N prompt.

use std::io::{self, BufRead, IsTerminal, Write};

use camino::Utf8Path;

use crate::Result;
use crate::apply;
use crate::error::GharsError;
use crate::github;
use crate::paths::Paths;
use crate::plan::Action;
use crate::preflight;

use super::args::{ApplyArgs, ColorMode};
use super::cmd_plan::{compute_plan, open_dbus};
use super::exit_codes::{apply_exit_code, cancel_exit_code, dry_run_exit_code, recreate_exit_code};
use super::load::{build_auth_registry, load_config};
use super::render::{render_apply_emission, render_plan};

pub(super) fn cmd_apply(
    config_path: &Utf8Path,
    paths: &Paths,
    args: &ApplyArgs,
    color: ColorMode,
    quiet: bool,
) -> Result<i32> {
    // load_config runs the full post-load validator sweep
    // (validate_security_overrides, validate_identity_fields,
    // validate_no_duplicate_caches, validate_cache_pool_names,
    // validate_runner_names,
    // validate_runner_tarballs) so cmd_apply does not need to
    // repeat any of them — apply inherits the same gate every
    // other cmd_* enforces.
    let cfg = load_config(config_path)?;

    if args.dry_run {
        // `--dry-run` is documented as an alias for `ghars plan` (Part 5).
        // With `--detailed-exitcode`, `dry_run_exit_code` returns 2 when
        // the plan has any non-NoOp action — terraform parity.
        // With `--detailed-exitcode-recreate`, returns 8 when the plan
        // has any recreate-class action — recreate trumps detailed.
        // Threads `args.diff` so `apply --dry-run --diff` produces the
        // same body output as `plan --diff`.
        let plan = compute_plan(&cfg, paths, &args.only)?;
        render_plan(&plan, color, false, quiet, args.diff)?;
        return Ok(dry_run_exit_code(
            args.detailed_exitcode,
            args.detailed_exitcode_recreate,
            &plan,
        ));
    }

    // Apply gate: preflight must pass.
    if let Err(e) = preflight::run_preflight(false) {
        if !quiet {
            let _ = writeln!(io::stderr(), "{e}");
        }
        return Ok(3);
    }

    // Ensure runtime directories exist on fresh hosts.
    std::fs::create_dir_all(paths.runtime_dir.as_std_path())?;

    let mut plan = compute_plan(&cfg, paths, &args.only)?;

    if !quiet {
        // Pre-confirm preview honors --diff so the operator reads the
        // same body content the dry-run / plan outputs would print.
        render_plan(&plan, color, false, false, args.diff)?;
    }

    // Pre-confirm recreate gate. When `--detailed-exitcode-recreate`
    // is set and the plan contains a recreate-class action, exit 8 BEFORE
    // prompting (or auto-approving) — lets a CI workflow short-circuit
    // on recreate plans without spending a human y/N or running the
    // mutation phase. Pure plan-shape decision; no host state touched.
    // Fires regardless of `--auto-approve` so CI scripts see the same
    // signal whether or not stdin is a TTY.
    if let Some(code) = recreate_exit_code(args.detailed_exitcode_recreate, &plan) {
        return Ok(code);
    }

    if !args.auto_approve && !confirm_apply()? {
        if !quiet {
            // Status message goes to stderr so wrapping scripts
            // that capture stdout (e.g. for plan output) don't see it
            // mixed in with structured output. Unix convention:
            // diagnostics on stderr, data on stdout.
            let _ = writeln!(io::stderr(), "apply cancelled");
        }
        // Cancellation with --detailed-exitcode returns 2 ("changes
        // still pending" — terraform semantics), distinct from 0 ("plan
        // had no diff, no work needed"). Without --detailed-exitcode,
        // 0 preserves the established CLI convention that cancelling
        // an interactive prompt is a non-error.
        // Cancellation with --detailed-exitcode-recreate returns
        // 8 — but the pre-confirm gate above already short-circuits on
        // recreate plans, so this branch is effectively reached only
        // when the plan has no recreates. cancel_exit_code keeps the
        // recreate check for symmetry / defense-in-depth.
        return Ok(cancel_exit_code(
            args.detailed_exitcode,
            args.detailed_exitcode_recreate,
            &plan,
        ));
    }

    if args.detailed_exitcode && plan.actions.iter().all(|a| matches!(a, Action::NoOp(_))) {
        return Ok(0);
    }

    // Reconcile NoOp runners against GitHub: if a runner is "in sync"
    // on disk but was deleted from GitHub's UI, wipe its on-disk state
    // and re-plan so apply sees CreateRunner instead of NoOp.
    if reconcile_github_registrations(&plan, &cfg, paths)? {
        tracing::info!("GitHub reconciliation detected drift; re-planning");
        plan = compute_plan(&cfg, paths, &args.only)?;
        if !quiet {
            render_plan(&plan, color, false, false, args.diff)?;
        }
    }

    // Resolve releases for runners that need a tarball download.
    let registry = build_auth_registry(&cfg.auth)?;
    resolve_plan_releases(&mut plan, &cfg, &registry)?;

    let systemd = open_dbus()?;
    let tarball = apply::RealTarball;
    let config_shell = apply::RealConfigShell;
    let deps = apply::Deps {
        systemd: &systemd,
        auth: &registry,
        tarball: &tarball,
        config_shell: &config_shell,
    };
    let opts = apply::ApplyOptions {
        auto_approve: args.auto_approve,
        fail_fast: args.fail_fast,
        dry_run: false,
        rollback_on_failure: args.rollback_on_failure,
    };
    let result = apply::apply(&plan, &deps, paths, &opts)?;
    if !quiet {
        let _ = render_apply_emission(&result, &mut io::stdout(), &mut io::stderr());
    }

    Ok(apply_exit_code(
        args.detailed_exitcode,
        args.detailed_exitcode_recreate,
        &result,
    ))
}

pub(super) fn confirm_apply() -> Result<bool> {
    // Detect a non-TTY stdin BEFORE blocking on read_line. When
    // ghars apply is launched from a script / cron / systemd one-shot
    // without --auto-approve, stdin is typically /dev/null or a pipe;
    // read_line then returns Ok(0) (EOF), the trim()=="" miss, and
    // confirm_apply returns Ok(false) — silently cancelling the apply.
    // Worse, on an unclosed pipe with no input, read_line blocks
    // indefinitely. Refusing up-front with an actionable error tells
    // the operator exactly which flag closes the gap.
    let stdin = io::stdin();
    if !stdin.is_terminal() {
        return Err(GharsError::Interactive(
            "stdin is not a terminal; cannot prompt for confirmation".into(),
            "pass `--auto-approve` for non-interactive use (CI, cron, systemd-run, \
             redirected stdin), or run from a TTY"
                .into(),
        ));
    }
    let mut stdout = io::stdout().lock();
    write!(stdout, "Apply these changes? [y/N] ").map_err(GharsError::Io)?;
    stdout.flush().map_err(GharsError::Io)?;
    let mut line = String::new();
    stdin.lock().read_line(&mut line).map_err(GharsError::Io)?;
    Ok(matches!(line.trim(), "y" | "Y" | "yes" | "YES"))
}

/// Resolve releases for every `CreateRunner` / `UpdateRunner`(recreate)
/// action that lacks a `runner_tarball` and has no `resolved_release`.
/// Uses the GitHub releases API with PAT authentication (5000 req/hr
/// vs 60 unauthenticated).
fn resolve_plan_releases(
    plan: &mut crate::plan::Plan,
    cfg: &crate::config::Config,
    _registry: &std::collections::HashMap<String, Box<dyn crate::auth::TokenSource>>,
) -> Result<()> {
    let client = github::build_blocking_client(cfg.proxy.as_ref())?;

    // Extract a PAT from the first auth source that has one, to
    // authenticate the releases API call. Without auth, GitHub's
    // rate limit is 60 req/hr per IP which is easily exhausted.
    let pat_token = extract_pat_for_api(cfg);

    for action in &mut plan.actions {
        let runner_plan = match action {
            Action::CreateRunner(p) => p,
            Action::UpdateRunner(d) if d.requires_recreate => &mut d.after,
            _ => continue,
        };
        if runner_plan.spec.runner_tarball.is_some() {
            continue;
        }
        if runner_plan.resolved_release.is_some() {
            continue;
        }
        let release = if let Some(ref version) = runner_plan.spec.runner_version {
            github::fetch_release_authenticated(&client, version, runner_plan.spec.arch, pat_token.as_deref())?
        } else {
            github::fetch_latest_release_authenticated(&client, runner_plan.spec.arch, pat_token.as_deref())?
        };
        runner_plan.resolved_release = Some(release);
    }
    Ok(())
}

/// Check runners against GitHub's runner registry. If a runner is
/// "in sync" on disk but not registered on GitHub (e.g. deleted via
/// the GitHub UI), wipe its on-disk spec-hash annotation so the next
/// plan sees a hash mismatch and emits a recreate. Returns true if
/// any runner was reconciled (caller should re-plan).
fn reconcile_github_registrations(
    plan: &crate::plan::Plan,
    cfg: &crate::config::Config,
    paths: &Paths,
) -> Result<bool> {
    let pat = extract_pat_for_api(cfg);
    let client = github::build_blocking_client(cfg.proxy.as_ref())?;
    let mut reconciled = false;

    for action in &plan.actions {
        let noop_name = match action {
            Action::NoOp(label) => {
                if let Some(name) = label.split(':').next() {
                    name.trim().to_string()
                } else {
                    continue;
                }
            }
            _ => continue,
        };

        // Find the runner's URL. Count-expanded names (ktstr-x64-1)
        // won't match cfg.runners directly (which has the base name
        // ktstr-x64 with count=N). Try exact match first, then prefix.
        let url = cfg.runners.iter()
            .find(|r| r.name == noop_name)
            .or_else(|| cfg.runners.iter().find(|r| noop_name.starts_with(&r.name)))
            .map(|r| r.url.as_str());
        let Some(url) = url else {
            continue;
        };

        match github::runner_is_registered(
            &client,
            url,
            &noop_name,
            pat.as_deref(),
        ) {
            Ok(true) => {}
            Ok(false) => {
                tracing::warn!(
                    runner = %noop_name,
                    "runner not registered on GitHub; wiping on-disk state to force re-registration"
                );
                // Remove the unit file so the next plan sees the runner
                // as missing and emits CreateRunner.
                let unit = paths.unit_file(&noop_name);
                if unit.exists() {
                    let _ = std::fs::remove_file(unit.as_std_path());
                }
                let dropin_dir = paths.drop_in_dir(&noop_name);
                if dropin_dir.exists() {
                    let _ = std::fs::remove_dir_all(dropin_dir.as_std_path());
                }
                reconciled = true;
            }
            Err(e) => {
                tracing::warn!(
                    runner = %noop_name,
                    error = %e,
                    "could not check GitHub registration; assuming in sync"
                );
            }
        }
    }
    Ok(reconciled)
}

/// Migrate runner home directories from regular root-owned dirs to the
/// DynamicUser private layout (dir under /var/lib/private/ + symlink
/// from /var/lib/). Runs once before plan so existing runners don't
/// fail at unit start.
/// Migrate runner home directories from regular root-owned dirs to the
/// DynamicUser private layout. Scans /var/lib/ghars/ for `ghars-*`
/// subdirs that are regular directories (not symlinks) and moves them
/// to /var/lib/private/ghars/ with a symlink in place.
fn migrate_runner_homes_to_private(
    _cfg: &crate::config::Config,
    paths: &Paths,
) -> Result<()> {
    let state_dir = paths.state_dir.as_std_path();
    let Ok(trust_zones) = std::fs::read_dir(state_dir) else {
        return Ok(());
    };
    for tz_entry in trust_zones.flatten() {
        if !tz_entry.file_type().map_or(false, |t| t.is_dir()) {
            continue;
        }
        let tz_name = tz_entry.file_name();
        let tz_str = tz_name.to_string_lossy();
        if tz_str.starts_with('.') {
            continue; // skip .staging etc
        }
        let Ok(runners) = std::fs::read_dir(tz_entry.path()) else {
            continue;
        };
        for runner_entry in runners.flatten() {
            let name = runner_entry.file_name();
            let name_str = name.to_string_lossy();
            if !name_str.starts_with("ghars-") {
                continue;
            }
            let meta = match std::fs::symlink_metadata(runner_entry.path()) {
                Ok(m) => m,
                Err(_) => continue,
            };
            if meta.file_type().is_symlink() || !meta.file_type().is_dir() {
                continue; // already correct or not a dir
            }
            let private_path = std::path::PathBuf::from(format!(
                "/var/lib/private/ghars/{}/{}",
                tz_str, name_str
            ));
            if private_path.exists() {
                continue;
            }
            tracing::info!(
                path = %runner_entry.path().display(),
                "migrating runner home to DynamicUser private layout"
            );
            if let Some(parent) = private_path.parent() {
                std::fs::create_dir_all(parent)?;
            }
            std::fs::rename(runner_entry.path(), &private_path)?;
            std::os::unix::fs::symlink(&private_path, runner_entry.path())?;
        }
    }
    Ok(())
}

/// Read the PAT value from the config's auth source for API auth.
fn extract_pat_for_api(cfg: &crate::config::Config) -> Option<String> {
    for (_name, spec) in &cfg.auth {
        match spec {
            crate::config::AuthSpec::Pat { token_env, token_file } => {
                if let Some(env_var) = token_env {
                    if let Ok(val) = std::env::var(env_var) {
                        if !val.is_empty() {
                            return Some(val);
                        }
                    }
                }
                if let Some(path) = token_file {
                    if let Ok(val) = std::fs::read_to_string(path.as_std_path()) {
                        let trimmed = val.trim().to_string();
                        if !trimmed.is_empty() {
                            return Some(trimmed);
                        }
                    }
                }
            }
            _ => continue,
        }
    }
    None
}
