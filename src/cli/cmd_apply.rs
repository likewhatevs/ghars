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

    // Ensure runtime directories exist on fresh hosts. Wrap raw Io
    // failures in a Validation so non-root invocations get the same
    // actionable hint as the lock-acquire path (root is required).
    std::fs::create_dir_all(paths.runtime_dir.as_std_path()).map_err(|e| {
        if e.kind() == std::io::ErrorKind::PermissionDenied {
            GharsError::Validation(
                format!("cannot create runtime dir {}: {e}", paths.runtime_dir),
                "ghars apply requires root (or CAP_DAC_OVERRIDE); re-run with sudo".into(),
            )
        } else {
            GharsError::Io(e)
        }
    })?;

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
    resolve_plan_releases(&mut plan, &cfg)?;

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
        no_restart: args.no_restart,
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
) -> Result<()> {
    let client = github::build_blocking_client(cfg.proxy.as_ref())?;

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
        // Per-runner PAT (looked up via the runner's `auth_name`) so
        // multi-auth configs use the right credential for each runner's
        // releases API call. Without auth the rate limit is 60 req/hr
        // per IP; with PAT it's 5000 req/hr.
        let pat_token = pat_for_auth_name(cfg, &runner_plan.spec.auth_name);
        let release = if let Some(ref version) = runner_plan.spec.runner_version {
            github::fetch_release_authenticated(&client, version, runner_plan.spec.arch, pat_token.as_deref())?
        } else {
            github::fetch_latest_release_authenticated(&client, runner_plan.spec.arch, pat_token.as_deref())?
        };
        // Also populate spec.runner_version so the downstream
        // renderer + execute_create_runner see the resolved version
        // through the same field that operator-pinned + discovered-
        // annotation paths populate. Without this fill, the spec
        // arriving at render_identity would have runner_version=None
        // for "implicit-latest" runners — render_identity falls back
        // to literal "latest" silently (units.rs:968), the drop-in
        // bytes land on disk with bin.latest paths, and the
        // execute_update_runner in-place arm hard-errors at
        // runners.rs:646 on the .env/.path rewrite. The "guarantee
        // Some by render time" invariant is closed jointly by:
        //   - lower_to_effective rejecting tarball+no-version
        //   - intersection arm filling from discovered annotation
        //   - resolve_plan_releases (this loop) filling from the API
        runner_plan.spec.runner_version = Some(release.version.clone());
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
    let client = github::build_blocking_client(cfg.proxy.as_ref())?;
    let mut reconciled = false;

    // Expand counts so `foo-1` / `foo-2` map to their per-runner auth
    // (the parent `foo` block's `auth_name`). Without expansion, every
    // count-generated runner falls through to no-match.
    let expanded = crate::plan::expand_counts(cfg)?;

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

        // Exact match against the post-expansion name set. Prefix match
        // (the previous heuristic) was non-deterministic: a runner
        // `foo-bar` would prefix-match a count-block `foo`'s sibling
        // `foo-1` and pick whichever block was listed first in TOML.
        let Some(runner) = expanded.iter().find(|r| r.name == noop_name) else {
            continue;
        };
        let url = runner.url.as_str();
        let pat = runner_pat(cfg, runner);

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
                // as missing and emits CreateRunner. Surface fs failures
                // via tracing::warn! so an operator can debug a
                // reconciliation that silently no-op'd because the file
                // was locked or the dir held mounts.
                let unit = paths.unit_file(&noop_name);
                if unit.exists()
                    && let Err(e) = std::fs::remove_file(unit.as_std_path())
                {
                    tracing::warn!(
                        runner = %noop_name,
                        path = %unit,
                        error = %e,
                        "failed to remove unit file during GitHub reconciliation"
                    );
                }
                let dropin_dir = paths.drop_in_dir(&noop_name);
                if dropin_dir.exists()
                    && let Err(e) = std::fs::remove_dir_all(dropin_dir.as_std_path())
                {
                    tracing::warn!(
                        runner = %noop_name,
                        path = %dropin_dir,
                        error = %e,
                        "failed to remove drop-in dir during GitHub reconciliation"
                    );
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

/// Resolve a PAT value for a specific auth-section entry.
///
/// Looks up `auth_name` in `cfg.auth` and resolves its PAT (env var or
/// root-owned 0o600 file) via [`crate::auth::resolve_pat_for_api`].
/// Returns `None` when the auth source is not a PAT, the env var is
/// unset, or the file is unreadable / mode-rejected.
pub(super) fn pat_for_auth_name(cfg: &crate::config::Config, auth_name: &str) -> Option<String> {
    crate::auth::resolve_pat_for_api(cfg.auth.get(auth_name)?)
}

/// Resolve the effective `auth_name` for a `RunnerSpec`: per-runner
/// `auth` if set, else `defaults.auth`, else `None`.
fn effective_auth_name<'a>(
    cfg: &'a crate::config::Config,
    runner: &'a crate::config::RunnerSpec,
) -> Option<&'a str> {
    runner.auth.as_deref().or(cfg.defaults.auth.as_deref())
}

/// Resolve a PAT for a specific runner using its effective `auth_name`.
pub(super) fn runner_pat(
    cfg: &crate::config::Config,
    runner: &crate::config::RunnerSpec,
) -> Option<String> {
    pat_for_auth_name(cfg, effective_auth_name(cfg, runner)?)
}

/// Resolve a PAT for a given GitHub URL by looking up the first runner
/// declared against it.
pub(super) fn pat_for_url(cfg: &crate::config::Config, url: &str) -> Option<String> {
    let runner = cfg.runners.iter().find(|r| r.url == url)?;
    runner_pat(cfg, runner)
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used)]
mod tests {
    use super::*;
    use crate::plan::{Plan, RunnerPlan};

    fn make_create_action_with_tarball() -> Action {
        let mut spec = crate::config::EffectiveRunnerSpec {
            environment: crate::config::EnvironmentSpec::default(),
            name: "buckos".into(),
            url: "https://github.com/example/repo".into(),
            arch: crate::config::Arch::X86_64,
            labels: vec![],
            memory_max: None,
            runner_version: Some("2.334.0".into()),
            runner_sha256: None,
            runner_tarball: Some("/tarballs/runner.tar.gz".into()),
            auth_name: "pat".into(),
            caches: vec![],
            trust_zone: "default".into(),
            network: None,
            proxy: None,
            hooks: None,
            hardening: crate::config::Hardening::default(),
            allowed_cpus: None,
            allowed_memory_nodes: None,
            spec_hash: "sha256:dead".into(),
            config_source: "/etc/ghars/ghars.toml".into(),
            renderer_schema: crate::systemd::RENDERER_SCHEMA,
        };
        let _ = &mut spec;
        Action::CreateRunner(RunnerPlan {
            spec,
            resolved_release: None,
            effective_unit_text: String::new(),
            drop_ins: std::collections::BTreeMap::new(),
            env_file: String::new(),
            path_file: String::new(),
            spec_hash: "sha256:dead".into(),
        })
    }

    /// `resolve_plan_releases` must short-circuit (no HTTP call) when
    /// every `CreateRunner` action carries a pinned `runner_tarball`.
    /// Pin the no-network short-circuit so a future regression that
    /// removed the early-continue doesn't silently make every test that
    /// invokes `resolve_plan_releases` fetch from GitHub.
    #[test]
    fn resolve_plan_releases_skips_actions_with_tarball_pinned() {
        let mut plan = Plan {
            actions: vec![make_create_action_with_tarball()],
            warnings: Vec::new(),
            keep_versions: 2,
        };
        let cfg = crate::config::Config::default();
        // No proxy → `build_blocking_client` constructs a client without
        // touching the network. The per-action loop then short-circuits
        // on `runner_tarball.is_some()` before any HTTP call.
        resolve_plan_releases(&mut plan, &cfg)
            .expect("tarball-pinned plan must not require network");
    }

    /// Empty plan: no `CreateRunner` / recreate `UpdateRunner` actions, so
    /// the function returns Ok without ever exercising the per-action
    /// release-fetch path.
    #[test]
    fn resolve_plan_releases_returns_ok_for_empty_plan() {
        let mut plan = Plan::default();
        let cfg = crate::config::Config::default();
        resolve_plan_releases(&mut plan, &cfg).expect("empty plan must succeed");
        assert!(plan.actions.is_empty());
    }

    /// `confirm_apply` must error with `GharsError::Interactive` when
    /// stdin is not a TTY (non-TTY = CI / cron / pipe). The test runner's
    /// stdin is reliably non-TTY, so this exercises the production
    /// branch directly.
    #[test]
    fn confirm_apply_errors_on_non_tty_stdin() {
        let err = confirm_apply().expect_err("non-TTY stdin must surface Interactive");
        assert!(
            matches!(err, GharsError::Interactive(_, _)),
            "expected Interactive variant, got {err:?}"
        );
    }
}
