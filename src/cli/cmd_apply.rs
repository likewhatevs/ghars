//! `ghars apply` command handler + the interactive y/N prompt.

use std::io::{self, BufRead, IsTerminal, Write};

use camino::Utf8Path;

use crate::Result;
use crate::apply;
use crate::error::GharsError;
use crate::paths::Paths;
use crate::plan::Action;
use crate::preflight;

use super::args::{ApplyArgs, ColorMode};
use super::cmd_plan::{compute_plan, open_dbus};
use super::exit_codes::{apply_exit_code, cancel_exit_code, dry_run_exit_code, recreate_exit_code};
use super::load::{build_auth_registry, load_config};
use super::render::{render_apply_emission, render_plan};

pub(crate) fn cmd_apply(
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

    let plan = compute_plan(&cfg, paths, &args.only)?;

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

    let registry = build_auth_registry(&cfg.auth)?;
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

pub(crate) fn confirm_apply() -> Result<bool> {
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
