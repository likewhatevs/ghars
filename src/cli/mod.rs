//! Clap definitions + command dispatch.
//!
//! Design spec: Part 5 (CLI interface). Subcommands: validate, plan,
//! apply, status, init, add, logs, metrics, completions, manpages, plus
//! three hidden netns helpers (`_netns-setup`, `_netns-teardown`,
//! `_netns-veth`).
//!
//! Exit-code mapping (Part 5):
//! - 0 success
//! - 1 generic error (default mode; full-failure apply with no auth
//!   cause; routes here from `GharsError::GitHub` / `Systemd` / `Io` /
//!   `Tarball` / `Sha256Mismatch` / `ApplyLocked` / `Apply`)
//! - 2 with `--detailed-exitcode`, plan diff non-empty (terraform):
//!   emitted by `apply --dry-run --detailed-exitcode` when the plan
//!   has any non-NoOp action, by `apply --detailed-exitcode` after a
//!   successful apply against a non-empty plan, and when the operator
//!   cancels at the apply prompt (`y/N`) with `--detailed-exitcode`
//!   set, to signal "changes still pending" rather than "success"
//! - 3 preflight failure — emitted by `cmd_apply` / `cmd_status` via
//!   `Ok(3)` and by `err_to_exit_code` from `GharsError::Preflight`
//! - 4 partial apply failure (some actions succeeded, some failed) —
//!   wins over 5 even when an Auth error is among the failures
//! - 5 full-failure apply where at least one failure was an Auth error;
//!   also returned by `err_to_exit_code` from a top-level
//!   `GharsError::Auth` (auth-resolve failure before the apply loop
//!   runs — e.g. `build_auth_registry` rejecting a missing PAT env
//!   var or unreadable token file)
//! - 6 config-class rejection — `GharsError::Config` (TOML parse,
//!   shape mismatch) and `GharsError::Validation` (same
//!   operator-actionable class — trust_zone charset, duplicate caches,
//!   render_identity gates). Wrapping scripts can branch on it without
//!   parsing stderr.
//! - 7 interactive prompting required but unavailable —
//!   `GharsError::Interactive`: emitted when `cmd_apply` reaches
//!   `confirm_apply()` with non-TTY stdin and `--auto-approve` not set.
//!   Distinct from 6 so wrapping scripts can tell "config is broken"
//!   from "apply needs --auto-approve" without parsing stderr.
//! - 8 with `--detailed-exitcode-recreate`, plan contains a recreate-
//!   class action — emitted by 5 surfaces: `cmd_plan`, `apply
//!   --dry-run`, the `apply` pre-confirm gate (fires BEFORE
//!   `confirm_apply` runs, regardless of `--auto-approve`), the
//!   apply-cancel path, and post-apply when `result.failed` is empty.
//!   Recreate-class actions are those whose
//!   [`crate::plan::Action::disruption`] returns
//!   [`crate::plan::Disruption::Recreate`]: `CreateRunner`,
//!   `UpdateRunner` with `requires_recreate=true`, `RemoveRunner`,
//!   `CreateCachePool`, and `RemoveCachePool`. `UpdateCachePool` is
//!   always `Disruption::Restart` (in-place drop-in rewrite +
//!   stop+start; no host-state destruction). The flag is independent
//!   of `--detailed-exitcode`; when both are set, recreate (8) trumps
//!   detailed-changes (2). Failure precedence: any non-zero failure
//!   code trumps 8 — 1 (full failure, no auth), 4 (partial apply
//!   failure), and 5 (full failure with auth) all win over 8.
//!   Recreate is a plan-shape signal; structural / post-execution
//!   failures are stronger. Lets CI auto-merge in-place changes while
//!   blocking recreate plans for human review.

mod args;
mod cmd_apply;
mod cmd_metrics;
mod cmd_misc;
mod cmd_plan;
mod cmd_status;
mod exit_codes;
mod json;
mod load;
mod render;

pub use args::{
    AddArgs, ApplyArgs, Cli, ColorMode, Command, InitArgs, LogsArgs, MetricsArgs, PlanArgs,
    StatusArgs, ValidateArgs,
};
pub use exit_codes::{err_to_exit_code, verbose_to_filter_level};
#[cfg(test)]
pub(crate) use render::render_rollback_advisory;

use crate::Result;
use crate::paths::Paths;

/// Dispatch a parsed CLI to its handler. Returns the process exit code.
///
/// Subcommands route to the library functions per Part 5; the netns
/// helpers are the only handlers that intentionally bypass the config
/// loader because they read per-instance state from
/// `<config_dir>/netns.d/INSTANCE.toml` written ahead of time by
/// `apply`.
///
/// # Errors
///
/// Returns `GharsError` from any subcommand handler that fails. The
/// caller in `main.rs` maps the variant to a Part 5 exit code via
/// `err_to_exit_code` — see that function's doc-comment for the full
/// per-variant table (Config / Validation → 6, Auth → 5,
/// Preflight → 3, every other variant → 1). Subcommand handlers
/// themselves return `Ok(N)` for non-success exits in the
/// per-command code-table (preflight = 3, partial apply = 4,
/// full-failure auth = 5, detailed-exitcode = 2 including the
/// cancel-with-`--detailed-exitcode` path). Note that 4 wins over 5
/// when some actions succeeded — see the cmd_apply tail.
pub fn dispatch(cli: Cli) -> Result<i32> {
    let paths = Paths::default();
    let color = ColorMode::from_cli(cli.no_color);
    match cli.command {
        Command::Validate(args) => cmd_plan::cmd_validate(&cli.config, &args, cli.quiet),
        Command::Plan(args) => cmd_plan::cmd_plan(&cli.config, &paths, &args, color, cli.quiet),
        Command::Apply(args) => cmd_apply::cmd_apply(&cli.config, &paths, &args, color, cli.quiet),
        Command::Status(args) => {
            cmd_status::cmd_status(&cli.config, &paths, &args, color, cli.quiet)
        }
        Command::Init(args) => cmd_misc::cmd_init(&cli.config, &args, cli.quiet),
        Command::Add(args) => cmd_misc::cmd_add(&cli.config, &paths, &args, color, cli.quiet),
        Command::Logs(args) => cmd_misc::cmd_logs(&paths, &args),
        Command::Metrics(args) => cmd_metrics::cmd_metrics(&paths, &args),
        Command::Completions { shell } => {
            cmd_misc::cmd_completions(shell);
            Ok(0)
        }
        Command::Manpages { output } => cmd_misc::cmd_manpages(&output),
        Command::NetnsSetup { instance } => {
            crate::netns::setup(&paths, &instance)?;
            Ok(0)
        }
        Command::NetnsTeardown { instance } => {
            crate::netns::teardown(&paths, &instance)?;
            Ok(0)
        }
        Command::NetnsVeth { instance, program } => crate::netns::run_in_netns(&instance, &program),
    }
}

#[cfg(test)]
#[path = "tests/mod.rs"]
mod tests;
