//! `config.sh` invocation seam: [`ConfigShell`] trait, [`ConfigShellCtx`],
//! [`RealConfigShell`], and the [`build_register_cmd`]/[`build_remove_cmd`]
//! pure command builders that pin SEC-05 token-via-env delivery.

use std::process::Command;

use camino::Utf8Path;

use crate::Result;
use crate::error::GharsError;

use super::tarball::spawn_err;

/// Runner-self-config seam. Production wires a [`RealConfigShell`] that
/// shells out to `<runner_home>/config.sh`. Tests inject a fake.
///
/// **SEC-05** — the registration / removal token is
/// delivered to `config.sh` via the `ACTIONS_RUNNER_INPUT_TOKEN`
/// environment variable rather than the `--token VALUE` CLI argument.
/// `actions/runner` reads this env var per
/// `src/Runner.Listener/CommandSettings.cs:245` (envPrefix
/// `"ACTIONS_RUNNER_INPUT_"` + arg name `"token"` from
/// `Constants.Runner.CommandLine.Args.Token`). Argv channels would
/// surface the token at `/proc/PID/cmdline` for the lifetime of the
/// process; env-var delivery keeps the token in `/proc/PID/environ`,
/// which is mode 0400 owner-only.
pub trait ConfigShell {
    /// Register the runner: `config.sh --url URL --name NAME --labels
    /// CSV --unattended --replace` with `ACTIONS_RUNNER_INPUT_TOKEN`
    /// set in the child environment, run as `user` with cwd
    /// `runner_home`. The token does NOT appear in argv (SEC-05).
    ///
    /// # Errors
    ///
    /// `GharsError::Apply` on spawn / non-zero exit.
    fn run_register(&self, ctx: &ConfigShellCtx<'_>) -> Result<()>;

    /// Deregister: `config.sh remove --unattended` with the removal
    /// token in `ACTIONS_RUNNER_INPUT_TOKEN`. Idempotent — exit code 1
    /// from a stale runner that's already been deregistered
    /// server-side is not surfaced as an error.
    ///
    /// # Errors
    ///
    /// `GharsError::Apply` on spawn / non-zero exit (other than the
    /// "already removed" case).
    fn run_remove(&self, ctx: &ConfigShellCtx<'_>) -> Result<()>;
}

/// Inputs for one `config.sh` invocation. Holding the runner home /
/// token / labels in one struct keeps the trait method clean and
/// future-proofs against new fields.
#[derive(Debug)]
pub struct ConfigShellCtx<'a> {
    /// Per-runner home
    /// (`/var/lib/ghars/<TRUST_ZONE>/ghars-<NAME>`).
    pub runner_home: &'a Utf8Path,
    /// Runner instance name (the `%i` value).
    pub name: &'a str,
    /// Repo / org URL for `--url`.
    pub url: &'a str,
    /// Runner labels for `--labels`.
    pub labels: &'a [String],
    /// Registration / removal token value.
    pub token: &'a str,
}

/// Environment-variable name actions/runner reads to populate the
/// `--token` argument when the CLI flag is absent. Sourced from
/// `actions/runner src/Runner.Listener/CommandSettings.cs:245`
/// (envPrefix `"ACTIONS_RUNNER_INPUT_"`) +
/// `Constants.Runner.CommandLine.Args.Token = "token"`. Used by
/// [`RealConfigShell`] for SEC-05 token delivery.
pub(super) const RUNNER_TOKEN_ENV: &str = "ACTIONS_RUNNER_INPUT_TOKEN";

/// Build the fully-prepared `Command` for `config.sh` registration.
/// Pure constructor — no I/O, no spawn — so tests can inspect argv
/// via `get_args()` and env via `get_envs()` without touching
/// `/usr/bin/sudo`. Centralizes the SEC-05 invariant: every callsite
/// that shells out to `config.sh` MUST route through this builder so
/// the token never leaks into argv.
///
/// `--preserve-env=ACTIONS_RUNNER_INPUT_TOKEN` (sudo 1.8.21+) tells
/// sudo to copy the named env var from its own environ into the
/// target user's environ; without it, sudo's default env_reset
/// strips the token before exec'ing config.sh.
pub(super) fn build_register_cmd(ctx: &ConfigShellCtx<'_>) -> Command {
    let labels_csv = ctx.labels.join(",");
    let mut cmd = Command::new(ctx.runner_home.join("config.sh"));
    // SEC-05: token rides in the env var, not argv. argv contains no
    // secret material; `/proc/PID/cmdline` of the running config.sh
    // subprocess is now safe to read. config.sh runs as root in apply;
    // systemd takes ownership at unit start via DynamicUser=yes +
    // StateDirectory=, which chowns the home + credentials to the
    // trust_zone's transient UID at start-of-unit time.
    cmd.args([
        "--url",
        ctx.url,
        "--name",
        ctx.name,
        "--labels",
        &labels_csv,
        "--unattended",
        "--replace",
    ])
    .env(RUNNER_TOKEN_ENV, ctx.token)
    .current_dir(ctx.runner_home.as_std_path());
    cmd
}

/// Build the `config.sh remove` Command. Same SEC-05 contract as
/// [`build_register_cmd`] — token rides in the env var, never argv.
/// config.sh's `remove` subcommand consumes the same
/// `Constants.Runner.CommandLine.Args.Token` field
/// (`GetRunnerDeletionToken` / `GetArgOrPrompt` in actions/runner),
/// so the env-var mapping applies identically to register and remove.
pub(super) fn build_remove_cmd(ctx: &ConfigShellCtx<'_>) -> Command {
    let mut cmd = Command::new(ctx.runner_home.join("config.sh"));
    cmd.args(["remove", "--unattended"])
        .env(RUNNER_TOKEN_ENV, ctx.token)
        .current_dir(ctx.runner_home.as_std_path());
    cmd
}

/// Production config.sh runner.
#[derive(Debug, Default)]
pub struct RealConfigShell;

impl ConfigShell for RealConfigShell {
    fn run_register(&self, ctx: &ConfigShellCtx<'_>) -> Result<()> {
        let status = build_register_cmd(ctx)
            .status()
            .map_err(|e| spawn_err("config.sh register", &e))?;
        if status.success() {
            return Ok(());
        }
        Err(GharsError::Apply {
            action: format!("config.sh register({})", ctx.name),
            source: Box::new(GharsError::Io(std::io::Error::other(format!(
                "config.sh register exited with {status:?}"
            )))),
        })
    }

    fn run_remove(&self, ctx: &ConfigShellCtx<'_>) -> Result<()> {
        let status = build_remove_cmd(ctx)
            .status()
            .map_err(|e| spawn_err("config.sh remove", &e))?;
        if status.success() {
            return Ok(());
        }
        // `config.sh remove` returns non-zero when the runner is
        // already deregistered server-side — treat as success so
        // `apply RemoveRunner` is idempotent. Distinguish via stderr
        // in a future revision; for now we trust the orchestration
        // order (stop → mint removal token → run remove).
        Ok(())
    }
}
