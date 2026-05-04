//! Clap argument structs and the `ColorMode` render hint.
//!
//! Top-level `Cli` and `Command` are defined here too — they hold the
//! command dispatch shape, so they live alongside the per-subcommand
//! `*Args` they wrap.

use std::io::{self, IsTerminal};

use camino::Utf8PathBuf;

/// Top-level `ghars` CLI.
#[derive(clap::Parser, Debug)]
#[command(
    name = "ghars",
    version,
    about = "Declaratively manage self-hosted GitHub Actions runners"
)]
pub struct Cli {
    /// Path to the config file (`/etc/ghars/ghars.toml` by default).
    #[arg(
        long,
        env = "GHARS_CONFIG",
        default_value = "/etc/ghars/ghars.toml",
        global = true
    )]
    pub config: Utf8PathBuf,
    /// Disable ANSI color output. Honors `NO_COLOR` env as well.
    #[arg(long, global = true)]
    pub no_color: bool,
    /// Suppress info-level output.
    #[arg(long, global = true)]
    pub quiet: bool,
    /// Increase verbosity (-v, -vv, -vvv).
    #[arg(short, long, global = true, action = clap::ArgAction::Count)]
    pub verbose: u8,
    /// Subcommand to run.
    #[command(subcommand)]
    pub command: Command,
}

/// Top-level subcommand. See Part 5 for full semantics of each.
#[derive(clap::Subcommand, Debug)]
pub enum Command {
    /// Validate the config file. Use --deep to round-trip auth tokens.
    Validate(ValidateArgs),
    /// Show actions `apply` would take. No system changes.
    Plan(PlanArgs),
    /// Converge actual state to match config.
    Apply(ApplyArgs),
    /// Tabular state of managed runners + system health.
    Status(StatusArgs),
    /// Scaffold ghars.toml. Runner identity comes from
    /// `DynamicUser=yes` at unit start (transient UID/GID per
    /// `trust_zone`); init does not provision any system user.
    Init(InitArgs),
    /// Add one runner interactively (prompts then runs apply).
    Add(AddArgs),
    /// Tail journalctl for one or more runner units.
    Logs(LogsArgs),
    /// Per-runner + total resource accounting via systemd D-Bus.
    Metrics(MetricsArgs),
    /// Generate shell completions to stdout.
    Completions {
        /// Target shell.
        shell: clap_complete::Shell,
    },
    /// Generate man pages to OUTPUT.
    Manpages {
        /// Output directory.
        output: Utf8PathBuf,
    },
    /// HIDDEN: setup veth + netns for INSTANCE.
    #[command(hide = true, name = "_netns-setup")]
    NetnsSetup {
        /// Instance name.
        instance: String,
    },
    /// HIDDEN: teardown veth + netns for INSTANCE.
    #[command(hide = true, name = "_netns-teardown")]
    NetnsTeardown {
        /// Instance name.
        instance: String,
    },
    /// HIDDEN: run PROGRAM ARGS inside the named netns. nsenter wrapper.
    #[command(hide = true, name = "_netns-veth")]
    NetnsVeth {
        /// Instance name.
        instance: String,
        /// Program + args.
        #[arg(trailing_var_arg = true, allow_hyphen_values = true)]
        program: Vec<String>,
    },
}

/// `ghars validate [--deep]`.
#[derive(clap::Args, Debug)]
pub struct ValidateArgs {
    /// Resolve auth tokens (network).
    #[arg(long)]
    pub deep: bool,
}

/// `ghars plan [...]`.
///
/// `--refresh-releases` and `--output-dir` are NOT exposed in v0.1 —
/// they were placeholders for capabilities that don't ship until
/// v0.2 (see CONTRIBUTING.md "Deferred to v0.2"). v0.1 always
/// queries the release API on-demand and always writes generated
/// artifacts to the host paths under `Paths`. Surfacing the flags
/// without the underlying behavior would silently no-op, which is
/// the failure mode this omission closes.
#[derive(clap::Args, Debug)]
pub struct PlanArgs {
    /// Filter to a subset of runner names (substring match).
    #[arg(long, value_delimiter = ',')]
    pub only: Vec<String>,
    /// Output as JSON; secrets are redacted in BOTH formats.
    #[arg(long)]
    pub json: bool,
    /// Make exit code 2 mean "changes detected" (terraform plan parity).
    /// Without this flag, `ghars plan` always exits 0 regardless of
    /// whether the plan diff is empty. With it, a non-empty plan
    /// returns 2 — matches `ApplyArgs::detailed_exitcode` semantics
    /// for symmetry, and lets CI gating workflows ("apply iff plan
    /// shows changes") drop a redundant `ghars apply --dry-run
    /// --detailed-exitcode` pre-step.
    #[arg(long)]
    pub detailed_exitcode: bool,
    /// Make exit code 8 mean "recreate-class action present". When set,
    /// any plan containing an action whose
    /// [`crate::plan::Action::disruption`] returns
    /// [`crate::plan::Disruption::Recreate`] returns 8; otherwise the
    /// usual exit code applies. Independent of `--detailed-exitcode`:
    /// either flag can fire alone, and when both are set recreate (8)
    /// trumps detailed-changes (2). Lets CI auto-merge pure in-place
    /// updates while blocking recreate plans for human review.
    ///
    /// Surfaces (5): fires on `ghars plan`, `ghars apply --dry-run`,
    /// the `ghars apply` pre-confirm gate (BEFORE `confirm_apply` runs,
    /// regardless of `--auto-approve`), the `ghars apply` cancel path
    /// (operator answered N), and the `ghars apply` post-success path
    /// (`result.failed.is_empty()`).
    ///
    /// Failure precedence (failure trumps plan-shape): non-zero failure
    /// codes always win over 8. Specifically 1 (full failure, no auth),
    /// 4 (partial apply failure), and 5 (full failure with auth) all
    /// override 8. Recreate is a plan-shape signal; structural /
    /// post-execution failures are stronger.
    #[arg(long)]
    pub detailed_exitcode_recreate: bool,
    /// Show full drop-in body content. Default off (no body content
    /// emitted). When set, each `Modified` drop-in renders as a
    /// unified text diff via
    /// `similar::udiff::unified_diff` (Myers algorithm, 3 lines
    /// of context); `Created` and `Removed` drop-ins emit the
    /// full body of the surviving side; `Preserved` drop-ins
    /// emit a `(unchanged)` marker. For recreate-class
    /// `UpdateRunner` actions (whose `drop_in_changes` payload
    /// is empty by design), every rendered drop-in in
    /// `delta.after.drop_ins` is shown as `Created`.
    ///
    /// SECURITY: drop-in bodies render `Environment=` lines
    /// verbatim. The `60-proxy.conf` drop-in carries
    /// `Environment=HTTP_PROXY=…` / `HTTPS_PROXY=…`, and an
    /// authenticated proxy URL embeds credentials in the
    /// userinfo component (e.g. `https://USER:PASS@host`). With
    /// `--diff` set those credentials appear in stdout (and any
    /// captured CI artifact, build log upload, terminal
    /// scrollback, or shared paste) in cleartext. Operators
    /// piping `ghars plan --diff` (or `ghars apply --diff` —
    /// same caveat applies) to artifacts that survive past the
    /// invoking shell session must treat the output as a
    /// credential-bearing file: do not commit, do not upload to
    /// shared logs, do not paste to chat. Other drop-ins may
    /// likewise embed sensitive `Environment=` values; proxy
    /// auth is the canonical case but not the only one. Default
    /// off precisely so the secret-bearing body never reaches
    /// stdout unless the operator opts in.
    ///
    /// Examples:
    ///   `ghars plan --diff`
    ///   `ghars plan --diff --json`
    #[arg(long)]
    pub diff: bool,
}

/// `ghars apply [...]`.
///
/// `--refresh-releases` is NOT exposed in v0.1 (see [`PlanArgs`] doc
/// comment + CONTRIBUTING.md "Deferred to v0.2").
#[derive(clap::Args, Debug)]
pub struct ApplyArgs {
    /// Filter to a subset of runner names.
    #[arg(long, value_delimiter = ',')]
    pub only: Vec<String>,
    /// Skip the interactive confirmation.
    #[arg(long)]
    pub auto_approve: bool,
    /// Stop on first action failure.
    #[arg(long)]
    pub fail_fast: bool,
    /// Alias for `ghars plan`. Prints, does not apply.
    #[arg(long)]
    pub dry_run: bool,
    /// Make exit code 2 mean "changes detected" (terraform convention).
    #[arg(long)]
    pub detailed_exitcode: bool,
    /// Make exit code 8 mean "recreate-class action present" — same
    /// semantics as [`PlanArgs::detailed_exitcode_recreate`]. Fires
    /// pre-confirm (so CI can block on recreate plans before any
    /// human y/N prompt) AND post-apply when no actions failed.
    /// Independent of `--detailed-exitcode`. Failure precedence
    /// preserved: 4 (partial) and 5 (auth) win over 8.
    #[arg(long)]
    pub detailed_exitcode_recreate: bool,
    /// Best-effort undo: when an action's `execute_*` handler fails,
    /// walk that action's `Vec<UndoStep>` in reverse and reverse each
    /// recorded step (file unlinks, unit stop/disable, group/user
    /// removal, GitHub deregister via fresh removal token). Per-action
    /// scope only — earlier successful actions are NOT touched. Default
    /// off; partial state is left for the next `ghars apply` to
    /// idempotently complete.
    #[arg(long)]
    pub rollback_on_failure: bool,
    /// Show full drop-in body content during the apply preview.
    /// Same semantics as [`PlanArgs::diff`] — see that field's
    /// doc for the secret-leakage caveat. Affects both `--dry-run`
    /// output and the pre-confirm preview rendered to stdout
    /// before the y/N prompt. Per-action output during apply
    /// itself uses the `ok:`/`fail:` shape regardless of `--diff`.
    #[arg(long)]
    pub diff: bool,
}

/// `ghars status [...]`.
#[derive(clap::Args, Debug)]
pub struct StatusArgs {
    /// Output JSON instead of table.
    #[arg(long)]
    pub json: bool,
    /// Append a metrics section.
    #[arg(long)]
    pub metrics: bool,
    /// Show only SYSTEM HEALTH section.
    #[arg(long, conflicts_with_all = ["runners_only", "metrics"])]
    pub health_only: bool,
    /// Show only RUNNERS section.
    #[arg(long, conflicts_with = "health_only")]
    pub runners_only: bool,
    /// Filter to specific runner names.
    pub names: Vec<String>,
}

/// `ghars init`.
#[derive(clap::Args, Debug)]
pub struct InitArgs {
    /// Output path override. Defaults to `<config>` global path.
    #[arg(long)]
    pub output: Option<Utf8PathBuf>,
}

/// `ghars add [...]`.
#[derive(clap::Args, Debug)]
pub struct AddArgs {
    /// `OWNER/REPO` or `OWNER` (org-level).
    #[arg(long)]
    pub repo: String,
    /// Runner name (defaults to `OWNER-REPO-N` where N picks the next free index).
    #[arg(long)]
    pub name: Option<String>,
    /// Comma-separated labels.
    #[arg(long, value_delimiter = ',')]
    pub labels: Vec<String>,
    /// Auth ref (default: defaults.auth from config; falls back to "interactive" if unset).
    #[arg(long)]
    pub auth: Option<String>,
    /// Don't apply — just edit the config. Operator runs `ghars apply` next.
    #[arg(long)]
    pub no_apply: bool,
}

/// `ghars logs`.
#[derive(clap::Args, Debug)]
pub struct LogsArgs {
    /// Runner names to tail. Empty = all managed runners.
    #[arg(value_delimiter = ',')]
    pub names: Vec<String>,
    /// Follow (journalctl -f).
    #[arg(short, long)]
    pub follow: bool,
    /// Show last N entries.
    #[arg(short = 'n', long, default_value_t = 100)]
    pub lines: u32,
    /// systemd journal time spec (e.g. "1 hour ago").
    #[arg(long)]
    pub since: Option<String>,
}

/// `ghars metrics`.
#[derive(clap::Args, Debug)]
pub struct MetricsArgs {
    /// Runner names to query. Empty = all managed runners.
    #[arg(value_delimiter = ',')]
    pub names: Vec<String>,
    /// Output JSON instead of a table.
    #[arg(long)]
    pub json: bool,
    /// Suppress the total row in table output.
    #[arg(long)]
    pub no_total: bool,
}

/// Render hint — does the operator want ANSI color in plan/status output?
#[derive(Debug, Clone, Copy)]
pub struct ColorMode {
    /// True ⇒ ANSI escape codes are emitted.
    pub enabled: bool,
}

impl ColorMode {
    pub(crate) fn from_cli(no_color_flag: bool) -> Self {
        let no_color_env = std::env::var_os("NO_COLOR").is_some();
        let stdout_tty = io::stdout().is_terminal();
        Self {
            enabled: !no_color_flag && !no_color_env && stdout_tty,
        }
    }
}
