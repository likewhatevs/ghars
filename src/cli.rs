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
//!   `Tarball` / `Sha256Mismatch` / `ApplyLocked` / `Apply` per #357)
//! - 2 with `--detailed-exitcode`, plan diff non-empty (terraform):
//!   emitted by `apply --dry-run --detailed-exitcode` when the plan
//!   has any non-NoOp action (#389), by `apply --detailed-exitcode`
//!   after a successful apply against a non-empty plan, and when the
//!   operator cancels at the apply prompt (`y/N`) with
//!   `--detailed-exitcode` set, to signal "changes still pending"
//!   rather than "success" (#358)
//! - 3 preflight failure — emitted by `cmd_apply` / `cmd_status` via
//!   `Ok(3)` and by `err_to_exit_code` from `GharsError::Preflight` (#357)
//! - 4 partial apply failure (some actions succeeded, some failed) —
//!   wins over 5 even when an Auth error is among the failures (#251)
//! - 5 full-failure apply where at least one failure was an Auth error;
//!   also returned by `err_to_exit_code` from a top-level
//!   `GharsError::Auth` (auth-resolve failure before the apply loop
//!   runs — e.g. `build_auth_registry` rejecting a missing PAT env
//!   var or unreadable token file, #357)
//! - 6 config-class rejection — `GharsError::Config` (#275: TOML parse,
//!   shape mismatch) and `GharsError::Validation` (#357: same
//!   operator-actionable class — trust_zone charset, duplicate caches,
//!   render_identity gates). Wrapping scripts can branch on it without
//!   parsing stderr.
//! - 7 interactive prompting required but unavailable —
//!   `GharsError::Interactive` (#390): emitted when `cmd_apply` reaches
//!   `confirm_apply()` with non-TTY stdin and `--auto-approve` not set.
//!   Distinct from 6 so wrapping scripts can tell "config is broken"
//!   from "apply needs --auto-approve" without parsing stderr.
//! - 8 with `--detailed-exitcode-recreate`, plan contains a recreate-
//!   class action — emitted by 5 surfaces: `cmd_plan`, `apply
//!   --dry-run`, the `apply` pre-confirm gate (fires BEFORE
//!   `confirm_apply` runs, regardless of `--auto-approve`), the
//!   apply-cancel path, and post-apply when `result.failed` is empty
//!   (#464). Recreate-class actions are those whose
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

use std::collections::{HashMap, HashSet};
use std::fs;
use std::fs::OpenOptions;
use std::io::{self, BufRead, IsTerminal, Write};
use std::os::unix::fs::OpenOptionsExt;
use std::process::Command as ProcCommand;
use std::process::Stdio;
use std::sync::LazyLock;

use camino::{Utf8Path, Utf8PathBuf};
use clap::CommandFactory;
use regex::Regex;
use unicode_general_category::{get_general_category, GeneralCategory};
use zbus::blocking::{Connection, Proxy};
use zbus::zvariant::OwnedObjectPath;

use crate::apply;
use crate::auth::{build_token_source, TokenSource};
use crate::config::{AuthSpec, Config, Hardening, HooksSpec};
use crate::error::GharsError;
use crate::escape_control_chars;
use crate::paths::Paths;
use crate::plan::{self, Action, Plan};
use crate::preflight;
use crate::state;
use crate::systemd::DbusSystemd;
use crate::validators;
use crate::Result;

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
    /// Scaffold ghars.toml. Per-runner system users are created at
    /// apply time (SEC-27); init no longer provisions a shared user.
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
    /// Output as JSON; secrets are redacted in BOTH formats. (F27)
    #[arg(long)]
    pub json: bool,
    /// Make exit code 2 mean "changes detected" (terraform plan parity).
    /// Without this flag, `ghars plan` always exits 0 regardless of
    /// whether the plan diff is empty. With it, a non-empty plan
    /// returns 2 — matches `ApplyArgs::detailed_exitcode` semantics
    /// for symmetry, and lets CI gating workflows ("apply iff plan
    /// shows changes") drop a redundant `ghars apply --dry-run
    /// --detailed-exitcode` pre-step. (#391)
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
    /// post-execution failures are stronger. (#464)
    #[arg(long)]
    pub detailed_exitcode_recreate: bool,
    /// Show full drop-in body content. Default off (pre-#285
    /// behavior, byte-identical). When set, each `Modified`
    /// drop-in renders as a unified text diff via
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
    /// stdout unless the operator opts in. (#461)
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
    /// preserved: 4 (partial) and 5 (auth) win over 8. (#464)
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
    /// itself uses the `ok:`/`fail:` shape regardless of `--diff`
    /// (#340 scope, not #285).
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
    fn from_cli(no_color_flag: bool) -> Self {
        let no_color_env = std::env::var_os("NO_COLOR").is_some();
        let stdout_tty = io::stdout().is_terminal();
        Self {
            enabled: !no_color_flag && !no_color_env && stdout_tty,
        }
    }
}

/// Map a top-level `GharsError` to its Part 5 process exit code
/// (#275 / #357).
///
/// Called by `main.rs` when `dispatch` returns `Err`. Extracted as a
/// pub function so the mapping can be unit-tested against every
/// variant without spawning a child process. (main.rs is a separate
/// `[[bin]]` target; the binary calls into the lib via `ghars::cli::`.)
///
/// Per-variant mapping (Part 5):
/// - `Config(_, _)`           → 6 (config parse / shape error)
/// - `Validation(_, _)`       → 6 (config-shape rejection: trust_zone
///   charset, duplicate caches, render_identity defense-in-depth —
///   operator must edit the TOML to recover, same actionable class
///   as Config)
/// - `Interactive(_, _)`      → 7 (#390: confirm_apply on non-TTY
///   stdin; distinct from 6 so wrapping scripts can branch on
///   "config is broken" vs "apply needs --auto-approve" without
///   parsing the error message)
/// - `Auth(_, _)`             → 5 (auth-resolve failure outside the
///   per-action accounting; same exit code per-action auth failures
///   route to via `apply_exit_code`)
/// - `Preflight(_, _)`        → 3 (preflight check failure; same
///   exit code cmd_apply / cmd_status emit via `Ok(3)`)
/// - `GitHub(_, _)`           → 1 (API error)
/// - `Systemd(_, _)`          → 1 (D-Bus / unit error)
/// - `Apply { .. }`           → 1 (should never reach here — apply
///   collects per-action failures into `ApplyResult` and routes
///   through `apply_exit_code`; this arm is the unreachable-by-design
///   safety net)
/// - `Io(_)`                  → 1 (filesystem)
/// - `Tarball(_)`             → 1 (extraction failure)
/// - `Sha256Mismatch { .. }`  → 1 (digest mismatch)
/// - `ApplyLocked { .. }`     → 1 (lock contention)
///
/// The mapping uses an exhaustive `match` (no wildcard) so any future
/// `GharsError` variant addition forces a compile error here, surfacing
/// the design decision at code-review time rather than silently
/// routing a new variant to the catch-all.
#[must_use]
pub fn err_to_exit_code(err: &GharsError) -> i32 {
    match err {
        GharsError::Config(_, _) => 6,
        GharsError::Validation(_, _) => 6,
        GharsError::Interactive(_, _) => 7,
        GharsError::Auth(_, _) => 5,
        GharsError::Preflight(_, _) => 3,
        GharsError::GitHub(_, _) => 1,
        GharsError::Systemd(_, _) => 1,
        GharsError::Apply { .. } => 1,
        GharsError::Io(_) => 1,
        GharsError::Tarball(_, _) => 1,
        GharsError::Sha256Mismatch { .. } => 1,
        GharsError::ApplyLocked { .. } => 1,
    }
}

/// Map (`--quiet`, `-v` count) → tracing-subscriber level filter
/// string. Pure function so the truth table is exhaustively testable.
///
/// Mapping:
/// - `quiet=true,  verbose=0` → "warn"  (suppress info-level chatter)
/// - `quiet=false, verbose=0` → "info"  (default)
/// - any verbose>=1           → "debug" / "trace" regardless of quiet
///
/// `-v` overrides `--quiet` when both are passed because the operator
/// who passed both is asking for MORE verbosity, not less. This
/// matches the convention of GNU coreutils (`tar -v --quiet`) and
/// rsync.
///
/// Used by `main.rs` to compose the `EnvFilter` fallback when
/// `RUST_LOG` is not set; RUST_LOG always wins when present.
#[must_use]
pub fn verbose_to_filter_level(quiet: bool, verbose: u8) -> &'static str {
    if quiet && verbose == 0 {
        return "warn";
    }
    match verbose {
        0 => "info",
        1 => "debug",
        _ => "trace",
    }
}

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
/// per-variant table (#275 + #357: Config / Validation → 6,
/// Auth → 5, Preflight → 3, every other variant → 1). Subcommand
/// handlers themselves return `Ok(N)` for non-success exits in the
/// per-command code-table (preflight = 3, partial apply = 4,
/// full-failure auth = 5, detailed-exitcode = 2 including the
/// cancel-with-`--detailed-exitcode` path per #358). Note that 4
/// wins over 5 when some actions succeeded — see the cmd_apply
/// tail (#251 ruling).
pub fn dispatch(cli: Cli) -> Result<i32> {
    let paths = Paths::default();
    let color = ColorMode::from_cli(cli.no_color);
    match cli.command {
        Command::Validate(args) => cmd_validate(&cli.config, &args, cli.quiet),
        Command::Plan(args) => cmd_plan(&cli.config, &paths, &args, color, cli.quiet),
        Command::Apply(args) => cmd_apply(&cli.config, &paths, &args, color, cli.quiet),
        Command::Status(args) => cmd_status(&cli.config, &paths, &args, color, cli.quiet),
        Command::Init(args) => cmd_init(&cli.config, &args, cli.quiet),
        Command::Add(args) => cmd_add(&cli.config, &paths, &args, color, cli.quiet),
        Command::Logs(args) => cmd_logs(&paths, &args),
        Command::Metrics(args) => cmd_metrics(&paths, &args),
        Command::Completions { shell } => {
            cmd_completions(shell);
            Ok(0)
        }
        Command::Manpages { output } => cmd_manpages(&output),
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

// ---------- Helpers ----------------------------------------------------

/// Load config.toml from `path` using `toml::from_str` +
/// `std::fs::read_to_string`. Mirrors the design's "config: load from
/// TOML path via `toml::from_str` + `std::fs::read_to_string`" guidance
/// for B5 — the library `config::load` is still a stub; the CLI does
/// the IO.
fn load_config(path: &Utf8Path) -> Result<Config> {
    let raw = fs::read_to_string(path.as_std_path()).map_err(|e| {
        GharsError::Config(
            format!("read {path}: {e}"),
            "ensure the config file exists and is readable".into(),
        )
    })?;
    let cfg: Config = toml::from_str(&raw).map_err(|e| {
        GharsError::Config(
            format!("parse {path}: {e}"),
            "fix the TOML syntax / schema; see `ghars validate`".into(),
        )
    })?;
    // SEC-30 + #283: deserialize-time serde validation only enforces
    // structural shape (#[serde(deny_unknown_fields)] + the typed
    // EgressRule fields). The semantic validators below live behind
    // post-load helpers — running them eagerly here means every CLI
    // entry point that calls load_config (cmd_validate, cmd_plan,
    // cmd_apply, cmd_status, cmd_add) gets the same gate. A missed
    // call site at any of them would re-introduce the corresponding
    // SEC attack surface (e.g. operator-controlled EgressRule.comment
    // with quote-breaking chars reaches render_nft_rules without going
    // through validate_egress_comment).
    //
    // build_auth_registry in cmd_validate / cmd_apply runs AFTER
    // load_config's full sweep: config-shape gates run before
    // external-IO / file-mode gates so an operator with both invalid
    // auth AND a config-validation failure addresses the structurally-
    // broken config first, then fixes auth.
    //
    // Each section below documents one validator. Order is
    // semantically meaningful and preserved across this section.
    //
    // --- validate_networks ---
    // SEC-30 (egress comment) + DNS / address-family shape.
    //
    // --- validate_security_overrides ---
    // SEC-01 (extra_capabilities / extra_bind_paths) + SEC-12 (hooks).
    // Conditionally filesystem-touching: when [hooks] or
    // [[runner]].hooks is set, validate_hook_script opens the script
    // with O_NOFOLLOW and inspects mode / uid. With no hooks
    // configured, the validator is shape-only.
    //
    // --- validate_identity_fields ---
    // #344/#346 trust_zone control-char rejection.
    //
    // --- validate_no_duplicate_caches ---
    // #370 dedup-loop trap.
    //
    // --- validate_cache_pool_names ---
    // #402 + #407 length cap (pool keys + runner.caches refs).
    //
    // --- validate_runner_names ---
    // #427 length cap (derived ghars-{name} system user).
    //
    // --- validate_user_overrides ---
    // #434 length + charset cap on operator-supplied User= values.
    //
    // --- validate_prefix_overrides ---
    // #591 charset / traversal / reserved-root / symlink gate on
    // operator-supplied `[defaults.prefix]` and per-runner `prefix`
    // paths. The pure-string checks (regex, `..`, reserved-root) fire
    // before the lstat, so a hostile string fails fast without
    // filesystem touch — but the lstat itself does touch the
    // filesystem when the pure-string checks pass.
    //
    // --- validate_pat_xor ---
    // #613 AuthSpec::Pat shape-only XOR check on token_env /
    // token_file (re-validated by PatToken::new at apply). Shape-only
    // (no filesystem access). PatToken::new runs SEC-25 (mode / owner
    // / symlink) at apply.
    //
    // --- validate_runner_tarballs ---
    // #349 lstat / regular-file gate on operator-supplied
    // runner_tarball paths. Filesystem-touching (alongside
    // validate_prefix_overrides, and validate_security_overrides
    // when hooks are configured). Placed after the pure-shape /
    // length-cap gates so an operator hitting a typo in
    // [defaults.user] sees that error before a separate "tarball
    // missing" error from a per-runner override.
    //
    // --- validate_netns_runner_name_lengths ---
    // #432 IFNAMSIZ (kernel veth name) cap (= NETNS_RUNNER_NAME_MAX_LEN,
    // 7) on operator-chosen runner names whose effective network mode
    // resolves to Netns. Runs LAST because it depends on
    // validate_networks having already accepted the [network.NAME] map
    // shape — an unresolved network key here falls through (the
    // validate_networks gate will have surfaced the error) so we don't
    // double-report. Skipped for Open-mode runners which don't allocate
    // a veth pair.
    crate::config::validate_networks(&cfg)?;
    validate_security_overrides(&cfg)?;
    validate_identity_fields(&cfg)?;
    validate_no_duplicate_caches(&cfg)?;
    validate_cache_pool_names(&cfg)?;
    validate_runner_names(&cfg)?;
    validate_user_overrides(&cfg)?;
    validate_prefix_overrides(&cfg)?;
    validate_auth_keys(&cfg)?;
    validate_pat_xor(&cfg)?;
    validate_runner_tarballs(&cfg)?;
    validate_netns_runner_name_lengths(&cfg)?;
    Ok(cfg)
}

/// Build the auth registry — one `TokenSource` per `[auth.NAME]` block.
/// Each source is constructed eagerly so `validate --deep` and `apply`
/// surface env / file-mode misconfiguration before any GitHub call.
fn build_auth_registry(
    auth: &indexmap::IndexMap<String, AuthSpec>,
) -> Result<HashMap<String, Box<dyn TokenSource>>> {
    let mut out: HashMap<String, Box<dyn TokenSource>> = HashMap::with_capacity(auth.len());
    for (name, spec) in auth {
        out.insert(name.clone(), build_token_source(spec, name)?);
    }
    Ok(out)
}

// ---------- security-override validators (SEC-01, SEC-12) ---------------

/// Run SEC-01 + SEC-12 validators across the [defaults] block and every
/// `[[runner]]` block.
///
/// SEC-01 — `Hardening.extra_capabilities` and
/// `Hardening.extra_bind_paths` go through the deny-list validators
/// in `validators::validate_extra_capabilities` /
/// `validators::validate_extra_bind_paths`. Both `[defaults.hardening]`
/// and per-runner `[[runner]].hardening` are checked; a value at
/// either layer that hits a deny entry rejects the entire config.
///
/// SEC-12 — `HooksSpec.pre_job` and `post_job` go through
/// `validators::validate_hook_script` which lstat's the path and
/// rejects symlinks, non-files, mode missing owner-execute, or
/// ownership != root.
///
/// Defaults are validated FIRST so a denied default surfaces with the
/// `[defaults]` label instead of being attributed to whichever runner
/// inherited it. Runners are walked in source order; the first
/// failure short-circuits.
///
/// # Errors
///
/// `GharsError::Validation` wrapping the underlying validator error.
/// The wrapper prepends `"defaults: "` or `"runner NAME: "` so the
/// operator can locate the offending block in their TOML.
fn validate_security_overrides(cfg: &Config) -> Result<()> {
    // [defaults.hardening]
    validate_hardening_block(&cfg.defaults.hardening)
        .map_err(|e| crate::error::prepend_validation_scope("defaults", e))?;
    // [defaults.hooks]
    if let Some(hooks) = cfg.hooks.as_ref() {
        validate_hooks_block(hooks)
            .map_err(|e| crate::error::prepend_validation_scope("hooks", e))?;
    }

    for runner in &cfg.runners {
        let scope = format!("runner {:?}", runner.name);
        validate_hardening_block(&runner.hardening)
            .map_err(|e| crate::error::prepend_validation_scope(&scope, e))?;
        if let Some(hooks) = runner.hooks.as_ref() {
            validate_hooks_block(hooks)
                .map_err(|e| crate::error::prepend_validation_scope(&scope, e))?;
        }
    }
    Ok(())
}

fn validate_hardening_block(h: &Hardening) -> Result<()> {
    validators::validate_extra_capabilities(&h.extra_capabilities)?;
    validators::validate_extra_bind_paths(&h.extra_bind_paths)?;
    Ok(())
}

fn validate_hooks_block(h: &HooksSpec) -> Result<()> {
    if let Some(pre) = h.pre_job.as_ref() {
        validators::validate_hook_script(pre.as_path())?;
    }
    if let Some(post) = h.post_job.as_ref() {
        validators::validate_hook_script(post.as_path())?;
    }
    Ok(())
}

// ---------- duplicate-cache validator (#370) ----------------------------

/// Reject `[[runner]] caches = ["a", "a"]` at config load. A duplicate
/// in the source `Vec<String>` would render two identical
/// `X-Ghars-Caches=` entries (X-Ghars-Caches is a comma-joined CSV
/// emitted in `render_identity`) and would trigger an in-place
/// spec-hash bump every time the apply path canonicalizes the
/// bindings into a BTreeSet. Catching the duplicate at load time
/// gives the operator a scoped error (`runner "NAME": ...`) instead
/// of a confusing drift loop.
///
/// The runner's index in `cfg.runners` is the iteration order; first
/// duplicate found inside a single `[[runner]]` block aborts the
/// validator. Cross-runner reuse of the same pool is fine — pools
/// are explicitly designed to be referenced by multiple runners
/// (`CacheMode::Shared` is `CachePoolSpec.mode`'s `#[default]`).
///
/// # Errors
///
/// `GharsError::Validation` naming the runner and the duplicated pool
/// name. The hint tells the operator to remove the duplicate entry.
fn validate_no_duplicate_caches(cfg: &Config) -> Result<()> {
    for runner in &cfg.runners {
        let mut seen: HashSet<&str> = HashSet::with_capacity(runner.caches.len());
        for cache in &runner.caches {
            if !seen.insert(cache.as_str()) {
                return Err(GharsError::Validation(
                    format!(
                        "runner {:?}: duplicate cache pool reference {cache:?} in caches list",
                        runner.name
                    ),
                    "remove the duplicate entry from [[runner]].caches; pools may be \
                     referenced from multiple runners but never twice from one"
                        .into(),
                ));
            }
        }
    }
    Ok(())
}

// ---------- cache-pool-name length cap (#402, #407) ---------------------

/// Reject `[cache_pools.NAME]` keys and `[[runner]] caches = [...]`
/// entries whose length would push the derived group name
/// `"ghars-cache-{name}"` past systemd's 31-char limit.
/// `apply::cache_pool_group` produces the group, and `apply.rs`
/// invokes `groupadd` / `usermod -aG` against it during
/// `execute_create_runner`. Without this gate, an operator-chosen
/// oversize pool key would fail at apply time with an opaque
/// `groupadd: name too long` error and a half-applied state. Catching
/// at config load surfaces a scoped error (`cache_pool "NAME": ...`
/// or `runner "NAME" caches[]: ...`) before any side effects.
///
/// #407 defense-in-depth: runner.caches Vec entries are also validated
/// here. The plan-time cross-reference in `plan::lower_to_effective`
/// matches the entry against `cfg.cache_pools.keys()`, so an unknown
/// `> CACHE_POOL_NAME_MAX_LEN`-char string normally fails at "unknown
/// cache pool" before the length cap matters. But a future code path
/// that synthesizes an EffectiveCacheBinding without round-tripping
/// through that lookup would let an oversize string slip past —
/// usermod -aG would then fail mid-apply with a half-applied
/// groupadd. Validating both surfaces here closes that gap
/// pre-emptively.
///
/// # Errors
///
/// `GharsError::Validation` wrapping `validators::validate_cache_pool_name`
/// with the `cache_pool "NAME":` or `runner "NAME" caches[]:` scope prefix.
fn validate_cache_pool_names(cfg: &Config) -> Result<()> {
    for name in cfg.cache_pools.keys() {
        let scope = format!("cache_pool {name:?}");
        validators::validate_cache_pool_name(name)
            .map_err(|e| crate::error::prepend_validation_scope(&scope, e))?;
    }
    // #407: validate every runner.caches entry. The cross-reference
    // check in plan_from rejects unknown names ("unknown cache pool"),
    // but that error fires at plan time and is shape-agnostic — an
    // oversize entry that also happens to match a (hypothetical)
    // oversize pool key is the case `validate_cache_pool_name` is
    // designed to reject before plan_from is even reached.
    for runner in &cfg.runners {
        for cache in &runner.caches {
            let scope = format!("runner {:?} caches[]", runner.name);
            validators::validate_cache_pool_name(cache)
                .map_err(|e| crate::error::prepend_validation_scope(&scope, e))?;
        }
    }
    Ok(())
}

// ---------- runner-name length cap (#427) -------------------------------

/// Reject `[[runner]] name = "..."` keys whose length would push the
/// derived system user `"ghars-{name}"` past systemd's strict-mode name
/// limit. `plan::merge_defaults` produces the user as
/// `"{RUNNER_USER_PREFIX}{name}"` when no explicit `user =` override is
/// set, and `apply.rs` invokes `useradd` / `usermod` against it during
/// `execute_create_runner`. Without this gate, an operator-chosen
/// oversize runner name would fail at apply time with an opaque
/// `useradd: name too long` error and a half-applied state. Catching at
/// config load surfaces a scoped error (`runner "NAME": ...`) before
/// any side effects.
///
/// # Errors
///
/// `GharsError::Validation` wrapping `validators::validate_runner_name`
/// with the `runner "NAME":` scope prefix.
fn validate_runner_names(cfg: &Config) -> Result<()> {
    for runner in &cfg.runners {
        let scope = format!("runner {:?}", runner.name);
        validators::validate_runner_name(&runner.name)
            .map_err(|e| crate::error::prepend_validation_scope(&scope, e))?;
    }
    Ok(())
}

// ---------- user-override length + charset cap (#434) -------------------

/// Reject `[defaults] user = "..."` and `[[runner]] user = "..."` values
/// that would push systemd's strict-mode `valid_user_group_name` check
/// (src/basic/user-util.c:824) over its 31-char cap, or that contain
/// any character outside the Linux user-name charset.
///
/// `validate_user` (validators::validate_user) enforces both gates: an
/// explicit length check above [`validators::USER_MAX_LEN`] and the
/// regex `^[a-z_][a-z0-9_-]{0,30}$`. Without this load-time validator,
/// the rendered runner template emits `User=<value>` and systemd
/// refuses unit load with an opaque error during apply. Catching at
/// load gives the operator a scoped diagnostic (`defaults: ...` /
/// `runner "NAME": ...`) before any side effect.
///
/// Both surfaces are validated even though most operators omit `user`
/// (per-runner `ghars-{name}` derivation is the secure default per
/// SEC-27): a single explicit override at either layer reaches
/// `merge_defaults` and the renderer.
///
/// # Errors
///
/// `GharsError::Validation` wrapping the underlying `validate_user`
/// error with the `defaults:` or `runner "NAME":` scope prefix.
fn validate_user_overrides(cfg: &Config) -> Result<()> {
    if let Some(u) = cfg.defaults.user.as_deref() {
        validators::validate_user(u)
            .map_err(|e| crate::error::prepend_validation_scope("defaults", e))?;
    }
    for runner in &cfg.runners {
        if let Some(u) = runner.user.as_deref() {
            let scope = format!("runner {:?}", runner.name);
            validators::validate_user(u)
                .map_err(|e| crate::error::prepend_validation_scope(&scope, e))?;
        }
    }
    Ok(())
}

/// #591: gate `defaults.prefix` and per-runner `prefix` overrides
/// through `validators::validate_prefix` at config-load time. The
/// validator already exists (`validators::validate_prefix`) and
/// rejects empty input, disallowed charset, `..` traversal segments,
/// top-level reserved directories, and symlinks — but no caller wired
/// it into the config-load pipeline before this fix, so an
/// operator-supplied hostile prefix (control chars, traversal,
/// reserved root) flowed straight to `merge_defaults` and downstream
/// `Paths` construction.
///
/// Defense-in-depth: the path-charset rejection here covers prefix
/// values that later participate in `UndoStep::WriteFile` describe()
/// output (sanitized in #552) and any future code that joins
/// `<prefix>/<name>/...` into shell-visible diagnostics. The
/// renderer-side scrubs are the last line of defense — the validator
/// is the first.
///
/// # Errors
///
/// `GharsError::Validation` wrapping the underlying `validate_prefix`
/// error with the `defaults:` or `runner "NAME":` scope prefix.
fn validate_prefix_overrides(cfg: &Config) -> Result<()> {
    if let Some(p) = cfg.defaults.prefix.as_ref() {
        validators::validate_prefix(p.as_str())
            .map_err(|e| crate::error::prepend_validation_scope("defaults", e))?;
    }
    for runner in &cfg.runners {
        if let Some(p) = runner.prefix.as_ref() {
            let scope = format!("runner {:?}", runner.name);
            validators::validate_prefix(p.as_str())
                .map_err(|e| crate::error::prepend_validation_scope(&scope, e))?;
        }
    }
    Ok(())
}

/// POSIX-portable shell environment variable name shape, with the
/// common bash/zsh extension that permits lowercase letters.
///
/// IEEE Std 1003.1-2017 strictly limits portable name characters to
/// ASCII uppercase letters, digits, and underscores, with the first
/// character not a digit. Mainstream shells (bash, zsh, dash, ksh)
/// accept lowercase letters in practice, and operator configs
/// frequently use mixed case. The regex below allows lowercase to
/// match operator expectation; the portability-strict subset
/// (uppercase only) is a runtime concern of whatever consumes
/// `std::env::var`, not a config-load shape gate. `validate_pat_xor`
/// rejects `token_env` values that don't match — values that pass
/// the trim/whitespace gate but cannot be looked up because no
/// portable shell exports the name, so apply surfaces a misleading
/// "env var unset" diagnostic (`std::env::var` returns `NotPresent`)
/// on inputs like embedded whitespace, dashes, or other punctuation.
static POSIX_ENV_VAR_NAME_RE: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r"^[A-Za-z_][A-Za-z0-9_]*$")
        .expect("POSIX env var name regex is a compile-time constant")
});

/// Hints reused by every `validate_pat_xor` rejection arm so the
/// canonical example value (`GHARS_PAT` / `/etc/ghars/pat`) appears
/// in operator output regardless of which gate fires first.
const TOKEN_ENV_HINT: &str =
    "set token_env to the name of an environment variable holding the PAT \
     (e.g. token_env = \"GHARS_PAT\"), or remove the field";
const TOKEN_FILE_HINT: &str =
    "set token_file to the absolute path of a 0600 root-owned file holding \
     the PAT (e.g. token_file = \"/etc/ghars/pat\"), or remove the field";

/// #659: returns true for characters disallowed inside non-empty
/// `token_env` / `token_file` values — characters that survive the
/// trim/whitespace gate but break apply-time lookups (`std::env::var`
/// returning `NotPresent` on a name with an embedded BOM, `open(2)`
/// failing on a path with an embedded NUL, etc.). Three classes:
///   - explicit codepoints (#659/#672): NUL (U+0000), SOFT HYPHEN
///     (U+00AD), Arabic Letter Mark (U+061C), Mongolian Vowel
///     Separator (U+180E), the ZWSP/ZWNJ/ZWJ/LRM/RLM block
///     (U+200B..=U+200F), the bidi embedding controls including
///     LRO/RLO/PDF (U+202A..=U+202E — the Trojan Source attack
///     vector, Boucher & Anderson 2021), the WJ + invisible math
///     operators block (U+2060..=U+2064), bidi isolates LRI/RLI/FSI/
///     PDI (U+2066..=U+2069), and BOM (U+FEFF). These render
///     invisibly in operator terminals and would survive a copy-paste
///     from a docs site that injected them as formatting. NUL
///     belongs to general-category Cc (and is also caught by the
///     `is_control()` arm below); listing it explicitly keeps the
///     diagnostic tight on the well-known invisible chars even if a
///     future regression narrows the control-char arm.
///   - ALL control chars (`char::is_control()`) — #676 dropped the
///     prior `\t` `\n` `\r` carve-out. Pre-#676 those three were
///     whitelisted on the speculative grounds that paths or env-var
///     names might contain them. Unix permits these chars in paths,
///     but PAT-token deployment paths never legitimately contain
///     them: PAT tokens are small static credentials and their
///     declared paths/env-var names are operator-authored config
///     identifiers, not arbitrary Unix file names. Rejecting all Cc
///     chars in both fields closes the gap that an embedded `\n` in
///     token_file would survive every other shape gate.
///   - ALL Mn-class combining marks (#678): Mn-class combining marks
///     (Unicode NonspacingMark) are rejected uniformly — they can
///     produce visually deceptive paths via combining diacritical
///     marks that overlay ASCII characters. Token paths are
///     operator-authored config identifiers, not arbitrary file
///     paths; operators with internationalized paths should use
///     precomposed (NFC) forms. This subsumes the prior explicit
///     entries for Combining Grapheme Joiner (U+034F) and variation
///     selectors VS1..=VS16 (U+FE00..=U+FE0F), which are all Mn.
///
/// `char::is_control()` covers the Unicode general-category Cc class
/// (ASCII 0x00-0x1F + 0x7F + various U+0080-U+009F C1 controls); the
/// explicit list adds Cf-class default-ignorables (SHY, ALM, MVS, the
/// ZWSP/ZWNJ/ZWJ/LRM/RLM/bidi-control blocks, WJ + invisible math
/// operators, bidi isolates, BOM); the Mn-class arm covers all
/// combining marks (NonspacingMark) — none of which are in Cc.
fn is_disallowed_hidden_char(c: char) -> bool {
    matches!(
        c,
        '\u{0000}'
            | '\u{00AD}'
            | '\u{061C}'
            | '\u{180E}'
            | '\u{200B}'..='\u{200F}'
            | '\u{202A}'..='\u{202E}'
            | '\u{2060}'..='\u{2064}'
            | '\u{2066}'..='\u{2069}'
            | '\u{FEFF}'
    ) || c.is_control()
        || get_general_category(c) == GeneralCategory::NonspacingMark
}

/// #613: walk every `[auth.NAME]` entry and, for `AuthSpec::Pat`,
/// reject configurations that violate the documented XOR invariant
/// (config.rs:481, auth.rs:286): exactly one of `token_env` /
/// `token_file` MUST be set. `PatToken::new` re-validates this at
/// apply time.
///
/// Wiring landscape — which CLI commands previously caught the
/// violation, and which silently accepted misconfigured PAT entries:
///   - `cmd_validate` and `cmd_apply` unconditionally call
///     `build_auth_registry`, which constructs every `PatToken`
///     eagerly — these would ALREADY surface the XOR error before
///     this gate existed (note: `--deep` only gates the
///     registration-token MINT step, not auth construction).
///   - `cmd_plan`, `cmd_status`, and `cmd_add` do NOT call
///     `build_auth_registry`; without this gate, they accepted
///     misconfigured `[auth.NAME]` entries and the failure first
///     surfaced at apply time, by which point state may already
///     have changed (`ghars plan` printed an Ok plan that would
///     immediately fail `ghars apply`).
///
/// Wiring at `load_config` means every entry point sees the same
/// gate uniformly — the gate is load-bearing for cmd_plan /
/// cmd_status / cmd_add, redundant-but-harmless for cmd_validate /
/// cmd_apply (the registry construction would catch it anyway).
///
/// This is a SHAPE-ONLY check. It does NOT lstat `token_file` —
/// `PatToken::new` runs the SEC-25 mode-0600 + owner-root + not-
/// symlink check at apply time, where the file is actually read.
/// Splitting the responsibilities: config-load rejects mis-shaped
/// AuthSpec entries; apply rejects badly-permissioned token files.
///
/// What "mis-shaped" means here:
///   - Both `token_env` AND `token_file` set: violates the XOR
///     invariant.
///   - Neither set: violates the "exactly one" invariant.
///   - `token_env` empty / whitespace-only / hidden-char-bearing /
///     leading-or-trailing-whitespace / not a POSIX env var name:
///     shape-valid TOML but useless — `std::env::var` would either
///     return `NotPresent` or look up the wrong name and surface
///     deep in apply as a confusing "env var unset" error after
///     partial state has changed.
///   - `token_file` empty / whitespace-only / hidden-char-bearing /
///     leading-or-trailing-whitespace: shape-valid TOML but useless
///     — `Utf8PathBuf::from("")` is empty, a whitespace-only path
///     fails at `open(2)` with a confusing "no such file" message,
///     and a path with edge whitespace looks correct in error output
///     but fails the open at a literal-space basename. The empty
///     check fires first so `" "` rejects with the empty-or-
///     whitespace diagnostic (more informative than "leading
///     whitespace"); the hidden-char check fires next so an embedded
///     BOM or NUL surfaces a codepoint+offset diagnostic; the
///     trim-mismatch check fires last so a real path with extra
///     edge spaces surfaces with a path-shape diagnostic.
///
/// Gate ordering for each field (independent — each field walks the
/// sequence on its own value, with no cross-field interaction):
///   1. trim().is_empty() — empty / all-whitespace.
///   2. hidden-char scan (#659) — surface byte offset + codepoint.
///      Fires BEFORE the edge-whitespace and shape checks so an
///      embedded BOM in a value that would also fail trim-mismatch
///      or charset surfaces as a hidden-char diagnostic (more
///      actionable than the downstream check).
///   3. trim-mismatch on BOTH fields — value is non-empty and
///      contains no hidden chars but its edges carry whitespace.
///      token_env's #669 fires here; token_file's #660 fires here.
///      Both produce "leading or trailing whitespace". Fires BEFORE
///      the POSIX charset gate so `"X "` / `" X"` surface as
///      whitespace-mismatch rather than the less-specific "POSIX env
///      var name" diagnostic.
///   4. POSIX charset (#658) — token_env only. Catches dashes, dots,
///      embedded whitespace, and other punctuation that pass the
///      trim/hidden/edge gates but break env var name shape.
///      token_file has no analogous step-4 gate; filesystem paths
///      accept arbitrary printable bytes so the trim-mismatch step
///      is the last domain check.
/// The XOR tuple-match at the end fires only when BOTH fields'
/// per-field gates pass — it catches (true,true) when both fields
/// are present and shape-valid, and (false,false) when neither is
/// set. A misconfigured per-field value short-circuits before the
/// tuple-match is reached.
///
/// Other AuthSpec variants (`GithubApp`, `Interactive`, `TokenFile`)
/// have no XOR shape to validate; they are accepted without validation.
///
/// # Errors
///
/// `GharsError::Validation` wrapping a hint specific to the offending
/// field — empty/whitespace, mutual-exclusivity, or missing-field —
/// scoped to `[auth.NAME]`.
fn validate_pat_xor(cfg: &Config) -> Result<()> {
    for (name, spec) in &cfg.auth {
        if let AuthSpec::Pat {
            token_env,
            token_file,
        } = spec
        {
            let scope = format!("auth {name:?}");
            // Three diagnostic forms: empty/whitespace, Mn combining-mark with NFC hint, Cf/Cc hidden-char.
            let check_empty_or_hidden = |val: &str, field: &str, hint: &str| -> Result<()> {
                if val.trim().is_empty() {
                    return Err(crate::error::prepend_validation_scope(
                        &scope,
                        GharsError::Validation(
                            format!("{field} is empty or whitespace-only"),
                            hint.into(),
                        ),
                    ));
                }
                // #659: hidden default-ignorable / control characters
                // pass the trim/whitespace check but surface as
                // confusing apply-time errors (env::var lookup
                // mismatch, open(2) ENOENT on a path with embedded
                // BOM, etc.). Surface byte offset + codepoint so the
                // operator can locate the invisible char in their
                // editor. #694: Mn-class combining marks (Unicode
                // NonspacingMark — U+0300 family + variation
                // selectors + CGJ) get a dedicated diagnostic
                // suggesting precomposed (NFC) forms instead of the
                // generic "hidden character" framing — the
                // remediation differs from removing a stray BOM /
                // ZWSP.
                if let Some((idx, ch)) = val
                    .char_indices()
                    .find(|(_, c)| is_disallowed_hidden_char(*c))
                {
                    let msg = if get_general_category(ch) == GeneralCategory::NonspacingMark {
                        // CGJ + variation selectors (incl. supplement) are Mn but have no NFC form; route to "remove" advice.
                        if matches!(
                            ch,
                            '\u{034F}' | '\u{FE00}'..='\u{FE0F}' | '\u{E0100}'..='\u{E01EF}'
                        ) {
                            format!(
                                "{field} contains a disallowed combining mark \
                                 U+{codepoint:04X} at byte offset {idx}; remove the \
                                 codepoint (no precomposed equivalent exists)",
                                codepoint = ch as u32,
                            )
                        } else {
                            format!(
                                "{field} contains a disallowed combining mark \
                                 U+{codepoint:04X} at byte offset {idx}; remove the \
                                 codepoint, or use the precomposed (NFC) form if \
                                 the character was intentional",
                                codepoint = ch as u32,
                            )
                        }
                    } else {
                        format!(
                            "{field} contains a disallowed hidden character \
                             U+{codepoint:04X} at byte offset {idx}",
                            codepoint = ch as u32,
                        )
                    };
                    return Err(crate::error::prepend_validation_scope(
                        &scope,
                        GharsError::Validation(msg, hint.into()),
                    ));
                }
                Ok(())
            };

            if let Some(env) = token_env.as_deref() {
                check_empty_or_hidden(env, "token_env", TOKEN_ENV_HINT)?;
                // #669: leading / trailing whitespace on real content
                // (e.g. `"X "`, `" X"`, `" X "`) rejects with a
                // dedicated diagnostic before the POSIX charset gate.
                // Pre-#669 these inputs fell through to the POSIX
                // gate, which surfaced "is not a valid POSIX
                // environment variable name" — technically correct
                // but misleading: the operator's intent was almost
                // certainly a shell-quoting hiccup, not a charset
                // violation. The dedicated diagnostic names the
                // condition. This fires only for non-empty values
                // (trim-empty already short-circuited inside
                // check_empty_or_hidden) whose edges carry extra
                // whitespace.
                if env != env.trim() {
                    return Err(crate::error::prepend_validation_scope(
                        &scope,
                        GharsError::Validation(
                            format!("token_env {env:?} has leading or trailing whitespace"),
                            TOKEN_ENV_HINT.into(),
                        ),
                    ));
                }
                // #658: POSIX env var name charset. Values that pass
                // the trim/hidden-char/edge-whitespace gates but
                // contain dashes, dots, embedded whitespace, or
                // other punctuation would either fail `std::env::var`
                // outright or look up an unrelated name.
                if !POSIX_ENV_VAR_NAME_RE.is_match(env) {
                    return Err(crate::error::prepend_validation_scope(
                        &scope,
                        GharsError::Validation(
                            format!(
                                "token_env {env:?} is not a valid POSIX environment variable name \
                                 (must start with a letter or underscore and contain only ASCII \
                                 letters, digits, and underscores)"
                            ),
                            TOKEN_ENV_HINT.into(),
                        ),
                    ));
                }
            }

            if let Some(path) = token_file.as_ref() {
                let path_str = path.as_str();
                check_empty_or_hidden(path_str, "token_file", TOKEN_FILE_HINT)?;
                // #660: leading / trailing whitespace on a real path
                // (e.g. `" /etc/ghars/pat"`, `"/etc/ghars/pat "`,
                // `" /etc/ghars/pat "`) would surface as `open(2)`
                // ENOENT on a literal-space basename. Reject here
                // with an actionable diagnostic that names the
                // condition. trim()-empty already short-circuited;
                // this fires only for non-empty values whose edges
                // carry extra whitespace.
                if path_str != path_str.trim() {
                    return Err(crate::error::prepend_validation_scope(
                        &scope,
                        GharsError::Validation(
                            format!("token_file {path_str:?} has leading or trailing whitespace"),
                            "remove leading and trailing whitespace from the path to a 0600 \
                             root-owned file holding the PAT (e.g. token_file = \
                             \"/etc/ghars/pat\")"
                                .into(),
                        ),
                    ));
                }
            }

            // #624: error messages omit the "kind = \"pat\":" prefix —
            // `prepend_validation_scope` already adds the
            // `auth "NAME"` scope which identifies the offending block,
            // and `AuthSpec::Pat` is the only variant the loop checks.
            // #663: every hint arm names a concrete example value
            // (GHARS_PAT / /etc/ghars/pat) so an operator reading the
            // (true,true) or (false,false) error gets the same
            // remediation breadcrumb the empty-string / charset arms
            // already provide.
            match (token_env.is_some(), token_file.is_some()) {
                (true, true) => {
                    return Err(crate::error::prepend_validation_scope(
                        &scope,
                        GharsError::Validation(
                            "token_env and token_file are mutually exclusive".into(),
                            "remove one — set token_env (read PAT from env, e.g. \
                             token_env = \"GHARS_PAT\") OR token_file (read PAT from a \
                             0600 root-owned file, e.g. token_file = \"/etc/ghars/pat\"), \
                             never both"
                                .into(),
                        ),
                    ));
                }
                (false, false) => {
                    return Err(crate::error::prepend_validation_scope(
                        &scope,
                        GharsError::Validation(
                            "exactly one of token_env / token_file is required".into(),
                            "set token_env (read PAT from env, e.g. token_env = \"GHARS_PAT\") \
                             OR token_file (read PAT from a 0600 root-owned file, e.g. \
                             token_file = \"/etc/ghars/pat\")"
                                .into(),
                        ),
                    ));
                }
                _ => {}
            }
        }
    }
    Ok(())
}

/// #673: walk every `[auth.NAME]` key and gate it through
/// `validators::validate_identifier` (config.rs:24-27 documents the
/// regex as shared by runner names, auth keys, cache pool keys, and
/// network keys). Auth keys are user-chosen identifiers that flow
/// into:
///   - the auth-name → `TokenSource` map (`build_auth_registry`);
///   - error scopes via `prepend_validation_scope("auth {name:?}", ...)`,
///     where bizarre keys could surface as confusing
///     `auth "FOO BAR\n!!!": ...` diagnostics;
///   - operator-visible configuration in TOML editors, where a key
///     containing whitespace or punctuation would be hard to
///     reference from `[[runner]] auth = "NAME"`.
///
/// Without this gate, `[auth.NAME]` keys could be any TOML bare-key-
/// or-quoted-string shape — far broader than IDENTIFIER_REGEX. Wiring
/// at `load_config` means cmd_validate / cmd_plan / cmd_apply /
/// cmd_status / cmd_add all see the same gate, matching the existing
/// pattern for runner / cache pool / network names.
///
/// # Errors
///
/// `GharsError::Validation` wrapping the underlying `validate_identifier`
/// error with the `auth "NAME"` scope prefix.
fn validate_auth_keys(cfg: &Config) -> Result<()> {
    for name in cfg.auth.keys() {
        let scope = format!("auth {name:?}");
        validators::validate_identifier(name)
            .map_err(|e| crate::error::prepend_validation_scope(&scope, e))?;
    }
    Ok(())
}

/// #349: walk every `[[runner]] runner_tarball = "..."` and gate the
/// path through `validators::validate_runner_tarball`. The validator
/// lstats the path, rejects symlinks, and rejects non-regular files —
/// the same shape `extract::install_runner_binary` requires before
/// extraction. Wiring it into `load_config` means cmd_validate /
/// cmd_plan / cmd_apply / cmd_status / cmd_add all see the same gate;
/// the prior surface where the validator existed but was never called
/// (#349) had no callsite.
///
/// `defaults.runner_tarball` does NOT exist in the schema — see
/// `config::Defaults` (only auth / prefix / user / labels / arch /
/// hardening / proxy / hooks live at defaults level). Per-runner is
/// the only surface walked here.
///
/// `runner_tarball` on RunnerSpec is `Option<Utf8PathBuf>`. We forward
/// the infallible `as_str()` view to the validator — Utf8PathBuf is
/// UTF-8 by construction (the wrapper rejects non-UTF-8 input at
/// construction time), so the conversion never loses data.
///
/// # Errors
///
/// `GharsError::Validation` wrapping the underlying validator error
/// with the `runner "NAME"` scope prefix.
fn validate_runner_tarballs(cfg: &Config) -> Result<()> {
    for runner in &cfg.runners {
        if let Some(p) = runner.runner_tarball.as_ref() {
            let scope = format!("runner {:?}", runner.name);
            validators::validate_runner_tarball(p.as_str())
                .map_err(|e| crate::error::prepend_validation_scope(&scope, e))?;
        }
    }
    Ok(())
}

// ---------- netns runner-name length cap (#432) -------------------------

/// #432: reject runner names whose rendered veth interface name
/// `"ghars-{name}-h"` would exceed the kernel's `IFNAMSIZ - 1 = 15`
/// limit (`net/core/dev.c:dev_valid_name`). The hard cap on the
/// operator-controlled `{name}` segment is
/// [`validators::NETNS_RUNNER_NAME_MAX_LEN`] (= 7) — see
/// `validators.rs` for the kernel source citation and the
/// const-derivation chain.
///
/// Only runners whose effective network mode resolves to `Netns`
/// face this cap. Open-mode runners do not allocate a veth pair, so
/// they inherit only the global `RUNNER_NAME_MAX_LEN` cap derived
/// from systemd's strict-mode user-name limit. Effective network
/// mode is computed via the documented inheritance chain (Part 3 /
/// `plan::merge_defaults`):
///   1. `runner.network` (Some) → use that network key.
///   2. else `defaults.network` (Some) → use that network key.
///   3. else implicit Open mode (no [network.NAME] reference) — skip
///      the cap.
/// When the resolved key exists in `cfg.networks`, we check
/// `mode == Netns`. An unresolved key does NOT short-circuit the
/// gate here — `validate_networks` (validator #1) is responsible
/// for surfacing the unknown-network error; the lookup miss in this
/// validator falls through to "no netns gating" so a single
/// rejection (the unknown key) surfaces without piggybacking an
/// unrelated length-cap error.
///
/// For count blocks (`[[runner]] count = N`) the rendered veth
/// instance is `{name}-{i}` for `i in 1..=N`. The worst-case
/// instance length is `name.len() + 1 + count.to_string().len()`
/// (the `+1` is the literal '-' between prefix and index). We cap
/// the worst case rather than every expansion individually so the
/// gate is O(runners) not O(runners + total expanded count).
///
/// # Errors
///
/// `GharsError::Validation` wrapping a message naming both the
/// `IFNAMSIZ` source and the actual oversize length, with the
/// `runner "NAME":` scope prefix.
fn validate_netns_runner_name_lengths(cfg: &Config) -> Result<()> {
    use crate::config::NetworkMode;
    for runner in &cfg.runners {
        // Resolve effective network reference: per-runner override
        // wins over [defaults] (Part 3 merge table). None at both
        // layers ≡ implicit Open mode → no veth, no cap.
        let net_key = runner
            .network
            .as_deref()
            .or(cfg.defaults.network.as_deref());
        let Some(key) = net_key else { continue };
        // Look up the [network.NAME] block. A missing key here means
        // validate_networks (validator #1) will reject upstream — we
        // skip this runner so we don't double-report the unknown-
        // network error with an irrelevant length cap. (validate_
        // networks runs first so in practice load_config's
        // short-circuit hits that error before we get here.)
        let Some(spec) = cfg.networks.get(key) else {
            continue;
        };
        if !matches!(spec.mode, NetworkMode::Netns) {
            continue;
        }
        // count = Some(0) is a no-op in `plan::expand_counts` — the
        // planner emits ZERO instances for that block, so no veth is
        // ever allocated. Skip the gate entirely; otherwise we'd
        // false-reject configs that the planner would expand to
        // nothing.
        if matches!(runner.count, Some(0)) {
            continue;
        }
        // Worst-case expanded instance length. The semantics here
        // mirror `plan::is_count_block` exactly: `count >= 2` is the
        // ONLY shape that produces multi-instance `{name}-{i}`
        // expansion. `count = None` and `count = Some(1)` both keep
        // the bare name (no suffix). Treating those two cases as
        // "no suffix" prevents false rejections of bare-name
        // configs that the planner would happily accept.
        let suffix_digits = match runner.count {
            Some(n) if n > 1 => n.to_string().len(),
            _ => 0,
        };
        let worst_case_len = if suffix_digits == 0 {
            runner.name.len()
        } else {
            // +1 for the '-' separator between prefix and index.
            runner.name.len() + 1 + suffix_digits
        };
        if worst_case_len > validators::NETNS_RUNNER_NAME_MAX_LEN {
            let scope = format!("runner {:?}", runner.name);
            let msg = if suffix_digits == 0 {
                format!(
                    "netns mode requires runner name <= {max} chars (kernel \
                     IFNAMSIZ {ifn} caps veth name 'ghars-{{name}}-h'); got {got} chars",
                    max = validators::NETNS_RUNNER_NAME_MAX_LEN,
                    ifn = validators::IFNAMSIZ,
                    got = runner.name.len(),
                )
            } else {
                format!(
                    "netns mode requires runner instance name <= {max} chars (kernel \
                     IFNAMSIZ {ifn} caps veth name 'ghars-{{name}}-h'); count block \
                     '{prefix}-N' worst-case expands to {got} chars (prefix {plen} + \
                     1 + count digits {dlen})",
                    max = validators::NETNS_RUNNER_NAME_MAX_LEN,
                    ifn = validators::IFNAMSIZ,
                    prefix = runner.name,
                    got = worst_case_len,
                    plen = runner.name.len(),
                    dlen = suffix_digits,
                )
            };
            let hint = format!(
                "shorten the runner name to ≤{} chars or switch to network mode 'open'",
                validators::NETNS_RUNNER_NAME_MAX_LEN
            );
            return Err(crate::error::prepend_validation_scope(
                &scope,
                GharsError::Validation(msg, hint),
            ));
        }
    }
    Ok(())
}

// ---------- identity-field validators (#344/#346) -----------------------

/// Reject control characters in TOML fields that flow into
/// `render_identity` X-Ghars-* annotations. Today the only operator-
/// controllable surface that lands in render_identity without
/// per-character validation upstream is `trust_zone` (RunnerSpec +
/// CachePoolSpec). `render_identity` itself runs `check_identity_field`
/// at render time as defense-in-depth (#286), but rejecting at config
/// load lets the operator see the error WITH the offending block name
/// (`runner "NAME"` / `cache_pool "NAME"`) instead of an opaque
/// "field \"trust_zone\" contains forbidden newline" surfacing during
/// `plan` or `apply`.
///
/// `config_source` is NOT validated here — it is composed at plan time
/// from `paths.config_dir` (plan_from's config_source synthesis) and
/// is not a TOML field.
/// That validation lives at the plan-time composition site so it
/// covers any future caller that synthesizes a `config_source` value
/// without going through this load-time gate (#345).
///
/// # Errors
///
/// `GharsError::Validation` wrapping the underlying `check_identity_field`
/// error with the scope prefix (`runner "NAME":` / `cache_pool "NAME":`).
fn validate_identity_fields(cfg: &Config) -> Result<()> {
    for runner in &cfg.runners {
        let scope = format!("runner {:?}", runner.name);
        crate::systemd::check_identity_field("trust_zone", &runner.trust_zone)
            .map_err(|e| crate::error::prepend_validation_scope(&scope, e))?;
    }
    for (name, pool) in &cfg.cache_pools {
        let scope = format!("cache_pool {name:?}");
        crate::systemd::check_identity_field("trust_zone", &pool.trust_zone)
            .map_err(|e| crate::error::prepend_validation_scope(&scope, e))?;
    }
    Ok(())
}

// ---------- validate ----------------------------------------------------

fn cmd_validate(config_path: &Utf8Path, args: &ValidateArgs, quiet: bool) -> Result<i32> {
    // load_config runs the full post-load validator sweep
    // (validate_networks + validate_security_overrides +
    // validate_identity_fields + validate_no_duplicate_caches +
    // validate_cache_pool_names + validate_runner_names +
    // validate_user_overrides + validate_prefix_overrides +
    // validate_pat_xor + validate_runner_tarballs +
    // validate_netns_runner_name_lengths).
    // cmd_validate need not repeat them.
    let cfg = load_config(config_path)?;
    // Structural validation: build the registry (constructors enforce
    // env / file / mode), then plan against an empty actual state. The
    // planner runs cross-reference validators (auth / cache / network)
    // as a side-effect of expansion + lower_to_effective.
    let registry = build_auth_registry(&cfg.auth).map_err(|e| match e {
        GharsError::Auth(msg, hint) => {
            GharsError::Validation(format!("auth registry: {msg}"), hint)
        }
        other => other,
    })?;
    let paths = Paths::default();
    let actual = state::ActualState::default();
    let _plan = plan::plan_from(&cfg, &actual, &paths)?;

    if args.deep {
        // Round-trip token mints. We do NOT print or persist the
        // token; success is the only signal needed.
        for (name, source) in &registry {
            if let Some(spec) = cfg.runners.iter().find(|r| match &r.auth {
                Some(a) => a == name,
                None => cfg.defaults.auth.as_deref() == Some(name),
            }) {
                source
                    .mint_registration_token(&spec.url)
                    .map_err(|e| match e {
                        GharsError::Auth(msg, hint) => {
                            GharsError::Auth(format!("auth {name:?}: {msg}"), hint)
                        }
                        other => other,
                    })?;
            }
        }
    }

    if !quiet {
        let _ = writeln!(io::stdout(), "config OK ({config_path})");
    }
    Ok(0)
}

// ---------- plan --------------------------------------------------------

fn cmd_plan(
    config_path: &Utf8Path,
    paths: &Paths,
    args: &PlanArgs,
    color: ColorMode,
    quiet: bool,
) -> Result<i32> {
    // load_config runs the full post-load validator sweep — the
    // pre-batch-18 per-cmd repeats (validate_identity_fields,
    // validate_no_duplicate_caches, validate_cache_pool_names,
    // validate_runner_names, validate_user_overrides,
    // validate_runner_tarballs) were moved into load_config so
    // cmd_plan, cmd_status, cmd_add etc. all share the same gate.
    let cfg = load_config(config_path)?;
    let plan = compute_plan(&cfg, paths, &args.only)?;
    render_plan(&plan, color, args.json, quiet, args.diff)?;
    // #391: `--detailed-exitcode` opts into terraform-plan parity:
    // exit 2 when the plan contains any non-NoOp action, 0 otherwise.
    // #464: `--detailed-exitcode-recreate` opts in independently:
    // exit 8 when the plan contains a recreate-class action.
    // Mirrors `dry_run_exit_code` and `apply_exit_code` so all three
    // paths (`plan`, `apply --dry-run`, `apply`) emit the same code
    // for "changes detected" / "recreates detected" when the flags
    // are set. Without either flag, this returns 0 — the default-mode
    // behavior CI scripts currently rely on stays unchanged.
    Ok(dry_run_exit_code(
        args.detailed_exitcode,
        args.detailed_exitcode_recreate,
        &plan,
    ))
}

/// Open the system D-Bus and wrap the failure mode that operators
/// most often hit when running `ghars plan` or `ghars apply --dry-run`
/// without root.
///
/// Without this wrapper, `DbusSystemd::new()` propagates a raw
/// zbus connection error like `"system D-Bus connect failed:
/// permission denied"` which doesn't tell the operator what to do
/// next. The wrapper preserves the underlying message but rewrites
/// the hint so `Display` of the resulting `GharsError::Validation`
/// includes the actionable instruction (run as root or grant a
/// polkit policy). (#258)
fn open_dbus() -> Result<DbusSystemd> {
    DbusSystemd::new().map_err(|e| match e {
        GharsError::Systemd(msg, _) => GharsError::Validation(
            format!("ghars plan / apply requires system D-Bus access: {msg}"),
            "run as root, or grant the calling user a polkit policy that \
             allows access to org.freedesktop.systemd1 (typically \
             /usr/share/polkit-1/rules.d/)"
                .into(),
        ),
        other => other,
    })
}

fn compute_plan(cfg: &Config, paths: &Paths, only: &[String]) -> Result<Plan> {
    let systemd = open_dbus()?;
    let actual = state::discover(&systemd, paths)?;
    let mut plan = plan::plan_from(cfg, &actual, paths)?;
    if !only.is_empty() {
        plan.actions.retain(|a| action_matches_filter(a, only));
    }
    Ok(plan)
}

fn action_matches_filter(action: &Action, only: &[String]) -> bool {
    let label = action.label();
    only.iter().any(|frag| label.contains(frag.as_str()))
}

fn render_plan(plan: &Plan, color: ColorMode, json: bool, quiet: bool, diff: bool) -> Result<()> {
    if json {
        return render_plan_json(plan, diff);
    }
    if quiet {
        return Ok(());
    }
    let mut stdout = io::stdout().lock();
    if plan.actions.is_empty() {
        writeln!(stdout, "Plan: no changes.").map_err(GharsError::Io)?;
        return Ok(());
    }
    for action in &plan.actions {
        let line = render_action_line(action, color, diff);
        writeln!(stdout, "{line}").map_err(GharsError::Io)?;
    }
    // CLN-3: text-mode plan summary footer — operators reading
    // `ghars plan` without `--json` need the same disruption-class
    // counts CI consumers get from JSON `summary`. Emitted between
    // the action lines and the warnings tail so operator eyes see
    // it before the (less critical) warning block. Format mirrors
    // `summary` JSON keys verbatim so a single `grep any_recreate`
    // matches both surfaces.
    writeln!(stdout, "{}", render_plan_summary_line(&plan.actions)).map_err(GharsError::Io)?;
    for warning in &plan.warnings {
        writeln!(stdout, "warning: {warning}").map_err(GharsError::Io)?;
    }
    Ok(())
}

/// #569: shared filter for #468 recreate-class Removed entries.
/// Both the text renderer (`render_action_line`) and JSON renderer
/// (`plan_to_json_value`) iterate `delta.before_drop_in_basenames`
/// and emit one entry per basename absent from `delta.after.drop_ins`.
/// Single source of truth — a future change to the predicate (e.g.
/// excluding annotations or applying basename normalization) lands
/// in one place.
///
/// Returns `Some(iter)` when discovered pre-state is available (the
/// caller is expected to surface Removed entries). Returns `None`
/// when `before_drop_in_basenames` is `None` ("unknown pre-state");
/// the caller MUST suppress the Removed section in that case rather
/// than emit a misleading silence (see plan.rs
/// `RunnerDelta::before_drop_in_basenames` field doc and the
/// original #468 contract). `Some(empty_iter)` ⇒ the discovered
/// drop-in directory was present but empty / fully reused, no
/// Removed entries.
fn recreate_removed_basenames(d: &plan::RunnerDelta) -> Option<impl Iterator<Item = &String>> {
    d.before_drop_in_basenames.as_ref().map(|before| {
        before
            .iter()
            .filter(|b| !d.after.drop_ins.contains_key(b.as_str()))
    })
}

/// #612: human-readable gloss for opaque
/// [`plan::RunnerDelta::recreate_reasons`] tokens. Returns `Some` only
/// for the two tokens that don't name a config field — `uncovered` and
/// `runsvc_integrity` — both of which look meaningless in the
/// `! runner NAME (… recreate (uncovered)) [recreate]` plan line
/// without context. Self-explanatory tokens (`url`, `runner_version`,
/// `labels`, `arch`, `user`, `prefix`, `runner_sha256`,
/// `runner_tarball`, `network`) are field names — no gloss needed.
///
/// Token strings are static `&'static str` constants pushed by
/// [`plan::classify_recreate_reasons_from_annotations`] (the
/// field-name set) and the `runsvc_integrity_recreate` /
/// `uncovered` arms in `plan_from`. The match here mirrors that
/// vocabulary; the [`plan::RunnerDelta::recreate_reasons`] field doc
/// is the single source of truth — keep the two in lockstep.
///
/// Returning `Option` rather than a fallback string keeps the
/// renderer's `note:` line conditional — only opaque tokens
/// produce noise; named-field tokens stay silent because
/// `field_changes` already shows the before→after pair on the
/// preceding line.
fn recreate_reason_note(reason: &str) -> Option<&'static str> {
    match reason {
        "uncovered" => Some(
            "spec hash differs but no field-level change was detected; \
             this is a coverage-gap fallback — recreate is safe but \
             disruptive (file a bug if reproducible)",
        ),
        "runsvc_integrity" => Some(
            "the discovered runsvc.sh wrapper digest is missing or stale \
             (X-Ghars-Runsvc-Sha256 absent); recreate forces config.sh \
             to mint a fresh trusted digest (SEC-02)",
        ),
        _ => None,
    }
}

fn render_action_line(action: &Action, color: ColorMode, diff: bool) -> String {
    let (sigil, summary, ansi) = match action {
        Action::CreateRunner(p) => ('+', format!("runner {} (create)", p.spec.name), "\x1b[32m"),
        Action::UpdateRunner(d) => {
            // #260: surface the drift cause so the operator can tell a
            // config edit (`spec_changed`) from out-of-band drift
            // (`drift_detected`) without re-running discovery.
            //
            // #462: recreate-class UpdateRunner takes the `!` sigil to
            // distinguish destructive updates (token re-mint + unit
            // teardown + reregister) from in-place updates that share
            // the `~` glyph. The `[recreate]` bracket tag at end-of-
            // line still conveys the same information; `!` is the
            // fast-scan column-0 signal symmetric with `+`/`-` for
            // create/remove. CreateRunner/RemoveRunner /
            // CreateCachePool/RemoveCachePool keep `+`/`-` (already
            // convey destructive intent). UpdateCachePool keeps `~`
            // (always Restart-class — never recreate). NoOp keeps
            // ` `. Format:
            //   ~ runner NAME (CAUSE; update: in-place)
            //   ! runner NAME (CAUSE; update: recreate (FIELDS))
            //
            // F-DA2 (shell-safety): the `!` sigil is followed by a
            // space (`! `) to avoid bash history-expansion (`!word`).
            // Future format changes that drop the space MUST move
            // `!` to a non-leading position.
            //
            // F-DA4: `!` is NOT a uniform recreate-class marker — it
            // signals UpdateRunner escalated to recreate (the
            // surprising case). For all-recreate-class extraction,
            // grep `[recreate]` (text) or use `summary.recreates`
            // (JSON).
            //
            // #535: omit the parenthetical when `recreate_reasons` is
            // empty so the renderer never emits `recreate ()`.
            // `plan::plan_from` sets `requires_recreate =
            // !recreate_reasons.is_empty()` post-classify, so this
            // branch is unreachable from production today. Keep the
            // guard as defense for hand-constructed `RunnerDelta`
            // fixtures and any future construction site that decouples
            // `requires_recreate` from `recreate_reasons` length.
            let (sigil, mode) = if d.requires_recreate {
                let mode = if d.recreate_reasons.is_empty() {
                    "update: recreate".to_string()
                } else {
                    format!("update: recreate ({})", d.recreate_reasons.join(","))
                };
                ('!', mode)
            } else {
                ('~', "update: in-place".into())
            };
            let cause = d.drift_cause.label();
            (
                sigil,
                format!("runner {} ({cause}; {mode})", d.identity.name),
                "\x1b[33m",
            )
        }
        Action::RemoveRunner(i) => ('-', format!("runner {} (remove)", i.name), "\x1b[31m"),
        Action::CreateCachePool(p) => (
            '+',
            format!("cache_pool {} (create)", p.binding.name),
            "\x1b[32m",
        ),
        Action::UpdateCachePool(d) => (
            '~',
            format!("cache_pool {} (update)", d.binding.name),
            "\x1b[33m",
        ),
        Action::RemoveCachePool(name) => ('-', format!("cache_pool {name} (remove)"), "\x1b[31m"),
        Action::NoOp(reason) => (' ', format!("noop ({reason})"), ""),
    };
    // #285: append the worst-case disruption tag in square brackets
    // after the per-action summary so operators see the blast radius
    // at a glance:
    //   + runner foo (create) [recreate]
    //   ~ runner foo (spec_changed; update: in-place) [restart]
    //   ! runner foo (spec_changed; update: recreate (...)) [recreate]
    //     noop (foo: in sync) [none]
    // The tag is part of the colored summary line — it is built into
    // `summary` BEFORE the ANSI wrap, so when color is on the
    // bracketed label sits inside `\x1b[33m...\x1b[0m`. ANSI strippers
    // (or `--no-color` callers) preserve the bracket text intact, so
    // `grep [none]` on stripped output matches every action with no
    // scheduled host mutation. NoOp also receives the tag — the
    // suffix is unconditional.
    let disruption = action.disruption().label();
    let summary = format!("{summary} [{disruption}]");
    let header = if color.enabled && !ansi.is_empty() {
        format!("{ansi}{sigil} {summary}\x1b[0m")
    } else {
        format!("{sigil} {summary}")
    };
    // BATCH C / PART 6: append per-field details under UpdateRunner.
    // Plan engine emits `field_changes` for recreate-bound fields whose
    // annotation reconstruction differs from the desired spec, and
    // `drop_in_changes` for every basename in the union of rendered +
    // discovered drop-ins. Both render as 4-space-indented lines beneath
    // the header so a reader scanning the plan sees the exact field-
    // level deltas without re-running the planner. Detail lines are not
    // colored — color is reserved for the action sigil line so
    // `grep`-on-color pipelines stay clean. Body diffs (Created /
    // Removed full body, Modified unified diff, Preserved marker) are
    // surfaced only under `--diff` (#285).
    if let Action::UpdateRunner(d) = action {
        let mut out = header;
        for fc in &d.field_changes {
            out.push('\n');
            // #463: render_text() preserves the v1 comma-joined format
            // for List-typed values so existing operator grep
            // pipelines (`grep "labels:.*gpu"`) keep working.
            out.push_str(&format!(
                "    {}: {} → {}",
                fc.path,
                fc.before.render_text(),
                fc.after.render_text(),
            ));
        }
        // #612: under-header gloss for opaque recreate-reason tokens.
        // The header line shows
        // `! runner NAME (… recreate (uncovered,runsvc_integrity)) …`
        // verbatim from `recreate_reasons.join(",")` so operator grep
        // (`grep 'recreate ('`) keeps working unchanged. Self-
        // explanatory field-name tokens (url, labels, arch, …) already
        // surface as before→after rows above; the two non-field
        // tokens — `uncovered` and `runsvc_integrity` — name internal
        // classifier triggers that look meaningless without context.
        // Emit one indented `note: TOKEN — explanation` line per
        // opaque token here, matching the 4-space indent used by
        // field_changes above. `recreate_reason_note` returns `None`
        // for self-explanatory tokens, so this loop is a no-op for
        // typical recreates (e.g. label-only recreate emits the
        // header + `labels: a → b` and stops). The note loop runs
        // unconditionally on `recreate_reasons` (not gated on
        // `field_changes` emptiness) because `runsvc_integrity` and
        // `uncovered` BOTH come with `field_changes.is_empty()` per
        // RunnerDelta.field_changes doc — gating on the loop above
        // having emitted lines would suppress the gloss exactly when
        // it's most needed.
        for reason in &d.recreate_reasons {
            if let Some(note) = recreate_reason_note(reason) {
                out.push('\n');
                out.push_str(&format!("    note: {reason} — {note}"));
            }
        }
        // Recreate-class UpdateRunner has empty `drop_in_changes` by
        // design (plan.rs short-circuits the per-basename diff when
        // `requires_recreate` is true — every drop-in is rebuilt from
        // scratch). Under `--diff`, surface the post-recreate body
        // anyway by treating each entry in `delta.after.drop_ins` as
        // Created. Without --diff the brief view stays unchanged
        // (header only).
        if diff && d.requires_recreate {
            for (basename, body) in &d.after.drop_ins {
                out.push('\n');
                out.push_str(&format!("    + {basename}"));
                // CLN-1/F8/F13: route through the same
                // render_drop_in_body_block as in-place Created
                // entries. The synthesized DropInChangeKind::Created
                // carries the post-render body verbatim — one
                // function, one format, no recreate-vs-in-place
                // body-block divergence.
                let synthesized = plan::DropInChangeKind::Created {
                    after: body.clone(),
                };
                let block = render_drop_in_body_block(&synthesized, color);
                if !block.is_empty() {
                    out.push('\n');
                    out.push_str(&block);
                }
            }
            // #468: surface drop-ins the recreate will DELETE. For
            // each basename present in the discovered pre-update set
            // (`d.before_drop_in_basenames`) but absent from the
            // post-recreate set (`d.after.drop_ins`), emit a `-
            // basename` line. Basename-only — no body block — to
            // avoid the credential-leakage surface in #461 (e.g.
            // operator's `99-custom.conf` may have referenced
            // sensitive Environment= values).
            //
            // `None` ⇒ "unknown pre-state" (test fixture or any
            // future construction site without a `DiscoveredRunner`);
            // SUPPRESS the Removed section rather than risk a
            // misleading silence.
            // `Some(vec![])` ⇒ "known empty pre-state"; loop is a
            // no-op naturally.
            if let Some(removed) = recreate_removed_basenames(d) {
                for basename in removed {
                    out.push('\n');
                    // #567: defense-in-depth escape of ASCII control
                    // bytes / ANSI escapes from the basename before
                    // stdout emission. Basenames are derived from
                    // on-disk filesystem entries discovered by
                    // `state::discover` walking the runner's drop-in
                    // directory; an attacker with write access there
                    // could craft a file named with `\x1b[…m` to
                    // manipulate the operator's terminal at
                    // plan-render time. Upstream `validate_drop_in`
                    // rejects such names at config-load, but
                    // discovery has no such gate — escape at the
                    // render site so operator sees a `\u{NN}` glyph
                    // instead of an active escape.
                    out.push_str(&format!("    - {}", escape_control_chars(basename),));
                }
            }
        } else {
            for dc in &d.drop_in_changes {
                // #301: surface Created / Modified / Removed in the
                // brief view so toggling a drop-in family (enabling
                // [proxy] → creates 60-proxy.conf, clearing
                // memory_max → removes 10-memory.conf) is visible
                // without reading the JSON payload or running with
                // `--diff`. Sigils use the create/modify/remove
                // subset of the Action sigil vocabulary
                // (+ create, ~ modified, - removed) so the operator's
                // eye picks the same shape. The Action-level `!`
                // (recreate UpdateRunner) has no drop-in analog.
                // Preserved is the
                // audit-trail "no edit" tag and stays out of the
                // brief view; under --diff it surfaces with an
                // explicit `(unchanged)` marker so operators can
                // confirm the no-edit verdict from the operator-
                // visible plan output rather than parsing JSON.
                let sigil_basename = match dc.change {
                    plan::DropInChangeKind::Created { .. } => Some(('+', dc.basename.as_str())),
                    plan::DropInChangeKind::Modified { .. } => Some(('~', dc.basename.as_str())),
                    plan::DropInChangeKind::Removed { .. } => Some(('-', dc.basename.as_str())),
                    plan::DropInChangeKind::Preserved => {
                        if diff {
                            Some((' ', dc.basename.as_str()))
                        } else {
                            None
                        }
                    }
                };
                if let Some((sigil, basename)) = sigil_basename {
                    out.push('\n');
                    // #567 (item 8): same defense-in-depth basename
                    // escape as the recreate-Removed path at line ~1396.
                    // Drop-in basenames originate from on-disk
                    // filesystem entries via state::discover; an
                    // attacker with write access to the runner's
                    // drop-in directory could craft a file named
                    // `\x1b[…m` to hijack the operator's terminal at
                    // plan-render time. Symmetric coverage with the
                    // recreate path closes the asymmetry adversary
                    // findings raised.
                    out.push_str(&format!("    {sigil} {}", escape_control_chars(basename),));
                    if diff {
                        let block = render_drop_in_body_block(&dc.change, color);
                        if !block.is_empty() {
                            out.push('\n');
                            out.push_str(&block);
                        }
                    }
                }
            }
        }
        return out;
    }
    header
}

/// Render the `--diff` body payload for one `DropInChange`.
/// Returned as a string starting with the indented body content
/// (no leading newline — the caller decides how to glue the block
/// onto the preceding sigil line). Trailing newline is trimmed.
///
/// `color` controls only the Modified unified-diff path: when
/// enabled, `+` lines wrap in green and `-` lines wrap in red
/// (matches `git diff` / GNU `diff --color`). `@@` hunk headers
/// and context lines stay uncolored so `grep '^+'` on stripped
/// output still matches.
///
/// Output shapes (body content indented 12 spaces inside an 8-space
/// fence header so the content visually nests under the basename
/// sigil line):
///
/// - `Created { after }`: `        after:` header, then indented body.
/// - `Removed { before }`: `        before:` header, then indented body.
/// - `Modified { before, after }`: a unified diff via
///   `similar::udiff::unified_diff(Algorithm::Myers, ..., 3,
///   Some(("on-disk", "desired")))` — 3-line context (matches GNU
///   `diff -u3`). The `on-disk` / `desired` labels make the
///   in-memory-vs-disk semantics explicit (the `before` is the
///   discovered drop-in body, the `after` is the post-render bytes
///   ghars-apply will write); avoids the temporal-vs-spatial
///   ambiguity of `before`/`after` header labels.
/// - `Preserved`: a single `(unchanged)` marker line so operators
///   can confirm the no-edit verdict without parsing JSON.
///
/// # Security
///
/// This function is the sole chokepoint for body-block emission on
/// the text-mode `ghars plan --diff` path. Body content rendered
/// here may contain sensitive values from the operator's TOML —
/// for example, `60-proxy.conf` carries `Environment=HTTP_PROXY=
/// http://user:pass@host` when the operator configures an
/// authenticated proxy. Text output of `ghars plan --diff` should
/// not be uploaded to shared artifacts (CI logs, pastebins, ticket
/// attachments) without redaction. Symmetric with the `# Security`
/// caveat on `plan_to_json_value`. Tracked as task #461 (SEC-NEW:
/// --diff body output may expose proxy credentials from
/// 60-proxy.conf).
fn render_drop_in_body_block(kind: &plan::DropInChangeKind, color: ColorMode) -> String {
    let mut out = String::new();
    match kind {
        plan::DropInChangeKind::Preserved => {
            out.push_str("        (unchanged)\n");
        }
        plan::DropInChangeKind::Created { after } => {
            out.push_str("        after:\n");
            push_indented_body(&mut out, after);
        }
        plan::DropInChangeKind::Removed { before } => {
            out.push_str("        before:\n");
            push_indented_body(&mut out, before);
        }
        plan::DropInChangeKind::Modified { before, after } => {
            // Header labels follow the in-memory-vs-disk comparison
            // semantics: `on-disk` is the discovered drop-in body
            // (the `before`), `desired` is the post-render bytes
            // ghars-apply will write (the `after`). Avoids the
            // ambiguity of `before`/`after` which read as temporal
            // when the comparison is actually spatial (filesystem
            // vs. plan output).
            let unified = similar::udiff::unified_diff(
                similar::Algorithm::Myers,
                before.as_str(),
                after.as_str(),
                3,
                Some(("on-disk", "desired")),
            );
            push_indented_unified_diff(&mut out, &unified, color);
        }
    }
    while out.ends_with('\n') {
        out.pop();
    }
    out
}

/// Append `body` to `out`, prefixing every non-empty line with 12
/// spaces (the drop-in body indent: twice the basename-line indent).
/// Each line is terminated with `\n` regardless of whether the
/// input was newline-terminated, so the caller can append an
/// `after:` block immediately after a `before:` block without
/// inserting glue. Empty input ⇒ no output.
///
/// #590: each line passes through `escape_control_chars` before
/// emission. The body content originates from operator-authored
/// drop-in files (`Created.after`, `Removed.before`); operator-
/// supplied bodies could contain raw C0/DEL bytes that would
/// otherwise reach the operator's terminal under `--diff` and
/// hijack rendering. Defense-in-depth scrub at the per-line level
/// keeps both the indent prefix (12 spaces, pure printable ASCII)
/// and the line-terminating `\n` (intentional, structural) intact
/// — only the line CONTENT is escaped. The body's own newlines
/// already separate visible lines via the `body.lines()` iterator.
fn push_indented_body(out: &mut String, body: &str) {
    if body.is_empty() {
        return;
    }
    // `lines()` strips trailing newlines per line and skips the
    // empty trailing line when the input ends with `\n`. That gives
    // us a single `\n`-terminated emit per visible line — the
    // ambiguity around trailing-newline-or-not in the input goes
    // away.
    for line in body.lines() {
        if line.is_empty() {
            out.push('\n');
        } else {
            out.push_str("            ");
            out.push_str(&escape_control_chars(line));
            out.push('\n');
        }
    }
}

/// Append a unified-diff `body` (output of
/// `similar::udiff::unified_diff`) to `out` with the standard
/// 12-space drop-in body indent. When `color.enabled` is true,
/// `+`-prefixed lines wrap in green and `-`-prefixed lines wrap
/// in red — matching `git diff` / GNU `diff --color` so operator
/// muscle memory transfers. `@@` hunk headers and context lines
/// stay uncolored.
///
/// The ANSI wrap goes INSIDE the indent prefix so a `grep '^    '`
/// pipe that strips the indent keeps the bare `+`/`-` first
/// character intact for downstream `grep '^+'` matchers.
///
/// `similar::udiff::unified_diff` is invoked with
/// `Some(("on-disk", "desired"))` in this codebase, so the body
/// starts with `--- on-disk` and `+++ desired` header lines. The
/// `^---`/`^+++` distinction matters: those header lines must NOT
/// be color-wrapped (matches `git diff --color`'s convention of
/// bold/cyan headers, not red/green). The branch order below
/// checks the multi-char `+++`/`---` prefixes BEFORE the
/// single-char `+`/`-` so headers route correctly.
fn push_indented_unified_diff(out: &mut String, body: &str, color: ColorMode) {
    if body.is_empty() {
        return;
    }
    for line in body.lines() {
        if line.is_empty() {
            out.push('\n');
            continue;
        }
        out.push_str("            ");
        // #590: scrub control bytes from the diff line CONTENT
        // before any color wrapping. Diff lines are derived from
        // operator-authored drop-in bodies (the `before`/`after`
        // strings passed to `similar::udiff::unified_diff`); a
        // hostile body line could embed raw `\x1b` that would
        // otherwise hijack the operator's terminal under `--diff`.
        // Escape FIRST so legitimate sigil characters (`+`/`-`/
        // `@`) — none of which are control chars — survive the
        // `starts_with` checks below; then wrap with our own
        // legitimate ANSI green/red bytes for the color path. The
        // 12-space indent prefix and the line-terminating `\n`
        // are written outside this branch and stay structural.
        let scrubbed = escape_control_chars(line);
        let line_ref = scrubbed.as_ref();
        if color.enabled {
            // ANSI wraps the line content (including its sigil)
            // so the colored bytes start AFTER the indent — that
            // way `awk '$1=="+" {print}'` on a stripped pipeline
            // still matches by treating the first column as the
            // sigil character.
            if line_ref.starts_with("+++") || line_ref.starts_with("---") {
                // Header lines from a future similar revision —
                // leave uncolored to match git diff's `--color`
                // convention (those lines are bold/cyan there,
                // not red/green).
                out.push_str(line_ref);
            } else if line_ref.starts_with('+') {
                out.push_str("\x1b[32m");
                out.push_str(line_ref);
                out.push_str("\x1b[0m");
            } else if line_ref.starts_with('-') {
                out.push_str("\x1b[31m");
                out.push_str(line_ref);
                out.push_str("\x1b[0m");
            } else {
                out.push_str(line_ref);
            }
        } else {
            out.push_str(line_ref);
        }
        out.push('\n');
    }
}

/// Build the JSON value for `plan` without writing it. Pure function
/// so tests assert the in-memory shape and `render_plan_json` shares
/// the exact construction the operator sees through stdout (no test
/// mirror to drift). Inner `drop_in_changes[].change_kind` is the
/// per-entry discriminator (#305 — distinct from the per-action
/// `kind` so consumers can disambiguate without context).
///
/// `diff` controls whether each `drop_in_changes` entry carries the
/// drop-in body content (`true`) or only the basename + change_kind
/// (`false`, pre-#285 shape — backward compatible with existing
/// consumers).
///
/// When `diff = true`:
/// - `Created` adds `after` (full body string).
/// - `Removed` adds `before` (full body string).
/// - `Modified` adds `unified_diff` (string from
///   `similar::udiff::unified_diff`).
/// - `Preserved` adds nothing — the basename + `"preserved"`
///   change_kind is the entire payload.
///
/// For `Action::UpdateRunner` with `requires_recreate = true`, the
/// planner's `drop_in_changes` is empty by design (recreate
/// rebuilds every drop-in from scratch). When `diff = true`, the
/// JSON path synthesizes `Created` entries from
/// `delta.after.drop_ins` so consumers can see the post-recreate
/// drop-ins. Without `diff`, the array stays empty (backward
/// compatible).
///
/// # Security
///
/// Drop-in body content emitted under `diff = true` may contain
/// sensitive values rendered verbatim from the operator's TOML —
/// for example, `60-proxy.conf` carries `Environment=HTTP_PROXY=
/// http://user:pass@host` when the operator configures an
/// authenticated proxy. JSON output of `ghars plan --diff`
/// should not be uploaded to shared artifacts (CI logs,
/// pastebins, ticket attachments) without redaction. Tracked as
/// task #461 (SEC-NEW: --diff body output may expose proxy
/// credentials from 60-proxy.conf).
#[must_use]
pub(crate) fn plan_to_json_value(plan: &Plan, diff: bool) -> serde_json::Value {
    let actions: Vec<serde_json::Value> = plan
        .actions
        .iter()
        .map(|a| {
            // #285: every action object carries a top-level
            // `disruption` field so JSON consumers (CI, dashboards)
            // can branch on the worst-case operational impact
            // without rederiving it from the per-variant fields. The
            // label vocabulary is shared with the text renderer.
            let disruption = a.disruption().label();
            match a {
                Action::CreateRunner(p) => serde_json::json!({
                    "kind": "create_runner",
                    "name": p.spec.name,
                    "url": p.spec.url,
                    "spec_hash": p.spec_hash,
                    "disruption": disruption,
                }),
                Action::UpdateRunner(d) => {
                    // BATCH C / PART 6: emit field_changes + drop_in_changes
                    // so JSON consumers (CI, dashboards) can render the same
                    // per-field deltas the text path renders, without
                    // re-running the planner. Drop-in bodies (`before`/
                    // `after`/`unified_diff`) ride behind `--diff` (#285).
                    // #463: schema v2 — `before`/`after` are tagged
                    // FieldValue objects (`{"type": "string", "value": "x"}`
                    // or `{"type": "list", "values": ["a", "b"]}`) so JSON
                    // consumers can programmatically detect List vs Scalar
                    // without re-splitting comma-joined strings.
                    let field_changes: Vec<serde_json::Value> = d
                        .field_changes
                        .iter()
                        .map(|fc| {
                            serde_json::json!({
                                "path": fc.path,
                                "before": fc.before.to_json(),
                                "after": fc.after.to_json(),
                            })
                        })
                        .collect();
                    let drop_in_changes: Vec<serde_json::Value> = if diff && d.requires_recreate {
                        // CLN-5: synthesize Created entries from
                        // delta.after.drop_ins (BTreeMap, so already
                        // alphabetically ordered) and route through
                        // the same drop_in_change_to_json the
                        // in-place path uses. One JSON shape, no
                        // hand-rolled duplicate. Without `--diff`
                        // the array stays empty (backward compat).
                        let mut entries: Vec<serde_json::Value> = d
                            .after
                            .drop_ins
                            .iter()
                            .map(|(basename, body)| {
                                drop_in_change_to_json(
                                    &plan::DropInChange {
                                        basename: basename.clone(),
                                        change: plan::DropInChangeKind::Created {
                                            after: body.clone(),
                                        },
                                    },
                                    diff,
                                )
                            })
                            .collect();
                        // #468: surface drop-ins the recreate will
                        // DELETE. Diverges intentionally from the
                        // in-place Removed JSON shape: no `before`
                        // body field — basename + change_kind +
                        // `body_suppressed: true` marker. Body would
                        // re-introduce #461's credential-leakage
                        // surface for any drop-in that embedded
                        // `Environment=` lines (e.g. `60-proxy.conf`
                        // with an authenticated proxy URL).
                        // Operator-actionable signal is the basename
                        // alone; `body_suppressed: true` lets JSON
                        // consumers distinguish "no body because
                        // suppressed" from "no body because absent".
                        //
                        // `None` ⇒ "unknown pre-state" (test
                        // fixture or any future construction site
                        // that doesn't have a `DiscoveredRunner` in
                        // scope); SUPPRESS the Removed entries
                        // rather than risk a misleading silence in
                        // JSON consumers.
                        if let Some(removed) = recreate_removed_basenames(d) {
                            for basename in removed {
                                // #567: same defense-in-depth escape as
                                // the text path. `serde_json` escapes
                                // ESC on the JSON wire, which is safe
                                // for parsers that honor JSON quoting;
                                // but downstream jq pipelines that
                                // pipe `.basename` back to a terminal
                                // via `echo -e` / `printf '%b'` (or
                                // shells with `xpg_echo`) would
                                // re-interpret the escape. Replacing
                                // each control char with
                                // `char::escape_default` form before
                                // serialization keeps the basename
                                // terminal-safe regardless of the
                                // downstream consumer's interpolation
                                // semantics.
                                entries.push(serde_json::json!({
                                    "basename": escape_control_chars(basename).into_owned(),
                                    "change_kind": "removed",
                                    "body_suppressed": true,
                                }));
                            }
                        }
                        entries
                    } else {
                        d.drop_in_changes
                            .iter()
                            .map(|dc| drop_in_change_to_json(dc, diff))
                            .collect()
                    };
                    serde_json::json!({
                        "kind": "update_runner",
                        "name": d.identity.name,
                        "requires_recreate": d.requires_recreate,
                        "recreate_reasons": d.recreate_reasons,
                        // #260: cause label uses the same snake_case
                        // vocabulary as the text path so `grep
                        // spec_changed` matches both.
                        "drift_cause": d.drift_cause.label(),
                        "spec_hash": d.after.spec_hash,
                        "field_changes": field_changes,
                        "drop_in_changes": drop_in_changes,
                        "disruption": disruption,
                    })
                }
                Action::RemoveRunner(i) => serde_json::json!({
                    "kind": "remove_runner",
                    "name": i.name,
                    "url": i.url,
                    "disruption": disruption,
                }),
                Action::CreateCachePool(p) => serde_json::json!({
                    "kind": "create_cache_pool",
                    "name": p.binding.name,
                    "kinds": p.binding.kinds,
                    "spec_hash": p.spec_hash,
                    "disruption": disruption,
                }),
                Action::UpdateCachePool(d) => serde_json::json!({
                    "kind": "update_cache_pool",
                    "name": d.binding.name,
                    "kinds": d.binding.kinds,
                    "spec_hash": d.spec_hash,
                    "disruption": disruption,
                }),
                Action::RemoveCachePool(name) => serde_json::json!({
                    "kind": "remove_cache_pool",
                    "name": name,
                    "disruption": disruption,
                }),
                Action::NoOp(reason) => serde_json::json!({
                    "kind": "noop",
                    "reason": reason,
                    "disruption": disruption,
                }),
            }
        })
        .collect();
    // #285 (devadv D-6): top-level `schema_version` is a forward-
    // compat hook for CI consumers that need to detect breaking
    // changes in this JSON shape. Bump this string when the shape
    // changes in a way that existing consumers cannot transparently
    // ignore (added keys are NOT a bump; renamed/removed keys are).
    // Stays a string so we can use semver-flavored values like
    // "2.0" without restructuring downstream parsers.
    //
    // #285 (devadv D-7): top-level `summary` rolls per-action
    // counts up so CI policy gates can branch on the plan
    // disposition without iterating the actions array.
    // `any_recreate` is the load-bearing field for "block this
    // plan if it would deregister any runner" guards.
    let summary = plan_summary_value(&plan.actions);
    // #463: bumped from "1" → "2" because FieldChange.before/after
    // changed from raw String to tagged FieldValue objects
    // (`{"type": "string", "value"}` / `{"type": "list", "values"}`).
    // Existing v1 consumers parsing `before` as a String would
    // see an object and fail; the bump signals the breaking change
    // explicitly.
    serde_json::json!({
        "schema_version": "2",
        "summary": summary,
        "actions": actions,
        "warnings": plan.warnings,
    })
}

/// Build the top-level `summary` object that JSON `ghars plan`
/// emits at the `summary` key. CI policy gates branch on these
/// fields without iterating the per-action body.
///
/// Fields:
/// - `total_actions` — `actions.len()`.
/// - `by_disruption` — object keyed by `Disruption::label()`
///   (`none` / `restart` / `recreate`), values are u64 counts.
///   All three keys are always present (count `0` when absent)
///   so consumers see a stable shape.
/// - `any_recreate` — bool, equivalent to `!recreates.is_empty()`.
///   Load-bearing for "block this plan if it would deregister any
///   runner" guards.
/// - `recreates` — array of `Action::label()` strings, one per
///   `Recreate`-class action, sorted lexicographically. Always
///   present, emitted as `[]` when the plan has no recreate-class
///   actions. (#469)
///
/// **`recreates` element contract** (#469):
/// - Each element matches the verbatim `Action::label()` output —
///   the same string cmd_apply emits in `ok: LABEL` and
///   `fail: LABEL` lines, so a single grep on the label spans
///   plan and apply surfaces.
/// - The shape is `Variant(name)` (PascalCase variant + paren-
///   wrapped entity name): `CreateRunner(alpha)`,
///   `RemoveRunner(beta)`, `CreateCachePool(build)`,
///   `RemoveCachePool(build)`, `UpdateRunner(gamma)` (only when
///   that delta has `requires_recreate = true`; in-place
///   `UpdateRunner` is `Restart` and is excluded). `UpdateCachePool`
///   is always `Restart` and never appears here. `NoOp` is
///   `Disruption::None` and never appears.
/// - Element values are PascalCase to match `Action::label()`;
///   JSON keys (`total_actions`, `by_disruption`, `any_recreate`,
///   `recreates`) are snake_case. (Mixed case is intentional —
///   element values mirror Rust enum variant names verbatim;
///   keys follow snake_case JSON convention.)
/// - Same-name entities of different kinds disambiguate via the
///   variant prefix: `RemoveRunner(alpha)` and `RemoveCachePool(alpha)`
///   are distinct labels.
/// - Sort is `slice::sort_unstable()` (byte-wise lexicographic;
///   stability is irrelevant for `Vec<String>` because equal
///   elements are indistinguishable). For ASCII-only labels
///   (`Action::label()` interpolates entity names matching
///   `IDENTIFIER_REGEX` = `^[a-z]([a-z0-9-]*[a-z0-9])?$`, plus the
///   static PascalCase variant prefix and parens), this coincides
///   with operator-readable alphabetical order.
///
/// **Invariants** (#469, pinned by tests at
/// `plan_to_json_value_summary_recreates_*`):
/// - `recreates.len() == by_disruption["recreate"]` (same Vec
///   sourced both fields from).
/// - `!recreates.is_empty() == any_recreate`.
/// - Order is independent of plan-emit order; sort is stable
///   across runs.
/// - Output is `--diff`-independent — `recreates` carries no body
///   text or per-action payload, only labels.
///
/// **CI example**: gate on no-recreate plans with
/// `jq -e '.summary.recreates | length == 0'` (exits 0 when the
/// array is empty, non-zero otherwise).
///
/// CLN-2: the `by_disruption` loop iterates
/// `disruption_summary_variants()` instead of hardcoding label
/// strings — `Disruption::label()` stays the single source of
/// truth for the label vocabulary.
///
/// CLN-469-1: `recreates` is collected first; `by_disruption["recreate"]`
/// derives its count from `recreates.len()` and `any_recreate`
/// derives from `!recreates.is_empty()`. The for-variant loop
/// only counts the two non-recreate variants, removing a redundant
/// filter pass and a `mut` bool.
fn plan_summary_value(actions: &[Action]) -> serde_json::Value {
    let mut recreates: Vec<String> = actions
        .iter()
        .filter(|a| a.disruption() == plan::Disruption::Recreate)
        .map(plan::Action::label)
        .collect();
    recreates.sort_unstable();
    let any_recreate = !recreates.is_empty();
    let mut by_disruption = serde_json::Map::new();
    for variant in disruption_summary_variants() {
        let count: u64 = if matches!(variant, plan::Disruption::Recreate) {
            recreates.len() as u64
        } else {
            actions.iter().filter(|a| a.disruption() == variant).count() as u64
        };
        by_disruption.insert(variant.label().into(), serde_json::json!(count));
    }
    serde_json::json!({
        "total_actions": actions.len(),
        "by_disruption": serde_json::Value::Object(by_disruption),
        "any_recreate": any_recreate,
        "recreates": recreates,
    })
}

/// All `Disruption` variants in canonical (least → most disruptive)
/// order. The single source of truth for iterating the taxonomy
/// outside the enum's own match arms — used by `plan_summary_value`
/// for JSON keys, `render_plan` for the text-mode footer, and
/// future code that needs the same ordering.
fn disruption_summary_variants() -> [plan::Disruption; 3] {
    [
        plan::Disruption::None,
        plan::Disruption::Restart,
        plan::Disruption::Recreate,
    ]
}

/// CLN-3: build the text-mode plan summary footer.
///
/// Format:
/// `Plan: N actions (N restart, N recreate, N none). any_recreate: true|false`
///
/// The label vocabulary mirrors the JSON `summary.by_disruption`
/// keys so a single `grep any_recreate` matches both surfaces.
/// Order is restart → recreate → none (most-actionable-first for
/// operator scanning), distinct from
/// `disruption_summary_variants()`'s least-to-most-disruptive order
/// used for the JSON-key iteration. The disruption parenthetical
/// + `any_recreate` suffix is delegated to
/// `format_disruption_tail` (CLN-2) — the single source of truth
/// for the format string shared with `render_apply_summary_line`.
#[must_use]
pub(crate) fn render_plan_summary_line(actions: &[Action]) -> String {
    let mut none_count: u64 = 0;
    let mut restart_count: u64 = 0;
    let mut recreate_count: u64 = 0;
    for a in actions {
        match a.disruption() {
            plan::Disruption::None => none_count += 1,
            plan::Disruption::Restart => restart_count += 1,
            plan::Disruption::Recreate => recreate_count += 1,
        }
    }
    format!(
        "Plan: {total} actions {tail}",
        total = actions.len(),
        tail = format_disruption_tail(none_count, restart_count, recreate_count),
    )
}

/// CLN-2 (#476): build the shared `(N restart, N recreate, N none).
/// any_recreate: bool` tail used by both `render_plan_summary_line`
/// and `render_apply_summary_line`. Single source of truth for the
/// disruption-parenthetical + `any_recreate` suffix format string,
/// so a future rename of any `Disruption::label()` token or the
/// `any_recreate` key propagates to both surfaces without a parallel
/// edit.
///
/// Order is restart → recreate → none
/// (most-actionable-first for operator scanning), matching both
/// callers. `any_recreate` is `true` ⇔ `recreate > 0`.
#[must_use]
fn format_disruption_tail(none: u64, restart: u64, recreate: u64) -> String {
    let any_recreate = recreate > 0;
    format!(
        "({restart} {restart_label}, {recreate} {recreate_label}, \
         {none} {none_label}). any_recreate: {any_recreate}",
        restart = restart,
        restart_label = plan::Disruption::Restart.label(),
        recreate = recreate,
        recreate_label = plan::Disruption::Recreate.label(),
        none = none,
        none_label = plan::Disruption::None.label(),
        any_recreate = any_recreate,
    )
}

/// #476: build the text-mode apply summary footer. Symmetric with
/// `render_plan_summary_line` on the disruption parenthetical and
/// `any_recreate` suffix; the headline triple
/// (`applied/failed/skipped`) is apply-specific.
///
/// Format:
/// `Apply: A applied, F failed, S skipped (R restart, K recreate, N none). any_recreate: true|false`
///
/// **Outcome-class buckets** (the headline `A applied, F failed, S
/// skipped` triple):
/// - `failed` — `ApplyOutcome::Failed` rows (#474). Includes both
///   per-action handler failures and the synthetic `daemon_reload`
///   Failed row when Manager.Reload itself errored.
/// - `skipped` — outcomes that returned `Ok` but performed no host
///   mutation: `NoOp`, `DryRunSkipped`, `InPlaceSkipped`,
///   `PoolSkipped`. These four variants are the apply-time outcomes
///   that returned Ok with no host mutation. Failed rows always go
///   in `failed` regardless of their `plan_disruption`.
/// - `applied` — host-mutating outcomes: `Created`, `Removed`,
///   `Recreated`, `InPlaceRestarted`, `PoolCreated`, `PoolUpdated`,
///   `PoolRemoved`. The match arm enumerates these explicitly (not a
///   wildcard) so a future variant addition forces a compile-time
///   bucketing decision instead of silently defaulting to `applied`.
///
/// **Disruption parenthetical** (`R restart, K recreate, N none`):
/// derived from each outcome's `disruption()` method. Same vocabulary
/// as the plan footer so operators reading both surfaces get
/// consistent terminology. Includes BOTH successful and failed rows
/// (Failed.disruption() returns the action's plan-time worst-case
/// per #474), so a partially-applied recreate-class action that
/// errored mid-way still contributes to the `recreate` count.
/// Delegated to `format_disruption_tail` (CLN-2) — single source of
/// truth for the format string shared with `render_plan_summary_line`.
///
/// **`any_recreate`**: true ⇔ any outcome's `disruption()` is
/// `Recreate`. Includes failed Recreate-class actions, matching the
/// plan footer's definition (recreate-class = blast radius class).
///
/// Order is restart → recreate → none (most-actionable-first for
/// operator scanning), matching `render_plan_summary_line`.
///
/// **fail_fast caveat**: under `ApplyOptions::fail_fast`, the loop
/// short-circuits on the first action error and unprocessed actions
/// are absent from `result.details` (see apply.rs:333-341). The
/// footer total (`applied + failed + skipped`) may therefore be less
/// than the originating plan's action count.
#[must_use]
pub(crate) fn render_apply_summary_line(result: &apply::ApplyResult) -> String {
    let mut applied: u64 = 0;
    let mut failed: u64 = 0;
    let mut skipped: u64 = 0;
    let mut none_count: u64 = 0;
    let mut restart_count: u64 = 0;
    let mut recreate_count: u64 = 0;
    for (_, outcome) in &result.details {
        match outcome {
            apply::ApplyOutcome::Failed { .. } => failed += 1,
            apply::ApplyOutcome::NoOp
            | apply::ApplyOutcome::DryRunSkipped
            | apply::ApplyOutcome::InPlaceSkipped
            | apply::ApplyOutcome::PoolSkipped => skipped += 1,
            apply::ApplyOutcome::Created
            | apply::ApplyOutcome::Removed
            | apply::ApplyOutcome::Recreated
            | apply::ApplyOutcome::InPlaceRestarted { .. }
            | apply::ApplyOutcome::PoolCreated
            | apply::ApplyOutcome::PoolUpdated
            | apply::ApplyOutcome::PoolRemoved => applied += 1,
        }
        match outcome.disruption() {
            plan::Disruption::None => none_count += 1,
            plan::Disruption::Restart => restart_count += 1,
            plan::Disruption::Recreate => recreate_count += 1,
        }
    }
    format!(
        "Apply: {applied} applied, {failed} failed, {skipped} skipped {tail}",
        applied = applied,
        failed = failed,
        skipped = skipped,
        tail = format_disruption_tail(none_count, restart_count, recreate_count),
    )
}

/// Build one `drop_in_changes[]` JSON entry. When `diff = false`,
/// emits the pre-#285 shape (`basename` + `change_kind`). When
/// `diff = true`, adds body content per variant: `after` for
/// Created, `before` for Removed, `unified_diff` for Modified.
/// Preserved adds nothing — the basename + `"preserved"`
/// `change_kind` is the entire payload.
fn drop_in_change_to_json(dc: &plan::DropInChange, diff: bool) -> serde_json::Value {
    let change_kind = match dc.change {
        plan::DropInChangeKind::Created { .. } => "created",
        plan::DropInChangeKind::Modified { .. } => "modified",
        plan::DropInChangeKind::Removed { .. } => "removed",
        plan::DropInChangeKind::Preserved => "preserved",
    };
    let mut obj = serde_json::Map::new();
    // #567 (item 8): same defense-in-depth basename escape as the
    // recreate-Removed JSON path at ~line 1763. `dc.basename` flows
    // from `state::discover`'s filesystem walk, which has no
    // charset gate (config-load validates operator-authored drop-in
    // names but discovery-side basenames from the on-disk
    // `<drop-in-dir>/` listing bypass that). Replacing the raw
    // String with `escape_control_chars(...).into_owned()` keeps
    // the JSON wire shape terminal-safe for downstream
    // `jq | echo -e` / `printf '%b'` pipelines.
    obj.insert(
        "basename".into(),
        serde_json::Value::String(escape_control_chars(&dc.basename).into_owned()),
    );
    obj.insert(
        "change_kind".into(),
        serde_json::Value::String(change_kind.into()),
    );
    if diff {
        match &dc.change {
            plan::DropInChangeKind::Created { after } => {
                obj.insert("after".into(), serde_json::Value::String(after.clone()));
            }
            plan::DropInChangeKind::Removed { before } => {
                obj.insert("before".into(), serde_json::Value::String(before.clone()));
            }
            plan::DropInChangeKind::Modified { before, after } => {
                // Header labels match the text-path renderer:
                // `on-disk` for the discovered body, `desired`
                // for the post-render bytes. Same in-memory-vs-
                // disk semantics rationale documented at
                // `render_drop_in_body_block`.
                let unified = similar::udiff::unified_diff(
                    similar::Algorithm::Myers,
                    before.as_str(),
                    after.as_str(),
                    3,
                    Some(("on-disk", "desired")),
                );
                obj.insert("unified_diff".into(), serde_json::Value::String(unified));
            }
            plan::DropInChangeKind::Preserved => {
                // No payload — bytes are identical on both sides.
            }
        }
    }
    serde_json::Value::Object(obj)
}

fn render_plan_json(plan: &Plan, diff: bool) -> Result<()> {
    let body = plan_to_json_value(plan, diff);
    let mut stdout = io::stdout().lock();
    // serde_json encode failures here are internal encoder failures
    // (e.g. stdout closed, write returns short), NOT operator config
    // errors — map to GharsError::Io so main.rs's #275 mapping
    // doesn't surface exit code 6 (config) for an io fault.
    serde_json::to_writer_pretty(&mut stdout, &body)
        .map_err(|e| GharsError::Io(io::Error::other(format!("encode plan json: {e}"))))?;
    writeln!(stdout).map_err(GharsError::Io)?;
    Ok(())
}

// ---------- apply -------------------------------------------------------

fn cmd_apply(
    config_path: &Utf8Path,
    paths: &Paths,
    args: &ApplyArgs,
    color: ColorMode,
    quiet: bool,
) -> Result<i32> {
    // load_config runs the full post-load validator sweep — the
    // pre-batch-18 per-cmd repeats (validate_security_overrides,
    // validate_identity_fields, validate_no_duplicate_caches,
    // validate_cache_pool_names, validate_runner_names,
    // validate_user_overrides, validate_runner_tarballs) all live in
    // load_config now. Apply therefore inherits the same gate every
    // other cmd_* enforces.
    let cfg = load_config(config_path)?;

    if args.dry_run {
        // `--dry-run` is documented as an alias for `ghars plan` (Part 5).
        // With `--detailed-exitcode`, `dry_run_exit_code` returns 2 when
        // the plan has any non-NoOp action — terraform parity (#389).
        // With `--detailed-exitcode-recreate`, returns 8 when the plan
        // has any recreate-class action — recreate trumps detailed (#464).
        // Threads `args.diff` so `apply --dry-run --diff` produces the
        // same body output as `plan --diff` (#285).
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

    // #464: pre-confirm recreate gate. When `--detailed-exitcode-recreate`
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
            // #393: status message goes to stderr so wrapping scripts
            // that capture stdout (e.g. for plan output) don't see it
            // mixed in with structured output. Unix convention:
            // diagnostics on stderr, data on stdout.
            let _ = writeln!(io::stderr(), "apply cancelled");
        }
        // #358: cancellation with --detailed-exitcode returns 2 ("changes
        // still pending" — terraform semantics), distinct from 0 ("plan
        // had no diff, no work needed"). Without --detailed-exitcode,
        // 0 preserves the established CLI convention that cancelling
        // an interactive prompt is a non-error.
        // #464: cancellation with --detailed-exitcode-recreate returns
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
    let users = apply::RealUsers;
    let config_shell = apply::RealConfigShell;
    let deps = apply::Deps {
        systemd: &systemd,
        auth: &registry,
        tarball: &tarball,
        users: &users,
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
        // #340 + #474: render every action with a per-action detail
        // line. Format: `ok: LABEL [disruption] (detail)` for success
        // / skip / dry-run, `fail: LABEL [disruption] (error)` for
        // failed actions. The `[disruption]` bracket tag
        // (`[none]`/`[restart]`/`[recreate]`) reuses the plan-output
        // vocabulary from #285 so a single `grep [recreate]` matches
        // both surfaces. `result.details` is populated in execution
        // order (post sort_into_phases) covering success, skip,
        // dry-run, AND failure rows (#474); the outcome's `detail()`
        // carries the variant-specific suffix (e.g. "in-place: 2
        // file(s) changed, 0 group op(s)", or with a non-empty
        // pool diff "in-place: 2 file(s) changed, 1 group op(s)
        // (added: build-cache)" per #473; "noop (bytes + groups
        // match)"; "dry-run (skipped)"; or the failure error
        // string). NoOp actions are special-cased to emit
        // `noop: REASON` instead of the verbose `ok: NoOp(REASON)
        // [none] (noop (in sync))` double-tag (DA1 finding) — the
        // label already carries `NoOp(REASON)`, so re-saying `noop
        // (in sync)` is redundant. `fail:` rows route to stderr to
        // preserve the stdout/stderr split for grep pipelines.
        // `result.failed` retains the typed GharsError chain for
        // programmatic consumers; the rendering layer reads
        // `result.details` exclusively now.
        for (label, outcome) in &result.details {
            match outcome {
                apply::ApplyOutcome::NoOp => {
                    // F-DA3: append `[none]` for shape parity with the
                    // `ok: LABEL [disruption] (...)` and
                    // `fail: LABEL [disruption] (...)` lines so a single
                    // regex parses every row. NoOp is always
                    // `Disruption::None` (verified at apply.rs by the
                    // `disruption()` mapping).
                    let reason = label
                        .strip_prefix("NoOp(")
                        .and_then(|s| s.strip_suffix(')'))
                        .unwrap_or(label.as_str());
                    let _ = writeln!(io::stdout(), "noop: {reason} [none]");
                }
                apply::ApplyOutcome::Failed { .. } => {
                    let _ = writeln!(
                        io::stderr(),
                        "fail: {label} [{}] ({})",
                        outcome.disruption().label(),
                        outcome.detail(),
                    );
                }
                _ => {
                    let _ = writeln!(
                        io::stdout(),
                        "ok: {label} [{}] ({})",
                        outcome.disruption().label(),
                        outcome.detail(),
                    );
                }
            }
        }
        // #476: apply summary footer — symmetric with
        // `render_plan_summary_line` (#285 / #471). Emitted after
        // the per-action lines and before the exit code so
        // operators see the rollup at the bottom of the apply
        // output. Goes to stdout (matches plan footer).
        let _ = writeln!(io::stdout(), "{}", render_apply_summary_line(&result));
        // #478: rollback-state advisory — gated on
        // `!result.failed.is_empty()` so successful applies emit no
        // extra noise. Goes to STDERR (the advisory belongs with
        // `fail:` rows, not the success-path summary on stdout).
        // Multi-line block listing each failed action with its
        // recorded UndoSteps (#281's per-action mutation manifest)
        // so the operator sees what landed on disk before the
        // action errored. PHD-1 (#478 pass 1): when
        // `--rollback-on-failure` was set, `apply::undo` already
        // ran (best-effort, per-step failures logged to tracing,
        // not surfaced to the operator). The advisory still lists
        // the full step set because per-step undo success is not
        // tracked at the `ApplyResult` level — the steps describe
        // what was ATTEMPTED (forward-direction inversions) or
        // SKIPPED (reverse-direction lossy ones), not what
        // residual state remains. Operator MUST treat the list as
        // a cleanup checklist, not a "still pending" report.
        if let Some(advisory) = render_rollback_advisory(&result) {
            let _ = writeln!(io::stderr(), "{advisory}");
        }
    }

    Ok(apply_exit_code(
        &result,
        args.detailed_exitcode,
        args.detailed_exitcode_recreate,
    ))
}

/// #478: render the rollback-state advisory for a failed `apply` run,
/// or `None` when no action failed (success path emits no advisory).
/// The advisory walks `result.failed_undo_logs` (populated by
/// `apply()` on every Err path) and produces a multi-line block:
///
/// ```text
/// Rollback advisory: N action(s) failed. Manual cleanup may be required:
///   LABEL_A:
///     - started gh-runner@foo.service
///     - wrote /etc/ghars/runners/foo/00-ghars.conf
///   LABEL_B:
///     - created group ghars-cache-build
/// ```
///
/// Per-step descriptions come from [`apply::UndoStep::describe`] —
/// past-tense, byte-content omitted, operator-readable. Steps are
/// listed in REVERSE (LIFO) order — the most recent mutation first —
/// matching the iteration direction of [`apply::undo`] (apply.rs's
/// `log.steps().iter().rev()`). The intent: an operator reading
/// top-to-bottom can apply the inverse of each line and unwind the
/// state in the same order [`apply::undo`] would have, regardless of
/// whether `--rollback-on-failure` ran. The verb tokens below come
/// verbatim from [`apply::UndoStep::describe`] — left column matches
/// the past-tense strings that function emits for each variant
/// (`wrote`, `removed file`, `created directory`, …). Right column
/// is the operator inverse, NOT what `apply::undo` runs (some
/// inverses are reverse-direction and skipped per
/// [`apply::UndoStep::is_reverse_direction`]; see "(lossy)" /
/// "re-run `apply`" entries). When `describe()` gains a variant or
/// changes a verb, this table MUST be updated in lockstep:
/// - `wrote PATH`              → `rm PATH`
/// - `removed file PATH`       → restore from backup (lossy)
/// - `created directory PATH`  → `rmdir PATH`
/// - `removed directory PATH`  → re-run `apply` to recreate
/// - `started UNIT`            → `systemctl stop UNIT`
/// - `stopped UNIT`            → `systemctl start UNIT`
/// - `enabled UNIT`            → `systemctl disable UNIT`
/// - `disabled UNIT`           → `systemctl enable UNIT`
/// - `created group NAME`      → `groupdel NAME`
/// - `deleted group NAME`      → `groupadd --system NAME` (lossy)
/// - `created user NAME`       → `userdel -r NAME`
/// - `deleted user NAME`       → re-run `apply` to recreate
/// - `registered runner NAME …` → `config.sh remove --token <fresh>`
///
/// Entries with empty step lists (synthetic `daemon_reload` post-loop
/// failure; actions that errored before recording any side effect)
/// are skipped from the per-label block. Header N counts ONLY entries
/// with non-empty step lists (#618), so header count == body block
/// count under the mixed case (some empty + some non-empty); empty-
/// step failures still surface via the per-action `fail:` lines from
/// the cmd_apply detail loop.
///
/// #553: invariant `result.failed.len() == result.failed_undo_logs.len()`.
/// `apply::apply` pushes both Vecs in lockstep on every Err arm
/// (per-action arm at apply.rs:2123/2147-2149; synthetic
/// daemon_reload arm at apply.rs:2188/2201). The lengths can only
/// diverge in hand-constructed `ApplyResult` test fixtures.
/// `debug_assert_eq!` pins the contract in dev/CI builds; release
/// builds proceed because `n` (the header count) and the body loop
/// both derive from `failed_undo_logs` independently of `failed`.
///
/// #551 / #618: returns `None` when no entry in `failed_undo_logs` has
/// a non-empty step list. A single gate (`n == 0` after filtering)
/// covers both the no-failures case (`result.failed.is_empty()` ⇒
/// length-equal invariant ⇒ `failed_undo_logs.is_empty()` ⇒ `n == 0`)
/// and the all-empty-steps case (synthetic `daemon_reload` post-loop
/// failure; actions that errored before recording any side effect ⇒
/// every entry filtered out ⇒ `n == 0`). Returning `None` keeps
/// stderr clean — the per-action `fail:` lines from the cmd_apply
/// detail loop already communicate the failure count and labels;
/// the advisory's purpose is "what to clean up", and silence is
/// more honest than a header rendered by
/// [`format_rollback_advisory_header`] without a body. Pure function
/// (no I/O); the caller (`cmd_apply`) routes the returned text to
/// stderr.
#[must_use]
pub(crate) fn render_rollback_advisory(result: &apply::ApplyResult) -> Option<String> {
    debug_assert_eq!(
        result.failed.len(),
        result.failed_undo_logs.len(),
        "ApplyResult invariant: failed and failed_undo_logs must have equal length",
    );
    // #618: header N counts ONLY entries with non-empty step lists so
    // the printed count matches the body block count under the mixed
    // case (some empty + some non-empty). This single count subsumes
    // both prior early-return paths: `result.failed.is_empty()` ⇒
    // (length-equal invariant) ⇒ `failed_undo_logs.is_empty()` ⇒
    // `n == 0`; ALL-empty step lists ⇒ `n == 0`. One gate covers both.
    let n = result
        .failed_undo_logs
        .iter()
        .filter(|(_, steps)| !steps.is_empty())
        .count();
    if n == 0 {
        return None;
    }
    let mut out = format_rollback_advisory_header(n);
    for (label, steps) in &result.failed_undo_logs {
        if steps.is_empty() {
            continue;
        }
        // #600: defense-in-depth escape of the per-failure label.
        // Labels flow from `Action::label()` → `result.failed_undo_logs`
        // keys, derived from operator-supplied runner names and pool
        // names. Upstream `IDENTIFIER_REGEX` rejects control chars at
        // config-load time, so the only path to a hostile label today
        // would require a regex relaxation. Escaping at the render
        // site closes that asymmetry — the per-step bullets below
        // already escape via `step.describe()` + the per-step
        // `escape_control_chars` call inside the step-loop body
        // further down this function, so the label needed parity
        // coverage.
        out.push_str("\n  ");
        out.push_str(&escape_control_chars(label));
        out.push(':');
        // F-DA2 (#478 pass 1): walk steps in REVERSE (LIFO) to match
        // apply::undo's `log.steps().iter().rev()` direction. The
        // operator's manual-cleanup checklist reads top-to-bottom
        // and undoes the most-recent mutation first.
        //
        // #552: defense-in-depth escape of the per-step description
        // before stderr emission. `UndoStep::describe()` interpolates
        // operator-supplied paths (drop-in basenames built from runner
        // names) and unit/group/user names; upstream charset
        // validators reject control chars at config-load and
        // render-identity time, but a renderer-side scrub means a
        // future relaxation in those validators cannot leak ANSI
        // escapes into the rollback advisory.
        for step in steps.iter().rev() {
            out.push_str("\n    - ");
            out.push_str(&escape_control_chars(&step.describe()));
        }
    }
    Some(out)
}

/// #611: single source of truth for the advisory header line in
/// production code. Extracting the format string behind a named
/// function means a future text change ("Rollback advisory:" /
/// "Manual cleanup may be required:") happens in one place at the
/// call site, not scattered across every renderer that used to
/// inline the literal (mirrors the #471 pattern that lifted
/// Disruption-label tokens behind `Disruption::label()`). Tests
/// continue to hardcode the operator-visible substrings — that's
/// correct for contract pinning: a test that calls this helper
/// would silently pass after a header rename, while a substring
/// assertion fails loudly and signals the operator-visible break.
///
/// Naming follows the project's `format_*` precedent for pure
/// string-building helpers (e.g. `format_disruption_tail` /
/// peers in `render_plan_summary_line`); see #652.
fn format_rollback_advisory_header(n: usize) -> String {
    format!("Rollback advisory: {n} action(s) failed. Manual cleanup may be required:")
}

/// Map a slice of `preflight::CheckResult` to the `ghars status`
/// process exit code per Part 5.
///
/// - any `Outcome::Fail` in `health` → 3 (preflight/validation failure)
/// - otherwise → 0
///
/// Pure function (no I/O); pulled out so tests can synthesize health
/// vectors without a real preflight scan (#237). Both
/// `render_status_text` and `render_status_json` delegate to keep the
/// same exit-code contract regardless of output format.
#[must_use]
pub(crate) fn status_exit_code(health: &[preflight::CheckResult]) -> i32 {
    if health
        .iter()
        .any(|c| matches!(c.outcome, preflight::Outcome::Fail))
    {
        3
    } else {
        0
    }
}

/// True iff `plan` contains any action whose
/// [`crate::plan::Action::disruption`] is
/// [`crate::plan::Disruption::Recreate`]. Drives the
/// `--detailed-exitcode-recreate` exit-code 8 path (#464).
///
/// Recreate-class actions per [`crate::plan::Action::disruption`] at
/// plan.rs: `CreateRunner`, `UpdateRunner` with
/// `requires_recreate=true`, `RemoveRunner`, `CreateCachePool`, and
/// `RemoveCachePool`. `UpdateCachePool` is always
/// `Disruption::Restart`. Ignores `Disruption::Restart` (in-place
/// restart) and `Disruption::None` (NoOp).
#[must_use]
pub(crate) fn plan_has_recreate(plan: &Plan) -> bool {
    plan.actions
        .iter()
        .any(|a| a.disruption() == plan::Disruption::Recreate)
}

/// Returns `Some(8)` when the operator opted into
/// `--detailed-exitcode-recreate` AND the plan contains a recreate-
/// class action; otherwise `None` so callers fall through to the
/// existing `--detailed-exitcode` / default-0 logic.
///
/// Plan-side recreate gate. Three lexical direct callers:
/// 1. `cmd_apply` pre-confirm gate (fires BEFORE `confirm_apply` runs,
///    regardless of `--auto-approve`),
/// 2. `cancel_exit_code` (apply-cancel surface),
/// 3. `dry_run_exit_code` (plan + apply-dry-run surfaces).
///
/// CLI surfaces map onto these callers via direct + transitive routing:
/// the `cmd_apply` pre-confirm gate calls this helper directly;
/// `cmd_plan` and `cmd_apply --dry-run` reach it transitively through
/// `dry_run_exit_code`; `cmd_apply`'s cancel path reaches it
/// transitively through `cancel_exit_code`; the post-apply success
/// path reaches NEITHER this helper NOR a delegating wrapper.
///
/// The post-apply path (`apply_exit_code`) does NOT delegate here: it
/// inlines an equivalent `Disruption::Recreate` check against
/// `result.details` (apply-time outcomes) instead of `plan.actions`
/// (plan-time declarations). The two data sources are equivalent for
/// the recreate signal because [`crate::plan::Action::disruption`] and
/// [`crate::apply::ApplyOutcome::disruption`] both return
/// [`crate::plan::Disruption::Recreate`] for the same set of variants.
///
/// Returning `Option` instead of a plain `i32` lets the caller chain
/// `.or_else(|| ...)` with the existing helpers without sprinkling
/// early returns across the command-dispatch path. (#464)
#[must_use]
pub(crate) fn recreate_exit_code(detailed_exitcode_recreate: bool, plan: &Plan) -> Option<i32> {
    if detailed_exitcode_recreate && plan_has_recreate(plan) {
        Some(8)
    } else {
        None
    }
}

/// Process exit code when the operator cancels at the apply prompt
/// (`y/N` answered N). Pulled out so tests can pin the contract
/// without driving the cmd_apply path through a TTY mock.
///
/// Precedence (#464):
/// - `--detailed-exitcode-recreate` set + recreate-class action in
///   `plan` → 8. "Plan contains a recreate the operator must
///   review; do not auto-merge."
/// - else `--detailed-exitcode` set → 2. The plan had pending
///   changes the operator chose not to apply; 2 communicates "diff
///   present, not applied" — terraform-class signal that wrapping
///   scripts can branch on without parsing stderr (#358).
/// - else → 0. Cancelling an interactive prompt is the established
///   CLI convention for "user aborted; not an error".
///
/// Recreate trumps detailed-changes: when both flags fire, 8 is
/// strictly more informative than 2 (recreate implies pending
/// changes, but pending changes do not imply recreate).
#[must_use]
pub(crate) fn cancel_exit_code(
    detailed_exitcode: bool,
    detailed_exitcode_recreate: bool,
    plan: &Plan,
) -> i32 {
    if let Some(code) = recreate_exit_code(detailed_exitcode_recreate, plan) {
        return code;
    }
    if detailed_exitcode {
        2
    } else {
        0
    }
}

/// Process exit code for `apply --dry-run` (Part 5).
///
/// `--dry-run` is documented as an alias for `ghars plan`; with
/// `--detailed-exitcode`, exit 2 when the plan has any non-NoOp
/// action — terraform `plan -detailed-exitcode` parity. Pulled out
/// so tests pin the contract without spinning up a real D-Bus or
/// the apply runtime (#389).
///
/// Precedence (#464):
/// - `detailed_exitcode_recreate = true`, plan has recreate         → 8
/// - else `detailed_exitcode = false`                                → 0
/// - else `detailed_exitcode = true`, plan all-NoOp                  → 0
/// - else `detailed_exitcode = true`, plan has any non-NoOp action   → 2
#[must_use]
pub(crate) fn dry_run_exit_code(
    detailed_exitcode: bool,
    detailed_exitcode_recreate: bool,
    plan: &Plan,
) -> i32 {
    if let Some(code) = recreate_exit_code(detailed_exitcode_recreate, plan) {
        return code;
    }
    if detailed_exitcode && plan.actions.iter().any(|a| !matches!(a, Action::NoOp(_))) {
        2
    } else {
        0
    }
}

/// Map an `ApplyResult` to the process exit code per Part 5.
///
/// Precedence (Part 5 + #251 + #464 rulings):
/// - partial failure         → 4  (some succeeded, some failed)
/// - total failure, any auth → 5
/// - total failure, no auth  → 1
/// - no failures, recreate-class action present + flag set → 8 (#464)
/// - no failures             → 0  (or 2 with `--detailed-exitcode`)
///
/// Partial failure (4) wins over auth (5) when both apply because 4
/// communicates strictly more to the operator: "some actions landed,
/// others did not — go look at the per-action log". 5 is narrower
/// ("nothing landed, and at least one Auth error explains why");
/// collapsing a partial-success run to 5 would hide the partial
/// progress. (#251)
///
/// Failure precedence trumps recreate (#464): both 4 and 5 are
/// stronger than 8. A partial apply leaves the operator with a
/// concrete cleanup task ("some actions landed"); a recreate flag
/// is a plan-shape signal about what the apply WOULD have done.
/// Surfacing 8 over 4 would hide the more-actionable "go check
/// what landed" signal. Same reasoning for 5: auth failure is a
/// structural pre-condition violation; recreate is downstream
/// plan-shape. Recreate (8) only fires on the success path
/// (`result.failed.is_empty()`).
///
/// Recreate detection uses [`apply::ApplyOutcome::disruption`] on
/// every entry of `result.details` so the same rule that drives the
/// `[recreate]` bracket tag also drives this exit-code branch —
/// single source of truth, no risk of plan-time/apply-time drift.
///
/// Pulled out as a pure function so tests synthesize `ApplyResult`
/// values and pin the precedence directly without spinning up D-Bus or
/// the apply runtime (#237).
#[must_use]
pub(crate) fn apply_exit_code(
    result: &apply::ApplyResult,
    detailed_exitcode: bool,
    detailed_exitcode_recreate: bool,
) -> i32 {
    if result.failed.is_empty() {
        if detailed_exitcode_recreate
            && result
                .details
                .iter()
                .any(|(_, o)| o.disruption() == plan::Disruption::Recreate)
        {
            return 8;
        }
        return if detailed_exitcode { 2 } else { 0 };
    }
    if !result.succeeded.is_empty() {
        return 4;
    }
    let any_auth = result
        .failed
        .iter()
        .any(|(_, e)| matches!(e, GharsError::Auth(_, _)));
    if any_auth {
        5
    } else {
        1
    }
}

fn confirm_apply() -> Result<bool> {
    // #253: detect a non-TTY stdin BEFORE blocking on read_line. When
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

// ---------- status ------------------------------------------------------

fn cmd_status(
    config_path: &Utf8Path,
    paths: &Paths,
    args: &StatusArgs,
    color: ColorMode,
    quiet: bool,
) -> Result<i32> {
    let _ = color;
    let _ = quiet;

    // #261 design ruling (Part 10 status section): cmd_status MUST load
    // the config FIRST, before any other work. Two reasons make this
    // non-negotiable:
    //
    //   1. Orphan classification (the "ORPHAN — no [[runner]] in config;
    //      next apply will REMOVE" column at design line 3649) requires
    //      the parsed desired set. Without it, runners discovered on
    //      disk can't be told apart from runners the operator declared.
    //   2. Smoke-test invariant: `ghars status --runners-only` after a
    //      config edit must surface "your config is malformed" if it is.
    //      Suppressing config errors and proceeding violates fail-fast
    //      and wastes operator time on "why is status showing X?" when
    //      the answer is "config wouldn't parse anyway."
    let cfg = load_config(config_path)?;

    let health = if args.runners_only {
        Vec::new()
    } else {
        preflight::run_all(false)
    };

    let runners = if args.health_only {
        state::ActualState::default()
    } else {
        let mut actual = match DbusSystemd::new() {
            Ok(s) => state::discover(&s, paths)?,
            Err(err) => {
                // #262: surface the failure on stderr instead of returning
                // an empty default silently. State output that omits
                // managed runners with no warning misleads operators into
                // thinking nothing is installed when in fact the system
                // bus is unreachable (sandboxed shell, broken dbus,
                // missing CAP_SYS_RAWIO inside a container, etc.).
                eprintln!(
                    "warning: systemd D-Bus connection failed: {err}; runner state unavailable."
                );
                state::ActualState::default()
            }
        };
        // #261: populate `actual.orphans` here. state::discover always
        // returns an empty orphans Vec because at the discovery layer we
        // only know "managed" vs "external", not "in-config" vs "out-of-
        // config" — see the ActualState.orphans doc. cmd_status is the
        // first caller that has both halves available, so it does the
        // diff inline. The design ruling at Part 10 calls this
        // diff_against_config(actual, desired); inlined here as a
        // simple set-difference rather than a new pub fn until a second
        // caller needs it (status text renderer covers the orphan
        // column off this same field).
        let desired_names: std::collections::HashSet<&str> =
            cfg.runners.iter().map(|r| r.name.as_str()).collect();
        for name in actual.runners.keys() {
            if !desired_names.contains(name.as_str()) {
                actual
                    .orphans
                    .push(state::OrphanedUnit { name: name.clone() });
            }
        }
        actual
    };

    let metrics_rows = if args.metrics {
        collect_metrics(&runners.runners.keys().cloned().collect::<Vec<_>>()).unwrap_or_default()
    } else {
        Vec::new()
    };

    if args.json {
        return render_status_json(&health, &runners, &metrics_rows);
    }
    render_status_text(&health, &runners, &metrics_rows, &args.names)
}

fn render_status_text(
    health: &[preflight::CheckResult],
    runners: &state::ActualState,
    metrics: &[MetricRow],
    name_filter: &[String],
) -> Result<i32> {
    let mut stdout = io::stdout().lock();
    if !health.is_empty() {
        writeln!(stdout, "SYSTEM HEALTH").map_err(GharsError::Io)?;
        for c in health {
            let outcome = match c.outcome {
                preflight::Outcome::Pass => "PASS",
                preflight::Outcome::Fail => "FAIL",
                preflight::Outcome::Warn => "WARN",
                preflight::Outcome::Skip => "SKIP",
            };
            writeln!(stdout, "  {outcome:<5} {:<14} {}", c.name, c.detail)
                .map_err(GharsError::Io)?;
            if !c.hint.is_empty() {
                writeln!(stdout, "          hint: {}", c.hint).map_err(GharsError::Io)?;
            }
        }
        writeln!(stdout).map_err(GharsError::Io)?;
    }
    if !runners.runners.is_empty() || !runners.external.is_empty() {
        writeln!(stdout, "RUNNERS").map_err(GharsError::Io)?;
        writeln!(
            stdout,
            "  {:<24} {:<10} {:<10} drift",
            "name", "active", "enabled"
        )
        .map_err(GharsError::Io)?;
        for (name, r) in &runners.runners {
            if !name_filter.is_empty() && !name_filter.iter().any(|n| n == name) {
                continue;
            }
            let active = if r.running { "active" } else { "inactive" };
            let enabled = if r.enabled { "enabled" } else { "disabled" };
            // Drift labels match `state::Drift` variant names rendered
            // snake_case so text + JSON output share one label vocabulary
            // (e.g. `grep drop_ins_modified` works against either).
            // For variants carrying the unmanaged-basenames Vec, the
            // basenames are appended after a colon so the operator can
            // see which files drifted without re-running `systemctl cat`.
            let drift = match &r.drift {
                state::Drift::InSync => "in_sync".to_string(),
                state::Drift::UnitEdited => "unit_edited".to_string(),
                state::Drift::DropInsModified(names) => {
                    format!("drop_ins_modified: {}", names.join(", "))
                }
                state::Drift::Both(names) => {
                    format!("both: {}", names.join(", "))
                }
            };
            writeln!(stdout, "  {name:<24} {active:<10} {enabled:<10} {drift}")
                .map_err(GharsError::Io)?;
        }
        for ext in &runners.external {
            writeln!(stdout, "  {ext:<24} external   -          -").map_err(GharsError::Io)?;
        }
        writeln!(stdout).map_err(GharsError::Io)?;
    }
    if !metrics.is_empty() {
        writeln!(stdout, "METRICS").map_err(GharsError::Io)?;
        render_metrics_text(&mut stdout, metrics, false)?;
    }
    Ok(status_exit_code(health))
}

fn render_status_json(
    health: &[preflight::CheckResult],
    runners: &state::ActualState,
    metrics: &[MetricRow],
) -> Result<i32> {
    let health_json: Vec<serde_json::Value> = health
        .iter()
        .map(|c| {
            let outcome = match c.outcome {
                preflight::Outcome::Pass => "pass",
                preflight::Outcome::Fail => "fail",
                preflight::Outcome::Warn => "warn",
                preflight::Outcome::Skip => "skip",
            };
            serde_json::json!({
                "name": c.name,
                "outcome": outcome,
                "detail": c.detail,
                "hint": c.hint,
            })
        })
        .collect();
    let runners_json: Vec<serde_json::Value> = runners
        .runners
        .iter()
        .map(|(name, r)| {
            // Extract the unmanaged-basenames Vec carried by
            // `DropInsModified` and `Both`. The Vec is non-empty by
            // construction (`state::classify_drift`) — `Vec::new()` would
            // mean InSync — so we only emit the JSON field when those
            // variants fire.
            let unmanaged: &[String] = match &r.drift {
                state::Drift::DropInsModified(names) | state::Drift::Both(names) => names,
                state::Drift::InSync | state::Drift::UnitEdited => &[],
            };
            let mut obj = serde_json::json!({
                "name": name,
                "running": r.running,
                "enabled": r.enabled,
                "drift": match &r.drift {
                    state::Drift::InSync => "in_sync",
                    state::Drift::UnitEdited => "unit_edited",
                    state::Drift::DropInsModified(_) => "drop_ins_modified",
                    state::Drift::Both(_) => "both",
                },
                "spec_hash": r.spec_hash,
            });
            if !unmanaged.is_empty() {
                obj.as_object_mut()
                    .expect("serde_json::json!({...}) always returns Object")
                    .insert(
                        "drift_unmanaged_drop_ins".into(),
                        serde_json::Value::Array(
                            unmanaged
                                .iter()
                                .map(|s| serde_json::Value::String(s.clone()))
                                .collect(),
                        ),
                    );
            }
            obj
        })
        .collect();
    let metrics_json: Vec<serde_json::Value> = metrics
        .iter()
        .map(|m| {
            serde_json::json!({
                "name": m.name,
                "memory_bytes": m.memory_bytes,
                "cpu_nsec": m.cpu_nsec,
                "io_read_bytes": m.io_read_bytes,
                "io_write_bytes": m.io_write_bytes,
                "tasks": m.tasks,
            })
        })
        .collect();
    let body = serde_json::json!({
        "health": health_json,
        "runners": runners_json,
        "external": runners.external,
        "metrics": metrics_json,
    });
    let mut stdout = io::stdout().lock();
    // See render_plan_json: encode failures map to Io, not Config.
    serde_json::to_writer_pretty(&mut stdout, &body)
        .map_err(|e| GharsError::Io(io::Error::other(format!("encode status json: {e}"))))?;
    writeln!(stdout).map_err(GharsError::Io)?;
    Ok(status_exit_code(health))
}

// ---------- init --------------------------------------------------------

const INIT_EXAMPLE_CONFIG: &str = "\
# ghars config — see https://github.com/OWNER/REPO for the full schema.
# All identifier keys (auth.*, cache_pools.*, network.*, [[runner]].name)
# must match `^[a-z]([a-z0-9-]*[a-z0-9])?$` and be ≤ 64 chars.

[defaults]
# user: leave unset so each runner gets `ghars-RUNNERNAME` (SEC-27).
prefix = \"/var/lib/ghars\"
runner_version = \"2.334.0\"
auth = \"pat\"
arch = \"x86_64\"
labels = [\"self-hosted\", \"linux\"]

[auth.pat]
kind = \"pat\"
token_env = \"GHARS_PAT\"

# Uncomment when adding runners.
# [[runner]]
# name = \"example\"
# url = \"https://github.com/owner/repo\"
# labels = [\"x64\"]
";

fn cmd_init(config_path: &Utf8Path, args: &InitArgs, quiet: bool) -> Result<i32> {
    let dest = args
        .output
        .clone()
        .unwrap_or_else(|| config_path.to_owned());
    if let Some(parent) = dest.parent() {
        fs::create_dir_all(parent.as_std_path())?;
    }
    if dest.exists() {
        return Err(GharsError::Validation(
            format!("{dest} already exists; refusing to overwrite"),
            "delete the file or pass `--output PATH` for a different location".into(),
        ));
    }
    // Mode 0640: owner rw, group r, world none. The default umask leaves
    // /etc/ghars/ghars.toml world-readable (0644) which would expose the
    // [auth.*] section's `token_env` / `token_file` references — those
    // are paths/env-var names, not secrets, but they fingerprint the
    // operator's secrets layout. Enforce 0640 from creation so the
    // window where the file is world-readable doesn't exist (compared to
    // a write-then-chmod sequence).
    let mut f = OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(0o640)
        .open(dest.as_std_path())?;
    f.write_all(INIT_EXAMPLE_CONFIG.as_bytes())?;
    f.flush()?;

    // SEC-27: ghars no longer creates a shared `ghars` system user at
    // init time. Per-runner system users (`ghars-RUNNERNAME`) are
    // provisioned by `apply::execute_create_runner` via
    // `RealUsers::useradd_if_missing` — that's where they belong, since
    // the runner name is known and the per-runner UID gives cross-
    // runner ptrace/signal/DAC isolation for free. A vestigial shared
    // `ghars` user contradicts that model and would have led operators
    // into the SEC-27 hole that per-runner UIDs are designed to close.
    if !quiet {
        let _ = writeln!(io::stdout(), "wrote {dest}");
    }
    Ok(0)
}

// ---------- add ---------------------------------------------------------

fn cmd_add(
    config_path: &Utf8Path,
    paths: &Paths,
    args: &AddArgs,
    color: ColorMode,
    quiet: bool,
) -> Result<i32> {
    let cfg = load_config(config_path)?;

    let url = format!("https://github.com/{}", args.repo.trim_start_matches('/'));
    let name = args.name.clone().unwrap_or_else(|| {
        // OWNER/REPO → owner-repo-N (next free index); OWNER → owner-N.
        let base = args.repo.replace('/', "-");
        let mut i: u32 = 1;
        loop {
            let candidate = format!("{base}-{i}");
            if !cfg.runners.iter().any(|r| r.name == candidate) {
                break candidate;
            }
            i += 1;
        }
    });
    let auth = args
        .auth
        .clone()
        .or_else(|| cfg.defaults.auth.clone())
        .unwrap_or_else(|| "interactive".into());

    // #254: validate the constructed URL + auth ref BEFORE appending the
    // [[runner]] block. Catching a typo here avoids leaving a malformed
    // block in the user's config that the next `apply` would reject.
    validators::validate_url(&url)?;
    if !cfg.auth.contains_key(&auth) {
        let known: Vec<&str> = cfg.auth.keys().map(String::as_str).collect();
        let known_msg = if known.is_empty() {
            "no [auth.*] entries are declared in the config".to_string()
        } else {
            format!("known auth keys: {}", known.join(", "))
        };
        return Err(GharsError::Validation(
            format!("auth {auth:?} is not declared in [auth.*]"),
            format!(
                "add a `[auth.{auth}]` block (e.g. `[auth.{auth}] kind = \"interactive\"`) or pass \
                 `--auth NAME` referencing an existing entry; {known_msg}"
            ),
        ));
    }
    // The runner name is generated above (auto-numbered) when the
    // operator omits --name; either way it must satisfy
    // IDENTIFIER_REGEX so apply downstream accepts it. (#243)
    validators::validate_runner_name(&name)?;

    // Build the [[runner]] TOML block manually. We avoid round-tripping
    // the full config because that would erase comments + key order.
    use std::fmt::Write as _;
    let mut block = String::new();
    block.push_str("\n[[runner]]\n");
    let _ = writeln!(block, "name = \"{name}\"");
    let _ = writeln!(block, "url = \"{url}\"");
    if !args.labels.is_empty() {
        let labels: Vec<String> = args.labels.iter().map(|l| format!("\"{l}\"")).collect();
        let _ = writeln!(block, "labels = [{}]", labels.join(", "));
    }
    if cfg.defaults.auth.as_deref() != Some(auth.as_str()) {
        let _ = writeln!(block, "auth = \"{auth}\"");
    }

    let mut existing = fs::read_to_string(config_path.as_std_path())?;
    if !existing.ends_with('\n') {
        existing.push('\n');
    }
    existing.push_str(&block);
    fs::write(config_path.as_std_path(), existing)?;

    if !quiet {
        let _ = writeln!(io::stdout(), "added [[runner]] {name}");
    }

    if args.no_apply {
        return Ok(0);
    }

    // Re-load + apply.
    let apply_args = ApplyArgs {
        only: vec![name],
        auto_approve: false,
        fail_fast: false,
        dry_run: false,
        detailed_exitcode: false,
        detailed_exitcode_recreate: false,
        rollback_on_failure: false,
        diff: false,
    };
    cmd_apply(config_path, paths, &apply_args, color, quiet)
}

// ---------- logs --------------------------------------------------------

fn cmd_logs(paths: &Paths, args: &LogsArgs) -> Result<i32> {
    let names = if args.names.is_empty() {
        match DbusSystemd::new() {
            Ok(s) => state::discover(&s, paths)?
                .runners
                .keys()
                .cloned()
                .collect::<Vec<_>>(),
            Err(err) => {
                // #262: do not silently substitute an empty discovery —
                // tail with no names returns a confusing "no runners to
                // tail" error below; the operator deserves to know that
                // the underlying cause was a D-Bus failure.
                eprintln!(
                    "warning: systemd D-Bus connection failed: {err}; runner state unavailable."
                );
                Vec::new()
            }
        }
    } else {
        // #255: validate operator-supplied names against IDENTIFIER_REGEX
        // before constructing the journalctl query. journalctl `-u
        // ghars-runner@$NAME.service` would gleefully spawn for any
        // string; rejecting bad shapes early gives a clear error and
        // closes a SEC-35-adjacent injection vector via the unit name.
        for name in &args.names {
            validators::validate_runner_name(name).map_err(|e| match e {
                GharsError::Validation(msg, _) => GharsError::Validation(
                    format!("invalid runner name {name:?}: {msg}"),
                    format!(
                        "names must match IDENTIFIER_REGEX (lowercase letters, digits, \
                         dashes; start with a letter, end with a letter or digit) and \
                         be ≤{} characters",
                        validators::RUNNER_NAME_MAX_LEN,
                    ),
                ),
                other => other,
            })?;
        }
        args.names.clone()
    };

    if names.is_empty() {
        return Err(GharsError::Validation(
            "no runners to tail".into(),
            "pass NAMES or run after `ghars apply` so managed units exist".into(),
        ));
    }

    let mut cmd = ProcCommand::new("journalctl");
    for name in &names {
        cmd.arg("-u").arg(format!("ghars-runner@{name}.service"));
    }
    if args.follow {
        cmd.arg("-f");
    }
    cmd.arg("-n").arg(args.lines.to_string());
    if let Some(since) = &args.since {
        cmd.arg("--since").arg(since);
    }
    let status = cmd
        .stdout(Stdio::inherit())
        .stderr(Stdio::inherit())
        .stdin(Stdio::inherit())
        .status()
        .map_err(GharsError::Io)?;
    Ok(status.code().unwrap_or(1))
}

// ---------- metrics -----------------------------------------------------

#[derive(Debug, Default, Clone)]
struct MetricRow {
    name: String,
    memory_bytes: u64,
    cpu_nsec: u64,
    io_read_bytes: u64,
    io_write_bytes: u64,
    tasks: u64,
}

fn cmd_metrics(paths: &Paths, args: &MetricsArgs) -> Result<i32> {
    let names = if args.names.is_empty() {
        match DbusSystemd::new() {
            Ok(s) => state::discover(&s, paths)?
                .runners
                .keys()
                .cloned()
                .collect::<Vec<_>>(),
            Err(err) => {
                // #262: surface the failure rather than returning an empty
                // metrics table that hides why nothing is shown.
                eprintln!(
                    "warning: systemd D-Bus connection failed: {err}; runner state unavailable."
                );
                Vec::new()
            }
        }
    } else {
        // #255: validate operator-supplied names against IDENTIFIER_REGEX
        // before the D-Bus per-unit query (`Manager.GetUnit
        // ghars-runner@$NAME.service`) is constructed.
        for name in &args.names {
            validators::validate_runner_name(name).map_err(|e| match e {
                GharsError::Validation(msg, _) => GharsError::Validation(
                    format!("invalid runner name {name:?}: {msg}"),
                    format!(
                        "names must match IDENTIFIER_REGEX (lowercase letters, digits, \
                         dashes; start with a letter, end with a letter or digit) and \
                         be ≤{} characters",
                        validators::RUNNER_NAME_MAX_LEN,
                    ),
                ),
                other => other,
            })?;
        }
        args.names.clone()
    };
    let rows = collect_metrics(&names)?;
    if args.json {
        return render_metrics_json(&rows, args.no_total);
    }
    let mut stdout = io::stdout().lock();
    render_metrics_text(&mut stdout, &rows, args.no_total)?;
    Ok(0)
}

fn collect_metrics(names: &[String]) -> Result<Vec<MetricRow>> {
    let connection = Connection::system().map_err(|e| {
        GharsError::Systemd(
            format!("system D-Bus connect failed: {e}"),
            "verify dbus is running and the caller has access to the system bus".into(),
        )
    })?;
    let manager = Proxy::new(
        &connection,
        "org.freedesktop.systemd1",
        "/org/freedesktop/systemd1",
        "org.freedesktop.systemd1.Manager",
    )
    .map_err(|e| {
        GharsError::Systemd(
            format!("construct Manager proxy: {e}"),
            "verify systemd D-Bus interface is reachable".into(),
        )
    })?;
    let mut rows: Vec<MetricRow> = Vec::with_capacity(names.len());
    for name in names {
        let unit = format!("ghars-runner@{name}.service");
        let row = match read_metrics(&connection, &manager, &unit, name) {
            Ok(row) => row,
            Err(err) => {
                // Per-runner D-Bus failures are surfaced on stderr so the
                // operator can tell which rows are real vs missing data.
                // The row stays in the output (with zeros) so downstream
                // consumers see a stable shape — but the warning makes
                // clear the zeros are "lookup failed", not "actually 0".
                let _ = writeln!(io::stderr(), "warning: metrics: {name}: {err}");
                MetricRow {
                    name: name.clone(),
                    ..MetricRow::default()
                }
            }
        };
        rows.push(row);
    }
    Ok(rows)
}

fn read_metrics(
    connection: &Connection,
    manager: &Proxy<'_>,
    unit: &str,
    runner_name: &str,
) -> Result<MetricRow> {
    let path: OwnedObjectPath = manager.call("GetUnit", &(unit,)).map_err(|e| {
        GharsError::Systemd(
            format!("Manager.GetUnit({unit}): {e}"),
            "verify the unit is loaded — daemon-reload + try again".into(),
        )
    })?;
    let unit_proxy = Proxy::new(
        connection,
        "org.freedesktop.systemd1",
        path.as_ref(),
        "org.freedesktop.systemd1.Service",
    )
    .map_err(|e| {
        GharsError::Systemd(
            format!("construct Service proxy for {unit}: {e}"),
            "verify systemd D-Bus interface is reachable".into(),
        )
    })?;

    let memory_bytes = unit_proxy.get_property::<u64>("MemoryCurrent").unwrap_or(0);
    let cpu_nsec = unit_proxy.get_property::<u64>("CPUUsageNSec").unwrap_or(0);
    let io_read_bytes = unit_proxy.get_property::<u64>("IOReadBytes").unwrap_or(0);
    let io_write_bytes = unit_proxy.get_property::<u64>("IOWriteBytes").unwrap_or(0);
    let tasks = unit_proxy.get_property::<u64>("TasksCurrent").unwrap_or(0);

    Ok(MetricRow {
        name: runner_name.to_owned(),
        memory_bytes,
        cpu_nsec,
        io_read_bytes,
        io_write_bytes,
        tasks,
    })
}

fn render_metrics_text<W: Write>(stdout: &mut W, rows: &[MetricRow], no_total: bool) -> Result<()> {
    writeln!(
        stdout,
        "  {:<24} {:>10} {:>14} {:>14} {:>14} {:>8}",
        "name", "memory", "cpu_nsec", "io_read", "io_write", "tasks"
    )
    .map_err(GharsError::Io)?;
    let mut total = MetricRow {
        name: "TOTAL".into(),
        ..MetricRow::default()
    };
    for r in rows {
        writeln!(
            stdout,
            "  {:<24} {:>10} {:>14} {:>14} {:>14} {:>8}",
            r.name,
            human_bytes(r.memory_bytes),
            r.cpu_nsec,
            human_bytes(r.io_read_bytes),
            human_bytes(r.io_write_bytes),
            r.tasks
        )
        .map_err(GharsError::Io)?;
        total.memory_bytes = total.memory_bytes.saturating_add(r.memory_bytes);
        total.cpu_nsec = total.cpu_nsec.saturating_add(r.cpu_nsec);
        total.io_read_bytes = total.io_read_bytes.saturating_add(r.io_read_bytes);
        total.io_write_bytes = total.io_write_bytes.saturating_add(r.io_write_bytes);
        total.tasks = total.tasks.saturating_add(r.tasks);
    }
    if !no_total && rows.len() > 1 {
        writeln!(
            stdout,
            "  {:<24} {:>10} {:>14} {:>14} {:>14} {:>8}",
            total.name,
            human_bytes(total.memory_bytes),
            total.cpu_nsec,
            human_bytes(total.io_read_bytes),
            human_bytes(total.io_write_bytes),
            total.tasks
        )
        .map_err(GharsError::Io)?;
    }
    Ok(())
}

fn render_metrics_json(rows: &[MetricRow], no_total: bool) -> Result<i32> {
    let runners: Vec<serde_json::Value> = rows
        .iter()
        .map(|r| {
            serde_json::json!({
                "name": r.name,
                "memory_bytes": r.memory_bytes,
                "cpu_nsec": r.cpu_nsec,
                "io_read_bytes": r.io_read_bytes,
                "io_write_bytes": r.io_write_bytes,
                "tasks": r.tasks,
            })
        })
        .collect();
    // saturating fold matches the text path (render_metrics_text) so
    // overflow behavior is identical between formats. `.sum()` panics in
    // debug builds on overflow; saturating_add keeps the JSON path
    // consistent with the table path's saturating accumulator.
    let total = MetricRow {
        memory_bytes: rows
            .iter()
            .fold(0u64, |a, r| a.saturating_add(r.memory_bytes)),
        cpu_nsec: rows.iter().fold(0u64, |a, r| a.saturating_add(r.cpu_nsec)),
        io_read_bytes: rows
            .iter()
            .fold(0u64, |a, r| a.saturating_add(r.io_read_bytes)),
        io_write_bytes: rows
            .iter()
            .fold(0u64, |a, r| a.saturating_add(r.io_write_bytes)),
        tasks: rows.iter().fold(0u64, |a, r| a.saturating_add(r.tasks)),
        ..MetricRow::default()
    };
    let body = if no_total {
        serde_json::json!({ "runners": runners })
    } else {
        serde_json::json!({
            "runners": runners,
            "total": {
                "memory_bytes": total.memory_bytes,
                "cpu_nsec": total.cpu_nsec,
                "io_read_bytes": total.io_read_bytes,
                "io_write_bytes": total.io_write_bytes,
                "tasks": total.tasks,
            },
        })
    };
    let mut stdout = io::stdout().lock();
    // See render_plan_json: encode failures map to Io, not Config.
    serde_json::to_writer_pretty(&mut stdout, &body)
        .map_err(|e| GharsError::Io(io::Error::other(format!("encode metrics json: {e}"))))?;
    writeln!(stdout).map_err(GharsError::Io)?;
    Ok(0)
}

fn human_bytes(n: u64) -> String {
    bytesize::ByteSize::b(n).to_string()
}

// ---------- completions / manpages --------------------------------------

fn cmd_completions(shell: clap_complete::Shell) {
    cmd_completions_to(shell, &mut io::stdout());
}

/// `cmd_completions` with a caller-supplied writer (#252 helper). Tests
/// pass a `Vec<u8>` to capture the generated shell-completion script
/// and assert the per-shell preamble lands as expected. Production
/// always passes `io::stdout()`.
fn cmd_completions_to<W: io::Write>(shell: clap_complete::Shell, w: &mut W) {
    let mut cmd = Cli::command();
    let bin_name = cmd.get_name().to_owned();
    clap_complete::generate(shell, &mut cmd, bin_name, w);
}

fn cmd_manpages(output: &Utf8Path) -> Result<i32> {
    fs::create_dir_all(output.as_std_path())?;
    let cmd = Cli::command();
    let man = clap_mangen::Man::new(cmd.clone());
    let mut buffer: Vec<u8> = Vec::new();
    man.render(&mut buffer).map_err(GharsError::Io)?;
    let dest = output.join(format!("{}.1", cmd.get_name()));
    fs::write(dest.as_std_path(), buffer)?;
    // Recurse into subcommands so `ghars-status.1`, `ghars-apply.1`,
    // etc. are emitted alongside the top-level page.
    for sub in cmd.get_subcommands() {
        if sub.is_hide_set() {
            continue;
        }
        let sub_name = format!("{}-{}", cmd.get_name(), sub.get_name());
        let mut buffer: Vec<u8> = Vec::new();
        // clap::Command::name takes Into<clap::builder::Str>, which only
        // From<&'static str>. Leak the per-subcommand name string —
        // manpage generation runs once per `ghars manpages` invocation
        // and the leaks are bounded by the subcommand count.
        let leaked: &'static str = Box::leak(sub_name.clone().into_boxed_str());
        clap_mangen::Man::new(sub.clone().name(leaked))
            .render(&mut buffer)
            .map_err(GharsError::Io)?;
        let dest = output.join(format!("{sub_name}.1"));
        fs::write(dest.as_std_path(), buffer)?;
    }
    Ok(0)
}

#[cfg(test)]
#[allow(clippy::unwrap_used)]
mod tests {
    use super::*;
    use clap::Parser;

    // ---- #275: err_to_exit_code variant mapping ---------------------

    /// `GharsError::Config` → exit code 6 (Part 5).
    #[test]
    fn err_to_exit_code_config_returns_six() {
        let err = GharsError::Config("missing field".into(), "add it".into());
        assert_eq!(err_to_exit_code(&err), 6);
    }

    /// `GharsError::Validation` → exit code 6 (#357). Validation
    /// errors are config-shape rejections (trust_zone charset,
    /// duplicate caches, render_identity defense-in-depth) — the
    /// operator must edit the TOML to recover, same actionable
    /// class as Config.
    #[test]
    fn err_to_exit_code_validation_returns_six() {
        let err = GharsError::Validation("bad shape".into(), "fix it".into());
        assert_eq!(err_to_exit_code(&err), 6);
    }

    /// `GharsError::Interactive` → exit code 7 (#390). Distinct
    /// from `Validation` (6) because the operator-actionable
    /// answer is "pass `--auto-approve` or run from a TTY", not
    /// "edit the TOML". Wrapper scripts and CI gating need a
    /// dedicated code so a non-TTY apply can be retried with
    /// `--auto-approve` automatically without parsing the error
    /// message; collapsing into 6 would require shell scripts to
    /// `grep` for "auto-approve" in stderr to disambiguate.
    #[test]
    fn err_to_exit_code_interactive_returns_seven() {
        let err = GharsError::Interactive(
            "stdin is not a terminal".into(),
            "pass --auto-approve".into(),
        );
        assert_eq!(err_to_exit_code(&err), 7);
    }

    /// `GharsError::Auth` → exit code 5 (#357). Per-action auth
    /// failures during apply already route to 5 via `apply_exit_code`
    /// (#251); a top-level `Auth` Err is an auth-resolve failure
    /// outside per-action accounting and routes to the same code so
    /// scripts can branch uniformly on auth-class failures.
    #[test]
    fn err_to_exit_code_auth_returns_five() {
        let err = GharsError::Auth("token rejected".into(), "rotate".into());
        assert_eq!(err_to_exit_code(&err), 5);
    }

    /// `GharsError::Preflight` → exit code 3 (#357). Same code
    /// `cmd_apply` / `cmd_status` emit via `Ok(3)` for preflight
    /// failures, so wrapping scripts see "preflight failed" uniformly
    /// regardless of whether the failure surfaced via Err or via the
    /// per-command Ok(3) path.
    #[test]
    fn err_to_exit_code_preflight_returns_three() {
        let err = GharsError::Preflight("systemd too old".into(), "upgrade".into());
        assert_eq!(err_to_exit_code(&err), 3);
    }

    /// `GharsError::Io` → exit code 1 (generic).
    #[test]
    fn err_to_exit_code_io_returns_one() {
        let err = GharsError::Io(io::Error::other("encode failure"));
        assert_eq!(err_to_exit_code(&err), 1);
    }

    /// `GharsError::GitHub` → exit code 1 (#357). GitHub API errors
    /// are operator-environment problems (network, rate-limit,
    /// upstream outage), not config-shape — they don't route to 6.
    #[test]
    fn err_to_exit_code_github_returns_one() {
        let err = GharsError::GitHub("404 Not Found".into(), "verify URL".into());
        assert_eq!(err_to_exit_code(&err), 1);
    }

    /// `GharsError::Systemd` → exit code 1 (#357). D-Bus / unit
    /// errors are runtime-environment failures, not config-shape.
    #[test]
    fn err_to_exit_code_systemd_returns_one() {
        let err = GharsError::Systemd("D-Bus timeout".into(), "check dbus".into());
        assert_eq!(err_to_exit_code(&err), 1);
    }

    /// `GharsError::Tarball` → exit code 1 (#357). Tarball
    /// extraction failure (download, unpack) is a runtime/network
    /// issue, not config-shape.
    #[test]
    fn err_to_exit_code_tarball_returns_one() {
        let err = GharsError::Tarball("HTTP 502".into(), None);
        assert_eq!(err_to_exit_code(&err), 1);
    }

    /// `GharsError::Tarball` with a structured hint must map to the
    /// same exit code 1 — the new optional hint field is purely a
    /// rendering surface and must not influence exit-code mapping.
    /// Pin against a regression that adds a hint-aware exit-code
    /// branch (e.g. 0 for "expected" vs 1 for "unexpected").
    #[test]
    fn err_to_exit_code_tarball_with_hint_returns_one() {
        let err = GharsError::Tarball(
            "HTTP 502".into(),
            Some("retry; if persistent, check status.github.com".into()),
        );
        assert_eq!(err_to_exit_code(&err), 1);
    }

    /// `GharsError::Sha256Mismatch` → exit code 1 (#357). Digest
    /// mismatch on a downloaded tarball — runtime-class.
    #[test]
    fn err_to_exit_code_sha256_mismatch_returns_one() {
        let err = GharsError::Sha256Mismatch {
            path: "/var/lib/ghars/runner.tar.gz".into(),
            expected: "a".repeat(64),
            actual: "b".repeat(64),
        };
        assert_eq!(err_to_exit_code(&err), 1);
    }

    /// `GharsError::ApplyLocked` → exit code 1 (#357). Lock
    /// contention is operator-actionable but doesn't fit any of
    /// 3/4/5/6 semantics; routes to generic 1.
    #[test]
    fn err_to_exit_code_apply_locked_returns_one() {
        let err = GharsError::ApplyLocked {
            pid: 12345,
            path: "/run/ghars/apply.lock".into(),
            stale: false,
        };
        assert_eq!(err_to_exit_code(&err), 1);
    }

    /// `GharsError::Apply { .. }` → exit code 1 (#357). The Apply
    /// variant should never reach `err_to_exit_code` in practice
    /// (apply collects per-action failures into `ApplyResult` and
    /// routes via `apply_exit_code`); the arm exists as the
    /// unreachable-by-design safety net so the exhaustive match
    /// stays exhaustive.
    #[test]
    fn err_to_exit_code_apply_returns_one() {
        let inner = GharsError::Validation("inner".into(), "inner hint".into());
        let err = GharsError::Apply {
            action: "CreateRunner(buckos)".into(),
            source: Box::new(inner),
        };
        assert_eq!(err_to_exit_code(&err), 1);
    }

    // ---- #358: cancel_exit_code (cancel + --detailed-exitcode) -----

    /// Cancellation without `--detailed-exitcode` → 0. Cancelling
    /// an interactive prompt is a non-error per established CLI
    /// convention. With #464, `cancel_exit_code` also takes a
    /// recreate flag + `&Plan`; we pass `false` + an empty plan
    /// to pin the pre-#464 behavior.
    #[test]
    fn cancel_exit_code_without_detailed_returns_zero() {
        let plan = Plan::default();
        assert_eq!(cancel_exit_code(false, false, &plan), 0);
    }

    /// Cancellation with `--detailed-exitcode` → 2. Plan had
    /// pending changes the operator chose not to apply; 2
    /// communicates "diff present, not applied" — terraform-class
    /// signal that scripts can branch on without parsing stderr.
    #[test]
    fn cancel_exit_code_with_detailed_returns_two() {
        let plan = Plan::default();
        assert_eq!(cancel_exit_code(true, false, &plan), 2);
    }

    // ---- #389: dry_run_exit_code (apply --dry-run --detailed-exitcode)

    /// Dry-run without `--detailed-exitcode` → 0 regardless of plan
    /// contents. The terraform `plan -detailed-exitcode` semantic is
    /// strictly opt-in.
    #[test]
    fn dry_run_exit_code_without_detailed_returns_zero() {
        let plan = Plan {
            actions: vec![Action::CreateRunner(fake_runner_plan("a"))],
            warnings: vec![],
        };
        assert_eq!(dry_run_exit_code(false, false, &plan), 0);
    }

    /// Dry-run with `--detailed-exitcode` and a plan containing a
    /// non-NoOp action → 2 (terraform "diff present, not applied"). The
    /// non-NoOp action here is `CreateRunner`; any non-NoOp variant
    /// would trigger the same code path.
    #[test]
    fn dry_run_exit_code_with_detailed_and_non_noop_returns_two() {
        let plan = Plan {
            actions: vec![Action::CreateRunner(fake_runner_plan("a"))],
            warnings: vec![],
        };
        assert_eq!(dry_run_exit_code(true, false, &plan), 2);
    }

    /// Dry-run with `--detailed-exitcode` and an all-NoOp plan → 0.
    /// "no diff, no work needed" is the terraform-class signal of 0,
    /// not 2 — wrapping scripts must treat the two cases differently.
    #[test]
    fn dry_run_exit_code_with_detailed_and_all_noop_returns_zero() {
        let plan = Plan {
            actions: vec![
                Action::NoOp("a: in sync".into()),
                Action::NoOp("b: in sync".into()),
            ],
            warnings: vec![],
        };
        assert_eq!(dry_run_exit_code(true, false, &plan), 0);
    }

    /// Dry-run with `--detailed-exitcode` and an empty action vec → 0.
    /// Empty Vec has nothing to report — same semantic as all-NoOp:
    /// no diff present.
    #[test]
    fn dry_run_exit_code_with_detailed_and_empty_plan_returns_zero() {
        let plan = Plan::default();
        assert_eq!(dry_run_exit_code(true, false, &plan), 0);
    }

    // ---- #464: --detailed-exitcode-recreate (exit code 8) ------------

    /// `plan_has_recreate` returns `true` for any plan whose action set
    /// contains a recreate-class action. `CreateRunner` is recreate per
    /// `Action::disruption()` at plan.rs.
    #[test]
    fn plan_has_recreate_detects_create_runner() {
        let plan = Plan {
            actions: vec![Action::CreateRunner(fake_runner_plan("a"))],
            warnings: vec![],
        };
        assert!(plan_has_recreate(&plan));
    }

    /// `plan_has_recreate` returns `false` for plans with only NoOp
    /// actions. Empty action vec is also `false` — no actions, nothing
    /// to recreate.
    #[test]
    fn plan_has_recreate_returns_false_for_all_noop_or_empty() {
        let all_noop = Plan {
            actions: vec![Action::NoOp("a: in sync".into())],
            warnings: vec![],
        };
        assert!(!plan_has_recreate(&all_noop));
        assert!(!plan_has_recreate(&Plan::default()));
    }

    /// `recreate_exit_code` returns `Some(8)` only when both the flag
    /// is set AND the plan has a recreate-class action.
    #[test]
    fn recreate_exit_code_returns_eight_when_flag_set_and_recreate_present() {
        let plan = Plan {
            actions: vec![Action::CreateRunner(fake_runner_plan("a"))],
            warnings: vec![],
        };
        assert_eq!(recreate_exit_code(true, &plan), Some(8));
    }

    /// `recreate_exit_code` returns `None` when the flag is unset, even
    /// for a plan with recreate-class actions — the flag is strictly
    /// opt-in.
    #[test]
    fn recreate_exit_code_returns_none_when_flag_unset_even_with_recreate() {
        let plan = Plan {
            actions: vec![Action::CreateRunner(fake_runner_plan("a"))],
            warnings: vec![],
        };
        assert_eq!(recreate_exit_code(false, &plan), None);
    }

    /// `recreate_exit_code` returns `None` when the flag is set but
    /// the plan has no recreate (all-NoOp here). The post-apply path
    /// will then fall through to existing `--detailed-exitcode` /
    /// success logic.
    #[test]
    fn recreate_exit_code_returns_none_when_flag_set_but_no_recreate() {
        let all_noop = Plan {
            actions: vec![Action::NoOp("a: in sync".into())],
            warnings: vec![],
        };
        assert_eq!(recreate_exit_code(true, &all_noop), None);
    }

    /// `dry_run_exit_code` returns 8 (not 2) when both flags are set
    /// and the plan has a recreate. Pins the precedence rule:
    /// recreate trumps detailed-changes when both apply.
    #[test]
    fn dry_run_exit_code_recreate_trumps_detailed_when_both_flags_set() {
        let plan = Plan {
            actions: vec![Action::CreateRunner(fake_runner_plan("a"))],
            warnings: vec![],
        };
        assert_eq!(dry_run_exit_code(true, true, &plan), 8);
    }

    /// `cancel_exit_code` returns 8 (not 2) when both flags are set
    /// and the plan has a recreate. Symmetric with the dry-run rule:
    /// cancellation under a recreate plan still surfaces the recreate
    /// signal so a CI caller cannot mistake "operator declined" for
    /// "no recreate detected".
    #[test]
    fn cancel_exit_code_recreate_trumps_detailed_when_both_flags_set() {
        let plan = Plan {
            actions: vec![Action::CreateRunner(fake_runner_plan("a"))],
            warnings: vec![],
        };
        assert_eq!(cancel_exit_code(true, true, &plan), 8);
    }

    /// `apply_exit_code`: success path with recreate-class action in
    /// `result.details` + flag set → 8. Detection uses
    /// `ApplyOutcome::disruption()` so the same rule that drives the
    /// `[recreate]` bracket tag also drives this exit code.
    #[test]
    fn apply_exit_code_recreate_returns_eight_on_success_with_flag() {
        let result = apply::ApplyResult {
            succeeded: vec!["create runner a".into()],
            failed: vec![],
            details: vec![("create runner a".into(), apply::ApplyOutcome::Created)],
            ..Default::default()
        };
        assert_eq!(apply_exit_code(&result, false, true), 8);
    }

    /// `apply_exit_code`: success path with `--detailed-exitcode-recreate`
    /// but no recreate-class outcomes → falls through to existing
    /// `--detailed-exitcode` / success logic (in this case, 0 since
    /// detailed-exitcode is unset and the apply succeeded).
    #[test]
    fn apply_exit_code_recreate_flag_without_recreate_outcome_returns_zero() {
        let result = apply::ApplyResult {
            succeeded: vec!["update runner a".into()],
            failed: vec![],
            details: vec![(
                "update runner a".into(),
                apply::ApplyOutcome::InPlaceRestarted {
                    files_changed: 1,
                    pools_added: vec![],
                    pools_removed: vec![],
                },
            )],
            ..Default::default()
        };
        assert_eq!(apply_exit_code(&result, false, true), 0);
    }

    /// `apply_exit_code`: failure precedence — partial-failure (4)
    /// trumps recreate (8) even when recreate-class actions ALSO
    /// landed successfully. The operator needs to know "go check
    /// what failed" before "go check what would recreate". (#464)
    #[test]
    fn apply_exit_code_partial_failure_trumps_recreate() {
        let result = apply::ApplyResult {
            succeeded: vec!["create runner a".into()],
            failed: vec![("create runner b".into(), validation_err("nope"))],
            details: vec![("create runner a".into(), apply::ApplyOutcome::Created)],
            ..Default::default()
        };
        assert_eq!(apply_exit_code(&result, false, true), 4);
    }

    /// `apply_exit_code`: failure precedence — total auth failure (5)
    /// trumps recreate (8). Auth is a structural pre-condition;
    /// recreate is downstream plan-shape. (#464)
    #[test]
    fn apply_exit_code_auth_failure_trumps_recreate() {
        let result = apply::ApplyResult {
            succeeded: vec![],
            failed: vec![("create runner a".into(), auth_err("401"))],
            details: vec![],
            ..Default::default()
        };
        assert_eq!(apply_exit_code(&result, false, true), 5);
    }

    /// CLI parses `ghars plan --detailed-exitcode-recreate` and sets
    /// the new flag on `PlanArgs`. Default-false pin: a bare
    /// `ghars plan` leaves the field `false`.
    #[test]
    fn cli_parses_plan_detailed_exitcode_recreate() {
        let cli = Cli::try_parse_from(["ghars", "plan", "--detailed-exitcode-recreate"]).unwrap();
        match cli.command {
            Command::Plan(args) => {
                assert!(args.detailed_exitcode_recreate);
                assert!(!args.detailed_exitcode);
            }
            _ => panic!("expected Plan"),
        }
        let bare = Cli::try_parse_from(["ghars", "plan"]).unwrap();
        match bare.command {
            Command::Plan(args) => assert!(!args.detailed_exitcode_recreate),
            _ => panic!("expected Plan"),
        }
    }

    /// CLI parses `ghars apply --detailed-exitcode-recreate` and sets
    /// the new flag on `ApplyArgs`. Both flags can fire together;
    /// pin that combination here so the precedence-trumping
    /// (`apply_exit_code`) tests have a known argv path.
    #[test]
    fn cli_parses_apply_detailed_exitcode_recreate() {
        let cli = Cli::try_parse_from([
            "ghars",
            "apply",
            "--detailed-exitcode",
            "--detailed-exitcode-recreate",
        ])
        .unwrap();
        match cli.command {
            Command::Apply(args) => {
                assert!(args.detailed_exitcode);
                assert!(args.detailed_exitcode_recreate);
            }
            _ => panic!("expected Apply"),
        }
    }

    // ---- #464 T-1: cancel_exit_code missing cells ---------------------

    /// T-1a: cancel + recreate flag (alone) + recreate plan → 8.
    /// Pins recreate trumps default-0 even without `--detailed-exitcode`.
    #[test]
    fn cancel_exit_code_recreate_flag_only_with_recreate_returns_eight() {
        let plan = Plan {
            actions: vec![Action::CreateRunner(fake_runner_plan("a"))],
            warnings: vec![],
        };
        assert_eq!(cancel_exit_code(false, true, &plan), 8);
    }

    /// T-1b: cancel + both flags + NoOp plan → 2 (recreate flag set
    /// but no recreate present, falls through to detailed-exitcode).
    #[test]
    fn cancel_exit_code_both_flags_no_recreate_returns_two() {
        let all_noop = Plan {
            actions: vec![Action::NoOp("a: in sync".into())],
            warnings: vec![],
        };
        assert_eq!(cancel_exit_code(true, true, &all_noop), 2);
    }

    /// T-1c: cancel + recreate flag (alone) + NoOp plan → 0.
    /// No detailed flag, no recreate present — default to 0.
    #[test]
    fn cancel_exit_code_recreate_flag_only_no_recreate_returns_zero() {
        let all_noop = Plan {
            actions: vec![Action::NoOp("a: in sync".into())],
            warnings: vec![],
        };
        assert_eq!(cancel_exit_code(false, true, &all_noop), 0);
    }

    // ---- #464 T-2: dry_run_exit_code missing cells --------------------

    /// T-2a: dry-run + recreate flag (alone) + recreate plan → 8.
    /// Pins recreate trumps default-0 even without `--detailed-exitcode`.
    #[test]
    fn dry_run_exit_code_recreate_flag_only_with_recreate_returns_eight() {
        let plan = Plan {
            actions: vec![Action::CreateRunner(fake_runner_plan("a"))],
            warnings: vec![],
        };
        assert_eq!(dry_run_exit_code(false, true, &plan), 8);
    }

    /// T-2b: dry-run + both flags + non-NoOp non-recreate plan → 2.
    /// (Synthesized via UpdateRunner with `requires_recreate=false`,
    /// which is `Disruption::Restart`, not `Disruption::Recreate`.)
    /// Recreate flag set but no recreate present, falls through to
    /// detailed-exitcode → 2 because plan has non-NoOp action.
    #[test]
    fn dry_run_exit_code_both_flags_no_recreate_returns_two() {
        let in_place_delta = plan::RunnerDelta {
            identity: fake_identity("a"),
            after: fake_runner_plan("a"),
            requires_recreate: false,
            recreate_reasons: vec![],
            drift_cause: plan::DriftCause::SpecChanged,
            field_changes: vec![],
            drop_in_changes: vec![],
            before_caches: None,
            before_drop_in_basenames: None,
        };
        let plan = Plan {
            actions: vec![Action::UpdateRunner(in_place_delta)],
            warnings: vec![],
        };
        assert_eq!(dry_run_exit_code(true, true, &plan), 2);
    }

    /// T-2c: dry-run + recreate flag (alone) + NoOp plan → 0.
    /// No detailed flag, no recreate present — default to 0.
    #[test]
    fn dry_run_exit_code_recreate_flag_only_no_recreate_returns_zero() {
        let all_noop = Plan {
            actions: vec![Action::NoOp("a: in sync".into())],
            warnings: vec![],
        };
        assert_eq!(dry_run_exit_code(false, true, &all_noop), 0);
    }

    // ---- #464 T-3: apply_exit_code 8>2 precedence ---------------------

    /// T-3: `apply_exit_code` with both flags set + success path +
    /// recreate-class outcome → 8. Pins that recreate (8) trumps
    /// detailed-changes (2) at the apply layer too — symmetric with
    /// dry_run/cancel rule.
    #[test]
    fn apply_exit_code_recreate_trumps_detailed_at_apply_layer() {
        let result = apply::ApplyResult {
            succeeded: vec!["create runner a".into()],
            failed: vec![],
            details: vec![("create runner a".into(), apply::ApplyOutcome::Created)],
            ..Default::default()
        };
        assert_eq!(apply_exit_code(&result, true, true), 8);
    }

    /// #556 (T-4): `apply_exit_code` total-failure-without-auth →
    /// 1 trumps recreate (8). Symmetric with the partial-failure (4)
    /// and auth-failure (5) precedence pins: failure precedence
    /// strictly trumps recreate, regardless of which failure class
    /// fired. Pinning 1's precedence here closes the
    /// `failed=N, succeeded=0, no auth, recreate-class outcome`
    /// quadrant the existing tests left untested.
    #[test]
    fn apply_exit_code_total_non_auth_failure_trumps_recreate() {
        let result = apply::ApplyResult {
            succeeded: vec![],
            failed: vec![("create runner b".into(), validation_err("nope"))],
            details: vec![(
                "create runner b".into(),
                apply::ApplyOutcome::Failed {
                    plan_disruption: plan::Disruption::Recreate,
                    error_summary: "validation error".into(),
                },
            )],
            ..Default::default()
        };
        // Total failure (no auth, no successes) → 1, NOT 8 even
        // though the failed outcome claims recreate disruption. The
        // success-path recreate gate at the top of `apply_exit_code`
        // is gated on `result.failed.is_empty()` so this exercises
        // the failure branch.
        assert_eq!(apply_exit_code(&result, false, true), 1);
    }

    /// #558 (T-6): `plan_has_recreate` returns `true` for
    /// recreate-class actions BEYOND `CreateRunner`. Existing tests
    /// only cover Create + NoOp. `RemoveRunner` is unambiguously
    /// recreate per `Action::disruption` — pin so the helper does
    /// not regress to a Create-only check.
    #[test]
    fn plan_has_recreate_detects_remove_runner() {
        let plan = Plan {
            actions: vec![Action::RemoveRunner(fake_identity("legacy"))],
            warnings: vec![],
        };
        assert!(plan_has_recreate(&plan));
    }

    /// #559 (T-5): inverse pin — `apply_exit_code` flag-OFF with a
    /// recreate-class outcome in `result.details` MUST NOT return
    /// 8. The recreate signal is strictly opt-in; CI callers that
    /// did not pass `--detailed-exitcode-recreate` get the existing
    /// 0 (or 2 with `--detailed-exitcode`) regardless of what the
    /// apply path produced.
    #[test]
    fn apply_exit_code_recreate_outcome_with_flag_off_returns_zero() {
        let result = apply::ApplyResult {
            succeeded: vec!["create runner a".into()],
            failed: vec![],
            details: vec![("create runner a".into(), apply::ApplyOutcome::Created)],
            ..Default::default()
        };
        // Both detailed flags off → 0 (not 8) on success even with
        // a recreate-class outcome.
        assert_eq!(apply_exit_code(&result, false, false), 0);
        // detailed_exitcode on, recreate flag off → 2 (existing
        // detailed-exitcode contract, NOT 8).
        assert_eq!(apply_exit_code(&result, true, false), 2);
    }

    /// #571 (T-4/T-5): `FieldValue::List` edge cases — empty Vec
    /// renders as the empty string in text, and as
    /// `{"type":"list","values":[]}` in JSON. Single-item Vec
    /// renders as the bare item with no trailing comma. Pins both
    /// edge cases against future `render_text` / `to_json`
    /// refactors that might mishandle the bounds.
    #[test]
    fn field_value_list_edge_cases_empty_and_single_item() {
        let empty = plan::FieldValue::List(Vec::new());
        assert_eq!(empty.render_text(), "");
        let empty_json = empty.to_json();
        assert_eq!(empty_json["type"], "list");
        assert_eq!(
            empty_json["values"]
                .as_array()
                .expect("List must carry values array")
                .len(),
            0,
        );

        let single = plan::FieldValue::List(vec!["only".into()]);
        assert_eq!(
            single.render_text(),
            "only",
            "single-item List MUST NOT add trailing comma",
        );
        let single_json = single.to_json();
        assert_eq!(single_json["type"], "list");
        let values = single_json["values"]
            .as_array()
            .expect("List must carry values array");
        assert_eq!(values.len(), 1);
        assert_eq!(values[0], "only");
    }

    #[test]
    fn cli_parses_validate() {
        let cli = Cli::try_parse_from(["ghars", "validate", "--deep"]).unwrap();
        match cli.command {
            Command::Validate(args) => assert!(args.deep),
            _ => panic!("expected Validate"),
        }
    }

    #[test]
    fn cli_parses_apply_with_flags() {
        let cli = Cli::try_parse_from([
            "ghars",
            "apply",
            "--auto-approve",
            "--fail-fast",
            "--detailed-exitcode",
        ])
        .unwrap();
        match cli.command {
            Command::Apply(args) => {
                assert!(args.auto_approve);
                assert!(args.fail_fast);
                assert!(args.detailed_exitcode);
            }
            _ => panic!("expected Apply"),
        }
    }

    #[test]
    fn cli_parses_logs_with_named_runners() {
        let cli = Cli::try_parse_from(["ghars", "logs", "ci-1,ci-2", "--follow"]).unwrap();
        match cli.command {
            Command::Logs(args) => {
                assert_eq!(args.names, vec!["ci-1".to_owned(), "ci-2".to_owned()]);
                assert!(args.follow);
            }
            _ => panic!("expected Logs"),
        }
    }

    #[test]
    fn cli_hidden_netns_subcommands_present() {
        let cli = Cli::try_parse_from(["ghars", "_netns-setup", "buckos"]).unwrap();
        assert!(matches!(cli.command, Command::NetnsSetup { .. }));
    }

    #[test]
    fn cli_global_no_color_flag_set() {
        let cli = Cli::try_parse_from(["ghars", "--no-color", "plan"]).unwrap();
        assert!(cli.no_color);
    }

    #[test]
    fn render_action_line_uses_sigil_per_kind() {
        let create = Action::CreateRunner(plan::RunnerPlan {
            spec: crate::config::EffectiveRunnerSpec {
                name: "buckos".into(),
                url: "https://github.com/example/buckos".into(),
                arch: crate::config::Arch::X86_64,
                user: "ghars-buckos".into(),
                prefix: Utf8PathBuf::from("/var/lib/ghars"),
                labels: vec!["x".into()],
                memory_max: None,
                runner_version: None,
                runner_sha256: None,
                runner_tarball: None,
                auth_name: "pat".into(),
                caches: vec![],
                trust_zone: "default".into(),
                network: None,
                proxy: None,
                hooks: None,
                hardening: crate::config::Hardening::default(),
                allowed_cpus: None,
                allowed_memory_nodes: None,
                spec_hash: "sha256:0".into(),
                runsvc_sha256: String::new(),
                config_source: "/etc/ghars/ghars.toml".into(),
            },
            resolved_release: None,
            effective_unit_text: String::new(),
            drop_ins: std::collections::BTreeMap::new(),
            spec_hash: "sha256:0".into(),
        });
        let line = render_action_line(&create, ColorMode { enabled: false }, false);
        assert!(line.starts_with("+ "));
        assert!(line.contains("create"));

        let remove = Action::RemoveCachePool("build".into());
        let line = render_action_line(&remove, ColorMode { enabled: false }, false);
        assert!(line.starts_with("- "));
        assert!(line.contains("build"));
    }

    #[test]
    fn human_bytes_formats() {
        assert!(human_bytes(0).starts_with('0'));
        // 2 GiB ⇒ should contain "GB" or similar (bytesize formatting).
        let s = human_bytes(2 * 1024 * 1024 * 1024);
        assert!(!s.is_empty());
    }

    // -------- #241: cmd_init no longer creates the ghars system user --

    #[test]
    fn cmd_init_writes_config_only_no_user_provisioning() {
        // SEC-27 (#241): init scaffolds ghars.toml and nothing else.
        // Per-runner system users live in apply::execute_create_runner;
        // a vestigial shared `ghars` user contradicts the per-runner
        // UID model. This test confirms cmd_init does NOT shell out
        // to useradd by inspecting NSS afterwards: even if the test
        // host happens to have a `ghars` user pre-existing, our test
        // is concerned only that cmd_init succeeds without root + the
        // file lands. The negative claim (no useradd) is now structural
        // — `apply::Users` is not even imported in cli.rs anymore.
        let tmp = tempfile::tempdir().unwrap();
        let config_path = Utf8PathBuf::from_path_buf(tmp.path().to_path_buf())
            .unwrap()
            .join("ghars.toml");
        let args = InitArgs { output: None };
        let rc = cmd_init(&config_path, &args, true).unwrap();
        assert_eq!(rc, 0);
        // Config landed verbatim from INIT_EXAMPLE_CONFIG.
        let written = fs::read_to_string(config_path.as_std_path()).unwrap();
        assert_eq!(written, INIT_EXAMPLE_CONFIG);
    }

    #[test]
    fn cmd_init_writes_config_with_owner_group_only_mode() {
        // #240: ghars.toml at /etc/ghars/ghars.toml exposes the
        // [auth.*] section's `token_env` / `token_file` references and
        // any custom paths the operator embedded. Default umask leaves
        // the file 0644 (world-readable). Enforce 0640 from creation
        // (OpenOptions.mode + create_new — no write-then-chmod window).
        use std::os::unix::fs::PermissionsExt;
        let tmp = tempfile::tempdir().unwrap();
        let config_path = Utf8PathBuf::from_path_buf(tmp.path().to_path_buf())
            .unwrap()
            .join("ghars.toml");
        cmd_init(&config_path, &InitArgs { output: None }, true).unwrap();
        let meta = fs::metadata(config_path.as_std_path()).unwrap();
        // Mask off file type bits; only inspect mode lower 12 bits.
        let mode = meta.permissions().mode() & 0o7777;
        assert_eq!(mode, 0o640, "expected mode 0640, got {mode:04o}");
    }

    #[test]
    fn cmd_init_refuses_to_overwrite_existing_config() {
        // The pre-existing failure mode: init must never silently
        // clobber an operator's edited ghars.toml. Confirms the early
        // `dest.exists()` reject still fires after the SEC-27 cleanup.
        let tmp = tempfile::tempdir().unwrap();
        let config_path = Utf8PathBuf::from_path_buf(tmp.path().to_path_buf())
            .unwrap()
            .join("ghars.toml");
        fs::write(config_path.as_std_path(), "# operator's existing config\n").unwrap();
        let err = cmd_init(&config_path, &InitArgs { output: None }, true).unwrap_err();
        assert!(
            format!("{err}").contains("already exists"),
            "rejection must mention overwrite, got: {err}"
        );
        // The operator's file is intact.
        let body = fs::read_to_string(config_path.as_std_path()).unwrap();
        assert_eq!(body, "# operator's existing config\n");
    }

    // -------- #243: cmd_add validates inputs ---------------------------

    fn add_args_for(repo: &str, name: Option<&str>, auth: Option<&str>) -> AddArgs {
        AddArgs {
            repo: repo.into(),
            name: name.map(String::from),
            labels: vec![],
            auth: auth.map(String::from),
            no_apply: true,
        }
    }

    fn write_minimal_config(path: &Utf8Path) {
        // Minimum viable config that load_config accepts: a defaults
        // block + an [auth.pat] entry the cmd_add validator can find.
        let body = "\
[defaults]
prefix = \"/var/lib/ghars\"

[auth.pat]
kind = \"pat\"
token_env = \"GHARS_PAT\"
";
        fs::write(path.as_std_path(), body).unwrap();
    }

    #[test]
    fn cmd_add_rejects_invalid_repo_url() {
        // #243: a malformed --repo (e.g. ftp://, userinfo, traversal)
        // would construct an invalid URL. cmd_add must reject BEFORE
        // appending the [[runner]] block, leaving the operator's
        // config untouched.
        let tmp = tempfile::tempdir().unwrap();
        let config_path = Utf8PathBuf::from_path_buf(tmp.path().to_path_buf())
            .unwrap()
            .join("ghars.toml");
        write_minimal_config(&config_path);
        let original = fs::read_to_string(config_path.as_std_path()).unwrap();
        let paths = Paths::default();
        // `OWNER/../escape` triggers a traversal segment in the
        // constructed URL; validate_url rejects.
        let args = add_args_for("OWNER/../escape", None, Some("pat"));
        let err = cmd_add(
            &config_path,
            &paths,
            &args,
            ColorMode { enabled: false },
            true,
        )
        .unwrap_err();
        assert!(
            matches!(err, GharsError::Validation(_, _)),
            "expected Validation, got: {err}"
        );
        // Config is unchanged — no [[runner]] block was appended.
        let after = fs::read_to_string(config_path.as_std_path()).unwrap();
        assert_eq!(
            after, original,
            "cmd_add must not mutate config on validation failure"
        );
    }

    #[test]
    fn cmd_add_rejects_unknown_auth_ref() {
        // #243: --auth NAME must reference a [auth.NAME] entry that
        // exists in the loaded config. An unknown auth ref would
        // otherwise leave a [[runner]] block that every subsequent
        // apply rejects.
        let tmp = tempfile::tempdir().unwrap();
        let config_path = Utf8PathBuf::from_path_buf(tmp.path().to_path_buf())
            .unwrap()
            .join("ghars.toml");
        write_minimal_config(&config_path);
        let original = fs::read_to_string(config_path.as_std_path()).unwrap();
        let paths = Paths::default();
        let args = add_args_for("OWNER/REPO", None, Some("ghost-auth"));
        let err = cmd_add(
            &config_path,
            &paths,
            &args,
            ColorMode { enabled: false },
            true,
        )
        .unwrap_err();
        let msg = format!("{err}");
        assert!(
            msg.contains("ghost-auth") && msg.contains("auth"),
            "rejection must mention the unknown auth ref, got: {msg}"
        );
        let after = fs::read_to_string(config_path.as_std_path()).unwrap();
        assert_eq!(after, original);
    }

    #[test]
    fn cmd_add_rejects_invalid_runner_name() {
        // #243: explicit --name must satisfy IDENTIFIER_REGEX
        // (lowercase, dashes, no leading digit). Reject early so the
        // user's config doesn't pick up a name that apply will refuse.
        let tmp = tempfile::tempdir().unwrap();
        let config_path = Utf8PathBuf::from_path_buf(tmp.path().to_path_buf())
            .unwrap()
            .join("ghars.toml");
        write_minimal_config(&config_path);
        let original = fs::read_to_string(config_path.as_std_path()).unwrap();
        let paths = Paths::default();
        // Uppercase letters and trailing dash both break the regex.
        let args = add_args_for("OWNER/REPO", Some("Bad-Name-"), Some("pat"));
        let err = cmd_add(
            &config_path,
            &paths,
            &args,
            ColorMode { enabled: false },
            true,
        )
        .unwrap_err();
        assert!(
            matches!(err, GharsError::Validation(_, _)),
            "expected Validation, got: {err}"
        );
        let after = fs::read_to_string(config_path.as_std_path()).unwrap();
        assert_eq!(after, original);
    }

    #[test]
    fn cmd_add_appends_runner_block_when_inputs_validate() {
        // Positive control: when --repo, --name, and --auth all pass
        // validation AND the auth ref exists in [auth.*], cmd_add
        // appends a well-formed [[runner]] block and returns 0
        // (no_apply prevents the apply leg from running so this
        // doesn't need a mock systemd).
        let tmp = tempfile::tempdir().unwrap();
        let config_path = Utf8PathBuf::from_path_buf(tmp.path().to_path_buf())
            .unwrap()
            .join("ghars.toml");
        write_minimal_config(&config_path);
        let paths = Paths::default();
        let args = add_args_for("owner/repo", Some("owner-repo-1"), Some("pat"));
        let rc = cmd_add(
            &config_path,
            &paths,
            &args,
            ColorMode { enabled: false },
            true,
        )
        .unwrap();
        assert_eq!(rc, 0);
        let after = fs::read_to_string(config_path.as_std_path()).unwrap();
        assert!(after.contains("[[runner]]"));
        assert!(after.contains("name = \"owner-repo-1\""));
        assert!(after.contains("url = \"https://github.com/owner/repo\""));
    }

    // -------- #253 / #390: confirm_apply on non-TTY -------------------

    #[test]
    fn confirm_apply_rejects_when_stdin_is_not_a_terminal() {
        // #253: under `cargo nextest` stdin is a pipe (NOT a TTY), so
        // calling confirm_apply directly exercises the fail-closed
        // branch — read_line would otherwise return Ok(0) and silently
        // cancel the apply (or block on an unclosed pipe). The
        // function MUST surface an Interactive error (#390) pointing
        // operators at --auto-approve, with exit code 7 to disambiguate
        // from config-shape Validation rejections (6).
        if io::stdin().is_terminal() {
            // Manual / interactive `cargo nextest` runs may attach a
            // TTY (e.g. running tests inside an interactive shell with
            // `cargo nextest run --no-capture`). Skip in that case
            // rather than blocking on read_line.
            return;
        }
        let err = confirm_apply().expect_err(
            "confirm_apply must reject non-TTY stdin; would otherwise block / silently cancel",
        );
        // #390: the variant must be Interactive (not Validation), so
        // wrapper scripts can branch on the variant tag — and exit
        // code 7 confirms err_to_exit_code maps the new variant
        // distinctly from Validation's 6.
        assert!(
            matches!(err, GharsError::Interactive(_, _)),
            "expected Interactive variant (#390), got: {err:?}"
        );
        assert_eq!(
            err_to_exit_code(&err),
            7,
            "Interactive variant must route to exit code 7"
        );
        let msg = format!("{err}");
        assert!(
            msg.contains("auto-approve") || msg.contains("--auto-approve"),
            "error must point operator at --auto-approve, got: {msg}"
        );
        assert!(
            msg.contains("terminal") || msg.contains("TTY") || msg.contains("tty"),
            "error must explain WHY (no TTY), got: {msg}"
        );
    }

    // ---------- #247: removed flags should be rejected by the parser

    #[test]
    fn cli_rejects_removed_plan_flag_refresh_releases() {
        // `--refresh-releases` was removed in v0.1; clap must reject
        // it now. This pins the regression so a future "let's add
        // the flag back even though it's not implemented" change
        // fails CI.
        let r = Cli::try_parse_from(["ghars", "plan", "--refresh-releases"]);
        assert!(
            r.is_err(),
            "plan --refresh-releases must be rejected (#247)"
        );
    }

    #[test]
    fn cli_rejects_removed_plan_flag_output_dir() {
        let r = Cli::try_parse_from(["ghars", "plan", "--output-dir", "/tmp/x"]);
        assert!(r.is_err(), "plan --output-dir must be rejected (#247)");
    }

    #[test]
    fn cli_rejects_removed_apply_flag_refresh_releases() {
        let r = Cli::try_parse_from(["ghars", "apply", "--refresh-releases"]);
        assert!(
            r.is_err(),
            "apply --refresh-releases must be rejected (#247)"
        );
    }

    // ---------- #251: exit-code precedence ----------------------------

    // #237: tests drive the production `apply_exit_code` directly
    // (no test-local precedence duplication). `classify` partially
    // applies `detailed_exitcode_recreate = false` so the existing
    // pre-#464 tests stay terse; #464-specific tests call
    // `apply_exit_code` with all three args inline.
    fn classify(result: &apply::ApplyResult, detailed_exitcode: bool) -> i32 {
        apply_exit_code(result, detailed_exitcode, false)
    }

    fn auth_err(msg: &str) -> GharsError {
        GharsError::Auth(msg.into(), "hint".into())
    }

    fn validation_err(msg: &str) -> GharsError {
        GharsError::Validation(msg.into(), "hint".into())
    }

    #[test]
    fn exit_code_partial_failure_beats_auth_only() {
        // Some succeeded, some failed (one of which is auth) → 4.
        let r = apply::ApplyResult {
            succeeded: vec!["CreateRunner(a)".into()],
            failed: vec![("CreateRunner(b)".into(), auth_err("token expired"))],
            skipped: vec![],
            details: vec![],
            failed_undo_logs: vec![],
        };
        assert_eq!(classify(&r, false), 4);
    }

    #[test]
    fn exit_code_full_failure_with_auth_returns_5() {
        // Nothing succeeded, at least one failure was auth → 5.
        let r = apply::ApplyResult {
            succeeded: vec![],
            failed: vec![("CreateRunner(a)".into(), auth_err("token expired"))],
            skipped: vec![],
            details: vec![],
            failed_undo_logs: vec![],
        };
        assert_eq!(classify(&r, false), 5);
    }

    #[test]
    fn exit_code_full_failure_no_auth_returns_1() {
        let r = apply::ApplyResult {
            succeeded: vec![],
            failed: vec![("CreateRunner(a)".into(), validation_err("bad spec"))],
            skipped: vec![],
            details: vec![],
            failed_undo_logs: vec![],
        };
        assert_eq!(classify(&r, false), 1);
    }

    #[test]
    fn exit_code_clean_run_zero_or_two_per_detailed_flag() {
        let r = apply::ApplyResult::default();
        assert_eq!(classify(&r, false), 0);
        assert_eq!(classify(&r, true), 2);
    }

    #[test]
    fn exit_code_clean_run_with_succeeded_actions_no_detailed() {
        // success branch: failed empty, succeeded non-empty → 0
        // (or 2 with --detailed-exitcode).
        let r = apply::ApplyResult {
            succeeded: vec!["CreateRunner(a)".into(), "CreateRunner(b)".into()],
            failed: vec![],
            skipped: vec![],
            details: vec![],
            failed_undo_logs: vec![],
        };
        assert_eq!(classify(&r, false), 0);
        assert_eq!(classify(&r, true), 2);
    }

    #[test]
    fn exit_code_clean_run_only_skipped_actions_returns_zero() {
        // NoOp + dry-run produce skipped entries; no failures, no
        // successes. Per Part 5, this is still 0 (or 2 with detailed).
        let r = apply::ApplyResult {
            succeeded: vec![],
            failed: vec![],
            skipped: vec!["NoOp(a: in sync)".into()],
            details: vec![],
            failed_undo_logs: vec![],
        };
        assert_eq!(classify(&r, false), 0);
        assert_eq!(classify(&r, true), 2);
    }

    #[test]
    fn exit_code_partial_failure_non_auth_returns_4() {
        // Some succeeded, some failed (non-auth) → 4.
        let r = apply::ApplyResult {
            succeeded: vec!["CreateRunner(a)".into()],
            failed: vec![("CreateRunner(b)".into(), validation_err("bad spec"))],
            skipped: vec![],
            details: vec![],
            failed_undo_logs: vec![],
        };
        assert_eq!(classify(&r, false), 4);
    }

    #[test]
    fn exit_code_partial_failure_with_only_succeeded_takes_4_not_5() {
        // Mixed: 2 succeeded, 1 auth-failed, 1 non-auth-failed. Auth's
        // 5 must NOT win when partial-success is observable. (#251)
        let r = apply::ApplyResult {
            succeeded: vec!["CreateRunner(a)".into(), "CreateRunner(b)".into()],
            failed: vec![
                ("CreateRunner(c)".into(), auth_err("token expired")),
                ("CreateRunner(d)".into(), validation_err("bad spec")),
            ],
            skipped: vec![],
            details: vec![],
            failed_undo_logs: vec![],
        };
        assert_eq!(classify(&r, false), 4);
    }

    #[test]
    fn exit_code_full_failure_mixed_auth_and_other_returns_5() {
        // No successes, mixed failure types — any auth in the failed
        // list bumps the code to 5. The non-auth peer doesn't downgrade
        // it to 1.
        let r = apply::ApplyResult {
            succeeded: vec![],
            failed: vec![
                ("CreateRunner(a)".into(), auth_err("token expired")),
                ("CreateRunner(b)".into(), validation_err("bad spec")),
            ],
            skipped: vec![],
            details: vec![],
            failed_undo_logs: vec![],
        };
        assert_eq!(classify(&r, false), 5);
    }

    #[test]
    fn exit_code_detailed_does_not_affect_failure_paths() {
        // --detailed-exitcode only swaps 0 ↔ 2 on success. Failure
        // codes (1, 4, 5) must be identical regardless of the flag.
        let auth_only = apply::ApplyResult {
            succeeded: vec![],
            failed: vec![("a".into(), auth_err("x"))],
            skipped: vec![],
            details: vec![],
            failed_undo_logs: vec![],
        };
        assert_eq!(classify(&auth_only, false), 5);
        assert_eq!(classify(&auth_only, true), 5);

        let partial = apply::ApplyResult {
            succeeded: vec!["a".into()],
            failed: vec![("b".into(), validation_err("x"))],
            skipped: vec![],
            details: vec![],
            failed_undo_logs: vec![],
        };
        assert_eq!(classify(&partial, false), 4);
        assert_eq!(classify(&partial, true), 4);

        let total_no_auth = apply::ApplyResult {
            succeeded: vec![],
            failed: vec![("a".into(), validation_err("x"))],
            skipped: vec![],
            details: vec![],
            failed_undo_logs: vec![],
        };
        assert_eq!(classify(&total_no_auth, false), 1);
        assert_eq!(classify(&total_no_auth, true), 1);
    }

    // ---------- #237: status_exit_code ---------------------------------

    fn pass(name: &str) -> preflight::CheckResult {
        preflight::CheckResult {
            name: name.into(),
            outcome: preflight::Outcome::Pass,
            detail: "ok".into(),
            hint: String::new(),
        }
    }

    fn fail(name: &str) -> preflight::CheckResult {
        preflight::CheckResult {
            name: name.into(),
            outcome: preflight::Outcome::Fail,
            detail: "broken".into(),
            hint: "fix it".into(),
        }
    }

    fn warn(name: &str) -> preflight::CheckResult {
        preflight::CheckResult {
            name: name.into(),
            outcome: preflight::Outcome::Warn,
            detail: "advisory".into(),
            hint: "consider".into(),
        }
    }

    fn skip(name: &str) -> preflight::CheckResult {
        preflight::CheckResult {
            name: name.into(),
            outcome: preflight::Outcome::Skip,
            detail: "n/a".into(),
            hint: String::new(),
        }
    }

    #[test]
    fn status_exit_code_zero_when_all_pass() {
        let health = vec![pass("OS"), pass("kvm"), pass("systemd")];
        assert_eq!(status_exit_code(&health), 0);
    }

    #[test]
    fn status_exit_code_zero_when_empty() {
        // status --runners-only feeds an empty health vec to
        // status_exit_code (no checks run). That must not be a failure.
        let health: Vec<preflight::CheckResult> = vec![];
        assert_eq!(status_exit_code(&health), 0);
    }

    #[test]
    fn status_exit_code_three_when_any_fail() {
        let health = vec![pass("OS"), fail("kvm"), pass("systemd")];
        assert_eq!(status_exit_code(&health), 3);
    }

    #[test]
    fn status_exit_code_three_when_first_check_fails() {
        let health = vec![fail("OS"), pass("kvm")];
        assert_eq!(status_exit_code(&health), 3);
    }

    #[test]
    fn status_exit_code_zero_when_only_warns_or_skips() {
        // Warn and Skip are non-blocking; only Fail trips the exit code.
        let health = vec![pass("OS"), warn("ptrace_scope"), skip("root")];
        assert_eq!(status_exit_code(&health), 0);
    }

    // ---------- #258: D-Bus failure rewrap ----------------------------

    #[test]
    fn open_dbus_error_carries_actionable_hint() {
        // We can't fake the real DbusSystemd::new() failure path
        // without root / no-D-Bus context, but we CAN verify the
        // wrapping closure produces the right message + hint shape.
        // Reproduce the exact transform open_dbus applies.
        let raw = GharsError::Systemd(
            "system D-Bus connect failed: permission denied".into(),
            "verify dbus is running and the caller has access".into(),
        );
        let mapped = match raw {
            GharsError::Systemd(msg, _) => GharsError::Validation(
                format!("ghars plan / apply requires system D-Bus access: {msg}"),
                "run as root, or grant the calling user a polkit policy that \
                 allows access to org.freedesktop.systemd1 (typically \
                 /usr/share/polkit-1/rules.d/)"
                    .into(),
            ),
            other => other,
        };
        let display = format!("{mapped}");
        assert!(
            display.contains("ghars plan / apply requires system D-Bus access"),
            "missing top-level message: {display}",
        );
        assert!(
            display.contains("polkit"),
            "hint must mention polkit policy: {display}",
        );
        assert!(
            matches!(mapped, GharsError::Validation(_, _)),
            "must be Validation variant",
        );
    }

    // ---------- #236: argv parsing for every subcommand --------------

    #[test]
    fn argv_validate_without_deep_defaults_to_false() {
        let cli = Cli::try_parse_from(["ghars", "validate"]).unwrap();
        match cli.command {
            Command::Validate(args) => assert!(!args.deep),
            _ => panic!("expected Validate"),
        }
    }

    #[test]
    fn argv_plan_with_only_filter_and_json() {
        let cli = Cli::try_parse_from(["ghars", "plan", "--only", "ci-1,ci-2", "--json"]).unwrap();
        match cli.command {
            Command::Plan(args) => {
                assert_eq!(args.only, vec!["ci-1".to_owned(), "ci-2".to_owned()]);
                assert!(args.json);
            }
            _ => panic!("expected Plan"),
        }
    }

    /// `ghars plan --detailed-exitcode` parses (#391 / #456). Pins the
    /// flag name + the bool field shape so a future rename or
    /// `ArgAction` change breaks compile here rather than silently
    /// dropping the terraform-plan-parity exit code.
    #[test]
    fn argv_plan_detailed_exitcode_flag_parses() {
        let cli = Cli::try_parse_from(["ghars", "plan", "--detailed-exitcode"]).unwrap();
        match cli.command {
            Command::Plan(args) => assert!(args.detailed_exitcode),
            _ => panic!("expected Plan"),
        }
    }

    /// `ghars plan` (no flag) leaves `detailed_exitcode = false` (#456).
    /// Pins the default so a future move to `Option<bool>`, an
    /// `ArgAction::SetTrue` sentinel, or an inverted `default_value`
    /// can't change the exit-code semantics for unflagged invocations.
    #[test]
    fn argv_plan_detailed_exitcode_default_false() {
        let cli = Cli::try_parse_from(["ghars", "plan"]).unwrap();
        match cli.command {
            Command::Plan(args) => assert!(!args.detailed_exitcode),
            _ => panic!("expected Plan"),
        }
    }

    #[test]
    fn argv_apply_defaults_all_flags_off() {
        let cli = Cli::try_parse_from(["ghars", "apply"]).unwrap();
        match cli.command {
            Command::Apply(args) => {
                assert!(!args.auto_approve);
                assert!(!args.fail_fast);
                assert!(!args.detailed_exitcode);
                // #557 (T-7): pin clap default-false for the recreate
                // gate. Drift here would surprise CI consumers with
                // unexpected exit code 8.
                assert!(
                    !args.detailed_exitcode_recreate,
                    "--detailed-exitcode-recreate must default off",
                );
                assert!(!args.dry_run);
                assert!(args.only.is_empty());
            }
            _ => panic!("expected Apply"),
        }
    }

    #[test]
    fn argv_apply_dry_run_alone() {
        let cli = Cli::try_parse_from(["ghars", "apply", "--dry-run"]).unwrap();
        match cli.command {
            Command::Apply(args) => assert!(args.dry_run),
            _ => panic!("expected Apply"),
        }
    }

    #[test]
    fn argv_status_default_no_filters() {
        let cli = Cli::try_parse_from(["ghars", "status"]).unwrap();
        match cli.command {
            Command::Status(args) => {
                assert!(!args.json);
                assert!(!args.metrics);
                assert!(!args.health_only);
                assert!(!args.runners_only);
                assert!(args.names.is_empty());
            }
            _ => panic!("expected Status"),
        }
    }

    #[test]
    fn argv_status_health_only_with_json() {
        let cli = Cli::try_parse_from(["ghars", "status", "--health-only", "--json"]).unwrap();
        match cli.command {
            Command::Status(args) => {
                assert!(args.health_only);
                assert!(args.json);
            }
            _ => panic!("expected Status"),
        }
    }

    #[test]
    fn argv_status_runners_only_conflicts_with_health_only() {
        // Mutex per Part 5: --health-only and --runners-only cannot
        // both be set; clap rejects at parse time.
        let r = Cli::try_parse_from(["ghars", "status", "--health-only", "--runners-only"]);
        assert!(
            r.is_err(),
            "--health-only + --runners-only must be mutually exclusive"
        );
    }

    #[test]
    fn argv_status_names_passed_positionally() {
        let cli = Cli::try_parse_from(["ghars", "status", "buckos", "ci-1"]).unwrap();
        match cli.command {
            Command::Status(args) => {
                assert_eq!(args.names, vec!["buckos".to_owned(), "ci-1".to_owned()]);
            }
            _ => panic!("expected Status"),
        }
    }

    #[test]
    fn cmd_status_runners_only_propagates_config_parse_error() {
        // #261: cmd_status MUST load_config FIRST, before any other
        // work, even under --runners-only. Two contracts on this
        // assertion (per design Part 10):
        //
        //   1. Config-load contract — a malformed TOML must surface as
        //      Err(GharsError::Config) propagated from load_config via
        //      the `?` short-circuit. cmd_status must NOT swallow the
        //      error and proceed with state-only output.
        //   2. Smoke-test invariant — `ghars status --runners-only`
        //      after a config edit is the operator's first signal that
        //      the edit broke parsing. Suppressing the error and
        //      rendering only systemd-discovered runners would push the
        //      problem to the next plan/apply, wasting operator time.
        //
        // The earlier (incorrect) implementation printed a stderr
        // warning and returned Ok via state-only rendering. This test
        // pins the corrected fail-fast behavior.
        let tmp = tempfile::tempdir().unwrap();
        let config_path = Utf8PathBuf::from_path_buf(tmp.path().to_path_buf())
            .unwrap()
            .join("ghars.toml");
        // Plant deliberately malformed TOML — unterminated string.
        fs::write(
            config_path.as_std_path(),
            "defaults = { url = \"https://example.com\n",
        )
        .unwrap();

        let paths = Paths::default();
        let args = StatusArgs {
            json: false,
            metrics: false,
            health_only: false,
            runners_only: true,
            names: vec![],
        };
        let err = cmd_status(
            &config_path,
            &paths,
            &args,
            ColorMode { enabled: false },
            true,
        )
        .expect_err("malformed config + --runners-only must error, not warn-and-proceed");
        assert!(
            matches!(err, GharsError::Config(_, _)),
            "expected GharsError::Config; got {err:?}"
        );
        let msg = format!("{err}");
        assert!(
            msg.contains("parse") || msg.contains("read"),
            "config error must indicate parse / read failure; got: {msg}"
        );
    }

    /// #406 BATCH 18: cmd_status calls load_config which now runs the
    /// full post-load validator sweep. Pre-batch-18, cmd_status only
    /// got validate_networks via load_config — the other 4 validators
    /// (security_overrides, identity_fields, no_duplicate_caches,
    /// cache_pool_names) were wired into cmd_validate / cmd_plan /
    /// cmd_apply individually but NOT cmd_status. An oversize pool key
    /// would slip past `ghars status` and only fail later at apply.
    /// This test pins that the lift fixed the gap end-to-end via the
    /// public cmd_status surface.
    ///
    /// runners_only=true skips D-Bus (no MockSystemd needed) — config
    /// load (with validators) is the only thing exercised before the
    /// state-discovery branch.
    #[test]
    fn cmd_status_rejects_oversize_cache_pool_via_load_config() {
        let tmp = tempfile::tempdir().unwrap();
        let config_path = Utf8PathBuf::from_path_buf(tmp.path().to_path_buf())
            .unwrap()
            .join("ghars.toml");
        // CACHE_POOL_NAME_MAX_LEN + 1-char pool key. Body builds a
        // structurally-valid TOML so the only validator that can reject
        // is validate_cache_pool_names — proves the lift wired into
        // load_config rather than relying on cmd_status itself.
        let oversize_pool = "a".repeat(crate::validators::CACHE_POOL_NAME_MAX_LEN + 1);
        let body = format!(
            "\
[defaults]
prefix = \"/var/lib/ghars\"

[auth.pat]
kind = \"pat\"
token_env = \"GHARS_PAT\"

[cache_pools.{oversize_pool}]
kinds = [\"sccache\"]
size = \"200G\"
"
        );
        fs::write(config_path.as_std_path(), body).unwrap();

        let paths = Paths::default();
        let args = StatusArgs {
            json: false,
            metrics: false,
            health_only: false,
            runners_only: true,
            names: vec![],
        };
        let err = cmd_status(
            &config_path,
            &paths,
            &args,
            ColorMode { enabled: false },
            true,
        )
        .expect_err("oversize cache_pool must propagate via load_config");
        match &err {
            GharsError::Validation(msg, _) => {
                assert!(
                    msg.contains("cache_pool") && msg.contains(&oversize_pool),
                    "msg must scope to the offending pool by name; got: {msg}"
                );
                assert!(
                    msg.contains("ghars-cache-"),
                    "msg must come from the cache-pool-cap layer; got: {msg}"
                );
            }
            other => panic!("expected GharsError::Validation, got: {other:?}"),
        }
        assert_eq!(
            err_to_exit_code(&err),
            6,
            "Validation must map to exit code 6 (Part 5)"
        );
    }

    /// #427 end-to-end: a `[[runner]] name` longer than
    /// `RUNNER_NAME_MAX_LEN` must reject through `cmd_status` because
    /// `validate_runner_names` is wired into `load_config` (the 6th
    /// post-load validator). Symmetric to
    /// `cmd_status_rejects_oversize_cache_pool_via_load_config` —
    /// proves the lift covers the runner-name surface end-to-end via
    /// the public CLI rather than relying on cmd_validate / cmd_apply
    /// individually.
    #[test]
    fn cmd_status_rejects_oversize_runner_name_via_load_config() {
        let tmp = tempfile::tempdir().unwrap();
        let config_path = Utf8PathBuf::from_path_buf(tmp.path().to_path_buf())
            .unwrap()
            .join("ghars.toml");
        let oversize_name = "a".repeat(crate::validators::RUNNER_NAME_MAX_LEN + 1);
        let body = format!(
            "\
[defaults]
prefix = \"/var/lib/ghars\"

[auth.pat]
kind = \"pat\"
token_env = \"GHARS_PAT\"

[[runner]]
name = \"{oversize_name}\"
url = \"https://github.com/example/repo\"
auth = \"pat\"
"
        );
        fs::write(config_path.as_std_path(), body).unwrap();

        let paths = Paths::default();
        let args = StatusArgs {
            json: false,
            metrics: false,
            health_only: false,
            runners_only: true,
            names: vec![],
        };
        let err = cmd_status(
            &config_path,
            &paths,
            &args,
            ColorMode { enabled: false },
            true,
        )
        .expect_err("oversize runner name must propagate via load_config");
        match &err {
            GharsError::Validation(msg, _) => {
                assert!(
                    msg.contains("runner") && msg.contains(&oversize_name),
                    "msg must scope to the offending runner by name; got: {msg}"
                );
                assert!(
                    msg.contains(crate::validators::RUNNER_USER_PREFIX),
                    "msg must come from the runner-name-cap layer (mentions \
                     derived user prefix); got: {msg}"
                );
            }
            other => panic!("expected GharsError::Validation, got: {other:?}"),
        }
        assert_eq!(
            err_to_exit_code(&err),
            6,
            "Validation must map to exit code 6 (Part 5)"
        );
    }

    /// #434 end-to-end: a `[[runner]] user = "..."` longer than
    /// `USER_MAX_LEN` must reject through `cmd_status` because
    /// `validate_user_overrides` is wired into `load_config` (the 7th
    /// post-load validator). Symmetric to the runner-name and
    /// cache-pool tests above — proves the lift covers the operator-
    /// supplied User= surface end-to-end.
    #[test]
    fn cmd_status_rejects_oversize_runner_user_via_load_config() {
        let tmp = tempfile::tempdir().unwrap();
        let config_path = Utf8PathBuf::from_path_buf(tmp.path().to_path_buf())
            .unwrap()
            .join("ghars.toml");
        let oversize_user = "a".repeat(crate::validators::USER_MAX_LEN + 1);
        let body = format!(
            "\
[defaults]
prefix = \"/var/lib/ghars\"

[auth.pat]
kind = \"pat\"
token_env = \"GHARS_PAT\"

[[runner]]
name = \"buckos\"
url = \"https://github.com/example/repo\"
auth = \"pat\"
user = \"{oversize_user}\"
"
        );
        fs::write(config_path.as_std_path(), body).unwrap();

        let paths = Paths::default();
        let args = StatusArgs {
            json: false,
            metrics: false,
            health_only: false,
            runners_only: true,
            names: vec![],
        };
        let err = cmd_status(
            &config_path,
            &paths,
            &args,
            ColorMode { enabled: false },
            true,
        )
        .expect_err("oversize runner user must propagate via load_config");
        match &err {
            GharsError::Validation(msg, _) => {
                assert!(
                    msg.contains("runner") && msg.contains("buckos"),
                    "msg must scope to the offending runner by name; got: {msg}"
                );
                assert!(
                    msg.contains("too long")
                        && msg.contains(&crate::validators::USER_MAX_LEN.to_string()),
                    "msg must come from the user-length-cap layer; got: {msg}"
                );
            }
            other => panic!("expected GharsError::Validation, got: {other:?}"),
        }
        assert_eq!(
            err_to_exit_code(&err),
            6,
            "Validation must map to exit code 6 (Part 5)"
        );
    }

    /// #434 defaults variant: `[defaults] user = "..."` longer than
    /// `USER_MAX_LEN` must reject with the `defaults:` scope (NOT a
    /// per-runner scope). Pairs with the runner-scope test above to
    /// cover both surfaces of `validate_user_overrides`.
    #[test]
    fn cmd_status_rejects_oversize_defaults_user_via_load_config() {
        let tmp = tempfile::tempdir().unwrap();
        let config_path = Utf8PathBuf::from_path_buf(tmp.path().to_path_buf())
            .unwrap()
            .join("ghars.toml");
        let oversize_user = "a".repeat(crate::validators::USER_MAX_LEN + 1);
        let body = format!(
            "\
[defaults]
prefix = \"/var/lib/ghars\"
user = \"{oversize_user}\"

[auth.pat]
kind = \"pat\"
token_env = \"GHARS_PAT\"
"
        );
        fs::write(config_path.as_std_path(), body).unwrap();

        let paths = Paths::default();
        let args = StatusArgs {
            json: false,
            metrics: false,
            health_only: false,
            runners_only: true,
            names: vec![],
        };
        let err = cmd_status(
            &config_path,
            &paths,
            &args,
            ColorMode { enabled: false },
            true,
        )
        .expect_err("oversize defaults user must propagate via load_config");
        match &err {
            GharsError::Validation(msg, _) => {
                assert!(
                    msg.contains("defaults"),
                    "msg must scope to defaults block; got: {msg}"
                );
                assert!(
                    msg.contains("too long"),
                    "msg must come from the user-length-cap layer; got: {msg}"
                );
            }
            other => panic!("expected GharsError::Validation, got: {other:?}"),
        }
        assert_eq!(err_to_exit_code(&err), 6);
    }

    /// #381 end-to-end: a `[[runner]] trust_zone` containing a control
    /// character (here `\n`) must reject through `cmd_status` because
    /// `validate_identity_fields` is wired into `load_config` as one
    /// of the post-load validators (see the validator-order comment
    /// in `load_config`). Symmetric to the cache-pool / runner-name /
    /// runner-user end-to-end tests above. Pins the runner-scoped
    /// surface of `validate_identity_fields`
    /// — the existing `validate_identity_fields_*` unit tests pin the
    /// helper directly; this exercises the end-to-end CLI path so a
    /// future refactor that drops `validate_identity_fields` from
    /// `load_config` (or moves it to a per-cmd pre-step) will break
    /// here.
    #[test]
    fn cmd_status_rejects_runner_trust_zone_with_newline_via_load_config() {
        let tmp = tempfile::tempdir().unwrap();
        let config_path = Utf8PathBuf::from_path_buf(tmp.path().to_path_buf())
            .unwrap()
            .join("ghars.toml");
        // The TOML literal `"audited\nInjected=stuff"` survives the
        // serde-toml decoder verbatim because `\n` inside a basic
        // string is the standard escape; the validator runs on the
        // decoded String. This is the attack shape the `\n` rejection
        // is supposed to close (an operator config edit smuggling a
        // second X-Ghars-* line into the rendered drop-in body).
        let body = "\
[defaults]
prefix = \"/var/lib/ghars\"

[auth.pat]
kind = \"pat\"
token_env = \"GHARS_PAT\"

[[runner]]
name = \"buckos\"
url = \"https://github.com/example/repo\"
auth = \"pat\"
trust_zone = \"audited\\nInjected=stuff\"
"
        .to_string();
        fs::write(config_path.as_std_path(), body).unwrap();

        let paths = Paths::default();
        let args = StatusArgs {
            json: false,
            metrics: false,
            health_only: false,
            runners_only: true,
            names: vec![],
        };
        let err = cmd_status(
            &config_path,
            &paths,
            &args,
            ColorMode { enabled: false },
            true,
        )
        .expect_err("trust_zone with newline must propagate via load_config");
        match &err {
            GharsError::Validation(msg, _) => {
                assert!(
                    msg.contains("runner") && msg.contains("buckos"),
                    "msg must scope to the offending runner; got: {msg}"
                );
                assert!(
                    msg.contains("trust_zone"),
                    "msg must name the trust_zone field; got: {msg}"
                );
                assert!(
                    msg.contains("newline"),
                    "msg must classify the offending char; got: {msg}"
                );
            }
            other => panic!("expected GharsError::Validation, got: {other:?}"),
        }
        assert_eq!(
            err_to_exit_code(&err),
            6,
            "Validation must map to exit code 6 (Part 5)"
        );
    }

    /// #381 end-to-end: a `[cache_pools.NAME] trust_zone` containing
    /// a control character (here `\r`) must reject through `cmd_status`.
    /// Symmetric to the runner-scoped trust_zone test above —
    /// `validate_identity_fields` walks both `cfg.runners` and
    /// `cfg.cache_pools`, so the e2e gate must cover both surfaces.
    #[test]
    fn cmd_status_rejects_cache_pool_trust_zone_with_carriage_return_via_load_config() {
        let tmp = tempfile::tempdir().unwrap();
        let config_path = Utf8PathBuf::from_path_buf(tmp.path().to_path_buf())
            .unwrap()
            .join("ghars.toml");
        let body = "\
[defaults]
prefix = \"/var/lib/ghars\"

[auth.pat]
kind = \"pat\"
token_env = \"GHARS_PAT\"

[cache_pools.build]
kinds = [\"sccache\"]
size = \"200G\"
trust_zone = \"audited\\rsmuggled\"
"
        .to_string();
        fs::write(config_path.as_std_path(), body).unwrap();

        let paths = Paths::default();
        let args = StatusArgs {
            json: false,
            metrics: false,
            health_only: false,
            runners_only: true,
            names: vec![],
        };
        let err = cmd_status(
            &config_path,
            &paths,
            &args,
            ColorMode { enabled: false },
            true,
        )
        .expect_err("cache_pool trust_zone with carriage return must propagate via load_config");
        match &err {
            GharsError::Validation(msg, _) => {
                assert!(
                    msg.contains("cache_pool") && msg.contains("build"),
                    "msg must scope to the offending cache_pool; got: {msg}"
                );
                assert!(
                    msg.contains("trust_zone"),
                    "msg must name the trust_zone field; got: {msg}"
                );
                assert!(
                    msg.contains("carriage return"),
                    "msg must classify the offending char; got: {msg}"
                );
            }
            other => panic!("expected GharsError::Validation, got: {other:?}"),
        }
        assert_eq!(err_to_exit_code(&err), 6);
    }

    /// #381 end-to-end happy path: `cmd_status` ACCEPTS a config whose
    /// trust_zone fields are clean (no control chars). Pins the
    /// negative — without it, a future regression that always rejects
    /// trust_zone (e.g. validator misuse) would only fail the rejection
    /// tests above as "no error fired", which is symmetric ambiguity.
    /// Asserts cmd_status returns Ok (with --runners-only the D-Bus
    /// path is skipped, so no live systemd is needed) and the trust_zone
    /// values pass through validate_identity_fields unaltered.
    ///
    /// rc=1 (no preflight check ran the runners-only path through it)
    /// is the expected return when the discovered state has no runners
    /// matching the empty filter; the load_config gate is what we
    /// pin here (Ok return ≡ load_config accepted).
    #[test]
    fn cmd_status_accepts_clean_trust_zone_via_load_config() {
        let tmp = tempfile::tempdir().unwrap();
        let config_path = Utf8PathBuf::from_path_buf(tmp.path().to_path_buf())
            .unwrap()
            .join("ghars.toml");
        let body = "\
[defaults]
prefix = \"/var/lib/ghars\"

[auth.pat]
kind = \"pat\"
token_env = \"GHARS_PAT\"

[[runner]]
name = \"buckos\"
url = \"https://github.com/example/repo\"
auth = \"pat\"
trust_zone = \"audited\"

[cache_pools.build]
kinds = [\"sccache\"]
size = \"200G\"
trust_zone = \"audited\"
";
        fs::write(config_path.as_std_path(), body).unwrap();

        let paths = Paths::default();
        let args = StatusArgs {
            json: false,
            metrics: false,
            health_only: false,
            runners_only: true,
            names: vec![],
        };
        // Expect Ok — load_config + validate_identity_fields pass for
        // clean ASCII values; runners-only mode short-circuits the
        // D-Bus discovery so the result is independent of the test
        // environment.
        let result = cmd_status(
            &config_path,
            &paths,
            &args,
            ColorMode { enabled: false },
            true,
        );
        assert!(
            result.is_ok(),
            "clean trust_zone must pass load_config; got: {result:?}"
        );
    }

    /// #349 end-to-end: a `[[runner]] runner_tarball = "/nonexistent..."`
    /// must reject through `cmd_status` because `validate_runner_tarballs`
    /// is the 8th post-load validator wired into `load_config`. Symmetric
    /// to the runner-name / cache-pool / runner-user end-to-end tests
    /// above — proves the lift covers the operator-supplied
    /// runner_tarball surface so cmd_validate / cmd_plan / cmd_apply /
    /// cmd_status / cmd_add all share the same gate.
    ///
    /// The validator's lstat path is the gate: a non-existent path
    /// returns `validation()` from `validators::validate_runner_tarball`
    /// at the `!p.exists()` arm, so this test pins the missing-file
    /// branch end-to-end. Symlink and non-regular-file branches are
    /// pinned by the validator's own unit tests in validators.rs.
    #[test]
    fn cmd_status_rejects_nonexistent_runner_tarball_via_load_config() {
        let tmp = tempfile::tempdir().unwrap();
        let config_path = Utf8PathBuf::from_path_buf(tmp.path().to_path_buf())
            .unwrap()
            .join("ghars.toml");
        // Path is comfortably under the tempdir but never created.
        // Using a child of the tempdir (rather than a hardcoded
        // /nonexistent...) avoids env leakage AND prevents collisions
        // with anything an operator might have on disk.
        let nonexistent = Utf8PathBuf::from_path_buf(tmp.path().to_path_buf())
            .unwrap()
            .join("absent.tar.gz");
        let body = format!(
            "\
[defaults]
prefix = \"/var/lib/ghars\"

[auth.pat]
kind = \"pat\"
token_env = \"GHARS_PAT\"

[[runner]]
name = \"buckos\"
url = \"https://github.com/example/repo\"
auth = \"pat\"
runner_tarball = \"{nonexistent}\"
"
        );
        fs::write(config_path.as_std_path(), body).unwrap();

        let paths = Paths::default();
        let args = StatusArgs {
            json: false,
            metrics: false,
            health_only: false,
            runners_only: true,
            names: vec![],
        };
        let err = cmd_status(
            &config_path,
            &paths,
            &args,
            ColorMode { enabled: false },
            true,
        )
        .expect_err("nonexistent runner_tarball must propagate via load_config");
        match &err {
            GharsError::Validation(msg, _) => {
                assert!(
                    msg.contains("runner") && msg.contains("buckos"),
                    "msg must scope to the offending runner by name; got: {msg}"
                );
                assert!(
                    msg.contains("runner-tarball") && msg.contains("does not exist"),
                    "msg must come from the validate_runner_tarball layer; got: {msg}"
                );
            }
            other => panic!("expected GharsError::Validation, got: {other:?}"),
        }
        assert_eq!(
            err_to_exit_code(&err),
            6,
            "Validation must map to exit code 6 (Part 5)"
        );
    }

    /// #349 symlink branch: `validate_runner_tarball` lstat's the path
    /// BEFORE `is_file()` so a symlink-to-regular-file is rejected with
    /// the "not a symlink" error from the symlink-rejection arm of
    /// `validators::validate_runner_tarball`. This pins the rejection
    /// end-to-end through `cmd_status` → `load_config` →
    /// `validate_runner_tarballs`. Pairs with the nonexistent-file
    /// branch above and the directory-branch test below to cover all
    /// three error arms of the validator.
    #[test]
    fn cmd_status_rejects_symlink_runner_tarball_via_load_config() {
        let tmp = tempfile::tempdir().unwrap();
        let config_path = Utf8PathBuf::from_path_buf(tmp.path().to_path_buf())
            .unwrap()
            .join("ghars.toml");
        // Plant a real regular file so the symlink target exists; the
        // gate is on the lstat-determined type of the runner_tarball
        // path itself, not the resolved target.
        let target = tmp.path().join("real.tar.gz");
        fs::write(&target, b"fake tarball bytes\n").unwrap();
        let symlink_path = tmp.path().join("link.tar.gz");
        std::os::unix::fs::symlink(&target, &symlink_path).unwrap();
        let body = format!(
            "\
[defaults]
prefix = \"/var/lib/ghars\"

[auth.pat]
kind = \"pat\"
token_env = \"GHARS_PAT\"

[[runner]]
name = \"buckos\"
url = \"https://github.com/example/repo\"
auth = \"pat\"
runner_tarball = \"{}\"
",
            symlink_path.display()
        );
        fs::write(config_path.as_std_path(), body).unwrap();

        let paths = Paths::default();
        let args = StatusArgs {
            json: false,
            metrics: false,
            health_only: false,
            runners_only: true,
            names: vec![],
        };
        let err = cmd_status(
            &config_path,
            &paths,
            &args,
            ColorMode { enabled: false },
            true,
        )
        .expect_err("symlink runner_tarball must propagate via load_config");
        match &err {
            GharsError::Validation(msg, _) => {
                assert!(
                    msg.contains("runner") && msg.contains("buckos"),
                    "msg must scope to the offending runner by name; got: {msg}"
                );
                assert!(
                    msg.contains("symlink"),
                    "msg must come from the symlink-rejection branch; got: {msg}"
                );
            }
            other => panic!("expected GharsError::Validation, got: {other:?}"),
        }
        assert_eq!(
            err_to_exit_code(&err),
            6,
            "Validation must map to exit code 6 (Part 5)"
        );
    }

    /// #349 directory branch: `validate_runner_tarball` rejects a path
    /// that exists, is not a symlink, but `is_file()` returns false —
    /// covering the directory case (the `is_file()` arm of
    /// `validators::validate_runner_tarball`). Pairs with the
    /// nonexistent and symlink branch tests to give end-to-end
    /// coverage of all three rejection arms via `cmd_status`.
    #[test]
    fn cmd_status_rejects_directory_runner_tarball_via_load_config() {
        let tmp = tempfile::tempdir().unwrap();
        let config_path = Utf8PathBuf::from_path_buf(tmp.path().to_path_buf())
            .unwrap()
            .join("ghars.toml");
        // Create a directory at the runner_tarball path. Existence
        // check passes; lstat is_symlink check passes (real dir, no
        // symlink); is_file() returns false → directory branch.
        let dir_path = tmp.path().join("not-a-tarball");
        fs::create_dir_all(&dir_path).unwrap();
        let body = format!(
            "\
[defaults]
prefix = \"/var/lib/ghars\"

[auth.pat]
kind = \"pat\"
token_env = \"GHARS_PAT\"

[[runner]]
name = \"buckos\"
url = \"https://github.com/example/repo\"
auth = \"pat\"
runner_tarball = \"{}\"
",
            dir_path.display()
        );
        fs::write(config_path.as_std_path(), body).unwrap();

        let paths = Paths::default();
        let args = StatusArgs {
            json: false,
            metrics: false,
            health_only: false,
            runners_only: true,
            names: vec![],
        };
        let err = cmd_status(
            &config_path,
            &paths,
            &args,
            ColorMode { enabled: false },
            true,
        )
        .expect_err("directory runner_tarball must propagate via load_config");
        match &err {
            GharsError::Validation(msg, _) => {
                assert!(
                    msg.contains("runner") && msg.contains("buckos"),
                    "msg must scope to the offending runner by name; got: {msg}"
                );
                assert!(
                    msg.contains("regular file"),
                    "msg must come from the not-a-regular-file branch; got: {msg}"
                );
            }
            other => panic!("expected GharsError::Validation, got: {other:?}"),
        }
        assert_eq!(
            err_to_exit_code(&err),
            6,
            "Validation must map to exit code 6 (Part 5)"
        );
    }

    /// #432 end-to-end: a `[[runner]] name` exceeding
    /// `NETNS_RUNNER_NAME_MAX_LEN` (= 7) MUST reject through
    /// `cmd_status` when the runner's effective network mode is
    /// `Netns`. The kernel hard-caps interface names at IFNAMSIZ-1
    /// (= 15) in `dev_valid_name`; ghars's veth shape
    /// `"ghars-{name}-h"` adds 8 bytes of overhead, so the operator-
    /// controlled segment cannot exceed 7. Without this gate the
    /// failure surfaces as an opaque `RTNETLINK answers: Numerical
    /// result out of range` from `ip link add` during apply.
    ///
    /// Uses runners_only=true to skip state.discover (which needs
    /// D-Bus) — load_config is the only code path under test here.
    #[test]
    fn cmd_status_rejects_oversize_netns_runner_name_via_load_config() {
        let tmp = tempfile::tempdir().unwrap();
        let config_path = Utf8PathBuf::from_path_buf(tmp.path().to_path_buf())
            .unwrap()
            .join("ghars.toml");
        // 8-char name (one over the cap) — fits the legacy
        // RUNNER_NAME_MAX_LEN (25) so #427 does not pre-reject; the
        // failure must come from the new netns gate.
        let oversize_name = "a".repeat(crate::validators::NETNS_RUNNER_NAME_MAX_LEN + 1);
        let body = format!(
            "\
[defaults]
prefix = \"/var/lib/ghars\"

[auth.pat]
kind = \"pat\"
token_env = \"GHARS_PAT\"

[network.isolated]
mode = \"netns\"
allowed_egress = [{{ addr = \"140.82.121.4\", port = 443, comment = \"github\" }}]

[[runner]]
name = \"{oversize_name}\"
url = \"https://github.com/example/repo\"
auth = \"pat\"
network = \"isolated\"
"
        );
        fs::write(config_path.as_std_path(), body).unwrap();

        let paths = Paths::default();
        let args = StatusArgs {
            json: false,
            metrics: false,
            health_only: false,
            runners_only: true,
            names: vec![],
        };
        let err = cmd_status(
            &config_path,
            &paths,
            &args,
            ColorMode { enabled: false },
            true,
        )
        .expect_err("oversize netns runner name must propagate via load_config");
        match &err {
            GharsError::Validation(msg, hint) => {
                assert!(
                    msg.contains("runner") && msg.contains(&oversize_name),
                    "msg must scope to the offending runner by name; got: {msg}"
                );
                assert!(
                    msg.contains("netns") && msg.contains("IFNAMSIZ"),
                    "msg must come from the netns IFNAMSIZ-cap layer; got: {msg}"
                );
                assert!(
                    hint.contains("'open'"),
                    "hint must offer 'open' as the alternate mode; got: {hint}"
                );
            }
            other => panic!("expected GharsError::Validation, got: {other:?}"),
        }
        assert_eq!(
            err_to_exit_code(&err),
            6,
            "Validation must map to exit code 6 (Part 5)"
        );
    }

    /// #447 defaults-inheritance pin: a `[[runner]]` with NO per-runner
    /// `network = "..."` must INHERIT `[defaults] network = "isolated"`
    /// and therefore be subject to the netns IFNAMSIZ gate. Without
    /// this test a regression that walked only `runner.network`
    /// (skipping the defaults fallback) would silently exempt
    /// inheriting runners from the IFNAMSIZ cap, producing the same
    /// opaque `RTNETLINK ... Numerical result out of range` failure at
    /// apply time that #432 was meant to prevent.
    ///
    /// 8-char name = `NETNS_RUNNER_NAME_MAX_LEN + 1` — the smallest
    /// shape that breaks IFNAMSIZ. Symmetric with the explicit-mode
    /// test above; the only difference is `network = "isolated"` lives
    /// at `[defaults]` level instead of `[[runner]]` level.
    #[test]
    fn cmd_status_rejects_oversize_netns_runner_name_via_defaults_inheritance() {
        let tmp = tempfile::tempdir().unwrap();
        let config_path = Utf8PathBuf::from_path_buf(tmp.path().to_path_buf())
            .unwrap()
            .join("ghars.toml");
        let oversize_name = "a".repeat(crate::validators::NETNS_RUNNER_NAME_MAX_LEN + 1);
        // [defaults] network = "isolated" — the runner has NO explicit
        // network field, so the validator MUST resolve through the
        // defaults inheritance.
        let body = format!(
            "\
[defaults]
prefix = \"/var/lib/ghars\"
network = \"isolated\"

[auth.pat]
kind = \"pat\"
token_env = \"GHARS_PAT\"

[network.isolated]
mode = \"netns\"
allowed_egress = [{{ addr = \"140.82.121.4\", port = 443, comment = \"github\" }}]

[[runner]]
name = \"{oversize_name}\"
url = \"https://github.com/example/repo\"
auth = \"pat\"
"
        );
        fs::write(config_path.as_std_path(), body).unwrap();

        let paths = Paths::default();
        let args = StatusArgs {
            json: false,
            metrics: false,
            health_only: false,
            runners_only: true,
            names: vec![],
        };
        let err = cmd_status(
            &config_path,
            &paths,
            &args,
            ColorMode { enabled: false },
            true,
        )
        .expect_err(
            "oversize netns runner name must propagate via load_config (defaults.network \
             inheritance path)",
        );
        match &err {
            GharsError::Validation(msg, _) => {
                assert!(
                    msg.contains("runner") && msg.contains(&oversize_name),
                    "msg must scope to the offending runner by name; got: {msg}"
                );
                assert!(
                    msg.contains("netns") && msg.contains("IFNAMSIZ"),
                    "msg must come from the netns IFNAMSIZ-cap layer (defaults.network \
                     resolution must reach the same gate as the explicit-mode path); got: {msg}"
                );
            }
            other => panic!("expected GharsError::Validation, got: {other:?}"),
        }
        assert_eq!(
            err_to_exit_code(&err),
            6,
            "Validation must map to exit code 6 (Part 5)"
        );
    }

    /// #432 contract pin: the same 8-char runner name that fails the
    /// netns gate above MUST PASS when no [network.NAME] is referenced
    /// (implicit Open mode — no veth allocated, no IFNAMSIZ exposure).
    /// Without this test a regression that tightened
    /// `RUNNER_NAME_MAX_LEN` globally would silently break operator
    /// configs that legitimately use longer names in Open mode.
    #[test]
    fn cmd_status_accepts_oversize_runner_name_in_open_mode() {
        let tmp = tempfile::tempdir().unwrap();
        let config_path = Utf8PathBuf::from_path_buf(tmp.path().to_path_buf())
            .unwrap()
            .join("ghars.toml");
        let oversize_name = "a".repeat(crate::validators::NETNS_RUNNER_NAME_MAX_LEN + 1);
        // No [network.NAME], no defaults.network → implicit Open mode.
        // The name is still well under RUNNER_NAME_MAX_LEN (25) so the
        // global runner-name cap accepts it.
        let body = format!(
            "\
[defaults]
prefix = \"/var/lib/ghars\"

[auth.pat]
kind = \"pat\"
token_env = \"GHARS_PAT\"

[[runner]]
name = \"{oversize_name}\"
url = \"https://github.com/example/repo\"
auth = \"pat\"
"
        );
        fs::write(config_path.as_std_path(), body).unwrap();

        // Direct load_config call: cmd_status would reach state.discover
        // which needs D-Bus access. This test is about the validators
        // accepting the config, not about cmd_status's full flow.
        let cfg_path = config_path;
        load_config(&cfg_path).expect(
            "8-char runner name in Open mode must pass all validators (no IFNAMSIZ exposure)",
        );
    }

    /// #432 contract pin: the existing #427 boundary at
    /// `RUNNER_NAME_MAX_LEN` (25 chars) must still hold for Open-mode
    /// runners. The new netns gate (= 7) is ADDITIONAL — it MUST NOT
    /// retroactively tighten the global runner-name cap. A regression
    /// that swapped `NETNS_RUNNER_NAME_MAX_LEN` for `RUNNER_NAME_MAX_LEN`
    /// in load_config's check would silently break every operator on
    /// Open mode.
    #[test]
    fn validate_runner_name_still_allows_25_char_name() {
        // 25-char name = exactly RUNNER_NAME_MAX_LEN. Open mode means
        // no netns gate applies. Construct a minimal valid Config
        // directly to exercise validate_runner_names + the load_config
        // sweep without TOML parsing. (TOML basic-string parsing
        // accepts the same name; the direct construction is faster
        // and avoids the parse layer.)
        let tmp = tempfile::tempdir().unwrap();
        let config_path = Utf8PathBuf::from_path_buf(tmp.path().to_path_buf())
            .unwrap()
            .join("ghars.toml");
        let max_name = "a".repeat(crate::validators::RUNNER_NAME_MAX_LEN);
        assert_eq!(
            max_name.len(),
            25,
            "RUNNER_NAME_MAX_LEN drift would invalidate this test's invariant"
        );
        let body = format!(
            "\
[defaults]
prefix = \"/var/lib/ghars\"

[auth.pat]
kind = \"pat\"
token_env = \"GHARS_PAT\"

[[runner]]
name = \"{max_name}\"
url = \"https://github.com/example/repo\"
auth = \"pat\"
"
        );
        fs::write(config_path.as_std_path(), body).unwrap();
        load_config(&config_path).expect(
            "25-char name (= RUNNER_NAME_MAX_LEN) in Open mode must pass — \
             #432 gate must NOT retroactively tighten Open-mode runners",
        );
    }

    /// #432 count-block expansion: a count block whose worst-case
    /// expanded instance name exceeds `NETNS_RUNNER_NAME_MAX_LEN` MUST
    /// reject. The expanded shape is `{prefix}-{i}` for `i in 1..=N`,
    /// so the worst case is `prefix.len() + 1 + count.to_string().len()`.
    /// With NETNS_RUNNER_NAME_MAX_LEN = 7, prefix len 5 + count digits
    /// 2 + the literal '-' = 8 chars, one over the cap.
    #[test]
    fn cmd_status_rejects_netns_count_block_with_expanded_oversize() {
        let tmp = tempfile::tempdir().unwrap();
        let config_path = Utf8PathBuf::from_path_buf(tmp.path().to_path_buf())
            .unwrap()
            .join("ghars.toml");
        // prefix = 5 chars; count = 99 (2 digits); worst-case expansion
        // = 5 + 1 + 2 = 8 > 7 = NETNS_RUNNER_NAME_MAX_LEN. The bare
        // prefix alone (5 chars) WOULD pass; the gate must catch the
        // count expansion.
        let prefix = "abcde"; // 5 chars
        let body = format!(
            "\
[defaults]
prefix = \"/var/lib/ghars\"

[auth.pat]
kind = \"pat\"
token_env = \"GHARS_PAT\"

[network.isolated]
mode = \"netns\"
allowed_egress = [{{ addr = \"140.82.121.4\", port = 443, comment = \"github\" }}]

[[runner]]
name = \"{prefix}\"
count = 99
url = \"https://github.com/example/repo\"
auth = \"pat\"
network = \"isolated\"
"
        );
        fs::write(config_path.as_std_path(), body).unwrap();

        let paths = Paths::default();
        let args = StatusArgs {
            json: false,
            metrics: false,
            health_only: false,
            runners_only: true,
            names: vec![],
        };
        let err = cmd_status(
            &config_path,
            &paths,
            &args,
            ColorMode { enabled: false },
            true,
        )
        .expect_err("netns count-block worst-case oversize must propagate via load_config");
        match &err {
            GharsError::Validation(msg, _) => {
                assert!(
                    msg.contains("runner") && msg.contains(prefix),
                    "msg must scope to the offending runner prefix; got: {msg}"
                );
                assert!(
                    msg.contains("count block") && msg.contains("worst-case"),
                    "msg must come from the count-expansion branch of the netns gate; got: {msg}"
                );
                assert!(
                    msg.contains("IFNAMSIZ"),
                    "msg must cite the kernel constant for operator orientation; got: {msg}"
                );
            }
            other => panic!("expected GharsError::Validation, got: {other:?}"),
        }
        assert_eq!(
            err_to_exit_code(&err),
            6,
            "Validation must map to exit code 6 (Part 5)"
        );
    }

    /// #432 boundary pin: a runner name of EXACTLY
    /// `NETNS_RUNNER_NAME_MAX_LEN` chars in netns mode must ACCEPT.
    /// Together with the `_rejects_oversize_` test (cap+1), this pins
    /// the exact boundary the validator enforces. A regression that
    /// off-by-ones the comparison (`>=` instead of `>`) would flip
    /// this test from pass to fail.
    #[test]
    fn cmd_status_accepts_max_len_netns_runner_name_via_load_config() {
        let tmp = tempfile::tempdir().unwrap();
        let config_path = Utf8PathBuf::from_path_buf(tmp.path().to_path_buf())
            .unwrap()
            .join("ghars.toml");
        let max_name = "a".repeat(crate::validators::NETNS_RUNNER_NAME_MAX_LEN);
        // Drift guard: NETNS_RUNNER_NAME_MAX_LEN is derived from
        // IFNAMSIZ - 1 - VETH_NAME_OVERHEAD = 16 - 1 - 8 = 7. If
        // either bookend changes, this assertion catches the drift
        // before the rest of the test reasons about a stale cap.
        assert_eq!(
            max_name.len(),
            7,
            "NETNS_RUNNER_NAME_MAX_LEN drift would invalidate this test's invariant"
        );
        let body = format!(
            "\
[defaults]
prefix = \"/var/lib/ghars\"

[auth.pat]
kind = \"pat\"
token_env = \"GHARS_PAT\"

[network.isolated]
mode = \"netns\"
allowed_egress = [{{ addr = \"140.82.121.4\", port = 443, comment = \"github\" }}]

[[runner]]
name = \"{max_name}\"
url = \"https://github.com/example/repo\"
auth = \"pat\"
network = \"isolated\"
"
        );
        fs::write(config_path.as_std_path(), body).unwrap();
        load_config(&config_path).expect(
            "name at exactly NETNS_RUNNER_NAME_MAX_LEN must pass — \
             cap is inclusive (the longest accepted), not exclusive",
        );
    }

    /// #432 count-block boundary pin: `count = Some(1)` MUST be
    /// treated as bare-name (no suffix), matching `plan::is_count_block`
    /// which only returns `true` for `count >= 2`. A 7-char name with
    /// `count = 1` produces a single instance with name `"aaaaaaa"` —
    /// no `-1` suffix — so it MUST pass the netns gate. A regression
    /// that included `count.to_string().len()` for `count = 1` would
    /// falsely reject this config.
    #[test]
    fn cmd_status_accepts_count_one_at_max_len_in_netns_mode() {
        let tmp = tempfile::tempdir().unwrap();
        let config_path = Utf8PathBuf::from_path_buf(tmp.path().to_path_buf())
            .unwrap()
            .join("ghars.toml");
        let name = "a".repeat(crate::validators::NETNS_RUNNER_NAME_MAX_LEN);
        assert_eq!(name.len(), 7, "drift guard for NETNS_RUNNER_NAME_MAX_LEN");
        let body = format!(
            "\
[defaults]
prefix = \"/var/lib/ghars\"

[auth.pat]
kind = \"pat\"
token_env = \"GHARS_PAT\"

[network.isolated]
mode = \"netns\"
allowed_egress = [{{ addr = \"140.82.121.4\", port = 443, comment = \"github\" }}]

[[runner]]
name = \"{name}\"
count = 1
url = \"https://github.com/example/repo\"
auth = \"pat\"
network = \"isolated\"
"
        );
        fs::write(config_path.as_std_path(), body).unwrap();
        load_config(&config_path).expect(
            "count = 1 keeps the bare name in plan::expand_counts (no `-1` suffix), \
             so a name at the cap must still pass — the validator's count semantics \
             must mirror `plan::is_count_block` (count >= 2 ONLY)",
        );
    }

    /// #432 count-block boundary pin: `count = Some(0)` produces
    /// ZERO runners (see `plan::expand_counts` early-return on
    /// `Some(0)`), so no veth is ever allocated for that block. The
    /// netns gate MUST NOT reject an oversize name when `count = 0`
    /// because the planner will emit zero instances regardless. A
    /// regression that gates blindly on `name.len()` (ignoring
    /// `count = 0`) would falsely reject this config.
    #[test]
    fn cmd_status_accepts_count_zero_oversize_in_netns_mode() {
        let tmp = tempfile::tempdir().unwrap();
        let config_path = Utf8PathBuf::from_path_buf(tmp.path().to_path_buf())
            .unwrap()
            .join("ghars.toml");
        // 8-char name (one over the netns cap). count = 0 means the
        // planner emits zero instances — no veth allocation, no
        // IFNAMSIZ exposure — so the gate must let this through.
        let name = "a".repeat(crate::validators::NETNS_RUNNER_NAME_MAX_LEN + 1);
        let body = format!(
            "\
[defaults]
prefix = \"/var/lib/ghars\"

[auth.pat]
kind = \"pat\"
token_env = \"GHARS_PAT\"

[network.isolated]
mode = \"netns\"
allowed_egress = [{{ addr = \"140.82.121.4\", port = 443, comment = \"github\" }}]

[[runner]]
name = \"{name}\"
count = 0
url = \"https://github.com/example/repo\"
auth = \"pat\"
network = \"isolated\"
"
        );
        fs::write(config_path.as_std_path(), body).unwrap();
        load_config(&config_path).expect(
            "count = 0 produces zero runners (see `plan::expand_counts` early-return), \
             so no veth is ever allocated — the netns gate must mirror this and \
             accept oversize names when the block expands to zero instances",
        );
    }

    /// #447: when `[defaults] network = "isolated"` is set and a
    /// `[[runner]]` block has no `network = ...` override, the
    /// netns gate MUST resolve the network reference through the
    /// defaults inheritance path (`runner.network → defaults.network
    /// → cfg.networks[name].mode`) and reject an oversize name. This
    /// pins the exact resolution order documented at the top of
    /// `validate_netns_runner_name_lengths`. A regression that only
    /// reads `runner.network` without falling back to
    /// `defaults.network` would silently accept an oversize name in
    /// netns deployments where operators rely on the defaults
    /// pattern (the canonical Part 3 idiom for fleets where every
    /// runner shares a network policy).
    #[test]
    fn cmd_status_rejects_oversize_netns_via_defaults_network_inheritance() {
        let tmp = tempfile::tempdir().unwrap();
        let config_path = Utf8PathBuf::from_path_buf(tmp.path().to_path_buf())
            .unwrap()
            .join("ghars.toml");
        let oversize_name = "a".repeat(crate::validators::NETNS_RUNNER_NAME_MAX_LEN + 1);
        // [defaults] network = "isolated" — no per-runner override.
        let body = format!(
            "\
[defaults]
prefix = \"/var/lib/ghars\"
network = \"isolated\"

[auth.pat]
kind = \"pat\"
token_env = \"GHARS_PAT\"

[network.isolated]
mode = \"netns\"
allowed_egress = [{{ addr = \"140.82.121.4\", port = 443, comment = \"github\" }}]

[[runner]]
name = \"{oversize_name}\"
url = \"https://github.com/example/repo\"
auth = \"pat\"
"
        );
        fs::write(config_path.as_std_path(), body).unwrap();

        let err = load_config(&config_path).expect_err(
            "oversize netns runner name MUST reject when network mode is \
             inherited from [defaults] (validator must walk the resolution chain)",
        );
        match &err {
            GharsError::Validation(msg, hint) => {
                assert!(
                    msg.contains("runner") && msg.contains(&oversize_name),
                    "msg must scope to the offending runner; got: {msg}"
                );
                assert!(
                    msg.contains("netns") && msg.contains("IFNAMSIZ"),
                    "msg must come from the netns IFNAMSIZ gate, not an unrelated \
                     validator; got: {msg}"
                );
                assert!(
                    hint.contains("'open'"),
                    "hint must offer 'open' as an alternate mode; got: {hint}"
                );
            }
            other => panic!("expected GharsError::Validation, got: {other:?}"),
        }
    }

    #[test]
    fn cmd_status_health_only_still_loads_config() {
        // #261: even when output is health-only (skips state.discover
        // entirely), cmd_status must still call load_config. The
        // "every command path validates config first" project
        // standard prevents users from getting a misleading "PASS" on
        // health checks while their config is silently broken.
        let tmp = tempfile::tempdir().unwrap();
        let config_path = Utf8PathBuf::from_path_buf(tmp.path().to_path_buf())
            .unwrap()
            .join("ghars.toml");
        fs::write(
            config_path.as_std_path(),
            "this is not toml at all = = = =\n",
        )
        .unwrap();

        let paths = Paths::default();
        let args = StatusArgs {
            json: false,
            metrics: false,
            health_only: true,
            runners_only: false,
            names: vec![],
        };
        let err = cmd_status(
            &config_path,
            &paths,
            &args,
            ColorMode { enabled: false },
            true,
        )
        .expect_err("malformed config + --health-only must still error");
        assert!(
            matches!(err, GharsError::Config(_, _)),
            "expected GharsError::Config; got {err:?}"
        );
    }

    #[test]
    fn argv_init_takes_optional_output_override() {
        let cli =
            Cli::try_parse_from(["ghars", "init", "--output", "/etc/ghars/foo.toml"]).unwrap();
        match cli.command {
            Command::Init(args) => {
                assert_eq!(
                    args.output.as_deref(),
                    Some(Utf8Path::new("/etc/ghars/foo.toml"))
                );
            }
            _ => panic!("expected Init"),
        }
    }

    #[test]
    fn argv_add_minimum_repo_only() {
        let cli = Cli::try_parse_from(["ghars", "add", "--repo", "owner/repo"]).unwrap();
        match cli.command {
            Command::Add(args) => {
                assert_eq!(args.repo, "owner/repo");
                assert!(args.name.is_none());
                assert!(args.labels.is_empty());
                assert!(args.auth.is_none());
                assert!(!args.no_apply);
            }
            _ => panic!("expected Add"),
        }
    }

    #[test]
    fn argv_add_full_with_labels_and_no_apply() {
        let cli = Cli::try_parse_from([
            "ghars",
            "add",
            "--repo",
            "owner/repo",
            "--name",
            "owner-repo-3",
            "--labels",
            "x64,linux,buck2",
            "--auth",
            "pat",
            "--no-apply",
        ])
        .unwrap();
        match cli.command {
            Command::Add(args) => {
                assert_eq!(args.repo, "owner/repo");
                assert_eq!(args.name.as_deref(), Some("owner-repo-3"));
                assert_eq!(
                    args.labels,
                    vec!["x64".to_owned(), "linux".to_owned(), "buck2".to_owned()]
                );
                assert_eq!(args.auth.as_deref(), Some("pat"));
                assert!(args.no_apply);
            }
            _ => panic!("expected Add"),
        }
    }

    #[test]
    fn argv_logs_default_lines_100_no_follow() {
        let cli = Cli::try_parse_from(["ghars", "logs"]).unwrap();
        match cli.command {
            Command::Logs(args) => {
                assert!(args.names.is_empty());
                assert!(!args.follow);
                assert_eq!(args.lines, 100);
                assert!(args.since.is_none());
            }
            _ => panic!("expected Logs"),
        }
    }

    #[test]
    fn argv_logs_with_since_and_explicit_lines() {
        let cli = Cli::try_parse_from([
            "ghars",
            "logs",
            "--since",
            "1 hour ago",
            "-n",
            "500",
            "buckos",
        ])
        .unwrap();
        match cli.command {
            Command::Logs(args) => {
                assert_eq!(args.since.as_deref(), Some("1 hour ago"));
                assert_eq!(args.lines, 500);
                assert_eq!(args.names, vec!["buckos".to_owned()]);
            }
            _ => panic!("expected Logs"),
        }
    }

    #[test]
    fn argv_metrics_defaults() {
        let cli = Cli::try_parse_from(["ghars", "metrics"]).unwrap();
        match cli.command {
            Command::Metrics(args) => {
                assert!(args.names.is_empty());
                assert!(!args.json);
                assert!(!args.no_total);
            }
            _ => panic!("expected Metrics"),
        }
    }

    #[test]
    fn argv_metrics_json_no_total_with_names() {
        let cli = Cli::try_parse_from(["ghars", "metrics", "buckos,ktstr", "--json", "--no-total"])
            .unwrap();
        match cli.command {
            Command::Metrics(args) => {
                assert_eq!(args.names, vec!["buckos".to_owned(), "ktstr".to_owned()]);
                assert!(args.json);
                assert!(args.no_total);
            }
            _ => panic!("expected Metrics"),
        }
    }

    #[test]
    fn argv_completions_each_supported_shell_parses() {
        // clap_complete::Shell variants. Pick a handful of well-known
        // ones; clap rejects unknown shells, so success here proves we
        // expose the same enum surface.
        for shell in ["bash", "zsh", "fish", "powershell"] {
            let cli = Cli::try_parse_from(["ghars", "completions", shell]).unwrap();
            match cli.command {
                Command::Completions { .. } => {}
                _ => panic!("expected Completions for {shell}"),
            }
        }
    }

    #[test]
    fn argv_manpages_requires_output_path() {
        let cli = Cli::try_parse_from(["ghars", "manpages", "/tmp/ghars-manpages"]).unwrap();
        match cli.command {
            Command::Manpages { output } => {
                assert_eq!(output, Utf8Path::new("/tmp/ghars-manpages"));
            }
            _ => panic!("expected Manpages"),
        }
        // Without an output positional, parse fails.
        let r = Cli::try_parse_from(["ghars", "manpages"]);
        assert!(r.is_err(), "manpages without OUTPUT must fail at parse");
    }

    #[test]
    fn argv_hidden_netns_setup_requires_instance() {
        let cli = Cli::try_parse_from(["ghars", "_netns-setup", "buckos"]).unwrap();
        assert!(matches!(cli.command, Command::NetnsSetup { .. }));
        let r = Cli::try_parse_from(["ghars", "_netns-setup"]);
        assert!(r.is_err(), "_netns-setup without instance must fail");
    }

    #[test]
    fn argv_hidden_netns_teardown_requires_instance() {
        let cli = Cli::try_parse_from(["ghars", "_netns-teardown", "ci-1"]).unwrap();
        assert!(matches!(cli.command, Command::NetnsTeardown { .. }));
    }

    #[test]
    fn argv_hidden_netns_veth_passes_program_args_through() {
        // trailing_var_arg + allow_hyphen_values is the contract for
        // `ghars _netns-veth INST -- /usr/sbin/ip -4 addr`.
        let cli =
            Cli::try_parse_from(["ghars", "_netns-veth", "ci-1", "/usr/sbin/ip", "-4", "addr"])
                .unwrap();
        match cli.command {
            Command::NetnsVeth { instance, program } => {
                assert_eq!(instance, "ci-1");
                assert_eq!(program, vec!["/usr/sbin/ip", "-4", "addr"]);
            }
            _ => panic!("expected NetnsVeth"),
        }
    }

    #[test]
    fn argv_global_quiet_and_verbose_count() {
        let cli = Cli::try_parse_from(["ghars", "--quiet", "-vv", "validate"]).unwrap();
        assert!(cli.quiet);
        assert_eq!(cli.verbose, 2);
    }

    #[test]
    fn argv_apply_only_value_delimiter_splits_csv() {
        // The `value_delimiter = ','` annotation is the only thing
        // turning a single CSV token into a vec. Drop it and the
        // operator's filter becomes a literal string match. Pin it.
        let cli = Cli::try_parse_from(["ghars", "apply", "--only", "ci-1,ci-2,ci-3"]).unwrap();
        match cli.command {
            Command::Apply(args) => {
                assert_eq!(
                    args.only,
                    vec!["ci-1".to_owned(), "ci-2".to_owned(), "ci-3".to_owned()]
                );
            }
            _ => panic!("expected Apply"),
        }
    }

    #[test]
    fn argv_logs_short_follow_flag() {
        // `-f` short form must be equivalent to `--follow`.
        let cli = Cli::try_parse_from(["ghars", "logs", "buckos", "-f"]).unwrap();
        match cli.command {
            Command::Logs(args) => {
                assert!(args.follow);
                assert_eq!(args.names, vec!["buckos".to_owned()]);
            }
            _ => panic!("expected Logs"),
        }
    }

    #[test]
    fn argv_global_config_explicit_flag_path_used() {
        // --config CLI flag is honored. We don't test env-fallback or
        // default-fallback here because both require std::env::set_var
        // / remove_var which are `unsafe` since Rust 2024 (race with
        // other threads), and the workspace forbids unsafe_code.
        // The clap derive itself wires `env = "GHARS_CONFIG"` and
        // `default_value = "/etc/ghars/ghars.toml"` — those are clap's
        // contract; if either of them broke at the source level the
        // doc comment for `Cli::config` would no longer compile.
        let cli =
            Cli::try_parse_from(["ghars", "--config", "/tmp/ghars-flag.toml", "validate"]).unwrap();
        assert_eq!(cli.config, Utf8Path::new("/tmp/ghars-flag.toml"));
    }

    #[test]
    fn argv_global_verbose_count_three_v_flags() {
        // Count action: `-vvv` increments three times.
        let cli = Cli::try_parse_from(["ghars", "-vvv", "plan"]).unwrap();
        assert_eq!(cli.verbose, 3);
    }

    /// #454: pin single `-v` shape. Without this, a regression that
    /// changed the clap action from `Count` to `SetTrue` would still
    /// pass the -vv/-vvv tests (clap-derive's `Count` collapses
    /// repeated short flags) but silently break the single-flag case
    /// because SetTrue stores 1 only on first occurrence.
    #[test]
    fn argv_global_verbose_count_single_v_flag() {
        let cli = Cli::try_parse_from(["ghars", "-v", "plan"]).unwrap();
        assert_eq!(cli.verbose, 1);
    }

    /// #454: pin `--verbose` long-form shape. Operators may pass the
    /// long form (CI scripts often do for readability); a regression
    /// that dropped `long` from the clap derive would silently break
    /// it without affecting the short-form `-v` tests.
    #[test]
    fn argv_global_verbose_long_form() {
        let cli = Cli::try_parse_from(["ghars", "--verbose", "plan"]).unwrap();
        assert_eq!(cli.verbose, 1);
    }

    // ---------- #454: verbose_to_filter_level truth table ----------

    /// #454 row 1/6: default operator state. No flags = info.
    #[test]
    fn verbose_to_filter_level_quiet_false_verbose_0_returns_info() {
        assert_eq!(verbose_to_filter_level(false, 0), "info");
    }

    /// #454 row 2/6: --quiet alone collapses info chatter to warn.
    #[test]
    fn verbose_to_filter_level_quiet_true_verbose_0_returns_warn() {
        assert_eq!(verbose_to_filter_level(true, 0), "warn");
    }

    /// #454 row 3/6: -v alone bumps to debug.
    #[test]
    fn verbose_to_filter_level_quiet_false_verbose_1_returns_debug() {
        assert_eq!(verbose_to_filter_level(false, 1), "debug");
    }

    /// #454 row 4/6: --quiet AND -v → -v wins; debug. Pins the
    /// "verbose overrides quiet" contract documented in the helper's
    /// doc-comment.
    #[test]
    fn verbose_to_filter_level_quiet_true_verbose_1_returns_debug() {
        assert_eq!(verbose_to_filter_level(true, 1), "debug");
    }

    /// #454 row 5/6: -vv = trace (any v >= 2 lands here).
    #[test]
    fn verbose_to_filter_level_quiet_false_verbose_2_returns_trace() {
        assert_eq!(verbose_to_filter_level(false, 2), "trace");
    }

    /// #454 row 6/6: --quiet AND -vv → -vv wins; trace.
    #[test]
    fn verbose_to_filter_level_quiet_true_verbose_2_returns_trace() {
        assert_eq!(verbose_to_filter_level(true, 2), "trace");
    }

    /// #454 saturation: any verbose >= 2 maps to trace, not just 2.
    /// Pins that the `_ => "trace"` arm catches arbitrary higher
    /// counts (operators sometimes type -vvvvv).
    #[test]
    fn verbose_to_filter_level_high_verbose_counts_saturate_at_trace() {
        for v in [3, 5, 10, u8::MAX] {
            assert_eq!(
                verbose_to_filter_level(false, v),
                "trace",
                "verbose={v} must saturate at trace"
            );
            assert_eq!(
                verbose_to_filter_level(true, v),
                "trace",
                "verbose={v} with quiet must still saturate at trace"
            );
        }
    }

    // ---------- #238: render_plan + render_action_line all variants -----

    fn fake_effective_spec(name: &str) -> crate::config::EffectiveRunnerSpec {
        crate::config::EffectiveRunnerSpec {
            name: name.into(),
            url: format!("https://github.com/example/{name}"),
            arch: crate::config::Arch::X86_64,
            user: format!("ghars-{name}"),
            prefix: Utf8PathBuf::from("/var/lib/ghars"),
            labels: vec![name.into()],
            memory_max: None,
            runner_version: None,
            runner_sha256: None,
            runner_tarball: None,
            auth_name: "pat".into(),
            caches: vec![],
            trust_zone: "default".into(),
            network: None,
            proxy: None,
            hooks: None,
            hardening: crate::config::Hardening::default(),
            allowed_cpus: None,
            allowed_memory_nodes: None,
            spec_hash: "sha256:0".into(),
            runsvc_sha256: String::new(),
            config_source: "/etc/ghars/ghars.toml".into(),
        }
    }

    fn fake_runner_plan(name: &str) -> plan::RunnerPlan {
        plan::RunnerPlan {
            spec: fake_effective_spec(name),
            resolved_release: None,
            effective_unit_text: String::new(),
            drop_ins: std::collections::BTreeMap::new(),
            spec_hash: "sha256:0".into(),
        }
    }

    fn fake_identity(name: &str) -> plan::RunnerIdentity {
        plan::RunnerIdentity {
            name: name.into(),
            url: format!("https://github.com/example/{name}"),
            auth_name: "pat".into(),
            prefix: Utf8PathBuf::from("/var/lib/ghars"),
            user: format!("ghars-{name}"),
        }
    }

    fn fake_cache_binding(name: &str) -> crate::config::EffectiveCacheBinding {
        crate::config::EffectiveCacheBinding {
            name: name.into(),
            kinds: vec![crate::config::CacheKind::Ccache],
            size: "10G".into(),
            mode: crate::config::CacheMode::Shared,
            trust_zone: "default".into(),
        }
    }

    /// CLN-2: build a recreate-class `RunnerDelta` with the given name +
    /// recreate_reasons. All other fields default to the same values
    /// callers would otherwise inline. Use for any recreate-class
    /// `UpdateRunner` test fixture where only name + reasons matter.
    fn recreate_delta(name: &str, reasons: Vec<&'static str>) -> plan::RunnerDelta {
        plan::RunnerDelta {
            identity: fake_identity(name),
            after: fake_runner_plan(name),
            requires_recreate: true,
            recreate_reasons: reasons,
            drift_cause: plan::DriftCause::SpecChanged,
            field_changes: Vec::new(),
            drop_in_changes: Vec::new(),
            before_caches: None,
            before_drop_in_basenames: None,
        }
    }

    /// CLN-2: build an in-place `RunnerDelta` (no recreate) with the
    /// given name. Symmetric to `recreate_delta` for the `~` sigil
    /// branch.
    fn inplace_delta(name: &str) -> plan::RunnerDelta {
        plan::RunnerDelta {
            identity: fake_identity(name),
            after: fake_runner_plan(name),
            requires_recreate: false,
            recreate_reasons: vec![],
            drift_cause: plan::DriftCause::SpecChanged,
            field_changes: Vec::new(),
            drop_in_changes: Vec::new(),
            before_caches: None,
            before_drop_in_basenames: None,
        }
    }

    #[test]
    fn render_action_line_create_runner_plain_and_color() {
        let action = Action::CreateRunner(fake_runner_plan("buckos"));
        let plain = render_action_line(&action, ColorMode { enabled: false }, false);
        assert!(plain.starts_with("+ "));
        assert!(plain.contains("runner buckos"));
        assert!(plain.contains("create"));
        // No ANSI when color off.
        assert!(!plain.contains("\x1b["));
        let colored = render_action_line(&action, ColorMode { enabled: true }, false);
        assert!(colored.contains("\x1b[32m"), "expected green ANSI prefix");
        assert!(colored.contains("\x1b[0m"), "expected ANSI reset");
    }

    #[test]
    fn render_action_line_update_runner_emits_field_changes_indented() {
        // BATCH C / PART 6: per-field FieldChange entries render as
        // 4-space-indented `path: before → after` lines under the
        // header. The test exercises a recreate-class field (url) and
        // a list-typed field (labels) to confirm both paths produce a
        // line; list rendering uses Display of the whole vec for now —
        // the +/- per-item form is reserved for the full --diff flag
        // (#285).
        let delta = plan::RunnerDelta {
            identity: fake_identity("buckos"),
            after: fake_runner_plan("buckos"),
            requires_recreate: true,
            recreate_reasons: vec!["url"],
            drift_cause: plan::DriftCause::SpecChanged,
            field_changes: vec![
                plan::FieldChange {
                    path: "url",
                    before: plan::FieldValue::String("https://github.com/example/buckos".into()),
                    after: plan::FieldValue::String("https://github.com/example/buckos-new".into()),
                },
                plan::FieldChange {
                    path: "labels",
                    before: plan::FieldValue::List(vec!["ci".into()]),
                    after: plan::FieldValue::List(vec!["ci".into(), "gpu".into()]),
                },
            ],
            drop_in_changes: Vec::new(),
            before_caches: None,
            before_drop_in_basenames: None,
        };
        let line = render_action_line(
            &Action::UpdateRunner(delta),
            ColorMode { enabled: false },
            false,
        );
        let lines: Vec<&str> = line.split('\n').collect();
        assert_eq!(lines.len(), 3, "header + 2 field lines, got: {line}");
        // #462: recreate-class UpdateRunner uses `!` sigil at column 0.
        assert!(lines[0].starts_with("! "), "got: {}", lines[0]);
        assert_eq!(
            lines[1],
            "    url: https://github.com/example/buckos → https://github.com/example/buckos-new",
        );
        // #463: List-typed FieldValue renders comma-joined in text
        // (no surrounding brackets — same v1 contract as the
        // pre-typed `labels.join(",")`). Operator grep pipelines
        // that key off `labels:.*gpu` keep working.
        assert_eq!(lines[2], "    labels: ci → ci,gpu");
    }

    #[test]
    fn render_action_line_update_runner_emits_drop_in_change_lines() {
        // #301: Created (`+ basename`), Modified (`~ basename`), and
        // Removed (`- basename`) all surface in the brief view under
        // the action header so toggling a per-family drop-in
        // (enabling [proxy] → 60-proxy.conf created, clearing
        // memory_max → 10-memory.conf removed) is operator-visible
        // without re-running the planner with --diff. Preserved is
        // the audit-trail "no edit" tag and stays out of the brief
        // view — JSON output covers all four variants for tooling.
        let delta = plan::RunnerDelta {
            identity: fake_identity("buckos"),
            after: fake_runner_plan("buckos"),
            requires_recreate: false,
            recreate_reasons: vec![],
            drift_cause: plan::DriftCause::DriftDetected,
            field_changes: Vec::new(),
            drop_in_changes: vec![
                plan::DropInChange {
                    basename: "10-memory.conf".into(),
                    change: plan::DropInChangeKind::Modified {
                        before: "old".into(),
                        after: "new".into(),
                    },
                },
                plan::DropInChange {
                    basename: "60-proxy.conf".into(),
                    change: plan::DropInChangeKind::Created {
                        after: "new".into(),
                    },
                },
                plan::DropInChange {
                    basename: "70-hooks.conf".into(),
                    change: plan::DropInChangeKind::Removed {
                        before: "old".into(),
                    },
                },
                plan::DropInChange {
                    basename: "15-resolv.conf".into(),
                    change: plan::DropInChangeKind::Preserved,
                },
            ],
            before_caches: None,
            before_drop_in_basenames: None,
        };
        let line = render_action_line(
            &Action::UpdateRunner(delta),
            ColorMode { enabled: false },
            false,
        );
        let lines: Vec<&str> = line.split('\n').collect();
        // header + 3 drop-in lines (Modified / Created / Removed);
        // Preserved is suppressed from the brief view.
        assert_eq!(
            lines.len(),
            4,
            "header + Modified + Created + Removed lines, got: {line}"
        );
        assert!(lines[0].starts_with("~ "), "got: {}", lines[0]);
        assert_eq!(lines[1], "    ~ 10-memory.conf");
        assert_eq!(lines[2], "    + 60-proxy.conf");
        assert_eq!(lines[3], "    - 70-hooks.conf");
        assert!(
            !line.contains("15-resolv.conf"),
            "Preserved drop-in must not appear in brief view: {line}"
        );
    }

    #[test]
    fn render_action_line_update_runner_in_place_includes_drift_cause() {
        // #260: in-place update without recreate must carry the
        // drift_cause label so operators can tell config edit vs
        // detected drift.
        let delta = plan::RunnerDelta {
            identity: fake_identity("buckos"),
            after: fake_runner_plan("buckos"),
            requires_recreate: false,
            recreate_reasons: vec![],
            drift_cause: plan::DriftCause::DriftDetected,
            field_changes: Vec::new(),
            drop_in_changes: Vec::new(),
            before_caches: None,
            before_drop_in_basenames: None,
        };
        let line = render_action_line(
            &Action::UpdateRunner(delta),
            ColorMode { enabled: false },
            false,
        );
        assert!(line.starts_with("~ "));
        assert!(line.contains("drift_detected"), "got: {line}");
        assert!(line.contains("update: in-place"), "got: {line}");
    }

    #[test]
    fn render_action_line_update_runner_recreate_lists_reasons_and_cause() {
        // #260 + existing recreate-reasons formatting: spec_changed
        // cause + requires_recreate path emits both labels.
        let delta = plan::RunnerDelta {
            identity: fake_identity("buckos"),
            after: fake_runner_plan("buckos"),
            requires_recreate: true,
            recreate_reasons: vec!["url", "runner_version"],
            drift_cause: plan::DriftCause::SpecChanged,
            field_changes: Vec::new(),
            drop_in_changes: Vec::new(),
            before_caches: None,
            before_drop_in_basenames: None,
        };
        let line = render_action_line(
            &Action::UpdateRunner(delta),
            ColorMode { enabled: false },
            false,
        );
        assert!(line.contains("spec_changed"), "got: {line}");
        assert!(line.contains("update: recreate"), "got: {line}");
        assert!(line.contains("url,runner_version"), "got: {line}");
    }

    /// #462: recreate-class UpdateRunner must use the `!` sigil.
    /// In-place UpdateRunner keeps `~`. Both header lines still
    /// terminate with the `[recreate]`/`[restart]` bracket tag from
    /// #285, but the column-0 sigil is the fast-scan signal that
    /// distinguishes destructive (token re-mint + GitHub
    /// reregistration + unit teardown) from in-place (drop-in
    /// rewrite + restart) updates.
    #[test]
    fn render_action_line_update_runner_sigil_distinguishes_recreate_from_inplace() {
        // Recreate-class: `!` sigil + `[recreate]` tag.
        let recreate_delta = plan::RunnerDelta {
            identity: fake_identity("buckos"),
            after: fake_runner_plan("buckos"),
            requires_recreate: true,
            recreate_reasons: vec!["url"],
            drift_cause: plan::DriftCause::SpecChanged,
            field_changes: Vec::new(),
            drop_in_changes: Vec::new(),
            before_caches: None,
            before_drop_in_basenames: None,
        };
        let recreate_line = render_action_line(
            &Action::UpdateRunner(recreate_delta),
            ColorMode { enabled: false },
            false,
        );
        assert!(
            recreate_line.starts_with("! "),
            "recreate-class UpdateRunner must use `!` sigil; got: {recreate_line}",
        );
        assert!(
            recreate_line.contains("[recreate]"),
            "recreate-class UpdateRunner must still emit [recreate] tag; got: {recreate_line}",
        );
        // In-place: `~` sigil + `[restart]` tag (existing behavior).
        let inplace_delta = plan::RunnerDelta {
            identity: fake_identity("buckos"),
            after: fake_runner_plan("buckos"),
            requires_recreate: false,
            recreate_reasons: vec![],
            drift_cause: plan::DriftCause::SpecChanged,
            field_changes: Vec::new(),
            drop_in_changes: Vec::new(),
            before_caches: None,
            before_drop_in_basenames: None,
        };
        let inplace_line = render_action_line(
            &Action::UpdateRunner(inplace_delta),
            ColorMode { enabled: false },
            false,
        );
        assert!(
            inplace_line.starts_with("~ "),
            "in-place UpdateRunner must use `~` sigil; got: {inplace_line}",
        );
        assert!(
            inplace_line.contains("[restart]"),
            "in-place UpdateRunner must emit [restart] tag; got: {inplace_line}",
        );
        // Negative pin: in-place line must NOT have `!` at column 0.
        assert!(
            !inplace_line.starts_with("! "),
            "in-place UpdateRunner must NOT use `!` sigil; got: {inplace_line}",
        );
    }

    #[test]
    fn render_action_line_update_runner_both_cause() {
        // #260: hash changed AND drift detected → combined label.
        let delta = plan::RunnerDelta {
            identity: fake_identity("buckos"),
            after: fake_runner_plan("buckos"),
            requires_recreate: false,
            recreate_reasons: vec![],
            drift_cause: plan::DriftCause::SpecChangedAndDriftDetected,
            field_changes: Vec::new(),
            drop_in_changes: Vec::new(),
            before_caches: None,
            before_drop_in_basenames: None,
        };
        let line = render_action_line(
            &Action::UpdateRunner(delta),
            ColorMode { enabled: false },
            false,
        );
        assert!(
            line.contains("spec_changed_and_drift_detected"),
            "got: {line}"
        );
    }

    #[test]
    fn render_action_line_remove_runner_and_color() {
        let action = Action::RemoveRunner(fake_identity("legacy"));
        let plain = render_action_line(&action, ColorMode { enabled: false }, false);
        assert!(plain.starts_with("- "));
        assert!(plain.contains("runner legacy"));
        assert!(plain.contains("remove"));
        let colored = render_action_line(&action, ColorMode { enabled: true }, false);
        assert!(colored.contains("\x1b[31m"), "expected red ANSI prefix");
    }

    #[test]
    fn render_action_line_create_cache_pool() {
        let action = Action::CreateCachePool(plan::CachePoolPlan {
            binding: fake_cache_binding("build"),
            drop_in_body: String::new(),
            spec_hash: "sha256:0".into(),
        });
        let plain = render_action_line(&action, ColorMode { enabled: false }, false);
        assert!(plain.starts_with("+ "));
        assert!(plain.contains("cache_pool build"));
    }

    #[test]
    fn render_action_line_update_cache_pool() {
        let action = Action::UpdateCachePool(plan::CachePoolDelta {
            binding: fake_cache_binding("build"),
            drop_in_body: String::new(),
            spec_hash: "sha256:0".into(),
        });
        let plain = render_action_line(&action, ColorMode { enabled: false }, false);
        assert!(plain.starts_with("~ "));
        assert!(plain.contains("cache_pool build"));
        assert!(plain.contains("update"));
    }

    #[test]
    fn render_action_line_remove_cache_pool() {
        let action = Action::RemoveCachePool("build".into());
        let plain = render_action_line(&action, ColorMode { enabled: false }, false);
        assert!(plain.starts_with("- "));
        assert!(plain.contains("build"));
    }

    #[test]
    fn render_action_line_noop_no_ansi_even_when_color_enabled() {
        let action = Action::NoOp("buckos: in sync".into());
        let plain = render_action_line(&action, ColorMode { enabled: true }, false);
        // NoOp has no ansi color in the variant table, so even with
        // color on the output stays plain.
        assert!(plain.starts_with("  "), "got: {plain}");
        assert!(plain.contains("noop"));
        assert!(plain.contains("in sync"));
        assert!(
            !plain.contains("\x1b["),
            "noop must not be colored: {plain}"
        );
    }

    // ---------- #285: Action::disruption() per variant -------------

    #[test]
    fn disruption_create_runner_is_recreate() {
        // CreateRunner mints a registration token + runs config.sh
        // — the most disruptive class.
        let a = Action::CreateRunner(fake_runner_plan("buckos"));
        assert_eq!(a.disruption(), plan::Disruption::Recreate);
        assert_eq!(a.disruption().label(), "recreate");
    }

    #[test]
    fn disruption_update_runner_recreate_branch_is_recreate() {
        // requires_recreate=true routes through execute_remove +
        // execute_create — both touch the GitHub registration API.
        let delta = plan::RunnerDelta {
            identity: fake_identity("buckos"),
            after: fake_runner_plan("buckos"),
            requires_recreate: true,
            recreate_reasons: vec!["url"],
            drift_cause: plan::DriftCause::SpecChanged,
            field_changes: Vec::new(),
            drop_in_changes: Vec::new(),
            before_caches: None,
            before_drop_in_basenames: None,
        };
        let a = Action::UpdateRunner(delta);
        assert_eq!(a.disruption(), plan::Disruption::Recreate);
    }

    #[test]
    fn disruption_update_runner_inplace_branch_is_restart() {
        // requires_recreate=false stays in execute_update_runner's
        // in-place path: at worst, daemon-reload + stop + start.
        // Plan-time worst-case (apply-time None short-circuit per
        // #337 is byte-equality-driven and not plan-visible).
        let delta = plan::RunnerDelta {
            identity: fake_identity("buckos"),
            after: fake_runner_plan("buckos"),
            requires_recreate: false,
            recreate_reasons: vec![],
            drift_cause: plan::DriftCause::SpecChanged,
            field_changes: Vec::new(),
            drop_in_changes: Vec::new(),
            before_caches: None,
            before_drop_in_basenames: None,
        };
        let a = Action::UpdateRunner(delta);
        assert_eq!(a.disruption(), plan::Disruption::Restart);
        assert_eq!(a.disruption().label(), "restart");
    }

    #[test]
    fn disruption_remove_runner_is_recreate() {
        // RemoveRunner mints a removal token and calls the GitHub
        // deregister endpoint before tearing down the unit.
        let a = Action::RemoveRunner(fake_identity("legacy"));
        assert_eq!(a.disruption(), plan::Disruption::Recreate);
    }

    #[test]
    fn disruption_create_cache_pool_is_recreate() {
        // execute_create_cache_pool provisions per-pool group +
        // storage dir + unit drop-in — host-state construction
        // symmetric with RemoveCachePool's destruction path.
        let a = Action::CreateCachePool(plan::CachePoolPlan {
            binding: fake_cache_binding("build"),
            drop_in_body: String::new(),
            spec_hash: "sha256:0".into(),
        });
        assert_eq!(a.disruption(), plan::Disruption::Recreate);
    }

    #[test]
    fn disruption_update_cache_pool_is_restart() {
        // execute_update_cache_pool rewrites drop-in + daemon-reload
        // + stop + start; group + storage identity preserved.
        let a = Action::UpdateCachePool(plan::CachePoolDelta {
            binding: fake_cache_binding("build"),
            drop_in_body: String::new(),
            spec_hash: "sha256:0".into(),
        });
        assert_eq!(a.disruption(), plan::Disruption::Restart);
    }

    #[test]
    fn disruption_remove_cache_pool_is_recreate() {
        // execute_remove_cache_pool deletes the per-pool group,
        // storage dir, drop-ins — host-state destruction.
        let a = Action::RemoveCachePool("build".into());
        assert_eq!(a.disruption(), plan::Disruption::Recreate);
    }

    #[test]
    fn disruption_noop_is_none() {
        let a = Action::NoOp("buckos: in sync".into());
        assert_eq!(a.disruption(), plan::Disruption::None);
        assert_eq!(a.disruption().label(), "none");
    }

    #[test]
    fn disruption_labels_are_snake_case_stable() {
        // CLN-6/ADV-2: pin the JSON / text-mode label vocabulary
        // so a future refactor that touches Disruption::label()
        // cannot silently rename the tokens CI consumers grep on.
        assert_eq!(plan::Disruption::None.label(), "none");
        assert_eq!(plan::Disruption::Restart.label(), "restart");
        assert_eq!(plan::Disruption::Recreate.label(), "recreate");
    }

    #[test]
    fn disruption_ordering_is_least_to_most() {
        // CLN-6/ADV-2: pin the derived PartialOrd/Ord ordering so
        // callers can guard with `disruption >= Recreate` without
        // reading the enum's variant declaration order. Variant
        // declaration order IS the source of truth here, so the
        // test fails loudly if anyone reorders without updating
        // the contract.
        assert!(plan::Disruption::None < plan::Disruption::Restart);
        assert!(plan::Disruption::Restart < plan::Disruption::Recreate);
        assert!(plan::Disruption::None < plan::Disruption::Recreate);
    }

    #[test]
    fn render_plan_summary_line_uses_disruption_label_not_hardcoded() {
        // PHD #285 / #471: pin that every label token in the text
        // footer comes from `Disruption::label()`, not from a
        // hardcoded string literal in the format string. If a
        // future refactor inlines the label strings (regressing
        // the CLN-2 / #471 fix), the substring assertions below
        // continue to pass — but the source-of-truth check at
        // the bottom (substring built from `label()` calls)
        // would still match. The load-bearing guarantee is the
        // exact match against the synthesized expected string,
        // which fails the moment the labels drift between
        // `Disruption::label()` and the format string.
        let actions = vec![
            Action::NoOp("a: in sync".into()),
            Action::CreateRunner(fake_runner_plan("c")),
            Action::UpdateRunner(plan::RunnerDelta {
                identity: fake_identity("u"),
                after: fake_runner_plan("u"),
                requires_recreate: false,
                recreate_reasons: vec![],
                drift_cause: plan::DriftCause::SpecChanged,
                field_changes: Vec::new(),
                drop_in_changes: Vec::new(),
                before_caches: None,
                before_drop_in_basenames: None,
            }),
        ];
        let line = render_plan_summary_line(&actions);
        let expected = format!(
            "Plan: 3 actions (1 {restart}, 1 {recreate}, 1 {none}). \
             any_recreate: true",
            restart = plan::Disruption::Restart.label(),
            recreate = plan::Disruption::Recreate.label(),
            none = plan::Disruption::None.label(),
        );
        assert_eq!(line, expected);
    }

    // ---------- #476: render_apply_summary_line ---------------------

    /// #476: empty result emits zeroed footer with `any_recreate: false`.
    /// Pins the contract that the footer is always emitted (even when
    /// the plan was empty / dry-run-noop), preserving the
    /// "always-present footer" invariant operators rely on for
    /// scripted parsing.
    #[test]
    fn render_apply_summary_line_empty_result() {
        let result = apply::ApplyResult::default();
        let line = render_apply_summary_line(&result);
        let expected = format!(
            "Apply: 0 applied, 0 failed, 0 skipped \
             (0 {restart}, 0 {recreate}, 0 {none}). \
             any_recreate: false",
            restart = plan::Disruption::Restart.label(),
            recreate = plan::Disruption::Recreate.label(),
            none = plan::Disruption::None.label(),
        );
        assert_eq!(line, expected);
    }

    /// #476: every outcome class lands in the right bucket.
    /// `applied` covers Created/Removed/Recreated/InPlaceRestarted/
    /// PoolCreated/PoolUpdated/PoolRemoved; `skipped` covers NoOp,
    /// DryRunSkipped, InPlaceSkipped, PoolSkipped; `failed` covers
    /// ApplyOutcome::Failed. The disruption parenthetical mirrors
    /// each outcome's `disruption()` mapping (verified against
    /// apply.rs:295-308).
    #[test]
    fn render_apply_summary_line_buckets_every_variant_correctly() {
        // 3 applied: Created (Recreate), InPlaceRestarted (Restart),
        //            PoolUpdated (Restart)
        // 2 skipped: NoOp (None), InPlaceSkipped (None)
        // 1 failed:  Failed{plan_disruption=Recreate} (Recreate)
        // → applied=3, failed=1, skipped=2
        // → restart=2, recreate=2, none=2 (NoOp+InPlaceSkipped)
        // → any_recreate=true (Created + Failed both Recreate)
        let result = apply::ApplyResult {
            details: vec![
                ("CreateRunner(a)".into(), apply::ApplyOutcome::Created),
                (
                    "UpdateRunner(b)".into(),
                    apply::ApplyOutcome::InPlaceRestarted {
                        files_changed: 1,
                        pools_added: Vec::new(),
                        pools_removed: Vec::new(),
                    },
                ),
                (
                    "UpdateCachePool(c)".into(),
                    apply::ApplyOutcome::PoolUpdated,
                ),
                ("NoOp(x: in sync)".into(), apply::ApplyOutcome::NoOp),
                (
                    "UpdateRunner(y)".into(),
                    apply::ApplyOutcome::InPlaceSkipped,
                ),
                (
                    "RemoveRunner(z)".into(),
                    apply::ApplyOutcome::Failed {
                        error_summary: "systemd: stop failed".into(),
                        plan_disruption: plan::Disruption::Recreate,
                    },
                ),
            ],
            ..apply::ApplyResult::default()
        };
        let line = render_apply_summary_line(&result);
        let expected = format!(
            "Apply: 3 applied, 1 failed, 2 skipped \
             (2 {restart}, 2 {recreate}, 2 {none}). \
             any_recreate: true",
            restart = plan::Disruption::Restart.label(),
            recreate = plan::Disruption::Recreate.label(),
            none = plan::Disruption::None.label(),
        );
        assert_eq!(line, expected);
    }

    /// #476: `any_recreate` is true when ANY row's disruption is
    /// Recreate, including a Failed row carrying
    /// `plan_disruption=Recreate`. A partially-applied recreate-class
    /// action that errored mid-way still flips the gate, matching the
    /// plan-footer's blast-radius semantics.
    #[test]
    fn render_apply_summary_line_failed_recreate_flips_any_recreate() {
        let result = apply::ApplyResult {
            details: vec![(
                "CreateRunner(a)".into(),
                apply::ApplyOutcome::Failed {
                    error_summary: "github: 401".into(),
                    plan_disruption: plan::Disruption::Recreate,
                },
            )],
            ..apply::ApplyResult::default()
        };
        let line = render_apply_summary_line(&result);
        assert!(
            line.contains("any_recreate: true"),
            "failed Recreate row must flip any_recreate: {line}",
        );
        assert!(line.contains("0 applied"), "got: {line}");
        assert!(line.contains("1 failed"), "got: {line}");
        assert!(line.contains("0 skipped"), "got: {line}");
        assert!(
            line.contains(&format!(
                "1 {recreate}",
                recreate = plan::Disruption::Recreate.label(),
            )),
            "failed Recreate must contribute to recreate count: {line}",
        );
    }

    /// #478 / #618: empty result (no failures) ⇒ no advisory rendered.
    /// Pins that successful applies emit zero stderr advisory noise.
    /// The gate counts non-empty step lists in `failed_undo_logs`;
    /// a default `ApplyResult` (empty `failed_undo_logs`) yields
    /// `n == 0`, returning `None`.
    #[test]
    fn render_rollback_advisory_returns_none_on_success() {
        let result = apply::ApplyResult::default();
        assert!(render_rollback_advisory(&result).is_none());
    }

    /// #478 / #618: header + per-action body + per-step bullet list.
    /// Pins the exact rendering format so operators with downstream
    /// parsers see a stable contract. Header counts entries in
    /// `failed_undo_logs` with non-empty steps (#618).
    #[test]
    fn render_rollback_advisory_renders_per_action_steps() {
        let mut result = apply::ApplyResult::default();
        result.failed.push((
            "CreateCachePool(build)".into(),
            crate::error::GharsError::Apply {
                action: "CreateCachePool(build)".into(),
                source: Box::new(crate::error::GharsError::Systemd(
                    "mock enable failure".into(),
                    "test".into(),
                )),
            },
        ));
        result.failed_undo_logs.push((
            "CreateCachePool(build)".into(),
            vec![
                apply::UndoStep::CreateDir {
                    path: camino::Utf8PathBuf::from(
                        "/etc/systemd/system/ghars-cache@build.service.d",
                    ),
                },
                apply::UndoStep::WriteFile {
                    path: camino::Utf8PathBuf::from(
                        "/etc/systemd/system/ghars-cache@build.service.d/00-ghars.conf",
                    ),
                    prior_content: None,
                },
                apply::UndoStep::GroupAdd {
                    name: "ghars-cache-build".into(),
                },
            ],
        ));
        let advisory = render_rollback_advisory(&result).unwrap();
        // Header: count of failed actions with cleanup steps,
        // "Manual cleanup may be required:" (#618).
        assert!(
            advisory.starts_with("Rollback advisory: 1 action(s) failed."),
            "advisory must lead with failed-count header; got: {advisory}",
        );
        assert!(
            advisory.contains("Manual cleanup may be required:"),
            "advisory must include cleanup-required clause; got: {advisory}",
        );
        // Per-action label as a sub-block header, indented 2 spaces
        // (matches operator's expected nested rendering).
        assert!(
            advisory.contains("\n  CreateCachePool(build):"),
            "advisory must include per-action label; got: {advisory}",
        );
        // Per-step bullet, indented 4 spaces, past-tense via describe().
        assert!(
            advisory.contains(
                "\n    - created directory /etc/systemd/system/ghars-cache@build.service.d"
            ),
            "advisory must include CreateDir step via describe(); got: {advisory}",
        );
        assert!(
            advisory.contains(
                "\n    - wrote /etc/systemd/system/ghars-cache@build.service.d/00-ghars.conf"
            ),
            "advisory must include WriteFile step; got: {advisory}",
        );
        assert!(
            advisory.contains("\n    - created group ghars-cache-build"),
            "advisory must include GroupAdd step; got: {advisory}",
        );
    }

    /// #478 / #551 / #618: the synthetic `daemon_reload` post-loop
    /// failure has an empty UndoLog (no per-action mutation manifest).
    /// The advisory renderer skips per-action blocks whose step list
    /// is empty AND counts ONLY non-empty entries in the header N
    /// (#618), so header count matches body block count under the
    /// MIXED case (empty + non-empty side by side). The ISOLATED
    /// all-empty case is pinned by
    /// `render_rollback_advisory_daemon_reload_only_failure_returns_none`
    /// per #551 (returns `None` instead of header-only output).
    #[test]
    fn render_rollback_advisory_skips_empty_step_lists() {
        // Mixed: one daemon_reload (empty) + one real failure with steps.
        let mut result = apply::ApplyResult::default();
        result.failed.push((
            "daemon_reload".into(),
            crate::error::GharsError::Apply {
                action: "daemon_reload".into(),
                source: Box::new(crate::error::GharsError::Systemd(
                    "post-loop reload".into(),
                    "test".into(),
                )),
            },
        ));
        result.failed.push((
            "RemoveRunner(orphan)".into(),
            crate::error::GharsError::Apply {
                action: "RemoveRunner(orphan)".into(),
                source: Box::new(crate::error::GharsError::Systemd(
                    "stop failed".into(),
                    "test".into(),
                )),
            },
        ));
        result
            .failed_undo_logs
            .push(("daemon_reload".into(), Vec::new()));
        result.failed_undo_logs.push((
            "RemoveRunner(orphan)".into(),
            vec![apply::UndoStep::StopUnit {
                name: "ghars-runner@orphan.service".into(),
            }],
        ));
        let advisory = render_rollback_advisory(&result).unwrap();
        // #618: header counts ONLY non-empty entries (1 here: the
        // RemoveRunner(orphan) failure). The empty-step daemon_reload
        // failure surfaces via the per-action `fail:` line in the
        // cmd_apply detail loop, not via the advisory header.
        assert!(
            advisory.starts_with("Rollback advisory: 1 action(s) failed."),
            "header must count only non-empty-step entries; got: {advisory}",
        );
        // daemon_reload's empty-step entry must NOT appear as a
        // per-action block (no `\n  daemon_reload:` line).
        assert!(
            !advisory.contains("\n  daemon_reload:"),
            "empty-step entry must NOT render a per-action block; got: {advisory}",
        );
        // RemoveRunner(orphan)'s non-empty entry MUST render.
        assert!(
            advisory.contains("\n  RemoveRunner(orphan):"),
            "non-empty entry must render its block; got: {advisory}",
        );
        assert!(
            advisory.contains("\n    - stopped ghars-runner@orphan.service"),
            "non-empty entry's step must render via describe(); got: {advisory}",
        );
    }

    /// #476: only-skipped path (dry-run). Every action skipped via
    /// `DryRunSkipped`; applied=0, failed=0, skipped=N, all in `none`
    /// disruption bucket.
    #[test]
    fn render_apply_summary_line_only_dry_run_skipped() {
        let result = apply::ApplyResult {
            details: vec![
                ("CreateRunner(a)".into(), apply::ApplyOutcome::DryRunSkipped),
                (
                    "UpdateCachePool(b)".into(),
                    apply::ApplyOutcome::DryRunSkipped,
                ),
            ],
            ..apply::ApplyResult::default()
        };
        let line = render_apply_summary_line(&result);
        let expected = format!(
            "Apply: 0 applied, 0 failed, 2 skipped \
             (0 {restart}, 0 {recreate}, 2 {none}). \
             any_recreate: false",
            restart = plan::Disruption::Restart.label(),
            recreate = plan::Disruption::Recreate.label(),
            none = plan::Disruption::None.label(),
        );
        assert_eq!(line, expected);
    }

    // ---------- #285: disruption tag in render_action_line --------

    #[test]
    fn render_action_line_appends_recreate_tag_for_create() {
        let a = Action::CreateRunner(fake_runner_plan("buckos"));
        let line = render_action_line(&a, ColorMode { enabled: false }, false);
        assert!(
            line.contains("[recreate]"),
            "create runner header missing disruption tag: {line}"
        );
    }

    #[test]
    fn render_action_line_appends_restart_tag_for_inplace_update() {
        let delta = plan::RunnerDelta {
            identity: fake_identity("buckos"),
            after: fake_runner_plan("buckos"),
            requires_recreate: false,
            recreate_reasons: vec![],
            drift_cause: plan::DriftCause::DriftDetected,
            field_changes: Vec::new(),
            drop_in_changes: Vec::new(),
            before_caches: None,
            before_drop_in_basenames: None,
        };
        let line = render_action_line(
            &Action::UpdateRunner(delta),
            ColorMode { enabled: false },
            false,
        );
        assert!(
            line.contains("[restart]"),
            "in-place update header missing disruption tag: {line}"
        );
    }

    #[test]
    fn render_action_line_appends_none_tag_for_noop() {
        let line = render_action_line(
            &Action::NoOp("foo: in sync".into()),
            ColorMode { enabled: false },
            false,
        );
        assert!(
            line.contains("[none]"),
            "noop header missing disruption tag: {line}"
        );
    }

    #[test]
    fn render_action_line_appends_restart_tag_for_update_cache_pool() {
        // UpdateCachePool stays Restart even with the new mapping.
        let a = Action::UpdateCachePool(plan::CachePoolDelta {
            binding: fake_cache_binding("build"),
            drop_in_body: String::new(),
            spec_hash: "sha256:0".into(),
        });
        let line = render_action_line(&a, ColorMode { enabled: false }, false);
        assert!(line.contains("[restart]"), "got: {line}");
    }

    #[test]
    fn render_action_line_appends_recreate_tag_for_create_cache_pool() {
        let a = Action::CreateCachePool(plan::CachePoolPlan {
            binding: fake_cache_binding("build"),
            drop_in_body: String::new(),
            spec_hash: "sha256:0".into(),
        });
        let line = render_action_line(&a, ColorMode { enabled: false }, false);
        assert!(line.contains("[recreate]"), "got: {line}");
    }

    #[test]
    fn render_action_line_color_path_keeps_disruption_tag_outside_ansi_block() {
        // The disruption tag must appear in the line regardless of
        // whether ANSI is enabled — grep-on-color pipelines that
        // strip ANSI still need to see it. Concretely: search for the
        // bracketed label as a substring; the test does NOT pin its
        // exact position to leave room for cosmetic shifts.
        let a = Action::CreateRunner(fake_runner_plan("buckos"));
        let line = render_action_line(&a, ColorMode { enabled: true }, false);
        assert!(line.contains("[recreate]"), "got: {line}");
        assert!(line.contains("\x1b[32m"), "expected color in line: {line}");
    }

    // ---------- #285: --diff body payload (text) ------------------

    #[test]
    fn render_action_line_diff_modified_emits_unified_diff() {
        // Per coordinator ruling, Modified is always a unified diff
        // (no separate "full" mode for both bodies).
        let delta = plan::RunnerDelta {
            identity: fake_identity("buckos"),
            after: fake_runner_plan("buckos"),
            requires_recreate: false,
            recreate_reasons: vec![],
            drift_cause: plan::DriftCause::SpecChanged,
            field_changes: Vec::new(),
            drop_in_changes: vec![plan::DropInChange {
                basename: "10-memory.conf".into(),
                change: plan::DropInChangeKind::Modified {
                    before: "[Service]\nMemoryMax=1G\n".into(),
                    after: "[Service]\nMemoryMax=2G\n".into(),
                },
            }],
            before_caches: None,
            before_drop_in_basenames: None,
        };
        let line = render_action_line(
            &Action::UpdateRunner(delta),
            ColorMode { enabled: false },
            true,
        );
        // Brief sigil-basename line still appears.
        assert!(line.contains("    ~ 10-memory.conf"), "got: {line}");
        // similar::unified_diff emits @@ hunk headers and -/+ lines.
        assert!(line.contains("@@"), "expected unified diff hunk: {line}");
        assert!(line.contains("-MemoryMax=1G"), "got: {line}");
        assert!(line.contains("+MemoryMax=2G"), "got: {line}");
        // No `before:`/`after:` block — Modified uses unified diff
        // exclusively under --diff.
        assert!(!line.contains("        before:"), "got: {line}");
        assert!(
            !line.contains("        after:\n            [Service]"),
            "got: {line}"
        );
    }

    #[test]
    fn render_action_line_diff_emits_after_only_for_created() {
        let delta = plan::RunnerDelta {
            identity: fake_identity("buckos"),
            after: fake_runner_plan("buckos"),
            requires_recreate: false,
            recreate_reasons: vec![],
            drift_cause: plan::DriftCause::SpecChanged,
            field_changes: Vec::new(),
            drop_in_changes: vec![plan::DropInChange {
                basename: "60-proxy.conf".into(),
                change: plan::DropInChangeKind::Created {
                    after: "Environment=HTTP_PROXY=http://p:8080\n".into(),
                },
            }],
            before_caches: None,
            before_drop_in_basenames: None,
        };
        let line = render_action_line(
            &Action::UpdateRunner(delta),
            ColorMode { enabled: false },
            true,
        );
        assert!(line.contains("    + 60-proxy.conf"), "got: {line}");
        // Created has only after (no before to diff).
        assert!(line.contains("        after:"), "got: {line}");
        assert!(!line.contains("        before:"), "got: {line}");
        assert!(
            line.contains("            Environment=HTTP_PROXY=http://p:8080"),
            "got: {line}",
        );
    }

    #[test]
    fn render_action_line_diff_emits_before_only_for_removed() {
        let delta = plan::RunnerDelta {
            identity: fake_identity("buckos"),
            after: fake_runner_plan("buckos"),
            requires_recreate: false,
            recreate_reasons: vec![],
            drift_cause: plan::DriftCause::SpecChanged,
            field_changes: Vec::new(),
            drop_in_changes: vec![plan::DropInChange {
                basename: "70-hooks.conf".into(),
                change: plan::DropInChangeKind::Removed {
                    before: "Environment=ACTIONS_RUNNER_HOOK_JOB_STARTED=/x\n".into(),
                },
            }],
            before_caches: None,
            before_drop_in_basenames: None,
        };
        let line = render_action_line(
            &Action::UpdateRunner(delta),
            ColorMode { enabled: false },
            true,
        );
        assert!(line.contains("    - 70-hooks.conf"), "got: {line}");
        assert!(line.contains("        before:"), "got: {line}");
        assert!(!line.contains("        after:"), "got: {line}");
    }

    #[test]
    fn render_action_line_diff_emits_unchanged_marker_for_preserved() {
        // Preserved is shown under --diff so operators can confirm
        // the no-edit verdict without parsing JSON. Sigil is space
        // (no edit class), payload is the literal `(unchanged)`
        // marker.
        let delta = plan::RunnerDelta {
            identity: fake_identity("buckos"),
            after: fake_runner_plan("buckos"),
            requires_recreate: false,
            recreate_reasons: vec![],
            drift_cause: plan::DriftCause::SpecChanged,
            field_changes: Vec::new(),
            drop_in_changes: vec![plan::DropInChange {
                basename: "15-resolv.conf".into(),
                change: plan::DropInChangeKind::Preserved,
            }],
            before_caches: None,
            before_drop_in_basenames: None,
        };
        let line = render_action_line(
            &Action::UpdateRunner(delta),
            ColorMode { enabled: false },
            true,
        );
        assert!(line.contains("      15-resolv.conf"), "got: {line}");
        assert!(line.contains("        (unchanged)"), "got: {line}");
    }

    #[test]
    fn render_action_line_no_diff_does_not_emit_body_blocks() {
        // Without --diff, brief shape is byte-preserved: header +
        // sigil-basename only, no `before:`/`after:` blocks, no
        // unified diff, Preserved suppressed entirely.
        let delta = plan::RunnerDelta {
            identity: fake_identity("buckos"),
            after: fake_runner_plan("buckos"),
            requires_recreate: false,
            recreate_reasons: vec![],
            drift_cause: plan::DriftCause::SpecChanged,
            field_changes: Vec::new(),
            drop_in_changes: vec![
                plan::DropInChange {
                    basename: "10-memory.conf".into(),
                    change: plan::DropInChangeKind::Modified {
                        before: "MemoryMax=1G\n".into(),
                        after: "MemoryMax=2G\n".into(),
                    },
                },
                plan::DropInChange {
                    basename: "15-resolv.conf".into(),
                    change: plan::DropInChangeKind::Preserved,
                },
            ],
            before_caches: None,
            before_drop_in_basenames: None,
        };
        let line = render_action_line(
            &Action::UpdateRunner(delta),
            ColorMode { enabled: false },
            false,
        );
        assert!(line.contains("    ~ 10-memory.conf"), "got: {line}");
        // No body content at all without --diff.
        assert!(!line.contains("        before:"), "got: {line}");
        assert!(!line.contains("        after:"), "got: {line}");
        assert!(!line.contains("MemoryMax="), "got: {line}");
        assert!(!line.contains("@@"), "got: {line}");
        // Preserved suppressed without --diff (matches pre-#285).
        assert!(!line.contains("15-resolv.conf"), "got: {line}");
        assert!(!line.contains("(unchanged)"), "got: {line}");
    }

    #[test]
    fn render_action_line_diff_recreate_renders_after_drop_ins_as_created() {
        // Recreate-class UpdateRunner has empty drop_in_changes by
        // design — under --diff, the CLI synthesizes Created entries
        // from delta.after.drop_ins so operators can see what the
        // post-recreate runner unit will look like.
        let mut after_plan = fake_runner_plan("buckos");
        after_plan.drop_ins.insert(
            "00-ghars.conf".into(),
            "[Unit]\nX-Ghars-Spec-Hash=sha256:abc\n".into(),
        );
        after_plan
            .drop_ins
            .insert("10-memory.conf".into(), "[Service]\nMemoryMax=4G\n".into());
        let delta = plan::RunnerDelta {
            identity: fake_identity("buckos"),
            after: after_plan,
            requires_recreate: true,
            recreate_reasons: vec!["runner_version"],
            drift_cause: plan::DriftCause::SpecChanged,
            field_changes: Vec::new(),
            drop_in_changes: Vec::new(), // recreate path leaves this empty
            before_caches: None,
            before_drop_in_basenames: None,
        };
        let line = render_action_line(
            &Action::UpdateRunner(delta),
            ColorMode { enabled: false },
            true,
        );
        assert!(line.contains("[recreate]"), "got: {line}");
        // Both drop-ins render as Created entries with bodies.
        assert!(line.contains("    + 00-ghars.conf"), "got: {line}");
        assert!(line.contains("    + 10-memory.conf"), "got: {line}");
        assert!(
            line.contains("            X-Ghars-Spec-Hash="),
            "got: {line}"
        );
        assert!(line.contains("            MemoryMax=4G"), "got: {line}");
    }

    #[test]
    fn render_action_line_no_diff_recreate_does_not_render_drop_ins() {
        // Without --diff, recreate output is unchanged from pre-#285
        // (no drop-in expansion at all — header only).
        let mut after_plan = fake_runner_plan("buckos");
        after_plan.drop_ins.insert(
            "00-ghars.conf".into(),
            "[Unit]\nX-Ghars-Spec-Hash=sha256:abc\n".into(),
        );
        let delta = plan::RunnerDelta {
            identity: fake_identity("buckos"),
            after: after_plan,
            requires_recreate: true,
            recreate_reasons: vec!["runner_version"],
            drift_cause: plan::DriftCause::SpecChanged,
            field_changes: Vec::new(),
            drop_in_changes: Vec::new(),
            before_caches: None,
            before_drop_in_basenames: None,
        };
        let line = render_action_line(
            &Action::UpdateRunner(delta),
            ColorMode { enabled: false },
            false,
        );
        assert!(line.contains("[recreate]"), "got: {line}");
        // No drop-in lines without --diff.
        assert!(!line.contains("00-ghars.conf"), "got: {line}");
        assert!(!line.contains("X-Ghars-Spec-Hash"), "got: {line}");
    }

    // ---- #468: recreate `--diff` shows removed drop-ins -----------------

    /// T1: recreate `--diff` with `before_drop_in_basenames` containing
    /// a name NOT in `after.drop_ins` → emits `- {basename}` line.
    /// `99-custom.conf` is the canonical operator drop-in: it's in the
    /// pre-recreate set but not in the post-recreate `after.drop_ins`,
    /// so the recreate is about to delete it. Pin: the basename is
    /// surfaced as Removed (with no body block — basename-only).
    #[test]
    fn render_action_line_diff_recreate_emits_removed_for_dropped_basename() {
        let mut after_plan = fake_runner_plan("buckos");
        after_plan.drop_ins.insert(
            "00-ghars.conf".into(),
            "[Unit]\nX-Ghars-Spec-Hash=sha256:abc\n".into(),
        );
        let delta = plan::RunnerDelta {
            identity: fake_identity("buckos"),
            after: after_plan,
            requires_recreate: true,
            recreate_reasons: vec!["runner_version"],
            drift_cause: plan::DriftCause::SpecChanged,
            field_changes: Vec::new(),
            drop_in_changes: Vec::new(),
            before_caches: None,
            before_drop_in_basenames: Some(vec!["00-ghars.conf".into(), "99-custom.conf".into()]),
        };
        let line = render_action_line(
            &Action::UpdateRunner(delta),
            ColorMode { enabled: false },
            true,
        );
        // Created entry for 00-ghars.conf (kept across recreate) renders
        // first in the visual order: "what's coming in" before "what's
        // leaving". Pin both ordering and presence.
        let created_idx = line
            .find("    + 00-ghars.conf")
            .expect("Created line missing");
        let removed_idx = line
            .find("    - 99-custom.conf")
            .expect("Removed line missing for 99-custom.conf");
        assert!(
            created_idx < removed_idx,
            "Created must precede Removed in recreate --diff output, got: {line}"
        );
        // Operator's 99-custom.conf is basename-only — no body block.
        // We never carried its body in `before_drop_in_basenames`, so
        // there's nothing for the renderer to print as a body block.
        // Defense-in-depth: `99-custom.conf` should appear exactly once
        // in the output (not in a body block).
        assert_eq!(
            line.matches("99-custom.conf").count(),
            1,
            "99-custom.conf should appear exactly once (basename-only), got: {line}"
        );
    }

    /// T2: recreate `--diff` with `before_drop_in_basenames = None`
    /// → no Removed lines. Pin the regression contract: when discovered
    /// state is unavailable (test fixtures or any other construction
    /// site without a `DiscoveredRunner`), the renderer suppresses the
    /// Removed section entirely rather than risk a misleading silence.
    #[test]
    fn render_action_line_diff_recreate_none_basenames_emits_no_removed() {
        let mut after_plan = fake_runner_plan("buckos");
        after_plan.drop_ins.insert(
            "00-ghars.conf".into(),
            "[Unit]\nX-Ghars-Spec-Hash=sha256:abc\n".into(),
        );
        let delta = plan::RunnerDelta {
            identity: fake_identity("buckos"),
            after: after_plan,
            requires_recreate: true,
            recreate_reasons: vec!["runner_version"],
            drift_cause: plan::DriftCause::SpecChanged,
            field_changes: Vec::new(),
            drop_in_changes: Vec::new(),
            before_caches: None,
            before_drop_in_basenames: None,
        };
        let line = render_action_line(
            &Action::UpdateRunner(delta),
            ColorMode { enabled: false },
            true,
        );
        // Created lines still render (existing #285 behavior).
        assert!(line.contains("    + 00-ghars.conf"), "got: {line}");
        // No Removed lines — `None` is "unknown pre-state", suppressed.
        assert!(
            !line.contains("    - "),
            "no Removed sigil expected when before_drop_in_basenames is None, got: {line}"
        );
    }

    /// #563 COV-1: recreate `--diff` with multiple removed basenames
    /// preserves insertion order in the rendered output. Operators
    /// reading the diff scan top-to-bottom — order drift would
    /// disrupt visual review. Pin: input Vec
    /// `[99-zlast.conf, 99-acustom.conf, 99-mtuning.conf]` produces
    /// the same Vec insertion order in the output, NOT a sorted
    /// view.
    #[test]
    fn render_action_line_diff_recreate_multi_removed_preserves_vec_order() {
        let mut after_plan = fake_runner_plan("buckos");
        after_plan.drop_ins.insert(
            "00-ghars.conf".into(),
            "[Unit]\nX-Ghars-Spec-Hash=sha256:abc\n".into(),
        );
        let delta = plan::RunnerDelta {
            identity: fake_identity("buckos"),
            after: after_plan,
            requires_recreate: true,
            recreate_reasons: vec!["runner_version"],
            drift_cause: plan::DriftCause::SpecChanged,
            field_changes: Vec::new(),
            drop_in_changes: Vec::new(),
            before_caches: None,
            // Insertion order deliberately differs from alphabetical
            // — if the renderer accidentally sorts, the assertion
            // below breaks.
            before_drop_in_basenames: Some(vec![
                "99-zlast.conf".into(),
                "99-acustom.conf".into(),
                "99-mtuning.conf".into(),
            ]),
        };
        let line = render_action_line(
            &Action::UpdateRunner(delta),
            ColorMode { enabled: false },
            true,
        );
        let z_idx = line.find("    - 99-zlast.conf").expect("zlast missing");
        let a_idx = line.find("    - 99-acustom.conf").expect("acustom missing");
        let m_idx = line.find("    - 99-mtuning.conf").expect("mtuning missing");
        assert!(
            z_idx < a_idx && a_idx < m_idx,
            "Removed entries must preserve before_drop_in_basenames Vec insertion order, got: {line}",
        );
    }

    /// #563 COV-2: recreate `--diff` with `before_drop_in_basenames =
    /// Some(vec![])` (discovered drop-in directory was present but
    /// empty / fully reused) renders no Removed lines. Distinct
    /// from the `None` case (T2): `Some(empty)` is "known empty",
    /// `None` is "unknown". Pin both produce the same operator-
    /// visible output (no Removed lines) but via different code
    /// paths.
    #[test]
    fn render_action_line_diff_recreate_empty_vec_emits_no_removed() {
        let mut after_plan = fake_runner_plan("buckos");
        after_plan.drop_ins.insert(
            "00-ghars.conf".into(),
            "[Unit]\nX-Ghars-Spec-Hash=sha256:abc\n".into(),
        );
        let delta = plan::RunnerDelta {
            identity: fake_identity("buckos"),
            after: after_plan,
            requires_recreate: true,
            recreate_reasons: vec!["runner_version"],
            drift_cause: plan::DriftCause::SpecChanged,
            field_changes: Vec::new(),
            drop_in_changes: Vec::new(),
            before_caches: None,
            before_drop_in_basenames: Some(Vec::new()),
        };
        let line = render_action_line(
            &Action::UpdateRunner(delta),
            ColorMode { enabled: false },
            true,
        );
        assert!(
            !line.contains("    - "),
            "empty before_drop_in_basenames Vec must emit no Removed lines, got: {line}",
        );
    }

    /// T3: recreate `--diff` with `before_drop_in_basenames` ⊆
    /// `after.drop_ins` (every pre-recreate drop-in is preserved
    /// post-recreate) → no Removed lines emitted. Pin that the filter
    /// (`!d.after.drop_ins.contains_key`) excludes basenames present
    /// on both sides.
    #[test]
    fn render_action_line_diff_recreate_subset_emits_no_removed() {
        let mut after_plan = fake_runner_plan("buckos");
        after_plan.drop_ins.insert(
            "00-ghars.conf".into(),
            "[Unit]\nX-Ghars-Spec-Hash=sha256:abc\n".into(),
        );
        after_plan
            .drop_ins
            .insert("10-memory.conf".into(), "[Service]\nMemoryMax=4G\n".into());
        let delta = plan::RunnerDelta {
            identity: fake_identity("buckos"),
            after: after_plan,
            requires_recreate: true,
            recreate_reasons: vec!["runner_version"],
            drift_cause: plan::DriftCause::SpecChanged,
            field_changes: Vec::new(),
            drop_in_changes: Vec::new(),
            before_caches: None,
            // before set ⊆ after set — both are kept.
            before_drop_in_basenames: Some(vec!["00-ghars.conf".into(), "10-memory.conf".into()]),
        };
        let line = render_action_line(
            &Action::UpdateRunner(delta),
            ColorMode { enabled: false },
            true,
        );
        // Both Created lines present.
        assert!(line.contains("    + 00-ghars.conf"), "got: {line}");
        assert!(line.contains("    + 10-memory.conf"), "got: {line}");
        // No Removed lines — every before-basename is also in after.
        assert!(
            !line.contains("    - "),
            "no Removed sigil expected when before ⊆ after, got: {line}"
        );
    }

    /// T4: recreate WITHOUT `--diff` (brief view) + populated
    /// `before_drop_in_basenames` → no Removed lines emitted. Pin
    /// that the brief view stays unchanged regardless of the new
    /// field — the Removed loop is gated on `diff && requires_recreate`.
    #[test]
    fn render_action_line_no_diff_recreate_with_basenames_emits_no_removed() {
        let mut after_plan = fake_runner_plan("buckos");
        after_plan.drop_ins.insert(
            "00-ghars.conf".into(),
            "[Unit]\nX-Ghars-Spec-Hash=sha256:abc\n".into(),
        );
        let delta = plan::RunnerDelta {
            identity: fake_identity("buckos"),
            after: after_plan,
            requires_recreate: true,
            recreate_reasons: vec!["runner_version"],
            drift_cause: plan::DriftCause::SpecChanged,
            field_changes: Vec::new(),
            drop_in_changes: Vec::new(),
            before_caches: None,
            before_drop_in_basenames: Some(vec!["00-ghars.conf".into(), "99-custom.conf".into()]),
        };
        let line = render_action_line(
            &Action::UpdateRunner(delta),
            ColorMode { enabled: false },
            false,
        );
        assert!(line.contains("[recreate]"), "got: {line}");
        // Brief view: no drop-in lines at all.
        assert!(!line.contains("99-custom.conf"), "got: {line}");
        assert!(!line.contains("00-ghars.conf"), "got: {line}");
        assert!(!line.contains("    - "), "got: {line}");
    }

    /// T5: `plan_to_json_value` recreate path emits
    /// `{"basename": "...", "change_kind": "removed"}` for basenames
    /// only in the before set. Diverges from in-place Removed: NO
    /// `before` body field — basename-only signal (sidesteps #461).
    #[test]
    fn plan_to_json_value_diff_recreate_emits_removed_basenames() {
        let mut after_plan = fake_runner_plan("buckos");
        after_plan.drop_ins.insert(
            "00-ghars.conf".into(),
            "[Unit]\nX-Ghars-Spec-Hash=sha256:abc\n".into(),
        );
        let delta = plan::RunnerDelta {
            identity: fake_identity("buckos"),
            after: after_plan,
            requires_recreate: true,
            recreate_reasons: vec!["runner_version"],
            drift_cause: plan::DriftCause::SpecChanged,
            field_changes: Vec::new(),
            drop_in_changes: Vec::new(),
            before_caches: None,
            before_drop_in_basenames: Some(vec!["00-ghars.conf".into(), "99-custom.conf".into()]),
        };
        let plan = Plan {
            actions: vec![Action::UpdateRunner(delta)],
            warnings: vec![],
        };
        let body = plan_to_json_value(&plan, true);
        let actions = body["actions"].as_array().expect("actions array");
        let drop_in_changes = actions[0]["drop_in_changes"]
            .as_array()
            .expect("drop_in_changes array");
        // 1 Created (00-ghars.conf) + 1 Removed (99-custom.conf) = 2 entries.
        assert_eq!(drop_in_changes.len(), 2, "got: {drop_in_changes:?}");
        // Find the Removed entry.
        let removed = drop_in_changes
            .iter()
            .find(|v| v["change_kind"] == "removed")
            .expect("removed entry missing");
        assert_eq!(removed["basename"], "99-custom.conf");
        // Diverges from in-place Removed: NO `before` body field
        // (basename-only signal, sidesteps #461).
        assert!(
            removed.get("before").is_none(),
            "recreate-path Removed must NOT carry a `before` body, got: {removed:?}"
        );
        // API-1: explicit `body_suppressed: true` marker so JSON
        // consumers can distinguish "no body because suppressed" from
        // "no body because absent" without inferring from absence.
        assert_eq!(
            removed["body_suppressed"], true,
            "recreate-path Removed must carry `body_suppressed: true`, got: {removed:?}"
        );
    }

    /// T6: `plan_to_json_value` recreate path with
    /// `before_drop_in_basenames = None` → no Removed entries emitted
    /// in the JSON. Symmetric with T2 (text path).
    #[test]
    fn plan_to_json_value_diff_recreate_none_basenames_emits_no_removed() {
        let mut after_plan = fake_runner_plan("buckos");
        after_plan.drop_ins.insert(
            "00-ghars.conf".into(),
            "[Unit]\nX-Ghars-Spec-Hash=sha256:abc\n".into(),
        );
        let delta = plan::RunnerDelta {
            identity: fake_identity("buckos"),
            after: after_plan,
            requires_recreate: true,
            recreate_reasons: vec!["runner_version"],
            drift_cause: plan::DriftCause::SpecChanged,
            field_changes: Vec::new(),
            drop_in_changes: Vec::new(),
            before_caches: None,
            before_drop_in_basenames: None,
        };
        let plan = Plan {
            actions: vec![Action::UpdateRunner(delta)],
            warnings: vec![],
        };
        let body = plan_to_json_value(&plan, true);
        let actions = body["actions"].as_array().expect("actions array");
        let drop_in_changes = actions[0]["drop_in_changes"]
            .as_array()
            .expect("drop_in_changes array");
        // 1 Created (00-ghars.conf) only — no Removed entries.
        assert_eq!(drop_in_changes.len(), 1, "got: {drop_in_changes:?}");
        let any_removed = drop_in_changes
            .iter()
            .any(|v| v["change_kind"] == "removed");
        assert!(
            !any_removed,
            "no Removed entries expected when before_drop_in_basenames is None, got: {drop_in_changes:?}"
        );
    }

    // ---------- #285: JSON disruption + diff payload --------------

    #[test]
    fn plan_to_json_value_includes_disruption_for_every_action_kind() {
        let plan = Plan {
            actions: vec![
                Action::CreateRunner(fake_runner_plan("a")),
                Action::UpdateRunner(plan::RunnerDelta {
                    identity: fake_identity("b"),
                    after: fake_runner_plan("b"),
                    requires_recreate: false,
                    recreate_reasons: vec![],
                    drift_cause: plan::DriftCause::SpecChanged,
                    field_changes: Vec::new(),
                    drop_in_changes: Vec::new(),
                    before_caches: None,
                    before_drop_in_basenames: None,
                }),
                Action::RemoveRunner(fake_identity("c")),
                Action::CreateCachePool(plan::CachePoolPlan {
                    binding: fake_cache_binding("p"),
                    drop_in_body: String::new(),
                    spec_hash: "sha256:0".into(),
                }),
                Action::UpdateCachePool(plan::CachePoolDelta {
                    binding: fake_cache_binding("p2"),
                    drop_in_body: String::new(),
                    spec_hash: "sha256:0".into(),
                }),
                Action::RemoveCachePool("p3".into()),
                Action::NoOp("d: in sync".into()),
            ],
            warnings: vec![],
        };
        let body = plan_to_json_value(&plan, false);
        let actions = body["actions"].as_array().unwrap();
        let labels: Vec<&str> = actions
            .iter()
            .map(|v| v["disruption"].as_str().unwrap_or(""))
            .collect();
        assert_eq!(
            labels,
            vec![
                "recreate", // CreateRunner
                "restart",  // UpdateRunner in-place
                "recreate", // RemoveRunner
                "recreate", // CreateCachePool
                "restart",  // UpdateCachePool
                "recreate", // RemoveCachePool
                "none",     // NoOp
            ]
        );
    }

    #[test]
    fn plan_to_json_value_update_runner_recreate_emits_recreate_disruption() {
        // ADV-6: the all-variants test above covers in-place
        // UpdateRunner ("restart") but not the recreate branch
        // (`requires_recreate = true`). The plan-to-disruption
        // mapping at plan.rs::Action::disruption forks on
        // `requires_recreate`, so both arms need an explicit JSON
        // pin — without this, a regression that hardcoded
        // "restart" for every UpdateRunner would slip past
        // existing coverage.
        let plan = Plan {
            actions: vec![Action::UpdateRunner(plan::RunnerDelta {
                identity: fake_identity("recreate-me"),
                after: fake_runner_plan("recreate-me"),
                requires_recreate: true,
                recreate_reasons: vec!["runner_version"],
                drift_cause: plan::DriftCause::SpecChanged,
                field_changes: Vec::new(),
                drop_in_changes: Vec::new(),
                before_caches: None,
                before_drop_in_basenames: None,
            })],
            warnings: vec![],
        };
        let body = plan_to_json_value(&plan, false);
        assert_eq!(body["actions"][0]["disruption"], "recreate");
        assert_eq!(body["actions"][0]["kind"], "update_runner");
    }

    #[test]
    fn plan_to_json_value_no_diff_drop_in_changes_omit_bodies() {
        let plan = Plan {
            actions: vec![Action::UpdateRunner(plan::RunnerDelta {
                identity: fake_identity("buckos"),
                after: fake_runner_plan("buckos"),
                requires_recreate: false,
                recreate_reasons: vec![],
                drift_cause: plan::DriftCause::SpecChanged,
                field_changes: Vec::new(),
                drop_in_changes: vec![plan::DropInChange {
                    basename: "10-memory.conf".into(),
                    change: plan::DropInChangeKind::Modified {
                        before: "MemoryMax=1G\n".into(),
                        after: "MemoryMax=2G\n".into(),
                    },
                }],
                before_caches: None,
                before_drop_in_basenames: None,
            })],
            warnings: vec![],
        };
        let body = plan_to_json_value(&plan, false);
        let entry = &body["actions"][0]["drop_in_changes"][0];
        assert_eq!(entry["basename"], "10-memory.conf");
        assert_eq!(entry["change_kind"], "modified");
        assert!(
            entry.get("before").is_none(),
            "no-diff must not embed before: {entry}"
        );
        assert!(
            entry.get("after").is_none(),
            "no-diff must not embed after: {entry}"
        );
        assert!(
            entry.get("unified_diff").is_none(),
            "no-diff must not embed unified_diff: {entry}",
        );
    }

    #[test]
    fn plan_to_json_value_diff_modified_embeds_unified_diff_only() {
        // Per coordinator ruling, Modified always uses unified_diff
        // (no `before`/`after` pair in JSON either).
        let plan = Plan {
            actions: vec![Action::UpdateRunner(plan::RunnerDelta {
                identity: fake_identity("buckos"),
                after: fake_runner_plan("buckos"),
                requires_recreate: false,
                recreate_reasons: vec![],
                drift_cause: plan::DriftCause::SpecChanged,
                field_changes: Vec::new(),
                drop_in_changes: vec![plan::DropInChange {
                    basename: "10-memory.conf".into(),
                    change: plan::DropInChangeKind::Modified {
                        before: "[Service]\nMemoryMax=1G\n".into(),
                        after: "[Service]\nMemoryMax=2G\n".into(),
                    },
                }],
                before_caches: None,
                before_drop_in_basenames: None,
            })],
            warnings: vec![],
        };
        let body = plan_to_json_value(&plan, true);
        let entry = &body["actions"][0]["drop_in_changes"][0];
        assert!(entry.get("unified_diff").is_some(), "got: {entry}");
        let diff = entry["unified_diff"].as_str().unwrap();
        assert!(diff.contains("@@"), "expected unified diff hunk: {diff}");
        assert!(diff.contains("-MemoryMax=1G"), "got: {diff}");
        assert!(diff.contains("+MemoryMax=2G"), "got: {diff}");
        // Modified does NOT carry before/after pair in JSON either.
        assert!(entry.get("before").is_none(), "got: {entry}");
        assert!(entry.get("after").is_none(), "got: {entry}");
    }

    #[test]
    fn plan_to_json_value_diff_created_embeds_after_only() {
        let plan = Plan {
            actions: vec![Action::UpdateRunner(plan::RunnerDelta {
                identity: fake_identity("buckos"),
                after: fake_runner_plan("buckos"),
                requires_recreate: false,
                recreate_reasons: vec![],
                drift_cause: plan::DriftCause::SpecChanged,
                field_changes: Vec::new(),
                drop_in_changes: vec![plan::DropInChange {
                    basename: "60-proxy.conf".into(),
                    change: plan::DropInChangeKind::Created {
                        after: "Environment=HTTP_PROXY=http://p:8080\n".into(),
                    },
                }],
                before_caches: None,
                before_drop_in_basenames: None,
            })],
            warnings: vec![],
        };
        let body = plan_to_json_value(&plan, true);
        let entry = &body["actions"][0]["drop_in_changes"][0];
        assert_eq!(entry["after"], "Environment=HTTP_PROXY=http://p:8080\n");
        assert!(entry.get("before").is_none(), "got: {entry}");
        assert!(entry.get("unified_diff").is_none(), "got: {entry}");
    }

    #[test]
    fn plan_to_json_value_diff_preserved_emits_no_body_payload() {
        // Preserved variants under --diff do not add any body keys
        // — basename + change_kind="preserved" is the entire shape.
        let plan = Plan {
            actions: vec![Action::UpdateRunner(plan::RunnerDelta {
                identity: fake_identity("buckos"),
                after: fake_runner_plan("buckos"),
                requires_recreate: false,
                recreate_reasons: vec![],
                drift_cause: plan::DriftCause::SpecChanged,
                field_changes: Vec::new(),
                drop_in_changes: vec![plan::DropInChange {
                    basename: "15-resolv.conf".into(),
                    change: plan::DropInChangeKind::Preserved,
                }],
                before_caches: None,
                before_drop_in_basenames: None,
            })],
            warnings: vec![],
        };
        let body = plan_to_json_value(&plan, true);
        let entry = &body["actions"][0]["drop_in_changes"][0];
        assert_eq!(entry["change_kind"], "preserved");
        assert!(entry.get("before").is_none(), "got: {entry}");
        assert!(entry.get("after").is_none(), "got: {entry}");
        assert!(entry.get("unified_diff").is_none(), "got: {entry}");
    }

    #[test]
    fn plan_to_json_value_diff_recreate_synthesizes_created_entries() {
        // Recreate UpdateRunner has empty drop_in_changes; under
        // --diff the JSON synthesizes Created entries from
        // delta.after.drop_ins so consumers see post-recreate state.
        // Without --diff the array stays empty (backward compat).
        let mut after_plan = fake_runner_plan("buckos");
        after_plan.drop_ins.insert(
            "00-ghars.conf".into(),
            "[Unit]\nX-Ghars-Spec-Hash=sha256:abc\n".into(),
        );
        after_plan
            .drop_ins
            .insert("10-memory.conf".into(), "[Service]\nMemoryMax=4G\n".into());
        let delta = plan::RunnerDelta {
            identity: fake_identity("buckos"),
            after: after_plan,
            requires_recreate: true,
            recreate_reasons: vec!["runner_version"],
            drift_cause: plan::DriftCause::SpecChanged,
            field_changes: Vec::new(),
            drop_in_changes: Vec::new(),
            before_caches: None,
            before_drop_in_basenames: None,
        };
        let plan = Plan {
            actions: vec![Action::UpdateRunner(delta)],
            warnings: vec![],
        };
        let body = plan_to_json_value(&plan, true);
        let entries = body["actions"][0]["drop_in_changes"].as_array().unwrap();
        assert_eq!(entries.len(), 2);
        // BTreeMap iteration is alphabetical, so 00 < 10.
        assert_eq!(entries[0]["basename"], "00-ghars.conf");
        assert_eq!(entries[0]["change_kind"], "created");
        assert!(entries[0]["after"]
            .as_str()
            .unwrap()
            .contains("X-Ghars-Spec-Hash"));
        assert_eq!(entries[1]["basename"], "10-memory.conf");
        assert_eq!(entries[1]["change_kind"], "created");
        assert!(entries[1]["after"]
            .as_str()
            .unwrap()
            .contains("MemoryMax=4G"));

        // Without --diff: backward-compat empty array.
        let body = plan_to_json_value(&plan, false);
        let entries = body["actions"][0]["drop_in_changes"].as_array().unwrap();
        assert!(
            entries.is_empty(),
            "no-diff recreate must keep array empty: {entries:?}"
        );
    }

    // ---------- #285 addendum (D-6): schema_version --------------

    #[test]
    fn plan_to_json_value_emits_schema_version_at_top_level() {
        // Top-level `schema_version` is a forward-compat hook for
        // CI consumers. Bumped to `"2"` in #463 because
        // FieldChange.before/after became tagged FieldValue objects;
        // any future shape change that breaks v2 consumers requires
        // another bump and CHANGELOG/devadv re-review.
        let plan = Plan {
            actions: vec![Action::NoOp("a: in sync".into())],
            warnings: vec![],
        };
        for diff in [false, true] {
            let body = plan_to_json_value(&plan, diff);
            assert_eq!(
                body["schema_version"].as_str(),
                Some("2"),
                "schema_version must be \"2\": diff={diff}, body={body}",
            );
        }
    }

    #[test]
    fn plan_to_json_value_empty_plan_still_carries_schema_version_and_summary() {
        let plan = Plan {
            actions: vec![],
            warnings: vec![],
        };
        let body = plan_to_json_value(&plan, false);
        assert_eq!(body["schema_version"], "2");
        assert_eq!(body["summary"]["total_actions"], 0);
        assert_eq!(body["summary"]["any_recreate"], false);
        assert_eq!(body["summary"]["by_disruption"]["none"], 0);
        assert_eq!(body["summary"]["by_disruption"]["restart"], 0);
        assert_eq!(body["summary"]["by_disruption"]["recreate"], 0);
    }

    // ---------- #285 addendum (D-7): summary ---------------------

    #[test]
    fn plan_to_json_value_summary_counts_match_action_disruptions() {
        // 1 NoOp + 2 in-place UpdateRunner + 1 CreateRunner +
        // 1 RemoveCachePool → none=1, restart=2, recreate=2,
        // any_recreate=true.
        let in_place = || plan::RunnerDelta {
            identity: fake_identity("ip"),
            after: fake_runner_plan("ip"),
            requires_recreate: false,
            recreate_reasons: vec![],
            drift_cause: plan::DriftCause::SpecChanged,
            field_changes: Vec::new(),
            drop_in_changes: Vec::new(),
            before_caches: None,
            before_drop_in_basenames: None,
        };
        let plan = Plan {
            actions: vec![
                Action::NoOp("a: in sync".into()),
                Action::UpdateRunner(in_place()),
                Action::UpdateRunner(in_place()),
                Action::CreateRunner(fake_runner_plan("c")),
                Action::RemoveCachePool("p".into()),
            ],
            warnings: vec![],
        };
        let body = plan_to_json_value(&plan, false);
        let s = &body["summary"];
        assert_eq!(s["total_actions"], 5);
        assert_eq!(s["by_disruption"]["none"], 1);
        assert_eq!(s["by_disruption"]["restart"], 2);
        assert_eq!(s["by_disruption"]["recreate"], 2);
        assert_eq!(s["any_recreate"], true);
    }

    #[test]
    fn plan_to_json_value_summary_any_recreate_false_when_only_restart_and_none() {
        // CI policy gates branch on `any_recreate` — pin that
        // restart-only + noop plans report false.
        let in_place = plan::RunnerDelta {
            identity: fake_identity("ip"),
            after: fake_runner_plan("ip"),
            requires_recreate: false,
            recreate_reasons: vec![],
            drift_cause: plan::DriftCause::SpecChanged,
            field_changes: Vec::new(),
            drop_in_changes: Vec::new(),
            before_caches: None,
            before_drop_in_basenames: None,
        };
        let plan = Plan {
            actions: vec![
                Action::NoOp("a: in sync".into()),
                Action::UpdateRunner(in_place),
                Action::UpdateCachePool(plan::CachePoolDelta {
                    binding: fake_cache_binding("p"),
                    drop_in_body: String::new(),
                    spec_hash: "sha256:0".into(),
                }),
            ],
            warnings: vec![],
        };
        let body = plan_to_json_value(&plan, false);
        let s = &body["summary"];
        assert_eq!(s["total_actions"], 3);
        assert_eq!(s["by_disruption"]["none"], 1);
        assert_eq!(s["by_disruption"]["restart"], 2);
        assert_eq!(s["by_disruption"]["recreate"], 0);
        assert_eq!(s["any_recreate"], false);
    }

    #[test]
    fn plan_to_json_value_summary_any_recreate_true_for_any_recreate_action() {
        // Single recreate-class action flips the `any_recreate`
        // gate — CI policy guards on this.
        let plan = Plan {
            actions: vec![
                Action::NoOp("a: in sync".into()),
                Action::CreateRunner(fake_runner_plan("c")),
            ],
            warnings: vec![],
        };
        let body = plan_to_json_value(&plan, false);
        assert_eq!(body["summary"]["any_recreate"], true);
        assert_eq!(body["summary"]["by_disruption"]["recreate"], 1);
    }

    // ---------- #469: summary.recreates --------------------------

    /// #469: empty plan must still emit `recreates: []` as a key
    /// (stable shape so CI consumers can `jq '.summary.recreates |
    /// length'` without conditional checks for key presence).
    #[test]
    fn plan_to_json_value_summary_recreates_empty_when_no_actions() {
        let plan = Plan {
            actions: vec![],
            warnings: vec![],
        };
        let body = plan_to_json_value(&plan, false);
        assert_eq!(
            body["summary"]["recreates"],
            serde_json::json!([] as [&str; 0]),
            "empty plan must emit recreates: []",
        );
    }

    /// #469: every recreate-class action lands in `recreates` and the
    /// list is sorted alphabetically by `Action::label()`. Non-
    /// recreate actions (NoOp, in-place UpdateRunner, UpdateCachePool)
    /// must NOT appear in `recreates`. Pin the full label vocabulary
    /// (`CreateRunner(...)`, `RemoveRunner(...)`, `CreateCachePool(...)`,
    /// `RemoveCachePool(...)`, `UpdateRunner(...)` when
    /// `requires_recreate=true`) so a future refactor that drops a
    /// recreate-class action from the filter is caught.
    #[test]
    fn plan_to_json_value_summary_recreates_lists_all_recreate_actions_sorted() {
        let in_place = plan::RunnerDelta {
            identity: fake_identity("inplace-r"),
            after: fake_runner_plan("inplace-r"),
            requires_recreate: false,
            recreate_reasons: vec![],
            drift_cause: plan::DriftCause::SpecChanged,
            field_changes: Vec::new(),
            drop_in_changes: Vec::new(),
            before_caches: None,
            before_drop_in_basenames: None,
        };
        let recreate_delta = plan::RunnerDelta {
            identity: fake_identity("recreate-r"),
            after: fake_runner_plan("recreate-r"),
            requires_recreate: true,
            // recreate_reasons intentionally empty: Action::label() ignores
            // recreate_reasons content and emits only the entity name, so
            // its value is irrelevant to summary.recreates output.
            recreate_reasons: vec![],
            drift_cause: plan::DriftCause::SpecChanged,
            field_changes: Vec::new(),
            drop_in_changes: Vec::new(),
            before_caches: None,
            before_drop_in_basenames: None,
        };
        // Insert in deliberately UNSORTED order — the production
        // sort is what gives us the canonical alphabetical output
        // regardless of upstream order.
        let plan = Plan {
            actions: vec![
                Action::CreateRunner(fake_runner_plan("zzz")),
                Action::NoOp("a: in sync".into()),
                Action::RemoveCachePool("aaa-pool".into()),
                Action::UpdateRunner(in_place),
                Action::CreateCachePool(plan::CachePoolPlan {
                    binding: fake_cache_binding("mmm-pool"),
                    drop_in_body: String::new(),
                    spec_hash: "sha256:0".into(),
                }),
                Action::UpdateRunner(recreate_delta),
                Action::RemoveRunner(fake_identity("bbb-r")),
                Action::UpdateCachePool(plan::CachePoolDelta {
                    binding: fake_cache_binding("upd-pool"),
                    drop_in_body: String::new(),
                    spec_hash: "sha256:0".into(),
                }),
            ],
            warnings: vec![],
        };
        let body = plan_to_json_value(&plan, false);
        let recreates = body["summary"]["recreates"].as_array().unwrap();
        // Expected: every Recreate action's label, alphabetically.
        // Excludes NoOp (none), in-place UpdateRunner (restart),
        // UpdateCachePool (restart).
        let actual: Vec<&str> = recreates.iter().map(|v| v.as_str().unwrap()).collect();
        assert_eq!(
            actual,
            vec![
                "CreateCachePool(mmm-pool)",
                "CreateRunner(zzz)",
                "RemoveCachePool(aaa-pool)",
                "RemoveRunner(bbb-r)",
                "UpdateRunner(recreate-r)",
            ],
            "summary.recreates must list every Recreate-class action label, sorted alphabetically",
        );
        // Structural pin (CLN-469-1): post-refactor,
        // by_disruption["recreate"] is sourced from `recreates.len()`
        // inside `plan_summary_value`, so the two fields cannot
        // diverge on input — they share a single counter. Asserting
        // equality here pins the source-shared invariant against a
        // future refactor that re-splits the count from the Vec.
        assert_eq!(
            body["summary"]["by_disruption"]["recreate"],
            serde_json::json!(actual.len()),
            "summary.recreates length must equal summary.by_disruption.recreate (CLN-469-1: shared counter)",
        );
        assert_eq!(body["summary"]["any_recreate"], true);
    }

    /// #469: restart-only + noop plan reports `recreates: []` even
    /// when total_actions > 0. Symmetric pin against
    /// `summary_any_recreate_false_when_only_restart_and_none`.
    #[test]
    fn plan_to_json_value_summary_recreates_empty_when_only_restart_and_none() {
        let in_place = plan::RunnerDelta {
            identity: fake_identity("ip"),
            after: fake_runner_plan("ip"),
            requires_recreate: false,
            recreate_reasons: vec![],
            drift_cause: plan::DriftCause::SpecChanged,
            field_changes: Vec::new(),
            drop_in_changes: Vec::new(),
            before_caches: None,
            before_drop_in_basenames: None,
        };
        let plan = Plan {
            actions: vec![
                Action::NoOp("a: in sync".into()),
                Action::UpdateRunner(in_place),
                Action::UpdateCachePool(plan::CachePoolDelta {
                    binding: fake_cache_binding("p"),
                    drop_in_body: String::new(),
                    spec_hash: "sha256:0".into(),
                }),
            ],
            warnings: vec![],
        };
        let body = plan_to_json_value(&plan, false);
        assert_eq!(
            body["summary"]["recreates"],
            serde_json::json!([] as [&str; 0]),
            "no-recreate plan must emit recreates: []",
        );
        assert_eq!(body["summary"]["any_recreate"], false);
    }

    /// #469: cross-type entity-name collision contract.
    ///
    /// A runner named `alpha` and a cache pool named `alpha` are
    /// disambiguated in `summary.recreates` by their `Action::label()`
    /// variant prefix: `RemoveRunner(alpha)` vs `RemoveCachePool(alpha)`.
    /// Pins the doc-block claim that "Same-name entities of different
    /// kinds disambiguate via the variant prefix" — bare-name output
    /// would collide here and lose information.
    #[test]
    fn plan_to_json_value_summary_recreates_disambiguates_same_name_runner_and_pool() {
        let plan = Plan {
            actions: vec![
                Action::RemoveRunner(fake_identity("alpha")),
                Action::RemoveCachePool("alpha".into()),
            ],
            warnings: vec![],
        };
        let body = plan_to_json_value(&plan, false);
        let recreates = body["summary"]["recreates"].as_array().unwrap();
        let actual: Vec<&str> = recreates.iter().map(|v| v.as_str().unwrap()).collect();
        assert_eq!(
            actual,
            vec!["RemoveCachePool(alpha)", "RemoveRunner(alpha)"],
            "same-name runner and pool must produce two distinct labeled entries",
        );
    }

    /// #469: `recreates` is `--diff`-independent.
    ///
    /// `summary.recreates` carries only `Action::label()` strings and
    /// derives nothing from drop-in bodies or per-action diff payload.
    /// Toggling the `diff` argument to `plan_to_json_value` MUST NOT
    /// change `summary.recreates`. Pins the doc-block invariant
    /// "Output is `--diff`-independent" against a future refactor that
    /// accidentally couples `recreates` to diff-mode payload.
    #[test]
    fn plan_to_json_value_summary_recreates_is_diff_invariant() {
        let recreate_delta = plan::RunnerDelta {
            identity: fake_identity("alpha"),
            after: fake_runner_plan("alpha"),
            requires_recreate: true,
            recreate_reasons: vec![],
            drift_cause: plan::DriftCause::SpecChanged,
            field_changes: Vec::new(),
            // Modified drop-in: with `diff=true`, plan_to_json_value
            // emits unified_diff bodies in actions[]; `recreates`
            // must remain unchanged regardless.
            drop_in_changes: vec![plan::DropInChange {
                basename: "10-memory.conf".into(),
                change: plan::DropInChangeKind::Modified {
                    before: "[Service]\nMemoryMax=1G\n".into(),
                    after: "[Service]\nMemoryMax=2G\n".into(),
                },
            }],
            before_caches: None,
            before_drop_in_basenames: None,
        };
        let plan = Plan {
            actions: vec![
                Action::CreateRunner(fake_runner_plan("beta")),
                Action::UpdateRunner(recreate_delta),
                Action::RemoveCachePool("gamma".into()),
            ],
            warnings: vec![],
        };
        let no_diff = plan_to_json_value(&plan, false);
        let with_diff = plan_to_json_value(&plan, true);
        assert_eq!(
            no_diff["summary"]["recreates"], with_diff["summary"]["recreates"],
            "summary.recreates must be identical across diff=false and diff=true",
        );
        // Sanity: also verify the array is non-empty, otherwise the
        // assertion above would trivially pass on `[] == []`.
        assert!(
            !no_diff["summary"]["recreates"]
                .as_array()
                .unwrap()
                .is_empty(),
            "test must drive a non-empty recreates array; otherwise diff-invariance is trivial",
        );
    }

    /// #469: all-recreate-only plan boundary pin.
    ///
    /// When every action is recreate-class (no `NoOp`, no
    /// `Restart`-class actions), `recreates.len()` must equal
    /// `total_actions` and `by_disruption.{none,restart}` must be 0.
    /// Symmetric counterpart to
    /// `summary_recreates_empty_when_only_restart_and_none` — the
    /// "everything fires the recreate gate" boundary against the
    /// "nothing fires the recreate gate" boundary. Pins both endpoints
    /// of the disruption-class spectrum.
    #[test]
    fn plan_to_json_value_summary_recreates_only_recreate_class_actions() {
        let plan = Plan {
            actions: vec![
                Action::CreateRunner(fake_runner_plan("a")),
                Action::RemoveRunner(fake_identity("b")),
                Action::RemoveCachePool("c".into()),
            ],
            warnings: vec![],
        };
        let body = plan_to_json_value(&plan, false);
        let s = &body["summary"];
        let recreates = s["recreates"].as_array().unwrap();
        assert_eq!(s["total_actions"], 3);
        assert_eq!(
            recreates.len(),
            3,
            "all-recreate plan: recreates.len() must equal total_actions",
        );
        assert_eq!(s["by_disruption"]["none"], 0);
        assert_eq!(s["by_disruption"]["restart"], 0);
        assert_eq!(s["by_disruption"]["recreate"], 3);
        assert_eq!(s["any_recreate"], true);
    }

    /// #469: pool-only plan pin.
    ///
    /// A plan with only cache-pool actions (no runner actions) must
    /// still produce the correct `recreates` set. `CreateCachePool`
    /// and `RemoveCachePool` are recreate-class; `UpdateCachePool` is
    /// `Restart` and MUST be excluded. Guards against a future
    /// refactor that narrows the recreate filter to runner-only
    /// (e.g. by switching from `disruption()` to a runner-specific
    /// predicate).
    #[test]
    fn plan_to_json_value_summary_recreates_pool_only_plan() {
        let plan = Plan {
            actions: vec![
                Action::CreateCachePool(plan::CachePoolPlan {
                    binding: fake_cache_binding("x"),
                    drop_in_body: String::new(),
                    spec_hash: "sha256:0".into(),
                }),
                Action::UpdateCachePool(plan::CachePoolDelta {
                    binding: fake_cache_binding("u"),
                    drop_in_body: String::new(),
                    spec_hash: "sha256:0".into(),
                }),
                Action::RemoveCachePool("y".into()),
            ],
            warnings: vec![],
        };
        let body = plan_to_json_value(&plan, false);
        let recreates = body["summary"]["recreates"].as_array().unwrap();
        let actual: Vec<&str> = recreates.iter().map(|v| v.as_str().unwrap()).collect();
        assert_eq!(
            actual,
            vec!["CreateCachePool(x)", "RemoveCachePool(y)"],
            "pool-only plan: recreates must contain only CreateCachePool + RemoveCachePool, UpdateCachePool excluded",
        );
        assert_eq!(body["summary"]["by_disruption"]["restart"], 1);
        assert_eq!(body["summary"]["by_disruption"]["recreate"], 2);
        assert_eq!(body["summary"]["any_recreate"], true);
    }

    // ---------- #285 addendum (D-13): colorized unified diff ------

    #[test]
    fn render_action_line_diff_modified_color_wraps_plus_lines_green() {
        let delta = plan::RunnerDelta {
            identity: fake_identity("buckos"),
            after: fake_runner_plan("buckos"),
            requires_recreate: false,
            recreate_reasons: vec![],
            drift_cause: plan::DriftCause::SpecChanged,
            field_changes: Vec::new(),
            drop_in_changes: vec![plan::DropInChange {
                basename: "10-memory.conf".into(),
                change: plan::DropInChangeKind::Modified {
                    before: "[Service]\nMemoryMax=1G\n".into(),
                    after: "[Service]\nMemoryMax=2G\n".into(),
                },
            }],
            before_caches: None,
            before_drop_in_basenames: None,
        };
        let line = render_action_line(
            &Action::UpdateRunner(delta),
            ColorMode { enabled: true },
            true,
        );
        // `+MemoryMax=2G` wrapped in green (\x1b[32m ... \x1b[0m).
        assert!(
            line.contains("\x1b[32m+MemoryMax=2G\x1b[0m"),
            "expected green-wrapped + line: {line}",
        );
        // `-MemoryMax=1G` wrapped in red (\x1b[31m ... \x1b[0m).
        assert!(
            line.contains("\x1b[31m-MemoryMax=1G\x1b[0m"),
            "expected red-wrapped - line: {line}",
        );
    }

    #[test]
    fn render_action_line_diff_modified_no_color_emits_plain_unified_diff() {
        // Same Modified payload, color disabled — no ANSI escape
        // sequences in the body, but `+`/`-` sigils still present.
        let delta = plan::RunnerDelta {
            identity: fake_identity("buckos"),
            after: fake_runner_plan("buckos"),
            requires_recreate: false,
            recreate_reasons: vec![],
            drift_cause: plan::DriftCause::SpecChanged,
            field_changes: Vec::new(),
            drop_in_changes: vec![plan::DropInChange {
                basename: "10-memory.conf".into(),
                change: plan::DropInChangeKind::Modified {
                    before: "[Service]\nMemoryMax=1G\n".into(),
                    after: "[Service]\nMemoryMax=2G\n".into(),
                },
            }],
            before_caches: None,
            before_drop_in_basenames: None,
        };
        let line = render_action_line(
            &Action::UpdateRunner(delta),
            ColorMode { enabled: false },
            true,
        );
        // Unified-diff body has the +/- sigils but no ANSI bytes
        // around them.
        assert!(line.contains("+MemoryMax=2G"), "got: {line}");
        assert!(line.contains("-MemoryMax=1G"), "got: {line}");
        assert!(
            !line.contains("\x1b[32m+MemoryMax"),
            "no-color must not wrap + lines in green: {line}",
        );
        assert!(
            !line.contains("\x1b[31m-MemoryMax"),
            "no-color must not wrap - lines in red: {line}",
        );
    }

    #[test]
    fn render_action_line_diff_modified_color_does_not_wrap_hunk_header() {
        // `@@` hunk headers are NOT colored — operator scripts
        // grepping `^@@` on color-stripped output still match.
        let delta = plan::RunnerDelta {
            identity: fake_identity("buckos"),
            after: fake_runner_plan("buckos"),
            requires_recreate: false,
            recreate_reasons: vec![],
            drift_cause: plan::DriftCause::SpecChanged,
            field_changes: Vec::new(),
            drop_in_changes: vec![plan::DropInChange {
                basename: "10-memory.conf".into(),
                change: plan::DropInChangeKind::Modified {
                    before: "[Service]\nMemoryMax=1G\n".into(),
                    after: "[Service]\nMemoryMax=2G\n".into(),
                },
            }],
            before_caches: None,
            before_drop_in_basenames: None,
        };
        let line = render_action_line(
            &Action::UpdateRunner(delta),
            ColorMode { enabled: true },
            true,
        );
        // The `@@` line itself is uncolored; check that no ANSI
        // prefix immediately precedes it.
        assert!(line.contains("@@"), "expected hunk header: {line}");
        assert!(
            !line.contains("\x1b[32m@@") && !line.contains("\x1b[31m@@"),
            "hunk header must not be wrapped in ANSI color: {line}",
        );
    }

    #[test]
    fn render_action_line_diff_modified_unified_diff_uses_on_disk_desired_headers() {
        // Header labels track the in-memory-vs-disk semantics:
        // `--- on-disk` (the discovered drop-in body) and
        // `+++ desired` (the post-render bytes). Pin the strings
        // so the convention doesn't silently revert to the
        // ambiguous `before`/`after` (or `None` → no labels).
        let delta = plan::RunnerDelta {
            identity: fake_identity("buckos"),
            after: fake_runner_plan("buckos"),
            requires_recreate: false,
            recreate_reasons: vec![],
            drift_cause: plan::DriftCause::SpecChanged,
            field_changes: Vec::new(),
            drop_in_changes: vec![plan::DropInChange {
                basename: "10-memory.conf".into(),
                change: plan::DropInChangeKind::Modified {
                    before: "[Service]\nMemoryMax=1G\n".into(),
                    after: "[Service]\nMemoryMax=2G\n".into(),
                },
            }],
            before_caches: None,
            before_drop_in_basenames: None,
        };
        let line = render_action_line(
            &Action::UpdateRunner(delta),
            ColorMode { enabled: false },
            true,
        );
        assert!(line.contains("--- on-disk"), "got: {line}");
        assert!(line.contains("+++ desired"), "got: {line}");
    }

    #[test]
    fn render_action_line_diff_modified_color_does_not_wrap_unified_diff_headers() {
        // `--- on-disk` and `+++ desired` are header lines, not
        // change lines, and must NOT be wrapped in red/green —
        // matches `git diff --color`, which renders headers in
        // bold/cyan, not the change-line palette. Pin both
        // headers stay uncolored when color is enabled.
        let delta = plan::RunnerDelta {
            identity: fake_identity("buckos"),
            after: fake_runner_plan("buckos"),
            requires_recreate: false,
            recreate_reasons: vec![],
            drift_cause: plan::DriftCause::SpecChanged,
            field_changes: Vec::new(),
            drop_in_changes: vec![plan::DropInChange {
                basename: "10-memory.conf".into(),
                change: plan::DropInChangeKind::Modified {
                    before: "[Service]\nMemoryMax=1G\n".into(),
                    after: "[Service]\nMemoryMax=2G\n".into(),
                },
            }],
            before_caches: None,
            before_drop_in_basenames: None,
        };
        let line = render_action_line(
            &Action::UpdateRunner(delta),
            ColorMode { enabled: true },
            true,
        );
        assert!(line.contains("--- on-disk"), "got: {line}");
        assert!(line.contains("+++ desired"), "got: {line}");
        assert!(
            !line.contains("\x1b[31m--- on-disk"),
            "--- on-disk header must not be red-wrapped: {line}",
        );
        assert!(
            !line.contains("\x1b[32m+++ desired"),
            "+++ desired header must not be green-wrapped: {line}",
        );
    }

    #[test]
    fn render_action_line_diff_created_no_color_wrap_on_created_body() {
        // Created bodies render under `        after:` with the
        // raw drop-in body — those bytes are NOT a unified diff,
        // so no `+`/`-` sigils, and color must not wrap them.
        // Pin that the body text appears verbatim and no ANSI
        // bytes wrap individual content lines.
        let delta = plan::RunnerDelta {
            identity: fake_identity("buckos"),
            after: fake_runner_plan("buckos"),
            requires_recreate: false,
            recreate_reasons: vec![],
            drift_cause: plan::DriftCause::SpecChanged,
            field_changes: Vec::new(),
            drop_in_changes: vec![plan::DropInChange {
                basename: "60-proxy.conf".into(),
                change: plan::DropInChangeKind::Created {
                    after: "[Service]\nEnvironment=HTTP_PROXY=http://p:8080\n".into(),
                },
            }],
            before_caches: None,
            before_drop_in_basenames: None,
        };
        let line = render_action_line(
            &Action::UpdateRunner(delta),
            ColorMode { enabled: true },
            true,
        );
        // The `+ 60-proxy.conf` sigil-line sits on the basename
        // line (not body); the body itself has no `+`/`-` to color.
        assert!(line.contains("    + 60-proxy.conf"), "got: {line}");
        assert!(line.contains("            [Service]"), "got: {line}");
        // `Environment=` is part of the body — must not be color-
        // wrapped because it was never `+` or `-` prefixed.
        assert!(
            !line.contains("\x1b[32m            [Service]"),
            "Created body lines must not be color-wrapped: {line}",
        );
    }

    // ---------- #285: --diff argv parsing -------------------------

    #[test]
    fn cli_plan_diff_default_is_false() {
        let cli = Cli::try_parse_from(["ghars", "plan"]).unwrap();
        match cli.command {
            Command::Plan(args) => assert!(!args.diff),
            other => panic!("expected Plan, got {other:?}"),
        }
    }

    #[test]
    fn cli_plan_diff_flag_sets_true() {
        let cli = Cli::try_parse_from(["ghars", "plan", "--diff"]).unwrap();
        match cli.command {
            Command::Plan(args) => assert!(args.diff),
            other => panic!("expected Plan, got {other:?}"),
        }
    }

    #[test]
    fn cli_plan_diff_does_not_take_value() {
        // Bool flag, not enum — a positional value following --diff
        // is a parse error (or in clap's case, attaches as another
        // positional — try_parse_from rejects unknown positionals
        // for a strict subcommand). Pin that --diff itself does not
        // consume its argument.
        let res = Cli::try_parse_from(["ghars", "plan", "--diff", "verbose"]);
        assert!(
            res.is_err(),
            "expected parse error for --diff with positional 'verbose', got: {res:?}",
        );
    }

    #[test]
    fn cli_apply_diff_default_is_false() {
        let cli = Cli::try_parse_from(["ghars", "apply"]).unwrap();
        match cli.command {
            Command::Apply(args) => assert!(!args.diff),
            other => panic!("expected Apply, got {other:?}"),
        }
    }

    #[test]
    fn cli_apply_diff_flag_sets_true() {
        let cli = Cli::try_parse_from(["ghars", "apply", "--diff"]).unwrap();
        match cli.command {
            Command::Apply(args) => assert!(args.diff),
            other => panic!("expected Apply, got {other:?}"),
        }
    }

    // render_plan covers the multi-action assembly path. We test the
    // empty-plan branch, the warnings tail, and the JSON path here.

    #[test]
    fn render_plan_json_emits_action_array_per_variant() {
        let warnings = vec!["shared user disables isolation".to_owned()];
        let plan = Plan {
            actions: vec![
                Action::CreateRunner(fake_runner_plan("a")),
                Action::UpdateRunner(plan::RunnerDelta {
                    identity: fake_identity("b"),
                    after: fake_runner_plan("b"),
                    requires_recreate: true,
                    recreate_reasons: vec!["runner_version"],
                    drift_cause: plan::DriftCause::SpecChanged,
                    field_changes: Vec::new(),
                    drop_in_changes: Vec::new(),
                    before_caches: None,
                    before_drop_in_basenames: None,
                }),
                Action::RemoveRunner(fake_identity("c")),
                Action::CreateCachePool(plan::CachePoolPlan {
                    binding: fake_cache_binding("p"),
                    drop_in_body: String::new(),
                    spec_hash: "sha256:0".into(),
                }),
                Action::UpdateCachePool(plan::CachePoolDelta {
                    binding: fake_cache_binding("p2"),
                    drop_in_body: String::new(),
                    spec_hash: "sha256:0".into(),
                }),
                Action::RemoveCachePool("p3".into()),
                Action::NoOp("d: in sync".into()),
            ],
            warnings,
        };
        // Drive the production Value-construction directly. No test
        // mirror — `plan_to_json_value` IS the production code (#313).
        let body = plan_to_json_value(&plan, false);
        let actions = body["actions"].as_array().expect("actions array");
        let kinds: Vec<&str> = actions
            .iter()
            .filter_map(|v| v.get("kind").and_then(|s| s.as_str()))
            .collect();
        assert_eq!(
            kinds,
            vec![
                "create_runner",
                "update_runner",
                "remove_runner",
                "create_cache_pool",
                "update_cache_pool",
                "remove_cache_pool",
                "noop",
            ]
        );
        // update_runner carries drift_cause + recreate_reasons (#260).
        let upd = actions
            .iter()
            .find(|v| v["kind"] == "update_runner")
            .unwrap();
        assert_eq!(upd["drift_cause"], "spec_changed");
        assert_eq!(upd["requires_recreate"], true);
        // No payload exposes raw token values or env-var references.
        let serialized = serde_json::to_string(&body).unwrap();
        assert!(!serialized.contains("token"), "no token leakage");
    }

    #[test]
    fn render_plan_quiet_writes_nothing() -> Result<()> {
        // quiet=true short-circuits BEFORE printing anything to stdout.
        // We verify the function returns Ok(()) and does not panic
        // when given a non-empty plan; the absence of output is
        // structural in the function body (`if quiet { return Ok(()) }`).
        let plan = Plan {
            actions: vec![Action::CreateRunner(fake_runner_plan("a"))],
            warnings: vec![],
        };
        render_plan(&plan, ColorMode { enabled: false }, false, true, false)
    }

    #[test]
    fn render_plan_empty_emits_no_changes_line_when_not_quiet() -> Result<()> {
        // The `Plan: no changes.` early-return path. Tested through
        // the public helper; the assertion is that the call succeeds
        // without panicking on an empty action list.
        let plan = Plan::default();
        render_plan(&plan, ColorMode { enabled: false }, false, false, false)
    }

    #[test]
    fn render_plan_json_path_succeeds_for_full_plan() -> Result<()> {
        // render_plan with json=true delegates to render_plan_json.
        // Drives the helper end-to-end; all-variant JSON shape is
        // pinned by render_plan_json_emits_action_array_per_variant.
        let plan = Plan {
            actions: vec![Action::CreateRunner(fake_runner_plan("a"))],
            warnings: vec!["shared user".into()],
        };
        render_plan(&plan, ColorMode { enabled: false }, true, false, false)
    }

    /// Item 6: end-to-end exercise of `render_plan_json` against an
    /// UpdateRunner action carrying a populated `field_changes` Vec
    /// AND a `drop_in_changes` Vec covering all four
    /// `DropInChangeKind` variants. The production renderer takes
    /// `&Plan` and writes to stdout — there is no return value, so
    /// the assertion is structural: render must succeed without
    /// panic on the most complex Update shape the planner can emit.
    /// The shape contract (top-level `actions` + `warnings`,
    /// per-action `field_changes` + `drop_in_changes`) is pinned by
    /// `render_plan_json_emits_action_array_per_variant` which
    /// drives `plan_to_json_value` directly (no test mirror after
    /// #313). Together the two tests cover both the happy-path
    /// output shape AND the non-panicking end-to-end pipe.
    #[test]
    fn render_plan_json_handles_update_runner_with_full_diff_payload() -> Result<()> {
        let delta = plan::RunnerDelta {
            identity: fake_identity("buckos"),
            after: fake_runner_plan("buckos"),
            requires_recreate: false,
            recreate_reasons: vec![],
            drift_cause: plan::DriftCause::SpecChangedAndDriftDetected,
            field_changes: vec![
                plan::FieldChange {
                    path: "auth_name",
                    before: plan::FieldValue::String("pat".into()),
                    after: plan::FieldValue::String("pat-new".into()),
                },
                plan::FieldChange {
                    path: "labels",
                    before: plan::FieldValue::List(vec!["ci".into()]),
                    after: plan::FieldValue::List(vec!["ci".into(), "gpu".into()]),
                },
            ],
            drop_in_changes: vec![
                plan::DropInChange {
                    basename: "00-ghars.conf".into(),
                    change: plan::DropInChangeKind::Modified {
                        before: "old".into(),
                        after: "new".into(),
                    },
                },
                plan::DropInChange {
                    basename: "10-memory.conf".into(),
                    change: plan::DropInChangeKind::Removed {
                        before: "MemoryMax=8G".into(),
                    },
                },
                plan::DropInChange {
                    basename: "60-proxy.conf".into(),
                    change: plan::DropInChangeKind::Created {
                        after: "Environment=HTTP_PROXY=...".into(),
                    },
                },
                plan::DropInChange {
                    basename: "15-resolv.conf".into(),
                    change: plan::DropInChangeKind::Preserved,
                },
            ],
            before_caches: None,
            before_drop_in_basenames: None,
        };
        let plan = Plan {
            actions: vec![Action::UpdateRunner(delta)],
            warnings: vec!["mixed signal: hash + drift".into()],
        };
        // Production renderer writes to stdout; the test assertion is
        // that the call succeeds (no panic, no Err). Output-shape
        // contract is enforced by the all-variants test that mirrors
        // the Value construction.
        render_plan_json(&plan, false)
    }

    #[test]
    fn render_plan_with_warnings_does_not_panic() -> Result<()> {
        // Warnings tail prints `warning: ...` lines after actions. The
        // assertion is that the function succeeds; the formatted output
        // shape is `warning: WARNING_TEXT` per render_plan body.
        let plan = Plan {
            actions: vec![Action::CreateRunner(fake_runner_plan("a"))],
            warnings: vec![
                "shared user disables isolation".into(),
                "memory_max in defaults overridden by runner".into(),
            ],
        };
        render_plan(&plan, ColorMode { enabled: false }, false, false, false)
    }

    // ColorMode::from_cli — the no_color flag branch is testable
    // structurally; the env var + TTY branches require std::env mutation
    // (forbidden under unsafe_code = "forbid" since Rust 2024).
    #[test]
    fn color_mode_from_cli_no_color_flag_disables_ansi() {
        let mode = ColorMode::from_cli(true);
        assert!(
            !mode.enabled,
            "--no-color must force ANSI output off regardless of env / TTY"
        );
    }

    #[test]
    fn render_action_line_create_cache_pool_color_path_emits_green() {
        // CreateCachePool also gets the green ANSI prefix (matches
        // CreateRunner). Without color, no escapes.
        let action = Action::CreateCachePool(plan::CachePoolPlan {
            binding: fake_cache_binding("build"),
            drop_in_body: String::new(),
            spec_hash: "sha256:0".into(),
        });
        let plain = render_action_line(&action, ColorMode { enabled: false }, false);
        assert!(!plain.contains("\x1b["), "no ANSI without color");
        let colored = render_action_line(&action, ColorMode { enabled: true }, false);
        assert!(colored.contains("\x1b[32m"), "expected green ANSI prefix");
        assert!(colored.contains("\x1b[0m"), "expected ANSI reset");
    }

    #[test]
    fn render_action_line_update_cache_pool_color_path_emits_yellow() {
        let action = Action::UpdateCachePool(plan::CachePoolDelta {
            binding: fake_cache_binding("build"),
            drop_in_body: String::new(),
            spec_hash: "sha256:0".into(),
        });
        let plain = render_action_line(&action, ColorMode { enabled: false }, false);
        assert!(!plain.contains("\x1b["));
        let colored = render_action_line(&action, ColorMode { enabled: true }, false);
        assert!(colored.contains("\x1b[33m"), "expected yellow ANSI prefix");
        assert!(colored.contains("\x1b[0m"));
    }

    #[test]
    fn render_action_line_remove_cache_pool_color_path_emits_red() {
        let action = Action::RemoveCachePool("build".into());
        let plain = render_action_line(&action, ColorMode { enabled: false }, false);
        assert!(!plain.contains("\x1b["));
        let colored = render_action_line(&action, ColorMode { enabled: true }, false);
        assert!(colored.contains("\x1b[31m"), "expected red ANSI prefix");
        assert!(colored.contains("\x1b[0m"));
    }

    #[test]
    fn render_action_line_update_runner_color_path_emits_yellow() {
        // Update is yellow regardless of recreate-vs-in-place.
        let delta = plan::RunnerDelta {
            identity: fake_identity("buckos"),
            after: fake_runner_plan("buckos"),
            requires_recreate: false,
            recreate_reasons: vec![],
            drift_cause: plan::DriftCause::DriftDetected,
            field_changes: Vec::new(),
            drop_in_changes: Vec::new(),
            before_caches: None,
            before_drop_in_basenames: None,
        };
        let colored = render_action_line(
            &Action::UpdateRunner(delta),
            ColorMode { enabled: true },
            false,
        );
        assert!(colored.contains("\x1b[33m"), "expected yellow ANSI prefix");
    }

    #[test]
    fn render_plan_json_create_runner_kind_label_is_create_runner() {
        // Per-variant JSON shape pin (operator-facing API contract).
        // Constructs a plan with each variant in turn and confirms
        // the kind discriminator. (Full-plan version exists at
        // render_plan_json_emits_action_array_per_variant; these
        // smaller per-variant tests fail with a clearer signal when
        // a single variant's shape regresses.)
        let plan = Plan {
            actions: vec![Action::CreateRunner(fake_runner_plan("a"))],
            warnings: vec![],
        };
        let v = plan_to_json_value(&plan, false);
        let actions = v["actions"].as_array().expect("actions array");
        assert_eq!(actions.len(), 1);
        assert_eq!(actions[0]["kind"], "create_runner");
        assert_eq!(actions[0]["name"], "a");
        assert!(actions[0]["url"].is_string());
        assert!(actions[0]["spec_hash"]
            .as_str()
            .unwrap()
            .starts_with("sha256:"));
    }

    #[test]
    fn render_plan_json_remove_runner_kind_label_is_remove_runner() {
        let plan = Plan {
            actions: vec![Action::RemoveRunner(fake_identity("legacy"))],
            warnings: vec![],
        };
        let v = plan_to_json_value(&plan, false);
        let actions = v["actions"].as_array().unwrap();
        assert_eq!(actions[0]["kind"], "remove_runner");
        assert_eq!(actions[0]["name"], "legacy");
    }

    #[test]
    fn render_plan_json_create_cache_pool_kind_label() {
        let plan = Plan {
            actions: vec![Action::CreateCachePool(plan::CachePoolPlan {
                binding: fake_cache_binding("build"),
                drop_in_body: String::new(),
                spec_hash: "sha256:0".into(),
            })],
            warnings: vec![],
        };
        let v = plan_to_json_value(&plan, false);
        let actions = v["actions"].as_array().unwrap();
        assert_eq!(actions[0]["kind"], "create_cache_pool");
        assert_eq!(actions[0]["name"], "build");
    }

    #[test]
    fn render_plan_json_update_cache_pool_kind_label() {
        let plan = Plan {
            actions: vec![Action::UpdateCachePool(plan::CachePoolDelta {
                binding: fake_cache_binding("build"),
                drop_in_body: String::new(),
                spec_hash: "sha256:0".into(),
            })],
            warnings: vec![],
        };
        let v = plan_to_json_value(&plan, false);
        let actions = v["actions"].as_array().unwrap();
        assert_eq!(actions[0]["kind"], "update_cache_pool");
    }

    #[test]
    fn render_plan_json_remove_cache_pool_kind_label() {
        let plan = Plan {
            actions: vec![Action::RemoveCachePool("build".into())],
            warnings: vec![],
        };
        let v = plan_to_json_value(&plan, false);
        let actions = v["actions"].as_array().unwrap();
        assert_eq!(actions[0]["kind"], "remove_cache_pool");
        assert_eq!(actions[0]["name"], "build");
    }

    #[test]
    fn render_plan_json_update_runner_emits_field_changes_and_drop_in_changes() {
        // BATCH C / PART 6: JSON output must surface
        // RunnerDelta.field_changes and RunnerDelta.drop_in_changes so
        // CI / dashboard consumers can render the same per-field
        // detail the text path renders. drop_in_changes carries one
        // entry per basename in the union of rendered + discovered
        // drop-ins (including Preserved — JSON consumers may want to
        // render the audit trail), each tagged with a `change_kind`
        // string (#305 — distinct from the per-action `kind`).
        let plan = Plan {
            actions: vec![Action::UpdateRunner(plan::RunnerDelta {
                identity: fake_identity("buckos"),
                after: fake_runner_plan("buckos"),
                requires_recreate: true,
                recreate_reasons: vec!["url"],
                drift_cause: plan::DriftCause::SpecChanged,
                field_changes: vec![plan::FieldChange {
                    path: "url",
                    before: plan::FieldValue::String("before".into()),
                    after: plan::FieldValue::String("after".into()),
                }],
                drop_in_changes: vec![
                    plan::DropInChange {
                        basename: "10-memory.conf".into(),
                        change: plan::DropInChangeKind::Modified {
                            before: "old".into(),
                            after: "new".into(),
                        },
                    },
                    plan::DropInChange {
                        basename: "15-resolv.conf".into(),
                        change: plan::DropInChangeKind::Preserved,
                    },
                ],
                before_caches: None,
                before_drop_in_basenames: None,
            })],
            warnings: vec![],
        };
        let v = plan_to_json_value(&plan, false);
        // #574: assert schema_version on the full-payload smoke test
        // so a renderer-level bump can't bypass the dedicated
        // `plan_to_json_value_emits_schema_version_at_top_level` pin.
        assert_eq!(v["schema_version"], "2");
        let action = &v["actions"][0];
        assert_eq!(action["kind"], "update_runner");

        let fcs = action["field_changes"].as_array().unwrap();
        assert_eq!(fcs.len(), 1);
        assert_eq!(fcs[0]["path"], "url");
        // #463 schema v2: `before`/`after` are tagged FieldValue
        // objects ({"type": "string", "value": ..} for scalars,
        // {"type": "list", "values": [..]} for lists).
        assert_eq!(fcs[0]["before"]["type"], "string");
        assert_eq!(fcs[0]["before"]["value"], "before");
        assert_eq!(fcs[0]["after"]["type"], "string");
        assert_eq!(fcs[0]["after"]["value"], "after");

        let dics = action["drop_in_changes"].as_array().unwrap();
        assert_eq!(dics.len(), 2);
        assert_eq!(dics[0]["basename"], "10-memory.conf");
        // #305: inner discriminator is `change_kind`, distinct from
        // the per-action `kind`, so JSON consumers can disambiguate
        // without context.
        assert_eq!(dics[0]["change_kind"], "modified");
        assert_eq!(dics[1]["basename"], "15-resolv.conf");
        assert_eq!(dics[1]["change_kind"], "preserved");
        // Drop-in body content (`before`, `after`) is intentionally
        // NOT in the JSON — full body diff is reserved for --diff.
        assert!(
            dics[0].get("before").is_none(),
            "no body diff in basic JSON"
        );
        assert!(dics[0].get("after").is_none(), "no body diff in basic JSON");
    }

    /// #463 T-1: pin the List-typed FieldValue JSON shape end-to-end.
    /// Symmetric with the String-typed pin in
    /// `render_plan_json_update_runner_emits_field_changes_and_drop_in_changes` —
    /// catches drift where a renderer change accidentally collapses
    /// `{"type": "list", "values": [...]}` into a bare array or
    /// reuses the scalar `value` key for List entries.
    #[test]
    fn render_plan_json_update_runner_emits_typed_list_field_value_for_labels() {
        let delta = plan::RunnerDelta {
            identity: fake_identity("buckos"),
            after: fake_runner_plan("buckos"),
            requires_recreate: true,
            recreate_reasons: vec!["labels"],
            drift_cause: plan::DriftCause::SpecChanged,
            field_changes: vec![plan::FieldChange {
                path: "labels",
                before: plan::FieldValue::List(vec!["ci".into()]),
                after: plan::FieldValue::List(vec!["ci".into(), "gpu".into()]),
            }],
            drop_in_changes: Vec::new(),
            before_caches: None,
            before_drop_in_basenames: None,
        };
        let plan = Plan {
            actions: vec![Action::UpdateRunner(delta)],
            warnings: vec![],
        };
        let v = plan_to_json_value(&plan, false);
        let fcs = v["actions"][0]["field_changes"].as_array().unwrap();
        assert_eq!(fcs.len(), 1);
        let fc = &fcs[0];
        assert_eq!(fc["path"], "labels");
        // Tagged list shape: `type: "list"`, `values: [..]`.
        assert_eq!(fc["before"]["type"], "list");
        assert_eq!(fc["after"]["type"], "list");
        let before_values = fc["before"]["values"]
            .as_array()
            .expect("List variant must carry `values` array");
        let after_values = fc["after"]["values"]
            .as_array()
            .expect("List variant must carry `values` array");
        assert_eq!(before_values, &vec![serde_json::json!("ci")]);
        assert_eq!(
            after_values,
            &vec![serde_json::json!("ci"), serde_json::json!("gpu")],
        );
        // List variants MUST NOT emit the scalar `value` key.
        assert!(
            fc["before"].get("value").is_none(),
            "List variant must not carry scalar `value` key, got: {}",
            fc["before"],
        );
        assert!(
            fc["after"].get("value").is_none(),
            "List variant must not carry scalar `value` key, got: {}",
            fc["after"],
        );
    }

    #[test]
    fn render_plan_json_noop_kind_label_with_reason() {
        let plan = Plan {
            actions: vec![Action::NoOp("a: in sync".into())],
            warnings: vec![],
        };
        let v = plan_to_json_value(&plan, false);
        let actions = v["actions"].as_array().unwrap();
        assert_eq!(actions[0]["kind"], "noop");
        assert_eq!(actions[0]["reason"], "a: in sync");
    }

    #[test]
    fn render_plan_json_warnings_array_includes_each_string() {
        let plan = Plan {
            actions: vec![],
            warnings: vec!["w1".into(), "w2".into(), "w3".into()],
        };
        let v = plan_to_json_value(&plan, false);
        let warnings = v["warnings"].as_array().unwrap();
        assert_eq!(warnings.len(), 3);
        assert_eq!(warnings[0], "w1");
        assert_eq!(warnings[1], "w2");
        assert_eq!(warnings[2], "w3");
    }

    #[test]
    fn render_plan_json_no_token_or_secret_keys() {
        // F27 contract: secrets never appear in either format. We feed
        // a plan with auth + cache references and assert the JSON keys
        // are bounded by the documented set.
        let plan = Plan {
            actions: vec![
                Action::CreateRunner(fake_runner_plan("a")),
                Action::UpdateRunner(plan::RunnerDelta {
                    identity: fake_identity("b"),
                    after: fake_runner_plan("b"),
                    requires_recreate: true,
                    recreate_reasons: vec!["url"],
                    drift_cause: plan::DriftCause::SpecChanged,
                    field_changes: Vec::new(),
                    drop_in_changes: Vec::new(),
                    before_caches: None,
                    before_drop_in_basenames: None,
                }),
            ],
            warnings: vec![],
        };
        let serialized = serde_json::to_string(&plan_to_json_value(&plan, false)).unwrap();
        for forbidden in ["token", "secret", "private_key", "password"] {
            assert!(
                !serialized.contains(forbidden),
                "JSON must not leak `{forbidden}`: {serialized}"
            );
        }
    }

    // ---------- #242: cmd_init mode + cmd_add labels coverage --------

    #[test]
    fn cmd_init_returns_zero_and_writes_canonical_body() {
        // Positive path: init with a fresh path lands the verbatim
        // INIT_EXAMPLE_CONFIG and returns rc=0.
        let tmp = tempfile::tempdir().unwrap();
        let config_path = Utf8PathBuf::from_path_buf(tmp.path().to_path_buf())
            .unwrap()
            .join("ghars.toml");
        let rc = cmd_init(&config_path, &InitArgs { output: None }, true).unwrap();
        assert_eq!(rc, 0);
        let body = fs::read_to_string(config_path.as_std_path()).unwrap();
        assert_eq!(body, INIT_EXAMPLE_CONFIG);
        assert!(body.contains("# ghars config"));
        // OWNER/REPO placeholder (#263).
        assert!(body.contains("OWNER/REPO"));
        // Per-runner SEC-27 hint.
        assert!(body.contains("SEC-27"));
    }

    #[test]
    fn cmd_init_output_override_writes_to_alt_path_not_global() {
        // When `--output` is set, the global --config path stays
        // untouched. This pins the override semantics so a future
        // refactor can't silently use --config when --output is set.
        let tmp = tempfile::tempdir().unwrap();
        let global_path = Utf8PathBuf::from_path_buf(tmp.path().to_path_buf())
            .unwrap()
            .join("ghars.toml");
        let alt_path = Utf8PathBuf::from_path_buf(tmp.path().to_path_buf())
            .unwrap()
            .join("alt.toml");
        let args = InitArgs {
            output: Some(alt_path.clone()),
        };
        cmd_init(&global_path, &args, true).unwrap();
        assert!(alt_path.exists(), "--output path must exist");
        assert!(!global_path.exists(), "--config path must stay untouched");
    }

    #[test]
    fn cmd_add_appends_labels_when_provided() {
        // Labels list must round-trip into the [[runner]] block.
        let tmp = tempfile::tempdir().unwrap();
        let config_path = Utf8PathBuf::from_path_buf(tmp.path().to_path_buf())
            .unwrap()
            .join("ghars.toml");
        write_minimal_config(&config_path);
        let paths = Paths::default();
        let args = AddArgs {
            repo: "owner/repo".into(),
            name: Some("owner-repo-1".into()),
            labels: vec!["x64".into(), "self-hosted".into()],
            auth: Some("pat".into()),
            no_apply: true,
        };
        let rc = cmd_add(
            &config_path,
            &paths,
            &args,
            ColorMode { enabled: false },
            true,
        )
        .unwrap();
        assert_eq!(rc, 0);
        let after = fs::read_to_string(config_path.as_std_path()).unwrap();
        assert!(after.contains("labels = [\"x64\", \"self-hosted\"]"));
    }

    #[test]
    fn cmd_add_omits_auth_when_match_defaults() {
        // When --auth matches defaults.auth the appended block omits
        // the `auth = ...` line (avoids redundant overrides cluttering
        // the operator's config).
        let tmp = tempfile::tempdir().unwrap();
        let config_path = Utf8PathBuf::from_path_buf(tmp.path().to_path_buf())
            .unwrap()
            .join("ghars.toml");
        // Config has defaults.auth = "pat", which matches the --auth.
        let body = "\
[defaults]
prefix = \"/var/lib/ghars\"
auth = \"pat\"

[auth.pat]
kind = \"pat\"
token_env = \"GHARS_PAT\"
";
        fs::write(config_path.as_std_path(), body).unwrap();
        let paths = Paths::default();
        let args = AddArgs {
            repo: "owner/repo".into(),
            name: Some("owner-repo-1".into()),
            labels: vec![],
            auth: Some("pat".into()),
            no_apply: true,
        };
        cmd_add(
            &config_path,
            &paths,
            &args,
            ColorMode { enabled: false },
            true,
        )
        .unwrap();
        let after = fs::read_to_string(config_path.as_std_path()).unwrap();
        // The added block should not duplicate `auth = "pat"` since
        // it matches defaults.
        let added_block = after.split("[[runner]]").nth(1).unwrap_or("");
        assert!(
            !added_block.contains("auth = "),
            "auth match-defaults should not write redundant `auth = ...`: \n{added_block}"
        );
    }

    // ---------- #242 follow-up: gap-filling cmd_init/cmd_add tests ----

    #[test]
    fn cmd_init_creates_parent_dir_when_missing() {
        // dest.parent() doesn't exist → create_dir_all. Operator runs
        // `ghars init --output /etc/ghars-new/ghars.toml` on a host
        // with no /etc/ghars-new yet; the command must create the dir
        // tree, not error out.
        let tmp = tempfile::tempdir().unwrap();
        let nested = Utf8PathBuf::from_path_buf(tmp.path().to_path_buf())
            .unwrap()
            .join("a")
            .join("b")
            .join("c")
            .join("ghars.toml");
        // Sanity: the parent didn't exist before the call.
        assert!(!nested.parent().unwrap().exists());
        cmd_init(
            &Utf8PathBuf::from("/never-used"),
            &InitArgs {
                output: Some(nested.clone()),
            },
            true,
        )
        .unwrap();
        assert!(nested.exists(), "config file landed at the nested path");
    }

    #[test]
    fn init_example_config_content_invariants() {
        // Pin the load-bearing fields of INIT_EXAMPLE_CONFIG so a
        // future edit can't silently drop them. Each invariant maps
        // to operator-visible behavior: prefix is the per-runner home
        // root, GHARS_PAT is the documented env var name, x86_64 is
        // the v0.1 default arch, [auth.pat] is the placeholder block
        // operators reference from [defaults].auth.
        assert!(INIT_EXAMPLE_CONFIG.contains("prefix = \"/var/lib/ghars\""));
        assert!(INIT_EXAMPLE_CONFIG.contains("runner_version = \""));
        assert!(INIT_EXAMPLE_CONFIG.contains("token_env = \"GHARS_PAT\""));
        assert!(INIT_EXAMPLE_CONFIG.contains("arch = \"x86_64\""));
        assert!(INIT_EXAMPLE_CONFIG.contains("[auth.pat]"));
        assert!(INIT_EXAMPLE_CONFIG.contains("kind = \"pat\""));
        // SEC-27 hint must remain so operators don't paste a shared
        // user= line back in by mistake.
        assert!(INIT_EXAMPLE_CONFIG.contains("SEC-27"));
        // Personal-fork URL must not appear (#263).
        assert!(!INIT_EXAMPLE_CONFIG.contains("likewhatevs"));
        assert!(INIT_EXAMPLE_CONFIG.contains("OWNER/REPO"));
    }

    #[test]
    fn cmd_add_auto_name_first_index_when_no_existing_runners() {
        // No runners → owner-repo-1 (auto-numbered).
        let tmp = tempfile::tempdir().unwrap();
        let config_path = Utf8PathBuf::from_path_buf(tmp.path().to_path_buf())
            .unwrap()
            .join("ghars.toml");
        write_minimal_config(&config_path);
        let paths = Paths::default();
        let args = AddArgs {
            repo: "owner/repo".into(),
            name: None,
            labels: vec![],
            auth: Some("pat".into()),
            no_apply: true,
        };
        cmd_add(
            &config_path,
            &paths,
            &args,
            ColorMode { enabled: false },
            true,
        )
        .unwrap();
        let after = fs::read_to_string(config_path.as_std_path()).unwrap();
        assert!(after.contains("name = \"owner-repo-1\""), "got:\n{after}");
    }

    #[test]
    fn cmd_add_auto_name_next_index_when_first_taken() {
        // owner-repo-1 already exists → owner-repo-2.
        let tmp = tempfile::tempdir().unwrap();
        let config_path = Utf8PathBuf::from_path_buf(tmp.path().to_path_buf())
            .unwrap()
            .join("ghars.toml");
        let body = "\
[defaults]
prefix = \"/var/lib/ghars\"

[auth.pat]
kind = \"pat\"
token_env = \"GHARS_PAT\"

[[runner]]
name = \"owner-repo-1\"
url = \"https://github.com/owner/repo\"
auth = \"pat\"
";
        fs::write(config_path.as_std_path(), body).unwrap();
        let paths = Paths::default();
        let args = AddArgs {
            repo: "owner/repo".into(),
            name: None,
            labels: vec![],
            auth: Some("pat".into()),
            no_apply: true,
        };
        cmd_add(
            &config_path,
            &paths,
            &args,
            ColorMode { enabled: false },
            true,
        )
        .unwrap();
        let after = fs::read_to_string(config_path.as_std_path()).unwrap();
        // The new block uses owner-repo-2 (the first free index).
        assert!(
            after.contains("name = \"owner-repo-2\""),
            "expected next-free-index name; got:\n{after}"
        );
        // The original owner-repo-1 block is intact.
        assert_eq!(after.matches("name = \"owner-repo-1\"").count(), 1);
    }

    #[test]
    fn cmd_add_writes_auth_line_when_args_auth_differs_from_defaults() {
        // defaults.auth = "pat" but --auth = "secondary" → the new
        // block writes auth = "secondary" because it diverges from
        // the inherited default.
        let tmp = tempfile::tempdir().unwrap();
        let config_path = Utf8PathBuf::from_path_buf(tmp.path().to_path_buf())
            .unwrap()
            .join("ghars.toml");
        let body = "\
[defaults]
prefix = \"/var/lib/ghars\"
auth = \"pat\"

[auth.pat]
kind = \"pat\"
token_env = \"GHARS_PAT\"

[auth.secondary]
kind = \"interactive\"
";
        fs::write(config_path.as_std_path(), body).unwrap();
        let paths = Paths::default();
        let args = AddArgs {
            repo: "owner/repo".into(),
            name: Some("owner-repo-1".into()),
            labels: vec![],
            auth: Some("secondary".into()),
            no_apply: true,
        };
        cmd_add(
            &config_path,
            &paths,
            &args,
            ColorMode { enabled: false },
            true,
        )
        .unwrap();
        let after = fs::read_to_string(config_path.as_std_path()).unwrap();
        let added_block = after.split("[[runner]]").last().unwrap_or("");
        assert!(
            added_block.contains("auth = \"secondary\""),
            "auth-differs-from-defaults must write the override line:\n{added_block}"
        );
    }

    #[test]
    fn cmd_add_omits_labels_line_when_empty() {
        // labels=[] → the appended block does NOT include a
        // `labels = []` line. Keeps the operator's TOML clean.
        let tmp = tempfile::tempdir().unwrap();
        let config_path = Utf8PathBuf::from_path_buf(tmp.path().to_path_buf())
            .unwrap()
            .join("ghars.toml");
        write_minimal_config(&config_path);
        let paths = Paths::default();
        let args = AddArgs {
            repo: "owner/repo".into(),
            name: Some("owner-repo-1".into()),
            labels: vec![],
            auth: Some("pat".into()),
            no_apply: true,
        };
        cmd_add(
            &config_path,
            &paths,
            &args,
            ColorMode { enabled: false },
            true,
        )
        .unwrap();
        let after = fs::read_to_string(config_path.as_std_path()).unwrap();
        let added_block = after.split("[[runner]]").last().unwrap_or("");
        assert!(
            !added_block.contains("labels ="),
            "empty labels list must not emit a labels= line:\n{added_block}"
        );
    }

    #[test]
    fn cmd_add_url_strips_leading_slash_from_repo() {
        // args.repo = "/owner/repo" → trim_start_matches('/') → URL
        // is https://github.com/owner/repo (no leading slash, no `//`).
        let tmp = tempfile::tempdir().unwrap();
        let config_path = Utf8PathBuf::from_path_buf(tmp.path().to_path_buf())
            .unwrap()
            .join("ghars.toml");
        write_minimal_config(&config_path);
        let paths = Paths::default();
        let args = AddArgs {
            repo: "/owner/repo".into(),
            name: Some("owner-repo-1".into()),
            labels: vec![],
            auth: Some("pat".into()),
            no_apply: true,
        };
        cmd_add(
            &config_path,
            &paths,
            &args,
            ColorMode { enabled: false },
            true,
        )
        .unwrap();
        let after = fs::read_to_string(config_path.as_std_path()).unwrap();
        assert!(
            after.contains("url = \"https://github.com/owner/repo\""),
            "leading slash must be stripped; got:\n{after}"
        );
        assert!(
            !after.contains("https://github.com//"),
            "double slash must not appear in URL:\n{after}"
        );
    }

    #[test]
    fn cmd_add_appends_newline_when_existing_file_lacks_one() {
        // Edge case: existing config doesn't end with `\n`. cmd_add
        // must push a newline before the [[runner]] block so the new
        // block doesn't run into the previous line.
        let tmp = tempfile::tempdir().unwrap();
        let config_path = Utf8PathBuf::from_path_buf(tmp.path().to_path_buf())
            .unwrap()
            .join("ghars.toml");
        // Note: NO trailing newline.
        let body = "\
[defaults]
prefix = \"/var/lib/ghars\"

[auth.pat]
kind = \"pat\"
token_env = \"GHARS_PAT\"";
        fs::write(config_path.as_std_path(), body).unwrap();
        let paths = Paths::default();
        let args = AddArgs {
            repo: "owner/repo".into(),
            name: Some("owner-repo-1".into()),
            labels: vec![],
            auth: Some("pat".into()),
            no_apply: true,
        };
        cmd_add(
            &config_path,
            &paths,
            &args,
            ColorMode { enabled: false },
            true,
        )
        .unwrap();
        let after = fs::read_to_string(config_path.as_std_path()).unwrap();
        // The trailing `token_env = "GHARS_PAT"` line + the new
        // [[runner]] block must not be on the same line.
        assert!(
            !after.contains("token_env = \"GHARS_PAT\"[[runner]]"),
            "missing newline between original tail and appended block:\n{after}"
        );
        // And the appended block lands.
        assert!(after.contains("[[runner]]"));
        assert!(after.contains("name = \"owner-repo-1\""));
    }

    // ---------- #260: drift_cause label coverage ----------------------

    #[test]
    fn drift_cause_labels_cover_each_variant() {
        assert_eq!(plan::DriftCause::SpecChanged.label(), "spec_changed");
        assert_eq!(plan::DriftCause::DriftDetected.label(), "drift_detected");
        assert_eq!(
            plan::DriftCause::SpecChangedAndDriftDetected.label(),
            "spec_changed_and_drift_detected"
        );
    }

    // ---------- #252: cmd_completions / cmd_manpages ------------------

    #[test]
    fn cmd_completions_to_writes_bash_completion_script() {
        // Capture into Vec<u8> via the test seam. Bash completions
        // begin with `_ghars()` (the bash function definition that
        // clap_complete emits as the entry point).
        let mut buf: Vec<u8> = Vec::new();
        cmd_completions_to(clap_complete::Shell::Bash, &mut buf);
        let text = String::from_utf8(buf).expect("bash completion is utf-8");
        assert!(
            text.contains("_ghars()"),
            "bash completion missing _ghars(): {}",
            &text[..text.len().min(200)]
        );
        // The completion script must reference at least one
        // subcommand so a regression that drops the subcommand
        // tree surfaces here.
        assert!(text.contains("apply"), "bash completion missing 'apply'");
    }

    #[test]
    fn cmd_completions_to_writes_zsh_completion_script() {
        // Zsh completions begin with `#compdef ghars`.
        let mut buf: Vec<u8> = Vec::new();
        cmd_completions_to(clap_complete::Shell::Zsh, &mut buf);
        let text = String::from_utf8(buf).expect("zsh completion is utf-8");
        assert!(
            text.contains("#compdef ghars"),
            "zsh completion missing #compdef header"
        );
    }

    #[test]
    fn cmd_completions_to_writes_fish_completion_script() {
        // Fish completions use `complete -c ghars`.
        let mut buf: Vec<u8> = Vec::new();
        cmd_completions_to(clap_complete::Shell::Fish, &mut buf);
        let text = String::from_utf8(buf).expect("fish completion is utf-8");
        assert!(
            text.contains("complete -c ghars"),
            "fish completion missing 'complete -c ghars' marker"
        );
    }

    #[test]
    fn cmd_completions_to_writes_powershell_completion_script() {
        // PowerShell completions use `Register-ArgumentCompleter`.
        let mut buf: Vec<u8> = Vec::new();
        cmd_completions_to(clap_complete::Shell::PowerShell, &mut buf);
        let text = String::from_utf8(buf).expect("pwsh completion is utf-8");
        assert!(
            text.contains("Register-ArgumentCompleter"),
            "powershell completion missing 'Register-ArgumentCompleter'"
        );
        assert!(
            text.contains("'ghars'"),
            "powershell completion missing 'ghars' command name"
        );
    }

    #[test]
    fn cmd_completions_to_writes_elvish_completion_script() {
        // Elvish completions use `set edit:completion:arg-completer`.
        let mut buf: Vec<u8> = Vec::new();
        cmd_completions_to(clap_complete::Shell::Elvish, &mut buf);
        let text = String::from_utf8(buf).expect("elvish completion is utf-8");
        assert!(
            text.contains("edit:completion:arg-completer"),
            "elvish completion missing 'edit:completion:arg-completer'"
        );
        assert!(
            text.contains("ghars"),
            "elvish completion missing 'ghars' command name"
        );
    }

    #[test]
    fn cmd_manpages_creates_missing_output_directory() {
        // Pass a non-existent path inside tempdir. cmd_manpages must
        // call `fs::create_dir_all` and produce the man page tree.
        let dir = tempfile::tempdir().unwrap();
        let nested = dir.path().join("does").join("not").join("exist");
        let out = Utf8PathBuf::from_path_buf(nested.clone()).unwrap();
        assert!(!nested.exists(), "precondition: target must not exist");
        let exit = cmd_manpages(&out).unwrap();
        assert_eq!(exit, 0);
        assert!(
            nested.exists() && nested.is_dir(),
            "cmd_manpages must create the output directory"
        );
        assert!(
            out.join("ghars.1").as_std_path().exists(),
            "top-level manpage missing in created dir"
        );
    }

    #[test]
    fn cmd_manpages_top_level_body_contains_troff_header() {
        // The manpage body emitted by clap_mangen begins with a
        // `.TH "GHARS" "1" ...` header line (troff title-header).
        // Pin the macro name + section number so a future
        // clap_mangen output regression that drops the header
        // (producing an unrenderable manpage that `man` can't parse)
        // surfaces here.
        let dir = tempfile::tempdir().unwrap();
        let out = Utf8PathBuf::from_path_buf(dir.path().to_path_buf()).unwrap();
        cmd_manpages(&out).unwrap();
        let body = std::fs::read_to_string(out.join("ghars.1").as_std_path()).unwrap();
        assert!(
            body.contains(".TH ghars 1"),
            "manpage missing .TH ghars 1 troff header: preview {}",
            &body[..body.len().min(300)]
        );
        // The NAME section follows immediately after .TH per troff
        // convention; pin so clap_mangen reorderings surface here.
        assert!(
            body.contains(".SH NAME"),
            "manpage missing .SH NAME section: preview {}",
            &body[..body.len().min(300)]
        );
    }

    #[test]
    fn cmd_manpages_writes_top_level_and_per_subcommand_files() {
        let dir = tempfile::tempdir().unwrap();
        let out = Utf8PathBuf::from_path_buf(dir.path().to_path_buf()).unwrap();
        let exit = cmd_manpages(&out).unwrap();
        assert_eq!(exit, 0);
        // Top-level page must exist.
        let top = out.join("ghars.1");
        assert!(
            top.as_std_path().exists(),
            "top-level manpage missing: {top}"
        );
        // Each visible subcommand also gets a `ghars-NAME.1` file.
        // Pick a few that are stable in v0.1.
        for sub in ["apply", "plan", "status", "init", "validate"] {
            let path = out.join(format!("ghars-{sub}.1"));
            assert!(
                path.as_std_path().exists(),
                "missing manpage for `{sub}`: {path}"
            );
        }
        // Hidden subcommands must NOT be emitted (the loop in
        // cmd_manpages skips `is_hide_set()`).
        let hidden = out.join("ghars-_netns-setup.1");
        assert!(
            !hidden.as_std_path().exists(),
            "hidden subcommand should not have a manpage: {hidden}"
        );
        // The body of the top-level manpage must mention the binary
        // name in nroff format. This kills a mutant that writes an
        // empty file.
        let body = std::fs::read_to_string(top.as_std_path()).unwrap();
        assert!(
            body.contains("ghars"),
            "manpage body missing 'ghars': preview {}",
            &body[..body.len().min(200)]
        );
    }

    // ---------- #257: dispatch routing parses every Command variant ----
    //
    // The `dispatch` function itself touches systemd / D-Bus / netns
    // helpers, so it can't be invoked directly in unit tests. The
    // testable obligation is that EVERY Command variant has an argv
    // shape that parses correctly and produces the expected
    // Command::* discriminant. An exhaustive match in the test body
    // ensures that adding a new variant without a parse test fails
    // the compile (the `match cli.command` would emit a
    // non-exhaustive-pattern error).

    fn parse_command(argv: &[&str]) -> Command {
        Cli::try_parse_from(argv).unwrap().command
    }

    #[test]
    fn dispatch_routing_validate() {
        assert!(matches!(
            parse_command(&["ghars", "validate"]),
            Command::Validate(_)
        ));
    }

    #[test]
    fn dispatch_routing_plan() {
        assert!(matches!(
            parse_command(&["ghars", "plan"]),
            Command::Plan(_)
        ));
    }

    #[test]
    fn dispatch_routing_apply() {
        assert!(matches!(
            parse_command(&["ghars", "apply"]),
            Command::Apply(_)
        ));
    }

    #[test]
    fn dispatch_routing_status() {
        assert!(matches!(
            parse_command(&["ghars", "status"]),
            Command::Status(_)
        ));
    }

    #[test]
    fn dispatch_routing_init() {
        assert!(matches!(
            parse_command(&["ghars", "init"]),
            Command::Init(_)
        ));
    }

    #[test]
    fn dispatch_routing_add() {
        assert!(matches!(
            parse_command(&["ghars", "add", "--repo", "owner/repo", "--auth", "pat",]),
            Command::Add(_)
        ));
    }

    #[test]
    fn dispatch_routing_logs() {
        assert!(matches!(
            parse_command(&["ghars", "logs"]),
            Command::Logs(_)
        ));
    }

    #[test]
    fn dispatch_routing_metrics() {
        assert!(matches!(
            parse_command(&["ghars", "metrics"]),
            Command::Metrics(_)
        ));
    }

    #[test]
    fn dispatch_routing_completions() {
        let cmd = parse_command(&["ghars", "completions", "bash"]);
        match cmd {
            Command::Completions { shell } => {
                assert!(matches!(shell, clap_complete::Shell::Bash));
            }
            other => panic!("expected Command::Completions, got {other:?}"),
        }
    }

    #[test]
    fn dispatch_routing_manpages() {
        let cmd = parse_command(&["ghars", "manpages", "/tmp/man-out"]);
        match cmd {
            Command::Manpages { output } => {
                assert_eq!(output, Utf8PathBuf::from("/tmp/man-out"));
            }
            other => panic!("expected Command::Manpages, got {other:?}"),
        }
    }

    #[test]
    fn dispatch_routing_netns_setup_hidden() {
        let cmd = parse_command(&["ghars", "_netns-setup", "buckos"]);
        match cmd {
            Command::NetnsSetup { instance } => assert_eq!(instance, "buckos"),
            other => panic!("expected Command::NetnsSetup, got {other:?}"),
        }
    }

    #[test]
    fn dispatch_routing_netns_teardown_hidden() {
        let cmd = parse_command(&["ghars", "_netns-teardown", "buckos"]);
        match cmd {
            Command::NetnsTeardown { instance } => assert_eq!(instance, "buckos"),
            other => panic!("expected Command::NetnsTeardown, got {other:?}"),
        }
    }

    #[test]
    fn dispatch_routing_netns_veth_hidden() {
        let cmd = parse_command(&[
            "ghars",
            "_netns-veth",
            "buckos",
            "/usr/sbin/nft",
            "-f",
            "/etc/ghars/nft.d/buckos-ns.nft",
        ]);
        match cmd {
            Command::NetnsVeth { instance, program } => {
                assert_eq!(instance, "buckos");
                assert_eq!(
                    program,
                    vec!["/usr/sbin/nft", "-f", "/etc/ghars/nft.d/buckos-ns.nft",]
                );
            }
            other => panic!("expected Command::NetnsVeth, got {other:?}"),
        }
    }

    /// Compile-time exhaustiveness gate: this test fails to COMPILE
    /// if a new Command variant is added without extending the
    /// dispatch_routing_* test suite. The match must list every
    /// variant by name so the rustc non-exhaustive-pattern error
    /// surfaces during routine `cargo check --tests`.
    #[test]
    fn dispatch_routing_variants_are_exhaustively_tested() {
        // Build one of each variant and pattern-match exhaustively.
        // Adding a new Command variant without updating the match
        // arms causes a compile error here.
        let variants: Vec<Command> = vec![
            parse_command(&["ghars", "validate"]),
            parse_command(&["ghars", "plan"]),
            parse_command(&["ghars", "apply"]),
            parse_command(&["ghars", "status"]),
            parse_command(&["ghars", "init"]),
            parse_command(&["ghars", "add", "--repo", "o/r"]),
            parse_command(&["ghars", "logs"]),
            parse_command(&["ghars", "metrics"]),
            parse_command(&["ghars", "completions", "bash"]),
            parse_command(&["ghars", "manpages", "/tmp/x"]),
            parse_command(&["ghars", "_netns-setup", "x"]),
            parse_command(&["ghars", "_netns-teardown", "x"]),
            parse_command(&["ghars", "_netns-veth", "x", "/bin/true"]),
        ];
        // Verify exhaustively.
        let mut counts = [0usize; 13];
        for v in variants {
            #[allow(clippy::match_same_arms)]
            let idx = match v {
                Command::Validate(_) => 0,
                Command::Plan(_) => 1,
                Command::Apply(_) => 2,
                Command::Status(_) => 3,
                Command::Init(_) => 4,
                Command::Add(_) => 5,
                Command::Logs(_) => 6,
                Command::Metrics(_) => 7,
                Command::Completions { .. } => 8,
                Command::Manpages { .. } => 9,
                Command::NetnsSetup { .. } => 10,
                Command::NetnsTeardown { .. } => 11,
                Command::NetnsVeth { .. } => 12,
            };
            counts[idx] += 1;
        }
        // Exactly one of each variant landed.
        assert_eq!(
            counts, [1; 13],
            "every Command variant must round-trip exactly once: {counts:?}"
        );
    }

    /// dispatch's Completions arm should return Ok(0) — the
    /// `clap_complete::generate` write to stdout is infallible (in
    /// the sense that the writer is `io::stdout()` which doesn't
    /// surface errors back to the caller in this code path), and
    /// the dispatch arm wraps in `Ok(0)` after the call. Pin so a
    /// future refactor that returns the wrong exit code surfaces.
    /// Note: this writes to the test runner's captured stdout.
    #[test]
    fn dispatch_completions_returns_ok_zero() {
        let cli = Cli::try_parse_from(["ghars", "completions", "bash"]).unwrap();
        let exit = dispatch(cli).expect("completions must succeed");
        assert_eq!(exit, 0);
    }

    /// dispatch's NetnsVeth arm propagates `run_in_netns`'s empty-
    /// program rejection. Pins the wiring; complementary to
    /// `netns::tests::run_in_netns_rejects_empty_program` which
    /// covers the helper directly.
    #[test]
    fn dispatch_netns_veth_propagates_empty_program_rejection() {
        // clap's `trailing_var_arg` requires the trailing program
        // arg, but we can synthesize an empty program by hand.
        let cli = Cli {
            config: Utf8PathBuf::from("/etc/ghars/ghars.toml"),
            no_color: false,
            quiet: false,
            verbose: 0,
            command: Command::NetnsVeth {
                instance: "buckos".into(),
                program: Vec::new(),
            },
        };
        let err = dispatch(cli).unwrap_err();
        // run_in_netns surfaces a Validation error; dispatch
        // bubbles it up unwrapped.
        assert!(
            matches!(err, GharsError::Validation(_, _)),
            "expected Validation, got {err:?}"
        );
    }

    // -------- #344/#346: trust_zone charset validator -------------------

    /// Helper for the trust_zone tests: build the minimal Config that
    /// `validate_identity_fields` expects, then mutate the runner /
    /// pool's trust_zone in-place. We bypass `toml::from_str` because
    /// embedding raw `\n` / `\0` in a TOML basic string would also be
    /// rejected by the parser before our validator ran — we want to
    /// prove our validator catches the chars, not that TOML happens to
    /// reject the literal escape sequences.
    fn cfg_with_runner_trust_zone(name: &str, trust_zone: String) -> Config {
        let runner = crate::config::RunnerSpec {
            name: name.into(),
            count: None,
            url: format!("https://github.com/example/{name}"),
            auth: Some("pat".into()),
            labels: Vec::new(),
            memory_max: None,
            runner_version: None,
            runner_sha256: None,
            runner_tarball: None,
            arch: None,
            user: None,
            prefix: None,
            caches: Vec::new(),
            trust_zone,
            network: None,
            proxy: None,
            hooks: None,
            hardening: crate::config::Hardening::default(),
            allowed_cpus: None,
            allowed_memory_nodes: None,
        };
        let mut auth = indexmap::IndexMap::new();
        auth.insert(
            "pat".into(),
            crate::config::AuthSpec::Pat {
                token_env: Some("GHARS_PAT".into()),
                token_file: None,
            },
        );
        Config {
            defaults: crate::config::Defaults::default(),
            auth,
            cache_pools: indexmap::IndexMap::new(),
            networks: indexmap::IndexMap::new(),
            runners: vec![runner],
            proxy: None,
            hooks: None,
        }
    }

    /// #344: a runner.trust_zone containing `\n` must be rejected at
    /// config-load by `validate_identity_fields`. Pre-fix, the only
    /// gate was `render_identity` (#286), which surfaces the error
    /// during `plan` rather than `validate` and without the
    /// `runner "NAME"` scope prefix the operator needs to locate the
    /// offending block.
    #[test]
    fn validate_identity_fields_rejects_runner_trust_zone_with_newline() {
        let cfg = cfg_with_runner_trust_zone("buckos", "secure\nzone".into());
        let err = validate_identity_fields(&cfg).expect_err("must reject newline");
        match err {
            GharsError::Validation(msg, _) => {
                assert!(
                    msg.contains("runner") && msg.contains("buckos"),
                    "msg must scope to the offending runner; got: {msg}"
                );
                assert!(
                    msg.contains("trust_zone") && msg.contains("newline"),
                    "msg must name the field + char class; got: {msg}"
                );
                // #380: config-load gate is NOT render_identity. The
                // bare check_identity_field error must not bake in the
                // render_identity prefix, and validate_identity_fields
                // must not accidentally route through render_identity.
                assert!(
                    !msg.contains("render_identity"),
                    "msg must NOT contain \"render_identity\" prefix at \
                     config-load time; got: {msg}"
                );
                // #380 (FIX 12): the runner scope prefix must be
                // adjacent to `field "trust_zone"` — no infix between
                // them. Catches a regression that re-introduces a
                // function-name prefix between the block scope and
                // the field name.
                assert!(
                    msg.contains("runner \"buckos\": field"),
                    "msg must contain `runner \"buckos\": field` as adjacent \
                     substring (no infix between scope and field); got: {msg}"
                );
            }
            other => panic!("expected GharsError::Validation, got {other:?}"),
        }
    }

    /// #344: a runner.trust_zone containing `\0` (NUL byte) must be
    /// rejected. Pinned alongside the newline test because NUL is a
    /// distinct branch in `check_identity_field`'s NUL-class branch
    /// — a future regression that broadened the newline check but
    /// dropped NUL would slip past the newline-only test.
    #[test]
    fn validate_identity_fields_rejects_runner_trust_zone_with_nul() {
        let cfg = cfg_with_runner_trust_zone("buckos", "zone\0nul".into());
        let err = validate_identity_fields(&cfg).expect_err("must reject NUL byte");
        match err {
            GharsError::Validation(msg, _) => {
                assert!(
                    msg.contains("runner") && msg.contains("buckos"),
                    "msg must scope to the offending runner; got: {msg}"
                );
                assert!(
                    msg.contains("trust_zone") && msg.contains("NUL"),
                    "msg must name the field + char class; got: {msg}"
                );
                // #380: config-load gate must NOT emit "render_identity:" prefix.
                assert!(
                    !msg.contains("render_identity"),
                    "msg must NOT contain \"render_identity\" prefix at \
                     config-load time; got: {msg}"
                );
                // #380 (P2-F2): adjacent-substring pin — runner scope
                // must be directly followed by `field`, no infix.
                assert!(
                    msg.contains("runner \"buckos\": field"),
                    "msg must contain `runner \"buckos\": field` as adjacent \
                     substring (no infix between scope and field); got: {msg}"
                );
            }
            other => panic!("expected GharsError::Validation, got {other:?}"),
        }
    }

    /// #344: a `[cache_pools.NAME].trust_zone` containing `\n` must be
    /// rejected with the `cache_pool "NAME":` scope prefix. The runner
    /// branch is exercised by the two tests above; this test pins the
    /// SECOND iteration in `validate_identity_fields` (the one over
    /// `cfg.cache_pools`). Without this test the cleaner could remove
    /// the cache_pool loop and only the runner tests would notice.
    #[test]
    fn validate_identity_fields_rejects_cache_pool_trust_zone_with_newline() {
        // Reuse the runner-flavored fixture for everything but the
        // cache_pools map, which we attach with a single
        // newline-injected pool.
        let mut cfg = cfg_with_runner_trust_zone("buckos", "default".into());
        cfg.cache_pools.insert(
            "build".into(),
            crate::config::CachePoolSpec {
                kinds: vec![crate::config::CacheKind::Sccache],
                size: "200G".into(),
                mode: crate::config::CacheMode::default(),
                trust_zone: "secure\nzone".into(),
            },
        );
        let err = validate_identity_fields(&cfg).expect_err("must reject newline");
        match err {
            GharsError::Validation(msg, _) => {
                assert!(
                    msg.contains("cache_pool") && msg.contains("build"),
                    "msg must scope to the offending cache_pool; got: {msg}"
                );
                assert!(
                    msg.contains("trust_zone") && msg.contains("newline"),
                    "msg must name the field + char class; got: {msg}"
                );
                // #380: config-load gate must NOT emit "render_identity:" prefix.
                assert!(
                    !msg.contains("render_identity"),
                    "msg must NOT contain \"render_identity\" prefix at \
                     config-load time; got: {msg}"
                );
                // #380 (P2-F2): adjacent-substring pin — cache_pool
                // scope must be directly followed by `field`, no infix.
                assert!(
                    msg.contains("cache_pool \"build\": field"),
                    "msg must contain `cache_pool \"build\": field` as adjacent \
                     substring (no infix between scope and field); got: {msg}"
                );
            }
            other => panic!("expected GharsError::Validation, got {other:?}"),
        }
    }

    // -------- #345/#346: config_source charset (plan-time gate) ---------

    /// #345: `config_source` is composed at plan time from
    /// `paths.config_dir.join("ghars.toml")` (plan_from's config_source
    /// synthesis). A `Paths`
    /// instance with a `\n` in `config_dir` (synthesizable in tests
    /// today, plumbable via a future `--config-dir` flag) must reject
    /// at the start of `plan_from` before `lower_to_effective` clones
    /// the value into every effective spec. Pinned because the
    /// production-time guarantee that `config_dir` is hard-coded
    /// (`Paths::default()` returns `/etc/ghars`) is a code-time
    /// invariant, not a type-system one — a future caller that
    /// constructs its own `Paths` would skip the gate without this
    /// regression test.
    #[test]
    fn plan_from_rejects_config_source_with_newline_in_paths_config_dir() {
        // Build a minimal config that plan_from would otherwise accept
        // (one runner, one auth) and a Paths with a newline-injected
        // config_dir.
        let cfg = cfg_with_runner_trust_zone("buckos", "default".into());
        let paths = Paths {
            config_dir: Utf8PathBuf::from("/etc/ghars\ninjected"),
            ..Paths::default()
        };
        let actual = state::ActualState::default();
        let err = plan::plan_from(&cfg, &actual, &paths)
            .expect_err("config_source with newline must reject");
        match err {
            GharsError::Validation(msg, _) => {
                assert!(
                    msg.contains("config_source") && msg.contains("newline"),
                    "msg must name the field + char class; got: {msg}"
                );
                // #380: plan_from invokes check_identity_field directly
                // (no render_identity wrapper). The bare error must
                // not carry the "render_identity:" prefix.
                assert!(
                    !msg.contains("render_identity"),
                    "msg must NOT contain \"render_identity\" prefix at \
                     plan_from config_source gate; got: {msg}"
                );
            }
            other => panic!("expected GharsError::Validation, got {other:?}"),
        }
    }

    // -------- #370: duplicate cache references in [[runner]].caches ----

    /// #370: `[[runner]] caches = ["build", "build"]` must reject at
    /// config load. The duplicate would render two identical
    /// X-Ghars-Caches comma-elements (`render_identity` joins the
    /// Vec via `cache_names.join(",")`), and apply.rs canonicalizes
    /// through BTreeSet, so plan would oscillate the spec_hash on
    /// every re-run as the Vec equality flips between
    /// duplicate-preserved and dedup-canonical forms.
    #[test]
    fn validate_no_duplicate_caches_rejects_repeated_pool_in_one_runner() {
        let mut cfg = cfg_with_runner_trust_zone("buckos", "default".into());
        cfg.runners[0].caches = vec!["build".into(), "build".into()];
        let err =
            validate_no_duplicate_caches(&cfg).expect_err("must reject duplicate cache reference");
        match err {
            GharsError::Validation(msg, _) => {
                assert!(
                    msg.contains("runner") && msg.contains("buckos"),
                    "msg must scope to the offending runner; got: {msg}"
                );
                assert!(
                    msg.contains("build") && msg.contains("duplicate"),
                    "msg must name the duplicated pool + describe the issue; got: {msg}"
                );
            }
            other => panic!("expected GharsError::Validation, got {other:?}"),
        }
    }

    /// #370: a runner with non-duplicate caches passes. Pinned so a
    /// future regression that broadened the validator into rejecting
    /// the multi-element happy path is caught.
    #[test]
    fn validate_no_duplicate_caches_accepts_distinct_pools() {
        let mut cfg = cfg_with_runner_trust_zone("buckos", "default".into());
        cfg.runners[0].caches = vec!["build".into(), "test".into(), "release".into()];
        validate_no_duplicate_caches(&cfg).expect("distinct cache references must pass validation");
    }

    /// #370: cross-runner reuse of the same pool is FINE — pools are
    /// designed to be referenced by multiple runners
    /// (`CacheMode::Shared` is `CachePoolSpec.mode`'s `#[default]`).
    /// The validator must check each runner's caches independently,
    /// not the union.
    #[test]
    fn validate_no_duplicate_caches_accepts_same_pool_across_runners() {
        let mut cfg = cfg_with_runner_trust_zone("buckos", "default".into());
        cfg.runners[0].caches = vec!["build".into()];
        // Add a second runner referencing the same pool.
        let mut second = cfg.runners[0].clone();
        second.name = "ci".into();
        second.url = "https://github.com/example/ci".into();
        second.caches = vec!["build".into()];
        cfg.runners.push(second);
        validate_no_duplicate_caches(&cfg).expect("cross-runner pool reuse must pass validation");
    }

    // -------- #613: AuthSpec::Pat XOR shape gate ------------------------

    /// Build a fixture Config with a single `[auth.NAME]` entry of
    /// AuthSpec::Pat and the runner's auth ref pointing at `name`. The
    /// 4+ reject tests below all share this scaffold — the helper
    /// collapses the boilerplate (#636) and pins the auth-name → error
    /// scope linkage in one place.
    ///
    /// `cfg_with_runner_trust_zone` inserts `[auth.pat]` by default;
    /// this helper unconditionally clears the inherited `[auth.pat]`
    /// entry then inserts `[auth.NAME]` so the resulting Config has
    /// exactly one auth entry under `name`.
    fn cfg_with_pat_auth(name: &str, token_env: Option<&str>, token_file: Option<&str>) -> Config {
        let mut cfg = cfg_with_runner_trust_zone("buckos", "default".into());
        cfg.auth.clear();
        cfg.auth.insert(
            name.into(),
            crate::config::AuthSpec::Pat {
                token_env: token_env.map(String::from),
                token_file: token_file.map(camino::Utf8PathBuf::from),
            },
        );
        cfg.runners[0].auth = Some(name.into());
        cfg
    }

    /// Run `validate_pat_xor(cfg)`, expect a `GharsError::Validation`,
    /// and assert every substring in `msg_parts` appears in the
    /// message, every substring in `hint_parts` appears in the
    /// hint, and every substring in `must_not_contain` appears in
    /// NEITHER the message NOR the hint. Always pins:
    ///   - variant is `Validation` (no Ok, no other error class).
    ///   - msg contains the colon-space `auth "NAME": ` scope shape
    ///     emitted by `prepend_validation_scope`.
    ///   - msg does NOT contain a redundant `kind = pat`/`kind =
    ///     "pat"` prefix (#624/#637) — the scope already identifies
    ///     the offending `[auth.NAME]` block and AuthSpec::Pat is the
    ///     only variant the loop checks.
    ///   - hint is non-empty.
    #[track_caller]
    fn assert_pat_xor_rejects(
        cfg: &Config,
        auth_name: &str,
        msg_parts: &[&str],
        hint_parts: &[&str],
        must_not_contain: &[&str],
    ) {
        let err = validate_pat_xor(cfg).expect_err("validate_pat_xor must reject");
        match err {
            GharsError::Validation(msg, hint) => {
                let expected_quoted = format!("\"{auth_name}\"");
                let expected_scope = format!("auth {expected_quoted}: ");
                assert!(
                    msg.contains(&expected_scope),
                    "msg must scope to {expected_scope:?} (colon-space format \
                     from prepend_validation_scope); got: {msg}"
                );
                // #624/#637: scope is `auth "NAME":` — never
                // `kind = pat:` (would duplicate the variant tag the
                // scope already implies).
                assert!(
                    !msg.contains("kind = pat"),
                    "msg must NOT contain redundant `kind = pat` prefix; got: {msg}"
                );
                assert!(
                    !msg.contains("kind = \"pat\""),
                    "msg must NOT contain redundant `kind = \"pat\"` prefix; got: {msg}"
                );
                assert!(
                    !hint.is_empty(),
                    "hint must be non-empty; got blank for auth {auth_name:?}"
                );
                for part in msg_parts {
                    assert!(msg.contains(part), "msg must contain {part:?}; got: {msg}");
                }
                for part in hint_parts {
                    assert!(
                        hint.contains(part),
                        "hint must contain {part:?}; got: {hint}"
                    );
                }
                for part in must_not_contain {
                    assert!(
                        !msg.contains(part),
                        "msg must NOT contain {part:?}; got: {msg}"
                    );
                    assert!(
                        !hint.contains(part),
                        "hint must NOT contain {part:?}; got: {hint}"
                    );
                }
            }
            other => panic!("expected GharsError::Validation, got {other:?}"),
        }
    }

    /// #613: `[auth.NAME]` with `kind = "pat"` and BOTH `token_env` and
    /// `token_file` set must reject at config-load. PatToken::new
    /// re-validates at apply time, but cmd_validate / cmd_plan
    /// short-circuit before reaching `build_token_source` — the
    /// load_config gate is the operator-visible rejection point for
    /// `ghars validate`.
    #[test]
    fn validate_pat_xor_rejects_both_token_env_and_token_file_set() {
        let cfg = cfg_with_pat_auth("pat", Some("GHARS_PAT"), Some("/etc/ghars/pat"));
        assert_pat_xor_rejects(&cfg, "pat", &["mutually exclusive"], &["remove one"], &[]);
    }

    /// #613: `[auth.NAME]` with `kind = "pat"` and NEITHER
    /// `token_env` nor `token_file` set must reject at config-load.
    /// Symmetric with the (Some, Some) gate — the only Ok shape is
    /// (Some, None) or (None, Some).
    #[test]
    fn validate_pat_xor_rejects_both_token_env_and_token_file_unset() {
        let cfg = cfg_with_pat_auth("pat", None, None);
        assert_pat_xor_rejects(
            &cfg,
            "pat",
            &["exactly one"],
            &["token_env", "token_file"],
            &[],
        );
    }

    /// #613: env-only PAT (the `cfg_with_runner_trust_zone` default
    /// shape) is the canonical Ok arm. Pinned so a future regression
    /// that broadened the validator into rejecting the happy path is
    /// caught.
    #[test]
    fn validate_pat_xor_accepts_token_env_only() {
        let cfg = cfg_with_runner_trust_zone("buckos", "default".into());
        // The fixture inserts AuthSpec::Pat { token_env: Some, token_file: None }
        validate_pat_xor(&cfg).expect("env-only PAT must pass validation");
    }

    /// #613: file-only PAT — the symmetric Ok arm. The shape-only gate
    /// MUST accept (None, Some) at config-load; `PatToken::new` runs
    /// the SEC-25 mode-0600 + owner-root + not-symlink check at apply
    /// time. Pinned so a future regression that rejects (None, Some)
    /// (e.g. a confused negation) is caught.
    #[test]
    fn validate_pat_xor_accepts_token_file_only() {
        let cfg = cfg_with_pat_auth("pat", None, Some("/etc/ghars/pat"));
        validate_pat_xor(&cfg).expect("file-only PAT must pass validation");
    }

    /// #623: `token_env = ""` (empty string) is shape-valid TOML but
    /// useless — `std::env::var("")` always returns `NotPresent`. The
    /// shape gate must reject this at config-load with an actionable
    /// message instead of falling through to apply where it surfaces
    /// as "env var unset".
    ///
    /// #630: hint shape is pinned via `assert_pat_xor_rejects` —
    /// asserts the hint references "environment variable" (the
    /// remediation domain) and the canonical example token_env =
    /// "GHARS_PAT" so a future regression that drops the example
    /// value or shifts the field-name reference is caught.
    #[test]
    fn validate_pat_xor_rejects_empty_token_env() {
        let cfg = cfg_with_pat_auth("pat", Some(""), None);
        assert_pat_xor_rejects(
            &cfg,
            "pat",
            &["token_env", "is empty or whitespace-only"],
            &["environment variable", "GHARS_PAT"],
            &[],
        );
    }

    /// #623: `token_file = ""` (empty string) is shape-valid TOML but
    /// useless — `Utf8PathBuf::from("")` is empty and `read_root_owned_0600`
    /// would fail with a confusing "open failed" error. The shape gate
    /// must reject this at config-load with an actionable message.
    ///
    /// #630: hint shape pinned — references the SEC-25 invariant
    /// ("0600 root-owned file") and the canonical example
    /// token_file = "/etc/ghars/pat".
    #[test]
    fn validate_pat_xor_rejects_empty_token_file() {
        let cfg = cfg_with_pat_auth("pat", None, Some(""));
        assert_pat_xor_rejects(
            &cfg,
            "pat",
            &["token_file", "is empty or whitespace-only"],
            &["0600 root-owned file", "/etc/ghars/pat"],
            &[],
        );
    }

    /// #629: a single-space `token_env = " "` is shape-valid TOML but
    /// useless for the same reason `token_env = ""` is — env-var
    /// names cannot contain spaces. Pre-#629 the gate ran
    /// `is_empty()` which returned false for `" "`, so a misconfigured
    /// whitespace-only value flowed through to apply where
    /// `std::env::var(" ")` returns `NotPresent` (or worse, succeeds
    /// on a shell that exported a literal-space env var). The post-fix
    /// gate uses `trim().is_empty()` so all-whitespace values reject
    /// with the same actionable diagnostic as truly empty ones.
    #[test]
    fn validate_pat_xor_rejects_whitespace_only_token_env_space() {
        let cfg = cfg_with_pat_auth("pat", Some(" "), None);
        assert_pat_xor_rejects(
            &cfg,
            "pat",
            &["token_env", "is empty or whitespace-only"],
            &["environment variable", "GHARS_PAT"],
            &[],
        );
    }

    /// #629: tab-only `token_env = "\t"` — same gate, different
    /// whitespace class (HT, U+0009). `str::trim` strips Unicode
    /// whitespace per `char::is_whitespace`, of which `\t` is one.
    /// Pinned so a regression that narrows trim() to spaces only
    /// (e.g. `s.replace(' ', "").is_empty()`) is caught.
    #[test]
    fn validate_pat_xor_rejects_whitespace_only_token_env_tab() {
        let cfg = cfg_with_pat_auth("pat", Some("\t"), None);
        assert_pat_xor_rejects(
            &cfg,
            "pat",
            &["token_env", "is empty or whitespace-only"],
            &["environment variable"],
            &[],
        );
    }

    /// #629: CRLF `token_env = "\r\n"` — operators occasionally paste
    /// from Windows tools that include `\r\n`. `str::trim` strips
    /// both. Pinned so the gate covers the full Unicode-whitespace
    /// surface, not just ASCII-32.
    #[test]
    fn validate_pat_xor_rejects_whitespace_only_token_env_crlf() {
        let cfg = cfg_with_pat_auth("pat", Some("\r\n"), None);
        assert_pat_xor_rejects(
            &cfg,
            "pat",
            &["token_env", "is empty or whitespace-only"],
            &["environment variable"],
            &[],
        );
    }

    /// #629: mixed whitespace `token_env = " \t\n "` — must reject.
    /// Pins that the gate rejects ANY all-whitespace combination, not
    /// just single-class runs.
    #[test]
    fn validate_pat_xor_rejects_whitespace_only_token_env_mixed() {
        let cfg = cfg_with_pat_auth("pat", Some(" \t\n "), None);
        assert_pat_xor_rejects(
            &cfg,
            "pat",
            &["token_env", "is empty or whitespace-only"],
            &["environment variable"],
            &[],
        );
    }

    /// #629: whitespace-only `token_file = " "` — symmetric with the
    /// token_env gate. `Utf8PathBuf::from(" ")` is a path with a
    /// single-space basename which would surface as a confusing
    /// "open failed" or "stat failed" error inside `PatToken::new`.
    #[test]
    fn validate_pat_xor_rejects_whitespace_only_token_file_space() {
        let cfg = cfg_with_pat_auth("pat", None, Some(" "));
        assert_pat_xor_rejects(
            &cfg,
            "pat",
            &["token_file", "is empty or whitespace-only"],
            &["0600 root-owned file", "/etc/ghars/pat"],
            &[],
        );
    }

    /// #629: tab-only `token_file = "\t"`.
    #[test]
    fn validate_pat_xor_rejects_whitespace_only_token_file_tab() {
        let cfg = cfg_with_pat_auth("pat", None, Some("\t"));
        assert_pat_xor_rejects(
            &cfg,
            "pat",
            &["token_file", "is empty or whitespace-only"],
            &["0600 root-owned file"],
            &[],
        );
    }

    /// #629: CRLF `token_file = "\r\n"` — symmetric with the
    /// token_env CRLF gate. Operators occasionally paste from
    /// Windows tools that include `\r\n`. `str::trim` strips both,
    /// so the gate rejects.
    #[test]
    fn validate_pat_xor_rejects_whitespace_only_token_file_crlf() {
        let cfg = cfg_with_pat_auth("pat", None, Some("\r\n"));
        assert_pat_xor_rejects(
            &cfg,
            "pat",
            &["token_file", "is empty or whitespace-only"],
            &["0600 root-owned file"],
            &[],
        );
    }

    /// #629: mixed whitespace `token_file = " \t\n "` — symmetric
    /// with the token_env mixed-whitespace gate. Pins that the
    /// token_file gate rejects ANY all-whitespace combination, not
    /// just single-class runs.
    #[test]
    fn validate_pat_xor_rejects_whitespace_only_token_file_mixed() {
        let cfg = cfg_with_pat_auth("pat", None, Some(" \t\n "));
        assert_pat_xor_rejects(
            &cfg,
            "pat",
            &["token_file", "is empty or whitespace-only"],
            &["0600 root-owned file"],
            &[],
        );
    }

    /// #629/#659 (Unicode pin): NBSP `token_env = "\u{00A0}"`
    /// (no-break space, U+00A0) — Unicode whitespace beyond ASCII.
    /// `str::trim` defers to `char::is_whitespace` which includes
    /// the Unicode `White_Space` property; NBSP is one. Pinned so
    /// the gate's coverage extends past ASCII-32/9/10/13 to the
    /// full Unicode whitespace surface — a regression that narrows
    /// to ASCII-only (e.g. `s.bytes().all(u8::is_ascii_whitespace)`)
    /// would silently let NBSP-only env-var names flow through.
    #[test]
    fn validate_pat_xor_rejects_whitespace_only_token_env_nbsp() {
        let cfg = cfg_with_pat_auth("pat", Some("\u{00A0}"), None);
        assert_pat_xor_rejects(
            &cfg,
            "pat",
            &["token_env", "is empty or whitespace-only"],
            &["environment variable"],
            &[],
        );
    }

    /// #669: `token_env = "X "` (trailing space on real content)
    /// rejects via the env-side trim-mismatch gate, BEFORE the POSIX
    /// charset gate. Pre-#669 this fell through to the POSIX charset
    /// gate, which surfaced "is not a valid POSIX environment
    /// variable name" — technically correct but misleading: the
    /// operator's intent was almost certainly a shell-quoting
    /// hiccup, not a charset violation. Post-#669 the trim-mismatch
    /// arm fires first with a dedicated diagnostic that names the
    /// condition.
    ///
    /// Renamed from `validate_pat_xor_accepts_token_env_with_trailing_space_on_real_content`
    /// (#661) when the POSIX charset gate landed; the pre-#658 test
    /// pinned the boundary that "X " accepted via trim().is_empty()
    /// being false. Post-#658 the test contract flipped from accept
    /// to reject; post-#669 the diagnostic shifted from POSIX-charset
    /// to trim-mismatch. The name remains `_rejects_` per #640
    /// (observable-contract terminology).
    #[test]
    fn validate_pat_xor_rejects_token_env_trailing_space_on_real_content() {
        let cfg = cfg_with_pat_auth("pat", Some("X "), None);
        // Precedence pin: the trim-mismatch arm fires AFTER the
        // empty/whitespace and hidden-char arms but BEFORE the POSIX
        // charset arm; the diagnostic must NOT carry either of those
        // other gates' text.
        assert_pat_xor_rejects(
            &cfg,
            "pat",
            &["token_env", "leading or trailing whitespace"],
            &["GHARS_PAT"],
            &[
                "is empty or whitespace-only",
                "hidden character",
                "POSIX environment variable name",
            ],
        );
    }

    /// #660: `token_file = "/etc/ghars/pat "` (trailing space on real
    /// content) rejects via the trim-mismatch gate. Pre-#660 the
    /// shape gate accepted any non-whitespace-only path; post-#660
    /// the trim-mismatch check catches a path whose edges carry
    /// extra whitespace which would surface as `open(2)` ENOENT on
    /// a literal-space basename. Pinned so a future regression that
    /// drops the trim-mismatch gate is caught.
    ///
    /// Renamed from `validate_pat_xor_accepts_token_file_with_trailing_space_on_real_content`
    /// (#661) when the trim-mismatch gate landed; the pre-#660 test
    /// pinned the boundary that "/etc/ghars/pat " accepted via
    /// trim().is_empty() being false. Post-#660 the contract flipped
    /// from accept to reject and the name follows. Convention per
    /// #640 (rename observable-contract terminology, not
    /// implementation detail).
    #[test]
    fn validate_pat_xor_rejects_token_file_trailing_space_on_real_content() {
        let cfg = cfg_with_pat_auth("pat", None, Some("/etc/ghars/pat "));
        // Precedence pin: the trim-mismatch arm fires AFTER the
        // empty/whitespace and hidden-char arms; the diagnostic
        // emitted here must NOT carry either preceding gate's text.
        assert_pat_xor_rejects(
            &cfg,
            "pat",
            &["token_file", "leading or trailing whitespace"],
            &["/etc/ghars/pat"],
            &["is empty or whitespace-only", "hidden character"],
        );
    }

    /// #669: `token_env = " X"` (leading-only whitespace on real
    /// content) rejects via the trim-mismatch gate before reaching
    /// the POSIX charset check. Symmetric with the trailing-space
    /// pin.
    #[test]
    fn validate_pat_xor_rejects_token_env_leading_space_on_real_content() {
        let cfg = cfg_with_pat_auth("pat", Some(" X"), None);
        assert_pat_xor_rejects(
            &cfg,
            "pat",
            &["token_env", "leading or trailing whitespace"],
            &["GHARS_PAT"],
            &[
                "is empty or whitespace-only",
                "hidden character",
                "POSIX environment variable name",
            ],
        );
    }

    /// #669: `token_env = " X "` (leading + trailing whitespace on
    /// real content) rejects via the trim-mismatch gate. Pinned
    /// alongside the leading-only and trailing-only cases so a
    /// regression that only handles one edge is caught.
    #[test]
    fn validate_pat_xor_rejects_token_env_both_sides_space_on_real_content() {
        let cfg = cfg_with_pat_auth("pat", Some(" X "), None);
        assert_pat_xor_rejects(
            &cfg,
            "pat",
            &["token_env", "leading or trailing whitespace"],
            &["GHARS_PAT"],
            &[
                "is empty or whitespace-only",
                "hidden character",
                "POSIX environment variable name",
            ],
        );
    }

    /// #661: `token_file = " /etc/ghars/pat"` (leading-only
    /// whitespace on real content) rejects via the trim-mismatch
    /// gate. Symmetric with the trailing-space pin; `path !=
    /// path.trim()` catches both edges.
    #[test]
    fn validate_pat_xor_rejects_token_file_leading_space_on_real_content() {
        let cfg = cfg_with_pat_auth("pat", None, Some(" /etc/ghars/pat"));
        assert_pat_xor_rejects(
            &cfg,
            "pat",
            &["token_file", "leading or trailing whitespace"],
            &["/etc/ghars/pat"],
            &["is empty or whitespace-only", "hidden character"],
        );
    }

    /// #661: `token_file = " /etc/ghars/pat "` (leading + trailing
    /// whitespace on real content) rejects via the trim-mismatch
    /// gate. Pinned alongside the leading-only and trailing-only
    /// cases.
    #[test]
    fn validate_pat_xor_rejects_token_file_both_sides_space_on_real_content() {
        let cfg = cfg_with_pat_auth("pat", None, Some(" /etc/ghars/pat "));
        assert_pat_xor_rejects(
            &cfg,
            "pat",
            &["token_file", "leading or trailing whitespace"],
            &["/etc/ghars/pat"],
            &["is empty or whitespace-only", "hidden character"],
        );
    }

    /// #658: a POSIX-violating `token_env` (e.g. `"FOO-BAR"` with a
    /// dash, which `std::env::var` accepts as a lookup key but whose
    /// shape is not a portable POSIX env var name) rejects with a
    /// charset diagnostic. Pinned independently of the
    /// leading/trailing-whitespace tests so a regression that
    /// narrows the POSIX gate to just whitespace rejection (and
    /// silently accepts arbitrary punctuation) is caught.
    #[test]
    fn validate_pat_xor_rejects_token_env_with_non_posix_chars() {
        let cfg = cfg_with_pat_auth("pat", Some("FOO-BAR"), None);
        assert_pat_xor_rejects(
            &cfg,
            "pat",
            &["token_env", "POSIX environment variable name"],
            &["GHARS_PAT"],
            &["is empty or whitespace-only", "hidden character"],
        );
    }

    /// #658: `token_env` starting with a digit (e.g. `"1FOO"`)
    /// rejects via POSIX charset. POSIX names must start with a
    /// letter or underscore — digit-leading shells often accept it
    /// in practice but the standard forbids it, and a portable
    /// runner config should reject the unportable form.
    #[test]
    fn validate_pat_xor_rejects_token_env_starting_with_digit() {
        let cfg = cfg_with_pat_auth("pat", Some("1FOO"), None);
        assert_pat_xor_rejects(
            &cfg,
            "pat",
            &["token_env", "POSIX environment variable name"],
            &["GHARS_PAT"],
            &["is empty or whitespace-only", "hidden character"],
        );
    }

    /// #658 NEGATIVE pin: a clean POSIX-conformant `token_env`
    /// (canonical `"GHARS_PAT"`) MUST pass the charset gate. Pinned
    /// so a future regression that over-tightens the regex (e.g.
    /// drops `_` from the first-char class, or rejects all-uppercase
    /// names) is caught.
    #[test]
    fn validate_pat_xor_accepts_token_env_canonical_posix_name() {
        let cfg = cfg_with_pat_auth("pat", Some("GHARS_PAT"), None);
        validate_pat_xor(&cfg).expect("canonical POSIX token_env must pass shape gate");
    }

    /// #658 NEGATIVE pin: a single-letter `token_env` (`"X"`) — the
    /// shortest legal POSIX form — MUST pass. Boundary check on the
    /// regex's `*` quantifier (zero or more trailing chars).
    #[test]
    fn validate_pat_xor_accepts_token_env_single_letter() {
        let cfg = cfg_with_pat_auth("pat", Some("X"), None);
        validate_pat_xor(&cfg).expect("single-letter POSIX token_env must pass shape gate");
    }

    /// #658 NEGATIVE pin: a leading-underscore `token_env` (`"_FOO"`)
    /// — the second legal POSIX first-char — MUST pass. POSIX env
    /// var names start with `[A-Za-z_]`, so `_` is in the legal set.
    #[test]
    fn validate_pat_xor_accepts_token_env_leading_underscore() {
        let cfg = cfg_with_pat_auth("pat", Some("_FOO"), None);
        validate_pat_xor(&cfg).expect("leading-underscore POSIX token_env must pass shape gate");
    }

    /// #659: `token_env` containing a NUL (U+0000) rejects via the
    /// hidden-char gate. Surfaces the codepoint + byte offset so
    /// the operator can locate the invisible char in their editor.
    /// NUL is a control char so it would also be caught by the
    /// `is_control()` arm of `is_disallowed_hidden_char`; pinning
    /// it explicitly catches a regression that narrows the
    /// explicit list and the control-char rule simultaneously.
    #[test]
    fn validate_pat_xor_rejects_token_env_with_nul() {
        let cfg = cfg_with_pat_auth("pat", Some("FOO\u{0000}BAR"), None);
        assert_pat_xor_rejects(
            &cfg,
            "pat",
            &["token_env", "hidden character", "U+0000", "byte offset"],
            &["GHARS_PAT"],
            &[],
        );
    }

    /// #659: `token_env` containing a BOM (U+FEFF) rejects via the
    /// hidden-char gate. Operators occasionally paste from
    /// Windows tools that prefix the value with a BOM; the byte
    /// is invisible in most editors and would silently break
    /// `std::env::var` lookup.
    #[test]
    fn validate_pat_xor_rejects_token_env_with_bom() {
        let cfg = cfg_with_pat_auth("pat", Some("\u{FEFF}GHARS_PAT"), None);
        assert_pat_xor_rejects(
            &cfg,
            "pat",
            &["token_env", "hidden character", "U+FEFF", "byte offset"],
            &["GHARS_PAT"],
            &[],
        );
    }

    /// #659: `token_env` containing a zero-width space (U+200B)
    /// rejects via the hidden-char gate. Pinned alongside BOM and
    /// NUL so the entire default-ignorable set defends against
    /// invisible breakage.
    #[test]
    fn validate_pat_xor_rejects_token_env_with_zero_width_space() {
        let cfg = cfg_with_pat_auth("pat", Some("FOO\u{200B}BAR"), None);
        assert_pat_xor_rejects(
            &cfg,
            "pat",
            &["token_env", "hidden character", "U+200B", "byte offset"],
            &["GHARS_PAT"],
            &[],
        );
    }

    /// #659: `token_env` containing a zero-width non-joiner (U+200C)
    /// rejects via the hidden-char gate. Together with the ZWSP /
    /// ZWJ / WJ pins, covers the default-ignorable format
    /// characters most likely to survive a copy-paste from a
    /// rich-text doc.
    #[test]
    fn validate_pat_xor_rejects_token_env_with_zero_width_non_joiner() {
        let cfg = cfg_with_pat_auth("pat", Some("FOO\u{200C}BAR"), None);
        assert_pat_xor_rejects(
            &cfg,
            "pat",
            &["token_env", "hidden character", "U+200C", "byte offset"],
            &["GHARS_PAT"],
            &[],
        );
    }

    /// #659: `token_env` containing a soft hyphen (U+00AD) rejects
    /// via the hidden-char gate. SHY is not a control char, so
    /// `is_control()` would not catch it — the explicit list arm
    /// fires.
    #[test]
    fn validate_pat_xor_rejects_token_env_with_soft_hyphen() {
        let cfg = cfg_with_pat_auth("pat", Some("FOO\u{00AD}BAR"), None);
        assert_pat_xor_rejects(
            &cfg,
            "pat",
            &["token_env", "hidden character", "U+00AD", "byte offset"],
            &["GHARS_PAT"],
            &[],
        );
    }

    /// #659: `token_file` containing a BOM (U+FEFF) at the start
    /// rejects via the hidden-char gate. Symmetric with the
    /// token_env BOM pin; the path-side surface is independent
    /// because paths lack the POSIX charset gate that catches BOM
    /// implicitly on the env-var side.
    #[test]
    fn validate_pat_xor_rejects_token_file_with_bom() {
        let cfg = cfg_with_pat_auth("pat", None, Some("\u{FEFF}/etc/ghars/pat"));
        assert_pat_xor_rejects(
            &cfg,
            "pat",
            &["token_file", "hidden character", "U+FEFF", "byte offset"],
            &["/etc/ghars/pat"],
            &[],
        );
    }

    /// #659: `token_file` containing a NUL (U+0000) rejects via the
    /// hidden-char gate. NUL terminates C strings, so an embedded
    /// NUL in a path would surface as a confusing kernel error
    /// (or worse, silently truncate the path) at apply time.
    #[test]
    fn validate_pat_xor_rejects_token_file_with_nul() {
        let cfg = cfg_with_pat_auth("pat", None, Some("/etc/\u{0000}ghars/pat"));
        assert_pat_xor_rejects(
            &cfg,
            "pat",
            &["token_file", "hidden character", "U+0000", "byte offset"],
            &["/etc/ghars/pat"],
            &[],
        );
    }

    /// #659: `token_file` containing a zero-width joiner (U+200D)
    /// rejects via the hidden-char gate. Symmetric with the
    /// token_env ZWNJ pin.
    #[test]
    fn validate_pat_xor_rejects_token_file_with_zero_width_joiner() {
        let cfg = cfg_with_pat_auth("pat", None, Some("/etc/ghars\u{200D}/pat"));
        assert_pat_xor_rejects(
            &cfg,
            "pat",
            &["token_file", "hidden character", "U+200D", "byte offset"],
            &["/etc/ghars/pat"],
            &[],
        );
    }

    /// #659: `token_env` containing a word joiner (U+2060) rejects
    /// via the hidden-char gate. Each explicit codepoint slot in
    /// `is_disallowed_hidden_char` (NUL/SHY/CGJ/ALM/MVS, the
    /// ZWSP-ZWNJ-ZWJ-LRM-RLM block, the bidi-override block,
    /// the WJ + invisible-math block, the bidi-isolate block,
    /// the variation-selector block, and BOM) is pinned by at least
    /// one test so a regression that drops a slot from the matches
    /// arm is caught. ZWJ is covered by the token_file pin; this
    /// test pins WJ on the token_env side.
    #[test]
    fn validate_pat_xor_rejects_token_env_with_word_joiner() {
        let cfg = cfg_with_pat_auth("pat", Some("FOO\u{2060}BAR"), None);
        assert_pat_xor_rejects(
            &cfg,
            "pat",
            &["token_env", "hidden character", "U+2060", "byte offset"],
            &["GHARS_PAT"],
            &[],
        );
    }

    /// #659: `token_env` containing an ESC control char (U+001B)
    /// rejects via the `is_control()` arm of `is_disallowed_hidden_char`.
    /// Pinned independently of the explicit-codepoint matches so a
    /// regression that narrows the control-char arm (e.g. drops it
    /// in favor of the explicit-only list) is caught — the explicit
    /// arm covers a finite set of default-ignorable / format
    /// codepoints; the control-char arm covers the rest of category
    /// Cc. ESC is the canonical attacker vector for terminal-escape
    /// injection, so this test doubles as a defense-in-depth pin
    /// against ANSI escapes flowing through env-var values.
    #[test]
    fn validate_pat_xor_rejects_token_env_with_control_char_esc() {
        let cfg = cfg_with_pat_auth("pat", Some("FOO\u{001B}BAR"), None);
        assert_pat_xor_rejects(
            &cfg,
            "pat",
            &["token_env", "hidden character", "U+001B", "byte offset"],
            &["GHARS_PAT"],
            &[],
        );
    }

    /// #659 precedence pin: hidden-char gate fires BEFORE the POSIX
    /// charset gate. Input `"\u{FEFF}foo-bar"` would fail BOTH:
    /// the BOM is in the explicit hidden-char list, AND the dash
    /// in `foo-bar` violates POSIX charset. The hidden-char gate is
    /// reached first (cli.rs check_empty_or_hidden runs before the
    /// regex match), so the diagnostic must surface as
    /// "hidden character ... U+FEFF" — not "POSIX environment
    /// variable name". Pinned so a future restructure that flips
    /// gate ordering (and surfaces the less-actionable POSIX
    /// diagnostic for invisible-char inputs) is caught.
    #[test]
    fn validate_pat_xor_precedence_hidden_char_before_posix_charset() {
        let cfg = cfg_with_pat_auth("pat", Some("\u{FEFF}foo-bar"), None);
        assert_pat_xor_rejects(
            &cfg,
            "pat",
            &["hidden character", "U+FEFF"],
            &["GHARS_PAT"],
            &["POSIX environment variable name"],
        );
    }

    /// #659: `token_env = "X\u{FEFF}FOO"` — non-zero byte offset
    /// pin. The hidden char (BOM, 3-byte UTF-8 sequence) sits at
    /// byte offset 1 (after a 1-byte ASCII 'X'). The diagnostic
    /// must surface "byte offset 1" — not 0 or any character index.
    /// Pinned so a regression that emits a character index instead
    /// of a byte offset (e.g. swapping char_indices for chars) is
    /// caught.
    #[test]
    fn validate_pat_xor_rejects_token_env_hidden_char_at_nonzero_byte_offset() {
        let cfg = cfg_with_pat_auth("pat", Some("X\u{FEFF}FOO"), None);
        assert_pat_xor_rejects(
            &cfg,
            "pat",
            &["hidden character", "U+FEFF", "byte offset 1"],
            &["GHARS_PAT"],
            &[],
        );
    }

    /// #660 NEGATIVE pin: `token_file = "/etc/ghars/my pat"` (real
    /// path with internal whitespace, no edge whitespace) MUST
    /// PASS the shape gate. `path_str != path_str.trim()` is FALSE
    /// when whitespace is purely internal — Unix paths can legally
    /// contain spaces (mount points, user-chosen filenames).
    /// Pinned so a regression that broadens the gate (e.g. to
    /// `path.contains(char::is_whitespace)`) and silently rejects
    /// valid paths with embedded spaces is caught.
    #[test]
    fn validate_pat_xor_accepts_token_file_with_internal_space() {
        let cfg = cfg_with_pat_auth("pat", None, Some("/etc/ghars/my pat"));
        validate_pat_xor(&cfg)
            .expect("token_file with internal-only whitespace must pass shape gate");
    }

    /// #658 precedence pin: per-field gates fire BEFORE the XOR
    /// tuple-match. Input `(Some("FOO-BAR"), Some("/etc/ghars/pat"))`
    /// is BOTH XOR-violating (both fields set) AND charset-violating
    /// on token_env (dash in "FOO-BAR"). The per-field charset gate
    /// is reached on the env-side first, so the diagnostic surfaces
    /// as "POSIX environment variable name" — not "mutually
    /// exclusive". Pinned so a future restructure that hoists the
    /// XOR check above the per-field gates is caught.
    #[test]
    fn validate_pat_xor_precedence_bad_env_clean_file_emits_charset_not_xor() {
        let cfg = cfg_with_pat_auth("pat", Some("FOO-BAR"), Some("/etc/ghars/pat"));
        assert_pat_xor_rejects(
            &cfg,
            "pat",
            &["POSIX environment variable name"],
            &["GHARS_PAT"],
            &["mutually exclusive"],
        );
    }

    /// #664/scope-propagation pin: an unusual auth name combined
    /// with the (true,true) XOR shape MUST scope the error to the
    /// operator's chosen name. Sibling test
    /// `validate_pat_xor_rejects_unusual_auth_name` exercises the
    /// empty-env arm with the same auth name; this test exercises
    /// the XOR arm so scope propagation is pinned across BOTH
    /// rejection sites the function emits. Defense-in-depth: a
    /// regression that hardcodes the "pat" substring inside the
    /// XOR arm's error rendering would slip past the empty-arm
    /// pin alone.
    #[test]
    fn validate_pat_xor_rejects_unusual_auth_name_xor_both_set() {
        let cfg = cfg_with_pat_auth(
            "alpha-zone-creds",
            Some("GHARS_PAT"),
            Some("/etc/ghars/pat"),
        );
        assert_pat_xor_rejects(
            &cfg,
            "alpha-zone-creds",
            &["mutually exclusive"],
            &["GHARS_PAT", "/etc/ghars/pat"],
            &[],
        );
    }

    /// #664: an unusual auth name that does NOT contain "pat" as a
    /// substring (e.g. `"alpha-zone-creds"`) MUST scope the error
    /// correctly via `assert_pat_xor_rejects`. The helper pins the
    /// scope shape (`auth "NAME": `) and the absence of redundant
    /// `kind = pat` prefix; this test exercises the case where any
    /// hardcoded substring drift in the rejector would slip past
    /// the canonical "pat" name. Defense-in-depth — the validator
    /// MUST identify the offending block by the operator's chosen
    /// name, not by a hardcoded substring of the AuthSpec variant.
    #[test]
    fn validate_pat_xor_rejects_unusual_auth_name() {
        let cfg = cfg_with_pat_auth("alpha-zone-creds", Some(""), None);
        assert_pat_xor_rejects(
            &cfg,
            "alpha-zone-creds",
            &["token_env", "is empty or whitespace-only"],
            &["GHARS_PAT"],
            &[],
        );
    }

    /// #663: the (true,true) XOR error hint includes both canonical
    /// example values (`GHARS_PAT` and `/etc/ghars/pat`) so an
    /// operator reading the rejection sees the same remediation
    /// breadcrumb the empty-string / charset arms already provide.
    /// Pinned so a future regression that strips the examples (or
    /// only includes one) is caught.
    #[test]
    fn validate_pat_xor_rejects_both_set_with_concrete_example_hints() {
        let cfg = cfg_with_pat_auth("pat", Some("GHARS_PAT"), Some("/etc/ghars/pat"));
        assert_pat_xor_rejects(
            &cfg,
            "pat",
            &["mutually exclusive"],
            &["GHARS_PAT", "/etc/ghars/pat"],
            &[],
        );
    }

    /// #663: the (false,false) "exactly one" hint includes both
    /// canonical example values. Symmetric with the (true,true) pin.
    #[test]
    fn validate_pat_xor_rejects_neither_set_with_concrete_example_hints() {
        let cfg = cfg_with_pat_auth("pat", None, None);
        assert_pat_xor_rejects(
            &cfg,
            "pat",
            &["exactly one"],
            &["GHARS_PAT", "/etc/ghars/pat"],
            &[],
        );
    }

    /// #631: precedence — `(Some(""), Some(""))` is BOTH XOR-violating
    /// (both fields set) AND empty (each value is empty). The
    /// validator emits the empty-token_env diagnostic FIRST because
    /// the empty/whitespace gate fires before the XOR tuple match.
    /// Pinned so a future restructure that flips the order (and
    /// surfaces "mutually exclusive" instead of the more specific
    /// "is empty" rejection) is caught — empty-string is the more
    /// useful diagnostic because the operator is more likely to
    /// have left the field as a placeholder than to have
    /// genuinely intended both fields to coexist.
    #[test]
    fn validate_pat_xor_precedence_both_empty_emits_empty_env_not_xor() {
        let cfg = cfg_with_pat_auth("pat", Some(""), Some(""));
        // Inverse pin via must_not_contain: the XOR diagnostic must
        // NOT fire for this shape — the empty-token_env arm
        // short-circuits before the tuple match.
        assert_pat_xor_rejects(
            &cfg,
            "pat",
            &["token_env", "is empty or whitespace-only"],
            &["environment variable"],
            &["mutually exclusive"],
        );
    }

    /// #631 (whitespace variant): `(Some(" "), Some(" "))` — same
    /// precedence as the (Some(""), Some("")) case. Both fields are
    /// whitespace-only AND both are set. The empty-or-whitespace
    /// gate fires first; the XOR gate is unreachable. Pinned so the
    /// whitespace path of the empty-env arm preserves the same
    /// short-circuit behavior as the empty-string path.
    #[test]
    fn validate_pat_xor_precedence_both_whitespace_emits_empty_env_not_xor() {
        let cfg = cfg_with_pat_auth("pat", Some(" "), Some(" "));
        // Inverse pin via must_not_contain: whitespace-env arm must
        // fire BEFORE the XOR arm (same precedence as the empty-string
        // case).
        assert_pat_xor_rejects(
            &cfg,
            "pat",
            &["token_env", "is empty or whitespace-only"],
            &["environment variable"],
            &["mutually exclusive"],
        );
    }

    /// #631 (token_file precedence): `(None, Some(""))` — only
    /// token_file is set, and it is empty. The empty-token_file arm
    /// must fire and emit the "token_file is empty or whitespace-
    /// only" diagnostic, NOT the (false, false) "exactly one"
    /// diagnostic. Pinned so a regression that confuses
    /// `token_file.is_some()` with `token_file.as_ref().is_some_and(non_empty)`
    /// — falling through to the (false, false) tuple match because
    /// the empty-string is treated as "unset" — is caught.
    #[test]
    fn validate_pat_xor_precedence_token_file_only_empty_emits_empty_file_not_required() {
        let cfg = cfg_with_pat_auth("pat", None, Some(""));
        // Inverse pin via must_not_contain: the "exactly one" arm
        // must NOT fire — the empty-token_file arm short-circuits
        // before the tuple match.
        assert_pat_xor_rejects(
            &cfg,
            "pat",
            &["token_file", "is empty or whitespace-only"],
            &["0600 root-owned file"],
            &["exactly one"],
        );
    }

    /// #638: loop continuation — when `[auth.interactive]` (a non-Pat
    /// variant) precedes a misconfigured `[auth.pat]` in source
    /// order, the validator must walk past the non-Pat entry and
    /// surface the Pat error. Pre-fix this was implicit (the loop
    /// no-ops on non-Pat variants), but no test pinned the
    /// continuation contract — a regression that early-returned on
    /// the first non-Pat variant would silently let bad Pat configs
    /// flow through cmd_plan/cmd_status. IndexMap preserves insert
    /// order, so the fixture builds [interactive, pat] in that
    /// order and asserts the error scopes to "pat".
    #[test]
    fn validate_pat_xor_rejects_bad_pat_after_non_pat_variant() {
        let mut cfg = cfg_with_runner_trust_zone("buckos", "default".into());
        cfg.auth.clear();
        cfg.auth
            .insert("interactive".into(), crate::config::AuthSpec::Interactive);
        cfg.auth.insert(
            "pat".into(),
            crate::config::AuthSpec::Pat {
                token_env: None,
                token_file: None,
            },
        );
        cfg.runners[0].auth = Some("pat".into());
        assert_pat_xor_rejects(
            &cfg,
            "pat",
            &["exactly one"],
            &["token_env", "token_file"],
            &[],
        );
    }

    /// #638 reverse direction: bad Pat FIRST, non-Pat variant after.
    /// The validator must surface the Pat error on the first iteration
    /// (early return) without examining the trailing non-Pat entry.
    /// Pinned alongside the [interactive, pat] direction so a
    /// regression that swaps to "skip Pat then fall through to
    /// non-Pat" is caught from both sides — the loop body must not
    /// depend on insertion order to fire correctly.
    #[test]
    fn validate_pat_xor_rejects_bad_pat_before_non_pat_variant() {
        let mut cfg = cfg_with_runner_trust_zone("buckos", "default".into());
        cfg.auth.clear();
        cfg.auth.insert(
            "pat".into(),
            crate::config::AuthSpec::Pat {
                token_env: None,
                token_file: None,
            },
        );
        cfg.auth
            .insert("interactive".into(), crate::config::AuthSpec::Interactive);
        cfg.runners[0].auth = Some("pat".into());
        assert_pat_xor_rejects(
            &cfg,
            "pat",
            &["exactly one"],
            &["token_env", "token_file"],
            &[],
        );
    }

    /// #639: multi-Pat — when one `[auth.NAME]` is a valid Pat and a
    /// second `[auth.NAME]` is a bad Pat, the validator surfaces only
    /// the bad one (and scopes the error to its name). Pinned so a
    /// regression that aborts on the first Pat regardless of shape
    /// (or that misattributes the error to the first auth name) is
    /// caught. IndexMap preserves insert order: [good-pat, bad-pat].
    #[test]
    fn validate_pat_xor_rejects_only_the_bad_pat_in_multi_pat_auth() {
        let mut cfg = cfg_with_runner_trust_zone("buckos", "default".into());
        cfg.auth.clear();
        cfg.auth.insert(
            "good-pat".into(),
            crate::config::AuthSpec::Pat {
                token_env: Some("GHARS_PAT_GOOD".into()),
                token_file: None,
            },
        );
        cfg.auth.insert(
            "bad-pat".into(),
            crate::config::AuthSpec::Pat {
                token_env: Some(String::new()),
                token_file: None,
            },
        );
        cfg.runners[0].auth = Some("good-pat".into());
        // assert_pat_xor_rejects pins that the error scope contains
        // "bad-pat" — not "good-pat" — so a regression that
        // misattributes is caught. Inverse pin via must_not_contain:
        // the error must NOT mention the well-formed Pat's name —
        // the validator stopped on the bad one.
        assert_pat_xor_rejects(
            &cfg,
            "bad-pat",
            &["token_env", "is empty or whitespace-only"],
            &["environment variable"],
            &["\"good-pat\""],
        );
    }

    /// #639 reverse direction: bad Pat FIRST, good Pat SECOND. The
    /// validator iterates in IndexMap insert order and must early-
    /// return on the bad Pat without examining the trailing good
    /// one. Pins the early-return contract: the loop fires on the
    /// first Pat that fails the shape gate and never visits later
    /// entries. Pinned alongside the [good-pat, bad-pat] case so a
    /// regression that filters/skips Pat entries (e.g. a hypothetical
    /// "find_first(predicate)" rewrite that misorders) is caught
    /// from both sides.
    #[test]
    fn validate_pat_xor_rejects_first_bad_pat_before_trailing_good_pat() {
        let mut cfg = cfg_with_runner_trust_zone("buckos", "default".into());
        cfg.auth.clear();
        cfg.auth.insert(
            "bad-pat".into(),
            crate::config::AuthSpec::Pat {
                token_env: Some(String::new()),
                token_file: None,
            },
        );
        cfg.auth.insert(
            "good-pat".into(),
            crate::config::AuthSpec::Pat {
                token_env: Some("GHARS_PAT_GOOD".into()),
                token_file: None,
            },
        );
        cfg.runners[0].auth = Some("good-pat".into());
        // Inverse pin via must_not_contain: the error must NOT
        // mention the trailing good Pat's name — early-return: the
        // validator stopped on the first bad one and never iterated
        // to the second.
        assert_pat_xor_rejects(
            &cfg,
            "bad-pat",
            &["token_env", "is empty or whitespace-only"],
            &["environment variable"],
            &["\"good-pat\""],
        );
    }

    /// #639 both-bad-Pat: when BOTH Pat entries are misconfigured,
    /// the validator early-returns on the FIRST bad Pat (insert
    /// order) and never examines the second. Pinned so a regression
    /// that "accumulates" failures across multiple Pat entries (or
    /// that misattributes the error to the second bad one) is
    /// caught. IndexMap preserves insert order: [bad1, bad2]. The
    /// fixture uses cfg_with_pat_auth for bad1, then manually
    /// inserts bad2 with the same fault shape (token_env=Some("")).
    #[test]
    fn validate_pat_xor_rejects_first_bad_pat_when_both_pats_faulted() {
        let mut cfg = cfg_with_pat_auth("bad1", Some(""), None);
        cfg.auth.insert(
            "bad2".into(),
            crate::config::AuthSpec::Pat {
                token_env: Some(String::new()),
                token_file: None,
            },
        );
        // Inverse pin via must_not_contain: the error must NOT
        // mention "bad2" — the validator early-returned on bad1
        // and never iterated to the second bad entry.
        assert_pat_xor_rejects(
            &cfg,
            "bad1",
            &["token_env", "is empty or whitespace-only"],
            &["environment variable"],
            &["\"bad2\""],
        );
    }

    /// #613/#640: non-Pat AuthSpec variants (`Interactive`, `TokenFile`,
    /// `GithubApp`) have no XOR shape to validate. The validator
    /// loop walks every entry but no-ops on non-Pat variants. Pinned
    /// so a future regression that fires on non-Pat variants is
    /// caught.
    ///
    /// Renamed from `_skips_` to `_accepts_` (#640) for naming
    /// consistency with sibling positive tests
    /// (`_accepts_token_env_only`, `_accepts_token_file_only`) —
    /// "accepts" describes the observable contract (Ok return);
    /// "skips" was implementation-coupled (the loop body's no-op
    /// branch).
    #[test]
    fn validate_pat_xor_accepts_non_pat_auth_variants() {
        let mut cfg = cfg_with_runner_trust_zone("buckos", "default".into());
        // Replace the default [auth.pat] with a non-Pat variant (Interactive).
        cfg.auth.clear();
        cfg.auth
            .insert("interactive".into(), crate::config::AuthSpec::Interactive);
        cfg.auth.insert(
            "tokenfile".into(),
            crate::config::AuthSpec::TokenFile {
                path: camino::Utf8PathBuf::from("/etc/ghars/regtok"),
            },
        );
        cfg.runners[0].auth = Some("interactive".into());
        validate_pat_xor(&cfg).expect("non-Pat AuthSpec variants must pass validation");
    }

    // -------- WO-S16A new tests (#669/#672/#674/#675/#676) -------------

    /// #672 (RLO Trojan Source): `token_env` containing U+202E
    /// (Right-to-Left Override) rejects via the hidden-char gate.
    /// Load-bearing for the security claim that bidi-override
    /// attacks (Boucher & Anderson 2021) cannot reach apply-time
    /// env::var lookup. RLO renders subsequent characters
    /// right-to-left in operator terminals, allowing visually
    /// identical strings to be different bytewise.
    #[test]
    fn validate_pat_xor_rejects_token_env_with_right_to_left_override() {
        let cfg = cfg_with_pat_auth("pat", Some("FOO\u{202E}BAR"), None);
        assert_pat_xor_rejects(
            &cfg,
            "pat",
            &["token_env", "hidden character", "U+202E", "byte offset"],
            &["GHARS_PAT"],
            &[],
        );
    }

    /// #672 (RLO Trojan Source on token_file): symmetric with the
    /// token_env RLO pin above. A `token_file` path containing U+202E
    /// (Right-to-Left Override) rejects via the hidden-char gate.
    /// RLO inside a path is a credible attack surface — bidi-rendered
    /// paths can disguise their actual byte sequence to a reviewing
    /// operator (e.g. `/etc/ghars/Pat.txt` rendered as
    /// `/etc/ghars/txt.taP` after RLO). Defense-in-depth pin so a
    /// regression that drops U+202E from the matches arm but leaves
    /// the token_env pin intact is still caught.
    #[test]
    fn validate_pat_xor_rejects_token_file_with_right_to_left_override() {
        let cfg = cfg_with_pat_auth("pat", None, Some("/etc/ghars/\u{202E}pat"));
        assert_pat_xor_rejects(
            &cfg,
            "pat",
            &["token_file", "hidden character", "U+202E", "byte offset"],
            &["/etc/ghars/pat"],
            &[],
        );
    }

    /// #672: `token_env` containing U+200E (LRM, Left-to-Right Mark)
    /// rejects via the hidden-char gate. LRM is in the U+200B..U+200F
    /// block expanded in #672. Pinned to catch a regression that
    /// re-narrows the explicit set to just ZWSP/ZWNJ/ZWJ.
    #[test]
    fn validate_pat_xor_rejects_token_env_with_left_to_right_mark() {
        let cfg = cfg_with_pat_auth("pat", Some("FOO\u{200E}BAR"), None);
        assert_pat_xor_rejects(
            &cfg,
            "pat",
            &["token_env", "hidden character", "U+200E", "byte offset"],
            &["GHARS_PAT"],
            &[],
        );
    }

    /// #672: `token_env` containing U+2066 (LRI, Left-to-Right
    /// Isolate) rejects via the hidden-char gate. Bidi isolate from
    /// the U+2066..U+2069 block expanded in #672.
    #[test]
    fn validate_pat_xor_rejects_token_env_with_bidi_isolate() {
        let cfg = cfg_with_pat_auth("pat", Some("FOO\u{2066}BAR"), None);
        assert_pat_xor_rejects(
            &cfg,
            "pat",
            &["token_env", "hidden character", "U+2066", "byte offset"],
            &["GHARS_PAT"],
            &[],
        );
    }

    /// `token_file` containing U+FE0F (VS-16, emoji variant selector)
    /// rejects via the hidden-char gate. Variation selectors are Mn
    /// (Mark, nonspacing) — NOT in the Cc class. Routes to the
    /// remove-only sub-arm (no precomposed equivalent exists for VS).
    #[test]
    fn validate_pat_xor_rejects_token_file_with_variation_selector() {
        let cfg = cfg_with_pat_auth("pat", None, Some("/etc/ghars\u{FE0F}/pat"));
        assert_pat_xor_rejects(
            &cfg,
            "pat",
            &[
                "token_file",
                "combining mark",
                "U+FE0F",
                "byte offset",
                "remove the codepoint",
                "no precomposed equivalent exists",
            ],
            &["/etc/ghars/pat"],
            &["NFC", "if the character was intentional", "hidden character"],
        );
    }

    /// `token_file` containing U+034F (COMBINING GRAPHEME JOINER)
    /// routes to the remove-only sub-arm of the Mn branch. CGJ is Mn
    /// but has no precomposed NFC form, so NFC advice would mislead.
    #[test]
    fn validate_pat_xor_rejects_token_file_with_combining_grapheme_joiner() {
        let cfg = cfg_with_pat_auth("pat", None, Some("/etc/ghars\u{034F}/pat"));
        assert_pat_xor_rejects(
            &cfg,
            "pat",
            &[
                "token_file",
                "combining mark",
                "U+034F",
                "byte offset",
                "remove the codepoint",
                "no precomposed equivalent exists",
            ],
            &["/etc/ghars/pat"],
            &["NFC", "if the character was intentional", "hidden character"],
        );
    }

    /// `token_file` containing U+FE00 (VARIATION SELECTOR-1, low
    /// boundary of U+FE00..=U+FE0F) routes to the remove-only
    /// sub-arm. Pins the lower edge of the BMP VS range against an
    /// off-by-one regression in the matches arm.
    #[test]
    fn validate_pat_xor_rejects_token_file_with_variation_selector_1() {
        let cfg = cfg_with_pat_auth("pat", None, Some("/etc/ghars\u{FE00}/pat"));
        assert_pat_xor_rejects(
            &cfg,
            "pat",
            &[
                "token_file",
                "combining mark",
                "U+FE00",
                "byte offset",
                "remove the codepoint",
                "no precomposed equivalent exists",
            ],
            &["/etc/ghars/pat"],
            &["NFC", "if the character was intentional", "hidden character"],
        );
    }

    /// `token_file` containing U+E0100 (VARIATION SELECTOR-17, low
    /// boundary of the supplementary VS17..=VS256 range at
    /// U+E0100..=U+E01EF). Same threat shape as BMP VS chars: Mn but
    /// no NFC composition. Pins the SMP boundary so a regression
    /// that lists only the BMP range surfaces here.
    #[test]
    fn validate_pat_xor_rejects_token_file_with_variation_selector_17() {
        let cfg = cfg_with_pat_auth("pat", None, Some("/etc/ghars\u{E0100}/pat"));
        assert_pat_xor_rejects(
            &cfg,
            "pat",
            &[
                "token_file",
                "combining mark",
                "U+E0100",
                "byte offset",
                "remove the codepoint",
                "no precomposed equivalent exists",
            ],
            &["/etc/ghars/pat"],
            &["NFC", "if the character was intentional", "hidden character"],
        );
    }

    /// `token_file` containing U+E01EF (VARIATION SELECTOR-256, high
    /// boundary of the supplementary VS17..=VS256 range at
    /// U+E0100..=U+E01EF). Pins the SMP closed-range upper edge —
    /// symmetric with VS-16 (U+FE0F) pinning the BMP upper edge. A
    /// regression that flips `..=` to `..` or truncates to U+E01EE
    /// surfaces here.
    #[test]
    fn validate_pat_xor_rejects_token_file_with_variation_selector_256() {
        let cfg = cfg_with_pat_auth("pat", None, Some("/etc/ghars\u{E01EF}/pat"));
        assert_pat_xor_rejects(
            &cfg,
            "pat",
            &[
                "token_file",
                "combining mark",
                "U+E01EF",
                "byte offset",
                "remove the codepoint",
                "no precomposed equivalent exists",
            ],
            &["/etc/ghars/pat"],
            &["NFC", "if the character was intentional", "hidden character"],
        );
    }

    /// `token_file` containing U+0483 (COMBINING CYRILLIC TITLO)
    /// routes to the diacritical sub-arm: "combining mark" + offer
    /// both remove-or-NFC remediations. The diacritical sub-arm is
    /// the conservative default for any Mn codepoint not explicitly
    /// listed in the no-NFC-form match.
    #[test]
    fn validate_pat_xor_rejects_token_file_with_cyrillic_combining_mark() {
        let cfg = cfg_with_pat_auth("pat", None, Some("/etc/ghars\u{0483}/pat"));
        assert_pat_xor_rejects(
            &cfg,
            "pat",
            &[
                "token_file",
                "combining mark",
                "U+0483",
                "byte offset",
                "remove the codepoint",
                "precomposed (NFC) form",
                "if the character was intentional",
            ],
            &["/etc/ghars/pat"],
            &["no precomposed equivalent exists", "hidden character"],
        );
    }

    /// #672: `token_env` containing U+061C (Arabic Letter Mark)
    /// rejects via the hidden-char gate. ALM is one of the
    /// individually-listed Cf-class chars expanded in #672.
    #[test]
    fn validate_pat_xor_rejects_token_env_with_arabic_letter_mark() {
        let cfg = cfg_with_pat_auth("pat", Some("FOO\u{061C}BAR"), None);
        assert_pat_xor_rejects(
            &cfg,
            "pat",
            &["token_env", "hidden character", "U+061C", "byte offset"],
            &["GHARS_PAT"],
            &[],
        );
    }

    /// #676: `token_file = "/etc/ghars/with\nnewline"` (embedded
    /// newline in a path) now rejects via the hidden-char gate.
    /// Pre-#676 the `\t` `\n` `\r` carve-out whitelisted these
    /// chars, so a path with a literal newline survived the
    /// hidden-char scan and the trim-mismatch gate (the path's
    /// edges had no whitespace) — flowing through to apply where
    /// `open(2)` would either succeed on a bizarre path or fail
    /// with confusing diagnostics. Post-#676 the carve-out is
    /// dropped: ALL Cc chars reject in token_file. Defense-in-depth
    /// pin against operator typos and attacker-injected paths.
    #[test]
    fn validate_pat_xor_rejects_token_file_with_embedded_newline() {
        let cfg = cfg_with_pat_auth("pat", None, Some("/etc/ghars/with\nnewline"));
        assert_pat_xor_rejects(
            &cfg,
            "pat",
            &["token_file", "hidden character", "U+000A", "byte offset"],
            &["/etc/ghars/pat"],
            &["leading or trailing whitespace"],
        );
    }

    /// #676: `token_file` with embedded TAB (U+0009) rejects
    /// post-#676. Symmetric with the embedded-newline pin; the
    /// pre-#676 carve-out covered all three of \t \n \r. Pinned so
    /// a regression that re-introduces any one of the three is
    /// caught.
    #[test]
    fn validate_pat_xor_rejects_token_file_with_embedded_tab() {
        let cfg = cfg_with_pat_auth("pat", None, Some("/etc/ghars/with\tab"));
        assert_pat_xor_rejects(
            &cfg,
            "pat",
            &["token_file", "hidden character", "U+0009", "byte offset"],
            &["/etc/ghars/pat"],
            &["leading or trailing whitespace"],
        );
    }

    /// #674: `token_env = "_"` (single underscore) — the shortest
    /// legal POSIX env var name MUST pass. Boundary check on the
    /// regex's first-char class `[A-Za-z_]` paired with the `*`
    /// quantifier on the trailing chars (zero-or-more allows a
    /// single-char name).
    #[test]
    fn validate_pat_xor_accepts_token_env_single_underscore() {
        let cfg = cfg_with_pat_auth("pat", Some("_"), None);
        validate_pat_xor(&cfg).expect("single-underscore POSIX token_env must pass shape gate");
    }

    /// #674: multi-Pat where the first bad Pat fails on charset and
    /// the second bad Pat fails on hidden-char. The validator
    /// early-returns on the FIRST bad Pat — the diagnostic must
    /// surface the charset gate's text, never the hidden-char text.
    /// Pinned so a regression that "accumulates" or reorders the
    /// fault evaluation across multi-Pat surfaces is caught.
    #[test]
    fn validate_pat_xor_rejects_first_bad_pat_charset_before_hidden_char_pat() {
        let mut cfg = cfg_with_pat_auth("bad-charset", Some("FOO-BAR"), None);
        cfg.auth.insert(
            "bad-hidden".into(),
            crate::config::AuthSpec::Pat {
                token_env: Some("FOO\u{FEFF}BAR".into()),
                token_file: None,
            },
        );
        assert_pat_xor_rejects(
            &cfg,
            "bad-charset",
            &["token_env", "POSIX environment variable name"],
            &["GHARS_PAT"],
            &["\"bad-hidden\"", "hidden character"],
        );
    }

    /// #674 reverse-ordering pin: multi-Pat where the lexicographically
    /// FIRST entry (BTreeMap iteration order) fails on hidden-char and
    /// the second entry fails on charset. The validator early-returns
    /// on the first bad Pat — the diagnostic must surface the
    /// hidden-char gate's text, never the charset text. Symmetric with
    /// the charset-before-hidden pin above; together they pin
    /// iteration-order independence: whichever fault comes first in
    /// BTreeMap order is the one surfaced, regardless of fault class.
    #[test]
    fn validate_pat_xor_rejects_first_bad_pat_hidden_char_before_charset_pat() {
        let mut cfg = cfg_with_pat_auth("aa-bad-hidden", Some("FOO\u{FEFF}BAR"), None);
        cfg.auth.insert(
            "zz-bad-charset".into(),
            crate::config::AuthSpec::Pat {
                token_env: Some("FOO-BAR".into()),
                token_file: None,
            },
        );
        assert_pat_xor_rejects(
            &cfg,
            "aa-bad-hidden",
            &["token_env", "hidden character", "U+FEFF"],
            &["GHARS_PAT"],
            &["\"zz-bad-charset\"", "POSIX environment variable name"],
        );
    }

    /// #675: `token_env` with a Cyrillic letter (U+0411 CYRILLIC
    /// CAPITAL LETTER BE) rejects via the POSIX charset gate. The
    /// regex's `[A-Za-z]` class is ASCII-only; non-ASCII letters
    /// fail. Pinned so a regression that loosens the regex to
    /// `\w` (Unicode word character) is caught.
    #[test]
    fn validate_pat_xor_rejects_token_env_with_cyrillic_letter() {
        let cfg = cfg_with_pat_auth("pat", Some("\u{0411}FOO"), None);
        assert_pat_xor_rejects(
            &cfg,
            "pat",
            &["token_env", "POSIX environment variable name"],
            &["GHARS_PAT"],
            &["hidden character"],
        );
    }

    /// #675: `token_env` with a fullwidth digit (U+FF11 FULLWIDTH
    /// DIGIT ONE) rejects via the POSIX charset gate. Fullwidth
    /// digits are Unicode `Nd` general category but outside the
    /// ASCII `[0-9]` class. Pinned alongside Cyrillic so a future
    /// regression that switches to `\d` is caught.
    #[test]
    fn validate_pat_xor_rejects_token_env_with_fullwidth_digit() {
        let cfg = cfg_with_pat_auth("pat", Some("FOO\u{FF11}"), None);
        assert_pat_xor_rejects(
            &cfg,
            "pat",
            &["token_env", "POSIX environment variable name"],
            &["GHARS_PAT"],
            &["hidden character"],
        );
    }

    /// #675: `token_env = "FOO.BAR"` (embedded dot) rejects via the
    /// POSIX charset gate. Dot is a common shell-config typo for
    /// underscore — operators sometimes write `MY.VAR` thinking
    /// it's valid. The regex anchors charset to `[A-Za-z0-9_]` so
    /// dot fails.
    #[test]
    fn validate_pat_xor_rejects_token_env_with_dot() {
        let cfg = cfg_with_pat_auth("pat", Some("FOO.BAR"), None);
        assert_pat_xor_rejects(
            &cfg,
            "pat",
            &["token_env", "POSIX environment variable name"],
            &["GHARS_PAT"],
            &[],
        );
    }

    /// #675: `token_env = "FOO$BAR"` (embedded dollar) rejects via
    /// the POSIX charset gate. Dollar is the shell variable
    /// expansion sigil — operators sometimes paste the SHELL
    /// REFERENCE form instead of the NAME. Pinned so the gate
    /// catches this common shape.
    #[test]
    fn validate_pat_xor_rejects_token_env_with_dollar() {
        let cfg = cfg_with_pat_auth("pat", Some("FOO$BAR"), None);
        assert_pat_xor_rejects(
            &cfg,
            "pat",
            &["token_env", "POSIX environment variable name"],
            &["GHARS_PAT"],
            &[],
        );
    }

    // -------- #678: Mn-class combining-mark rejection -------------------

    /// #678: `is_disallowed_hidden_char(U+0300)` (COMBINING GRAVE
    /// ACCENT, general category Mn — Mark, nonspacing) returns
    /// true via the new Mn-class arm. Pre-#678 only the explicit
    /// listed Mn codepoints (CGJ U+034F, variation selectors
    /// U+FE00..=U+FE0F) rejected; arbitrary combining marks like
    /// U+0300..=U+036F passed through. Pinned to catch a regression
    /// that drops the GeneralCategory check.
    #[test]
    fn is_disallowed_hidden_char_rejects_combining_grave_accent() {
        assert!(is_disallowed_hidden_char('\u{0300}'));
    }

    /// #678: `is_disallowed_hidden_char(U+0301)` (COMBINING ACUTE
    /// ACCENT, also Mn) returns true. Pinned alongside U+0300 so
    /// the property is exercised at both ends of the
    /// combining-diacritical-marks block (U+0300..=U+036F).
    #[test]
    fn is_disallowed_hidden_char_rejects_combining_acute_accent() {
        assert!(is_disallowed_hidden_char('\u{0301}'));
    }

    /// #678: `is_disallowed_hidden_char('a')` returns false — base
    /// ASCII letters are not Mn, not Cc, not in the explicit list.
    /// Negative pin so a regression that broadens the
    /// general-category check (e.g. accidentally rejects all
    /// `Mark` rather than `NonspacingMark`) is caught.
    #[test]
    fn is_disallowed_hidden_char_accepts_ascii_letter() {
        assert!(!is_disallowed_hidden_char('a'));
    }

    /// #678: `is_disallowed_hidden_char(U+00E0)` (LATIN SMALL LETTER
    /// A WITH GRAVE, the precomposed NFC form of `a + U+0300`)
    /// returns false. U+00E0 is `Ll` (Letter, lowercase) — NOT Mn —
    /// so the precomposed form is safe to use in
    /// internationalized config paths. Pinned so the doc-comment
    /// claim "operators with internationalized paths should use
    /// precomposed (NFC) forms" is empirically grounded.
    #[test]
    fn is_disallowed_hidden_char_accepts_precomposed_a_grave() {
        assert!(!is_disallowed_hidden_char('\u{00E0}'));
    }

    /// #678: `token_file = "pa\u{0300}t"` (path containing a base
    /// `t` overlaid with COMBINING GRAVE ACCENT) rejects via the
    /// hidden-char gate. The Mn arm catches the U+0300 codepoint;
    /// pre-#678 this would have flowed through every shape gate
    /// because `is_control()` doesn't catch combining marks and
    /// the explicit list didn't cover the generic combining-
    /// diacriticals block. Post-#694 the diagnostic is the
    /// dedicated "combining mark" + "precomposed (NFC)" form, not
    /// the generic "hidden character" framing — pinned alongside
    /// codepoint + byte offset so a regression that reverts the
    /// Mn-specific branch surfaces here.
    #[test]
    fn validate_pat_xor_rejects_token_file_with_combining_mark() {
        let cfg = cfg_with_pat_auth("pat", None, Some("pa\u{0300}t"));
        assert_pat_xor_rejects(
            &cfg,
            "pat",
            &["token_file", "combining mark", "U+0300", "byte offset", "precomposed", "NFC"],
            &["/etc/ghars/pat"],
            &["hidden character"],
        );
    }

    /// #693: regression pin — CGJ (U+034F COMBINING GRAPHEME JOINER)
    /// was explicitly listed in `is_disallowed_hidden_char` pre-#678
    /// and is now subsumed by the Mn-class arm. If the
    /// `unicode-general-category` crate ever misclassifies U+034F
    /// (e.g. via a UCD-table regeneration bug), this test surfaces
    /// the regression — without an explicit codepoint listing the
    /// Mn arm is the only line of defense.
    #[test]
    fn is_disallowed_hidden_char_rejects_combining_grapheme_joiner() {
        assert!(is_disallowed_hidden_char('\u{034F}'));
    }

    /// #693: regression pin — VS-16 (U+FE0F VARIATION SELECTOR-16,
    /// the emoji variant selector) was explicitly listed in
    /// `is_disallowed_hidden_char` pre-#678 (as part of the
    /// U+FE00..=U+FE0F range) and is now subsumed by the Mn-class
    /// arm. If the unicode-general-category crate ever misclassifies
    /// U+FE0F, this test surfaces it.
    #[test]
    fn is_disallowed_hidden_char_rejects_variation_selector() {
        assert!(is_disallowed_hidden_char('\u{FE0F}'));
    }

    /// #696: negative pin — U+0903 DEVANAGARI SIGN VISARGA is Mc
    /// (Spacing_Mark), NOT Mn. Defends against accidentally
    /// broadening the check to all Mark class (Mn+Mc+Me). Without
    /// this pin a future regression that swaps the
    /// `GeneralCategory::NonspacingMark` check for a generic
    /// `Mark` predicate would silently start rejecting legitimate
    /// internationalized scripts that rely on spacing marks.
    #[test]
    fn is_disallowed_hidden_char_accepts_spacing_mark() {
        assert!(!is_disallowed_hidden_char('\u{0903}'));
    }

    // -------- #673: validate_auth_keys tests ----------------------------

    /// #673: a properly-shaped auth key (matches IDENTIFIER_REGEX:
    /// lowercase letters + digits + dashes, starts with letter,
    /// ends with letter/digit) MUST pass validate_auth_keys. The
    /// canonical "pat" key from cfg_with_runner_trust_zone is the
    /// happy-path pin.
    #[test]
    fn validate_auth_keys_accepts_canonical_pat() {
        let cfg = cfg_with_runner_trust_zone("buckos", "default".into());
        validate_auth_keys(&cfg).expect("canonical 'pat' auth key must pass");
    }

    /// #673: an auth key matching the kebab-case identifier shape
    /// (multi-segment with internal dashes) MUST pass. Pinned so
    /// the regex `^[a-z]([a-z0-9-]*[a-z0-9])?$` is exercised at the
    /// multi-segment boundary, not just the single-word case.
    #[test]
    fn validate_auth_keys_accepts_kebab_case_multi_segment() {
        let cfg = cfg_with_pat_auth("alpha-zone-creds", Some("GHARS_PAT"), None);
        validate_auth_keys(&cfg).expect("kebab-case multi-segment auth key must pass");
    }

    /// #673: an auth key with an underscore (e.g. "alpha_zone_creds")
    /// rejects via validate_identifier — IDENTIFIER_REGEX is
    /// kebab-only (`[a-z0-9-]`), no underscores. Operators
    /// migrating from snake_case TOML conventions need a clear
    /// rejection rather than a confusing apply-time error.
    #[test]
    fn validate_auth_keys_rejects_underscore() {
        let mut cfg = cfg_with_runner_trust_zone("buckos", "default".into());
        cfg.auth.clear();
        cfg.auth.insert(
            "alpha_zone_creds".into(),
            crate::config::AuthSpec::Pat {
                token_env: Some("GHARS_PAT".into()),
                token_file: None,
            },
        );
        let err = validate_auth_keys(&cfg).expect_err("underscore must reject");
        match err {
            GharsError::Validation(msg, _) => {
                assert!(
                    msg.contains("auth \"alpha_zone_creds\""),
                    "msg must scope to auth key; got: {msg}"
                );
                assert!(
                    msg.contains("identifier invalid"),
                    "msg must come from validate_identifier; got: {msg}"
                );
            }
            other => panic!("expected GharsError::Validation, got {other:?}"),
        }
    }

    /// #673: an auth key with an uppercase letter rejects.
    /// IDENTIFIER_REGEX is lowercase-only.
    #[test]
    fn validate_auth_keys_rejects_uppercase() {
        let mut cfg = cfg_with_runner_trust_zone("buckos", "default".into());
        cfg.auth.clear();
        cfg.auth.insert(
            "PAT".into(),
            crate::config::AuthSpec::Pat {
                token_env: Some("GHARS_PAT".into()),
                token_file: None,
            },
        );
        let err = validate_auth_keys(&cfg).expect_err("uppercase auth key must reject");
        assert!(matches!(err, GharsError::Validation(..)));
    }

    /// #673: an auth key starting with a dash rejects.
    /// IDENTIFIER_REGEX requires a leading letter.
    #[test]
    fn validate_auth_keys_rejects_dash_leading() {
        let mut cfg = cfg_with_runner_trust_zone("buckos", "default".into());
        cfg.auth.clear();
        cfg.auth.insert(
            "-pat".into(),
            crate::config::AuthSpec::Pat {
                token_env: Some("GHARS_PAT".into()),
                token_file: None,
            },
        );
        let err = validate_auth_keys(&cfg).expect_err("dash-leading auth key must reject");
        assert!(matches!(err, GharsError::Validation(..)));
    }

    /// #673: an empty auth key rejects via the empty-input arm of
    /// validate_identifier. TOML allows empty quoted keys
    /// (`[auth.""]`), so this is reachable from operator input.
    #[test]
    fn validate_auth_keys_rejects_empty() {
        let mut cfg = cfg_with_runner_trust_zone("buckos", "default".into());
        cfg.auth.clear();
        cfg.auth.insert(
            String::new(),
            crate::config::AuthSpec::Pat {
                token_env: Some("GHARS_PAT".into()),
                token_file: None,
            },
        );
        let err = validate_auth_keys(&cfg).expect_err("empty auth key must reject");
        assert!(matches!(err, GharsError::Validation(..)));
    }

    /// #673: an auth key with embedded whitespace rejects. Pinned
    /// to catch the case where TOML's quoted-key syntax allows
    /// `[auth."FOO BAR"]` as a literal string but the validator
    /// still surfaces a clear rejection.
    #[test]
    fn validate_auth_keys_rejects_embedded_whitespace() {
        let mut cfg = cfg_with_runner_trust_zone("buckos", "default".into());
        cfg.auth.clear();
        cfg.auth.insert(
            "foo bar".into(),
            crate::config::AuthSpec::Pat {
                token_env: Some("GHARS_PAT".into()),
                token_file: None,
            },
        );
        let err = validate_auth_keys(&cfg).expect_err("whitespace in auth key must reject");
        assert!(matches!(err, GharsError::Validation(..)));
    }

    /// #673: validate_auth_keys walks every entry. When the first
    /// entry passes and the second fails, the validator surfaces
    /// the second's error. Pinned to catch a regression that early-
    /// returns on the first entry (only checking entry 0).
    #[test]
    fn validate_auth_keys_walks_past_valid_to_invalid() {
        let mut cfg = cfg_with_runner_trust_zone("buckos", "default".into());
        cfg.auth.clear();
        cfg.auth.insert(
            "good-pat".into(),
            crate::config::AuthSpec::Pat {
                token_env: Some("GHARS_PAT".into()),
                token_file: None,
            },
        );
        cfg.auth.insert(
            "bad_pat".into(),
            crate::config::AuthSpec::Pat {
                token_env: Some("GHARS_PAT".into()),
                token_file: None,
            },
        );
        let err = validate_auth_keys(&cfg).expect_err("second invalid auth key must reject");
        match err {
            GharsError::Validation(msg, _) => {
                assert!(
                    msg.contains("auth \"bad_pat\""),
                    "must scope to second key; got: {msg}"
                );
            }
            other => panic!("expected GharsError::Validation, got {other:?}"),
        }
    }

    /// #673 load_config integration pin: a TOML config that has a
    /// shape-valid `[auth.NAME]` Pat block but uses a quoted key
    /// containing whitespace (`[auth."bad key"]`) MUST reject at
    /// load_config time via the validate_auth_keys gate, BEFORE the
    /// downstream validate_pat_xor gate ever runs. Pinned end-to-end
    /// (file → load_config → first failing validator) because
    /// load_config is the single chokepoint that every CLI subcommand
    /// (cmd_validate, cmd_plan, cmd_apply, cmd_status, cmd_add) routes
    /// through; a regression that drops validate_auth_keys from the
    /// load_config sequence would silently accept hostile keys at all
    /// five callsites at once. The Pat block's token_env is shape-valid
    /// (`GHARS_PAT` passes POSIX charset and hidden-char gates) so the
    /// rejection here can ONLY come from validate_auth_keys — proves
    /// load_config wiring order.
    #[test]
    fn load_config_rejects_auth_key_with_space_before_pat_xor_gate() {
        let tmp = tempfile::tempdir().unwrap();
        let config_path = Utf8PathBuf::from_path_buf(tmp.path().to_path_buf())
            .unwrap()
            .join("ghars.toml");
        // Quoted key syntax: TOML accepts `[auth."bad key"]` as a
        // literal string key with embedded whitespace. The Pat block
        // is otherwise valid (token_env = "GHARS_PAT" passes every
        // validate_pat_xor gate).
        let body = "\
[defaults]
prefix = \"/var/lib/ghars\"

[auth.\"bad key\"]
kind = \"pat\"
token_env = \"GHARS_PAT\"

[[runner]]
name = \"buckos\"
url = \"https://github.com/owner/repo\"
auth = \"bad key\"
";
        fs::write(config_path.as_std_path(), body).unwrap();
        let err = load_config(&config_path).expect_err("space-bearing auth key must reject");
        match err {
            GharsError::Validation(msg, _) => {
                assert!(
                    msg.contains("auth \"bad key\""),
                    "msg must scope to the offending auth key; got: {msg}"
                );
                assert!(
                    msg.contains("identifier invalid"),
                    "msg must come from validate_identifier (validate_auth_keys), \
                     not validate_pat_xor; got: {msg}"
                );
            }
            other => panic!("expected GharsError::Validation, got {other:?}"),
        }
    }

    // -------- #402: cache pool name length cap --------------------------

    /// Pins (a) `validate_cache_pool_names` returns a Validation error
    /// scoped to the offending pool, (b) the error preserves the
    /// cache-pool-cap layer signature (`ghars-cache-` in the message),
    /// and (c) Validation maps to exit code 6 via `err_to_exit_code`.
    /// Wire-up at cmd_validate / cmd_plan / cmd_apply is structurally
    /// verified by code review; end-to-end integration tests are
    /// tracked by #239.
    #[test]
    fn validate_cache_pool_names_rejects_oversize_pool_with_exit_code_six() {
        let mut cfg = cfg_with_runner_trust_zone("buckos", "default".into());
        let pool_name = "a".repeat(crate::validators::CACHE_POOL_NAME_MAX_LEN + 1);
        cfg.cache_pools.insert(
            pool_name.clone(),
            crate::config::CachePoolSpec {
                kinds: vec![crate::config::CacheKind::Sccache],
                size: "200G".into(),
                mode: crate::config::CacheMode::default(),
                trust_zone: "default".into(),
            },
        );
        let err = validate_cache_pool_names(&cfg).expect_err("oversize pool name must reject");
        match &err {
            GharsError::Validation(msg, hint) => {
                assert!(
                    msg.contains("cache_pool") && msg.contains(&pool_name),
                    "msg must scope to the offending pool by name; got: {msg}"
                );
                assert!(
                    msg.contains("ghars-cache-"),
                    "msg must come from the cache-pool-cap layer (mentions \
                     derived group prefix), not the identifier-cap layer; \
                     got: {msg}"
                );
                // #425 / #431-DA-1: hint covers BOTH callsite contexts —
                // the [cache_pools.NAME] TOML key AND the [[runner]].caches
                // reference list — so the operator isn't misdirected when
                // the offender is a runner.caches entry rather than a
                // pool key. Pins the generic hint contract.
                assert!(
                    hint.contains("[cache_pools.NAME]") && hint.contains("[[runner]].caches"),
                    "hint must mention both [cache_pools.NAME] keys and \
                     [[runner]].caches references; got: {hint}"
                );
            }
            other => panic!("expected GharsError::Validation, got {other:?}"),
        }
        assert_eq!(
            err_to_exit_code(&err),
            6,
            "Validation must map to exit code 6 (Part 5)"
        );
    }

    /// #407 acceptance boundary: a runner.caches entry whose length
    /// exactly equals `CACHE_POOL_NAME_MAX_LEN` must pass — and
    /// the same name as a cache_pools key must also pass. Pins the
    /// inclusive-of-MAX_LEN contract so a future tightening of the
    /// cap (e.g. accidental change to `<` instead of `<=`) is caught
    /// by this test rather than by an operator hitting a previously-
    /// valid config.
    #[test]
    fn validate_cache_pool_names_accepts_runner_caches_at_max_len() {
        let mut cfg = cfg_with_runner_trust_zone("buckos", "default".into());
        let at_max = "a".repeat(crate::validators::CACHE_POOL_NAME_MAX_LEN);
        // Both the cache_pools key AND the runner.caches reference use
        // the same MAX_LEN string — this exercises both inner loops in
        // validate_cache_pool_names.
        cfg.cache_pools.insert(
            at_max.clone(),
            crate::config::CachePoolSpec {
                kinds: vec![crate::config::CacheKind::Sccache],
                size: "200G".into(),
                mode: crate::config::CacheMode::default(),
                trust_zone: "default".into(),
            },
        );
        cfg.runners[0].caches = vec![at_max.clone()];
        validate_cache_pool_names(&cfg).unwrap_or_else(|e| {
            panic!(
                "{}-char (== MAX_LEN) cache name must accept; got: {e}",
                crate::validators::CACHE_POOL_NAME_MAX_LEN
            )
        });
    }

    // -------- #434 (FIX 3): validate_user_overrides direct unit tests ------
    //
    // The end-to-end variants
    // (`cmd_status_rejects_oversize_runner_user_via_load_config` /
    // `cmd_status_rejects_oversize_defaults_user_via_load_config`) prove
    // the validator is wired into `load_config`. These direct tests pin
    // the function's two-scope contract — (1) `defaults.user` produces
    // the `defaults:` prefix; (2) `runner.user` produces the
    // `runner "NAME":` prefix — without going through cmd_status's
    // dependency on Paths / D-Bus. A future refactor that swaps the
    // scope-prefix wrapper would surface here directly instead of
    // through a dispatch-layer test.

    /// `validate_user_overrides` direct call: a `[defaults] user = "..."`
    /// over the cap rejects with the `defaults:` scope prefix (no
    /// per-runner scope). Pinned because pre-#434 the regex `{0,31}`
    /// accepted 32-char names; the explicit length gate is what
    /// rejects them now, and this test exercises that gate at the
    /// defaults surface.
    #[test]
    fn validate_user_overrides_rejects_oversize_defaults_user() {
        let mut cfg = cfg_with_runner_trust_zone("buckos", "default".into());
        let oversize_user = "a".repeat(crate::validators::USER_MAX_LEN + 1);
        cfg.defaults.user = Some(oversize_user.clone());
        let err = validate_user_overrides(&cfg).expect_err("oversize defaults.user must reject");
        match &err {
            GharsError::Validation(msg, _) => {
                assert!(
                    msg.contains("defaults"),
                    "msg must scope to defaults (NOT a runner); got: {msg}"
                );
                assert!(
                    !msg.contains("runner \""),
                    "msg must NOT carry a runner scope when the offending \
                     field lives in [defaults]; got: {msg}"
                );
                assert!(
                    msg.contains("too long")
                        && msg.contains(&crate::validators::USER_MAX_LEN.to_string()),
                    "msg must come from the user-length-cap layer; got: {msg}"
                );
            }
            other => panic!("expected GharsError::Validation, got {other:?}"),
        }
    }

    /// `validate_user_overrides` direct call: a `[[runner]] user = "..."`
    /// over the cap rejects with the `runner "NAME":` scope prefix (NOT
    /// the `defaults:` scope). Pairs with the defaults-scope test above
    /// to pin both branches in `validate_user_overrides`.
    #[test]
    fn validate_user_overrides_rejects_oversize_runner_user() {
        let mut cfg = cfg_with_runner_trust_zone("buckos", "default".into());
        let oversize_user = "a".repeat(crate::validators::USER_MAX_LEN + 1);
        cfg.runners[0].user = Some(oversize_user.clone());
        let err = validate_user_overrides(&cfg).expect_err("oversize runner.user must reject");
        match &err {
            GharsError::Validation(msg, _) => {
                assert!(
                    msg.contains("runner") && msg.contains("buckos"),
                    "msg must scope to the offending runner by name; got: {msg}"
                );
                assert!(
                    !msg.starts_with("defaults"),
                    "msg must NOT carry the defaults scope when the offending \
                     field lives on a runner; got: {msg}"
                );
                assert!(
                    msg.contains("too long")
                        && msg.contains(&crate::validators::USER_MAX_LEN.to_string()),
                    "msg must come from the user-length-cap layer; got: {msg}"
                );
            }
            other => panic!("expected GharsError::Validation, got {other:?}"),
        }
    }

    // -------- #591: validate_prefix_overrides direct unit tests ------
    //
    // `validators::validate_prefix` existed but had no caller in the
    // config-load pipeline before this fix; an
    // operator-supplied hostile prefix (control chars, `..` traversal,
    // top-level reserved root) flowed straight to `merge_defaults` and
    // downstream `Paths` construction. These direct tests pin the
    // function's two-scope contract — (1) `defaults.prefix` produces
    // the `defaults:` prefix; (2) `runner.prefix` produces the
    // `runner "NAME":` prefix — and exercise the regex-charset gate
    // (which fires before the lstat, so the test is fs-free).

    /// `validate_prefix_overrides` direct call: `[defaults] prefix`
    /// containing a control char (ESC) rejects with the `defaults:`
    /// scope prefix. The regex-charset gate inside `validate_prefix`
    /// fires before the lstat, so this test runs without filesystem
    /// touch — the hostile string is short-circuited at the
    /// `PREFIX_RE.is_match` step.
    #[test]
    fn validate_prefix_overrides_rejects_hostile_defaults_prefix() {
        let mut cfg = cfg_with_runner_trust_zone("buckos", "default".into());
        cfg.defaults.prefix = Some(Utf8PathBuf::from("/var/lib/\x1b[31mghars"));
        let err = validate_prefix_overrides(&cfg).expect_err("hostile defaults.prefix must reject");
        match &err {
            GharsError::Validation(msg, _) => {
                assert!(
                    msg.contains("defaults"),
                    "msg must scope to defaults (NOT a runner); got: {msg}"
                );
                assert!(
                    !msg.contains("runner \""),
                    "msg must NOT carry a runner scope when the offending \
                     field lives in [defaults]; got: {msg}"
                );
                assert!(
                    msg.contains("prefix"),
                    "msg must mention 'prefix' so the operator locates the \
                     offending TOML key; got: {msg}"
                );
                assert!(
                    msg.contains("disallowed characters"),
                    "msg must come from the prefix-charset gate (PREFIX_RE \
                     mismatch), not the lstat or traversal layer; got: {msg}"
                );
            }
            other => panic!("expected GharsError::Validation, got {other:?}"),
        }
    }

    /// `validate_prefix_overrides` direct call: `[[runner]] prefix`
    /// containing a control char (ESC) rejects with the
    /// `runner "NAME":` scope prefix (NOT `defaults:`). Pairs with
    /// the defaults-scope test above to pin both branches.
    #[test]
    fn validate_prefix_overrides_rejects_hostile_runner_prefix() {
        let mut cfg = cfg_with_runner_trust_zone("buckos", "default".into());
        cfg.runners[0].prefix = Some(Utf8PathBuf::from("/srv/\x1b[31mevil"));
        let err = validate_prefix_overrides(&cfg).expect_err("hostile runner.prefix must reject");
        match &err {
            GharsError::Validation(msg, _) => {
                assert!(
                    msg.contains("runner") && msg.contains("buckos"),
                    "msg must scope to the offending runner by name; got: {msg}"
                );
                assert!(
                    !msg.starts_with("defaults"),
                    "msg must NOT carry the defaults scope when the offending \
                     field lives on a runner; got: {msg}"
                );
                assert!(
                    msg.contains("prefix"),
                    "msg must mention 'prefix' so the operator locates the \
                     offending TOML key; got: {msg}"
                );
                assert!(
                    msg.contains("disallowed characters"),
                    "msg must come from the prefix-charset gate (PREFIX_RE \
                     mismatch); got: {msg}"
                );
            }
            other => panic!("expected GharsError::Validation, got {other:?}"),
        }
    }

    /// `validate_prefix_overrides` direct call: traversal segments
    /// (`..`) reject independently of the charset gate. The
    /// `validate_prefix` body checks `..` AFTER the regex match
    /// succeeds, so a string like `/var/lib/../etc` clears the
    /// charset gate and trips the traversal guard. Pin to ensure
    /// future regex tweaks don't drop the traversal layer.
    #[test]
    fn validate_prefix_overrides_rejects_traversal_in_runner_prefix() {
        let mut cfg = cfg_with_runner_trust_zone("buckos", "default".into());
        cfg.runners[0].prefix = Some(Utf8PathBuf::from("/var/lib/../etc"));
        let err = validate_prefix_overrides(&cfg).expect_err("traversal runner.prefix must reject");
        match &err {
            GharsError::Validation(msg, _) => {
                assert!(
                    msg.contains("runner") && msg.contains("buckos"),
                    "msg must scope to the offending runner by name; got: {msg}"
                );
                assert!(
                    msg.contains(".."),
                    "msg must come from the traversal layer (mentions '..'); \
                     got: {msg}"
                );
            }
            other => panic!("expected GharsError::Validation, got {other:?}"),
        }
    }

    /// `validate_prefix_overrides` accepts well-formed prefixes on
    /// both surfaces. Symmetric coverage with the rejection tests
    /// pins that the validator does NOT spuriously reject the
    /// canonical `/var/lib/ghars` deployment path; without this
    /// the rejection tests alone would not catch a regression that
    /// flipped accept/reject polarity.
    #[test]
    fn validate_prefix_overrides_accepts_canonical_paths() {
        let mut cfg = cfg_with_runner_trust_zone("buckos", "default".into());
        cfg.defaults.prefix = Some(Utf8PathBuf::from("/var/lib/ghars"));
        cfg.runners[0].prefix = Some(Utf8PathBuf::from("/srv/ghars-runner"));
        validate_prefix_overrides(&cfg)
            .expect("canonical /var/lib/ghars and /srv/ghars-runner must accept");
    }

    /// End-to-end via `load_config`: a TOML fixture with a hostile
    /// `[defaults] prefix` containing a control char must reach
    /// `cmd_status` as a `Validation` error scoped to `defaults`
    /// mentioning `prefix`. Pins the load_config wiring (#591) — a
    /// future refactor that drops `validate_prefix_overrides` from
    /// the `load_config` dispatch chain would surface here.
    #[test]
    fn cmd_status_rejects_hostile_defaults_prefix_via_load_config() {
        let tmp = tempfile::tempdir().unwrap();
        let config_path = Utf8PathBuf::from_path_buf(tmp.path().to_path_buf())
            .unwrap()
            .join("ghars.toml");
        // ESC byte (\x1b) embedded in defaults.prefix. PREFIX_RE rejects
        // anything outside [A-Za-z0-9/_.-], so the charset gate fires
        // before any filesystem lookup.
        let body = "\
[defaults]
prefix = \"/var/lib/\\u001b[31mghars\"

[auth.pat]
kind = \"pat\"
token_env = \"GHARS_PAT\"

[[runner]]
name = \"buckos\"
url = \"https://github.com/example/repo\"
auth = \"pat\"
";
        fs::write(config_path.as_std_path(), body).unwrap();

        let paths = Paths::default();
        let args = StatusArgs {
            json: false,
            metrics: false,
            health_only: false,
            runners_only: true,
            names: vec![],
        };
        let err = cmd_status(
            &config_path,
            &paths,
            &args,
            ColorMode { enabled: false },
            true,
        )
        .expect_err("hostile defaults.prefix must propagate via load_config");
        match &err {
            GharsError::Validation(msg, _) => {
                assert!(
                    msg.contains("defaults"),
                    "msg must scope to defaults; got: {msg}"
                );
                assert!(
                    msg.contains("prefix"),
                    "msg must mention 'prefix' so the operator locates the \
                     offending TOML key; got: {msg}"
                );
                assert!(
                    msg.contains("disallowed characters"),
                    "msg must come from the prefix-charset gate; got: {msg}"
                );
            }
            other => panic!("expected GharsError::Validation, got: {other:?}"),
        }
        assert_eq!(
            err_to_exit_code(&err),
            6,
            "Validation must map to exit code 6 (Part 5)"
        );
    }

    /// #407 defense-in-depth: a runner.caches entry whose length exceeds
    /// `CACHE_POOL_NAME_MAX_LEN` must reject at config load even when
    /// the cache_pools map itself is empty / valid. Today the planner's
    /// cross-reference rejects unknown names earlier, but that error
    /// is shape-agnostic ("unknown cache pool"). The cap layer here
    /// surfaces a `runner "NAME" caches[]:` scope so the operator sees
    /// which runner referenced the oversize string AND which length-cap
    /// layer rejected it.
    #[test]
    fn validate_cache_pool_names_rejects_oversize_runner_caches_entry() {
        let mut cfg = cfg_with_runner_trust_zone("buckos", "default".into());
        let oversize = "a".repeat(crate::validators::CACHE_POOL_NAME_MAX_LEN + 1);
        cfg.runners[0].caches = vec![oversize.clone()];
        let err =
            validate_cache_pool_names(&cfg).expect_err("oversize runner.caches entry must reject");
        match &err {
            GharsError::Validation(msg, hint) => {
                assert!(
                    msg.contains("runner \"buckos\" caches[]"),
                    "msg must scope to the offending runner.caches entry; \
                     got: {msg}"
                );
                assert!(
                    msg.contains(&oversize),
                    "msg must echo the offending value; got: {msg}"
                );
                assert!(
                    msg.contains("ghars-cache-"),
                    "msg must come from the cache-pool-cap layer (mentions \
                     derived group prefix); got: {msg}"
                );
                // #425 / #431-DA-1: same generic-hint pin as the
                // pool-key sibling test. Pinned BOTH callsite contexts
                // because this is the runner.caches surface — the hint
                // would have been actively misleading pre-#425 if it
                // only mentioned [cache_pools.NAME].
                assert!(
                    hint.contains("[cache_pools.NAME]") && hint.contains("[[runner]].caches"),
                    "hint must mention both [cache_pools.NAME] keys and \
                     [[runner]].caches references; got: {hint}"
                );
            }
            other => panic!("expected GharsError::Validation, got {other:?}"),
        }
        assert_eq!(
            err_to_exit_code(&err),
            6,
            "Validation must map to exit code 6 (Part 5)"
        );
    }

    // ---------- #491: sigil tests ---------------------------------------

    /// #491 / #535: pin the `!` sigil contract for recreate-class UpdateRunner
    /// against an EMPTY `recreate_reasons` Vec. Adds new coverage axes
    /// over `render_action_line_update_runner_sigil_distinguishes_recreate_from_inplace`
    /// (which uses a single non-empty reason): the empty-reasons case
    /// reaches the same `if d.requires_recreate` branch in
    /// `render_action_line`. The column-0 `! ` sigil + `[recreate]`
    /// bracket tag MUST hold even when reasons is empty — the sigil
    /// is the fast-scan signal and is independent of reasons content.
    ///
    /// #535: the empty-reasons branch emits `update: recreate` with NO
    /// parenthetical (omit-parens, not `update: recreate ()`).
    /// `plan::plan_from` sets `requires_recreate =
    /// !recreate_reasons.is_empty()` post-classify, so this path is
    /// unreachable from production today; the omit-parens guard is
    /// defense for hand-constructed `RunnerDelta` test fixtures and
    /// any future construction site that decouples those two fields.
    #[test]
    fn render_action_line_update_runner_recreate_uses_bang_sigil() {
        let action = Action::UpdateRunner(recreate_delta("buckos", vec![]));
        let line = render_action_line(&action, ColorMode { enabled: false }, false);
        assert!(
            line.starts_with("! "),
            "recreate-class UpdateRunner must lead with `! ` at column 0; \
             got: {line}",
        );
        assert!(line.contains("[recreate]"), "got: {line}");
        // #535: empty-reasons path — `update: recreate` (no parens).
        // Pin the `; update: recreate)` shape so the cause-mode joiner
        // (`; ` between drift_cause label and mode) plus the closing
        // outer paren are pinned together — guards against a renderer
        // change that drops either bookend independently.
        assert!(
            line.contains("; update: recreate)"),
            "empty recreate_reasons must render `; update: recreate)` \
             (cause-mode joiner + no parenthetical + closing `)` of \
             the outer summary); got: {line}",
        );
        assert!(
            !line.contains("update: recreate ("),
            "empty recreate_reasons must NOT emit empty parens \
             `update: recreate ()`; got: {line}",
        );
        // Explicit empty-parens-absence guard: no `()` substring
        // anywhere in the rendered line. Catches future renderer
        // regressions that produce empty parens via a different code
        // path (e.g. an unrelated field whose Vec serialization
        // surfaces `()` when empty).
        assert!(
            !line.contains("()"),
            "empty parens must not appear in recreate line; got: {line}",
        );
    }

    /// #533: yellow ANSI color for recreate-class UpdateRunner.
    /// `render_action_line` selects ANSI prefix by Action variant; both
    /// recreate and in-place UpdateRunner paths share `\x1b[33m`
    /// (yellow). Sigil distinction (`!` vs `~`) is the column-0 signal;
    /// color is the variant signal. The wrap shape is `\x1b[33m{sigil}
    /// {summary}\x1b[0m`, so the sigil byte lives INSIDE the ANSI
    /// block.
    #[test]
    fn render_action_line_recreate_update_runner_color_yellow() {
        let action = Action::UpdateRunner(recreate_delta("buckos", vec!["url"]));
        let line = render_action_line(&action, ColorMode { enabled: true }, false);
        assert!(
            line.contains("\x1b[33m"),
            "expected yellow ANSI; got: {line}"
        );
        assert!(line.contains("\x1b[0m"), "expected ANSI reset; got: {line}");
        // The sigil sits inside the ANSI wrap so a strip-ANSI pipe
        // still shows `!` at column 0.
        assert!(
            line.contains("\x1b[33m! "),
            "yellow ANSI must precede the `! ` sigil; got: {line}",
        );
    }

    /// #536: ColorMode.enabled=false produces zero ANSI escapes. This
    /// is the path taken by both `--no-color` and `NO_COLOR` env (and
    /// non-TTY stdout) — see `ColorMode::from_cli`. Sigil placement at
    /// column 0 is independent of color mode.
    #[test]
    fn render_action_line_recreate_update_runner_color_disabled_no_ansi() {
        let action = Action::UpdateRunner(recreate_delta("buckos", vec!["url"]));
        let line = render_action_line(&action, ColorMode { enabled: false }, false);
        assert!(
            !line.contains("\x1b["),
            "ColorMode disabled must produce zero ANSI escapes; got: {line}",
        );
        assert!(line.starts_with("! "), "got: {line}");
        assert!(line.contains("[recreate]"), "got: {line}");
    }

    /// #537: operator-grep parity — `^! ` line count == count of
    /// recreate-class UpdateRunner actions, NOT `summary.recreates.len()`.
    ///
    /// `summary.recreates` is the JSON sibling of the Recreate-class
    /// label list; it includes ALL Action variants whose
    /// `Action::disruption` is `Disruption::Recreate` — CreateRunner,
    /// UpdateRunner-recreate, RemoveRunner, CreateCachePool,
    /// RemoveCachePool. The `!` sigil only marks the UpdateRunner-
    /// recreate branch (F-DA4 in `render_action_line`'s doc-comment).
    ///
    /// Fixture covers the asymmetry: CreateRunner + UpdateRunner-
    /// recreate + in-place UpdateRunner + RemoveRunner + RemoveCachePool.
    /// `^! ` count = 1 (only the UpdateRunner-recreate row); summary
    /// recreate count = 4 (every recreate-class variant). Pins the
    /// strict-greater asymmetry so a future renderer change that
    /// broadens `!` to other variants would fail.
    #[test]
    fn render_action_line_sigil_count_matches_recreate_update_runners() {
        let actions = vec![
            Action::CreateRunner(fake_runner_plan("a")),
            Action::UpdateRunner(recreate_delta("b", vec!["arch"])),
            Action::UpdateRunner(inplace_delta("c")),
            Action::RemoveRunner(fake_identity("d")),
            Action::RemoveCachePool("e".into()),
        ];
        let lines: Vec<String> = actions
            .iter()
            .map(|a| render_action_line(a, ColorMode { enabled: false }, false))
            .collect();
        let bang_count = lines.iter().filter(|l| l.starts_with("! ")).count();
        let summary_recreates: Vec<String> = actions
            .iter()
            .filter(|a| a.disruption() == plan::Disruption::Recreate)
            .map(plan::Action::label)
            .collect();
        assert_eq!(
            bang_count, 1,
            "F-DA4: only UpdateRunner-recreate uses `!`; got bang_count=\
             {bang_count}, lines: {lines:?}",
        );
        assert_eq!(
            summary_recreates.len(),
            4,
            "summary.recreates includes ALL recreate-class variants \
             (CreateRunner + UpdateRunner-recreate + RemoveRunner + \
             RemoveCachePool); got: {summary_recreates:?}",
        );
        assert!(
            summary_recreates.len() > bang_count,
            "asymmetry pin: summary.recreates ({}) > `^! ` count \
             ({bang_count}) when non-UpdateRunner recreate-class \
             actions are present",
            summary_recreates.len(),
        );
    }

    /// #538: `!` column-0 sigil holds under `--diff=true`. The recreate
    /// branch in `render_action_line` synthesizes Created drop-in
    /// blocks from `delta.after.drop_ins` AND emits `- basename` lines
    /// for entries in `before_drop_in_basenames` that are absent from
    /// `after.drop_ins` (#468 Removed-line surface). Both shapes use a
    /// 4-space indent on the basename line (`    + name` / `    -
    /// name`) per `format!("    + {basename}")` / `format!("    -
    /// {basename}")` in `render_action_line`. Body content (when
    /// surfaced for `Created`) lives at 12-space indent under
    /// `push_indented_body`, but this test asserts the basename lines.
    #[test]
    fn render_action_line_recreate_sigil_holds_under_diff_flag() {
        let mut delta = recreate_delta("buckos", vec!["url"]);
        // Populate after.drop_ins so the diff branch synthesizes
        // Created entries.
        delta
            .after
            .drop_ins
            .insert("00-ghars.conf".into(), "[Service]\n".into());
        delta
            .after
            .drop_ins
            .insert("10-memory.conf".into(), "[Service]\nMemoryMax=2G\n".into());
        // Populate before_drop_in_basenames with a basename absent
        // from after.drop_ins so the Removed branch fires (#468).
        delta.before_drop_in_basenames =
            Some(vec!["00-ghars.conf".into(), "99-custom.conf".into()]);
        let line = render_action_line(
            &Action::UpdateRunner(delta),
            ColorMode { enabled: false },
            true,
        );
        let first_line = line.split('\n').next().unwrap_or("");
        assert!(
            first_line.starts_with("! "),
            "recreate header must lead with `! ` even under --diff; \
             first line: {first_line:?}; full: {line}",
        );
        // 4-space indent on basename lines (Created branch).
        assert!(
            line.contains("    + 00-ghars.conf"),
            "Created basename line missing; got: {line}",
        );
        assert!(
            line.contains("    + 10-memory.conf"),
            "Created basename line missing; got: {line}",
        );
        // 4-space indent on basename lines (Removed branch — #468).
        assert!(
            line.contains("    - 99-custom.conf"),
            "Removed basename line missing (before_drop_in_basenames \
             has 99-custom.conf, after.drop_ins does not); got: {line}",
        );
    }

    /// #539: defense-in-depth — `!` MUST NOT appear at column 0 on any
    /// non-recreate-UpdateRunner variant. Sigil vocabulary per
    /// `render_action_line`:
    /// - CreateRunner / CreateCachePool → `+`
    /// - RemoveRunner / RemoveCachePool → `-`
    /// - UpdateRunner-inplace / UpdateCachePool → `~`
    /// - NoOp → ` ` (space)
    /// `!` is reserved for UpdateRunner with `requires_recreate=true`
    /// (F-DA4). Pins the vocabulary so a future refactor cannot
    /// silently broaden `!` to other variants.
    #[test]
    fn render_action_line_bang_sigil_only_on_recreate_update_runner() {
        let cases: Vec<(&str, Action, char)> = vec![
            (
                "CreateRunner",
                Action::CreateRunner(fake_runner_plan("a")),
                '+',
            ),
            (
                "RemoveRunner",
                Action::RemoveRunner(fake_identity("a")),
                '-',
            ),
            (
                "CreateCachePool",
                Action::CreateCachePool(plan::CachePoolPlan {
                    binding: fake_cache_binding("build"),
                    drop_in_body: String::new(),
                    spec_hash: "sha256:0".into(),
                }),
                '+',
            ),
            (
                "UpdateCachePool",
                Action::UpdateCachePool(plan::CachePoolDelta {
                    binding: fake_cache_binding("build"),
                    drop_in_body: String::new(),
                    spec_hash: "sha256:0".into(),
                }),
                '~',
            ),
            (
                "RemoveCachePool",
                Action::RemoveCachePool("build".into()),
                '-',
            ),
            ("NoOp", Action::NoOp("a: in sync".into()), ' '),
            (
                "UpdateRunner-inplace",
                Action::UpdateRunner(inplace_delta("a")),
                '~',
            ),
        ];
        for (name, action, expected_sigil) in cases {
            let line = render_action_line(&action, ColorMode { enabled: false }, false);
            assert!(
                line.starts_with(&format!("{expected_sigil} ")),
                "{name} must lead with `{expected_sigil} `; got: {line}",
            );
            assert!(
                !line.starts_with("! "),
                "{name} must NOT lead with `!` (reserved for recreate-\
                 class UpdateRunner per F-DA4); got: {line}",
            );
        }
    }

    /// #540: F-DA2 shell-safety contract — `!` is followed by a space.
    /// Bash interprets `!word` as history expansion (e.g. `!1234`
    /// recalls a history entry); `! ` prevents that when an operator
    /// pastes a plan line into a shell. Two cases cover both format
    /// branches: bare/plain (sigil at column 0) and bare/color (sigil
    /// after the `\x1b[33m` ANSI prefix). Both must end the `!` byte
    /// with `b' '`. Other shape variants (with field_changes, with
    /// drop-in synthesis, etc.) test the body-block rendering, not
    /// the F-DA2 byte contract — coverage is on the `!` itself, not
    /// the surrounding payload.
    #[test]
    fn render_action_line_bang_sigil_always_followed_by_space() {
        let action_plain = Action::UpdateRunner(recreate_delta("a", vec!["url"]));
        let action_color = Action::UpdateRunner(recreate_delta("a", vec!["url"]));
        let cases: Vec<(&str, Action, ColorMode)> = vec![
            ("bare/plain", action_plain, ColorMode { enabled: false }),
            ("bare/color", action_color, ColorMode { enabled: true }),
        ];
        for (name, action, color) in cases {
            let line = render_action_line(&action, color, false);
            let bang_idx = line
                .find('!')
                .unwrap_or_else(|| panic!("{name}: no `!` in line: {line}"));
            let bytes = line.as_bytes();
            let after_bang = bang_idx + 1;
            assert!(
                after_bang < bytes.len(),
                "{name}: `!` is final byte; got: {line}",
            );
            assert_eq!(
                bytes[after_bang], b' ',
                "{name}: F-DA2 violation — `!` must be followed by ' ' \
                 (bash history expansion guard); got byte 0x{:02x} at \
                 position {after_bang}; line: {line}",
                bytes[after_bang],
            );
        }
    }

    // ---------- #506: detail/exit-code tests ----------------------------

    /// #506: pins that ApplyResult.details can carry multiple Failed
    /// rows interleaved with non-Failed rows. The fixture mirrors what
    /// the apply() loop produces under non-fail_fast: every action's
    /// outcome lands in details, and the success/failure split lives
    /// in `succeeded` / `failed` Vecs (which mirror details by label).
    /// This test pins the data shape; #583 covers integration via the
    /// real apply() loop.
    #[test]
    fn details_carries_multiple_failed_rows_with_independent_summaries() {
        let result = apply::ApplyResult {
            succeeded: vec!["UpdateRunner(b)".into()],
            failed: vec![
                (
                    "CreateCachePool(a)".into(),
                    validation_err("enable failed for a"),
                ),
                (
                    "CreateCachePool(c)".into(),
                    validation_err("enable failed for c"),
                ),
            ],
            details: vec![
                (
                    "CreateCachePool(a)".into(),
                    apply::ApplyOutcome::Failed {
                        error_summary: "enable failed for a".into(),
                        plan_disruption: plan::Disruption::Recreate,
                    },
                ),
                (
                    "UpdateRunner(b)".into(),
                    apply::ApplyOutcome::InPlaceRestarted {
                        files_changed: 1,
                        pools_added: Vec::new(),
                        pools_removed: Vec::new(),
                    },
                ),
                (
                    "CreateCachePool(c)".into(),
                    apply::ApplyOutcome::Failed {
                        error_summary: "enable failed for c".into(),
                        plan_disruption: plan::Disruption::Recreate,
                    },
                ),
            ],
            ..apply::ApplyResult::default()
        };
        // Three rows total: two Failed + one InPlaceRestarted between.
        assert_eq!(result.details.len(), 3);
        let failed_count = result
            .details
            .iter()
            .filter(|(_, o)| matches!(o, apply::ApplyOutcome::Failed { .. }))
            .count();
        assert_eq!(failed_count, 2);
        // Per-row error_summary independence (no shared/overwritten
        // state between Failed rows).
        let failed_summaries: Vec<&str> = result
            .details
            .iter()
            .filter_map(|(_, o)| match o {
                apply::ApplyOutcome::Failed { error_summary, .. } => Some(error_summary.as_str()),
                _ => None,
            })
            .collect();
        assert!(failed_summaries.contains(&"enable failed for a"));
        assert!(failed_summaries.contains(&"enable failed for c"));
        // Failed Vec mirrors details Failed rows by label.
        assert_eq!(result.failed.len(), 2);
        // Exit code: succeeded non-empty + failed non-empty → 4
        // (partial). The Failed details rows do not change the mapping.
        assert_eq!(apply_exit_code(&result, false, false), 4);
    }

    /// #507: pin the per-action prefix shapes cmd_apply emits for each
    /// outcome class. cmd_apply's per-action loop routes by variant to
    /// stdout (NoOp, success) or stderr (Failed); the stream routing
    /// itself is not directly testable without helper extraction
    /// (#581 tracks that refactor). This test reproduces the exact
    /// format!() invocations from the cmd_apply per-action loop and
    /// pins the prefix-shape contract:
    /// - `noop: REASON [none]` (NoOp arm)
    /// - `fail: LABEL [DISRUPTION] (DETAIL)` (Failed match arm)
    /// - `ok: LABEL [DISRUPTION] (DETAIL)` (catch-all arm)
    /// Operator grep pipelines (`^fail:`, `^ok:`, `^noop:`) survive
    /// any future refactor that preserves the prefix vocabulary.
    #[test]
    fn cmd_apply_failed_row_renders_with_fail_prefix_and_disruption_tag() {
        // Failed branch (cmd_apply per-action loop, Failed match arm).
        let fail_label = "CreateCachePool(build)";
        let fail_outcome = apply::ApplyOutcome::Failed {
            error_summary: "systemd: enable failed".into(),
            plan_disruption: plan::Disruption::Recreate,
        };
        let fail_rendered = format!(
            "fail: {fail_label} [{}] ({})",
            fail_outcome.disruption().label(),
            fail_outcome.detail(),
        );
        assert!(fail_rendered.starts_with("fail: "), "got: {fail_rendered}");
        assert!(fail_rendered.contains(fail_label), "got: {fail_rendered}");
        assert!(fail_rendered.contains("[recreate]"), "got: {fail_rendered}");
        assert!(
            fail_rendered.contains("(systemd: enable failed)"),
            "got: {fail_rendered}",
        );

        // Success branch (cmd_apply per-action loop, catch-all arm).
        let ok_label = "UpdateRunner(buckos)";
        let ok_outcome = apply::ApplyOutcome::InPlaceRestarted {
            files_changed: 2,
            pools_added: Vec::new(),
            pools_removed: Vec::new(),
        };
        let ok_rendered = format!(
            "ok: {ok_label} [{}] ({})",
            ok_outcome.disruption().label(),
            ok_outcome.detail(),
        );
        assert!(ok_rendered.starts_with("ok: "), "got: {ok_rendered}");
        assert!(ok_rendered.contains(ok_label), "got: {ok_rendered}");
        assert!(ok_rendered.contains("[restart]"), "got: {ok_rendered}");

        // NoOp branch (cmd_apply per-action loop, NoOp arm).
        // The NoOp arm strips the `NoOp(REASON)` wrapper to emit the
        // bare reason; reproduce that strip here.
        let noop_reason = "buckos: in sync";
        let noop_label_full = format!("NoOp({noop_reason})");
        let stripped = noop_label_full
            .strip_prefix("NoOp(")
            .and_then(|s| s.strip_suffix(')'))
            .unwrap_or(noop_label_full.as_str());
        assert_eq!(stripped, noop_reason);
        let noop_rendered = format!("noop: {stripped} [none]");
        assert!(noop_rendered.starts_with("noop: "), "got: {noop_rendered}");
        assert!(noop_rendered.contains("[none]"), "got: {noop_rendered}");

        // Cross-branch negative pins: each prefix is unique.
        assert!(!fail_rendered.starts_with("ok: "));
        assert!(!fail_rendered.starts_with("noop: "));
        assert!(!ok_rendered.starts_with("fail: "));
        assert!(!ok_rendered.starts_with("noop: "));
        assert!(!noop_rendered.starts_with("fail: "));
        assert!(!noop_rendered.starts_with("ok: "));
    }

    /// #509: exit-code regression pin — `apply_exit_code` failure
    /// precedence (1 / 4 / 5) is unaffected by the addition of Failed
    /// rows to `result.details` (#474). Keys off `result.failed`
    /// (typed-error Vec, source of truth) and `result.succeeded`,
    /// not details. Covers all three failure branches and the four
    /// (detailed-exitcode, detailed-exitcode-recreate) flag combos
    /// for partial-failure to confirm 4 trumps both 2 and 8.
    #[test]
    fn apply_exit_code_unaffected_by_details_failed_rows() {
        let partial = apply::ApplyResult {
            succeeded: vec!["CreateRunner(a)".into()],
            failed: vec![("CreateRunner(b)".into(), validation_err("mock"))],
            details: vec![
                ("CreateRunner(a)".into(), apply::ApplyOutcome::Created),
                (
                    "CreateRunner(b)".into(),
                    apply::ApplyOutcome::Failed {
                        error_summary: "mock".into(),
                        plan_disruption: plan::Disruption::Recreate,
                    },
                ),
            ],
            ..apply::ApplyResult::default()
        };
        // Partial-failure (4) trumps every flag combo: 2 (detailed) and
        // 8 (recreate) both lose to 4.
        for (de, der) in [(false, false), (false, true), (true, false), (true, true)] {
            assert_eq!(apply_exit_code(&partial, de, der), 4, "de={de}, der={der}");
        }

        // Total-auth failure → 5.
        let total_auth = apply::ApplyResult {
            failed: vec![("CreateRunner(a)".into(), auth_err("token mint"))],
            details: vec![(
                "CreateRunner(a)".into(),
                apply::ApplyOutcome::Failed {
                    error_summary: "token mint".into(),
                    plan_disruption: plan::Disruption::Recreate,
                },
            )],
            ..apply::ApplyResult::default()
        };
        assert_eq!(apply_exit_code(&total_auth, false, false), 5);

        // Total non-auth failure → 1.
        let total_non_auth = apply::ApplyResult {
            failed: vec![("CreateRunner(a)".into(), validation_err("mock"))],
            details: vec![(
                "CreateRunner(a)".into(),
                apply::ApplyOutcome::Failed {
                    error_summary: "mock".into(),
                    plan_disruption: plan::Disruption::Recreate,
                },
            )],
            ..apply::ApplyResult::default()
        };
        assert_eq!(apply_exit_code(&total_non_auth, false, false), 1);
    }

    // ---------- #492: cmd_apply summary footer tests --------------------

    /// #492: cmd_apply summary footer mixed-outcome shape.
    /// `render_apply_summary_line` emits the headline triple
    /// (`A applied, F failed, S skipped`) followed by the disruption
    /// parenthetical + `any_recreate` suffix produced by the shared
    /// `format_disruption_tail` (CLN-2 / #471). Disruption labels come
    /// from `Disruption::label()` (not hardcoded literals). This test
    /// pins the apply side only — for plan-side label sourcing see
    /// `render_plan_summary_line_uses_disruption_label_not_hardcoded`.
    #[test]
    fn render_apply_summary_line_mixed_outcomes_full_shape() {
        // Mixed plan: 1 Created + 1 Failed + 1 NoOp.
        let result = apply::ApplyResult {
            details: vec![
                ("CreateRunner(a)".into(), apply::ApplyOutcome::Created),
                (
                    "RemoveRunner(b)".into(),
                    apply::ApplyOutcome::Failed {
                        error_summary: "github: 401".into(),
                        plan_disruption: plan::Disruption::Recreate,
                    },
                ),
                ("NoOp(c: in sync)".into(), apply::ApplyOutcome::NoOp),
            ],
            ..apply::ApplyResult::default()
        };
        let line = render_apply_summary_line(&result);
        // Headline: 1 applied (Created), 1 failed, 1 skipped (NoOp).
        // Disruption: 2 recreate (Created + Failed-Recreate),
        // 0 restart, 1 none (NoOp).
        let expected = format!(
            "Apply: 1 applied, 1 failed, 1 skipped \
             (0 {restart}, 2 {recreate}, 1 {none}). \
             any_recreate: true",
            restart = plan::Disruption::Restart.label(),
            recreate = plan::Disruption::Recreate.label(),
            none = plan::Disruption::None.label(),
        );
        assert_eq!(line, expected);
    }

    /// #522 + #532: applied-bucket coverage for Removed / Recreated /
    /// PoolCreated / PoolRemoved. The pre-#522 test
    /// `render_apply_summary_line_buckets_every_variant_correctly`
    /// only exercises Created / InPlaceRestarted / PoolUpdated /
    /// NoOp / InPlaceSkipped / Failed. This test covers the four
    /// remaining `applied`-bucket variants — all of which are
    /// `Disruption::Recreate` per `ApplyOutcome::disruption` at
    /// apply.rs.
    #[test]
    fn render_apply_summary_line_applied_bucket_covers_remaining_variants() {
        let result = apply::ApplyResult {
            details: vec![
                ("RemoveRunner(a)".into(), apply::ApplyOutcome::Removed),
                ("UpdateRunner(b)".into(), apply::ApplyOutcome::Recreated),
                (
                    "CreateCachePool(c)".into(),
                    apply::ApplyOutcome::PoolCreated,
                ),
                (
                    "RemoveCachePool(d)".into(),
                    apply::ApplyOutcome::PoolRemoved,
                ),
            ],
            ..apply::ApplyResult::default()
        };
        let line = render_apply_summary_line(&result);
        // All four are applied + Disruption::Recreate.
        let expected = format!(
            "Apply: 4 applied, 0 failed, 0 skipped \
             (0 {restart}, 4 {recreate}, 0 {none}). \
             any_recreate: true",
            restart = plan::Disruption::Restart.label(),
            recreate = plan::Disruption::Recreate.label(),
            none = plan::Disruption::None.label(),
        );
        assert_eq!(line, expected);
    }

    /// #524: multi-failure-only plan (all-failed, no successes, no
    /// skips). Pins the headline triple `0 applied, N failed, 0
    /// skipped` and that Failed rows whose `plan_disruption =
    /// Recreate` flip `any_recreate: true` even with zero successful
    /// recreate-class outcomes.
    #[test]
    fn render_apply_summary_line_multi_failure_only_plan() {
        let result = apply::ApplyResult {
            details: vec![
                (
                    "CreateRunner(a)".into(),
                    apply::ApplyOutcome::Failed {
                        error_summary: "github: 401".into(),
                        plan_disruption: plan::Disruption::Recreate,
                    },
                ),
                (
                    "RemoveRunner(b)".into(),
                    apply::ApplyOutcome::Failed {
                        error_summary: "systemd: stop failed".into(),
                        plan_disruption: plan::Disruption::Recreate,
                    },
                ),
                (
                    "UpdateRunner(c)".into(),
                    apply::ApplyOutcome::Failed {
                        error_summary: "fs: write failed".into(),
                        plan_disruption: plan::Disruption::Restart,
                    },
                ),
            ],
            ..apply::ApplyResult::default()
        };
        let line = render_apply_summary_line(&result);
        let expected = format!(
            "Apply: 0 applied, 3 failed, 0 skipped \
             (1 {restart}, 2 {recreate}, 0 {none}). \
             any_recreate: true",
            restart = plan::Disruption::Restart.label(),
            recreate = plan::Disruption::Recreate.label(),
            none = plan::Disruption::None.label(),
        );
        assert_eq!(line, expected);
    }

    /// #525: synthetic `daemon_reload` Failed row — verifies the data
    /// shape apply() produces for the daemon_reload synthetic row, not
    /// apply() behavior directly. apply.rs's post-loop daemon_reload
    /// synthesis pushes a Failed row with `plan_disruption =
    /// Disruption::None` (per #520; Manager.Reload is a cache-flush
    /// with zero blast radius, hand-set explicitly because no `Action`
    /// exists to derive from). The summary footer counts the row as
    /// `failed` in the headline triple AND `none` in the disruption
    /// bucket. `any_recreate` MUST stay false unless some other
    /// Recreate-class row is present.
    #[test]
    fn render_apply_summary_line_synthetic_daemon_reload_failed_row() {
        // daemon_reload-only failure (no other actions).
        let result = apply::ApplyResult {
            details: vec![(
                "daemon_reload".into(),
                apply::ApplyOutcome::Failed {
                    error_summary: "systemd: post-loop reload failed".into(),
                    plan_disruption: plan::Disruption::None,
                },
            )],
            ..apply::ApplyResult::default()
        };
        let line = render_apply_summary_line(&result);
        let expected = format!(
            "Apply: 0 applied, 1 failed, 0 skipped \
             (0 {restart}, 0 {recreate}, 1 {none}). \
             any_recreate: false",
            restart = plan::Disruption::Restart.label(),
            recreate = plan::Disruption::Recreate.label(),
            none = plan::Disruption::None.label(),
        );
        assert_eq!(
            line, expected,
            "daemon_reload Failed (plan_disruption=None) must contribute \
             to `none` bucket and NOT flip any_recreate",
        );
    }

    /// #526: inverse pin — Restart-class Failed must NOT flip
    /// `any_recreate`. `Failed.disruption()` delegates to
    /// `plan_disruption`; for an in-place UpdateRunner that fails
    /// mid-execution, plan-time disruption is Restart, so the row
    /// contributes to `restart` count, NOT `recreate`. `any_recreate`
    /// stays false. Symmetric guard against the
    /// `render_apply_summary_line_failed_recreate_flips_any_recreate`
    /// positive pin.
    #[test]
    fn render_apply_summary_line_restart_class_failed_does_not_flip_any_recreate() {
        let result = apply::ApplyResult {
            details: vec![(
                "UpdateRunner(a)".into(),
                apply::ApplyOutcome::Failed {
                    error_summary: "fs: write failed".into(),
                    plan_disruption: plan::Disruption::Restart,
                },
            )],
            ..apply::ApplyResult::default()
        };
        let line = render_apply_summary_line(&result);
        let expected = format!(
            "Apply: 0 applied, 1 failed, 0 skipped \
             (1 {restart}, 0 {recreate}, 0 {none}). \
             any_recreate: false",
            restart = plan::Disruption::Restart.label(),
            recreate = plan::Disruption::Recreate.label(),
            none = plan::Disruption::None.label(),
        );
        assert_eq!(line, expected);
    }

    // ---------- #547: rollback advisory tests ---------------------------

    /// #547: ordering invariant pin —
    /// `failed_undo_logs[i].0 == failed[i].0` for every `i` in a
    /// multi-failure non-fail_fast scenario. apply::apply pushes
    /// to both Vecs in the same execute-order loop iteration; the
    /// advisory renderer walks `failed_undo_logs` for both the body
    /// blocks and the header count (post-#618: header N is the count
    /// of non-empty step lists, derived directly from
    /// `failed_undo_logs`). Pinning here catches a future refactor
    /// that decouples the two Vecs (e.g. moves the typed-error push
    /// elsewhere) and drifts the label ordering apart.
    #[test]
    fn render_rollback_advisory_failed_and_failed_undo_logs_share_label_ordering() {
        // Use push_failed (#646) to enforce the lockstep invariant
        // at fixture construction — each push pairs the failed entry
        // with its UndoLog so the lengths cannot drift.
        let mut result = apply::ApplyResult::default();
        push_failed(
            &mut result,
            "CreateCachePool(a)",
            vec![apply::UndoStep::CreateDir {
                path: camino::Utf8PathBuf::from("/etc/systemd/system/ghars-cache@a.service.d"),
            }],
        );
        push_failed(
            &mut result,
            "UpdateRunner(b)",
            vec![apply::UndoStep::WriteFile {
                path: camino::Utf8PathBuf::from(
                    "/etc/systemd/system/ghars-runner@b.service.d/00-ghars.conf",
                ),
                prior_content: None,
            }],
        );
        push_failed(
            &mut result,
            "RemoveRunner(c)",
            vec![apply::UndoStep::StopUnit {
                name: "ghars-runner@c.service".into(),
            }],
        );
        // Invariant: failed[i].0 == failed_undo_logs[i].0 for all i.
        assert_eq!(result.failed.len(), result.failed_undo_logs.len());
        for i in 0..result.failed.len() {
            assert_eq!(
                result.failed[i].0, result.failed_undo_logs[i].0,
                "label-pair ordering invariant violated at index {i}",
            );
        }
        // Render advisory and confirm all three labels appear in
        // the same order they were pushed.
        let advisory = render_rollback_advisory(&result).expect("advisory rendered");
        let pos_a = advisory.find("CreateCachePool(a):").expect("a present");
        let pos_b = advisory.find("UpdateRunner(b):").expect("b present");
        let pos_c = advisory.find("RemoveRunner(c):").expect("c present");
        assert!(pos_a < pos_b, "a must precede b: {advisory}");
        assert!(pos_b < pos_c, "b must precede c: {advisory}");
    }

    /// #549: step ordering pin — within a single failed action's
    /// per-action body, steps render in REVERSE (LIFO) order so the
    /// most-recent mutation appears first. Matches `apply::undo`'s
    /// `log.steps().iter().rev()` walk direction. Operator reading
    /// the cleanup checklist top-to-bottom unwinds state in the
    /// same order undo would.
    ///
    /// Same fixture as `render_rollback_advisory_renders_per_action_steps`
    /// (sibling) — that test pins step PRESENCE, this pins step ORDERING.
    #[test]
    fn render_rollback_advisory_renders_steps_in_reverse_lifo_order() {
        // Steps recorded in forward (insertion) order:
        // CreateDir → WriteFile → GroupAdd. Advisory MUST render in
        // reverse: GroupAdd → WriteFile → CreateDir.
        let mut result = apply::ApplyResult::default();
        push_failed(
            &mut result,
            "CreateCachePool(build)",
            vec![
                apply::UndoStep::CreateDir {
                    path: camino::Utf8PathBuf::from(
                        "/etc/systemd/system/ghars-cache@build.service.d",
                    ),
                },
                apply::UndoStep::WriteFile {
                    path: camino::Utf8PathBuf::from(
                        "/etc/systemd/system/ghars-cache@build.service.d/00-ghars.conf",
                    ),
                    prior_content: None,
                },
                apply::UndoStep::GroupAdd {
                    name: "ghars-cache-build".into(),
                },
            ],
        );
        let advisory = render_rollback_advisory(&result).expect("advisory rendered");
        let pos_create_dir = advisory
            .find("created directory /etc/systemd/system/ghars-cache@build.service.d")
            .expect("CreateDir step present");
        let pos_write_file = advisory
            .find("wrote /etc/systemd/system/ghars-cache@build.service.d/00-ghars.conf")
            .expect("WriteFile step present");
        let pos_group_add = advisory
            .find("created group ghars-cache-build")
            .expect("GroupAdd step present");
        // LIFO: GroupAdd (most recent) → WriteFile → CreateDir
        // (earliest, bottom).
        assert!(
            pos_group_add < pos_write_file,
            "GroupAdd must precede WriteFile (LIFO); got: {advisory}",
        );
        assert!(
            pos_write_file < pos_create_dir,
            "WriteFile must precede CreateDir (LIFO); got: {advisory}",
        );
    }

    /// #550 / #551: daemon_reload-only failure renders NO ADVISORY at all.
    /// The daemon_reload synthesis at apply::apply pushes to
    /// `result.failed` AND `result.failed_undo_logs` with an EMPTY
    /// step Vec (no per-action UndoLog exists for the synthetic
    /// post-loop step).
    ///
    /// Per #551, when EVERY entry in `failed_undo_logs` has an empty
    /// step list, `render_rollback_advisory` returns `None` instead
    /// of emitting a header that promises actionable cleanup with
    /// no body underneath. Silence is more honest than a header
    /// without a list. The per-action `fail:` line emitted by
    /// cmd_apply's detail loop already communicates the failure
    /// to the operator.
    ///
    /// `render_rollback_advisory_skips_empty_step_lists` (sibling) pins
    /// the MIXED case (empty + non-empty side by side) — that case
    /// still renders because the non-empty entry contributes a
    /// non-empty body. This test pins the ISOLATED daemon_reload-only
    /// case (no other failures present).
    #[test]
    fn render_rollback_advisory_daemon_reload_only_failure_returns_none() {
        let mut result = apply::ApplyResult::default();
        push_failed(&mut result, "daemon_reload", Vec::new());
        // #551: all-empty step lists ⇒ no advisory at all.
        assert!(
            render_rollback_advisory(&result).is_none(),
            "all-empty failed_undo_logs must suppress the advisory entirely",
        );
    }

    /// #616 / #551: multi-failure all-empty pin — verify the
    /// `filter(!is_empty()).count() == 0` gate scales beyond the
    /// single-entry daemon_reload case. Three failed actions, all
    /// with empty `UndoStep` Vecs (e.g. each errored before recording
    /// any side effect). The advisory renderer should still return
    /// `None` because the filter yields 0 for uniformly-empty input
    /// (every entry is rejected by the `!steps.is_empty()` predicate).
    ///
    /// Sibling: `render_rollback_advisory_daemon_reload_only_failure_returns_none`
    /// pins the single-entry isolated case; this multi-entry fixture
    /// catches a future regression that special-cases N==1 (e.g. if
    /// `result.failed_undo_logs.len() == 1 && ...` — falling back to
    /// emit-anyway when N>=2). Post-#618 the gate is
    /// `failed_undo_logs.iter().filter(|(_, s)| !s.is_empty()).count() == 0`;
    /// 3 uniformly-empty entries make the filter yield 0, matching
    /// the single-entry case. Pinning N>=2 here generalizes the
    /// non-empty-count gate beyond N==1.
    #[test]
    fn render_rollback_advisory_multi_failure_all_empty_returns_none() {
        let mut result = apply::ApplyResult::default();
        push_failed(&mut result, "CreateRunner(a)", Vec::new());
        push_failed(&mut result, "UpdateRunner(b)", Vec::new());
        push_failed(&mut result, "RemoveRunner(c)", Vec::new());
        // #551 multi-entry: all-empty step lists ⇒ no advisory.
        // Pins the post-#618 non-empty-count gate
        // (`filter(!is_empty()).count() == 0`) beyond the single
        // daemon_reload entry. This fixture is hand-constructed
        // (production apply.rs:2147-2149 always pushes the per-action
        // UndoLog with whatever steps were recorded — empty only for
        // pre-side-effect errors), but the rendering contract must
        // hold for the convergent case where every action errored
        // pre-mutation.
        assert!(
            render_rollback_advisory(&result).is_none(),
            "all-empty failed_undo_logs (multi-entry) must suppress the advisory entirely",
        );
    }

    /// #553: positive-control test for the
    /// `result.failed.len() == result.failed_undo_logs.len()`
    /// invariant pin at the top of `render_rollback_advisory`. Equal
    /// lengths satisfy the `debug_assert_eq!`; rendering proceeds
    /// normally and emits the advisory.
    ///
    /// Sibling: `render_rollback_advisory_debug_assert_panics_on_length_mismatch`
    /// (negative-control) drives the assertion failure under
    /// `cfg(debug_assertions)`.
    #[test]
    fn render_rollback_advisory_debug_assert_passes_on_equal_lengths() {
        let mut result = apply::ApplyResult::default();
        push_failed(
            &mut result,
            "CreateCachePool(build)",
            vec![apply::UndoStep::GroupAdd {
                name: "ghars-cache-build".into(),
            }],
        );
        // Equal lengths (1 == 1) ⇒ debug_assert_eq! passes; renderer
        // proceeds to emit the advisory.
        let advisory =
            render_rollback_advisory(&result).expect("equal-length input must render an advisory");
        assert!(
            advisory.contains("CreateCachePool(build):"),
            "advisory must include the failed action label; got: {advisory}",
        );
    }

    /// #553: negative-control test for the length-mismatch invariant.
    /// `apply::apply` pushes to `result.failed` and
    /// `result.failed_undo_logs` in lockstep on every Err arm
    /// (apply.rs:2123/2147-2149 per-action; apply.rs:2188/2201
    /// synthetic daemon_reload). The lengths can only diverge in
    /// hand-constructed `ApplyResult` test fixtures. The
    /// `debug_assert_eq!` at `render_rollback_advisory`'s entry
    /// catches such fixtures (and any future production-code
    /// regression that breaks the lockstep) at dev/CI build time.
    ///
    /// Gated on `cfg(debug_assertions)` because `debug_assert_eq!`
    /// expands to a no-op in release builds (per Rust stdlib's
    /// `debug_assert_eq!` macro doc — same gate as `debug_assert!`).
    /// `cargo nextest run` in CI uses dev profile by default, so the
    /// gate normally fires.
    #[cfg(debug_assertions)]
    #[test]
    #[should_panic(
        expected = "ApplyResult invariant: failed and failed_undo_logs must have equal length"
    )]
    fn render_rollback_advisory_debug_assert_panics_on_length_mismatch() {
        // failed has 1 entry; failed_undo_logs has 0. Production code
        // never produces this shape — pushed in lockstep at every Err
        // path in `apply::apply`. This fixture forces the assertion
        // failure to pin the contract.
        let result = apply::ApplyResult {
            failed: vec![(
                "CreateCachePool(build)".into(),
                validation_err("enable failed"),
            )],
            failed_undo_logs: Vec::new(),
            ..apply::ApplyResult::default()
        };
        let _ = render_rollback_advisory(&result);
    }

    // ---------- #646: render_rollback_advisory test scaffolding ------------

    /// #646: shared helper for `render_rollback_advisory` test fixtures.
    /// Every advisory test that drives the renderer with one or more
    /// failures must push to BOTH `failed` and `failed_undo_logs` in
    /// lockstep — the typed-error tuple and the per-action UndoLog
    /// pairing is the lockstep invariant `apply::apply` enforces in
    /// production (apply.rs Err arms push to both Vecs in the same
    /// loop iteration), and the `debug_assert_eq!` at
    /// `render_rollback_advisory`'s entry pins it. This helper
    /// centralizes the two-Vec append so test fixtures cannot drift
    /// the lengths apart by accident — a missed `failed_undo_logs`
    /// push would otherwise surface as a panic from the
    /// length-equality assertion, far from the test's intent.
    ///
    /// Sibling: `render_rollback_advisory_debug_assert_panics_on_length_mismatch`
    /// negative-controls the assertion; this helper is the
    /// positive-control scaffold every other advisory test uses to
    /// stay on the equal-length path.
    fn push_failed(result: &mut apply::ApplyResult, label: &str, steps: Vec<apply::UndoStep>) {
        result.failed.push((label.into(), validation_err("test")));
        result.failed_undo_logs.push((label.into(), steps));
    }

    // ---------- #651: format_rollback_advisory_header unit tests ----------

    /// #651 / #611: direct unit test for `format_rollback_advisory_header`
    /// at the single-failure case. Pin the exact format string the
    /// helper produces — `Rollback advisory: 1 action(s) failed.
    /// Manual cleanup may be required:` — so a future text change
    /// fails loudly here. The advisory caller
    /// (`render_rollback_advisory`) gates the helper behind `n >= 1`
    /// via the upstream `n == 0` early-return (the
    /// `failed_undo_logs.iter().filter(!is_empty).count() == 0` gate),
    /// so this is the smallest non-zero count the helper sees in
    /// production.
    ///
    /// Sibling: `format_rollback_advisory_header_n_five_format` pins the
    /// multi-failure case; `format_rollback_advisory_header_n_zero_gated_upstream`
    /// documents the upstream gate.
    #[test]
    fn format_rollback_advisory_header_n_one_format() {
        let header = format_rollback_advisory_header(1);
        assert_eq!(
            header, "Rollback advisory: 1 action(s) failed. Manual cleanup may be required:",
            "single-source-of-truth header drift; got: {header}",
        );
    }

    /// #651 / #611: direct unit test at N=5 — the typical
    /// multi-failure case (e.g. an apply run with five actions all
    /// of which left non-empty UndoLogs). Pin the `{n}` interpolation
    /// renders the integer as a decimal without padding or
    /// thousands-separator artifacts.
    ///
    /// Sibling: `format_rollback_advisory_header_n_one_format` pins the
    /// minimum non-zero count.
    #[test]
    fn format_rollback_advisory_header_n_five_format() {
        let header = format_rollback_advisory_header(5);
        assert_eq!(
            header, "Rollback advisory: 5 action(s) failed. Manual cleanup may be required:",
            "header N interpolation drift; got: {header}",
        );
    }

    /// #651 / #611 / #618 / #551: documents that the N=0 case is
    /// gated UPSTREAM — `render_rollback_advisory` returns `None`
    /// when `n == 0` (the
    /// `failed_undo_logs.iter().filter(!is_empty).count() == 0`
    /// gate inside `render_rollback_advisory`), so
    /// `format_rollback_advisory_header(0)` is unreachable from
    /// production callers. This test pins that the helper itself
    /// is a pure formatter and would emit a (defensible but
    /// operator-confusing) `0 action(s) failed.` header if the
    /// gate ever regressed — the test exists to surface that
    /// regression class as a CI failure instead of silent
    /// `Rollback advisory: 0 action(s) failed.` noise on stderr.
    ///
    /// Pin shape: the renderer must not be expected to emit a
    /// special-case message for N=0; the helper produces the
    /// templated string, and the caller's gate is the contract.
    /// If the gate ever regresses, the operator-visible noise will
    /// be `Rollback advisory: 0 action(s) failed.` — the helper's
    /// pure-formatter contract pinned here makes that regression
    /// surface as a CI failure in the gate-side tests
    /// (`render_rollback_advisory_returns_none_on_success`,
    /// `render_rollback_advisory_daemon_reload_only_failure_returns_none`,
    /// `render_rollback_advisory_multi_failure_all_empty_returns_none`),
    /// not as silent noise on operator stderr.
    #[test]
    fn format_rollback_advisory_header_n_zero_gated_upstream() {
        let header = format_rollback_advisory_header(0);
        assert_eq!(
            header, "Rollback advisory: 0 action(s) failed. Manual cleanup may be required:",
            "helper is a pure formatter — N=0 gate is upstream at \
             render_rollback_advisory's filter().count() == 0 \
             early return; got: {header}",
        );
    }

    // ---------- #648 / #649 / #650: render_rollback_advisory N coverage --

    /// #648 / #618: mixed case — two failed actions with EMPTY step
    /// lists + one failed action with a NON-EMPTY step list. The
    /// post-#618 header gate counts only entries with non-empty
    /// step lists, so N=1 (not N=3). The body must contain exactly
    /// ONE per-action sub-block (the non-empty entry).
    ///
    /// This pins the asymmetry between `failed` (3 entries) and the
    /// rendered output (header N=1, body block count=1) under the
    /// most operator-confusing input shape: the per-action
    /// `fail:` lines from cmd_apply's detail loop will report all
    /// three labels, but the advisory's "what to clean up" block
    /// only lists the one entry that actually mutated state.
    /// Sibling: `render_rollback_advisory_skips_empty_step_lists`
    /// covers the 1-empty + 1-non-empty case (N=1, body block
    /// count=1); this test extends to 2-empty + 1-non-empty to
    /// generalize beyond N==1 empty entries.
    #[test]
    fn render_rollback_advisory_mixed_two_empty_one_non_empty() {
        let mut result = apply::ApplyResult::default();
        push_failed(&mut result, "daemon_reload", Vec::new());
        push_failed(&mut result, "RemoveRunner(orphan_a)", Vec::new());
        push_failed(
            &mut result,
            "RemoveRunner(orphan_b)",
            vec![apply::UndoStep::StopUnit {
                name: "ghars-runner@orphan_b.service".into(),
            }],
        );
        let advisory =
            render_rollback_advisory(&result).expect("non-empty entry must yield an advisory");
        // Header: N counts ONLY the non-empty entry (post-#618 gate),
        // not all 3 failed actions.
        assert!(
            advisory.starts_with("Rollback advisory: 1 action(s) failed."),
            "header N must count only non-empty-step entries (1 of 3); got: {advisory}",
        );
        // Both empty-step entries must NOT render as per-action blocks.
        assert!(
            !advisory.contains("\n  daemon_reload:"),
            "empty-step daemon_reload must NOT render a per-action block; got: {advisory}",
        );
        assert!(
            !advisory.contains("\n  RemoveRunner(orphan_a):"),
            "empty-step RemoveRunner(orphan_a) must NOT render a per-action block; \
             got: {advisory}",
        );
        // The single non-empty entry MUST render its block.
        assert!(
            advisory.contains("\n  RemoveRunner(orphan_b):"),
            "non-empty entry must render its block; got: {advisory}",
        );
        // Body block count: count lines that begin with exactly 2
        // spaces followed by a non-space char (the label-line
        // shape `"  LABEL:"`). Step lines begin with 4 spaces
        // (`"    - STEP"`), so `starts_with("  ")` followed by
        // non-space distinguishes label lines from step lines.
        let block_starts = advisory
            .lines()
            .filter(|line| line.starts_with("  ") && !line.starts_with("   "))
            .count();
        assert_eq!(
            block_starts, 1,
            "exactly one per-action sub-block expected; got: {advisory}",
        );
    }

    /// #649 / #618: all-non-empty case — three failed actions, every
    /// one with a non-empty step list. Header N must equal the total
    /// failure count (3) because no entry is filtered out by the
    /// `!is_empty()` predicate. Body must have exactly 3 per-action
    /// sub-blocks. Pins the contract that under uniformly-non-empty
    /// input the post-#618 filter is a no-op vs the pre-#618
    /// `failed_undo_logs.len()` count.
    ///
    /// Sibling: `render_rollback_advisory_failed_and_failed_undo_logs_share_label_ordering`
    /// also covers 3 non-empty entries; that test pins ORDER
    /// (failed[i].0 == failed_undo_logs[i].0). This test is focused
    /// on the HEADER N count == total failures invariant under
    /// all-non-empty conditions.
    #[test]
    fn render_rollback_advisory_all_non_empty_header_matches_total() {
        let mut result = apply::ApplyResult::default();
        push_failed(
            &mut result,
            "CreateRunner(a)",
            vec![apply::UndoStep::GroupAdd {
                name: "ghars-runner-a".into(),
            }],
        );
        push_failed(
            &mut result,
            "CreateRunner(b)",
            vec![apply::UndoStep::GroupAdd {
                name: "ghars-runner-b".into(),
            }],
        );
        push_failed(
            &mut result,
            "CreateRunner(c)",
            vec![apply::UndoStep::GroupAdd {
                name: "ghars-runner-c".into(),
            }],
        );
        let advisory =
            render_rollback_advisory(&result).expect("all-non-empty must yield an advisory");
        // Header N == total failure count (3) under all-non-empty
        // input; the post-#618 filter is a no-op here.
        assert!(
            advisory.starts_with("Rollback advisory: 3 action(s) failed."),
            "header N must equal total non-empty-step entries (3); got: {advisory}",
        );
        // Each label appears as a per-action block.
        assert!(
            advisory.contains("\n  CreateRunner(a):"),
            "CreateRunner(a) block missing; got: {advisory}",
        );
        assert!(
            advisory.contains("\n  CreateRunner(b):"),
            "CreateRunner(b) block missing; got: {advisory}",
        );
        assert!(
            advisory.contains("\n  CreateRunner(c):"),
            "CreateRunner(c) block missing; got: {advisory}",
        );
        // Per-action sub-block count == 3. Count label lines (start
        // with exactly 2 spaces + non-space); step lines start with
        // 4 spaces and are excluded by the negative `starts_with("   ")`
        // (3-space) prefix check.
        let block_starts = advisory
            .lines()
            .filter(|line| line.starts_with("  ") && !line.starts_with("   "))
            .count();
        assert_eq!(
            block_starts, 3,
            "exactly three per-action sub-blocks expected; got: {advisory}",
        );
    }

    /// #650 / #618: alternating order — `failed_undo_logs` Vec ordered
    /// `[non-empty, empty, non-empty]`. Header N=2 (only the two
    /// non-empty entries pass the filter); body must have exactly
    /// two per-action sub-blocks, and they must appear in the
    /// SAME ORDER as the input Vec (first non-empty before second
    /// non-empty), with the empty entry skipped silently in the
    /// middle.
    ///
    /// Pins that the body loop inside `render_rollback_advisory`
    /// (`for (label, steps) in &result.failed_undo_logs { if
    /// steps.is_empty() { continue; } ... }`) walks the Vec in
    /// insertion order — a future reorder (e.g. partition into
    /// non-empty-first then empty-last before iterating) would
    /// scramble the operator's expected ordering relative to the
    /// per-action `fail:` lines emitted by cmd_apply's detail loop.
    ///
    /// Sibling: `render_rollback_advisory_skips_empty_step_lists` pins
    /// the empty-skip contract on a 2-element Vec; this test extends
    /// to a 3-element Vec with the empty entry in the middle to
    /// guard the skip-then-continue path order.
    #[test]
    fn render_rollback_advisory_alternating_order_preserves_position() {
        let mut result = apply::ApplyResult::default();
        // Position 0: non-empty.
        push_failed(
            &mut result,
            "RemoveRunner(first)",
            vec![apply::UndoStep::StopUnit {
                name: "ghars-runner@first.service".into(),
            }],
        );
        // Position 1: empty (skipped by body loop, filtered from
        // header N).
        push_failed(&mut result, "daemon_reload", Vec::new());
        // Position 2: non-empty.
        push_failed(
            &mut result,
            "RemoveRunner(third)",
            vec![apply::UndoStep::StopUnit {
                name: "ghars-runner@third.service".into(),
            }],
        );
        let advisory = render_rollback_advisory(&result)
            .expect("two non-empty entries must yield an advisory");
        // Header: N=2 (only the two non-empty entries; the middle
        // empty entry is filtered out).
        assert!(
            advisory.starts_with("Rollback advisory: 2 action(s) failed."),
            "header N must count only non-empty-step entries (2 of 3); got: {advisory}",
        );
        // Empty-step entry must NOT render.
        assert!(
            !advisory.contains("\n  daemon_reload:"),
            "empty-step entry must NOT render a per-action block; got: {advisory}",
        );
        // Both non-empty entries MUST render.
        let pos_first = advisory
            .find("\n  RemoveRunner(first):")
            .expect("first non-empty entry must render");
        let pos_third = advisory
            .find("\n  RemoveRunner(third):")
            .expect("third non-empty entry must render");
        // Order pin: position-0 entry must precede position-2 entry
        // in the rendered output, even though an empty entry sits
        // between them in the input Vec.
        assert!(
            pos_first < pos_third,
            "first non-empty entry must precede third non-empty entry \
             (insertion-order preservation across the empty skip); \
             got: {advisory}",
        );
        // Body sub-block count: exactly two label lines. Each starts
        // with exactly 2 spaces + non-space; step lines start with 4
        // spaces and are excluded by the negative `starts_with("   ")`
        // (3-space) prefix check.
        let block_starts = advisory
            .lines()
            .filter(|line| line.starts_with("  ") && !line.starts_with("   "))
            .count();
        assert_eq!(
            block_starts, 2,
            "exactly two per-action sub-blocks expected; got: {advisory}",
        );
    }

    // ---------- #585: sigil multi-element recreate_reasons pin -----------

    /// #585 (PASS-2 follow-up to #491): pin the multi-element
    /// `recreate_reasons.join(",")` format the renderer at
    /// `render_action_line` produces. The #491 base test covers the
    /// empty case; this test pins the multi-element case so a
    /// future renderer change to a different separator (e.g.
    /// `, ` with space, `+`, etc.) is caught at the test layer.
    /// Format expected: `update: recreate (url,arch)` — comma
    /// without space between elements.
    ///
    /// This `(REASONS)` parenthetical only applies when
    /// `recreate_reasons` is non-empty. Per #535, the empty-reasons
    /// branch emits `update: recreate` with NO parens (omit-parens
    /// guard at cli.rs:1314-1323) — see
    /// `render_action_line_update_runner_recreate_uses_bang_sigil`
    /// for that pin.
    #[test]
    fn render_action_line_recreate_multi_element_reasons_join_format() {
        let action = Action::UpdateRunner(recreate_delta("buckos", vec!["url", "arch"]));
        let line = render_action_line(&action, ColorMode { enabled: false }, false);
        assert!(line.starts_with("! "), "got: {line}");
        // Pin the exact `recreate_reasons.join(",")` shape: comma-only
        // (no space). The renderer at render_action_line uses
        // `format!("update: recreate ({})", d.recreate_reasons.join(","))`.
        assert!(
            line.contains("update: recreate (url,arch)"),
            "multi-element recreate_reasons must render with comma-only \
             separator (no space); got: {line}",
        );
    }

    // ---------- #612: opaque recreate-reason gloss ----------------------

    /// #612: `recreate_reason_note` returns `Some` for the two opaque
    /// classifier tokens (`uncovered`, `runsvc_integrity`). These are
    /// internal triggers — `uncovered` fires for spec-hash-mismatch
    /// fallback, `runsvc_integrity` for missing/stale runsvc.sh
    /// digest — and look meaningless in the
    /// `! runner NAME (… recreate (uncovered)) [recreate]` plan line
    /// without context. The note text feeds the indented `note: TOKEN
    /// — explanation` line `render_action_line` emits beneath the
    /// header.
    #[test]
    fn recreate_reason_note_glosses_opaque_tokens() {
        let uncovered = recreate_reason_note("uncovered").expect("uncovered must have a gloss");
        assert!(
            uncovered.contains("spec hash"),
            "uncovered gloss must mention the spec hash trigger; got: {uncovered}",
        );
        assert!(
            uncovered.contains("coverage"),
            "uncovered gloss must name the coverage-gap fallback nature; \
             got: {uncovered}",
        );
        let integrity =
            recreate_reason_note("runsvc_integrity").expect("runsvc_integrity must have a gloss");
        assert!(
            integrity.contains("runsvc.sh"),
            "runsvc_integrity gloss must mention the runsvc.sh wrapper; \
             got: {integrity}",
        );
        assert!(
            integrity.contains("SEC-02"),
            "runsvc_integrity gloss must cite the SEC-02 lineage so a \
             future reader can trace the trigger to the security finding; \
             got: {integrity}",
        );
    }

    /// #612: `recreate_reason_note` returns `None` for self-explanatory
    /// field-name tokens. The full vocabulary the classifier emits comes
    /// from `RunnerDelta::recreate_reasons` field doc (plan.rs); this
    /// test pins every named-field token to the no-gloss branch so a
    /// future addition that pushes a non-field token into
    /// recreate_reasons surfaces here unannotated. Adding a new opaque
    /// token without extending `recreate_reason_note` would leave the
    /// new token bare in plan output.
    #[test]
    fn recreate_reason_note_returns_none_for_field_name_tokens() {
        let field_tokens = [
            "url",
            "runner_version",
            "labels",
            "arch",
            "user",
            "prefix",
            "runner_sha256",
            "runner_tarball",
            "network",
        ];
        for token in field_tokens {
            assert!(
                recreate_reason_note(token).is_none(),
                "field-name token {token:?} must NOT carry a gloss; \
                 the field_changes line above the header already shows \
                 the before→after pair",
            );
        }
    }

    /// #612: `recreate_reason_note` returns `None` for unknown tokens.
    /// Defense for future classifier additions: a new token that lands
    /// here without an explicit gloss falls through silently rather
    /// than hard-erroring, but the test pins the no-gloss-by-default
    /// behavior so the dev advocate review flags the omission.
    #[test]
    fn recreate_reason_note_returns_none_for_unknown_token() {
        assert!(recreate_reason_note("").is_none());
        assert!(recreate_reason_note("some_future_token").is_none());
    }

    /// #612: `render_action_line` emits an indented
    /// `note: uncovered — …` line beneath the header for the
    /// `uncovered` token. Header line is unchanged (operator grep
    /// `recreate (uncovered)` keeps working — pinned by the existing
    /// `render_action_line_recreate_multi_element_reasons_join_format`
    /// sibling); the gloss rides as a separate detail line at the
    /// 4-space indent matching the field_changes loop above.
    #[test]
    fn render_action_line_recreate_uncovered_emits_note_line() {
        let action = Action::UpdateRunner(recreate_delta("buckos", vec!["uncovered"]));
        let line = render_action_line(&action, ColorMode { enabled: false }, false);
        // Header line still carries the raw token verbatim (operator
        // grep parity with multi-element-reasons test).
        let lines: Vec<&str> = line.split('\n').collect();
        assert!(
            lines[0].contains("update: recreate (uncovered)"),
            "header line must carry the raw `uncovered` token (operator \
             grep parity); got: {}",
            lines[0],
        );
        // Note line must be present, indented 4 spaces, with the
        // `note: TOKEN — explanation` shape.
        let note_line = lines
            .iter()
            .find(|l| l.starts_with("    note: uncovered "))
            .unwrap_or_else(|| panic!("missing `note: uncovered ` line; got: {line}"));
        assert!(
            note_line.contains("spec hash"),
            "note line must explain the uncovered trigger; got: {note_line}",
        );
    }

    /// #612: same contract as the uncovered test, for the
    /// `runsvc_integrity` token. Pins both opaque tokens so a future
    /// change to one but not the other is caught.
    #[test]
    fn render_action_line_recreate_runsvc_integrity_emits_note_line() {
        let action = Action::UpdateRunner(recreate_delta("buckos", vec!["runsvc_integrity"]));
        let line = render_action_line(&action, ColorMode { enabled: false }, false);
        let lines: Vec<&str> = line.split('\n').collect();
        assert!(
            lines[0].contains("update: recreate (runsvc_integrity)"),
            "header line must carry the raw `runsvc_integrity` token; \
             got: {}",
            lines[0],
        );
        let note_line = lines
            .iter()
            .find(|l| l.starts_with("    note: runsvc_integrity "))
            .unwrap_or_else(|| panic!("missing `note: runsvc_integrity ` line; got: {line}"));
        assert!(
            note_line.contains("runsvc.sh"),
            "note line must reference runsvc.sh; got: {note_line}",
        );
    }

    /// #612: field-name tokens (`url`, `runner_version`, …) MUST NOT
    /// emit a `note:` line — the field_changes loop renders the
    /// before→after pair already, and a redundant gloss would clutter
    /// the brief view. Pin the no-note guarantee for all
    /// field-name reasons.
    #[test]
    fn render_action_line_recreate_field_name_reasons_emit_no_note_line() {
        let action = Action::UpdateRunner(recreate_delta("buckos", vec!["url", "labels"]));
        let line = render_action_line(&action, ColorMode { enabled: false }, false);
        assert!(
            !line.contains("note:"),
            "field-name recreate_reasons must NOT emit a `note:` line; \
             got: {line}",
        );
    }

    /// #612: mixed reasons render the gloss for ONLY the opaque tokens,
    /// and emit one note per opaque token in the order they appear in
    /// `recreate_reasons`. Header line carries the full
    /// `recreate_reasons.join(",")` regardless. Pin the per-token
    /// emission so a future renderer change that emits one combined
    /// note (instead of per-token) is caught.
    #[test]
    fn render_action_line_recreate_mixed_reasons_emits_note_per_opaque_token() {
        let action = Action::UpdateRunner(recreate_delta(
            "buckos",
            vec!["url", "uncovered", "runsvc_integrity"],
        ));
        let line = render_action_line(&action, ColorMode { enabled: false }, false);
        let lines: Vec<&str> = line.split('\n').collect();
        assert!(
            lines[0].contains("update: recreate (url,uncovered,runsvc_integrity)"),
            "header must carry the full join(\",\")  payload; got: {}",
            lines[0],
        );
        // Two distinct note lines, one per opaque token.
        let pos_uncovered = line
            .find("    note: uncovered ")
            .expect("uncovered note must appear");
        let pos_runsvc = line
            .find("    note: runsvc_integrity ")
            .expect("runsvc_integrity note must appear");
        // Order pin: uncovered (index 1) precedes runsvc_integrity
        // (index 2) per the input Vec ordering.
        assert!(
            pos_uncovered < pos_runsvc,
            "note order must follow recreate_reasons Vec order \
             (uncovered before runsvc_integrity); got: {line}",
        );
        // url is a field-name token; it must NOT emit a note line.
        assert!(
            !line.contains("note: url "),
            "url is self-explanatory; must NOT emit a note line; got: {line}",
        );
    }

    /// #612: in-place UpdateRunner (no recreate) MUST NOT emit any
    /// `note:` lines even when `recreate_reasons` somehow contains an
    /// opaque token (which `plan::plan_from` never produces — the
    /// `requires_recreate = !recreate_reasons.is_empty()` invariant
    /// ties the two). Pin the gate by inspecting an in-place delta
    /// fixture: `recreate_reasons` is empty, so the note loop has
    /// nothing to iterate, but defense-in-depth: the loop sits inside
    /// the same `Action::UpdateRunner` arm that handles both branches,
    /// and a future renderer change that decouples the loop from the
    /// recreate gate would surface here.
    #[test]
    fn render_action_line_inplace_update_emits_no_note_line() {
        let action = Action::UpdateRunner(inplace_delta("buckos"));
        let line = render_action_line(&action, ColorMode { enabled: false }, false);
        assert!(line.starts_with("~ "), "in-place sigil; got: {line}");
        assert!(
            !line.contains("note:"),
            "in-place UpdateRunner must NOT emit `note:` lines; got: {line}",
        );
    }

    // ---------- #486: summary.recreates serde round-trip -----------------

    /// #486: round-trip the rendered `summary.recreates` array through
    /// `serde_json::to_string` + `from_str` and verify both the
    /// per-element labels and the relative ordering survive the trip.
    /// `plan_to_json_value` produces `serde_json::Value` directly; the
    /// CLI then writes that via `serde_json::to_string_pretty`. This
    /// test pins that the wire-format string a downstream
    /// `jq '.summary.recreates'` consumer would see deserializes back
    /// to the same Vec<String> — guarding against a future change that
    /// switches `recreates` to a typed wrapper that breaks bare-array
    /// JSON shape.
    ///
    /// Sibling: `plan_to_json_value_summary_recreates_lists_all_recreate_actions_sorted`
    /// pins the in-memory `Value` shape; this test pins the wire-string
    /// round-trip.
    #[test]
    fn plan_to_json_value_summary_recreates_serde_round_trip() {
        // Insertion order is INTENTIONALLY non-alphabetical so the
        // sort-order assertion below is falsifiable: removing
        // `recreates.sort_unstable()` from `plan_summary_value` would
        // leave the array in this insertion order and break the test.
        let plan = Plan {
            actions: vec![
                Action::RemoveRunner(fake_identity("mmm")),
                Action::CreateRunner(fake_runner_plan("zzz")),
                Action::RemoveCachePool("aaa".into()),
            ],
            warnings: vec![],
        };
        let body = plan_to_json_value(&plan, false);
        // Serialize to wire-format JSON string and back.
        let wire = serde_json::to_string(&body).expect("serialize body");
        let reread: serde_json::Value =
            serde_json::from_str(&wire).expect("deserialize wire format");
        // Per-element equality: every label survives the round-trip.
        let original = body["summary"]["recreates"].as_array().unwrap();
        let after = reread["summary"]["recreates"].as_array().unwrap();
        assert_eq!(
            original, after,
            "summary.recreates array must round-trip identical through serde_json",
        );
        // Sorted-order pin: the alphabetical sort produced by
        // `plan_summary_value` survives the round-trip too.
        let labels: Vec<&str> = after.iter().map(|v| v.as_str().unwrap()).collect();
        assert_eq!(
            labels,
            vec![
                "CreateRunner(zzz)",
                "RemoveCachePool(aaa)",
                "RemoveRunner(mmm)",
            ],
            "alphabetical sort must persist through wire-format round-trip",
        );
    }

    // ---------- #489: all-recreate-only plan apply-exit pin -------------

    /// #489: every action recreate-class — `summary.by_disruption.recreate`
    /// equals `actions.len()`, `none` and `restart` are zero,
    /// `any_recreate` is true. Strengthens the existing
    /// `plan_to_json_value_summary_recreates_only_recreate_class_actions`
    /// by exercising a 5-action mixed-class-but-all-recreate fixture
    /// (CreateRunner + UpdateRunner-recreate + RemoveRunner +
    /// CreateCachePool + RemoveCachePool) so all five recreate-class
    /// variants round-trip through the by_disruption counter, not just
    /// the 3-variant subset the existing test exercises.
    #[test]
    fn plan_to_json_value_summary_recreates_all_five_recreate_class_variants() {
        let recreate_delta = plan::RunnerDelta {
            identity: fake_identity("upd"),
            after: fake_runner_plan("upd"),
            requires_recreate: true,
            recreate_reasons: vec!["url"],
            drift_cause: plan::DriftCause::SpecChanged,
            field_changes: Vec::new(),
            drop_in_changes: Vec::new(),
            before_caches: None,
            before_drop_in_basenames: None,
        };
        let plan = Plan {
            actions: vec![
                Action::CreateRunner(fake_runner_plan("cr")),
                Action::UpdateRunner(recreate_delta),
                Action::RemoveRunner(fake_identity("rm")),
                Action::CreateCachePool(plan::CachePoolPlan {
                    binding: fake_cache_binding("ccp"),
                    drop_in_body: String::new(),
                    spec_hash: "sha256:0".into(),
                }),
                Action::RemoveCachePool("rcp".into()),
            ],
            warnings: vec![],
        };
        let body = plan_to_json_value(&plan, false);
        let s = &body["summary"];
        assert_eq!(s["total_actions"], 5);
        assert_eq!(s["by_disruption"]["recreate"], 5);
        assert_eq!(s["by_disruption"]["restart"], 0);
        assert_eq!(s["by_disruption"]["none"], 0);
        assert_eq!(s["any_recreate"], true);
        let recreates = s["recreates"].as_array().unwrap();
        assert_eq!(recreates.len(), 5);
    }

    // ---------- #490: summary.recreates proptest invariant --------------

    /// Strategy: generate an arbitrary Action variant. Each arm
    /// synthesizes a fresh fixture using the deterministic test
    /// helpers (`fake_runner_plan`, `fake_identity`,
    /// `fake_cache_binding`) over a short ASCII identifier so
    /// the resulting Plan parses cleanly through the renderer.
    /// The variant distribution is roughly uniform — proptest
    /// will reduce to the minimum failing input on a regression.
    ///
    /// The two UpdateRunner arms are split rather than generated
    /// from a single bool because the Restart arm must NOT appear
    /// in `summary.recreates` — pinning separate strategies makes
    /// the `Action::disruption()` → recreate-list mapping
    /// load-bearing. A regression that flipped the boundary would
    /// surface as a count mismatch in invariant 1.
    fn arb_action() -> impl proptest::strategy::Strategy<Value = Action> {
        use proptest::prelude::*;
        prop_oneof![
            // CreateRunner — always Recreate.
            "[a-z]{1,5}".prop_map(|n| Action::CreateRunner(fake_runner_plan(&n))),
            // UpdateRunner with requires_recreate=true — Recreate.
            "[a-z]{1,5}".prop_map(|n| Action::UpdateRunner(plan::RunnerDelta {
                identity: fake_identity(&n),
                after: fake_runner_plan(&n),
                requires_recreate: true,
                recreate_reasons: vec![],
                drift_cause: plan::DriftCause::SpecChanged,
                field_changes: Vec::new(),
                drop_in_changes: Vec::new(),
                before_caches: None,
                before_drop_in_basenames: None,
            })),
            // UpdateRunner with requires_recreate=false — Restart.
            "[a-z]{1,5}".prop_map(|n| Action::UpdateRunner(plan::RunnerDelta {
                identity: fake_identity(&n),
                after: fake_runner_plan(&n),
                requires_recreate: false,
                recreate_reasons: vec![],
                drift_cause: plan::DriftCause::SpecChanged,
                field_changes: Vec::new(),
                drop_in_changes: Vec::new(),
                before_caches: None,
                before_drop_in_basenames: None,
            })),
            // RemoveRunner — Recreate.
            "[a-z]{1,5}".prop_map(|n| Action::RemoveRunner(fake_identity(&n))),
            // CreateCachePool — Recreate.
            "[a-z]{1,5}".prop_map(|n| Action::CreateCachePool(plan::CachePoolPlan {
                binding: fake_cache_binding(&n),
                drop_in_body: String::new(),
                spec_hash: "sha256:0".into(),
            })),
            // UpdateCachePool — Restart.
            "[a-z]{1,5}".prop_map(|n| Action::UpdateCachePool(plan::CachePoolDelta {
                binding: fake_cache_binding(&n),
                drop_in_body: String::new(),
                spec_hash: "sha256:0".into(),
            })),
            // RemoveCachePool — Recreate.
            "[a-z]{1,5}".prop_map(Action::RemoveCachePool),
            // NoOp — Disruption::None. The generator includes it
            // so the test exercises mixes that include
            // disruption=None entries — the production code path
            // counts them under by_disruption.none, never under
            // recreate.
            "[a-z]{1,5}".prop_map(Action::NoOp),
        ]
    }

    proptest::proptest! {
        /// #490: cross-field invariant on `plan_summary_value` output.
        /// The function builds `summary.recreates` (Vec<String>) and
        /// `summary.by_disruption.recreate` (u64) from two SEPARATE
        /// passes over `actions` (CLN-469-1 sources both from the same
        /// counter, but the production order — collect-then-count vs
        /// count-then-collect — is an implementation detail the test
        /// suite must not encode). The proptest generates an arbitrary
        /// `Vec<Action>` (size 0..=8) mixing every variant + both
        /// UpdateRunner flavors (recreate vs in-place) + all three
        /// CachePool flavors (Create + Update + Remove) and asserts
        /// three invariants the rendered summary must satisfy on
        /// EVERY input:
        ///
        /// 1. `summary.recreates.len() == summary.by_disruption.recreate`
        ///    — the Vec and the counter cannot diverge. Catches a
        ///    future refactor that re-splits the count into a separate
        ///    `actions.iter().filter(...).count()` pass.
        /// 2. `summary.any_recreate == (summary.recreates.len() > 0)`
        ///    — the boolean flag must agree with list emptiness.
        ///    Catches a future change that derives `any_recreate` from
        ///    a different filter than the list construction.
        /// 3. `summary.recreates` is sorted ascending (canonical
        ///    `recreates.sort_unstable()` invariant per #503). Catches
        ///    a future change that drops the sort or reorders steps.
        ///
        /// Symmetric example-based coverage:
        /// `plan_to_json_value_summary_recreates_lists_all_recreate_actions_sorted`
        /// pins the same three invariants on a single hand-crafted
        /// 8-action fixture. The proptest expands coverage to arbitrary
        /// sequences (proptest default 256 cases × shrunk minimum)
        /// without relying on the implementer to enumerate every shape.
        #[test]
        fn prop_plan_summary_value_recreates_count_matches_by_disruption_and_is_sorted(
            actions in proptest::collection::vec(arb_action(), 0..=8),
        ) {
            let body = plan_summary_value(&actions);
            let recreates_len = body["recreates"].as_array().unwrap().len();
            let by_disruption_recreate = body["by_disruption"]["recreate"]
                .as_u64()
                .expect("by_disruption.recreate must be u64") as usize;

            // Invariant 1: list length == counter.
            proptest::prop_assert_eq!(
                recreates_len,
                by_disruption_recreate,
                "summary.recreates.len() must equal summary.by_disruption.recreate"
            );

            // Invariant 2: any_recreate boolean matches list emptiness.
            let any_recreate = body["any_recreate"]
                .as_bool()
                .expect("any_recreate must be bool");
            proptest::prop_assert_eq!(
                any_recreate,
                recreates_len > 0,
                "summary.any_recreate must equal (summary.recreates.len() > 0)"
            );

            // Invariant 3: recreates is sorted ascending.
            let recreates: Vec<&str> = body["recreates"]
                .as_array()
                .unwrap()
                .iter()
                .map(|v| v.as_str().unwrap())
                .collect();
            proptest::prop_assert!(
                recreates.windows(2).all(|w| w[0] <= w[1]),
                "summary.recreates must be sorted ascending; got: {:?}",
                recreates
            );
        }
    }

    // ---------- #494: pool-only plan no-runner fixture ------------------

    /// #494: pool-only plan (zero runner actions). Symmetric guard
    /// against a future refactor that scoped `summary.recreates` to
    /// runners by accident. Existing
    /// `plan_to_json_value_summary_recreates_pool_only_plan` covers
    /// Create/Update/Remove of cache pools; this test pins the
    /// absence-of-runner-actions axis explicitly by asserting
    /// `actions[].kind` never matches a runner variant.
    #[test]
    fn plan_to_json_value_summary_recreates_pool_only_no_runner_actions() {
        let plan = Plan {
            actions: vec![
                Action::CreateCachePool(plan::CachePoolPlan {
                    binding: fake_cache_binding("alpha"),
                    drop_in_body: String::new(),
                    spec_hash: "sha256:0".into(),
                }),
                Action::RemoveCachePool("beta".into()),
            ],
            warnings: vec![],
        };
        let body = plan_to_json_value(&plan, false);
        // recreates contains both pool actions, sorted.
        let labels: Vec<&str> = body["summary"]["recreates"]
            .as_array()
            .unwrap()
            .iter()
            .map(|v| v.as_str().unwrap())
            .collect();
        assert_eq!(
            labels,
            vec!["CreateCachePool(alpha)", "RemoveCachePool(beta)"],
        );
        // Zero-runner pin: every actions[].kind must be a pool variant.
        let actions = body["actions"].as_array().unwrap();
        for a in actions {
            let kind = a["kind"].as_str().unwrap();
            assert!(
                kind.contains("cache_pool"),
                "pool-only plan must have zero runner actions; got kind={kind}",
            );
        }
    }

    // ---------- #504: disruption_summary_variants() exhaustiveness ------

    /// #504: pin `disruption_summary_variants()` lists every variant of
    /// the `Disruption` enum exactly once, in canonical least-→-most-
    /// disruptive order. Catches a future variant addition (e.g. an
    /// apply-time `Disruption::Skipped`) that fails to update the
    /// iteration helper, which would silently exclude that variant
    /// from `summary.by_disruption` keys and the text footer.
    ///
    /// The bare `match` below — wildcard-free — is the load-bearing
    /// compile-time check: adding a fourth `Disruption` variant fails
    /// compilation here (E0004 missing-arm), forcing the developer to
    /// update both the enum and `disruption_summary_variants()`.
    #[test]
    fn disruption_summary_variants_contains_all_disruption_variants() {
        // Wildcard-free exhaustive match — fails compilation if a
        // Disruption variant is added without updating this test.
        match plan::Disruption::None {
            plan::Disruption::None | plan::Disruption::Restart | plan::Disruption::Recreate => {}
        }
        // Single full-array equality pin: length, membership, and
        // order all in one assertion.
        assert_eq!(
            disruption_summary_variants(),
            [
                plan::Disruption::None,
                plan::Disruption::Restart,
                plan::Disruption::Recreate,
            ],
        );
    }

    // ---------- #576: FieldValue::List end-to-end JSON round-trip -------

    /// #576: round-trip `FieldValue::List` through wire-format JSON
    /// (`to_string` + `from_str`) and verify the tagged-object shape
    /// `{"type":"list","values":[...]}` survives. Strengthens the
    /// existing in-memory pin
    /// `render_plan_json_update_runner_emits_typed_list_field_value_for_labels`
    /// by adding the wire-string round-trip axis — a future change to
    /// a non-self-describing serializer (bincode, serde_cbor, etc.)
    /// that keeps the in-memory shape but breaks JSON would be caught
    /// here.
    #[test]
    fn field_value_list_json_shape_round_trips_end_to_end() {
        let delta = plan::RunnerDelta {
            identity: fake_identity("buckos"),
            after: fake_runner_plan("buckos"),
            requires_recreate: true,
            recreate_reasons: vec!["labels"],
            drift_cause: plan::DriftCause::SpecChanged,
            field_changes: vec![plan::FieldChange {
                path: "labels",
                before: plan::FieldValue::List(vec!["ci".into()]),
                after: plan::FieldValue::List(vec!["ci".into(), "gpu".into()]),
            }],
            drop_in_changes: Vec::new(),
            before_caches: None,
            before_drop_in_basenames: None,
        };
        let plan = Plan {
            actions: vec![Action::UpdateRunner(delta)],
            warnings: vec![],
        };
        let body = plan_to_json_value(&plan, false);
        // Round-trip through wire-format JSON.
        let wire = serde_json::to_string(&body).expect("serialize");
        let reread: serde_json::Value = serde_json::from_str(&wire).expect("deserialize");
        let fc = &reread["actions"][0]["field_changes"][0];
        // Tagged-object shape: {"type":"list","values":[...]}.
        assert_eq!(fc["before"]["type"], "list");
        assert_eq!(fc["after"]["type"], "list");
        let after_values: Vec<&str> = fc["after"]["values"]
            .as_array()
            .expect("List variant must round-trip with values array")
            .iter()
            .map(|v| v.as_str().unwrap())
            .collect();
        assert_eq!(after_values, vec!["ci", "gpu"]);
        // Negative pin: scalar `value` key must NOT appear on List variant
        // even after round-trip.
        assert!(
            fc["before"].get("value").is_none(),
            "List variant must not carry scalar `value` key after round-trip",
        );
    }

    // ---------- #584: apply_exit_code recreate-flag-on no-recreate-out --

    /// #584: `apply_exit_code` with `detailed_exitcode_recreate=true`
    /// and a successful apply that produced ZERO recreate-class
    /// outcomes must return 0 (not 8). Strengthens existing
    /// `apply_exit_code_recreate_flag_without_recreate_outcome_returns_zero`
    /// by adding a multi-action mixed-non-recreate fixture
    /// (InPlaceRestarted + PoolUpdated + NoOp + InPlaceSkipped) so the
    /// recreate-detection short-circuit at `ApplyOutcome::disruption`
    /// is exercised against a richer set of non-recreate variants.
    #[test]
    fn apply_exit_code_recreate_flag_on_with_zero_recreate_outcomes_returns_zero() {
        let result = apply::ApplyResult {
            succeeded: vec!["UpdateRunner(a)".into(), "UpdateCachePool(b)".into()],
            failed: vec![],
            details: vec![
                (
                    "UpdateRunner(a)".into(),
                    apply::ApplyOutcome::InPlaceRestarted {
                        files_changed: 1,
                        pools_added: vec![],
                        pools_removed: vec![],
                    },
                ),
                (
                    "UpdateCachePool(b)".into(),
                    apply::ApplyOutcome::PoolUpdated,
                ),
                ("NoOp(c: in sync)".into(), apply::ApplyOutcome::NoOp),
                (
                    "UpdateRunner(d)".into(),
                    apply::ApplyOutcome::InPlaceSkipped,
                ),
            ],
            ..Default::default()
        };
        // recreate flag ON, detailed flag OFF: no recreate outcomes ⇒ 0.
        assert_eq!(
            apply_exit_code(&result, false, true),
            0,
            "recreate flag on but zero recreate-class outcomes must return 0",
        );
        // Sanity: with detailed flag also ON, falls through to detailed
        // = 2 (since result.details has non-NoOp activity). This pins
        // the `apply_exit_code` fall-through path:
        // `if detailed_exitcode { 2 } else { 0 }`.
        assert_eq!(
            apply_exit_code(&result, true, true),
            2,
            "recreate flag on, no recreate outcomes, detailed flag on ⇒ 2",
        );
    }

    // ---------- #583: fail_fast=true multi-failure detail-row pin -------

    /// #583: under `fail_fast=true`, `apply()` short-circuits on the
    /// first failure — so `details` carries exactly one Failed row
    /// regardless of how many actions remained in the plan. Strengthens
    /// `apply::tests::fail_fast_short_circuits_on_first_failure` by
    /// pinning the data-shape contract at the cli layer (the surface a
    /// `cmd_apply` JSON consumer would see): `details.len() == 1`,
    /// `failed.len() == 1`, even though the plan had 3 actions queued.
    /// Also pins that `apply_exit_code` derives the correct exit code
    /// (5 for total auth failure, 1 for non-auth) from this
    /// short-circuited shape.
    #[test]
    fn apply_exit_code_fail_fast_single_failed_row_drives_correct_exit() {
        // Synthesize the result-shape `apply()` produces under fail_fast
        // when the first action fails: one Failed detail row, one
        // failed entry, zero succeeded. (The apply()-driven path is
        // already pinned at `apply::tests::fail_fast_short_circuits_on_first_failure`;
        // this layer pins the post-apply ApplyResult contract for
        // cmd_apply consumers.)
        let result = apply::ApplyResult {
            succeeded: vec![],
            failed: vec![(
                "CreateCachePool(a)".into(),
                validation_err("mock enable failure"),
            )],
            details: vec![(
                "CreateCachePool(a)".into(),
                apply::ApplyOutcome::Failed {
                    error_summary: "mock enable failure".into(),
                    plan_disruption: plan::Disruption::Recreate,
                },
            )],
            ..Default::default()
        };
        // fail_fast contract: details.len() == failed.len() == 1.
        assert_eq!(result.details.len(), 1);
        assert_eq!(result.failed.len(), 1);
        // Total non-auth failure (succeeded empty, no auth error) ⇒ 1.
        assert_eq!(
            apply_exit_code(&result, false, false),
            1,
            "total non-auth failure under fail_fast must yield exit 1",
        );
        // Same shape but with auth error ⇒ 5 (auth failure trumps).
        let auth_result = apply::ApplyResult {
            succeeded: vec![],
            failed: vec![("CreateRunner(b)".into(), auth_err("401"))],
            details: vec![(
                "CreateRunner(b)".into(),
                apply::ApplyOutcome::Failed {
                    error_summary: "github: 401".into(),
                    plan_disruption: plan::Disruption::Recreate,
                },
            )],
            ..Default::default()
        };
        assert_eq!(
            apply_exit_code(&auth_result, false, false),
            5,
            "total auth failure under fail_fast must yield exit 5",
        );
    }

    // ---------- #597: call-site sanitization wiring pins -----------

    /// #597: pin that the recreate-Removed text path at
    /// `render_action_line` actually runs the basename through
    /// `escape_control_chars`. Helper-level coverage already lives in
    /// `lib.rs` (Cow allocation, escape_default semantics); this test
    /// pins the WIRING — that the production render site invokes the
    /// helper and the operator's terminal never sees the raw control
    /// byte. Drives the renderer with a hostile basename containing
    /// `\x1b[31m`; asserts the output (a) does not contain the raw
    /// ESC byte, and (b) does contain the `\u{1b}` printable form
    /// `char::escape_default` emits for ESC.
    ///
    /// Without this pin, a future refactor that moves the basename
    /// `format!` call to a path that bypasses `escape_control_chars`
    /// would compile and pass other recreate-Removed render tests
    /// (which use sanitized basenames) but reintroduce the ANSI-
    /// hijack vector that #567 closed.
    #[test]
    fn render_action_line_recreate_removed_text_path_escapes_hostile_basename() {
        let mut after_plan = fake_runner_plan("buckos");
        after_plan.drop_ins.insert(
            "00-ghars.conf".into(),
            "[Unit]\nX-Ghars-Spec-Hash=sha256:abc\n".into(),
        );
        let delta = plan::RunnerDelta {
            identity: fake_identity("buckos"),
            after: after_plan,
            requires_recreate: true,
            recreate_reasons: vec!["runner_version"],
            drift_cause: plan::DriftCause::SpecChanged,
            field_changes: Vec::new(),
            drop_in_changes: Vec::new(),
            before_caches: None,
            // Hostile basename: ESC + CSI sequence wrapped around
            // operator-readable text. A naive `format!("    - {}",
            // basename)` would emit the raw ESC byte to stdout and
            // the terminal would interpret it as the "switch foreground
            // to red" sequence.
            before_drop_in_basenames: Some(vec!["99-\x1b[31mhostile.conf".into()]),
        };
        let line = render_action_line(
            &Action::UpdateRunner(delta),
            ColorMode { enabled: false },
            true,
        );
        // (a) raw ESC byte must not survive — terminal interprets `\x1b`
        // as the start of a CSI escape sequence; surviving here would
        // mean the render site bypassed `escape_control_chars`.
        assert!(
            !line.contains('\x1b'),
            "raw ESC must not reach stdout from recreate-Removed text path; got: {line:?}"
        );
        // (b) printable form `\u{1b}` from `char::escape_default('\x1b')`
        // must be present — proves the helper actually ran (and not
        // some other escaping function that uses `\e` or `^[`).
        assert!(
            line.contains("\\u{1b}"),
            "expected \\u{{1b}} escape form from char::escape_default; got: {line}"
        );
        // The non-control suffix passes through.
        assert!(
            line.contains("hostile.conf"),
            "non-control text must pass through unchanged; got: {line}"
        );
    }

    /// #597: pin that the recreate-Removed JSON path at
    /// `plan_to_json_value` runs the basename through
    /// `escape_control_chars` before serialization. JSON serializers
    /// already encode ESC as a JSON 4-hex-digit escape, but a downstream `jq` pipeline
    /// that pipes the value back to a terminal via `echo -e` /
    /// `printf '%b'` would re-interpret the JSON-escaped form. The
    /// `escape_control_chars` step replaces ESC with the literal
    /// 6-character `\u{1b}` ASCII sequence — which is `\\u{1b}` after
    /// JSON encoding — keeping the basename terminal-safe regardless
    /// of consumer interpolation semantics.
    ///
    /// Pin: serialize a recreate delta with a hostile basename + diff,
    /// extract the resulting `basename` JSON string, assert (a) it
    /// does NOT contain the raw `\x1b` byte, and (b) it DOES contain
    /// the `\\u{1b}` substring from `char::escape_default`.
    #[test]
    fn plan_to_json_value_recreate_removed_json_path_escapes_hostile_basename() {
        let mut after_plan = fake_runner_plan("buckos");
        after_plan.drop_ins.insert(
            "00-ghars.conf".into(),
            "[Unit]\nX-Ghars-Spec-Hash=sha256:abc\n".into(),
        );
        let delta = plan::RunnerDelta {
            identity: fake_identity("buckos"),
            after: after_plan,
            requires_recreate: true,
            recreate_reasons: vec!["runner_version"],
            drift_cause: plan::DriftCause::SpecChanged,
            field_changes: Vec::new(),
            drop_in_changes: Vec::new(),
            before_caches: None,
            before_drop_in_basenames: Some(vec!["99-\x1b[31mhostile.conf".into()]),
        };
        let plan_obj = plan::Plan {
            actions: vec![Action::UpdateRunner(delta)],
            warnings: vec![],
        };
        // diff=true so the recreate path emits the Removed-suppressed
        // entries (the only path through the hostile-basename JSON
        // wrapper at line ~1776).
        let body = plan_to_json_value(&plan_obj, true);
        let serialized = body.to_string();
        // (a) raw ESC must not survive in the serialized output.
        // Note: serde_json natively encodes \x1b as the JSON
        // 4-hex-digit form, so this assertion alone does not prove
        // escape_control_chars ran — (b) below is the load-bearing
        // discriminator. Symmetric with the in-place JSON test
        // `plan_to_json_value_inplace_json_path_escapes_hostile_drop_in_basename`
        // (#599 / Adversary A2).
        assert!(
            !serialized.contains('\x1b'),
            "raw ESC must not survive JSON serialization; got: {serialized:?}"
        );
        // (b) `escape_control_chars` form (`\u{1b}` literal — six
        // ASCII bytes) must appear. JSON further escapes the leading
        // backslash, so the wire form is `\\u{1b}` (four chars in
        // the serialized string view: backslash, backslash, u, {, 1,
        // b, }). The raw assertion looks for the JSON-encoded form
        // `\\u{1b}` which, in Rust source after one round of escape,
        // is `"\\\\u{1b}"`.
        assert!(
            serialized.contains("\\\\u{1b}"),
            "expected JSON-encoded \\u{{1b}} substring (proves escape_control_chars ran \
             before serde escaping); got: {serialized}"
        );
        // The non-control suffix passes through.
        assert!(
            serialized.contains("hostile.conf"),
            "non-control text must pass through unchanged; got: {serialized}"
        );
    }

    // ---------- WO-S11C: remaining call-site sanitization wiring pins ---

    /// WO-S11C item 1: pin that the IN-PLACE text path at
    /// `render_action_line` (line ~1450) runs the drop-in basename
    /// through `escape_control_chars` before stdout emission.
    /// Symmetric with the recreate-Removed text path pin at
    /// `render_action_line_recreate_removed_text_path_escapes_hostile_basename`
    /// — the recreate path uses `before_drop_in_basenames`; the
    /// in-place path iterates `drop_in_changes` (Created / Modified /
    /// Removed entries with their per-variant body). Both render
    /// sites use the same `escape_control_chars(basename)` form, so
    /// a regression in one would not catch a regression in the other.
    ///
    /// Drives `render_action_line` with an in-place RunnerDelta whose
    /// sole `drop_in_changes` entry has a hostile basename. Asserts
    /// (a) raw ESC byte gone, (b) `\u{1b}` escape form present,
    /// (c) "hostile.conf" non-control suffix passes through.
    #[test]
    fn render_action_line_inplace_text_path_escapes_hostile_drop_in_basename() {
        let mut delta = inplace_delta("buckos");
        // Sole drop_in_changes entry — Created variant is the most
        // common in-place mutation (operator added a new drop-in
        // section like `[memory_max]`); the basename loop at
        // cli.rs:1448-1450 emits `    + {escape_control_chars(basename)}`.
        delta.drop_in_changes.push(plan::DropInChange {
            basename: "60-\x1b[31mhostile.conf".into(),
            change: plan::DropInChangeKind::Created {
                after: "[Service]\n".into(),
            },
        });
        let line = render_action_line(
            &Action::UpdateRunner(delta),
            ColorMode { enabled: false },
            false,
        );
        // (a) raw ESC byte must not survive — terminal interprets
        // `\x1b` as the start of a CSI escape sequence; surviving
        // here would mean the in-place render site bypassed
        // `escape_control_chars`.
        assert!(
            !line.contains('\x1b'),
            "raw ESC must not reach stdout from in-place text path; got: {line:?}"
        );
        // (b) printable form `\u{1b}` from `char::escape_default('\x1b')`
        // must be present — proves the helper actually ran.
        assert!(
            line.contains("\\u{1b}"),
            "expected \\u{{1b}} escape form from char::escape_default; got: {line}"
        );
        // (c) the non-control suffix passes through.
        assert!(
            line.contains("hostile.conf"),
            "non-control text must pass through unchanged; got: {line}"
        );
    }

    /// WO-S11C item 2: pin that the IN-PLACE JSON path at
    /// `drop_in_change_to_json` (line ~2146) runs the drop-in
    /// basename through `escape_control_chars` before serialization.
    /// Symmetric with the recreate-Removed JSON path pin at
    /// `plan_to_json_value_recreate_removed_json_path_escapes_hostile_basename`
    /// — the recreate path emits an inline `serde_json::json!`
    /// wrapper inside `plan_to_json_value`; the in-place path
    /// delegates to `drop_in_change_to_json` for each entry in
    /// `drop_in_changes`. Two distinct call sites, two distinct
    /// pins.
    ///
    /// Drives `plan_to_json_value` (diff=false) with an in-place
    /// RunnerDelta. The `drop_in_change_to_json` helper is invoked
    /// at cli.rs:1786 for each `dc` in `d.drop_in_changes`, and the
    /// helper's `obj.insert("basename", escape_control_chars(...))`
    /// at line 2146 is the wiring point under test.
    ///
    /// Assertion roles:
    /// - (a) `!serialized.contains('\\x1b')` is anti-tampering:
    ///   serde ALSO encodes raw ESC (it produces the JSON-
    ///   standard 4-hex-digit form `\\u001b`). A regression that
    ///   dropped `escape_control_chars` from the in-place path
    ///   would still not leak raw `\\x1b` bytes through serde's
    ///   encoder; this assertion only fires under tampering or a
    ///   serde-bypass refactor (e.g. raw `format!`-into-string
    ///   emit).
    /// - (b) `serialized.contains("\\\\u{1b}")` is the LOAD-
    ///   BEARING discriminator. The brace-form `\\u{1b}` is what
    ///   `char::escape_default` emits; serde's own ESC encoding
    ///   is the brace-less 4-hex-digit `\\u001b` form. Finding
    ///   the brace form in the serialized output PROVES the
    ///   helper ran BEFORE serde — its output became part of
    ///   the JSON STRING VALUE that serde then re-escaped (the
    ///   leading backslash becomes `\\\\`, hence `\\\\u{1b}` on the
    ///   wire and `"\\\\\\\\u{1b}"` in Rust source). A regression
    ///   that drops the helper makes this assertion fail because
    ///   serde would emit `\\u001b` instead.
    /// - (c) "hostile.conf" passes through — sanity check
    ///   that non-control suffix isn't truncated.
    #[test]
    fn plan_to_json_value_inplace_json_path_escapes_hostile_drop_in_basename() {
        let mut delta = inplace_delta("buckos");
        delta.drop_in_changes.push(plan::DropInChange {
            basename: "60-\x1b[31mhostile.conf".into(),
            change: plan::DropInChangeKind::Removed {
                before: "[Service]\n".into(),
            },
        });
        let plan_obj = plan::Plan {
            actions: vec![Action::UpdateRunner(delta)],
            warnings: vec![],
        };
        // diff=false routes through the in-place path's per-entry
        // map (cli.rs:1784-1787) which delegates to
        // drop_in_change_to_json. The recreate-Removed path
        // (line 1775-1779) is gated on `requires_recreate=true` and
        // is the entry-point for the existing `*_recreate_*` JSON
        // pin; this test exercises the disjoint in-place branch.
        let body = plan_to_json_value(&plan_obj, false);
        let serialized = body.to_string();
        // (a) raw ESC must not survive in the serialized output.
        // Note: serde_json natively encodes \x1b as the JSON
        // 4-hex-digit form, so this assertion alone does not prove
        // escape_control_chars ran — (b) below is the load-bearing
        // discriminator. See the doc-comment on this test for the
        // full assertion-roles breakdown.
        assert!(
            !serialized.contains('\x1b'),
            "raw ESC must not survive JSON serialization on in-place path; got: {serialized:?}"
        );
        // (b) `escape_control_chars` form (`\u{1b}` literal — six
        // ASCII bytes) must appear. JSON further escapes the leading
        // backslash, so the wire form is `\\u{1b}` (the Rust source
        // literal for that wire form is `"\\\\u{1b}"`). A regression
        // that drops escape_control_chars from the in-place path
        // would surface as serde's own JSON 4-hex-digit escape,
        // failing this match.
        assert!(
            serialized.contains("\\\\u{1b}"),
            "expected JSON-encoded \\u{{1b}} substring (proves escape_control_chars ran \
             before serde escaping); got: {serialized}"
        );
        // (c) the non-control suffix passes through.
        assert!(
            serialized.contains("hostile.conf"),
            "non-control text must pass through unchanged; got: {serialized}"
        );
    }

    /// WO-S11C item 3: pin the COMBINED defense-in-depth chain that
    /// scrubs `UndoStep::describe()` output before stderr emission.
    /// The chain has two intentionally-redundant layers:
    ///   1. `describe()` escapes each interpolated field per arm at
    ///      construction (apply.rs:643-689 — every `name`, `path`,
    ///      `url` arm runs the helper).
    ///   2. `render_rollback_advisory` re-escapes the full
    ///      `describe()` output before stderr emission via the
    ///      step-bullet escape inside
    ///      `render_rollback_advisory`'s rev-walk loop. The second
    ///      pass is idempotent (#596 — pinned in lib.rs) so the
    ///      redundancy costs only one O(n) byte scan.
    ///
    /// Asserting on the rendered advisory exercises the END of the
    /// chain. The assertions pass when AT LEAST ONE layer scrubs the
    /// hostile bytes — the other layer can be broken silently. A
    /// regression that drops a SINGLE layer is therefore NOT caught
    /// here; this test fires only when BOTH layers fail
    /// simultaneously (the worst-case bypass). Per-arm `describe()`
    /// coverage at `undo_step_all_variants_describe_escapes_hostile_input`
    /// pins layer 1 in isolation, so a layer-1 regression DOES
    /// surface there. This test pins the combined-seam behavior — it
    /// does NOT isolate the `render_rollback_advisory` wiring from
    /// the `describe()`-side wiring.
    ///
    /// Historical note: the per-failure label was NOT sanitized
    /// when this test was first introduced (#600 then-pending) — the
    /// per-step bullets passed through the describe() +
    /// render_rollback_advisory chain but the per-failure label
    /// rendered raw. #600 (WO-S12A) closed that gap by wrapping the
    /// label with `escape_control_chars` at the per-failure
    /// sub-block emission inside `render_rollback_advisory`. This
    /// test still uses a benign label (`"RemoveRunner(buckos)"`)
    /// because the dedicated label-escape pin is
    /// `render_rollback_advisory_escapes_hostile_label` —
    /// keeping this test focused on the step chain avoids
    /// double-coverage and over-constraining a single fixture.
    ///
    /// Drives the renderer with an `ApplyResult` carrying one
    /// failure + one `StartUnit` UndoStep whose `name` field
    /// contains an ESC. Asserts (a) no raw `\x1b` anywhere in the
    /// rendered advisory, (b) `\u{1b}` escape form present,
    /// (c) header / step bullet structure intact.
    #[test]
    fn render_rollback_advisory_escapes_hostile_undo_step() {
        let mut result = apply::ApplyResult::default();
        result.failed.push((
            "RemoveRunner(buckos)".into(),
            crate::error::GharsError::Apply {
                action: "RemoveRunner(buckos)".into(),
                source: Box::new(crate::error::GharsError::Systemd(
                    "mock stop failure".into(),
                    "test".into(),
                )),
            },
        ));
        // Hostile UndoStep::StartUnit. Note: describe() ALREADY runs
        // escape_control_chars on `name` (apply.rs:657-658). The
        // second pass at the step-bullet escape inside
        // `render_rollback_advisory`'s rev-walk loop is idempotent
        // (#596 — pinned in lib.rs). Together they guarantee a
        // future regression in EITHER layer cannot leak ESC bytes
        // to stderr.
        result.failed_undo_logs.push((
            "RemoveRunner(buckos)".into(),
            vec![apply::UndoStep::StartUnit {
                name: "ghars-runner@\x1b[31mevil.service".into(),
            }],
        ));
        let advisory = render_rollback_advisory(&result).unwrap();
        // (a) raw ESC byte must not appear ANYWHERE in the advisory.
        // The layered defense (describe()-side escape + the second
        // pass inside render_rollback_advisory) means EITHER layer
        // alone is sufficient to scrub. This assertion fails only if
        // BOTH layers regress simultaneously.
        assert!(
            !advisory.contains('\x1b'),
            "raw ESC must not survive describe() + render_rollback_advisory chain; got: {advisory:?}"
        );
        // (b) printable `\u{1b}` form from char::escape_default must
        // appear — proves the helper ran on the step text.
        assert!(
            advisory.contains("\\u{1b}"),
            "expected \\u{{1b}} escape form from char::escape_default; got: {advisory}"
        );
        // (c) header + step bullet structure intact: the advisory's
        // `Rollback advisory: N action(s) failed.` count line and
        // the `\n    - started ...` step bullet (past tense from
        // describe()'s `format!("started {}")` arm at apply.rs:657)
        // must both be present, proving the render structure
        // survived the escape pass.
        assert!(
            advisory.starts_with("Rollback advisory: 1 action(s) failed."),
            "advisory must lead with failed-count header; got: {advisory}"
        );
        assert!(
            advisory.contains("\n    - started "),
            "advisory must include the StartUnit step bullet via describe(); got: {advisory}"
        );
        // Sanity: the non-control suffix passes through.
        assert!(
            advisory.contains("evil.service"),
            "non-control text must pass through unchanged; got: {advisory}"
        );
    }

    // ---------- WO-S12A: cli.rs sanitization follow-ups ---------------

    /// WO-S12A #600: pin that `render_rollback_advisory` runs the
    /// per-failure label through `escape_control_chars` before
    /// stderr emission. Previously the label was emitted via
    /// `format!("\n  {label}:")` without escaping; the per-step
    /// bullets at the step-bullet escape inside
    /// `render_rollback_advisory`'s rev-walk loop were already
    /// escaped, so this fix closes the asymmetry. Today's `IDENTIFIER_REGEX` rejects
    /// control chars at config-load, so a hostile label cannot
    /// reach this site through normal inputs — but the
    /// failed_undo_logs key is constructed from `Action::label()`
    /// output, and a future regex relaxation or a synthetic test
    /// fixture (this very test) can drive a hostile label through.
    /// Defense-in-depth pin.
    ///
    /// Drives the renderer with an `ApplyResult` carrying one
    /// failure whose label contains `\x1b[31m`. Asserts (a) no raw
    /// `\x1b` anywhere in the rendered advisory (the label line
    /// would otherwise leak the byte even when the per-step bullets
    /// were already escaped at the step-bullet escape inside
    /// `render_rollback_advisory`'s rev-walk loop), (b) `\u{1b}`
    /// escape form present in the output, (c) header + step
    /// structure preserved.
    #[test]
    fn render_rollback_advisory_escapes_hostile_label() {
        let mut result = apply::ApplyResult::default();
        // Hostile label embedded in the typed-error tuple AND the
        // failed_undo_logs key (the renderer keys off the latter).
        let hostile_label = "RemoveRunner(\x1b[31mevil)";
        result.failed.push((
            hostile_label.into(),
            crate::error::GharsError::Apply {
                action: hostile_label.into(),
                source: Box::new(crate::error::GharsError::Systemd(
                    "mock failure".into(),
                    "test".into(),
                )),
            },
        ));
        // Use a benign step so any ESC byte in the rendered output
        // can ONLY have come from the label render path. If the
        // step-bullet escape inside `render_rollback_advisory`'s
        // rev-walk loop were the only defense, this test would
        // still fail until #600's label escape lands.
        result.failed_undo_logs.push((
            hostile_label.into(),
            vec![apply::UndoStep::StopUnit {
                name: "ghars-runner@a.service".into(),
            }],
        ));
        let advisory = render_rollback_advisory(&result).unwrap();
        // (a) raw ESC byte must not survive — the label rendered
        // by `render_rollback_advisory`'s per-failure sub-block
        // emission was the only remaining unescaped interpolation
        // before this fix.
        assert!(
            !advisory.contains('\x1b'),
            "raw ESC must not survive label render path; got: {advisory:?}"
        );
        // (b) printable `\u{1b}` from char::escape_default must
        // appear — proves escape_control_chars actually ran on the
        // label.
        assert!(
            advisory.contains("\\u{1b}"),
            "expected \\u{{1b}} escape form from char::escape_default; got: {advisory}"
        );
        // (c) structural: header + label sub-block + step bullet all
        // intact.
        assert!(
            advisory.starts_with("Rollback advisory: 1 action(s) failed."),
            "advisory must lead with failed-count header; got: {advisory}"
        );
        // The label render emits `\n  {label}:` after escape — the
        // `evil)` non-control suffix passes through, so the colon-
        // suffixed line is detectable via that substring.
        assert!(
            advisory.contains("evil):"),
            "non-control suffix of label must pass through with `:` separator; got: {advisory}"
        );
        // Step bullet structure unaffected.
        assert!(
            advisory.contains("\n    - stopped ghars-runner@a.service"),
            "step bullet must render via describe(); got: {advisory}"
        );
    }

    /// WO-S12A #590 (a): pin that `push_indented_body` escapes raw
    /// control bytes from operator-supplied drop-in bodies before
    /// emitting them to the indented body block. Drop-in bodies on
    /// the `--diff` path originate from `Created.after` /
    /// `Removed.before`, which carry operator-authored content from
    /// either rendered output or on-disk discovery — both can in
    /// principle contain raw `\x1b` bytes that would otherwise
    /// hijack the operator's terminal.
    ///
    /// Asserts (a) no raw `\x1b` in the indented output, (b)
    /// `\u{1b}` form present, (c) the printable suffix `evil`
    /// passes through.
    #[test]
    fn push_indented_body_escapes_hostile_line() {
        let mut out = String::new();
        push_indented_body(
            &mut out,
            "first line\nsecond \x1b[31m evil line\nthird line",
        );
        // (a) no raw ESC.
        assert!(
            !out.contains('\x1b'),
            "raw ESC must not survive push_indented_body; got: {out:?}"
        );
        // (b) printable form present.
        assert!(
            out.contains("\\u{1b}"),
            "expected \\u{{1b}} escape form from char::escape_default; got: {out}"
        );
        // (c) non-control suffix passes through.
        assert!(
            out.contains("evil line"),
            "non-control suffix must pass through unchanged; got: {out}"
        );
        // Sanity: structural newlines and the 12-space indent prefix
        // survive — the helper still emits one indented line per
        // input line.
        assert!(
            out.starts_with("            first line\n"),
            "first line must keep 12-space indent + \\n; got: {out:?}"
        );
        // The MIDDLE (hostile) line is the load-bearing case: the
        // 12-space indent prefix must survive the escape pass
        // unchanged (the prefix is pure printable ASCII, written
        // BEFORE escape_control_chars touches the line content),
        // and the line CONTENT must show the printable
        // `\u{1b}[31m` form in place of the original ESC byte.
        // This is the only assertion that pins both invariants
        // co-located on the same line — without it, a regression
        // that escaped the line content but lost the indent prefix
        // (e.g. a future helper that builds a `format!("{}", line)`
        // without the 12-space prefix) could pass (a)/(b)/(c) +
        // first-line + third-line assertions and still ship broken
        // middle-line layout.
        assert!(
            out.contains("            second \\u{1b}[31m evil line\n"),
            "hostile middle line must keep 12-space indent; got: {out:?}"
        );
        assert!(
            out.contains("            third line\n"),
            "third line must also be indented; got: {out:?}"
        );
    }

    /// WO-S12A #590 (b): pin that `render_drop_in_body_block` for
    /// the `Created` variant scrubs hostile bytes in the body. The
    /// helper delegates to `push_indented_body`, so this is the
    /// integration-level check that the `Created { after }` arm
    /// inside `render_drop_in_body_block` actually flows through
    /// the scrub.
    ///
    /// Asserts (a) no raw `\x1b` in the rendered block, (b)
    /// `\u{1b}` form present, (c) the printable suffix `evil`
    /// passes through, (d) the structural `after:` header stays
    /// intact.
    #[test]
    fn render_drop_in_body_block_created_escapes_hostile_body() {
        let kind = plan::DropInChangeKind::Created {
            after: "[Service]\nEnvironment=HTTP_PROXY=http://\x1b[31mevil@host\n".into(),
        };
        let block = render_drop_in_body_block(&kind, ColorMode { enabled: false });
        // (a) raw ESC must not survive.
        assert!(
            !block.contains('\x1b'),
            "raw ESC must not survive Created body block; got: {block:?}"
        );
        // (b) `\u{1b}` form present.
        assert!(
            block.contains("\\u{1b}"),
            "expected \\u{{1b}} escape form from char::escape_default; got: {block}"
        );
        // (c) non-control suffix passes through.
        assert!(
            block.contains("evil@host"),
            "non-control suffix must pass through unchanged; got: {block}"
        );
        // (d) structural header.
        assert!(
            block.starts_with("        after:\n"),
            "Created block must start with `        after:\\n` header; got: {block:?}"
        );
    }

    /// WO-S12A #590 (b'): mirror of `Created` test for the
    /// `Removed` variant. Recreate-class plan output emits
    /// `Removed { before }` entries via
    /// `RunnerDelta::before_drop_in_basenames` synthesis (the
    /// recreate path replays operator-authored on-disk drop-in
    /// bytes through `render_drop_in_body_block`'s `Removed` arm).
    /// The `before` body originates from on-disk discovery, which
    /// can carry any bytes the operator wrote — including raw
    /// `\x1b`. Without this mirror, the `Created` path is pinned
    /// but a regression that drops the scrub in the `Removed` arm
    /// of `render_drop_in_body_block` (e.g. someone refactors
    /// `Removed { before }` to call `out.push_str(before)` directly
    /// instead of `push_indented_body(&mut out, before)`) would
    /// not be caught by the existing test set. This is the fifth
    /// pin in the per-variant escape contract for
    /// `render_drop_in_body_block` (Preserved is a static string,
    /// Created/Modified/Removed each carry operator content).
    ///
    /// Asserts (a) no raw `\x1b` in the rendered block, (b)
    /// `\u{1b}` form present, (c) the printable suffix `evil`
    /// passes through, (d) the structural `before:` header (note:
    /// `before:`, not `after:` — distinct from the Created arm).
    #[test]
    fn render_drop_in_body_block_removed_escapes_hostile_body() {
        let kind = plan::DropInChangeKind::Removed {
            before: "[Service]\nEnvironment=HTTP_PROXY=http://\x1b[31mevil@host\n".into(),
        };
        let block = render_drop_in_body_block(&kind, ColorMode { enabled: false });
        // (a) raw ESC must not survive.
        assert!(
            !block.contains('\x1b'),
            "raw ESC must not survive Removed body block; got: {block:?}"
        );
        // (b) `\u{1b}` form present.
        assert!(
            block.contains("\\u{1b}"),
            "expected \\u{{1b}} escape form from char::escape_default; got: {block}"
        );
        // (c) non-control suffix passes through.
        assert!(
            block.contains("evil@host"),
            "non-control suffix must pass through unchanged; got: {block}"
        );
        // (d) structural header — `before:`, distinct from
        // Created's `after:`. This pins the variant routing inside
        // `render_drop_in_body_block` against a typo-class
        // regression where the `Removed` arm accidentally emits
        // the `Created` header.
        assert!(
            block.starts_with("        before:\n"),
            "Removed block must start with `        before:\\n` header; got: {block:?}"
        );
    }

    /// WO-S12A #590 (c): pin the unified-diff path. Hostile bytes
    /// in the operator-authored `before` or `after` flow into
    /// `similar::udiff::unified_diff`'s output, then
    /// `push_indented_unified_diff` emits each line. The escape
    /// happens BEFORE the color wrap so legitimate sigil chars
    /// (`+`/`-`/`@`) are still detectable for the green/red color
    /// branches.
    ///
    /// Fixture is **addition-only**: `before = ""` so similar
    /// emits no `-` lines (only `+++`/`---` headers, which
    /// `push_indented_unified_diff`'s `starts_with("+++")` /
    /// `starts_with("---")` branch routes to the
    /// uncolored-passthrough arm). The hostile bytes live in the
    /// `+` lines only. This makes the negative assertion
    /// `!colored.contains("\x1b[31m")` load-bearing: any
    /// `\x1b[31m` in output would have to come from the body's
    /// hostile bytes leaking through (since neither the `+`-arm
    /// nor the headers-arm emit `\x1b[31m`).
    ///
    /// Two paths exercised:
    /// - **(a) no-color**: ZERO raw ESC bytes in output. Hostile
    ///   body ESC must be escaped, and the no-color branch never
    ///   emits its own ESC.
    /// - **(b) color enabled**: legitimate green wrap (`\x1b[32m`)
    ///   and reset (`\x1b[0m`) for `+` lines MUST be present
    ///   (we emit them on purpose for additions). NO `\x1b[31m`
    ///   anywhere — the fixture has only `+` lines, so any red
    ///   CSI in the output would be a leak from the body. The
    ///   hostile body's CSI must surface only in the printable
    ///   `\u{1b}[31m` form.
    #[test]
    fn render_drop_in_body_block_modified_escapes_hostile_diff_lines() {
        // `before = ""` ⇒ similar emits an addition-only diff:
        // file-header lines (`---`/`+++` — uncolored by our
        // header-passthrough branch) plus one or more `+` lines
        // carrying the hostile body bytes. No `-` lines means no
        // intentional `\x1b[31m` in the output; the only path to
        // `\x1b[31m` is the body's hostile bytes leaking past
        // escape_control_chars.
        let before_text = "";
        let after_text = "[Service]\nEnvironment=A=\x1b[31m evil\n";
        let kind = plan::DropInChangeKind::Modified {
            before: before_text.into(),
            after: after_text.into(),
        };

        // (a) no-color: ZERO ESC bytes (none from us, none from
        // the body).
        let plain = render_drop_in_body_block(&kind, ColorMode { enabled: false });
        assert!(
            !plain.contains('\x1b'),
            "raw ESC must not survive Modified body block (no-color); got: {plain:?}"
        );
        assert!(
            plain.contains("\\u{1b}"),
            "expected \\u{{1b}} escape form (no-color); got: {plain}"
        );
        assert!(
            plain.contains("evil"),
            "non-control suffix must pass through (no-color); got: {plain}"
        );

        // (b) color enabled.
        let colored = render_drop_in_body_block(&kind, ColorMode { enabled: true });
        // Legitimate green wrap for `+`-prefixed line is present
        // (we emit `\x1b[32m` intentionally for additions).
        assert!(
            colored.contains("\x1b[32m"),
            "color path must emit green wrap for + line; got: {colored:?}"
        );
        // Legitimate reset is present.
        assert!(
            colored.contains("\x1b[0m"),
            "color path must emit reset; got: {colored:?}"
        );
        // The hostile body's `\x1b[31m` CSI sequence must be gone
        // and replaced with the printable escape — meaning we
        // should find `\\u{1b}[31m` (the body's bytes after
        // escape_control_chars converted ESC to its printable
        // escape form).
        assert!(
            colored.contains("\\u{1b}[31m"),
            "hostile `\\x1b[31m` from body must appear in printable form `\\u{{1b}}[31m`; \
             got: {colored}"
        );
        // NEGATIVE DISCRIMINATOR: no raw `\x1b[31m` anywhere.
        // The fixture has only `+` lines (addition-only diff);
        // the `+`-arm of push_indented_unified_diff emits
        // `\x1b[32m` (green) and `\x1b[0m` (reset), not
        // `\x1b[31m`. The header-passthrough arm emits no ANSI.
        // Any `\x1b[31m` byte in output would therefore prove
        // the body's hostile bytes leaked past the escape.
        assert!(
            !colored.contains("\x1b[31m"),
            "no leaked red CSI from body — fixture has only + lines; got: {colored:?}"
        );
        assert!(
            colored.contains("evil"),
            "non-control suffix must pass through (color); got: {colored}"
        );
    }
}
