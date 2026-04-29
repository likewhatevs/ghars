//! `ghars` binary entrypoint.
//!
//! Design spec: Part 6 enforcement rule item 1 — `fn main()` is sync;
//! ghars NEVER uses `#[tokio::main]`. Auth subsystem touches tokio via
//! `OnceLock<Runtime>` + `block_on(...)` only.
//!
//! Exit-code mapping per Part 5: 0 success, 1 generic, 2
//! detailed-exitcode (plan diff non-empty OR cancel-with-pending-changes),
//! 3 preflight, 4 partial apply, 5 auth (per-action OR top-level
//! `GharsError::Auth`), 6 config (`GharsError::Config` for parse/shape
//! errors OR `GharsError::Validation` for cross-field constraint
//! failures), 7 interactive (`GharsError::Interactive`), 8
//! detailed-exitcode-recreate (plan contains a recreate-class action;
//! CI gating signal independent of code 2; failure codes 4 and 5 still
//! win over 8).
//! The Err-variant → code mapping lives in `ghars::cli::err_to_exit_code`
//! as an exhaustive `match` so future variant additions force compile-time
//! review of the mapping.

use clap::Parser;

fn main() {
    // Parse the CLI BEFORE initializing tracing so `--verbose` /
    // `-vv` / `-vvv` can drive the default level. clap parsing
    // itself doesn't emit log lines, so the dependency-order swap
    // is safe.
    let cli = ghars::cli::Cli::parse();

    // --verbose / --quiet drive a tracing level. RUST_LOG always
    // wins when set so operators with existing log-routing setups
    // keep their override; the verbose-derived level is the FALLBACK
    // default. Write to stderr so `ghars status --json | jq` (and
    // any other stdout-as-data pipe) isn't polluted by structured
    // log lines.
    //
    // The (quiet, verbose) → level truth table lives in
    // `cli::verbose_to_filter_level` so it can be exhaustively
    // unit-tested without spawning a child process. Dependencies
    // (reqwest, hyper, zbus) stay at info so `-vv` doesn't drown the
    // operator in transport / protocol chatter. RUST_LOG (when set)
    // replaces the entire filter, letting operators dial in
    // per-target verbosity if they want.
    let verbose_level = ghars::cli::verbose_to_filter_level(cli.quiet, cli.verbose);
    let filter = tracing_subscriber::EnvFilter::try_from_default_env().unwrap_or_else(|_| {
        tracing_subscriber::EnvFilter::new(format!("ghars={verbose_level},info"))
    });
    tracing_subscriber::fmt()
        .with_env_filter(filter)
        .with_writer(std::io::stderr)
        .init();

    let code = match ghars::cli::dispatch(cli) {
        Ok(code) => code,
        Err(err) => {
            eprintln!("error: {err}");
            ghars::cli::err_to_exit_code(&err)
        }
    };
    std::process::exit(code);
}
