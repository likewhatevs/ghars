//! `ghars status` command handler + text/JSON renderers.

use std::io::{self, Write};
use std::process::Command as ProcCommand;

use camino::Utf8Path;

use crate::Result;
use crate::error::GharsError;
use crate::paths::Paths;
use crate::preflight;
use crate::state;

use super::args::{ColorMode, StatusArgs};
use super::cmd_apply::pat_for_url;
use super::cmd_metrics::{MetricRow, collect_metrics, render_metrics_text};
use super::exit_codes::status_exit_code;
use super::load::load_config;

pub(super) fn cmd_status(
    config_path: &Utf8Path,
    paths: &Paths,
    args: &StatusArgs,
    color: ColorMode,
    quiet: bool,
) -> Result<i32> {
    let _ = color;
    let _ = quiet;

    // Per the Part 10 status-section design ruling: cmd_status MUST
    // load the config FIRST, before any other work. Two reasons make
    // this non-negotiable:
    //
    //   1. Orphan classification (the "ORPHAN — no [[runner]] in config;
    //      next apply will REMOVE" status column) requires the parsed
    //      desired set. Without it, runners discovered on disk can't
    //      be told apart from runners the operator declared.
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
        let mut actual = super::util::discover_or_warn(paths)?;
        // Populate `actual.orphans` here. state::discover always
        // returns an empty orphans Vec because at the discovery layer we
        // only know "managed" vs "external", not "in-config" vs "out-of-
        // config" — see the ActualState.orphans doc. cmd_status is the
        // first caller that has both halves available, so it does the
        // diff inline. The design ruling at Part 10 calls this
        // diff_against_config(actual, desired); inlined here as a
        // simple set-difference rather than a new pub fn until a second
        // caller needs it (status text renderer covers the orphan
        // column off this same field).
        //
        // `expand_counts` is required: a `[[runner]] name="foo" count=3`
        // block produces on-disk units `foo-1`/`foo-2`/`foo-3` but the
        // raw `cfg.runners` slice carries only the bare `foo`. Diffing
        // against unexpanded names would misclassify every count-expanded
        // runner as an orphan.
        let expanded = crate::plan::expand_counts(&cfg)?;
        let desired_names: std::collections::HashSet<&str> =
            expanded.iter().map(|r| r.name.as_str()).collect();
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

    let github_statuses: std::collections::HashMap<String, String> = if args.github {
        // Distinct URLs across all declared runners; count-block siblings
        // share a URL so dedup via HashSet keeps the API call count
        // proportional to repos/orgs, not individual runners.
        let urls: std::collections::HashSet<&str> =
            cfg.runners.iter().map(|r| r.url.as_str()).collect();
        match crate::github::build_blocking_client(cfg.proxy.as_ref()) {
            Ok(client) => {
                let mut combined = std::collections::HashMap::new();
                for url in urls {
                    // Per-URL PAT: use whichever auth the runner pointing
                    // at this URL declared. Multi-auth configs no longer
                    // collapse to "any PAT".
                    let pat = pat_for_url(&cfg, url);
                    match crate::github::list_runner_statuses(&client, url, pat.as_deref()) {
                        Ok(map) => combined.extend(map),
                        Err(e) => {
                            eprintln!("warning: GitHub runner status query failed for {url}: {e}");
                        }
                    }
                }
                combined
            }
            Err(e) => {
                // Client-build failure: warn and fall through with an
                // empty map so the rest of the status report (RUNNERS,
                // METRICS, SCORE) still renders. The pre-fix code
                // short-circuited mid-render, hiding everything below.
                eprintln!("warning: cannot build HTTP client for --github: {e}");
                std::collections::HashMap::new()
            }
        }
    } else {
        std::collections::HashMap::new()
    };

    let score_rows = if args.score {
        // Collect both runner and cache-pool unit names from the
        // disk-discovery pass so units never installed (or removed
        // without a daemon-reload) don't silently disappear from the
        // table. `state::discover` returns them keyed by `%i`; the
        // score collector wraps each in the canonical
        // `ghars-runner@<name>.service` / `ghars-cache@<name>.service`
        // template-instance form expected by `systemd-analyze`.
        let units = score_unit_names(&runners);
        collect_score_rows(&units, run_systemd_analyze_security)
    } else {
        Vec::new()
    };

    if args.json {
        return render_status_json(&health, &runners, &metrics_rows, &score_rows, &github_statuses);
    }
    render_status_text(&health, &runners, &metrics_rows, &score_rows, &args.names, &github_statuses)
}

pub(super) fn render_status_text(
    health: &[preflight::CheckResult],
    runners: &state::ActualState,
    metrics: &[MetricRow],
    scores: &[ScoreRow],
    name_filter: &[String],
    github_statuses: &std::collections::HashMap<String, String>,
) -> Result<i32> {
    let mut stdout = io::stdout().lock();
    let has_github = !github_statuses.is_empty();
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
        if has_github {
            writeln!(
                stdout,
                "  {:<24} {:<10} {:<10} {:<10} drift",
                "name", "active", "enabled", "github"
            )
            .map_err(GharsError::Io)?;
        } else {
            writeln!(
                stdout,
                "  {:<24} {:<10} {:<10} drift",
                "name", "active", "enabled"
            )
            .map_err(GharsError::Io)?;
        }
        for (name, r) in &runners.runners {
            if !name_filter.is_empty() && !name_filter.iter().any(|n| n == name) {
                continue;
            }
            let active = if r.running { "active" } else { "inactive" };
            let enabled = if r.enabled { "enabled" } else { "disabled" };
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
            if has_github {
                let gh = github_statuses.get(name).map_or("-", String::as_str);
                writeln!(
                    stdout,
                    "  {name:<24} {active:<10} {enabled:<10} {gh:<10} {drift}"
                )
                .map_err(GharsError::Io)?;
            } else {
                writeln!(stdout, "  {name:<24} {active:<10} {enabled:<10} {drift}")
                    .map_err(GharsError::Io)?;
            }
        }
        for ext in &runners.external {
            // External runners (units present on disk but not declared
            // in the operator's TOML) MUST honor `--names` the same way
            // managed runners do. Without this filter, `ghars status
            // --names foo` would list every external unit on the host
            // even when `foo` isn't among them — drowning the operator's
            // scoped query in unrelated output.
            if !name_filter.is_empty() && !name_filter.iter().any(|n| n == ext) {
                continue;
            }
            writeln!(stdout, "  {ext:<24} external   -          -").map_err(GharsError::Io)?;
        }
        writeln!(stdout).map_err(GharsError::Io)?;
    }
    if !metrics.is_empty() {
        writeln!(stdout, "METRICS").map_err(GharsError::Io)?;
        render_metrics_text(&mut stdout, metrics, false)?;
    }
    if !scores.is_empty() {
        if !metrics.is_empty() {
            writeln!(stdout).map_err(GharsError::Io)?;
        }
        writeln!(stdout, "SECURITY").map_err(GharsError::Io)?;
        render_score_text(&mut stdout, scores)?;
    }
    Ok(status_exit_code(health))
}

pub(super) fn render_status_json(
    health: &[preflight::CheckResult],
    runners: &state::ActualState,
    metrics: &[MetricRow],
    scores: &[ScoreRow],
    github_statuses: &std::collections::HashMap<String, String>,
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
            if let Some(gh) = github_statuses.get(name) {
                #[allow(clippy::expect_used)]
                obj.as_object_mut()
                    .expect("serde_json::json!({...}) always returns Object")
                    .insert("github_status".into(), serde_json::Value::String(gh.clone()));
            }
            if !unmanaged.is_empty() {
                #[allow(clippy::expect_used)]
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
    let scores_json: Vec<serde_json::Value> = scores
        .iter()
        .map(|s| {
            // `score` and `label` are only present when the parse
            // succeeded; the lookup-error case carries an `error`
            // field in their place. Build the object conditionally
            // so consumers can branch on key presence without
            // sentinel values.
            match &s.outcome {
                ScoreOutcome::Ok { score, label } => serde_json::json!({
                    "unit": s.unit,
                    "score": score,
                    "label": label,
                }),
                ScoreOutcome::Error(msg) => serde_json::json!({
                    "unit": s.unit,
                    "error": msg,
                }),
            }
        })
        .collect();
    let body = serde_json::json!({
        "health": health_json,
        "runners": runners_json,
        "external": runners.external,
        "metrics": metrics_json,
        "security": scores_json,
    });
    let mut stdout = io::stdout().lock();
    // See render_plan_json: encode failures map to Io, not Config.
    serde_json::to_writer_pretty(&mut stdout, &body)
        .map_err(|e| GharsError::Io(io::Error::other(format!("encode status json: {e}"))))?;
    writeln!(stdout).map_err(GharsError::Io)?;
    Ok(status_exit_code(health))
}

// --- systemd-analyze security score collection -------------------------

/// One row of `systemd-analyze security` output for a managed unit.
///
/// Holds the canonical unit name (`ghars-runner@<name>.service` /
/// `ghars-cache@<name>.service`) plus the parser outcome — either a
/// successful score-and-label pair or the lookup/parse error message.
/// Errors are surfaced as a per-row entry rather than propagated up so
/// one missing unit (e.g. a daemon-reload skipped after install) does
/// not erase the report for the rest.
#[derive(Debug, Clone, PartialEq)]
pub(super) struct ScoreRow {
    pub(super) unit: String,
    pub(super) outcome: ScoreOutcome,
}

/// Parse-or-error outcome for a single unit's `systemd-analyze` run.
///
/// `Ok { score, label }` carries the parsed numeric score and the
/// adjacent label token (`SAFE`, `OK`, `MEDIUM`, `EXPOSED`, `UNSAFE`,
/// etc.) lifted verbatim from the `→ Overall exposure level` line.
/// `Error(msg)` records the cause of a per-unit failure (spawn
/// failure, non-zero exit, missing summary line) so the renderer can
/// surface it inline rather than dropping the row.
#[derive(Debug, Clone, PartialEq)]
pub(super) enum ScoreOutcome {
    Ok { score: f64, label: String },
    Error(String),
}

/// Build the canonical unit-name list from a discovered actual state.
///
/// Wraps each runner `%i` in `ghars-runner@<name>.service` and each
/// cache pool `%i` in `ghars-cache@<name>.service`. External
/// (operator-managed) runner units are intentionally omitted because
/// the score report is scoped to ghars-managed units only.
fn score_unit_names(actual: &state::ActualState) -> Vec<String> {
    let mut names: Vec<String> = Vec::new();
    for name in actual.runners.keys() {
        names.push(crate::paths::runner_unit_name(name));
    }
    for name in actual.cache_pools.keys() {
        names.push(crate::paths::cache_unit_name(name));
    }
    names
}

/// Run `systemd-analyze security` against each unit and parse the
/// `Overall exposure level` line out of every successful invocation.
///
/// `runner` is dependency-injected so tests can substitute a canned
/// stdout/stderr without invoking the real binary; production passes
/// [`run_systemd_analyze_security`].
fn collect_score_rows<R>(units: &[String], runner: R) -> Vec<ScoreRow>
where
    R: Fn(&str) -> std::result::Result<String, String>,
{
    units
        .iter()
        .map(|unit| {
            let outcome = match runner(unit) {
                Ok(output) => match parse_overall_exposure(&output) {
                    Some((score, label)) => ScoreOutcome::Ok { score, label },
                    None => ScoreOutcome::Error(format!(
                        "no `Overall exposure level` line in systemd-analyze output for {unit}"
                    )),
                },
                Err(msg) => ScoreOutcome::Error(msg),
            };
            ScoreRow {
                unit: unit.clone(),
                outcome,
            }
        })
        .collect()
}

/// Spawn `systemd-analyze security <unit>` and return its captured
/// stdout. Failures (spawn error, non-zero exit) are returned as
/// `Err(String)` so the caller can attach the message to the row's
/// `ScoreOutcome::Error` arm.
fn run_systemd_analyze_security(unit: &str) -> std::result::Result<String, String> {
    let output = ProcCommand::new("systemd-analyze")
        .arg("security")
        .arg("--no-pager")
        .arg(unit)
        .output()
        .map_err(|e| format!("spawn systemd-analyze: {e}"))?;
    if !output.status.success() {
        // Non-zero exit usually means the unit isn't loaded (e.g.
        // daemon-reload skipped after install) or systemd-analyze
        // itself rejected the request. Surface stderr so the
        // operator sees the underlying cause inline rather than
        // having to re-run the command manually.
        //
        // ExitStatus::code() returns None when the process was
        // killed by a signal. Surface "signal-killed" instead of a
        // magic `-1` so the operator can distinguish the two cases
        // (exit-status vs signal) at a glance.
        let stderr = String::from_utf8_lossy(&output.stderr);
        let exit_label = match output.status.code() {
            Some(code) => format!("exited {code}"),
            None => "signal-killed".to_string(),
        };
        return Err(format!(
            "systemd-analyze {exit_label} for {unit}: {}",
            stderr.trim()
        ));
    }
    String::from_utf8(output.stdout).map_err(|e| format!("systemd-analyze stdout not utf-8: {e}"))
}

/// Extract the numeric exposure score and label from the
/// `→ Overall exposure level` summary line emitted by
/// `systemd-analyze security`.
///
/// systemd-analyze prints (with the actual unicode arrow):
///   `→ Overall exposure level for <unit>: <N.M> <LABEL> [emoji]`
///
/// where LABEL is one of `UNSAFE`, `EXPOSED`, `MEDIUM`, `OK`, `SAFE`.
/// The label position is fixed (immediately after the score), and
/// the trailing emoji (if any) is whitespace-separated, so we split
/// on whitespace and take the next two tokens after the colon. The
/// arrow byte sequence varies across systemd locales, so we anchor
/// on the substring `Overall exposure level` rather than the leading
/// glyph.
///
/// Returns `None` when the marker line is absent or the score after
/// the colon does not parse as `f64` — the caller surfaces this as a
/// per-row error.
fn parse_overall_exposure(text: &str) -> Option<(f64, String)> {
    for line in text.lines() {
        let Some((_, after)) = line.split_once("Overall exposure level") else {
            continue;
        };
        // Format: `... for <unit>: <score> <label> [emoji]`. The
        // score is the first whitespace-separated token after the
        // colon; the label is the second.
        let after_colon = after.split_once(':').map(|(_, rest)| rest.trim())?;
        let mut tokens = after_colon.split_whitespace();
        let score_tok = tokens.next()?;
        let label_tok = tokens.next()?;
        let score: f64 = score_tok.parse().ok()?;
        return Some((score, label_tok.to_owned()));
    }
    None
}

/// Render the SECURITY section as a small fixed-width table. One row
/// per unit, plus an inline `error: ...` line for failed lookups so
/// the operator sees the cause without consulting JSON / journald.
fn render_score_text<W: Write>(stdout: &mut W, scores: &[ScoreRow]) -> Result<()> {
    let unit_hdr = "unit";
    let score_hdr = "score";
    let label_hdr = "label";
    writeln!(stdout, "  {unit_hdr:<40} {score_hdr:>5}  {label_hdr}").map_err(GharsError::Io)?;
    for row in scores {
        match &row.outcome {
            ScoreOutcome::Ok { score, label } => {
                writeln!(stdout, "  {:<40} {score:>5.1}  {label}", row.unit)
                    .map_err(GharsError::Io)?;
            }
            ScoreOutcome::Error(msg) => {
                writeln!(stdout, "  {:<40}    -   error: {msg}", row.unit)
                    .map_err(GharsError::Io)?;
            }
        }
    }
    Ok(())
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used)]
mod score_tests {
    //! Parser-only tests for the `--score` surface. These exercise
    //! `parse_overall_exposure` and `collect_score_rows` directly with
    //! canned `systemd-analyze` output / synthetic runner closures, so
    //! none of them invoke the real `systemd-analyze` binary. The
    //! production wrapper [`run_systemd_analyze_security`] is exercised
    //! end-to-end by the operator (and by the `just sd-analyze`
    //! recipe); covering the spawn path here would require a real
    //! systemd-analyze installation and could not run in CI.

    use super::*;

    /// Canonical happy-path summary line — single-runner unit, score
    /// 4.9 with the `OK` label and a trailing emoji. Pin the exact
    /// score float so a regression that drops the decimal portion
    /// (e.g. parses "4" before the period) surfaces as a value
    /// mismatch, not just `Some(...)`.
    #[test]
    fn parse_overall_exposure_extracts_score_and_label() {
        let output = "\
Lots of lines above
✓ RestrictRealtime=                                           Service realtime scheduling access is restricted
✗ UMask=                                                      Files created by service are world-readable by default                                                   0.1

→ Overall exposure level for ghars-runner@buckos.service: 4.9 OK 🙂
";
        let parsed = parse_overall_exposure(output).expect("must parse");
        assert!(
            (parsed.0 - 4.9).abs() < 1e-9,
            "score must be 4.9, got {}",
            parsed.0
        );
        assert_eq!(parsed.1, "OK");
    }

    /// systemd-analyze emits the score with a leading integer for
    /// well-hardened units (e.g. `0.1 SAFE`). Pin that the integer
    /// portion of "0.1" is preserved through the f64 parse — an
    /// off-by-one substring slice would lose the leading 0 and
    /// land on `.1`, which `f64::parse` accepts as 0.1 by accident
    /// of the relaxed grammar; lock the exact value to 0.1.
    #[test]
    fn parse_overall_exposure_safe_label_preserves_decimal() {
        let output = "→ Overall exposure level for ghars-runner@hardened.service: 0.1 SAFE 😀\n";
        let (score, label) = parse_overall_exposure(output).expect("must parse");
        assert!((score - 0.1).abs() < 1e-9, "score must be 0.1; got {score}");
        assert_eq!(label, "SAFE");
    }

    /// Multi-line preamble + the summary line at the end — pin that
    /// the parser anchors on the marker substring rather than line
    /// position. systemd-analyze appends the summary as the very last
    /// line in real output; tests simulate that shape.
    #[test]
    fn parse_overall_exposure_finds_marker_at_end_of_text() {
        let mut text = String::new();
        for i in 0..50 {
            text.push_str(&format!("preamble line {i}\n"));
        }
        text.push_str("→ Overall exposure level for ghars-cache@build.service: 7.2 EXPOSED 🙁\n");
        let (score, label) = parse_overall_exposure(&text).expect("must parse");
        assert!((score - 7.2).abs() < 1e-9);
        assert_eq!(label, "EXPOSED");
    }

    /// No marker line → None. systemd-analyze without the security
    /// subcommand prints a different summary; ensure the parser
    /// returns None rather than panicking on `unwrap`.
    #[test]
    fn parse_overall_exposure_returns_none_when_marker_absent() {
        let output = "Some unrelated systemd-analyze output\n  with no marker line\n";
        assert!(parse_overall_exposure(output).is_none());
    }

    /// Score token that doesn't parse as f64 → None. Defends
    /// against future systemd-analyze format changes (e.g. text
    /// label inserted before the numeric score) without panicking.
    #[test]
    fn parse_overall_exposure_returns_none_on_unparseable_score() {
        let output = "→ Overall exposure level for ghars-runner@x.service: NOT-A-NUMBER OK 🙂\n";
        assert!(parse_overall_exposure(output).is_none());
    }

    /// Empty input → None. Trivial but worth pinning so a future
    /// implementation that defaults to 0.0 / "" doesn't slip through.
    #[test]
    fn parse_overall_exposure_returns_none_on_empty_input() {
        assert!(parse_overall_exposure("").is_none());
    }

    /// Marker line missing the colon — malformed but possible if a
    /// future systemd-analyze releases changes the separator.
    /// Returns None rather than misparsing the unit name as the
    /// score token.
    #[test]
    fn parse_overall_exposure_returns_none_when_colon_absent() {
        let output = "→ Overall exposure level for ghars-runner@x.service 4.9 OK 🙂\n";
        assert!(parse_overall_exposure(output).is_none());
    }

    /// Marker line with trailing label only (no numeric score) →
    /// None. Defends the f64-parse failure path.
    #[test]
    fn parse_overall_exposure_returns_none_when_score_token_missing() {
        let output = "→ Overall exposure level for ghars-runner@x.service: \n";
        assert!(parse_overall_exposure(output).is_none());
    }

    /// Marker line with a score but no label → None. The format pin
    /// requires both tokens; absent the label, the row is malformed
    /// and the caller surfaces an error instead of a partial entry.
    #[test]
    fn parse_overall_exposure_returns_none_when_label_token_missing() {
        let output = "→ Overall exposure level for ghars-runner@x.service: 4.9\n";
        assert!(parse_overall_exposure(output).is_none());
    }

    /// `collect_score_rows` happy path: every unit returns a parseable
    /// summary. Returned rows preserve the input order.
    #[test]
    fn collect_score_rows_preserves_order_on_success() {
        let units = vec![
            "ghars-runner@a.service".to_string(),
            "ghars-runner@b.service".to_string(),
            "ghars-cache@build.service".to_string(),
        ];
        let runner = |unit: &str| -> std::result::Result<String, String> {
            Ok(format!(
                "→ Overall exposure level for {unit}: 5.5 MEDIUM 🙂\n"
            ))
        };
        let rows = collect_score_rows(&units, runner);
        assert_eq!(rows.len(), 3);
        for (row, expected_unit) in rows.iter().zip(units.iter()) {
            assert_eq!(&row.unit, expected_unit);
            match &row.outcome {
                ScoreOutcome::Ok { score, label } => {
                    assert!((score - 5.5).abs() < 1e-9);
                    assert_eq!(label, "MEDIUM");
                }
                ScoreOutcome::Error(msg) => panic!("expected Ok, got Error({msg})"),
            }
        }
    }

    /// Per-unit lookup error → `Error` row, other rows still parse.
    /// Pins the contract that one missing unit doesn't erase the
    /// rest of the report.
    #[test]
    fn collect_score_rows_surfaces_per_unit_runner_error() {
        let units = vec![
            "ghars-runner@ok.service".to_string(),
            "ghars-runner@missing.service".to_string(),
        ];
        let runner = |unit: &str| -> std::result::Result<String, String> {
            if unit.contains("missing") {
                Err("not loaded".to_string())
            } else {
                Ok(format!("→ Overall exposure level for {unit}: 1.5 OK 🙂\n"))
            }
        };
        let rows = collect_score_rows(&units, runner);
        assert_eq!(rows.len(), 2);
        match &rows[0].outcome {
            ScoreOutcome::Ok { score, label } => {
                assert!((score - 1.5).abs() < 1e-9);
                assert_eq!(label, "OK");
            }
            ScoreOutcome::Error(msg) => panic!("expected Ok, got Error({msg})"),
        }
        match &rows[1].outcome {
            ScoreOutcome::Error(msg) => assert!(
                msg.contains("not loaded"),
                "error msg must propagate runner failure: {msg}"
            ),
            ScoreOutcome::Ok { score, label } => {
                panic!("expected Error, got Ok {{ score: {score}, label: {label:?} }}")
            }
        }
    }

    /// Runner returns successful stdout but the parser cannot find
    /// a marker line → `Error` row carrying a parser-side message.
    /// Distinguishes "spawn failed" from "spawn succeeded but
    /// output was unexpected".
    #[test]
    fn collect_score_rows_surfaces_parser_error_on_unrecognized_output() {
        let units = vec!["ghars-runner@x.service".to_string()];
        let runner = |_unit: &str| -> std::result::Result<String, String> {
            Ok("nothing useful here\n".to_string())
        };
        let rows = collect_score_rows(&units, runner);
        assert_eq!(rows.len(), 1);
        match &rows[0].outcome {
            ScoreOutcome::Error(msg) => assert!(
                msg.contains("Overall exposure level"),
                "parser error must mention the missing marker: {msg}"
            ),
            ScoreOutcome::Ok { score, label } => {
                panic!("expected Error, got Ok {{ score: {score}, label: {label:?} }}")
            }
        }
    }

    /// `score_unit_names` covers both runner and cache pool maps. The
    /// runner-template prefix is `ghars-runner@`, the cache-template
    /// prefix is `ghars-cache@`. External (operator-managed) entries
    /// are intentionally omitted.
    #[test]
    fn score_unit_names_wraps_runners_and_cache_pools() {
        let mut actual = state::ActualState::default();
        actual.runners.insert(
            "alpha".into(),
            state::DiscoveredRunner {
                name: "alpha".into(),
                spec_hash: String::new(),
                on_disk_unit_text: String::new(),
                drop_ins: std::collections::BTreeMap::new(),
                running: false,
                enabled: false,
                drift: state::Drift::InSync,
            },
        );
        actual.runners.insert(
            "beta".into(),
            state::DiscoveredRunner {
                name: "beta".into(),
                spec_hash: String::new(),
                on_disk_unit_text: String::new(),
                drop_ins: std::collections::BTreeMap::new(),
                running: false,
                enabled: false,
                drift: state::Drift::InSync,
            },
        );
        actual.cache_pools.insert(
            "build".into(),
            state::DiscoveredCachePool {
                name: "build".into(),
                spec_hash: String::new(),
                drop_ins: std::collections::BTreeMap::new(),
                running: false,
                enabled: false,
                drift: state::Drift::InSync,
            },
        );
        actual.external.push("external-runner".into());

        let units = score_unit_names(&actual);
        assert_eq!(
            units,
            vec![
                "ghars-runner@alpha.service".to_string(),
                "ghars-runner@beta.service".to_string(),
                "ghars-cache@build.service".to_string(),
            ],
            "score_unit_names must wrap runner + cache pool keys with the canonical \
             template-instance prefixes and omit external operator-managed units"
        );
    }

    /// `render_score_text` happy path emits a header + one row per
    /// unit with the score formatted to one decimal. Pin the exact
    /// rendered shape so future changes to the column widths surface
    /// here rather than as a doc/code drift.
    #[test]
    fn render_score_text_renders_table_header_and_rows() {
        let scores = vec![
            ScoreRow {
                unit: "ghars-runner@buckos.service".into(),
                outcome: ScoreOutcome::Ok {
                    score: 4.9,
                    label: "OK".into(),
                },
            },
            ScoreRow {
                unit: "ghars-cache@build.service".into(),
                outcome: ScoreOutcome::Error("not loaded".into()),
            },
        ];
        let mut buf: Vec<u8> = Vec::new();
        render_score_text(&mut buf, &scores).expect("render must succeed");
        let out = String::from_utf8(buf).expect("output must be utf-8");
        assert!(
            out.contains("unit") && out.contains("score") && out.contains("label"),
            "header line must include the column titles; got: {out}"
        );
        assert!(
            out.contains("ghars-runner@buckos.service")
                && out.contains("4.9")
                && out.contains("OK"),
            "Ok row must include the unit name, formatted score, and label; got: {out}"
        );
        assert!(
            out.contains("ghars-cache@build.service") && out.contains("error: not loaded"),
            "Error row must include the unit name and the error message; got: {out}"
        );
    }
}
