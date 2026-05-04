//! `ghars status` command handler + text/JSON renderers.

use std::io::{self, Write};

use camino::Utf8Path;

use crate::Result;
use crate::error::GharsError;
use crate::paths::Paths;
use crate::preflight;
use crate::state;
use crate::systemd::DbusSystemd;

use super::args::{ColorMode, StatusArgs};
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
        let mut actual = match DbusSystemd::new() {
            Ok(s) => state::discover(&s, paths)?,
            Err(err) => {
                // Surface the failure on stderr instead of returning
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

pub(super) fn render_status_text(
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
    Ok(status_exit_code(health))
}

pub(super) fn render_status_json(
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
