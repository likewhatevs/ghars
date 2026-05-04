//! `ghars metrics` command handler + the per-runner `MetricRow`
//! collector and table/JSON renderers.
//!
//! `MetricRow` and `render_metrics_text` are also called from
//! `cmd_status` (with `--metrics`) so they live in this dedicated
//! module rather than inside `cmd_status`.

use std::io::{self, Write};

use crate::Result;
use crate::error::GharsError;
use crate::paths::Paths;
use crate::state;
use crate::systemd::DbusSystemd;
use crate::validators;
use zbus::blocking::{Connection, Proxy};
use zbus::zvariant::OwnedObjectPath;

use super::args::MetricsArgs;

#[derive(Debug, Default, Clone)]
pub(crate) struct MetricRow {
    pub(crate) name: String,
    pub(crate) memory_bytes: u64,
    pub(crate) cpu_nsec: u64,
    pub(crate) io_read_bytes: u64,
    pub(crate) io_write_bytes: u64,
    pub(crate) tasks: u64,
}

pub(crate) fn cmd_metrics(paths: &Paths, args: &MetricsArgs) -> Result<i32> {
    let names = if args.names.is_empty() {
        match DbusSystemd::new() {
            Ok(s) => state::discover(&s, paths)?
                .runners
                .keys()
                .cloned()
                .collect::<Vec<_>>(),
            Err(err) => {
                // Surface the failure rather than returning an empty
                // metrics table that hides why nothing is shown.
                eprintln!(
                    "warning: systemd D-Bus connection failed: {err}; runner state unavailable."
                );
                Vec::new()
            }
        }
    } else {
        // Validate operator-supplied names against IDENTIFIER_REGEX
        // before the D-Bus per-unit query (`Manager.GetUnit
        // ghars-runner@$NAME.service`) is constructed.
        for name in &args.names {
            validators::validate_runner_name(name).map_err(|e| match e {
                GharsError::Validation(msg, _) => GharsError::Validation(
                    format!("invalid runner name {name:?}: {msg}"),
                    format!(
                        "runner names must use lowercase letters, digits, and dashes; \
                         start with a letter; end with a letter or digit; \
                         and be ≤{} characters",
                        crate::config::IDENTIFIER_MAX_LEN,
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

pub(crate) fn collect_metrics(names: &[String]) -> Result<Vec<MetricRow>> {
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

pub(crate) fn read_metrics(
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

pub(crate) fn render_metrics_text<W: Write>(
    stdout: &mut W,
    rows: &[MetricRow],
    no_total: bool,
) -> Result<()> {
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

pub(crate) fn render_metrics_json(rows: &[MetricRow], no_total: bool) -> Result<i32> {
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

pub(crate) fn human_bytes(n: u64) -> String {
    bytesize::ByteSize::b(n).to_string()
}
