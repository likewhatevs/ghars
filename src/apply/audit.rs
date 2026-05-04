//! SEC-36 structured apply audit log: one JSON-line per action.

use std::fs::{self, OpenOptions};
use std::io::Write;
use std::os::unix::fs::OpenOptionsExt;

use crate::paths::Paths;

/// Append one JSON-line entry to `<logs_dir>/apply.log` (SEC-36 —
/// structured audit log of every apply action).
///
/// Schema (one object per line):
/// ```jsonc
/// {
///   "timestamp": "2026-04-29T12:34:56.789Z", // RFC3339 / ISO 8601 UTC
///   "action":    "CreateRunner",              // Action variant name
///   "target":    "buckos",                    // runner / pool name
///   "outcome":   "success"                    // or one-line error summary
/// }
/// ```
///
/// File invariants:
/// - **Mode 0600** at create time (`OpenOptions::mode(0o600)`); the
///   bits only apply on creation, so an operator-tightened existing
///   file keeps its tighter mode. Loosened mode is acceptable —
///   apply.log lines never embed secrets (the action label + target
///   name are operator-supplied identifiers; outcome strings are
///   already control-char-escaped via `escape_control_chars`).
/// - **Append-mode** (`O_APPEND`) — multiple `apply` invocations
///   serialize via `flock` on `apply.lock`, so cross-process write
///   ordering is determined by lock order; within an apply run the
///   loop is single-threaded and writes are sequential.
/// - **Best-effort**: any failure (parent dir missing, ENOSPC,
///   EACCES) is logged via `tracing::warn!` and swallowed. Audit
///   logging MUST NOT cause an apply to fail — that would invert
///   the operator priority of "execute the action" vs "record what
///   happened".
///
/// **Recommended logrotate config** (operators install separately —
/// not bundled in v0.1):
/// ```text
/// /var/log/ghars/apply.log {
///     weekly
///     rotate 12
///     compress
///     missingok
///     notifempty
///     create 0600 root root
///     postrotate
///         # No service reload — apply.rs reopens via append-mode each time.
///     endscript
/// }
/// ```
///
/// `target` is parsed out of the `Action::label()` format
/// `"Variant(name)"` — the parens-bounded name is the runner/pool.
/// `NoOp(reason)` is treated as `target = reason` so the log shape
/// stays uniform; consumers filter on `action != "NoOp"` if they
/// want to skip in-sync rows.
pub(super) fn write_audit_log_entry(paths: &Paths, label: &str, outcome: &str) {
    let log_path = paths.apply_log();
    let timestamp = chrono::Utc::now().to_rfc3339_opts(chrono::SecondsFormat::Millis, true);
    let (action, target) = parse_audit_label(label);

    let entry = serde_json::json!({
        "timestamp": timestamp,
        "action":    action,
        "target":    target,
        "outcome":   outcome,
    });
    let mut line = entry.to_string();
    line.push('\n');

    if let Some(parent) = log_path.parent() {
        if let Err(e) = fs::create_dir_all(parent.as_std_path()) {
            tracing::warn!(
                path = %log_path,
                error = %e,
                "audit log: failed to create parent directory; skipping entry"
            );
            return;
        }
    }
    let open_result = OpenOptions::new()
        .create(true)
        .append(true)
        .mode(0o600)
        .open(log_path.as_std_path());
    let mut file = match open_result {
        Ok(f) => f,
        Err(e) => {
            tracing::warn!(
                path = %log_path,
                error = %e,
                "audit log: open(create+append) failed; skipping entry"
            );
            return;
        }
    };
    if let Err(e) = file.write_all(line.as_bytes()) {
        tracing::warn!(
            path = %log_path,
            error = %e,
            "audit log: write failed; entry partially written"
        );
    }
}

/// Split `Action::label()` output (`"Variant(name)"`) into
/// `(variant, name)`. Returns `(label, "")` if the label doesn't
/// parse — defense in depth against future label format changes.
pub(super) fn parse_audit_label(label: &str) -> (&str, &str) {
    if let Some(open) = label.find('(') {
        if let Some(close_rel) = label[open..].rfind(')') {
            let close = open + close_rel;
            return (&label[..open], &label[open + 1..close]);
        }
    }
    (label, "")
}
