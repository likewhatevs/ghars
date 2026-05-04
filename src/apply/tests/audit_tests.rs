//! Tests for `apply::audit::write_audit_log_entry` (SEC-36).

use camino::Utf8PathBuf;

use super::super::audit::{parse_audit_label, write_audit_log_entry};
use super::super::outcome::ApplyOutcome;
use super::common::make_paths;

#[test]
fn write_audit_log_entry_creates_file_at_paths_apply_log() {
    let tmp = tempfile::tempdir().unwrap();
    let paths = make_paths(&tmp);
    write_audit_log_entry(&paths, "CreateRunner(buckos)", "success");
    let body = std::fs::read_to_string(paths.apply_log().as_std_path()).unwrap();
    assert!(
        !body.is_empty(),
        "audit log must contain the entry; got empty file"
    );
    // File must end with newline so each line is JSON-line shaped.
    assert!(body.ends_with('\n'), "audit log line must end with \\n");
}

#[test]
fn write_audit_log_entry_emits_one_line_per_call_via_append() {
    let tmp = tempfile::tempdir().unwrap();
    let paths = make_paths(&tmp);
    write_audit_log_entry(&paths, "CreateRunner(buckos)", "success");
    write_audit_log_entry(&paths, "RemoveRunner(spamtrap)", "success");
    write_audit_log_entry(&paths, "UpdateCachePool(build)", "success");
    let body = std::fs::read_to_string(paths.apply_log().as_std_path()).unwrap();
    let lines: Vec<&str> = body.lines().collect();
    assert_eq!(lines.len(), 3, "expected one line per call; got {body:?}");
}

#[test]
fn write_audit_log_entry_emits_canonical_json_line_shape() {
    let tmp = tempfile::tempdir().unwrap();
    let paths = make_paths(&tmp);
    write_audit_log_entry(&paths, "CreateRunner(buckos)", "success");
    let body = std::fs::read_to_string(paths.apply_log().as_std_path()).unwrap();
    let line = body.lines().next().unwrap();
    let entry: serde_json::Value = serde_json::from_str(line).expect("valid JSON line");
    assert_eq!(entry["action"], "CreateRunner");
    assert_eq!(entry["target"], "buckos");
    assert_eq!(entry["outcome"], "success");
    // Timestamp is RFC3339; we test that it parses as a chrono
    // DateTime to ensure the format is compatible with downstream
    // consumers (jq, ELK, journald JSON ingestion).
    let ts = entry["timestamp"].as_str().expect("timestamp must be string");
    chrono::DateTime::parse_from_rfc3339(ts).expect("timestamp must be RFC3339");
}

#[test]
fn write_audit_log_entry_creates_logs_dir_if_missing() {
    // Best-effort directory creation: the audit logger must not
    // require operators to have pre-created /var/log/ghars; it
    // creates the parent on first write.
    let tmp = tempfile::tempdir().unwrap();
    let paths = make_paths(&tmp);
    // Logs dir does NOT pre-exist.
    assert!(!paths.logs_dir.as_std_path().exists());
    write_audit_log_entry(&paths, "RemoveRunner(buckos)", "success");
    assert!(paths.logs_dir.as_std_path().exists());
    assert!(paths.apply_log().as_std_path().exists());
}

#[test]
fn write_audit_log_entry_swallows_failure_on_unwritable_parent() {
    // If parent dir creation fails (e.g. EACCES under /sys/), the
    // helper must not panic or propagate. The function is fire-
    // and-forget — operator priority is "execute the action",
    // not "record the result".
    let mut paths = make_paths(&tempfile::tempdir().unwrap());
    // Point logs_dir at a path that cannot be created (under
    // /proc/cmdline which is a regular file). create_dir_all
    // returns EEXIST→ENOTDIR; helper must swallow.
    paths.logs_dir = Utf8PathBuf::from("/proc/cmdline/audit-subdir-impossible");
    // Must not panic — best-effort logging.
    write_audit_log_entry(&paths, "CreateRunner(x)", "success");
}

#[test]
fn parse_audit_label_splits_variant_and_target() {
    assert_eq!(
        parse_audit_label("CreateRunner(buckos)"),
        ("CreateRunner", "buckos")
    );
    assert_eq!(
        parse_audit_label("UpdateCachePool(build-cache)"),
        ("UpdateCachePool", "build-cache")
    );
    assert_eq!(
        parse_audit_label("NoOp(in sync)"),
        ("NoOp", "in sync")
    );
}

#[test]
fn parse_audit_label_returns_full_label_when_unparseable() {
    // Defense in depth: a future label format that omits parens
    // must round-trip through the parser without losing data.
    assert_eq!(parse_audit_label("BareLabel"), ("BareLabel", ""));
    assert_eq!(parse_audit_label(""), ("", ""));
}

#[test]
fn apply_outcome_audit_summary_collapses_success_variants() {
    // Every successful host-mutation variant collapses to
    // "success" in the audit log. Operators filter on this token
    // when extracting "what mutations happened" without caring
    // about the specific variant.
    for outcome in [
        ApplyOutcome::Created,
        ApplyOutcome::Removed,
        ApplyOutcome::Recreated,
        ApplyOutcome::PoolCreated,
        ApplyOutcome::PoolUpdated,
        ApplyOutcome::PoolRemoved,
        ApplyOutcome::InPlaceRestarted {
            files_changed: 0,
            pools_added: vec![],
            pools_removed: vec![],
        },
    ] {
        assert_eq!(outcome.audit_summary(), "success");
    }
}

#[test]
fn apply_outcome_audit_summary_distinguishes_short_circuits() {
    // Short-circuit variants ("noop / in-sync / dry-run") are
    // intentionally distinct so audit consumers can filter
    // "actual mutations" from "this is what apply WOULD have
    // done" / "nothing to do" rows.
    assert_eq!(ApplyOutcome::InPlaceSkipped.audit_summary(), "in-sync");
    assert_eq!(ApplyOutcome::PoolSkipped.audit_summary(), "in-sync");
    assert_eq!(ApplyOutcome::NoOp.audit_summary(), "noop");
    assert_eq!(ApplyOutcome::DryRunSkipped.audit_summary(), "dry-run");
}

#[test]
fn apply_outcome_audit_summary_carries_failure_diagnostic() {
    // Failed variants forward the sanitized error string verbatim
    // so the audit consumer sees the same diagnostic the operator
    // saw on stderr.
    let outcome = ApplyOutcome::Failed {
        error_summary: "auth registry: pat not found".into(),
        plan_disruption: crate::plan::Disruption::Recreate,
    };
    assert_eq!(
        outcome.audit_summary(),
        "auth registry: pat not found"
    );
}
