//! Test chunk - co-located with cli/ submodules. See tests/mod.rs for fixture sharing rationale.
#![allow(clippy::unwrap_used)]

use super::*;

// ---- err_to_exit_code variant mapping ---------------------------

/// `GharsError::Config` → exit code 6 (Part 5).
#[test]
fn err_to_exit_code_config_returns_six() {
    let err = GharsError::Config("missing field".into(), "add it".into());
    assert_eq!(err_to_exit_code(&err), 6);
}

/// `GharsError::Validation` → exit code 6. Validation
/// errors are config-shape rejections (`trust_zone` charset,
/// duplicate caches, `render_identity` defense-in-depth) — the
/// operator must edit the TOML to recover, same actionable
/// class as Config.
#[test]
fn err_to_exit_code_validation_returns_six() {
    let err = GharsError::Validation("bad shape".into(), "fix it".into());
    assert_eq!(err_to_exit_code(&err), 6);
}

/// `GharsError::Interactive` → exit code 7. Distinct
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

/// `GharsError::Auth` → exit code 5. Per-action auth
/// failures during apply already route to 5 via `apply_exit_code`;
/// a top-level `Auth` Err is an auth-resolve failure
/// outside per-action accounting and routes to the same code so
/// scripts can branch uniformly on auth-class failures.
#[test]
fn err_to_exit_code_auth_returns_five() {
    let err = GharsError::Auth("token rejected".into(), "rotate".into());
    assert_eq!(err_to_exit_code(&err), 5);
}

/// `GharsError::Preflight` → exit code 3. Same code
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

/// `GharsError::GitHub` → exit code 1. GitHub API errors
/// are operator-environment problems (network, rate-limit,
/// upstream outage), not config-shape — they don't route to 6.
#[test]
fn err_to_exit_code_github_returns_one() {
    let err = GharsError::GitHub("404 Not Found".into(), "verify URL".into());
    assert_eq!(err_to_exit_code(&err), 1);
}

/// `GharsError::Systemd` → exit code 1. D-Bus / unit
/// errors are runtime-environment failures, not config-shape.
#[test]
fn err_to_exit_code_systemd_returns_one() {
    let err = GharsError::Systemd("D-Bus timeout".into(), "check dbus".into());
    assert_eq!(err_to_exit_code(&err), 1);
}

/// `GharsError::Tarball` → exit code 1. Tarball
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

/// `GharsError::Sha256Mismatch` → exit code 1. Digest
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

/// `GharsError::ApplyLocked` → exit code 1. Lock
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

/// `GharsError::Apply { .. }` → exit code 1. The Apply
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

// ---- cancel_exit_code (cancel + --detailed-exitcode) -----------

/// Cancellation without `--detailed-exitcode` → 0. Cancelling
/// an interactive prompt is a non-error per established CLI
/// convention. `cancel_exit_code` takes a recreate flag +
/// `&Plan`; passing `false` + an empty plan exercises the
/// no-recreate branch.
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

// ---- dry_run_exit_code (apply --dry-run --detailed-exitcode) ----

/// Dry-run without `--detailed-exitcode` → 0 regardless of plan
/// contents. The terraform `plan -detailed-exitcode` semantic is
/// strictly opt-in.
#[test]
fn dry_run_exit_code_without_detailed_returns_zero() {
    let plan = Plan {
        actions: vec![Action::CreateRunner(fake_runner_plan("a"))],
        warnings: vec![],
        keep_versions: 2,
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
        keep_versions: 2,
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
        keep_versions: 2,
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

// ---- --detailed-exitcode-recreate (exit code 8) -----------------

/// `Plan::has_recreate` returns `true` for any plan whose action set
/// contains a recreate-class action. `CreateRunner` is recreate per
/// `Action::disruption()` at plan.rs.
#[test]
fn plan_has_recreate_detects_create_runner() {
    let plan = Plan {
        actions: vec![Action::CreateRunner(fake_runner_plan("a"))],
        warnings: vec![],
        keep_versions: 2,
    };
    assert!(plan.has_recreate());
}

/// `Plan::has_recreate` returns `false` for plans with only `NoOp`
/// actions. Empty action vec is also `false` — no actions, nothing
/// to recreate.
#[test]
fn plan_has_recreate_returns_false_for_all_noop_or_empty() {
    let all_noop = Plan {
        actions: vec![Action::NoOp("a: in sync".into())],
        warnings: vec![],
        keep_versions: 2,
    };
    assert!(!all_noop.has_recreate());
    assert!(!Plan::default().has_recreate());
}

/// `recreate_exit_code` returns `Some(8)` only when both the flag
/// is set AND the plan has a recreate-class action.
#[test]
fn recreate_exit_code_returns_eight_when_flag_set_and_recreate_present() {
    let plan = Plan {
        actions: vec![Action::CreateRunner(fake_runner_plan("a"))],
        warnings: vec![],
        keep_versions: 2,
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
        keep_versions: 2,
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
        keep_versions: 2,
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
        keep_versions: 2,
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
        keep_versions: 2,
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
    assert_eq!(apply_exit_code(false, true, &result), 8);
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
    assert_eq!(apply_exit_code(false, true, &result), 0);
}

/// `apply_exit_code`: failure precedence — partial-failure (4)
/// trumps recreate (8) even when recreate-class actions ALSO
/// landed successfully. The operator needs to know "go check
/// what failed" before "go check what would recreate".
#[test]
fn apply_exit_code_partial_failure_trumps_recreate() {
    let result = apply::ApplyResult {
        succeeded: vec!["create runner a".into()],
        failed: vec![("create runner b".into(), validation_err("nope"))],
        details: vec![("create runner a".into(), apply::ApplyOutcome::Created)],
        ..Default::default()
    };
    assert_eq!(apply_exit_code(false, true, &result), 4);
}

/// `apply_exit_code`: failure precedence — total auth failure (5)
/// trumps recreate (8). Auth is a structural pre-condition;
/// recreate is downstream plan-shape.
#[test]
fn apply_exit_code_auth_failure_trumps_recreate() {
    let result = apply::ApplyResult {
        succeeded: vec![],
        failed: vec![("create runner a".into(), auth_err("401"))],
        details: vec![],
        ..Default::default()
    };
    assert_eq!(apply_exit_code(false, true, &result), 5);
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

// ---- cancel_exit_code missing cells -------------------------------

/// cancel + recreate flag (alone) + recreate plan → 8.
/// Pins recreate trumps default-0 even without `--detailed-exitcode`.
#[test]
fn cancel_exit_code_recreate_flag_only_with_recreate_returns_eight() {
    let plan = Plan {
        actions: vec![Action::CreateRunner(fake_runner_plan("a"))],
        warnings: vec![],
        keep_versions: 2,
    };
    assert_eq!(cancel_exit_code(false, true, &plan), 8);
}

/// cancel + both flags + `NoOp` plan → 2 (recreate flag set
/// but no recreate present, falls through to detailed-exitcode).
#[test]
fn cancel_exit_code_both_flags_no_recreate_returns_two() {
    let all_noop = Plan {
        actions: vec![Action::NoOp("a: in sync".into())],
        warnings: vec![],
        keep_versions: 2,
    };
    assert_eq!(cancel_exit_code(true, true, &all_noop), 2);
}

/// cancel + recreate flag (alone) + `NoOp` plan → 0.
/// No detailed flag, no recreate present — default to 0.
#[test]
fn cancel_exit_code_recreate_flag_only_no_recreate_returns_zero() {
    let all_noop = Plan {
        actions: vec![Action::NoOp("a: in sync".into())],
        warnings: vec![],
        keep_versions: 2,
    };
    assert_eq!(cancel_exit_code(false, true, &all_noop), 0);
}

// ---- dry_run_exit_code missing cells ------------------------------

/// dry-run + recreate flag (alone) + recreate plan → 8.
/// Pins recreate trumps default-0 even without `--detailed-exitcode`.
#[test]
fn dry_run_exit_code_recreate_flag_only_with_recreate_returns_eight() {
    let plan = Plan {
        actions: vec![Action::CreateRunner(fake_runner_plan("a"))],
        warnings: vec![],
        keep_versions: 2,
    };
    assert_eq!(dry_run_exit_code(false, true, &plan), 8);
}

/// dry-run + both flags + non-NoOp non-recreate plan → 2.
/// (Synthesized via `UpdateRunner` with `requires_recreate=false`,
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
        keep_versions: 2,
    };
    assert_eq!(dry_run_exit_code(true, true, &plan), 2);
}

/// dry-run + recreate flag (alone) + `NoOp` plan → 0.
/// No detailed flag, no recreate present — default to 0.
#[test]
fn dry_run_exit_code_recreate_flag_only_no_recreate_returns_zero() {
    let all_noop = Plan {
        actions: vec![Action::NoOp("a: in sync".into())],
        warnings: vec![],
        keep_versions: 2,
    };
    assert_eq!(dry_run_exit_code(false, true, &all_noop), 0);
}

// ---- apply_exit_code 8>2 precedence -------------------------------

/// `apply_exit_code` with both flags set + success path +
/// recreate-class outcome → 8. Pins that recreate (8) trumps
/// detailed-changes (2) at the apply layer too — symmetric with
/// `dry_run/cancel` rule.
#[test]
fn apply_exit_code_recreate_trumps_detailed_at_apply_layer() {
    let result = apply::ApplyResult {
        succeeded: vec!["create runner a".into()],
        failed: vec![],
        details: vec![("create runner a".into(), apply::ApplyOutcome::Created)],
        ..Default::default()
    };
    assert_eq!(apply_exit_code(true, true, &result), 8);
}

/// `apply_exit_code` total-failure-without-auth →
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
    assert_eq!(apply_exit_code(false, true, &result), 1);
}

/// `Plan::has_recreate` returns `true` for
/// recreate-class actions BEYOND `CreateRunner`. Existing tests
/// only cover Create + `NoOp`. `RemoveRunner` is unambiguously
/// recreate per `Action::disruption` — pin so the helper does
/// not regress to a Create-only check.
#[test]
fn plan_has_recreate_detects_remove_runner() {
    let plan = Plan {
        actions: vec![Action::RemoveRunner(fake_identity("legacy"))],
        warnings: vec![],
        keep_versions: 2,
    };
    assert!(plan.has_recreate());
}

/// Inverse pin — `apply_exit_code` flag-OFF with a
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
    assert_eq!(apply_exit_code(false, false, &result), 0);
    // detailed_exitcode on, recreate flag off → 2 (existing
    // detailed-exitcode contract, NOT 8).
    assert_eq!(apply_exit_code(true, false, &result), 2);
}

/// `FieldValue::List` edge cases — empty Vec
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
            config_source: "/etc/ghars/ghars.toml".into(),
            renderer_schema: crate::systemd::RENDERER_SCHEMA,
        },
        resolved_release: None,
        effective_unit_text: String::new(),
        drop_ins: std::collections::BTreeMap::new(),
        env_file: String::new(),
        path_file: String::new(),
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

// -------- cmd_init does not create the ghars system user ----------

#[test]
fn cmd_init_writes_config_only_no_user_provisioning() {
    // init scaffolds ghars.toml and nothing else. Runner identity
    // comes from `DynamicUser=yes` on the unit (per-trust_zone
    // transient UID/GID allocated at unit start), so init has no
    // user-provisioning step to perform — neither at scaffold time
    // nor lazily at apply time. This test confirms cmd_init
    // succeeds without root + the file lands; the negative claim
    // (no useradd) is now structural — `apply::Users` is not even
    // imported in cli.rs anymore.
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
    // ghars.toml at /etc/ghars/ghars.toml exposes the
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

// -------- cmd_add validates inputs ---------------------------------

#[test]
fn cmd_add_rejects_invalid_repo_url() {
    // A malformed --repo (e.g. ftp://, userinfo, traversal)
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
    // --auth NAME must reference a [auth.NAME] entry that
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
    // Explicit --name must satisfy IDENTIFIER_REGEX
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

#[test]
fn cmd_add_rejects_label_with_quote_injection() {
    // Operator passes a label whose body contains an embedded
    // quote + `\n` + a bogus key → the original code would
    // produce TOML that parses as a NEW key/value pair
    // injected into the runner block. validate_labels must
    // reject the byte before interpolation reaches the file.
    let tmp = tempfile::tempdir().unwrap();
    let config_path = Utf8PathBuf::from_path_buf(tmp.path().to_path_buf())
        .unwrap()
        .join("ghars.toml");
    write_minimal_config(&config_path);
    let paths = Paths::default();
    let mut args = add_args_for("owner/repo", Some("owner-repo-1"), Some("pat"));
    args.labels = vec!["self-hosted".into(), "evil\"\nuser = \"root".into()];
    let err = cmd_add(
        &config_path,
        &paths,
        &args,
        ColorMode { enabled: false },
        true,
    )
    .expect_err("must reject label with quote injection");
    assert!(
        matches!(err, GharsError::Validation(_, _)),
        "expected Validation error; got {err:?}"
    );
    // Defense in depth: even though the validator should fire,
    // verify the file was NOT mutated (no partial write).
    let after = fs::read_to_string(config_path.as_std_path()).unwrap();
    assert!(!after.contains("user = \"root\""));
    assert!(!after.contains("[[runner]]"));
}

#[test]
fn cmd_add_filters_empty_labels_from_clap_value_delimiter_artifact() {
    // clap's `value_delimiter = ','` produces zero-length entries
    // for `--labels foo,,bar` or `--labels ,foo`. The empty
    // entries would land in the labels Vec literal as `""` — a
    // plain `[Tag]` runner with no value. cmd_add must filter
    // them so the rendered TOML matches operator intent.
    let tmp = tempfile::tempdir().unwrap();
    let config_path = Utf8PathBuf::from_path_buf(tmp.path().to_path_buf())
        .unwrap()
        .join("ghars.toml");
    write_minimal_config(&config_path);
    let paths = Paths::default();
    let mut args = add_args_for("owner/repo", Some("owner-repo-1"), Some("pat"));
    args.labels = vec![
        String::new(),
        "self-hosted".into(),
        String::new(),
        "linux".into(),
    ];
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
    // Final TOML carries only the two non-empty labels — no
    // stray `""` placeholder.
    assert!(after.contains("labels = [\"self-hosted\", \"linux\"]"));
    assert!(!after.contains("\"\","));
    assert!(!after.contains("[\"\""));
}

#[test]
fn toml_basic_string_escape_handles_quote_backslash_and_controls() {
    // Per TOML spec, basic strings escape: `"` → `\"`, `\` →
    // `\\`, named C0 codepoints → `\n` / `\r` / `\t` / `\b` /
    // `\f`, other C0 + DEL → `\uXXXX`.
    assert_eq!(toml_basic_string_escape("hello"), "hello");
    assert_eq!(toml_basic_string_escape(r#"a"b"#), r#"a\"b"#);
    assert_eq!(toml_basic_string_escape(r"a\b"), r"a\\b");
    assert_eq!(toml_basic_string_escape("a\nb"), "a\\nb");
    assert_eq!(toml_basic_string_escape("a\tb"), "a\\tb");
    // Bell (U+0007) is C0 but unnamed; emits .
    assert_eq!(toml_basic_string_escape("a\x07b"), "a\\u0007b");
    // DEL (U+007F) — also escaped.
    assert_eq!(toml_basic_string_escape("a\x7fb"), "a\\u007Fb");
    // Non-ASCII printable passes through unchanged.
    assert_eq!(toml_basic_string_escape("café"), "café");
}

// -------- confirm_apply on non-TTY --------------------------------

#[test]
fn confirm_apply_rejects_when_stdin_is_not_a_terminal() {
    // Under `cargo nextest` stdin is a pipe (NOT a TTY), so
    // calling confirm_apply directly exercises the fail-closed
    // branch — read_line would otherwise return Ok(0) and silently
    // cancel the apply (or block on an unclosed pipe). The
    // function MUST surface an Interactive error pointing
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
    // The variant must be Interactive (not Validation), so
    // wrapper scripts can branch on the variant tag — and exit
    // code 7 confirms err_to_exit_code maps the new variant
    // distinctly from Validation's 6.
    assert!(
        matches!(err, GharsError::Interactive(_, _)),
        "expected Interactive variant, got: {err:?}"
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

// ---------- removed flags should be rejected by the parser

#[test]
fn cli_rejects_removed_plan_flag_refresh_releases() {
    // `--refresh-releases` was removed in v0.1; clap must reject
    // it now. This pins the regression so a future "let's add
    // the flag back even though it's not implemented" change
    // fails CI.
    let r = Cli::try_parse_from(["ghars", "plan", "--refresh-releases"]);
    assert!(r.is_err(), "plan --refresh-releases must be rejected");
}

#[test]
fn cli_rejects_removed_plan_flag_output_dir() {
    let r = Cli::try_parse_from(["ghars", "plan", "--output-dir", "/tmp/x"]);
    assert!(r.is_err(), "plan --output-dir must be rejected");
}

#[test]
fn cli_rejects_removed_apply_flag_refresh_releases() {
    let r = Cli::try_parse_from(["ghars", "apply", "--refresh-releases"]);
    assert!(r.is_err(), "apply --refresh-releases must be rejected");
}

// ---------- exit-code precedence -----------------------------------

// Tests drive the production `apply_exit_code` directly
// (no test-local precedence duplication). `classify` partially
// applies `detailed_exitcode_recreate = false` so the
// 2-flag-arity tests stay terse; recreate-flag tests call
// `apply_exit_code` with all three args inline.

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
    // 5 must NOT win when partial-success is observable.
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

// ---------- status_exit_code ---------------------------------------

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

// ---------- D-Bus failure rewrap -----------------------------------

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

// ---------- argv parsing for every subcommand ----------------------

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

/// `ghars plan --detailed-exitcode` parses. Pins the
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

/// `ghars plan` (no flag) leaves `detailed_exitcode = false`.
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
            // Pin clap default-false for the recreate
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
            assert!(!args.score);
            assert!(args.names.is_empty());
        }
        _ => panic!("expected Status"),
    }
}

#[test]
fn argv_status_score_flag_parses() {
    // `--score` is independent of every other status flag — clap
    // parses it as a bare bool, no conflicts. Pin the default-off
    // flip so a regression that wires the flag to a different field
    // (or accidentally enables it by default) surfaces here.
    let cli = Cli::try_parse_from(["ghars", "status", "--score"]).unwrap();
    match cli.command {
        Command::Status(args) => {
            assert!(args.score);
        }
        _ => panic!("expected Status"),
    }
}

#[test]
fn argv_status_score_combines_with_json() {
    // `--score --json` is the canonical machine-consumable shape;
    // pin that the two flags compose without conflict so wrapper
    // scripts can chain them.
    let cli = Cli::try_parse_from(["ghars", "status", "--score", "--json"]).unwrap();
    match cli.command {
        Command::Status(args) => {
            assert!(args.score);
            assert!(args.json);
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
    // cmd_status MUST load_config FIRST, before any other
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
        score: false,
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

/// `cmd_status` calls `load_config` which runs the
/// full post-load validator sweep. Pre-batch-18, `cmd_status` only
/// got `validate_networks` via `load_config` — the other 4 validators
/// (`security_overrides`, `identity_fields`, `no_duplicate_caches`,
/// `cache_pool_names`) were wired into `cmd_validate` / `cmd_plan` /
/// `cmd_apply` individually but NOT `cmd_status`. An oversize pool key
/// would slip past `ghars status` and only fail later at apply.
/// This test pins that the lift fixed the gap end-to-end via the
/// public `cmd_status` surface.
///
/// `runners_only=true` skips D-Bus (no `MockSystemd` needed) — config
/// load (with validators) is the only thing exercised before the
/// state-discovery branch.
#[test]
fn cmd_status_rejects_oversize_cache_pool_via_load_config() {
    let tmp = tempfile::tempdir().unwrap();
    let config_path = Utf8PathBuf::from_path_buf(tmp.path().to_path_buf())
        .unwrap()
        .join("ghars.toml");
    // IDENTIFIER_MAX_LEN + 1-char pool key. Body builds a
    // structurally-valid TOML so the only validator that can reject
    // is validate_cache_pool_names — proves the lift wired into
    // load_config rather than relying on cmd_status itself.
    let oversize_pool = "a".repeat(crate::config::IDENTIFIER_MAX_LEN + 1);
    let body = format!(
        "\
[defaults]

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
        score: false,
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
                "msg must scope to the offending cache_pool by name; got: {msg}"
            );
            assert!(
                msg.contains("identifier") && msg.contains("too long"),
                "msg must come from the identifier-shape gate; got: {msg}"
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

/// End-to-end: a `[[runner]] name` longer than `IDENTIFIER_MAX_LEN`
/// must reject through `cmd_status` because `validate_runner_names`
/// is wired into `load_config`. Symmetric to
/// `cmd_status_rejects_oversize_cache_pool_via_load_config` —
/// proves the lift covers the runner-name surface end-to-end via
/// the public CLI rather than relying on `cmd_validate` / `cmd_apply`
/// individually.
#[test]
fn cmd_status_rejects_oversize_runner_name_via_load_config() {
    let tmp = tempfile::tempdir().unwrap();
    let config_path = Utf8PathBuf::from_path_buf(tmp.path().to_path_buf())
        .unwrap()
        .join("ghars.toml");
    let oversize_name = "a".repeat(crate::config::IDENTIFIER_MAX_LEN + 1);
    let body = format!(
        "\
[defaults]

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
        score: false,
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
                msg.contains("identifier") && msg.contains("too long"),
                "msg must come from the identifier-shape gate; got: {msg}"
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

/// End-to-end: a `[[runner]] trust_zone` containing a control
/// character (here `\n`) must reject through `cmd_status` because
/// `validate_identity_fields` is wired into `load_config` as one
/// of the post-load validators (see the validator-order comment
/// in `load_config`). Symmetric to the cache-pool / runner-name
/// end-to-end tests above. Pins the runner-scoped
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
        score: false,
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

/// End-to-end: a `[cache_pools.NAME] trust_zone` containing
/// a control character (here `\r`) must reject through `cmd_status`.
/// Symmetric to the runner-scoped `trust_zone` test above —
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
        score: false,
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

/// End-to-end happy path: `cmd_status` ACCEPTS a config whose
/// `trust_zone` fields are clean (no control chars). Pins the
/// negative — without it, a future regression that always rejects
/// `trust_zone` (e.g. validator misuse) would only fail the rejection
/// tests above as "no error fired", which is symmetric ambiguity.
/// Asserts `cmd_status` returns Ok (with --runners-only the D-Bus
/// path is skipped, so no live systemd is needed) and the `trust_zone`
/// values pass through `validate_identity_fields` unaltered.
///
/// rc=1 (no preflight check ran the runners-only path through it)
/// is the expected return when the discovered state has no runners
/// matching the empty filter; the `load_config` gate is what we
/// pin here (Ok return ≡ `load_config` accepted).
#[test]
fn cmd_status_accepts_clean_trust_zone_via_load_config() {
    let tmp = tempfile::tempdir().unwrap();
    let config_path = Utf8PathBuf::from_path_buf(tmp.path().to_path_buf())
        .unwrap()
        .join("ghars.toml");
    let body = "\
[defaults]

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
        score: false,
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

/// End-to-end: a `[[runner]] trust_zone` longer than
/// `TRUST_ZONE_MAX_LEN` must reject through `cmd_status` because
/// `validate_trust_zone_lengths` is wired into `load_config`.
/// Pins that the lift covers the `trust_zone` length surface
/// end-to-end via the public CLI.
#[test]
fn cmd_status_rejects_oversize_runner_trust_zone_via_load_config() {
    let tmp = tempfile::tempdir().unwrap();
    let config_path = Utf8PathBuf::from_path_buf(tmp.path().to_path_buf())
        .unwrap()
        .join("ghars.toml");
    let oversize_tz = "a".repeat(crate::validators::TRUST_ZONE_MAX_LEN + 1);
    let body = format!(
        "\
[defaults]

[auth.pat]
kind = \"pat\"
token_env = \"GHARS_PAT\"

[[runner]]
name = \"buckos\"
url = \"https://github.com/example/repo\"
auth = \"pat\"
trust_zone = \"{oversize_tz}\"
"
    );
    fs::write(config_path.as_std_path(), body).unwrap();

    let paths = Paths::default();
    let args = StatusArgs {
        json: false,
        metrics: false,
        health_only: false,
        runners_only: true,
        score: false,
        names: vec![],
    };
    let err = cmd_status(
        &config_path,
        &paths,
        &args,
        ColorMode { enabled: false },
        true,
    )
    .expect_err("oversize runner trust_zone must propagate via load_config");
    match &err {
        GharsError::Validation(msg, _) => {
            assert!(
                msg.contains("runner") && msg.contains("buckos"),
                "msg must scope to the offending runner; got: {msg}"
            );
            assert!(
                msg.contains("trust_zone") && msg.contains("too long"),
                "msg must come from the trust_zone length cap; got: {msg}"
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

/// End-to-end: a `[cache_pools.NAME] trust_zone` longer than
/// `TRUST_ZONE_MAX_LEN` must reject through `cmd_status`. Sister
/// to the runner-side e2e test — the validator walks both
/// surfaces and the cap applies symmetrically.
#[test]
fn cmd_status_rejects_oversize_cache_pool_trust_zone_via_load_config() {
    let tmp = tempfile::tempdir().unwrap();
    let config_path = Utf8PathBuf::from_path_buf(tmp.path().to_path_buf())
        .unwrap()
        .join("ghars.toml");
    let oversize_tz = "a".repeat(crate::validators::TRUST_ZONE_MAX_LEN + 1);
    let body = format!(
        "\
[defaults]

[auth.pat]
kind = \"pat\"
token_env = \"GHARS_PAT\"

[cache_pools.build]
kinds = [\"sccache\"]
size = \"200G\"
trust_zone = \"{oversize_tz}\"
"
    );
    fs::write(config_path.as_std_path(), body).unwrap();

    let paths = Paths::default();
    let args = StatusArgs {
        json: false,
        metrics: false,
        health_only: false,
        runners_only: true,
        score: false,
        names: vec![],
    };
    let err = cmd_status(
        &config_path,
        &paths,
        &args,
        ColorMode { enabled: false },
        true,
    )
    .expect_err("oversize cache_pool trust_zone must propagate via load_config");
    match &err {
        GharsError::Validation(msg, _) => {
            assert!(
                msg.contains("cache_pool") && msg.contains("build"),
                "msg must scope to the offending cache_pool; got: {msg}"
            );
            assert!(
                msg.contains("trust_zone") && msg.contains("too long"),
                "msg must come from the trust_zone length cap; got: {msg}"
            );
        }
        other => panic!("expected GharsError::Validation, got: {other:?}"),
    }
    assert_eq!(err_to_exit_code(&err), 6);
}

/// End-to-end: a `[[runner]] runner_tarball = "/nonexistent..."`
/// must reject through `cmd_status` because `validate_runner_tarballs`
/// is the 8th post-load validator wired into `load_config`. Symmetric
/// to the runner-name / cache-pool end-to-end tests above —
/// proves the lift covers the operator-supplied `runner_tarball`
/// surface so `cmd_validate` / `cmd_plan` / `cmd_apply` / `cmd_status` /
/// `cmd_add` all share the same gate.
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
        score: false,
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

/// Symlink branch: `validate_runner_tarball` lstat's the path
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
        score: false,
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

/// Directory branch: `validate_runner_tarball` rejects a path
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
        score: false,
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

/// End-to-end: a `[[runner]] name` exceeding
/// `NETNS_RUNNER_NAME_MAX_LEN` (= 7) MUST reject through
/// `cmd_status` when the runner's effective network mode is
/// `Netns`. The kernel hard-caps interface names at IFNAMSIZ-1
/// (= 15) in `dev_valid_name`; ghars's veth shape
/// `"ghars-{name}-h"` adds 8 bytes of overhead, so the operator-
/// controlled segment cannot exceed 7. Without this gate the
/// failure surfaces as an opaque `RTNETLINK answers: Numerical
/// result out of range` from `ip link add` during apply.
///
/// Uses `runners_only=true` to skip state.discover (which needs
/// D-Bus) — `load_config` is the only code path under test here.
#[test]
fn cmd_status_rejects_oversize_netns_runner_name_via_load_config() {
    let tmp = tempfile::tempdir().unwrap();
    let config_path = Utf8PathBuf::from_path_buf(tmp.path().to_path_buf())
        .unwrap()
        .join("ghars.toml");
    // 8-char name (one over the cap) — fits the IDENTIFIER_MAX_LEN
    // (64) global cap so the identifier-shape gate does not
    // pre-reject; the failure must come from the netns gate.
    let oversize_name = "a".repeat(crate::validators::NETNS_RUNNER_NAME_MAX_LEN + 1);
    let body = format!(
        "\
[defaults]

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
        score: false,
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

/// Defaults-inheritance pin: a `[[runner]]` with NO per-runner
/// `network = "..."` must INHERIT `[defaults] network = "isolated"`
/// and therefore be subject to the netns IFNAMSIZ gate. Without
/// this test a regression that walked only `runner.network`
/// (skipping the defaults fallback) would silently exempt
/// inheriting runners from the IFNAMSIZ cap, producing the same
/// opaque `RTNETLINK ... Numerical result out of range` failure at
/// apply time that the netns-name-length gate prevents.
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
        score: false,
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

/// Contract pin: the same 8-char runner name that fails the
/// netns gate above MUST PASS when no [network.NAME] is referenced
/// (implicit Open mode — no veth allocated, no IFNAMSIZ exposure).
/// Without this test a regression that hoisted
/// `NETNS_RUNNER_NAME_MAX_LEN` into the global runner-name gate
/// would silently break operator configs that legitimately use
/// longer names in Open mode.
#[test]
fn cmd_status_accepts_oversize_runner_name_in_open_mode() {
    let tmp = tempfile::tempdir().unwrap();
    let config_path = Utf8PathBuf::from_path_buf(tmp.path().to_path_buf())
        .unwrap()
        .join("ghars.toml");
    let oversize_name = "a".repeat(crate::validators::NETNS_RUNNER_NAME_MAX_LEN + 1);
    // No [network.NAME], no defaults.network → implicit Open mode.
    // The name is well under IDENTIFIER_MAX_LEN (64) so the
    // identifier-shape gate accepts it.
    let body = format!(
        "\
[defaults]

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
    load_config(&cfg_path)
        .expect("8-char runner name in Open mode must pass all validators (no IFNAMSIZ exposure)");
}

/// Contract pin: the netns gate (= 7) is ADDITIONAL only for
/// Netns-mode runners — it MUST NOT retroactively tighten the
/// global runner-name cap on Open mode. A regression that
/// applied `NETNS_RUNNER_NAME_MAX_LEN` in `load_config`'s
/// runner-name check (instead of the surface-bound
/// `IDENTIFIER_MAX_LEN`) would silently break every operator on
/// Open mode.
#[test]
fn validate_runner_name_in_open_mode_allows_above_netns_cap() {
    // Pick a length above NETNS_RUNNER_NAME_MAX_LEN (= 7) but
    // within IDENTIFIER_MAX_LEN. Open mode means no netns gate
    // applies. Construct a minimal valid Config directly to
    // exercise validate_runner_names + the load_config sweep
    // without TOML parsing.
    let tmp = tempfile::tempdir().unwrap();
    let config_path = Utf8PathBuf::from_path_buf(tmp.path().to_path_buf())
        .unwrap()
        .join("ghars.toml");
    // One char above NETNS_RUNNER_NAME_MAX_LEN — the smallest
    // shape that would trip the netns gate. Open mode (no
    // [network.NAME] reference) means that gate is skipped, so
    // the name MUST pass the load_config sweep.
    let above_netns_cap_name = "a".repeat(crate::validators::NETNS_RUNNER_NAME_MAX_LEN + 1);
    let body = format!(
        "\
[defaults]

[auth.pat]
kind = \"pat\"
token_env = \"GHARS_PAT\"

[[runner]]
name = \"{above_netns_cap_name}\"
url = \"https://github.com/example/repo\"
auth = \"pat\"
"
    );
    fs::write(config_path.as_std_path(), body).unwrap();
    load_config(&config_path).expect(
        "name above NETNS_RUNNER_NAME_MAX_LEN in Open mode must pass — \
         netns-name-length gate must NOT retroactively tighten Open-mode runners",
    );
}

/// Count-block expansion: a count block whose worst-case
/// expanded instance name exceeds `NETNS_RUNNER_NAME_MAX_LEN` MUST
/// reject. The expanded shape is `{prefix}-{i}` for `i in 1..=N`,
/// so the worst case is `prefix.len() + 1 + count.to_string().len()`.
/// With `NETNS_RUNNER_NAME_MAX_LEN` = 7, prefix len 5 + count digits
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
        score: false,
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

/// Boundary pin: a runner name of EXACTLY
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

/// Count-block boundary pin: `count = Some(1)` MUST be
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

/// Count-block boundary pin: `count = Some(0)` produces
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

/// When `[defaults] network = "isolated"` is set and a
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
    // Even when output is health-only (skips state.discover
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
        score: false,
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
    let cli = Cli::try_parse_from(["ghars", "init", "--output", "/etc/ghars/foo.toml"]).unwrap();
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
    let cli =
        Cli::try_parse_from(["ghars", "metrics", "buckos,ktstr", "--json", "--no-total"]).unwrap();
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
    let cli = Cli::try_parse_from(["ghars", "_netns-veth", "ci-1", "/usr/sbin/ip", "-4", "addr"])
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

/// Pin single `-v` shape. Without this, a regression that
/// changed the clap action from `Count` to `SetTrue` would still
/// pass the -vv/-vvv tests (clap-derive's `Count` collapses
/// repeated short flags) but silently break the single-flag case
/// because `SetTrue` stores 1 only on first occurrence.
#[test]
fn argv_global_verbose_count_single_v_flag() {
    let cli = Cli::try_parse_from(["ghars", "-v", "plan"]).unwrap();
    assert_eq!(cli.verbose, 1);
}

/// Pin `--verbose` long-form shape. Operators may pass the
/// long form (CI scripts often do for readability); a regression
/// that dropped `long` from the clap derive would silently break
/// it without affecting the short-form `-v` tests.
#[test]
fn argv_global_verbose_long_form() {
    let cli = Cli::try_parse_from(["ghars", "--verbose", "plan"]).unwrap();
    assert_eq!(cli.verbose, 1);
}

// ---------- verbose_to_filter_level truth table ---------------

/// Row 1/6: default operator state. No flags = info.
#[test]
fn verbose_to_filter_level_quiet_false_verbose_0_returns_info() {
    assert_eq!(verbose_to_filter_level(false, 0), "info");
}

/// Row 2/6: --quiet alone collapses info chatter to warn.
#[test]
fn verbose_to_filter_level_quiet_true_verbose_0_returns_warn() {
    assert_eq!(verbose_to_filter_level(true, 0), "warn");
}

/// Row 3/6: -v alone bumps to debug.
#[test]
fn verbose_to_filter_level_quiet_false_verbose_1_returns_debug() {
    assert_eq!(verbose_to_filter_level(false, 1), "debug");
}

/// Row 4/6: --quiet AND -v → -v wins; debug. Pins the
/// "verbose overrides quiet" contract documented in the helper's
/// doc-comment.
#[test]
fn verbose_to_filter_level_quiet_true_verbose_1_returns_debug() {
    assert_eq!(verbose_to_filter_level(true, 1), "debug");
}

/// Row 5/6: -vv = trace (any v >= 2 lands here).
#[test]
fn verbose_to_filter_level_quiet_false_verbose_2_returns_trace() {
    assert_eq!(verbose_to_filter_level(false, 2), "trace");
}

/// Row 6/6: --quiet AND -vv → -vv wins; trace.
#[test]
fn verbose_to_filter_level_quiet_true_verbose_2_returns_trace() {
    assert_eq!(verbose_to_filter_level(true, 2), "trace");
}

/// Saturation: any verbose >= 2 maps to trace, not just 2.
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

// ---------- render_plan + render_action_line all variants ---------

/// Build a recreate-class `RunnerDelta` with the given name +
/// `recreate_reasons`. All other fields default to the same values
/// callers would otherwise inline. Use for any recreate-class
/// `UpdateRunner` test fixture where only name + reasons matter.

/// Build an in-place `RunnerDelta` (no recreate) with the
/// given name. Symmetric to `recreate_delta` for the `~` sigil
/// branch.

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
    // Per-field FieldChange entries render as
    // 4-space-indented `path: before → after` lines under the
    // header. The test exercises a recreate-class field (url) and
    // a list-typed field (labels) to confirm both paths produce a
    // line; list rendering uses Display of the whole vec for now —
    // the +/- per-item form is reserved for the full --diff flag.
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
    // Recreate-class UpdateRunner uses `!` sigil at column 0.
    assert!(lines[0].starts_with("! "), "got: {}", lines[0]);
    assert_eq!(
        lines[1],
        "    url: https://github.com/example/buckos → https://github.com/example/buckos-new",
    );
    // List-typed FieldValue renders comma-joined in text
    // (no surrounding brackets — same v1 contract as the
    // pre-typed `labels.join(",")`). Operator grep pipelines
    // that key off `labels:.*gpu` keep working.
    assert_eq!(lines[2], "    labels: ci → ci,gpu");
}

#[test]
fn render_action_line_update_runner_emits_drop_in_change_lines() {
    // Created (`+ basename`), Modified (`~ basename`), and
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
    // In-place update without recreate must carry the
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
    // Existing recreate-reasons formatting: spec_changed
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
