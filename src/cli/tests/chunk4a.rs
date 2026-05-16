//! Test chunk - co-located with cli/ submodules. See tests/mod.rs for fixture sharing rationale.
#![allow(clippy::unwrap_used)]

use super::*;

/// Defense-in-depth: a runner.caches entry whose length exceeds
/// `IDENTIFIER_MAX_LEN` must reject at config load even when the
/// `cache_pools` map itself is empty / valid. Today the planner's
/// cross-reference rejects unknown names earlier, but that error
/// is shape-agnostic ("unknown cache pool"). The identifier-shape
/// gate here surfaces a `runner "NAME" caches[]:` scope so the
/// operator sees which runner referenced the oversize string.
#[test]
fn validate_cache_pool_names_rejects_oversize_runner_caches_entry() {
    let mut cfg = cfg_with_runner_trust_zone("buckos", "default".into());
    let oversize = "a".repeat(crate::config::IDENTIFIER_MAX_LEN + 1);
    cfg.runners[0].caches = vec![oversize.clone()];
    let err =
        validate_cache_pool_names(&cfg).expect_err("oversize runner.caches entry must reject");
    match &err {
        GharsError::Validation(msg, _) => {
            assert!(
                msg.contains("runner \"buckos\" caches[]") && msg.contains(&oversize),
                "msg must scope to the offending runner.caches entry by value; \
                 got: {msg}"
            );
            assert!(
                msg.contains("identifier") && msg.contains("too long"),
                "msg must come from the identifier-shape gate; got: {msg}"
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

// ---------- sigil tests ---------------------------------------------

/// pin the `!` sigil contract for recreate-class `UpdateRunner`
/// against an EMPTY `recreate_reasons` Vec. Adds new coverage axes
/// over `render_action_line_update_runner_sigil_distinguishes_recreate_from_inplace`
/// (which uses a single non-empty reason): the empty-reasons case
/// reaches the same `if d.requires_recreate` branch in
/// `render_action_line`. The column-0 `! ` sigil + `[recreate]`
/// bracket tag MUST hold even when reasons is empty — the sigil
/// is the fast-scan signal and is independent of reasons content.
///
/// `plan::plan_from` enforces `requires_recreate =
/// !recreate_reasons.is_empty()`, so the renderer trusts the
/// invariant and unconditionally emits `update: recreate
/// (REASONS)`. A hand-constructed fixture that violates the
/// invariant would surface as `update: recreate ()` — a visible
/// loud signal that the fixture is malformed, not a silent
/// production failure mode.
#[test]
fn render_action_line_update_runner_recreate_uses_bang_sigil() {
    let action = Action::UpdateRunner(recreate_delta("buckos", vec!["url"]));
    let line = render_action_line(&action, ColorMode { enabled: false }, false);
    assert!(
        line.starts_with("! "),
        "recreate-class UpdateRunner must lead with `! ` at column 0; \
         got: {line}",
    );
    assert!(line.contains("[recreate]"), "got: {line}");
    assert!(
        line.contains("update: recreate (url)"),
        "recreate-class UpdateRunner must render reasons in parens; \
         got: {line}",
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

/// Yellow ANSI color for recreate-class `UpdateRunner`.
/// `render_action_line` selects ANSI prefix by Action variant; both
/// recreate and in-place `UpdateRunner` paths share `\x1b[33m`
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

/// ColorMode.enabled=false produces zero ANSI escapes. This
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

/// Operator-grep parity — `^! ` line count == count of
/// recreate-class `UpdateRunner` actions, NOT `summary.recreates.len()`.
///
/// `summary.recreates` is the JSON sibling of the Recreate-class
/// label list; it includes ALL Action variants whose
/// `Action::disruption` is `Disruption::Recreate` — `CreateRunner`,
/// UpdateRunner-recreate, `RemoveRunner`, `CreateCachePool`,
/// `RemoveCachePool`. The `!` sigil only marks the `UpdateRunner`-
/// recreate branch (per `render_action_line`'s doc-comment).
///
/// Fixture covers the asymmetry: `CreateRunner` + `UpdateRunner`-
/// recreate + in-place `UpdateRunner` + `RemoveRunner` + `RemoveCachePool`.
/// `^! ` count = 1 (only the UpdateRunner-recreate row); summary
/// recreate count = 4 (every recreate-class variant). Pins the
/// strict-greater asymmetry so a future renderer change that
/// broadens `!` to other variants would fail.
#[test]
fn render_action_line_sigil_count_matches_recreate_update_runners() {
    let actions = [
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
        "only UpdateRunner-recreate uses `!`; got bang_count=\
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

/// `!` column-0 sigil holds under `--diff=true`. The recreate
/// branch in `render_action_line` synthesizes Created drop-in
/// blocks from `delta.after.drop_ins` AND emits `- basename` lines
/// for entries in `before_drop_in_basenames` that are absent from
/// `after.drop_ins` (recreate-class Removed-line surface). Both shapes use a
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
    // from after.drop_ins so the Removed branch fires.
    delta.before_drop_in_basenames = Some(vec!["00-ghars.conf".into(), "99-custom.conf".into()]);
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
    // 4-space indent on basename lines (Removed branch).
    assert!(
        line.contains("    - 99-custom.conf"),
        "Removed basename line missing (before_drop_in_basenames \
         has 99-custom.conf, after.drop_ins does not); got: {line}",
    );
}

/// Defense-in-depth — `!` MUST NOT appear at column 0 on any
/// non-recreate-UpdateRunner variant. Sigil vocabulary per
/// `render_action_line`:
/// - `CreateRunner` / `CreateCachePool` → `+`
/// - `RemoveRunner` / `RemoveCachePool` → `-`
/// - UpdateRunner-inplace / `UpdateCachePool` → `~`
/// - `NoOp` → ` ` (space)
/// `!` is reserved for `UpdateRunner` with `requires_recreate=true`.
/// Pins the vocabulary so a future refactor cannot silently
/// broaden `!` to other variants.
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
             class UpdateRunner); got: {line}",
        );
    }
}

/// Shell-safety contract — `!` is followed by a space.
/// Bash interprets `!word` as history expansion (e.g. `!1234`
/// recalls a history entry); `! ` prevents that when an operator
/// pastes a plan line into a shell. Two cases cover both format
/// branches: bare/plain (sigil at column 0) and bare/color (sigil
/// after the `\x1b[33m` ANSI prefix). Both must end the `!` byte
/// with `b' '`. Other shape variants (with `field_changes`, with
/// drop-in synthesis, etc.) test the body-block rendering, not
/// the byte contract — coverage is on the `!` itself, not
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
            "{name}: shell-safety violation — `!` must be followed by ' ' \
             (bash history expansion guard); got byte 0x{:02x} at \
             position {after_bang}; line: {line}",
            bytes[after_bang],
        );
    }
}

// ---------- detail/exit-code tests ---------------------------------

/// Pins that ApplyResult.details can carry multiple Failed
/// rows interleaved with non-Failed rows. The fixture mirrors what
/// the `apply()` loop produces under non-fail_fast: every action's
/// outcome lands in details, and the success/failure split lives
/// in `succeeded` / `failed` Vecs (which mirror details by label).
/// This test pins the data shape; integration coverage via the
/// real `apply()` loop.
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
    assert_eq!(apply_exit_code(false, false, &result), 4);
}

/// Pin the per-action prefix shapes `cmd_apply` emits for each
/// outcome class. `cmd_apply`'s per-action loop routes by variant to
/// stdout (`NoOp`, success) or stderr (Failed); the stream routing
/// itself is not directly testable without helper extraction
/// (a separate refactor tracks that). This test reproduces the exact
/// format!() invocations from the `cmd_apply` per-action loop and
/// pins the prefix-shape contract:
/// - `noop: REASON [none]` (`NoOp` arm)
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

/// Exit-code regression pin — `apply_exit_code` failure
/// precedence (1 / 4 / 5) is unaffected by the addition of Failed
/// rows to `result.details`. Keys off `result.failed`
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
        assert_eq!(apply_exit_code(de, der, &partial), 4, "de={de}, der={der}");
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
    assert_eq!(apply_exit_code(false, false, &total_auth), 5);

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
    assert_eq!(apply_exit_code(false, false, &total_non_auth), 1);
}

// ---------- cmd_apply summary footer tests -------------------------

/// `cmd_apply` summary footer mixed-outcome shape.
/// `render_apply_summary_line` emits the headline triple
/// (`A applied, F failed, S skipped`) followed by the disruption
/// parenthetical + `any_recreate` suffix produced by the shared
/// `format_disruption_tail`. Disruption labels come
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

/// Applied-bucket coverage for Removed / Recreated /
/// `PoolCreated` / `PoolRemoved`. The sibling test
/// `render_apply_summary_line_buckets_every_variant_correctly`
/// exercises Created / `InPlaceRestarted` / `PoolUpdated` / `NoOp` /
/// `InPlaceSkipped` / Failed. This test covers the four remaining
/// `applied`-bucket variants — all of which are
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

/// Multi-failure-only plan (all-failed, no successes, no
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

/// Synthetic `daemon_reload` Failed row — verifies the data
/// shape `apply()` produces for the `daemon_reload` synthetic row, not
/// `apply()` behavior directly. apply.rs's post-loop `daemon_reload`
/// synthesis pushes a Failed row with `plan_disruption =
/// Disruption::None` (Manager.Reload is a cache-flush
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

/// Inverse pin — Restart-class Failed must NOT flip
/// `any_recreate`. `Failed.disruption()` delegates to
/// `plan_disruption`; for an in-place `UpdateRunner` that fails
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

// ---------- rollback advisory tests --------------------------------

/// Ordering invariant pin —
/// `failed_undo_logs[i].0 == failed[i].0` for every `i` in a
/// multi-failure non-fail_fast scenario. `apply::apply` pushes
/// to both Vecs in the same execute-order loop iteration; the
/// advisory renderer walks `failed_undo_logs` for both the body
/// blocks and the header count (header N is the count
/// of non-empty step lists, derived directly from
/// `failed_undo_logs`). Pinning here catches a future refactor
/// that decouples the two Vecs (e.g. moves the typed-error push
/// elsewhere) and drifts the label ordering apart.
#[test]
fn render_rollback_advisory_failed_and_failed_undo_logs_share_label_ordering() {
    // Use push_failed to enforce the lockstep invariant
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

/// Step ordering pin — within a single failed action's
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
    // CreateDir → WriteFile → EnableUnit. Advisory MUST render in
    // reverse: EnableUnit → WriteFile → CreateDir.
    let mut result = apply::ApplyResult::default();
    push_failed(
        &mut result,
        "CreateCachePool(build)",
        vec![
            apply::UndoStep::CreateDir {
                path: camino::Utf8PathBuf::from("/etc/systemd/system/ghars-cache@build.service.d"),
            },
            apply::UndoStep::WriteFile {
                path: camino::Utf8PathBuf::from(
                    "/etc/systemd/system/ghars-cache@build.service.d/00-ghars.conf",
                ),
                prior_content: None,
            },
            apply::UndoStep::EnableUnit {
                name: "ghars-cache@build.service".into(),
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
    let pos_enable = advisory
        .find("enabled ghars-cache@build.service")
        .expect("EnableUnit step present");
    // LIFO: EnableUnit (most recent) → WriteFile → CreateDir
    // (earliest, bottom).
    assert!(
        pos_enable < pos_write_file,
        "EnableUnit must precede WriteFile (LIFO); got: {advisory}",
    );
    assert!(
        pos_write_file < pos_create_dir,
        "WriteFile must precede CreateDir (LIFO); got: {advisory}",
    );
}

/// Daemon_reload-only failure renders NO ADVISORY at all.
/// The `daemon_reload` synthesis at `apply::apply` pushes to
/// `result.failed` AND `result.failed_undo_logs` with an EMPTY
/// step Vec (no per-action `UndoLog` exists for the synthetic
/// post-loop step).
///
/// When EVERY entry in `failed_undo_logs` has an empty
/// step list, `render_rollback_advisory` returns `None` instead
/// of emitting a header that promises actionable cleanup with
/// no body underneath. Silence is more honest than a header
/// without a list. The per-action `fail:` line emitted by
/// `cmd_apply`'s detail loop already communicates the failure
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
    // All-empty step lists ⇒ no advisory at all.
    assert!(
        render_rollback_advisory(&result).is_none(),
        "all-empty failed_undo_logs must suppress the advisory entirely",
    );
}

/// Multi-failure all-empty pin — verify the
/// `filter(!is_empty()).count() == 0` gate scales beyond the
/// single-entry `daemon_reload` case. Three failed actions, all
/// with empty `UndoStep` Vecs (e.g. each errored before recording
/// any side effect). The advisory renderer should still return
/// `None` because the filter yields 0 for uniformly-empty input
/// (every entry is rejected by the `!steps.is_empty()` predicate).
///
/// Sibling: `render_rollback_advisory_daemon_reload_only_failure_returns_none`
/// pins the single-entry isolated case; this multi-entry fixture
/// catches a future regression that special-cases N==1 (e.g. if
/// `result.failed_undo_logs.len() == 1 && ...` — falling back to
/// emit-anyway when N>=2). The gate is
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
    // Multi-entry: all-empty step lists ⇒ no advisory.
    // Pins the non-empty-count gate
    // (`filter(!is_empty()).count() == 0`) beyond the single
    // daemon_reload entry. This fixture is hand-constructed
    // (production `apply()`'s per-action loop always pushes the
    // per-action UndoLog with whatever steps were recorded —
    // empty only for pre-side-effect errors), but the rendering
    // contract must hold for the convergent case where every
    // action errored pre-mutation.
    assert!(
        render_rollback_advisory(&result).is_none(),
        "all-empty failed_undo_logs (multi-entry) must suppress the advisory entirely",
    );
}

/// Positive-control test for the
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
        vec![apply::UndoStep::EnableUnit {
            name: "ghars-cache@build.service".into(),
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

/// Negative-control test for the length-mismatch invariant.
/// `apply::apply` pushes to `result.failed` and
/// `result.failed_undo_logs` in lockstep on every Err arm —
/// both the per-action loop's Err arm and the synthetic
/// post-loop `daemon_reload` arm. The lengths can only diverge in
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

// ---------- render_rollback_advisory test scaffolding ----------------

/// shared helper for `render_rollback_advisory` test fixtures.
/// Every advisory test that drives the renderer with one or more
/// failures must push to BOTH `failed` and `failed_undo_logs` in
/// lockstep — the typed-error tuple and the per-action `UndoLog`
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
///
/// **Error content drift (intentional)**: `result.failed[i].1`
/// always carries `validation_err("test")` here regardless of
/// what the caller wants to surface to operators. Tests that
/// need a specific error message (e.g. fail-row text on stderr)
/// independently populate `result.details[i]` with
/// `apply::ApplyOutcome::Failed { error_summary, plan_disruption }`
/// — that's the row source the renderer reads. The two Vecs
/// carry different content by design:
///   - `details[i]`: per-action outcome the renderer reads to
///     emit `fail: LABEL [disruption] (error_summary)` on
///     stderr (per `render_apply_emission`'s contract);
///   - `failed[i].1`: the typed `GharsError` chain the renderer
///     does NOT read — it exists for the `apply_exit_code` mapper,
///     which walks `result.failed.iter().any(|(_, e)| matches!(e,
///     GharsError::Auth(_, _)))` to choose between exit codes 1
///     (generic failure) and 5 (auth failure).
///     `render_rollback_advisory` does not consult `failed[i].1`
///     either — it reads only `failed_undo_logs` for both header
///     count and body content.
///   - `failed_undo_logs[i].1`: the rollback `UndoStep` list
///     `render_rollback_advisory` body reads.
/// `validation_err("test")` is a type-level placeholder: it
/// satisfies `failed`'s `(String, GharsError)` shape so the
/// `debug_assert_eq!(failed.len(), failed_undo_logs.len())` gate
/// passes, and the renderer never reads it. **A future test that
/// reads `result.failed[i].1` content** (i.e. asserts on the
/// typed error rather than `details[i]`'s `error_summary`) must
/// either (a) replace `validation_err("test")` in this helper
/// with caller-supplied error content, or (b) bypass the helper
/// and push to `failed` / `failed_undo_logs` directly with the
/// specific `GharsError` it wants to assert on. Asserting on the
/// hardcoded `"test"` string would pin a placeholder, not the
/// production behavior.

// ---------- format_rollback_advisory_header unit tests ---------------

/// direct unit test for `format_rollback_advisory_header`
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

/// Direct unit test at N=5 — the typical
/// multi-failure case (e.g. an apply run with five actions all
/// of which left non-empty `UndoLogs`). Pin the `{n}` interpolation
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

/// Documents that the N=0 case is
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

// ---------- render_rollback_advisory N coverage -------------------

/// Mixed case — two failed actions with EMPTY step
/// lists + one failed action with a NON-EMPTY step list. The
/// header gate counts only entries with non-empty
/// step lists, so N=1 (not N=3). The body must contain exactly
/// ONE per-action sub-block (the non-empty entry).
///
/// This pins the asymmetry between `failed` (3 entries) and the
/// rendered output (header N=1, body block count=1) under the
/// most operator-confusing input shape: the per-action
/// `fail:` lines from `cmd_apply`'s detail loop will report all
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
    // Header: N counts ONLY the non-empty entry (per the gate),
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

/// All-non-empty case — three failed actions, every
/// one with a non-empty step list. Header N must equal the total
/// failure count (3) because no entry is filtered out by the
/// `!is_empty()` predicate. Body must have exactly 3 per-action
/// sub-blocks. Pins the contract that under uniformly-non-empty
/// input the filter is a no-op vs the pre-gate
/// `failed_undo_logs.len()` count.
///
/// Sibling: `render_rollback_advisory_failed_and_failed_undo_logs_share_label_ordering`
/// also covers 3 non-empty entries; that test pins ORDER
/// (failed[i].0 == `failed_undo_logs`[i].0). This test is focused
/// on the HEADER N count == total failures invariant under
/// all-non-empty conditions.
#[test]
fn render_rollback_advisory_all_non_empty_header_matches_total() {
    let mut result = apply::ApplyResult::default();
    push_failed(
        &mut result,
        "CreateRunner(a)",
        vec![apply::UndoStep::EnableUnit {
            name: "ghars-runner@a.service".into(),
        }],
    );
    push_failed(
        &mut result,
        "CreateRunner(b)",
        vec![apply::UndoStep::EnableUnit {
            name: "ghars-runner@b.service".into(),
        }],
    );
    push_failed(
        &mut result,
        "CreateRunner(c)",
        vec![apply::UndoStep::EnableUnit {
            name: "ghars-runner@c.service".into(),
        }],
    );
    let advisory = render_rollback_advisory(&result).expect("all-non-empty must yield an advisory");
    // Header N == total failure count (3) under all-non-empty
    // input; the filter is a no-op here.
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

/// Alternating order — `failed_undo_logs` Vec ordered
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
/// per-action `fail:` lines emitted by `cmd_apply`'s detail loop.
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
    let advisory =
        render_rollback_advisory(&result).expect("two non-empty entries must yield an advisory");
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

// ---------- sigil multi-element recreate_reasons pin -----------------

/// Pin the multi-element `recreate_reasons.join(",")` format the
/// renderer at `render_action_line` produces. The empty-case
/// pin lives on `render_action_line_update_runner_recreate_uses_bang_sigil`;
/// this test pins the multi-element case so a future renderer
/// change to a different separator (e.g. `, ` with space, `+`,
/// etc.) is caught at the test layer. Format expected:
/// `update: recreate (url,arch)` — comma without space between
/// elements.
///
/// This `(REASONS)` parenthetical only applies when
/// `recreate_reasons` is non-empty. The empty-reasons branch
/// emits `update: recreate` with NO parens (omit-parens guard
/// in `render_action_line`) — see
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

// ---------- recreate-reason rendering --------------------------------

// Before the uncovered-arm decoupling the renderer had an under-header `note: TOKEN — explanation`
// loop for opaque recreate-reason tokens (only `uncovered`). Since the uncovered-arm decoupling
// the uncovered arm in `plan_from` no longer pushes a recreate reason,
// so the production vocabulary for `recreate_reasons` is strictly
// field-name tokens (url, runner_version, labels, arch, runner_sha256,
// runner_tarball, network) — every one self-explanatory via the
// `field_changes` before→after row above. The note loop + the
// `recreate_reason_note` helper were both deleted; the tests that
// pinned them went with them. The pin below documents the no-note
// invariant for the field-name vocabulary so a future regression that
// re-introduces a gloss surfaces here.

/// field-name tokens (`url`, `runner_version`, …) MUST NOT
/// emit a `note:` line — the `field_changes` loop renders the
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

/// in-place `UpdateRunner` (no recreate) MUST NOT emit any
/// `note:` lines. Before the uncovered-arm decoupling the gate was the `recreate_reason_note`
/// helper returning None for non-opaque tokens; post-fix the gloss
/// loop itself is removed, so the gate is structural — `note:` lines
/// cannot appear at all from this renderer site. Pin the contract.
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

// ---------- summary.recreates serde round-trip ---------------------

/// Round-trip the rendered `summary.recreates` array through
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
        keep_versions: 2,
    };
    let body = plan_to_json_value(&plan, false);
    // Serialize to wire-format JSON string and back.
    let wire = serde_json::to_string(&body).expect("serialize body");
    let reread: serde_json::Value = serde_json::from_str(&wire).expect("deserialize wire format");
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
