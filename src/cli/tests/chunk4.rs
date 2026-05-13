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
/// The empty-reasons branch emits `update: recreate` with NO
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
    // empty-reasons path — `update: recreate` (no parens).
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

// ---------- opaque recreate-reason gloss ----------------------------

/// `recreate_reason_note` returns `Some` for the `uncovered` opaque
/// classifier token. This is an internal trigger — `uncovered` fires
/// for spec-hash-mismatch fallback — and looks meaningless in the
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
}

/// `recreate_reason_note` returns `None` for self-explanatory
/// field-name tokens. The full vocabulary the classifier emits comes
/// from `RunnerDelta::recreate_reasons` field doc (plan.rs); this
/// test pins every named-field token to the no-gloss branch so a
/// future addition that pushes a non-field token into
/// `recreate_reasons` surfaces here unannotated. Adding a new opaque
/// token without extending `recreate_reason_note` would leave the
/// new token bare in plan output.
#[test]
fn recreate_reason_note_returns_none_for_field_name_tokens() {
    let field_tokens = [
        "url",
        "runner_version",
        "labels",
        "arch",
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

/// `recreate_reason_note` returns `None` for unknown tokens.
/// Defense for future classifier additions: a new token that lands
/// here without an explicit gloss falls through silently rather
/// than hard-erroring, but the test pins the no-gloss-by-default
/// behavior so the dev advocate review flags the omission.
#[test]
fn recreate_reason_note_returns_none_for_unknown_token() {
    assert!(recreate_reason_note("").is_none());
    assert!(recreate_reason_note("some_future_token").is_none());
}

/// `render_action_line` emits an indented
/// `note: uncovered — …` line beneath the header for the
/// `uncovered` token. Header line is unchanged (operator grep
/// `recreate (uncovered)` keeps working — pinned by the existing
/// `render_action_line_recreate_multi_element_reasons_join_format`
/// sibling); the gloss rides as a separate detail line at the
/// 4-space indent matching the `field_changes` loop above.
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

/// mixed reasons render the gloss for ONLY the opaque token, and
/// the field-name token's `note:` line is suppressed because the
/// `field_changes` loop already shows its before→after pair.
#[test]
fn render_action_line_recreate_mixed_reasons_emits_note_per_opaque_token() {
    let action = Action::UpdateRunner(recreate_delta(
        "buckos",
        vec!["url", "uncovered"],
    ));
    let line = render_action_line(&action, ColorMode { enabled: false }, false);
    let lines: Vec<&str> = line.split('\n').collect();
    assert!(
        lines[0].contains("update: recreate (url,uncovered)"),
        "header must carry the full join(\",\")  payload; got: {}",
        lines[0],
    );
    assert!(
        line.contains("    note: uncovered "),
        "uncovered note must appear; got: {line}",
    );
    assert!(
        !line.contains("note: url "),
        "url is self-explanatory; must NOT emit a note line; got: {line}",
    );
}

/// in-place `UpdateRunner` (no recreate) MUST NOT emit any
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

// ---------- all-recreate-only plan apply-exit pin -----------------

/// Every action recreate-class — `summary.by_disruption.recreate`
/// equals `actions.len()`, `none` and `restart` are zero,
/// `any_recreate` is true. Strengthens the existing
/// `plan_to_json_value_summary_recreates_only_recreate_class_actions`
/// by exercising a 5-action mixed-class-but-all-recreate fixture
/// (`CreateRunner` + UpdateRunner-recreate + `RemoveRunner` +
/// `CreateCachePool` + `RemoveCachePool`) so all five recreate-class
/// variants round-trip through the `by_disruption` counter, not just
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
        keep_versions: 2,
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

// ---------- summary.recreates proptest invariant ------------------

// Strategy: generate an arbitrary Action variant. Each arm
// synthesizes a fresh fixture using the deterministic test
// helpers (`fake_runner_plan`, `fake_identity`,
// `fake_cache_binding`) over a short ASCII identifier so
// the resulting Plan parses cleanly through the renderer.
// The variant distribution is roughly uniform — proptest
// will reduce to the minimum failing input on a regression.
//
// The two UpdateRunner arms are split rather than generated
// from a single bool because the Restart arm must NOT appear
// in `summary.recreates` — pinning separate strategies makes
// the `Action::disruption()` → recreate-list mapping
// load-bearing. A regression that flipped the boundary would
// surface as a count mismatch in invariant 1.

proptest::proptest! {
    /// Cross-field invariant on `plan_summary_value` output.
    /// The function builds `summary.recreates` (Vec<String>) and
    /// `summary.by_disruption.recreate` (u64) from two SEPARATE
    /// passes over `actions` (the production order — collect-then-
    /// count vs count-then-collect — is an implementation detail
    /// the test suite must not encode; both fields share a single
    /// counter today). The proptest generates an arbitrary
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
    ///    `recreates.sort_unstable()` invariant). Catches
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

// ---------- pool-only plan no-runner fixture ----------------------

/// Pool-only plan (zero runner actions). Symmetric guard
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
        keep_versions: 2,
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

// ---------- disruption_summary_variants() exhaustiveness ----------

/// Pin `disruption_summary_variants()` lists every variant of
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

// ---------- FieldValue::List end-to-end JSON round-trip ----------

/// Round-trip `FieldValue::List` through wire-format JSON
/// (`to_string` + `from_str`) and verify the tagged-object shape
/// `{"type":"list","values":[...]}` survives. Strengthens the
/// existing in-memory pin
/// `render_plan_json_update_runner_emits_typed_list_field_value_for_labels`
/// by adding the wire-string round-trip axis — a future change to
/// a non-self-describing serializer (bincode, `serde_cbor`, etc.)
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
        keep_versions: 2,
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

// ---------- apply_exit_code recreate-flag-on no-recreate-out -----

/// `apply_exit_code` with `detailed_exitcode_recreate=true`
/// and a successful apply that produced ZERO recreate-class
/// outcomes must return 0 (not 8). Strengthens existing
/// `apply_exit_code_recreate_flag_without_recreate_outcome_returns_zero`
/// by adding a multi-action mixed-non-recreate fixture
/// (`InPlaceRestarted` + `PoolUpdated` + `NoOp` + `InPlaceSkipped`) so the
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
        apply_exit_code(false, true, &result),
        0,
        "recreate flag on but zero recreate-class outcomes must return 0",
    );
    // Sanity: with detailed flag also ON, falls through to detailed
    // = 2 (since result.details has non-NoOp activity). This pins
    // the `apply_exit_code` fall-through path:
    // `if detailed_exitcode { 2 } else { 0 }`.
    assert_eq!(
        apply_exit_code(true, true, &result),
        2,
        "recreate flag on, no recreate outcomes, detailed flag on ⇒ 2",
    );
}

// ---------- fail_fast=true multi-failure detail-row pin ----------

/// Under `fail_fast=true`, `apply()` short-circuits on the
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
        apply_exit_code(false, false, &result),
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
        apply_exit_code(false, false, &auth_result),
        5,
        "total auth failure under fail_fast must yield exit 5",
    );
}

// ---------- call-site sanitization wiring pins ----------------

/// Pin that the recreate-Removed text path at
/// `render_action_line` actually runs the basename through
/// `escape_control_chars`. Helper-level coverage already lives in
/// `lib.rs` (Cow allocation, `escape_default` semantics); this test
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
/// hijack vector that `escape_control_chars` closes.
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

/// Pin that the recreate-Removed JSON path at
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
        keep_versions: 2,
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
    // (Adversary A2 verification).
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

// ---------- remaining call-site sanitization wiring pins ----------

/// Pin that the IN-PLACE text path in `render_action_line`
/// runs the drop-in basename
/// through `escape_control_chars` before stdout emission.
/// Symmetric with the recreate-Removed text path pin at
/// `render_action_line_recreate_removed_text_path_escapes_hostile_basename`
/// — the recreate path uses `before_drop_in_basenames`; the
/// in-place path iterates `drop_in_changes` (Created / Modified /
/// Removed entries with their per-variant body). Both render
/// sites use the same `escape_control_chars(basename)` form, so
/// a regression in one would not catch a regression in the other.
///
/// Drives `render_action_line` with an in-place `RunnerDelta` whose
/// sole `drop_in_changes` entry has a hostile basename. Asserts
/// (a) raw ESC byte gone, (b) `\u{1b}` escape form present,
/// (c) "hostile.conf" non-control suffix passes through.
#[test]
fn render_action_line_inplace_text_path_escapes_hostile_drop_in_basename() {
    let mut delta = inplace_delta("buckos");
    // Sole drop_in_changes entry — Created variant is the most
    // common in-place mutation (operator added a new drop-in
    // section like `[memory_max]`); the basename loop in
    // `render_action_line`'s in-place text path emits
    // `    + {escape_control_chars(basename)}`.
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

/// Pin that the IN-PLACE JSON path in `drop_in_change_to_json`
/// runs the drop-in basename through `escape_control_chars` before
/// serialization.
/// Symmetric with the recreate-Removed JSON path pin at
/// `plan_to_json_value_recreate_removed_json_path_escapes_hostile_basename`
/// — the recreate path emits an inline `serde_json::json!`
/// wrapper inside `plan_to_json_value`; the in-place path
/// delegates to `drop_in_change_to_json` for each entry in
/// `drop_in_changes`. Two distinct call sites, two distinct
/// pins.
///
/// Drives `plan_to_json_value` (diff=false) with an in-place
/// `RunnerDelta`. The `drop_in_change_to_json` helper is invoked
/// for each `dc` in `d.drop_in_changes` from inside
/// `plan_to_json_value`, and the helper's `obj.insert("basename",
/// escape_control_chars(...))` is the wiring point under test.
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
        keep_versions: 2,
    };
    // diff=false routes through the in-place path's per-entry
    // `d.drop_in_changes.iter().map(...)` inside
    // `plan_to_json_value`, which delegates to
    // `drop_in_change_to_json`. The recreate-Removed path is
    // gated on `requires_recreate=true` and is the entry-point
    // for the existing `*_recreate_*` JSON pin; this test
    // exercises the disjoint in-place branch.
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

/// Pin the COMBINED defense-in-depth chain that
/// scrubs `UndoStep::describe()` output before stderr emission.
/// The chain has two intentionally-redundant layers:
///   1. `describe()` escapes each interpolated field per arm at
///      construction — every `name`, `path`, `url` arm runs
///      `escape_control_chars`.
///   2. `render_rollback_advisory` re-escapes the full
///      `describe()` output before stderr emission via the
///      step-bullet escape inside
///      `render_rollback_advisory`'s rev-walk loop. The second
///      pass is idempotent (pinned in lib.rs) so the
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
/// This test uses a benign label (`"RemoveRunner(buckos)"`)
/// because the dedicated label-escape pin is
/// `render_rollback_advisory_escapes_hostile_label`. Keeping
/// this test focused on the step chain avoids double-coverage
/// and over-constraining a single fixture.
///
/// Drives the renderer with an `ApplyResult` carrying one
/// failure + one `StartUnit` `UndoStep` whose `name` field
/// contains an ESC. Asserts (a) no raw `\x1b` anywhere in the
/// rendered advisory, (b) `\u{1b}` escape form present,
/// (c) header / step bullet structure intact.
#[test]
fn render_rollback_advisory_escapes_hostile_undo_step() {
    let mut result = apply::ApplyResult::default();
    // Hostile UndoStep::StartUnit. Note: describe() ALREADY runs
    // escape_control_chars on `name` in the StartUnit arm. The
    // second pass at the step-bullet escape inside
    // `render_rollback_advisory`'s rev-walk loop is idempotent
    // (pinned in lib.rs). Together they guarantee a
    // future regression in EITHER layer cannot leak ESC bytes
    // to stderr.
    push_failed(
        &mut result,
        "RemoveRunner(buckos)",
        vec![apply::UndoStep::StartUnit {
            name: "ghars-runner@\x1b[31mevil.service".into(),
        }],
    );
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
    // describe()'s `format!("started {}")` StartUnit arm) must
    // both be present, proving the render structure survived
    // the escape pass.
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

// ---------- cli.rs sanitization follow-ups -----------------------

/// pin that `render_rollback_advisory` runs the
/// per-failure label through `escape_control_chars` before
/// stderr emission. Without this escape, the label would be
/// emitted via `format!("\n  {label}:")` without escaping while
/// the per-step bullets in `render_rollback_advisory`'s rev-walk
/// loop ARE already escaped, producing an asymmetry. Today's
/// `IDENTIFIER_REGEX` rejects
/// control chars at config-load, so a hostile label cannot
/// reach this site through normal inputs — but the
/// `failed_undo_logs` key is constructed from `Action::label()`
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
    // Hostile label embedded in the failed_undo_logs key (the
    // renderer keys off the latter).
    let hostile_label = "RemoveRunner(\x1b[31mevil)";
    // Use a benign step so any ESC byte in the rendered output
    // can ONLY have come from the label render path. If the
    // step-bullet escape inside `render_rollback_advisory`'s
    // rev-walk loop were the only defense, this test would
    // still fail until the label escape (the per-failure
    // label-render path inside `render_rollback_advisory`) lands.
    push_failed(
        &mut result,
        hostile_label,
        vec![apply::UndoStep::StopUnit {
            name: "ghars-runner@a.service".into(),
        }],
    );
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

/// (a): pin that `push_indented_body` escapes raw
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

/// (b): pin that `render_drop_in_body_block` for
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

/// (b'): mirror of `Created` test for the
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

/// (c): pin the unified-diff path. Hostile bytes
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

// ---------- render_apply_emission stream-routing tests ---------------
//
// `render_apply_emission` extracts the cmd_apply post-execution
// emission block (per-action loop + summary footer + rollback
// advisory) into a single helper that takes generic `&mut impl
// io::Write` for stdout and stderr. Tests pass `Vec<u8>` capture
// buffers so the stream-routing contract becomes observable
// without a TTY: `noop:` and `ok:` rows plus the summary footer
// route to stdout; `fail:` rows plus the rollback advisory route
// to stderr. These are the smallest pinning tests for the
// contract documented in the helper's doc comment.

/// Drive `render_apply_emission` against fresh stdout/stderr
/// capture buffers and return both as decoded UTF-8 strings.
/// Centralizes the 5-line scaffold (`Vec::new` × 2, render call,
/// `String::from_utf8` × 2) so each test reads as a fixture-build
/// + a single helper call + assertions, not as the same scaffold
/// boilerplate inlined N times. Both `unwrap()` calls are the
/// test contract: writes to a `Vec<u8>` are infallible, and
/// `render_apply_emission` only emits via `writeln!(...,
/// "literal {}", String_typed)` — the literal fragments are
/// ASCII and the interpolated values come from
/// `String`/`&str`-typed inputs (label, `Disruption::label()`,
/// `outcome.detail()`), so the byte stream is valid UTF-8 by
/// construction. A panic from either `unwrap()` is therefore a
/// real regression worth surfacing rather than a contract
/// violation the test should silently tolerate.

/// Successful single-action plan (Created outcome) routes the
/// `ok:` row plus the summary footer to stdout, with stderr
/// completely empty. This is the success-path baseline:
/// the `cmd_apply` output must stay grep-able on stdout when no
/// action failed.
#[test]
fn render_apply_emission_ok_outcome_routes_to_stdout_only() {
    let result = apply::ApplyResult {
        details: vec![("CreateRunner(a)".into(), apply::ApplyOutcome::Created)],
        ..apply::ApplyResult::default()
    };
    let (out, err) = capture_apply_emission(&result);
    assert!(
        out.contains("ok: CreateRunner(a)"),
        "ok: row missing from stdout: {out}"
    );
    assert!(
        out.contains("Apply: 1 applied"),
        "summary footer missing from stdout: {out}"
    );
    assert!(
        err.is_empty(),
        "success path must not write to stderr; got: {err:?}"
    );
}

/// Failed single-action plan routes the `fail:` row to stderr
/// and only the summary footer to stdout. The `fail:` row MUST
/// stay off stdout so a `grep ^fail` pipeline does not falsely
/// match on stdout when stdout is being scraped for `ok:`/`noop:`
/// status. Mirror image of `render_apply_emission_ok_outcome_routes_to_stdout_only`.
#[test]
fn render_apply_emission_failed_outcome_routes_to_stderr() {
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
    let (out, err) = capture_apply_emission(&result);
    assert!(
        err.contains("fail: CreateRunner(a)"),
        "fail: row missing from stderr: {err}"
    );
    assert!(
        !out.contains("fail:"),
        "fail: row must NOT leak to stdout; got: {out}"
    );
    assert!(
        out.contains("Apply: 0 applied, 1 failed"),
        "summary footer missing from stdout: {out}"
    );
}

/// `NoOp` action emits the special `noop: REASON [none]` line
/// (label-strip collapses `NoOp(REASON)` into bare `REASON`)
/// and routes to stdout. Pins both:
/// (a) the strip-prefix/strip-suffix branch that converts
///     `NoOp(idempotent)` → `idempotent`, and
/// (b) the stream routing — `NoOp` goes to stdout, never stderr.
#[test]
fn render_apply_emission_noop_strips_label_prefix_and_routes_to_stdout() {
    let result = apply::ApplyResult {
        details: vec![("NoOp(idempotent)".into(), apply::ApplyOutcome::NoOp)],
        ..apply::ApplyResult::default()
    };
    let (out, err) = capture_apply_emission(&result);
    assert!(
        out.contains("noop: idempotent [none]"),
        "expected `noop: idempotent [none]` (label-strip applied); got: {out}",
    );
    assert!(
        !out.contains("noop: NoOp(idempotent)"),
        "label prefix must be stripped, not preserved; got: {out}",
    );
    assert!(err.is_empty(), "noop must not touch stderr; got: {err:?}");
}

/// Pins the `unwrap_or` fallback in the `NoOp` arm: when the label
/// does NOT have the `NoOp(...)` prefix wrapper (e.g. a synthetic
/// fixture or future label-shape evolution that supplies a bare
/// reason), the helper renders the label verbatim as the reason.
/// This guards the strip-prefix/strip-suffix chain — if a future
/// refactor replaces `unwrap_or(label.as_str())` with `unwrap()`,
/// this test traps the panic.
#[test]
fn render_apply_emission_noop_without_wrapper_renders_label_verbatim() {
    let result = apply::ApplyResult {
        details: vec![("literal-no-wrapper".into(), apply::ApplyOutcome::NoOp)],
        ..apply::ApplyResult::default()
    };
    let (out, _err) = capture_apply_emission(&result);
    assert!(
        out.contains("noop: literal-no-wrapper [none]"),
        "expected `noop: literal-no-wrapper [none]` (unwrap_or fallback applied); got: {out}",
    );
}

/// `DryRunSkipped` is one of the non-NoOp non-Failed
/// `ApplyOutcome` variants and must route to stdout via its
/// explicit `DryRunSkipped` arm (one branch of the merged
/// success/skip `|`-chain) without falsely matching the
/// `Failed` or `NoOp` arms.
#[test]
fn render_apply_emission_dry_run_skipped_routes_to_stdout() {
    let result = apply::ApplyResult {
        details: vec![("CreateRunner(a)".into(), apply::ApplyOutcome::DryRunSkipped)],
        ..apply::ApplyResult::default()
    };
    let (out, err) = capture_apply_emission(&result);
    assert!(
        out.contains("ok: CreateRunner(a)"),
        "DryRunSkipped renders as `ok:` row on stdout; got: {out}",
    );
    assert!(
        out.contains("dry-run"),
        "DryRunSkipped detail() emits 'dry-run'; got: {out}",
    );
    assert!(err.is_empty(), "stderr must stay empty; got: {err:?}");
}

/// Mixed plan: one `ok:` row AND one `fail:` row. The two streams
/// must split cleanly — `ok:` on stdout, `fail:` on stderr, with
/// neither leaking to the other side. Stronger than the single-
/// outcome tests above because it demonstrates per-action arm
/// dispatch rather than just a single-arm walk.
#[test]
fn render_apply_emission_mixed_outcomes_split_cleanly_across_streams() {
    let result = apply::ApplyResult {
        details: vec![
            ("CreateRunner(a)".into(), apply::ApplyOutcome::Created),
            (
                "RemoveRunner(b)".into(),
                apply::ApplyOutcome::Failed {
                    error_summary: "systemd: stop failed".into(),
                    plan_disruption: plan::Disruption::Recreate,
                },
            ),
        ],
        ..apply::ApplyResult::default()
    };
    let (out, err) = capture_apply_emission(&result);
    // Stdout has the ok row + footer, NOT the fail row.
    assert!(out.contains("ok: CreateRunner(a)"), "ok row: {out}");
    assert!(out.contains("Apply: 1 applied, 1 failed"), "footer: {out}");
    assert!(
        !out.contains("fail: RemoveRunner(b)"),
        "fail row leaked to stdout: {out}",
    );
    // Stderr has the fail row, NOT the ok row.
    assert!(
        err.contains("fail: RemoveRunner(b)"),
        "fail row missing from stderr: {err}",
    );
    assert!(
        !err.contains("ok: CreateRunner(a)"),
        "ok row leaked to stderr: {err}",
    );
}

/// When `result.failed_undo_logs` has at least one non-empty
/// step list, `render_rollback_advisory` returns Some(advisory)
/// and the helper emits it to STDERR. Pins:
/// (a) the advisory reaches stderr (not stdout);
/// (b) the `fail:` row also reaches stderr — both fail-class
///     emissions consolidate on the error stream.
#[test]
fn render_apply_emission_advisory_routes_to_stderr() {
    let mut result = apply::ApplyResult {
        details: vec![(
            "CreateCachePool(a)".into(),
            apply::ApplyOutcome::Failed {
                error_summary: "systemd: enable_unit failed".into(),
                plan_disruption: plan::Disruption::Recreate,
            },
        )],
        ..apply::ApplyResult::default()
    };
    push_failed(
        &mut result,
        "CreateCachePool(a)",
        vec![apply::UndoStep::CreateDir {
            path: Utf8PathBuf::from("/etc/systemd/system/ghars-cache@a.service.d"),
        }],
    );
    let (out, err) = capture_apply_emission(&result);
    assert!(
        err.contains("Rollback advisory"),
        "advisory missing from stderr: {err}",
    );
    assert!(
        err.contains("CreateCachePool(a)"),
        "advisory must list failed-action label: {err}",
    );
    // Load-bearing label-twice pin: a single `err.contains(label)`
    // would pass even if the advisory body omitted the label,
    // because the per-action `fail:` row already prints the label
    // on stderr (per `render_apply_emission`'s Failed-arm
    // routing). The advisory body independently contains the
    // label as a per-action sub-block header (`  LABEL:`) — so
    // the label MUST appear at least twice on stderr: once from
    // the `fail:` row, once from the advisory body. This pin
    // catches a regression that drops the advisory body's label
    // line while leaving the header.
    let label_count = err.matches("CreateCachePool(a)").count();
    assert!(
        label_count >= 2,
        "label must appear at least twice on stderr (fail: row + \
         advisory body); got {label_count} occurrence(s): {err}",
    );
    assert!(
        err.contains("created directory"),
        "advisory body must include step description: {err}",
    );
    assert!(
        !out.contains("Rollback advisory"),
        "advisory leaked to stdout: {out}",
    );
    // Footer still on stdout.
    assert!(
        out.contains("Apply: 0 applied, 1 failed"),
        "footer missing from stdout: {out}",
    );
    // Symmetric cross-stream negative pin: footer must NOT appear on stderr.
    assert!(!err.contains("Apply:"), "footer must NOT appear on stderr");
}

/// When `failed_undo_logs` is empty (no failures at all),
/// `render_rollback_advisory` returns None and the helper emits
/// no advisory line. Pins the negative case: a successful apply
/// produces no advisory noise on stderr.
#[test]
fn render_apply_emission_no_advisory_when_no_failures() {
    let result = apply::ApplyResult {
        details: vec![("CreateRunner(a)".into(), apply::ApplyOutcome::Created)],
        ..apply::ApplyResult::default()
    };
    let (_out, err) = capture_apply_emission(&result);
    assert!(
        !err.contains("Rollback advisory"),
        "no advisory expected on success: {err}",
    );
}

/// Pins the `render_apply_summary_line` footer routes to stdout
/// (not stderr) for a single-Created fixture. `err.is_empty()` is
/// the strongest inverse pin: any leak — footer or otherwise —
/// fails.
#[test]
fn render_apply_emission_footer_routes_to_stdout() {
    let result = apply::ApplyResult {
        details: vec![("CreateRunner(a)".into(), apply::ApplyOutcome::Created)],
        ..apply::ApplyResult::default()
    };
    let (out, err) = capture_apply_emission(&result);
    assert!(
        out.contains("Apply: 1 applied"),
        "summary footer missing from stdout: {out}",
    );
    assert!(
        err.is_empty(),
        "stderr must be empty for single-Created fixture: {err}",
    );
}

/// Line-oriented position pin for the rollback advisory: on stderr
/// the per-action `fail:` row MUST precede the advisory header,
/// which MUST precede the per-action body sub-block. The sibling
/// test `render_apply_emission_advisory_routes_to_stderr` (same
/// fixture) pins counts (`label_count >= 2`) but not relative
/// position; a regression that flipped the emission order so the
/// advisory printed before the per-action loop, or interleaved
/// the body sub-block above the advisory header, would still
/// satisfy the count assertion. This test catches that drift by
/// comparing line indices via `position()`.
#[test]
fn render_apply_emission_advisory_label_line_position_pin() {
    let mut result = apply::ApplyResult {
        details: vec![(
            "CreateCachePool(a)".into(),
            apply::ApplyOutcome::Failed {
                error_summary: "systemd: enable_unit failed".into(),
                plan_disruption: plan::Disruption::Recreate,
            },
        )],
        ..apply::ApplyResult::default()
    };
    push_failed(
        &mut result,
        "CreateCachePool(a)",
        vec![apply::UndoStep::CreateDir {
            path: Utf8PathBuf::from("/etc/systemd/system/ghars-cache@a.service.d"),
        }],
    );
    let (_out, err) = capture_apply_emission(&result);
    let lines: Vec<&str> = err.lines().collect();
    let fail_line_idx = lines
        .iter()
        .position(|l| l.starts_with("fail: CreateCachePool(a) ["))
        .unwrap_or_else(|| panic!("fail row missing from stderr: {err}"));
    let advisory_header_idx = lines
        .iter()
        .position(|l| l.starts_with("Rollback advisory:"))
        .unwrap_or_else(|| panic!("advisory header missing from stderr: {err}"));
    let label_subblock_idx = lines
        .iter()
        .position(|l| *l == "  CreateCachePool(a):")
        .unwrap_or_else(|| panic!("advisory body sub-block header missing from stderr: {err}"));
    assert!(
        fail_line_idx < advisory_header_idx,
        "fail row must precede advisory header (fail={fail_line_idx}, header={advisory_header_idx}): {err}",
    );
    assert!(
        advisory_header_idx < label_subblock_idx,
        "advisory header must precede body sub-block (header={advisory_header_idx}, body={label_subblock_idx}): {err}",
    );
}

/// Prefix-collision pin: full-line exact-equality format
/// correctness across two labels that share a common prefix
/// (`CreateCachePool(a` is a prefix of `CreateCachePool(ab`).
/// The full labels are NOT in a strict substring relationship —
/// the closing `)` in the shorter label diverges from `b` at the
/// same position in the longer — but the shared prefix means any
/// substring-based check that gets applied to a renderer-derived
/// fragment (e.g. searching for `"  CreateCachePool(a"` if a
/// future regression drops the trailing `:` from the body
/// sub-block header, or for `"fail: CreateCachePool(a "` if a
/// regression drops the `[` bracket-tag prefix from the fail
/// row) folds the shorter into the longer and overcounts.
///
/// Exact-line equality (`lines.iter().filter(|l| **l ==
/// "...").count() == 1`) is strictly stronger than any
/// `contains()` or `matches().count()` shape: it resolves the
/// two labels independently regardless of what punctuation the
/// surrounding format carries, because the full line bytes
/// (including the closing `)` and the trailing `]` / `:` /
/// `(...)` produced by the production renderer) must match
/// exactly.
///
/// This test fails loudly if a future renderer change drops the
/// trailing `:` after the body sub-block label, or drops the
/// bracket tag / detail parenthetical from the fail row, because
/// the assertion's exact-line literal would no longer appear on
/// any single line.
#[test]
fn render_apply_emission_advisory_label_substring_collision_safe() {
    let mut result = apply::ApplyResult {
        details: vec![
            (
                "CreateCachePool(a)".into(),
                apply::ApplyOutcome::Failed {
                    error_summary: "fail-a".into(),
                    plan_disruption: plan::Disruption::Recreate,
                },
            ),
            (
                "CreateCachePool(ab)".into(),
                apply::ApplyOutcome::Failed {
                    error_summary: "fail-ab".into(),
                    plan_disruption: plan::Disruption::Recreate,
                },
            ),
        ],
        ..apply::ApplyResult::default()
    };
    push_failed(
        &mut result,
        "CreateCachePool(a)",
        vec![apply::UndoStep::CreateDir {
            path: Utf8PathBuf::from("/etc/systemd/system/ghars-cache@a.service.d"),
        }],
    );
    push_failed(
        &mut result,
        "CreateCachePool(ab)",
        vec![apply::UndoStep::CreateDir {
            path: Utf8PathBuf::from("/etc/systemd/system/ghars-cache@ab.service.d"),
        }],
    );
    let (_out, err) = capture_apply_emission(&result);
    let lines: Vec<&str> = err.lines().collect();
    assert_eq!(
        lines
            .iter()
            .filter(|l| **l == "fail: CreateCachePool(a) [recreate] (fail-a)")
            .count(),
        1,
        "exact fail row for (a) must appear exactly once: {err}",
    );
    assert_eq!(
        lines
            .iter()
            .filter(|l| **l == "fail: CreateCachePool(ab) [recreate] (fail-ab)")
            .count(),
        1,
        "exact fail row for (ab) must appear exactly once: {err}",
    );
    assert_eq!(
        lines
            .iter()
            .filter(|l| **l == "  CreateCachePool(a):")
            .count(),
        1,
        "advisory body sub-block for (a) must appear exactly once: {err}",
    );
    assert_eq!(
        lines
            .iter()
            .filter(|l| **l == "  CreateCachePool(ab):")
            .count(),
        1,
        "advisory body sub-block for (ab) must appear exactly once: {err}",
    );
    assert!(
        err.contains("Rollback advisory: 2 action(s) failed."),
        "advisory header N must equal 2: {err}",
    );
}
