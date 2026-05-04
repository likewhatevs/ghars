//! Test chunk - co-located with cli/ submodules. See tests/mod.rs for fixture sharing rationale.
#![allow(clippy::unwrap_used)]

use super::*;


/// Recreate-class UpdateRunner must use the `!` sigil.
/// In-place UpdateRunner keeps `~`. Both header lines still
/// terminate with the `[recreate]`/`[restart]` bracket tag from
/// the disruption tag, but the column-0 sigil is the fast-scan signal that
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
    // Hash changed AND drift detected → combined label.
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

// ---------- Action::disruption() per variant -------------------

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
    // Plan-time worst-case (apply-time None short-circuit is
    // byte-equality-driven and not plan-visible).
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
    // Pin the JSON / text-mode label vocabulary
    // so a future refactor that touches Disruption::label()
    // cannot silently rename the tokens CI consumers grep on.
    assert_eq!(plan::Disruption::None.label(), "none");
    assert_eq!(plan::Disruption::Restart.label(), "restart");
    assert_eq!(plan::Disruption::Recreate.label(), "recreate");
}

/// Defense-in-depth invariant pin: every `Disruption::label()`
/// output must be free of `,`, `(`, and `)`. Those three
/// characters are STRUCTURAL in `format_disruption_tail`'s
/// `(N restart, N recreate, N none)` parenthetical — a label
/// that contained any of them would render an unparseable
/// summary line that scripted CI parsers cannot tokenize.
/// The vocabulary is pinned by `disruption_labels_are_snake_case_stable`
/// today, but a future contributor adding a new variant
/// (e.g. `Disruption::DnsRotate`) and reaching for a
/// human-friendly label like `dns(rotate)` would silently
/// break operator log parsing. The exhaustive iteration via
/// `disruption_summary_variants()` covers every variant
/// (pinned exhaustive by
/// `disruption_summary_variants_contains_all_disruption_variants`),
/// so adding a variant without updating that helper fails
/// compilation upstream of this test.
#[test]
fn disruption_labels_contain_no_parens_or_comma() {
    for variant in disruption_summary_variants() {
        let label = variant.label();
        assert!(
            !label.is_empty(),
            "Disruption::{variant:?}::label() must be non-empty; got empty string"
        );
        assert!(
            label.chars().all(|c| !",()".contains(c)),
            "Disruption::{variant:?}::label() = {label:?} contains a forbidden \
             char (one of `,`, `(`, `)`); these are structural in \
             format_disruption_tail's `(N restart, N recreate, N none)` \
             parenthetical and would break operator log parsing"
        );
    }
}

#[test]
fn disruption_ordering_is_least_to_most() {
    // Pin the derived PartialOrd/Ord ordering so
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
    // Pin that every label token in the text
    // footer comes from `Disruption::label()`, not from a
    // hardcoded string literal in the format string. If a
    // future refactor inlines the label strings (regressing
    // the helper extraction), the substring assertions below
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

// ---------- render_apply_summary_line ---------------------------

/// Empty result emits zeroed footer with `any_recreate: false`.
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

/// Every outcome class lands in the right bucket.
/// `applied` covers Created/Removed/Recreated/InPlaceRestarted/
/// PoolCreated/PoolUpdated/PoolRemoved; `skipped` covers NoOp,
/// DryRunSkipped, InPlaceSkipped, PoolSkipped; `failed` covers
/// ApplyOutcome::Failed. The disruption parenthetical mirrors
/// each outcome's `disruption()` mapping (verified against
/// `apply::ApplyOutcome::disruption`).
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

/// `any_recreate` is true when ANY row's disruption is
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

/// Empty result (no failures) ⇒ no advisory rendered.
/// Pins that successful applies emit zero stderr advisory noise.
/// The gate counts non-empty step lists in `failed_undo_logs`;
/// a default `ApplyResult` (empty `failed_undo_logs`) yields
/// `n == 0`, returning `None`.
#[test]
fn render_rollback_advisory_returns_none_on_success() {
    let result = apply::ApplyResult::default();
    assert!(render_rollback_advisory(&result).is_none());
}

/// Header + per-action body + per-step bullet list.
/// Pins the exact rendering format so operators with downstream
/// parsers see a stable contract. Header counts entries in
/// `failed_undo_logs` with non-empty steps.
#[test]
fn render_rollback_advisory_renders_per_action_steps() {
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
        ],
    );
    let advisory = render_rollback_advisory(&result).unwrap();
    // Header: count of failed actions with cleanup steps,
    // "Manual cleanup may be required:".
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
}

/// The synthetic `daemon_reload` post-loop
/// failure has an empty UndoLog (no per-action mutation manifest).
/// The advisory renderer skips per-action blocks whose step list
/// is empty AND counts ONLY non-empty entries in the header N
/// so header count matches body block count under the
/// MIXED case (empty + non-empty side by side). The ISOLATED
/// all-empty case is pinned by
/// `render_rollback_advisory_daemon_reload_only_failure_returns_none`
/// (returns `None` instead of header-only output).
#[test]
fn render_rollback_advisory_skips_empty_step_lists() {
    // Mixed: one daemon_reload (empty) + one real failure with steps.
    let mut result = apply::ApplyResult::default();
    push_failed(&mut result, "daemon_reload", Vec::new());
    push_failed(
        &mut result,
        "RemoveRunner(orphan)",
        vec![apply::UndoStep::StopUnit {
            name: "ghars-runner@orphan.service".into(),
        }],
    );
    let advisory = render_rollback_advisory(&result).unwrap();
    // Header counts ONLY non-empty entries (1 here: the
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

/// Prefix-collision pin: full-line exact-equality format
/// correctness across two `CreateDir` step bullets whose paths
/// share a common prefix (`ghars-cache@a` is a prefix of
/// `ghars-cache@ab`). The full bullet lines are NOT in a strict
/// substring relationship — the `.` after `a` in
/// `.service.d` diverges from the `b` at the same position in
/// the longer path — but the shared path prefix means any
/// substring-based check that gets applied to a renderer-derived
/// fragment (e.g. searching for `"    - created directory
/// /etc/systemd/system/ghars-cache@a"` if a future regression
/// drops or shortens the trailing `.service.d` suffix from the
/// describe() output) folds the shorter into the longer and
/// overcounts.
///
/// Exact-line equality (`lines().filter(|l| *l ==
/// "...").count() == 1`) is strictly stronger than any
/// `contains()` or `matches().count()` shape: it resolves the
/// two bullets independently regardless of what punctuation the
/// surrounding format carries, because the full line bytes
/// (including the trailing `.service.d` suffix produced by
/// `describe()`'s `format!("created directory {}")` arm) must
/// match exactly.
///
/// This test fails loudly if a future renderer change joins
/// bullets onto the same line, loses the `\n` separator, drops
/// the trailing path suffix, or duplicates a line — any of these
/// regressions shifts at least one exact-line count off 1.
#[test]
fn render_rollback_advisory_step_bullets_disambiguate_prefix_paths() {
    let mut result = apply::ApplyResult::default();
    push_failed(
        &mut result,
        "CreateCachePool(a)",
        vec![
            apply::UndoStep::CreateDir {
                path: camino::Utf8PathBuf::from(
                    "/etc/systemd/system/ghars-cache@a.service.d",
                ),
            },
            apply::UndoStep::CreateDir {
                path: camino::Utf8PathBuf::from(
                    "/etc/systemd/system/ghars-cache@ab.service.d",
                ),
            },
        ],
    );
    let advisory = render_rollback_advisory(&result).unwrap();
    // Exact-line equality count for each bullet. Each filter
    // matches the full rendered line bytes (4-space indent +
    // `- created directory ` prefix + path + trailing
    // `.service.d` suffix), so a future regression that
    // shortens, joins, or duplicates a bullet shifts the count
    // off 1.
    let short_bullet =
        "    - created directory /etc/systemd/system/ghars-cache@a.service.d";
    let long_bullet =
        "    - created directory /etc/systemd/system/ghars-cache@ab.service.d";
    let short_count = advisory.lines().filter(|l| *l == short_bullet).count();
    let long_count = advisory.lines().filter(|l| *l == long_bullet).count();
    assert_eq!(
        short_count, 1,
        "short-path bullet must appear exactly once; got: {advisory}",
    );
    assert_eq!(
        long_count, 1,
        "long-path bullet must appear exactly once; got: {advisory}",
    );
}

/// 3-element transitivity sibling: extends the 2-bullet pin with
/// a third path so the prefix relationship is transitive
/// (`a` ⊂ `ab` ⊂ `abc` as path prefixes). The 2-element variant
/// proves only that `a` doesn't fold into `ab`; the 3-element
/// variant additionally proves that `a` doesn't fold into `abc`
/// AND `ab` doesn't fold into `abc` AND `a` is independent of
/// `abc`.
///
/// This catches a future renderer regression that shortens or
/// drops the trailing `.service.d` suffix from `describe()`'s
/// `format!("created directory {}")` arm: in the 2-element
/// variant a single drop only collapses `a` into `ab`; in the
/// 3-element variant the same drop produces 3 collapses
/// (`a` ⊂ `ab`, `a` ⊂ `abc`, `ab` ⊂ `abc`), so any of three
/// independent `count == 1` assertions falsifies. The wider
/// falsification surface tightens the pin against partial
/// regressions where only one collapse path lands.
///
/// Exact-line equality remains the resolution mechanism — each
/// of the three full bullet lines must appear exactly once in
/// the rendered advisory.
#[test]
fn render_rollback_advisory_step_bullets_disambiguate_three_transitive_prefix_paths() {
    let mut result = apply::ApplyResult::default();
    push_failed(
        &mut result,
        "CreateCachePool(a)",
        vec![
            apply::UndoStep::CreateDir {
                path: camino::Utf8PathBuf::from(
                    "/etc/systemd/system/ghars-cache@a.service.d",
                ),
            },
            apply::UndoStep::CreateDir {
                path: camino::Utf8PathBuf::from(
                    "/etc/systemd/system/ghars-cache@ab.service.d",
                ),
            },
            apply::UndoStep::CreateDir {
                path: camino::Utf8PathBuf::from(
                    "/etc/systemd/system/ghars-cache@abc.service.d",
                ),
            },
        ],
    );
    let advisory = render_rollback_advisory(&result).unwrap();
    let bullet_a =
        "    - created directory /etc/systemd/system/ghars-cache@a.service.d";
    let bullet_ab =
        "    - created directory /etc/systemd/system/ghars-cache@ab.service.d";
    let bullet_abc =
        "    - created directory /etc/systemd/system/ghars-cache@abc.service.d";
    let count_a = advisory.lines().filter(|l| *l == bullet_a).count();
    let count_ab = advisory.lines().filter(|l| *l == bullet_ab).count();
    let count_abc = advisory.lines().filter(|l| *l == bullet_abc).count();
    assert_eq!(
        count_a, 1,
        "shortest-path bullet (a) must appear exactly once; got: {advisory}",
    );
    assert_eq!(
        count_ab, 1,
        "middle-path bullet (ab) must appear exactly once; got: {advisory}",
    );
    assert_eq!(
        count_abc, 1,
        "longest-path bullet (abc) must appear exactly once; got: {advisory}",
    );
}

/// Only-skipped path (dry-run). Every action skipped via
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

// ---------- disruption tag in render_action_line --------------

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

// ---------- --diff body payload (text) ------------------------

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
    // Preserved suppressed without --diff.
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
    // Without --diff, recreate output omits drop-in body
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

// ---- recreate `--diff` shows removed drop-ins ---------------------

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
    // Created lines still render (existing --diff body behavior).
    assert!(line.contains("    + 00-ghars.conf"), "got: {line}");
    // No Removed lines — `None` is "unknown pre-state", suppressed.
    assert!(
        !line.contains("    - "),
        "no Removed sigil expected when before_drop_in_basenames is None, got: {line}"
    );
}

/// COV-1: recreate `--diff` with multiple removed basenames
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

/// COV-2: recreate `--diff` with `before_drop_in_basenames =
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
/// `before` body field — basename-only signal.
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
        keep_versions: 2,
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
    // (basename-only signal).
    assert!(
        removed.get("before").is_none(),
        "recreate-path Removed must NOT carry a `before` body, got: {removed:?}"
    );
    // Explicit `body_suppressed: true` marker so JSON
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
        keep_versions: 2,
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

// ---------- JSON disruption + diff payload --------------------

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
        keep_versions: 2,
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
    // The all-variants test above covers in-place
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
        keep_versions: 2,
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
        keep_versions: 2,
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
        keep_versions: 2,
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
        keep_versions: 2,
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
        keep_versions: 2,
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
        keep_versions: 2,
    };
    let body = plan_to_json_value(&plan, true);
    let entries = body["actions"][0]["drop_in_changes"].as_array().unwrap();
    assert_eq!(entries.len(), 2);
    // BTreeMap iteration is alphabetical, so 00 < 10.
    assert_eq!(entries[0]["basename"], "00-ghars.conf");
    assert_eq!(entries[0]["change_kind"], "created");
    assert!(
        entries[0]["after"]
            .as_str()
            .unwrap()
            .contains("X-Ghars-Spec-Hash")
    );
    assert_eq!(entries[1]["basename"], "10-memory.conf");
    assert_eq!(entries[1]["change_kind"], "created");
    assert!(
        entries[1]["after"]
            .as_str()
            .unwrap()
            .contains("MemoryMax=4G")
    );

    // Without --diff: backward-compat empty array.
    let body = plan_to_json_value(&plan, false);
    let entries = body["actions"][0]["drop_in_changes"].as_array().unwrap();
    assert!(
        entries.is_empty(),
        "no-diff recreate must keep array empty: {entries:?}"
    );
}

// ---------- D-6 addendum: schema_version ---------------------

#[test]
fn plan_to_json_value_emits_schema_version_at_top_level() {
    // Top-level `schema_version` is a forward-compat hook for
    // CI consumers. Set to `"2"` because
    // FieldChange.before/after are tagged FieldValue objects;
    // any future shape change that breaks v2 consumers requires
    // another bump and CHANGELOG/devadv re-review.
    let plan = Plan {
        actions: vec![Action::NoOp("a: in sync".into())],
        warnings: vec![],
        keep_versions: 2,
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
        keep_versions: 2,
    };
    let body = plan_to_json_value(&plan, false);
    assert_eq!(body["schema_version"], "2");
    assert_eq!(body["summary"]["total_actions"], 0);
    assert_eq!(body["summary"]["any_recreate"], false);
    assert_eq!(body["summary"]["by_disruption"]["none"], 0);
    assert_eq!(body["summary"]["by_disruption"]["restart"], 0);
    assert_eq!(body["summary"]["by_disruption"]["recreate"], 0);
}

// ---------- D-7 addendum: summary ----------------------------

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
        keep_versions: 2,
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
        keep_versions: 2,
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
        keep_versions: 2,
    };
    let body = plan_to_json_value(&plan, false);
    assert_eq!(body["summary"]["any_recreate"], true);
    assert_eq!(body["summary"]["by_disruption"]["recreate"], 1);
}

// ---------- summary.recreates --------------------------------

/// Empty plan must still emit `recreates: []` as a key
/// (stable shape so CI consumers can `jq '.summary.recreates |
/// length'` without conditional checks for key presence).
#[test]
fn plan_to_json_value_summary_recreates_empty_when_no_actions() {
    let plan = Plan {
        actions: vec![],
        warnings: vec![],
        keep_versions: 2,
    };
    let body = plan_to_json_value(&plan, false);
    assert_eq!(
        body["summary"]["recreates"],
        serde_json::json!([] as [&str; 0]),
        "empty plan must emit recreates: []",
    );
}

/// Every recreate-class action lands in `recreates` and the
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
        keep_versions: 2,
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
    // Structural pin: post-refactor,
    // by_disruption["recreate"] is sourced from `recreates.len()`
    // inside `plan_summary_value`, so the two fields cannot
    // diverge on input — they share a single counter. Asserting
    // equality here pins the source-shared invariant against a
    // future refactor that re-splits the count from the Vec.
    assert_eq!(
        body["summary"]["by_disruption"]["recreate"],
        serde_json::json!(actual.len()),
        "summary.recreates length must equal summary.by_disruption.recreate (shared counter)",
    );
    assert_eq!(body["summary"]["any_recreate"], true);
}

/// Restart-only + noop plan reports `recreates: []` even
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
        keep_versions: 2,
    };
    let body = plan_to_json_value(&plan, false);
    assert_eq!(
        body["summary"]["recreates"],
        serde_json::json!([] as [&str; 0]),
        "no-recreate plan must emit recreates: []",
    );
    assert_eq!(body["summary"]["any_recreate"], false);
}

/// Cross-type entity-name collision contract.
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
        keep_versions: 2,
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

/// `recreates` is `--diff`-independent.
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
        keep_versions: 2,
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

/// All-recreate-only plan boundary pin.
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
        keep_versions: 2,
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

/// Pool-only plan pin.
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
        keep_versions: 2,
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

/// End-to-end pin: a count-expanded `[[runner]]` config with no
/// discovered runners produces N CreateRunner actions, and every
/// expanded label appears in `summary.recreates` (sorted).
/// Closes the integration gap between the count expansion at
/// `plan::expand_counts` and the recreate listing at
/// `plan_summary_value`.
///
/// Existing summary.recreates tests synthesize Action vectors
/// directly; this test threads through the real plan pipeline:
/// build a Config with `count = 3`, run `plan_from`, then call
/// `plan_summary_value` on the resulting Vec<Action>. The
/// composition has been the load-bearing operator path
/// (`ghars plan --json | jq '.summary.recreates'`) since the
/// recreates field landed; this test pins the e2e contract so a
/// regression at any stage (expand_counts, plan_from's CreateRunner
/// emission, summary_value's recreate filter) surfaces here.
///
/// **Count-fixture choice**: count=3 is chosen so single-digit
/// naming keeps lex-order coincident with natural-order
/// (`ci-1, ci-2, ci-3`). For count >= 10 lex-sort produces
/// `ci-1, ci-10, ci-2, ...` — operator-confusing but contractually
/// correct (sort_unstable on `Vec<String>` is byte-wise). The
/// count=0 + discovered-runner shape is pinned by the sibling
/// `plan_from_count_zero_with_discovered_runner_emits_remove_in_summary_recreates`
/// test below.
///
/// Asserts:
/// - `summary.total_actions == 3` — fan-out arity.
/// - `summary.recreates == ["CreateRunner(ci-1)", "CreateRunner(ci-2)",
///   "CreateRunner(ci-3)"]` (sorted by Action::label, which is
///   what plan_summary_value emits).
/// - `summary.by_disruption["recreate"] == 3`.
/// - `summary.any_recreate == true`.
#[test]
fn plan_from_count_expanded_recreate_class_lists_all_in_summary_recreates() {
    // Build a config with `[[runner]] name = "ci" count = 3`. Use
    // the existing trust_zone fixture as a base, then promote it
    // to a count block.
    let mut cfg = cfg_with_runner_trust_zone("ci", "default".into());
    cfg.runners[0].count = Some(3);

    // No discovered runners ⇒ all 3 expanded names emit
    // CreateRunner.
    let actual = state::ActualState::default();
    let paths = Paths::default();

    let plan =
        plan::plan_from(&cfg, &actual, &paths).expect("count-expanded plan_from must succeed");

    // Sanity: 3 CreateRunner actions, no UpdateRunner / RemoveRunner.
    let create_count = plan
        .actions
        .iter()
        .filter(|a| matches!(a, Action::CreateRunner(_)))
        .count();
    assert_eq!(
        create_count,
        3,
        "count = 3 with no discovered must emit 3 CreateRunner actions; \
         got {} actions: {:?}",
        plan.actions.len(),
        plan.actions
            .iter()
            .map(|a| format!("{a:?}"))
            .collect::<Vec<_>>(),
    );

    let body = plan_to_json_value(&plan, false);
    assert_eq!(
        body["summary"]["total_actions"], 3,
        "count-expansion fan-out: count=3 must produce 3 actions in \
         total_actions",
    );
    let recreates = body["summary"]["recreates"].as_array().unwrap();
    let actual_labels: Vec<&str> = recreates.iter().map(|v| v.as_str().unwrap()).collect();
    assert_eq!(
        actual_labels,
        vec![
            "CreateRunner(ci-1)",
            "CreateRunner(ci-2)",
            "CreateRunner(ci-3)",
        ],
        "summary.recreates must list every count-expanded CreateRunner \
         label; sort is plan_summary_value's sort_unstable() pass over \
         Action::label() output (byte-wise lex; coincides with \
         operator-readable alphabetical for ci-1/ci-2/ci-3).",
    );
    assert_eq!(
        body["summary"]["by_disruption"]["recreate"], 3,
        "by_disruption.recreate count must equal recreates.len() — \
         plan_summary_value sources both fields from the same Vec",
    );
    assert_eq!(body["summary"]["any_recreate"], true);
}

/// Count >= 10 sibling pin: byte-wise lex-sort produces
/// `ci-1, ci-10, ci-11, ci-12, ci-2, ...` rather than natural-order
/// `ci-1, ci-2, ..., ci-9, ci-10, ci-11, ci-12`. This is the
/// contractually-correct behavior of `Vec::<String>::sort_unstable`
/// (a byte-wise lex comparison defined by `<str as Ord>`); the
/// count=3 sibling above only exercises the digit-coincident regime
/// where lex order matches natural order. This test pins the
/// regime where they DIVERGE so a future change that introduces
/// natural-order sorting (e.g. `recreates.sort_by_key(|s|
/// natural_key(s))`) must update this expectation explicitly
/// rather than landing as a silent operator-visible reorder.
///
/// **Byte-wise derivation**: every label has the common prefix
/// `CreateRunner(ci-`. The first divergent byte across the 12
/// labels is at offset 16 (the first character of the index). For
/// names whose index begins with `1` (`ci-1`, `ci-10`, `ci-11`,
/// `ci-12`), the next position decides the ordering: `)` (0x29) <
/// `0` (0x30) < `1` (0x31) < `2` (0x32), giving
/// `ci-1` < `ci-10` < `ci-11` < `ci-12`. Names with first byte
/// `2..=9` (`ci-2` through `ci-9`) all sort AFTER the `1`-prefix
/// cluster because `2` (0x32) > `1` (0x31).
///
/// **Choice of count=12**: smallest count that exercises BOTH the
/// `1?`-prefix cluster (ci-10, ci-11, ci-12) AND single-digit
/// names that sort after it (ci-2..ci-9), proving the divergence
/// across the full 1-prefix vs 2-prefix boundary rather than just
/// the ci-1/ci-10 transition.
#[test]
fn plan_from_count_expanded_double_digit_summary_recreates_byte_wise_lex_sorted() {
    let mut cfg = cfg_with_runner_trust_zone("ci", "default".into());
    cfg.runners[0].count = Some(12);

    let actual = state::ActualState::default();
    let paths = Paths::default();

    let plan = plan::plan_from(&cfg, &actual, &paths)
        .expect("count=12 plan_from must succeed");

    let create_count = plan
        .actions
        .iter()
        .filter(|a| matches!(a, Action::CreateRunner(_)))
        .count();
    assert_eq!(
        create_count, 12,
        "count = 12 with no discovered must emit 12 CreateRunner actions",
    );

    let body = plan_to_json_value(&plan, false);
    assert_eq!(body["summary"]["total_actions"], 12);
    let recreates = body["summary"]["recreates"].as_array().unwrap();
    let actual_labels: Vec<&str> = recreates.iter().map(|v| v.as_str().unwrap()).collect();
    assert_eq!(
        actual_labels,
        vec![
            "CreateRunner(ci-1)",
            "CreateRunner(ci-10)",
            "CreateRunner(ci-11)",
            "CreateRunner(ci-12)",
            "CreateRunner(ci-2)",
            "CreateRunner(ci-3)",
            "CreateRunner(ci-4)",
            "CreateRunner(ci-5)",
            "CreateRunner(ci-6)",
            "CreateRunner(ci-7)",
            "CreateRunner(ci-8)",
            "CreateRunner(ci-9)",
        ],
        "summary.recreates must use byte-wise lex order — \
         ci-10/11/12 sort BETWEEN ci-1 and ci-2, NOT after ci-9 \
         (natural-order would put ci-10..ci-12 at the end). A \
         future change to natural-order sorting must update this \
         expected Vec explicitly.",
    );
    assert_eq!(body["summary"]["by_disruption"]["recreate"], 12);
    assert_eq!(body["summary"]["any_recreate"], true);
}

/// Count=0 orphan-removal shape: a managed runner exists
/// on disk (surfaced via `actual.orphans`) with no matching
/// `[[runner]]` block, so plan_from emits one `RemoveRunner` action.
/// `RemoveRunner` is recreate-class, so its label appears in
/// `summary.recreates`.
///
/// `actual.orphans` is the upstream-callable orphan path (cmd_status
/// populates it inline; `state::discover` itself never does). The
/// (false, true) discovery branch in plan_from would cover the same
/// ground but requires a fully-built `DiscoveredRunner` fixture.
/// Using `orphans` keeps the fixture minimal — only an
/// `OrphanedUnit { name }` is needed.
#[test]
fn plan_from_orphan_remove_runner_lists_label_in_summary_recreates() {
    // Empty config (no runners) — only the orphan triggers an action.
    let mut cfg = cfg_with_runner_trust_zone("placeholder", "default".into());
    cfg.runners.clear();

    let mut actual = state::ActualState::default();
    actual.orphans.push(state::OrphanedUnit {
        name: "legacy".into(),
    });
    let paths = Paths::default();

    let plan =
        plan::plan_from(&cfg, &actual, &paths).expect("orphan plan_from must succeed");

    let remove_count = plan
        .actions
        .iter()
        .filter(|a| matches!(a, Action::RemoveRunner(_)))
        .count();
    assert_eq!(
        remove_count, 1,
        "one orphan must produce one RemoveRunner; got {} actions",
        plan.actions.len(),
    );

    let body = plan_to_json_value(&plan, false);
    let recreates = body["summary"]["recreates"].as_array().unwrap();
    let labels: Vec<&str> = recreates.iter().map(|v| v.as_str().unwrap()).collect();
    assert_eq!(
        labels,
        vec!["RemoveRunner(legacy)"],
        "summary.recreates must contain the orphan's RemoveRunner label",
    );
    assert_eq!(body["summary"]["by_disruption"]["recreate"], 1);
    assert_eq!(body["summary"]["any_recreate"], true);
}

/// Empty plan shape: no runners in config, no discovered
/// state. plan_from emits zero actions; `summary.recreates` is the
/// empty array `[]` (stable JSON shape so CI consumers can `jq
/// '.summary.recreates | length'` without conditional key checks).
/// Pinned via plan_from end-to-end (sibling
/// `plan_to_json_value_summary_recreates_empty_when_no_actions`
/// pins the same shape from a hand-built `Plan { actions: vec![] }`
/// — this test threads through the count-expansion + diff
/// pipeline to catch a regression that emits stray actions for
/// the empty-vs-empty case).
#[test]
fn plan_from_no_desired_no_actual_emits_empty_summary_recreates() {
    let mut cfg = cfg_with_runner_trust_zone("placeholder", "default".into());
    cfg.runners.clear();
    let actual = state::ActualState::default();
    let paths = Paths::default();

    let plan = plan::plan_from(&cfg, &actual, &paths)
        .expect("empty desired + empty actual plan_from must succeed");

    assert!(
        plan.actions.is_empty(),
        "empty desired + empty actual must yield zero actions; got: {:?}",
        plan.actions
            .iter()
            .map(|a| format!("{a:?}"))
            .collect::<Vec<_>>(),
    );

    let body = plan_to_json_value(&plan, false);
    assert_eq!(
        body["summary"]["recreates"],
        serde_json::json!([] as [&str; 0]),
        "empty plan must emit recreates: [] not null/missing",
    );
    assert_eq!(body["summary"]["total_actions"], 0);
    assert_eq!(body["summary"]["by_disruption"]["recreate"], 0);
    assert_eq!(body["summary"]["any_recreate"], false);
}

/// Shared scaffold for the explicit-collision precedence sibling
/// tests (forward: explicit Some > count None, and inverse:
/// explicit None > count Some).
///
/// Sets up a `Config` with a count=3 block named `ci` (whose
/// `memory_max` is set to `count_block_memory_max`) plus an
/// explicit `[[runner]] name = "ci-1"` (whose `memory_max` is set
/// to `explicit_memory_max`), invokes `plan_from`, and runs the
/// invariants every direction must satisfy:
///
/// 1. The plan emits exactly 3 `CreateRunner` actions — `expand_counts`

/// Count expansion with explicit collision: a count block
/// `name = "ci" count = 3` plus an explicit `[[runner]] name =
/// "ci-1"` produces 3 distinct expanded names — the explicit ci-1
/// pre-empts the count-block ci-1, so the plan has CreateRunner
/// for ci-1, ci-2, ci-3 (one each, no duplicates). The
/// `expand_counts_auto_skips_explicit_collision` test in plan.rs
/// pins the expansion-side count; this test extends the contract
/// to the rendered `summary.recreates` shape — the count and
/// explicit blocks share a single recreates entry per name.
///
/// Body delegates to `assert_explicit_collision_precedence` for
/// the shared 6-invariant scaffold; this test contributes the
/// forward direction (count `memory_max = None`, explicit
/// `memory_max = Some("8G")`, expected ci-1 `Some("8G")`).
#[test]
fn plan_from_count_with_explicit_collision_lists_each_name_once_in_recreates() {
    assert_explicit_collision_precedence(
        None,
        Some("8G".into()),
        Some("8G".into()),
    );
}

/// Inverse of `plan_from_count_with_explicit_collision_lists_each_name_once_in_recreates`:
/// the explicit ci-1 carries `memory_max = None` while the count
/// block carries `memory_max = Some("4G")`. expand_counts's
/// `if explicit_names.contains(...)` arm still auto-skips the
/// count-expanded ci-1, so the explicit ci-1's RunnerSpec —
/// with its None memory_max — is what flows through
/// merge_defaults and into the resulting EffectiveRunnerSpec.
/// merge_defaults's `runner.memory_max OR defaults.memory_max`
/// or-chain then resolves to None (defaults left None by
/// `cfg_with_runner_trust_zone`).
///
/// The forward-direction sibling proves the explicit block wins
/// when it carries MORE configuration than the count block (the
/// "richer-spec wins" hypothesis would also pass that test). This
/// inverse direction proves the explicit block wins when it
/// carries LESS configuration than the count block — falsifying
/// any "richer-spec wins" alternative. Together they pin the
/// invariant that explicit-block precedence is positional/identity
/// based, not field-density based.
///
/// Body delegates to `assert_explicit_collision_precedence` for
/// the shared 6-invariant scaffold; this test contributes the
/// inverse direction (count `memory_max = Some("4G")`, explicit
/// `memory_max = None`, expected ci-1 `None`).
#[test]
fn plan_from_count_with_explicit_collision_explicit_none_wins_over_count_some() {
    assert_explicit_collision_precedence(
        Some("4G".into()),
        None,
        None,
    );
}

/// Count=0 → orphan RemoveRunner end-to-end shape: a `[[runner]]`
/// block with `count = Some(0)` is dropped at expand_counts
/// (`expand_counts`'s `matches!(spec.count, Some(0)) => continue`
/// arm — the explicit early-return for the count=0 case keeps
/// count=Some(1) and count=None passing through unchanged), so
/// the desired-set has zero runners after expansion. A managed
/// runner discovered on disk (`actual.runners["ci-1"]`, populated
/// by `state::discover` in production) has no matching desired
/// entry — `plan_from`'s `(false, true)` arm fires, emitting
/// `RemoveRunner(ci-1)`. `RemoveRunner` is recreate-class
/// (`Disruption::Recreate` per `Action::disruption()`), so its
/// label appears in `summary.recreates`.
///
/// Distinct from the sibling test
/// `plan_from_orphan_remove_runner_lists_label_in_summary_recreates`
/// — that fixture uses `cfg.runners.clear()` plus an
/// `actual.orphans` push, exercising step 9's
/// `for orphan in &actual.orphans` arm in `plan_from`. This test
/// instead routes through expand_counts's count=0 skip + the
/// `(false, true)` discovery branch (the shape `state::discover`
/// + `actual.runners` produces in production, since
/// `state::discover` itself never populates orphans). Together
/// they pin both surfaces.
#[test]
fn plan_from_count_zero_with_discovered_runner_emits_remove_in_summary_recreates() {
    // [[runner]] name = "ci" count = 0. expand_counts skips the
    // block entirely (count=0 → continue), so desired_names is
    // empty after expansion.
    let mut cfg = cfg_with_runner_trust_zone("ci", "default".into());
    cfg.runners[0].count = Some(0);

    // Discovered "ci-1" on disk with no matching desired entry.
    // Minimal DiscoveredRunner is sufficient — reconstruct_identity
    // tolerates empty on_disk_unit_text via unwrap_or_else fallbacks
    // for User= and WorkingDirectory= parsing, and the assertion
    // here only reads RemoveRunner's name field via Action::label
    // ("RemoveRunner(ci-1)"). InSync drift is the canonical
    // "no drift" classification — the (false, true) branch in
    // plan_from doesn't gate on drift, so any value works; InSync
    // is the simplest.
    let mut actual = state::ActualState::default();
    actual.runners.insert(
        "ci-1".into(),
        state::DiscoveredRunner {
            name: "ci-1".into(),
            spec_hash: String::new(),
            on_disk_unit_text: String::new(),
            drop_ins: std::collections::BTreeMap::new(),
            running: false,
            enabled: false,
            drift: state::Drift::InSync,
        },
    );
    let paths = Paths::default();

    let plan = plan::plan_from(&cfg, &actual, &paths)
        .expect("count=0 + discovered plan_from must succeed");

    // Sanity: exactly one RemoveRunner action, no Create/Update.
    let remove_count = plan
        .actions
        .iter()
        .filter(|a| matches!(a, Action::RemoveRunner(_)))
        .count();
    assert_eq!(
        remove_count, 1,
        "count=0 + one discovered runner must yield one RemoveRunner; \
         got {} actions: {:?}",
        plan.actions.len(),
        plan.actions
            .iter()
            .map(|a| format!("{a:?}"))
            .collect::<Vec<_>>(),
    );
    assert!(
        !plan
            .actions
            .iter()
            .any(|a| matches!(a, Action::CreateRunner(_) | Action::UpdateRunner(_))),
        "count=0 must NOT emit Create/Update; got: {:?}",
        plan.actions
            .iter()
            .map(|a| format!("{a:?}"))
            .collect::<Vec<_>>(),
    );

    let body = plan_to_json_value(&plan, false);
    let recreates = body["summary"]["recreates"].as_array().unwrap();
    let labels: Vec<&str> = recreates.iter().map(|v| v.as_str().unwrap()).collect();
    assert_eq!(
        labels,
        vec!["RemoveRunner(ci-1)"],
        "summary.recreates must contain the count=0 → orphan \
         RemoveRunner label",
    );
    assert_eq!(body["summary"]["by_disruption"]["recreate"], 1);
    assert_eq!(body["summary"]["any_recreate"], true);
    assert_eq!(body["summary"]["total_actions"], 1);
}

/// Discovered-only runner with POPULATED annotations: extends
/// the count=0 sibling above by feeding `plan_from`'s
/// discovered-only diff arm a `DiscoveredRunner` whose
/// `00-ghars.conf` drop-in carries a full annotation set.
/// `reconstruct_identity` reads
/// `discovered.drop_ins["00-ghars.conf"]` via
/// `DiscoveredAnnotations::from_discovered` for url and
/// auth_name. A populated fixture therefore produces a
/// `RunnerIdentity` with non-empty url + auth_name — matching
/// what `apply.rs::execute_remove_runner` needs to mint a
/// deregistration token on recreate.
///
/// The count=0 sibling
/// (`plan_from_count_zero_with_discovered_runner_emits_remove_in_summary_recreates`)
/// uses an empty fixture (empty on_disk_unit_text + empty
/// drop_ins), exercising `reconstruct_identity`'s `unwrap_or_else`
/// fallbacks. This test takes the populated path, distinct from
/// that fallback.
///
/// Distinct config shape: no count block; one explicit runner
/// "web" desired, one different-named "old-web" discovered. The
/// desired-only arm fires for "web" (CreateRunner), the
/// discovered-only arm fires for "old-web" (RemoveRunner). The
/// assertion focuses on the RemoveRunner — its identity must
/// carry the annotation values, not the fallback empty strings.
#[test]
fn plan_from_discovered_only_runner_populates_remove_runner_identity() {
    // Desired: explicit runner "web" (no count block).
    let cfg = cfg_with_runner_trust_zone("web", "default".into());

    // Discovered: a different runner "old-web" — managed unit
    // present on disk, no matching desired entry. The
    // discovered-only arm in plan_from emits RemoveRunner("old-web").
    // Build the discovered runner's spec + render to populate
    // drop_ins["00-ghars.conf"] (which DiscoveredAnnotations::
    // from_discovered reads for url + auth_name).
    let discovered_spec = crate::config::EffectiveRunnerSpec {
        name: "old-web".into(),
        url: "https://github.com/example/old-web".into(),
        arch: crate::config::Arch::X86_64,
        labels: vec!["old-web".into()],
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
        // Non-empty digest mirrors post-install steady state. See
        // `FIXTURE_RUNSVC_SHA256` doc-comment for rationale.
        runsvc_sha256: FIXTURE_RUNSVC_SHA256.into(),
        config_source: "/etc/ghars/ghars.toml".into(),
    };
    let rendered = crate::systemd::render_runner_unit(&discovered_spec)
        .expect("render_runner_unit must succeed for valid spec");
    // Use the production-shape unit body (the runner template
    // verbatim). The url + auth_name assertions below pass only
    // when `reconstruct_identity` reads the
    // `X-Ghars-Runner-Url` / `X-Ghars-Auth-Name` annotations
    // emitted by `render_runner_unit` into
    // `rendered.drop_ins["00-ghars.conf"]`, not from the
    // template body.
    let on_disk_unit_text = crate::systemd::runner_template_text();
    let mut actual = state::ActualState::default();
    actual.runners.insert(
        "old-web".into(),
        state::DiscoveredRunner {
            name: "old-web".into(),
            spec_hash: discovered_spec.spec_hash.clone(),
            on_disk_unit_text,
            drop_ins: rendered.drop_ins,
            running: false,
            enabled: false,
            drift: state::Drift::InSync,
        },
    );
    let paths = Paths::default();

    let plan = plan::plan_from(&cfg, &actual, &paths)
        .expect("discovered-only branch with populated annotations must succeed");

    // The plan must contain a RemoveRunner("old-web") AND a
    // CreateRunner("web") — both arms fire. Extract the
    // RemoveRunner's identity for the populated-fields pin.
    let remove_identity = plan
        .actions
        .iter()
        .find_map(|a| match a {
            Action::RemoveRunner(id) => Some(id),
            _ => None,
        })
        .expect("discovered-only arm must emit RemoveRunner");
    assert_eq!(
        remove_identity.name, "old-web",
        "RemoveRunner must target the discovered-only runner",
    );
    assert_eq!(
        remove_identity.url, "https://github.com/example/old-web",
        "RemoveRunner.url must reflect the X-Ghars-Runner-Url \
         annotation in the discovered 00-ghars.conf, not the \
         empty fallback that DiscoveredAnnotations::default \
         would produce on a missing drop-in",
    );
    assert_eq!(
        remove_identity.auth_name, "pat",
        "RemoveRunner.auth_name must reflect the X-Ghars-Auth-Name \
         annotation, not the empty fallback",
    );

    // Pin the docstring's "desired-only arm fires for 'web'
    // (CreateRunner)" claim. The doc states both arms fire in
    // this fixture; without this assertion that claim is
    // unverified and could silently regress (e.g. plan_from
    // refactor that drops the desired-only arm in mixed plans).
    assert!(
        plan.actions
            .iter()
            .any(|a| matches!(a, Action::CreateRunner(p) if p.spec.name == "web")),
        "desired-only arm must emit CreateRunner(web); got actions: {:?}",
        plan.actions
            .iter()
            .map(|a| format!("{a:?}"))
            .collect::<Vec<_>>(),
    );

    // Full-Vec pin on summary.recreates: the plan has exactly
    // 2 actions — CreateRunner("web") from the desired-only arm
    // and RemoveRunner("old-web") from the discovered-only arm.
    // Both are recreate-class (per Action::disruption()), so both
    // labels appear in summary.recreates. plan_summary_value
    // sorts via sort_unstable() over Action::label() output, so
    // "CreateRunner(web)" < "RemoveRunner(old-web)" by byte-wise
    // lex order. assert_eq! catches both ordering regressions
    // and any spurious/missing entries — strictly tighter than
    // a single .contains() check.
    let body = plan_to_json_value(&plan, false);
    let recreates = body["summary"]["recreates"].as_array().unwrap();
    let labels: Vec<&str> = recreates.iter().map(|v| v.as_str().unwrap()).collect();
    assert_eq!(
        labels,
        vec!["CreateRunner(web)", "RemoveRunner(old-web)"],
        "summary.recreates must equal exactly [CreateRunner(web), \
         RemoveRunner(old-web)] (sorted by Action::label byte-wise); \
         got: {labels:?}",
    );
}

// ---------- colorized unified diff ----------------------------

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

// ---------- --diff argv parsing -------------------------------

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
        keep_versions: 2,
    };
    // Drive the production Value-construction directly. No test
    // mirror — `plan_to_json_value` IS the production code.
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
    // update_runner carries drift_cause + recreate_reasons.
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
        keep_versions: 2,
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
        keep_versions: 2,
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
/// drives `plan_to_json_value` directly (no test mirror).
/// Together the two tests cover both the happy-path output shape
/// AND the non-panicking end-to-end pipe.
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
        keep_versions: 2,
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
        keep_versions: 2,
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
        keep_versions: 2,
    };
    let v = plan_to_json_value(&plan, false);
    let actions = v["actions"].as_array().expect("actions array");
    assert_eq!(actions.len(), 1);
    assert_eq!(actions[0]["kind"], "create_runner");
    assert_eq!(actions[0]["name"], "a");
    assert!(actions[0]["url"].is_string());
    assert!(
        actions[0]["spec_hash"]
            .as_str()
            .unwrap()
            .starts_with("sha256:")
    );
}

#[test]
fn render_plan_json_remove_runner_kind_label_is_remove_runner() {
    let plan = Plan {
        actions: vec![Action::RemoveRunner(fake_identity("legacy"))],
        warnings: vec![],
        keep_versions: 2,
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
        keep_versions: 2,
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
        keep_versions: 2,
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
        keep_versions: 2,
    };
    let v = plan_to_json_value(&plan, false);
    let actions = v["actions"].as_array().unwrap();
    assert_eq!(actions[0]["kind"], "remove_cache_pool");
    assert_eq!(actions[0]["name"], "build");
}
