//! Test chunk - co-located with cli/ submodules. See tests/mod.rs for fixture sharing rationale.
#![allow(clippy::unwrap_used)]

use super::*;

/// Recreate-class `UpdateRunner` must use the `!` sigil.
/// In-place `UpdateRunner` keeps `~`. Both header lines still
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
/// PoolCreated/PoolUpdated/PoolRemoved; `skipped` covers `NoOp`,
/// `DryRunSkipped`, `InPlaceSkipped`, `PoolSkipped`; `failed` covers
/// `ApplyOutcome::Failed`. The disruption parenthetical mirrors
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
                path: camino::Utf8PathBuf::from("/etc/systemd/system/ghars-cache@build.service.d"),
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
        advisory
            .contains("\n    - created directory /etc/systemd/system/ghars-cache@build.service.d"),
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
/// failure has an empty `UndoLog` (no per-action mutation manifest).
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
/// `describe()` output) folds the shorter into the longer and
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
                path: camino::Utf8PathBuf::from("/etc/systemd/system/ghars-cache@a.service.d"),
            },
            apply::UndoStep::CreateDir {
                path: camino::Utf8PathBuf::from("/etc/systemd/system/ghars-cache@ab.service.d"),
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
    let short_bullet = "    - created directory /etc/systemd/system/ghars-cache@a.service.d";
    let long_bullet = "    - created directory /etc/systemd/system/ghars-cache@ab.service.d";
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
                path: camino::Utf8PathBuf::from("/etc/systemd/system/ghars-cache@a.service.d"),
            },
            apply::UndoStep::CreateDir {
                path: camino::Utf8PathBuf::from("/etc/systemd/system/ghars-cache@ab.service.d"),
            },
            apply::UndoStep::CreateDir {
                path: camino::Utf8PathBuf::from("/etc/systemd/system/ghars-cache@abc.service.d"),
            },
        ],
    );
    let advisory = render_rollback_advisory(&result).unwrap();
    let bullet_a = "    - created directory /etc/systemd/system/ghars-cache@a.service.d";
    let bullet_ab = "    - created directory /etc/systemd/system/ghars-cache@ab.service.d";
    let bullet_abc = "    - created directory /etc/systemd/system/ghars-cache@abc.service.d";
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
