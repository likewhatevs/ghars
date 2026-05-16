//! Test chunk - co-located with cli/ submodules. See tests/mod.rs for fixture sharing rationale.
#![allow(clippy::unwrap_used)]

use super::*;

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
    // entries through the hostile-basename JSON wrapper in
    // `plan_to_json_value`.
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

/// Regression: when stdout writes fail (e.g. SIGPIPE/BrokenPipe from
/// `ghars apply | head`), the function must KEEP writing the `fail:`
/// rows and rollback advisory to stderr. Pre-fix code returned on the
/// first writeln! `?`, silently swallowing the operator-critical
/// failure-state signal.
#[test]
fn render_apply_emission_keeps_stderr_writing_when_stdout_pipes_break() {
    use std::io::ErrorKind;
    struct AlwaysBroken;
    impl io::Write for AlwaysBroken {
        fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
            let _ = buf;
            Err(io::Error::new(ErrorKind::BrokenPipe, "head closed"))
        }
        fn flush(&mut self) -> io::Result<()> {
            Ok(())
        }
    }
    let result = apply::ApplyResult {
        details: vec![
            ("CreateRunner(a)".into(), apply::ApplyOutcome::Created),
            (
                "CreateRunner(b)".into(),
                apply::ApplyOutcome::Failed {
                    error_summary: "github: 401".into(),
                    plan_disruption: plan::Disruption::Recreate,
                },
            ),
        ],
        failed: vec![(
            "CreateRunner(b)".into(),
            crate::error::GharsError::Auth("401".into(), String::new()),
        )],
        failed_undo_logs: vec![(
            "CreateRunner(b)".into(),
            vec![apply::UndoStep::CreateDir {
                path: camino::Utf8PathBuf::from("/var/lib/ghars/default/ghars-b"),
            }],
        )],
        ..apply::ApplyResult::default()
    };
    let mut stderr: Vec<u8> = Vec::new();
    // Function returns the first IO error from any sink. Verify the
    // error surfaces (so callers can choose to react) AND that the
    // stderr writes still happened despite stdout being broken.
    let res = render_apply_emission(&result, &mut AlwaysBroken, &mut stderr);
    assert!(res.is_err(), "expected first-error propagation; got Ok(())");
    let err = String::from_utf8(stderr).unwrap();
    assert!(
        err.contains("fail: CreateRunner(b)"),
        "fail: row must still reach stderr when stdout is broken; got: {err:?}"
    );
    assert!(
        err.contains("Rollback advisory"),
        "rollback advisory must still reach stderr when stdout is broken; got: {err:?}"
    );
}
