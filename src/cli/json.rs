//! JSON-mode rendering for `plan` output and the per-entry
//! `drop_in_change` JSON shape.
//!
//! Text-mode rendering is in `super::render`. The two paths share
//! the [`crate::plan::Disruption`] vocabulary
//! (`disruption_summary_variants` here, `format_disruption_tail` /
//! `Disruption::label()` in `render`).

use std::io;

use crate::Result;
use crate::error::GharsError;
use crate::escape_control_chars;
use crate::plan::{self, Action, Plan};

use super::render::recreate_removed_basenames;

/// Build the JSON value for `plan` without writing it. Pure function
/// so tests assert the in-memory shape and `render_plan_json` shares
/// the exact construction the operator sees through stdout (no test
/// mirror to drift). Inner `drop_in_changes[].change_kind` is the
/// per-entry discriminator — distinct from the per-action `kind`
/// so consumers can disambiguate without context.
///
/// `diff` controls whether each `drop_in_changes` entry carries the
/// drop-in body content (`true`) or only the basename + `change_kind`
/// (`false`, the body-omitting shape — backward compatible with
/// existing consumers).
///
/// When `diff = true`:
/// - `Created` adds `after` (full body string).
/// - `Removed` adds `before` (full body string).
/// - `Modified` adds `unified_diff` (string from
///   `similar::udiff::unified_diff`).
/// - `Preserved` adds nothing — the basename + `"preserved"`
///   `change_kind` is the entire payload.
///
/// For `Action::UpdateRunner` with `requires_recreate = true`, the
/// planner's `drop_in_changes` is empty by design (recreate
/// rebuilds every drop-in from scratch). When `diff = true`, the
/// JSON path synthesizes `Created` entries from
/// `delta.after.drop_ins` so consumers can see the post-recreate
/// drop-ins. Without `diff`, the array stays empty (backward
/// compatible).
///
/// # Security
///
/// Drop-in body content emitted under `diff = true` may contain
/// sensitive values rendered verbatim from the operator's TOML —
/// for example, `60-proxy.conf` carries `Environment=HTTP_PROXY=
/// http://user:pass@host` when the operator configures an
/// authenticated proxy. JSON output of `ghars plan --diff`
/// should not be uploaded to shared artifacts (CI logs,
/// pastebins, ticket attachments) without redaction. SEC-NEW:
/// --diff body output may expose proxy credentials from
/// 60-proxy.conf.
///
/// # Schema v1 → v2 migration
///
/// v1 emitted `FieldChange.before` / `.after` as bare strings;
/// v2 emits them as tagged objects keyed on `type`. v1 consumers
/// reading `.before` as a string should switch to `.before.value`
/// when `.before.type == "string"` or to `.before.values` (a JSON
/// array) when `.before.type == "list"`.
///
/// ```text
/// // v1 (schema_version "1"):
/// {"path": "labels", "before": "gpu,linux", "after": "gpu,linux,fast"}
///
/// // v2 (schema_version "2"):
/// {
///   "path": "labels",
///   "before": {"type": "list", "values": ["gpu", "linux"]},
///   "after":  {"type": "list", "values": ["gpu", "linux", "fast"]}
/// }
/// ```
#[must_use]
pub(crate) fn plan_to_json_value(plan: &Plan, diff: bool) -> serde_json::Value {
    let actions: Vec<serde_json::Value> = plan
        .actions
        .iter()
        .map(|a| {
            // Every action object carries a top-level
            // `disruption` field so JSON consumers (CI, dashboards)
            // can branch on the worst-case operational impact
            // without rederiving it from the per-variant fields. The
            // label vocabulary is shared with the text renderer.
            let disruption = a.disruption().label();
            match a {
                Action::CreateRunner(p) => serde_json::json!({
                    "kind": "create_runner",
                    "name": p.spec.name,
                    "url": p.spec.url,
                    "spec_hash": p.spec_hash,
                    "disruption": disruption,
                }),
                Action::UpdateRunner(d) => {
                    // Emit field_changes + drop_in_changes
                    // so JSON consumers (CI, dashboards) can render the same
                    // per-field deltas the text path renders, without
                    // re-running the planner. Drop-in bodies (`before`/
                    // `after`/`unified_diff`) ride behind `--diff`.
                    // Schema v2 — `before`/`after` are tagged
                    // FieldValue objects (`{"type": "string", "value": "x"}`
                    // or `{"type": "list", "values": ["a", "b"]}`) so JSON
                    // consumers can programmatically detect List vs Scalar
                    // without re-splitting comma-joined strings.
                    let field_changes: Vec<serde_json::Value> = d
                        .field_changes
                        .iter()
                        .map(|fc| {
                            serde_json::json!({
                                "path": fc.path,
                                "before": fc.before.to_json(),
                                "after": fc.after.to_json(),
                            })
                        })
                        .collect();
                    let drop_in_changes: Vec<serde_json::Value> = if diff && d.requires_recreate {
                        // Synthesize Created entries from
                        // delta.after.drop_ins (BTreeMap, so already
                        // alphabetically ordered) and route through
                        // the same drop_in_change_to_json the
                        // in-place path uses. One JSON shape, no
                        // hand-rolled duplicate. Without `--diff`
                        // the array stays empty (backward compat).
                        let mut entries: Vec<serde_json::Value> = d
                            .after
                            .drop_ins
                            .iter()
                            .map(|(basename, body)| {
                                drop_in_change_to_json(
                                    &plan::DropInChange {
                                        basename: basename.clone(),
                                        change: plan::DropInChangeKind::Created {
                                            after: body.clone(),
                                        },
                                    },
                                    diff,
                                )
                            })
                            .collect();
                        // Surface drop-ins the recreate will
                        // DELETE. Diverges intentionally from the
                        // in-place Removed JSON shape: no `before`
                        // body field — basename + change_kind +
                        // `body_suppressed: true` marker. Body would
                        // re-introduce the credential-leakage
                        // surface for any drop-in that embedded
                        // `Environment=` lines (e.g. `60-proxy.conf`
                        // with an authenticated proxy URL).
                        // Operator-actionable signal is the basename
                        // alone; `body_suppressed: true` lets JSON
                        // consumers distinguish "no body because
                        // suppressed" from "no body because absent".
                        //
                        // `None` ⇒ "unknown pre-state" (test
                        // fixture or any future construction site
                        // that doesn't have a `DiscoveredRunner` in
                        // scope); SUPPRESS the Removed entries
                        // rather than risk a misleading silence in
                        // JSON consumers.
                        if let Some(removed) = recreate_removed_basenames(d) {
                            for basename in removed {
                                // Same defense-in-depth escape as
                                // the text path. `serde_json` escapes
                                // ESC on the JSON wire, which is safe
                                // for parsers that honor JSON quoting;
                                // but downstream jq pipelines that
                                // pipe `.basename` back to a terminal
                                // via `echo -e` / `printf '%b'` (or
                                // shells with `xpg_echo`) would
                                // re-interpret the escape. Replacing
                                // each control char with
                                // `char::escape_default` form before
                                // serialization keeps the basename
                                // terminal-safe regardless of the
                                // downstream consumer's interpolation
                                // semantics.
                                entries.push(serde_json::json!({
                                    "basename": escape_control_chars(basename).into_owned(),
                                    "change_kind": "removed",
                                    "body_suppressed": true,
                                }));
                            }
                        }
                        entries
                    } else {
                        d.drop_in_changes
                            .iter()
                            .map(|dc| drop_in_change_to_json(dc, diff))
                            .collect()
                    };
                    serde_json::json!({
                        "kind": "update_runner",
                        "name": d.identity.name,
                        "requires_recreate": d.requires_recreate,
                        "recreate_reasons": d.recreate_reasons,
                        // Cause label uses the same snake_case
                        // vocabulary as the text path so `grep
                        // spec_changed` matches both.
                        "drift_cause": d.drift_cause.label(),
                        "spec_hash": d.after.spec_hash,
                        "field_changes": field_changes,
                        "drop_in_changes": drop_in_changes,
                        "disruption": disruption,
                    })
                }
                Action::RemoveRunner(i) => serde_json::json!({
                    "kind": "remove_runner",
                    "name": i.name,
                    "url": i.url,
                    "disruption": disruption,
                }),
                Action::CreateCachePool(p) => serde_json::json!({
                    "kind": "create_cache_pool",
                    "name": p.binding.name,
                    "kinds": p.binding.kinds,
                    "spec_hash": p.spec_hash,
                    "disruption": disruption,
                }),
                Action::UpdateCachePool(d) => serde_json::json!({
                    "kind": "update_cache_pool",
                    "name": d.binding.name,
                    "kinds": d.binding.kinds,
                    "spec_hash": d.spec_hash,
                    "disruption": disruption,
                }),
                Action::RemoveCachePool(name) => serde_json::json!({
                    "kind": "remove_cache_pool",
                    "name": name,
                    "disruption": disruption,
                }),
                Action::NoOp(reason) => serde_json::json!({
                    "kind": "noop",
                    "reason": reason,
                    "disruption": disruption,
                }),
            }
        })
        .collect();
    // Top-level `schema_version` is a forward-
    // compat hook for CI consumers that need to detect breaking
    // changes in this JSON shape. Bump this string when the shape
    // changes in a way that existing consumers cannot transparently
    // ignore (added keys are NOT a bump; renamed/removed keys are).
    // Adding a new variant to a tagged enum surface (e.g. a new
    // `FieldValue.type` value beyond `string` / `list`) IS a bump —
    // consumers that branch on the existing variant set must opt in
    // (their fallback arm would silently misroute the new shape).
    // Stays a string so we can use semver-flavored values like
    // "2.0" without restructuring downstream parsers.
    //
    // Top-level `summary` rolls per-action
    // counts up so CI policy gates can branch on the plan
    // disposition without iterating the actions array.
    // `any_recreate` is the load-bearing field for "block this
    // plan if it would deregister any runner" guards.
    let summary = plan_summary_value(&plan.actions);
    // Bumped from "1" → "2" because FieldChange.before/after
    // changed from raw String to tagged FieldValue objects
    // (`{"type": "string", "value"}` / `{"type": "list", "values"}`).
    // Existing v1 consumers parsing `before` as a String would
    // see an object and fail; the bump signals the breaking change
    // explicitly.
    serde_json::json!({
        "schema_version": "2",
        "summary": summary,
        "actions": actions,
        "warnings": plan.warnings,
    })
}

/// Build the top-level `summary` object that JSON `ghars plan`
/// emits at the `summary` key. CI policy gates branch on these
/// fields without iterating the per-action body.
///
/// Fields:
/// - `total_actions` — `actions.len()`.
/// - `by_disruption` — object keyed by `Disruption::label()`
///   (`none` / `restart` / `recreate`), values are u64 counts.
///   All three keys are always present (count `0` when absent)
///   so consumers see a stable shape.
/// - `any_recreate` — bool, equivalent to `!recreates.is_empty()`.
///   Load-bearing for "block this plan if it would deregister any
///   runner" guards.
/// - `recreates` — array of `Action::label()` strings, one per
///   `Recreate`-class action, sorted lexicographically. Always
///   present, emitted as `[]` when the plan has no recreate-class
///   actions.
///
/// **`recreates` element contract**:
/// - Each element matches the verbatim `Action::label()` output —
///   the same string `cmd_apply` emits in `ok: LABEL` and
///   `fail: LABEL` lines, so a single grep on the label spans
///   plan and apply surfaces.
/// - The shape is `Variant(name)` (`PascalCase` variant + paren-
///   wrapped entity name): `CreateRunner(alpha)`,
///   `RemoveRunner(beta)`, `CreateCachePool(build)`,
///   `RemoveCachePool(build)`, `UpdateRunner(gamma)` (only when
///   that delta has `requires_recreate = true`; in-place
///   `UpdateRunner` is `Restart` and is excluded). `UpdateCachePool`
///   is always `Restart` and never appears here. `NoOp` is
///   `Disruption::None` and never appears.
/// - Element values are `PascalCase` to match `Action::label()`;
///   JSON keys (`total_actions`, `by_disruption`, `any_recreate`,
///   `recreates`) are `snake_case`. (Mixed case is intentional —
///   element values mirror Rust enum variant names verbatim;
///   keys follow `snake_case` JSON convention.)
/// - Same-name entities of different kinds disambiguate via the
///   variant prefix: `RemoveRunner(alpha)` and `RemoveCachePool(alpha)`
///   are distinct labels.
/// - Sort is `slice::sort_unstable()` (byte-wise lexicographic;
///   stability is irrelevant for `Vec<String>` because equal
///   elements are indistinguishable). For ASCII-only labels
///   (`Action::label()` interpolates entity names matching
///   `IDENTIFIER_REGEX` = `^[a-z]([a-z0-9-]*[a-z0-9])?$`, plus the
///   static `PascalCase` variant prefix and parens), this coincides
///   with operator-readable alphabetical order.
///
/// **Invariants** (pinned by tests at
/// `plan_to_json_value_summary_recreates_*`):
/// - `recreates.len() == by_disruption["recreate"]` (same Vec
///   sourced both fields from).
/// - `!recreates.is_empty() == any_recreate`.
/// - Order is independent of plan-emit order; sort is stable
///   across runs.
/// - Output is `--diff`-independent — `recreates` carries no body
///   text or per-action payload, only labels.
///
/// **CI example**: gate on no-recreate plans with
/// `jq -e '.summary.recreates | length == 0'` (exits 0 when the
/// array is empty, non-zero otherwise).
///
/// The `by_disruption` loop iterates
/// `disruption_summary_variants()` instead of hardcoding label
/// strings — `Disruption::label()` stays the single source of
/// truth for the label vocabulary.
///
/// `recreates` is collected first; `by_disruption["recreate"]`
/// derives its count from `recreates.len()` and `any_recreate`
/// derives from `!recreates.is_empty()`. The for-variant loop
/// only counts the two non-recreate variants, removing a redundant
/// filter pass and a `mut` bool.
pub(crate) fn plan_summary_value(actions: &[Action]) -> serde_json::Value {
    let mut recreates: Vec<String> = actions
        .iter()
        .filter(|a| a.disruption() == plan::Disruption::Recreate)
        .map(plan::Action::label)
        .collect();
    recreates.sort_unstable();
    let any_recreate = !recreates.is_empty();
    let mut by_disruption = serde_json::Map::new();
    for variant in disruption_summary_variants() {
        let count: u64 = if matches!(variant, plan::Disruption::Recreate) {
            recreates.len() as u64
        } else {
            actions.iter().filter(|a| a.disruption() == variant).count() as u64
        };
        by_disruption.insert(variant.label().into(), serde_json::json!(count));
    }
    serde_json::json!({
        "total_actions": actions.len(),
        "by_disruption": serde_json::Value::Object(by_disruption),
        "any_recreate": any_recreate,
        "recreates": recreates,
    })
}

/// All `Disruption` variants in canonical (least → most disruptive)
/// order. The single source of truth for iterating the taxonomy
/// outside the enum's own match arms — used by `plan_summary_value`
/// for JSON keys, `render_plan` for the text-mode footer, and
/// future code that needs the same ordering.
pub(crate) fn disruption_summary_variants() -> [plan::Disruption; 3] {
    [
        plan::Disruption::None,
        plan::Disruption::Restart,
        plan::Disruption::Recreate,
    ]
}

/// Build one `drop_in_changes[]` JSON entry. When `diff = false`,
/// emits the minimal shape (`basename` + `change_kind`) without
/// body content. When `diff = true`, adds body content per
/// variant: `after` for Created, `before` for Removed,
/// `unified_diff` for Modified. Preserved adds nothing — the
/// basename + `"preserved"` `change_kind` is the entire payload.
pub(crate) fn drop_in_change_to_json(dc: &plan::DropInChange, diff: bool) -> serde_json::Value {
    let change_kind = match dc.change {
        plan::DropInChangeKind::Created { .. } => "created",
        plan::DropInChangeKind::Modified { .. } => "modified",
        plan::DropInChangeKind::Removed { .. } => "removed",
        plan::DropInChangeKind::Preserved => "preserved",
    };
    let mut obj = serde_json::Map::new();
    // Defense-in-depth basename escape (parity with the
    // recreate-Removed JSON path in `plan_to_json_value`).
    // `dc.basename` flows from `state::discover`'s filesystem
    // walk, which has no charset gate (config-load validates
    // operator-authored drop-in names but discovery-side
    // basenames from the on-disk `<drop-in-dir>/` listing bypass
    // that). Replacing the raw String with
    // `escape_control_chars(...).into_owned()` keeps the JSON
    // wire shape terminal-safe for downstream
    // `jq | echo -e` / `printf '%b'` pipelines.
    obj.insert(
        "basename".into(),
        serde_json::Value::String(escape_control_chars(&dc.basename).into_owned()),
    );
    obj.insert(
        "change_kind".into(),
        serde_json::Value::String(change_kind.into()),
    );
    if diff {
        match &dc.change {
            plan::DropInChangeKind::Created { after } => {
                obj.insert("after".into(), serde_json::Value::String(after.clone()));
            }
            plan::DropInChangeKind::Removed { before } => {
                obj.insert("before".into(), serde_json::Value::String(before.clone()));
            }
            plan::DropInChangeKind::Modified { before, after } => {
                // Header labels match the text-path renderer:
                // `on-disk` for the discovered body, `desired`
                // for the post-render bytes. Same in-memory-vs-
                // disk semantics rationale documented at
                // `render_drop_in_body_block`.
                let unified = similar::udiff::unified_diff(
                    similar::Algorithm::Myers,
                    before.as_str(),
                    after.as_str(),
                    3,
                    Some(("on-disk", "desired")),
                );
                obj.insert("unified_diff".into(), serde_json::Value::String(unified));
            }
            plan::DropInChangeKind::Preserved => {
                // No payload — bytes are identical on both sides.
            }
        }
    }
    serde_json::Value::Object(obj)
}

pub(crate) fn render_plan_json(plan: &Plan, diff: bool) -> Result<()> {
    let body = plan_to_json_value(plan, diff);
    let mut stdout = io::stdout().lock();
    // serde_json encode failures here are internal encoder failures
    // (e.g. stdout closed, write returns short), NOT operator config
    // errors — map to GharsError::Io so main.rs's variant→exit-code
    // mapping doesn't surface exit code 6 (config) for an io fault.
    serde_json::to_writer_pretty(&mut stdout, &body)
        .map_err(|e| GharsError::Io(io::Error::other(format!("encode plan json: {e}"))))?;
    use std::io::Write;
    writeln!(stdout).map_err(GharsError::Io)?;
    Ok(())
}
