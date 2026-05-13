//! Text-mode rendering for `plan` and `apply` outputs.
//!
//! The JSON path lives in `super::json`. These two surfaces share
//! `format_disruption_tail` (the `(R restart, K recreate, N none).
//! any_recreate: bool` suffix) and the `Disruption::label()` /
//! `disruption_summary_variants()` vocabulary.

use std::io::{self, Write};

use crate::Result;
use crate::apply;
use crate::error::GharsError;
use crate::escape_control_chars;
use crate::plan::{self, Action, Plan};

use super::args::ColorMode;
use super::json::render_plan_json;

pub(super) fn render_plan(
    plan: &Plan,
    color: ColorMode,
    json: bool,
    quiet: bool,
    diff: bool,
) -> Result<()> {
    if json {
        return render_plan_json(plan, diff);
    }
    if quiet {
        return Ok(());
    }
    let mut stdout = io::stdout().lock();
    if plan.actions.is_empty() {
        writeln!(stdout, "Plan: no changes.").map_err(GharsError::Io)?;
        // Empty action list does NOT mean empty warning list. The
        // planner emits warnings for situations that produce no
        // disruption-class action but still demand operator attention
        // (e.g. count-block name collisions, cache-trust-zone gloss,
        // discovered orphans that don't map to a Remove action). The
        // pre-fix early-return dropped these silently; an operator who
        // saw "Plan: no changes." would never know a warning fired.
        for warning in &plan.warnings {
            writeln!(stdout, "warning: {warning}").map_err(GharsError::Io)?;
        }
        return Ok(());
    }
    for action in &plan.actions {
        let line = render_action_line(action, color, diff);
        writeln!(stdout, "{line}").map_err(GharsError::Io)?;
    }
    // Text-mode plan summary footer — operators reading
    // `ghars plan` without `--json` need the same disruption-class
    // counts CI consumers get from JSON `summary`. Emitted between
    // the action lines and the warnings tail so operator eyes see
    // it before the (less critical) warning block. Format mirrors
    // `summary` JSON keys verbatim so a single `grep any_recreate`
    // matches both surfaces.
    writeln!(stdout, "{}", render_plan_summary_line(&plan.actions)).map_err(GharsError::Io)?;
    for warning in &plan.warnings {
        writeln!(stdout, "warning: {warning}").map_err(GharsError::Io)?;
    }
    Ok(())
}

/// Shared filter for recreate-class Removed entries.
/// Both the text renderer (`render_action_line`) and JSON renderer
/// (`plan_to_json_value`) iterate `delta.before_drop_in_basenames`
/// and emit one entry per basename absent from `delta.after.drop_ins`.
/// Single source of truth — a future change to the predicate (e.g.
/// excluding annotations or applying basename normalization) lands
/// in one place.
///
/// Returns `Some(iter)` when discovered pre-state is available (the
/// caller is expected to surface Removed entries). Returns `None`
/// when `before_drop_in_basenames` is `None` ("unknown pre-state");
/// the caller MUST suppress the Removed section in that case rather
/// than emit a misleading silence (see plan.rs
/// `RunnerDelta::before_drop_in_basenames` field doc for the full
/// contract). `Some(empty_iter)` ⇒ the discovered
/// drop-in directory was present but empty / fully reused, no
/// Removed entries.
pub(super) fn recreate_removed_basenames(
    d: &plan::RunnerDelta,
) -> Option<impl Iterator<Item = &String>> {
    d.before_drop_in_basenames.as_ref().map(|before| {
        before
            .iter()
            .filter(|b| !d.after.drop_ins.contains_key(b.as_str()))
    })
}

/// Render one Action as a single-line plan entry with leading sigil.
///
/// Sigil → variant mapping (column-0 grep targets):
/// - `+` ⇒ `CreateRunner` / `CreateCachePool`
/// - `-` ⇒ `RemoveRunner` / `RemoveCachePool`
/// - `~` ⇒ `UpdateRunner` (in-place, Restart-class) / `UpdateCachePool`
/// - `!` ⇒ `UpdateRunner` (recreate-class — escalated destructive update)
/// - ` ` ⇒ `NoOp`
///
/// `^~ runner` matches Restart-class `UpdateRunner` only — recreate-
/// class `UpdateRunner` uses `!`. To count "all `UpdateRunner`" use
/// either `^[~!] runner` (sigil-class union) or `^.* runner .*
/// update:` (verb-based, sigil-agnostic). For the "all destructive
/// actions" pipeline, grep `[recreate]` on the trailing bracket tag
/// instead — that matches `+`/`-`/`!` lines plus `[recreate]`-tagged
/// pool actions in one pass.
pub(super) fn render_action_line(action: &Action, color: ColorMode, diff: bool) -> String {
    let (sigil, summary, ansi) = match action {
        Action::CreateRunner(p) => ('+', format!("runner {} (create)", p.spec.name), "\x1b[32m"),
        Action::UpdateRunner(d) => {
            // Surface the drift cause so the operator can tell a
            // config edit (`spec_changed`) from out-of-band drift
            // (`drift_detected`) without re-running discovery.
            //
            // Recreate-class UpdateRunner takes the `!` sigil to
            // distinguish destructive updates (token re-mint + unit
            // teardown + reregister) from in-place updates that share
            // the `~` glyph. The `[recreate]` bracket tag at end-of-
            // line still conveys the same information; `!` is the
            // fast-scan column-0 signal symmetric with `+`/`-` for
            // create/remove. CreateRunner/RemoveRunner /
            // CreateCachePool/RemoveCachePool keep `+`/`-` (already
            // convey destructive intent). UpdateCachePool keeps `~`
            // (always Restart-class — never recreate). NoOp keeps
            // ` `. Format:
            //   ~ runner NAME (CAUSE; update: in-place)
            //   ! runner NAME (CAUSE; update: recreate (FIELDS))
            //
            // Shell-safety: the `!` sigil is followed by a
            // space (`! `) to avoid bash history-expansion (`!word`).
            // Future format changes that drop the space MUST move
            // `!` to a non-leading position.
            //
            // `!` is NOT a uniform recreate-class marker — it
            // signals UpdateRunner escalated to recreate (the
            // surprising case). For all-recreate-class extraction,
            // grep `[recreate]` (text) or use `summary.recreates`
            // (JSON).
            //
            // Omit the parenthetical when `recreate_reasons` is
            // empty so the renderer never emits `recreate ()`.
            // `plan::plan_from` sets `requires_recreate =
            // !recreate_reasons.is_empty()` post-classify, so this
            // branch is unreachable from production today. Keep the
            // guard as defense for hand-constructed `RunnerDelta`
            // fixtures and any future construction site that decouples
            // `requires_recreate` from `recreate_reasons` length.
            let (sigil, mode) = if d.requires_recreate {
                let mode = if d.recreate_reasons.is_empty() {
                    "update: recreate".to_string()
                } else {
                    format!("update: recreate ({})", d.recreate_reasons.join(","))
                };
                ('!', mode)
            } else {
                ('~', "update: in-place".into())
            };
            let cause = d.drift_cause.label();
            (
                sigil,
                format!("runner {} ({cause}; {mode})", d.identity.name),
                "\x1b[33m",
            )
        }
        Action::RemoveRunner(i) => ('-', format!("runner {} (remove)", i.name), "\x1b[31m"),
        Action::CreateCachePool(p) => (
            '+',
            format!("cache_pool {} (create)", p.binding.name),
            "\x1b[32m",
        ),
        Action::UpdateCachePool(d) => (
            '~',
            format!("cache_pool {} (update)", d.binding.name),
            "\x1b[33m",
        ),
        Action::RemoveCachePool(name) => ('-', format!("cache_pool {name} (remove)"), "\x1b[31m"),
        Action::NoOp(reason) => (' ', format!("noop ({reason})"), ""),
    };
    // Append the worst-case disruption tag in square brackets
    // after the per-action summary so operators see the blast radius
    // at a glance:
    //   + runner foo (create) [recreate]
    //   ~ runner foo (spec_changed; update: in-place) [restart]
    //   ! runner foo (spec_changed; update: recreate (...)) [recreate]
    //     noop (foo: in sync) [none]
    // The tag is part of the colored summary line — it is built into
    // `summary` BEFORE the ANSI wrap, so when color is on the
    // bracketed label sits inside `\x1b[33m...\x1b[0m`. ANSI strippers
    // (or `--no-color` callers) preserve the bracket text intact, so
    // `grep [none]` on stripped output matches every action with no
    // scheduled host mutation. NoOp also receives the tag — the
    // suffix is unconditional.
    let disruption = action.disruption().label();
    let summary = format!("{summary} [{disruption}]");
    let header = if color.enabled && !ansi.is_empty() {
        format!("{ansi}{sigil} {summary}\x1b[0m")
    } else {
        format!("{sigil} {summary}")
    };
    // Append per-field details under UpdateRunner.
    // Plan engine emits `field_changes` for recreate-bound fields whose
    // annotation reconstruction differs from the desired spec, and
    // `drop_in_changes` for every basename in the union of rendered +
    // discovered drop-ins. Both render as 4-space-indented lines beneath
    // the header so a reader scanning the plan sees the exact field-
    // level deltas without re-running the planner. Detail lines are not
    // colored — color is reserved for the action sigil line so
    // `grep`-on-color pipelines stay clean. Body diffs (Created /
    // Removed full body, Modified unified diff, Preserved marker) are
    // surfaced only under `--diff`.
    if let Action::UpdateRunner(d) = action {
        let mut out = header;
        for fc in &d.field_changes {
            out.push('\n');
            // render_text() preserves the v1 comma-joined format
            // for List-typed values so existing operator grep
            // pipelines (`grep "labels:.*gpu"`) keep working.
            out.push_str(&format!(
                "    {}: {} → {}",
                fc.path,
                fc.before.render_text(),
                fc.after.render_text(),
            ));
        }
        // No under-header gloss. Before the uncovered-arm decoupling the `uncovered` opaque
        // recreate-reason token had a `note: uncovered — …` gloss
        // line beneath the header; post-fix the uncovered arm in
        // `plan_from` falls through to in-place without pushing any
        // recreate reason, so the production vocabulary for
        // `recreate_reasons` is now strictly field-name tokens (url,
        // runner_version, labels, arch, runner_sha256, runner_tarball,
        // network). Field-name tokens already surface as before→after
        // rows above; no separate gloss adds value.
        // Recreate-class UpdateRunner has empty `drop_in_changes` by
        // design (plan.rs short-circuits the per-basename diff when
        // `requires_recreate` is true — every drop-in is rebuilt from
        // scratch). Under `--diff`, surface the post-recreate body
        // anyway by treating each entry in `delta.after.drop_ins` as
        // Created. Without --diff the brief view stays unchanged
        // (header only).
        if diff && d.requires_recreate {
            for (basename, body) in &d.after.drop_ins {
                out.push('\n');
                out.push_str(&format!("    + {basename}"));
                // Route through the same
                // render_drop_in_body_block as in-place Created
                // entries. The synthesized DropInChangeKind::Created
                // carries the post-render body verbatim — one
                // function, one format, no recreate-vs-in-place
                // body-block divergence.
                let synthesized = plan::DropInChangeKind::Created {
                    after: body.clone(),
                };
                let block = render_drop_in_body_block(&synthesized, color);
                if !block.is_empty() {
                    out.push('\n');
                    out.push_str(&block);
                }
            }
            // Surface drop-ins the recreate will DELETE. For
            // each basename present in the discovered pre-update set
            // (`d.before_drop_in_basenames`) but absent from the
            // post-recreate set (`d.after.drop_ins`), emit a `-
            // basename` line. Basename-only — no body block — to
            // avoid the credential-leakage surface for proxy creds
            // (e.g. operator's `99-custom.conf` may have referenced
            // sensitive Environment= values).
            //
            // `None` ⇒ "unknown pre-state" (test fixture or any
            // future construction site without a `DiscoveredRunner`);
            // SUPPRESS the Removed section rather than risk a
            // misleading silence.
            // `Some(vec![])` ⇒ "known empty pre-state"; loop is a
            // no-op naturally.
            if let Some(removed) = recreate_removed_basenames(d) {
                for basename in removed {
                    out.push('\n');
                    // Defense-in-depth escape of ASCII control
                    // bytes / ANSI escapes from the basename before
                    // stdout emission. Basenames are derived from
                    // on-disk filesystem entries discovered by
                    // `state::discover` walking the runner's drop-in
                    // directory; an attacker with write access there
                    // could craft a file named with `\x1b[…m` to
                    // manipulate the operator's terminal at
                    // plan-render time. Upstream `validate_drop_in`
                    // rejects such names at config-load, but
                    // discovery has no such gate — escape at the
                    // render site so operator sees a `\u{NN}` glyph
                    // instead of an active escape.
                    out.push_str(&format!("    - {}", escape_control_chars(basename),));
                }
            }
        } else {
            for dc in &d.drop_in_changes {
                // Surface Created / Modified / Removed in the
                // brief view so toggling a drop-in family (enabling
                // [proxy] → creates 60-proxy.conf, clearing
                // memory_max → removes 10-memory.conf) is visible
                // without reading the JSON payload or running with
                // `--diff`. Sigils use the create/modify/remove
                // subset of the Action sigil vocabulary
                // (+ create, ~ modified, - removed) so the operator's
                // eye picks the same shape. The Action-level `!`
                // (recreate UpdateRunner) has no drop-in analog.
                // Preserved is the
                // audit-trail "no edit" tag and stays out of the
                // brief view; under --diff it surfaces with an
                // explicit `(unchanged)` marker so operators can
                // confirm the no-edit verdict from the operator-
                // visible plan output rather than parsing JSON.
                let sigil_basename = match dc.change {
                    plan::DropInChangeKind::Created { .. } => Some(('+', dc.basename.as_str())),
                    plan::DropInChangeKind::Modified { .. } => Some(('~', dc.basename.as_str())),
                    plan::DropInChangeKind::Removed { .. } => Some(('-', dc.basename.as_str())),
                    plan::DropInChangeKind::Preserved => {
                        if diff {
                            Some((' ', dc.basename.as_str()))
                        } else {
                            None
                        }
                    }
                };
                if let Some((sigil, basename)) = sigil_basename {
                    out.push('\n');
                    // Same defense-in-depth basename
                    // escape as the recreate-Removed path at line ~1396.
                    // Drop-in basenames originate from on-disk
                    // filesystem entries via state::discover; an
                    // attacker with write access to the runner's
                    // drop-in directory could craft a file named
                    // `\x1b[…m` to hijack the operator's terminal at
                    // plan-render time. Symmetric coverage with the
                    // recreate path closes the asymmetry adversary
                    // findings raised.
                    out.push_str(&format!("    {sigil} {}", escape_control_chars(basename),));
                    if diff {
                        let block = render_drop_in_body_block(&dc.change, color);
                        if !block.is_empty() {
                            out.push('\n');
                            out.push_str(&block);
                        }
                    }
                }
            }
        }
        return out;
    }
    header
}

/// Render the `--diff` body payload for one `DropInChange`.
/// Returned as a string starting with the indented body content
/// (no leading newline — the caller decides how to glue the block
/// onto the preceding sigil line). Trailing newline is trimmed.
///
/// `color` controls only the Modified unified-diff path: when
/// enabled, `+` lines wrap in green and `-` lines wrap in red
/// (matches `git diff` / GNU `diff --color`). `@@` hunk headers
/// and context lines stay uncolored so `grep '^+'` on stripped
/// output still matches.
///
/// Output shapes (body content indented 12 spaces inside an 8-space
/// fence header so the content visually nests under the basename
/// sigil line):
///
/// - `Created { after }`: `        after:` header, then indented body.
/// - `Removed { before }`: `        before:` header, then indented body.
/// - `Modified { before, after }`: a unified diff via
///   `similar::udiff::unified_diff(Algorithm::Myers, ..., 3,
///   Some(("on-disk", "desired")))` — 3-line context (matches GNU
///   `diff -u3`). The `on-disk` / `desired` labels make the
///   in-memory-vs-disk semantics explicit (the `before` is the
///   discovered drop-in body, the `after` is the post-render bytes
///   ghars-apply will write); avoids the temporal-vs-spatial
///   ambiguity of `before`/`after` header labels.
/// - `Preserved`: a single `(unchanged)` marker line so operators
///   can confirm the no-edit verdict without parsing JSON.
///
/// # Security
///
/// This function is the sole chokepoint for body-block emission on
/// the text-mode `ghars plan --diff` path. Body content rendered
/// here may contain sensitive values from the operator's TOML —
/// for example, `60-proxy.conf` carries `Environment=HTTP_PROXY=
/// http://user:pass@host` when the operator configures an
/// authenticated proxy. Text output of `ghars plan --diff` should
/// not be uploaded to shared artifacts (CI logs, pastebins, ticket
/// attachments) without redaction. Symmetric with the `# Security`
/// caveat on `plan_to_json_value`. SEC-NEW: --diff body output may
/// expose proxy credentials from 60-proxy.conf.
pub(super) fn render_drop_in_body_block(kind: &plan::DropInChangeKind, color: ColorMode) -> String {
    let mut out = String::new();
    match kind {
        plan::DropInChangeKind::Preserved => {
            out.push_str("        (unchanged)\n");
        }
        plan::DropInChangeKind::Created { after } => {
            out.push_str("        after:\n");
            push_indented_body(&mut out, after);
        }
        plan::DropInChangeKind::Removed { before } => {
            out.push_str("        before:\n");
            push_indented_body(&mut out, before);
        }
        plan::DropInChangeKind::Modified { before, after } => {
            // Header labels follow the in-memory-vs-disk comparison
            // semantics: `on-disk` is the discovered drop-in body
            // (the `before`), `desired` is the post-render bytes
            // ghars-apply will write (the `after`). Avoids the
            // ambiguity of `before`/`after` which read as temporal
            // when the comparison is actually spatial (filesystem
            // vs. plan output).
            let unified = similar::udiff::unified_diff(
                similar::Algorithm::Myers,
                before.as_str(),
                after.as_str(),
                3,
                Some(("on-disk", "desired")),
            );
            push_indented_unified_diff(&mut out, &unified, color);
        }
    }
    while out.ends_with('\n') {
        out.pop();
    }
    out
}

/// Append `body` to `out`, prefixing every non-empty line with 12
/// spaces (the drop-in body indent: twice the basename-line indent).
/// Each line is terminated with `\n` regardless of whether the
/// input was newline-terminated, so the caller can append an
/// `after:` block immediately after a `before:` block without
/// inserting glue. Empty input ⇒ no output.
///
/// Each line passes through `escape_control_chars` before
/// emission. The body content originates from operator-authored
/// drop-in files (`Created.after`, `Removed.before`); operator-
/// supplied bodies could contain raw C0/DEL bytes that would
/// otherwise reach the operator's terminal under `--diff` and
/// hijack rendering. Defense-in-depth scrub at the per-line level
/// keeps both the indent prefix (12 spaces, pure printable ASCII)
/// and the line-terminating `\n` (intentional, structural) intact
/// — only the line CONTENT is escaped. The body's own newlines
/// already separate visible lines via the `body.lines()` iterator.
pub(super) fn push_indented_body(out: &mut String, body: &str) {
    if body.is_empty() {
        return;
    }
    // `lines()` strips trailing newlines per line and skips the
    // empty trailing line when the input ends with `\n`. That gives
    // us a single `\n`-terminated emit per visible line — the
    // ambiguity around trailing-newline-or-not in the input goes
    // away.
    for line in body.lines() {
        if line.is_empty() {
            out.push('\n');
        } else {
            out.push_str("            ");
            out.push_str(&escape_control_chars(line));
            out.push('\n');
        }
    }
}

/// Append a unified-diff `body` (output of
/// `similar::udiff::unified_diff`) to `out` with the standard
/// 12-space drop-in body indent. When `color.enabled` is true,
/// `+`-prefixed lines wrap in green and `-`-prefixed lines wrap
/// in red — matching `git diff` / GNU `diff --color` so operator
/// muscle memory transfers. `@@` hunk headers and context lines
/// stay uncolored.
///
/// The ANSI wrap goes INSIDE the indent prefix so a `grep '^    '`
/// pipe that strips the indent keeps the bare `+`/`-` first
/// character intact for downstream `grep '^+'` matchers.
///
/// `similar::udiff::unified_diff` is invoked with
/// `Some(("on-disk", "desired"))` in this codebase, so the body
/// starts with `--- on-disk` and `+++ desired` header lines. The
/// `^---`/`^+++` distinction matters: those header lines must NOT
/// be color-wrapped (matches `git diff --color`'s convention of
/// bold/cyan headers, not red/green). The branch order below
/// checks the multi-char `+++`/`---` prefixes BEFORE the
/// single-char `+`/`-` so headers route correctly.
pub(super) fn push_indented_unified_diff(out: &mut String, body: &str, color: ColorMode) {
    if body.is_empty() {
        return;
    }
    for line in body.lines() {
        if line.is_empty() {
            out.push('\n');
            continue;
        }
        out.push_str("            ");
        // Scrub control bytes from the diff line CONTENT
        // before any color wrapping. Diff lines are derived from
        // operator-authored drop-in bodies (the `before`/`after`
        // strings passed to `similar::udiff::unified_diff`); a
        // hostile body line could embed raw `\x1b` that would
        // otherwise hijack the operator's terminal under `--diff`.
        // Escape FIRST so legitimate sigil characters (`+`/`-`/
        // `@`) — none of which are control chars — survive the
        // `starts_with` checks below; then wrap with our own
        // legitimate ANSI green/red bytes for the color path. The
        // 12-space indent prefix and the line-terminating `\n`
        // are written outside this branch and stay structural.
        let scrubbed = escape_control_chars(line);
        let line_ref = scrubbed.as_ref();
        if color.enabled {
            // ANSI wraps the line content (including its sigil)
            // so the colored bytes start AFTER the indent — that
            // way `awk '$1=="+" {print}'` on a stripped pipeline
            // still matches by treating the first column as the
            // sigil character.
            if line_ref.starts_with("+++") || line_ref.starts_with("---") {
                // Header lines from a future similar revision —
                // leave uncolored to match git diff's `--color`
                // convention (those lines are bold/cyan there,
                // not red/green).
                out.push_str(line_ref);
            } else if line_ref.starts_with('+') {
                out.push_str("\x1b[32m");
                out.push_str(line_ref);
                out.push_str("\x1b[0m");
            } else if line_ref.starts_with('-') {
                out.push_str("\x1b[31m");
                out.push_str(line_ref);
                out.push_str("\x1b[0m");
            } else {
                out.push_str(line_ref);
            }
        } else {
            out.push_str(line_ref);
        }
        out.push('\n');
    }
}

/// Build the text-mode plan summary footer.
///
/// Format:
/// `Plan: N actions (N restart, N recreate, N none). any_recreate: true|false`
///
/// The label vocabulary mirrors the JSON `summary.by_disruption`
/// keys so a single `grep any_recreate` matches both surfaces.
/// Order is restart → recreate → none (most-actionable-first for
/// operator scanning), distinct from
/// `disruption_summary_variants()`'s least-to-most-disruptive order
/// used for the JSON-key iteration. The disruption parenthetical
/// + `any_recreate` suffix is delegated to
/// `format_disruption_tail` — the single source of truth
/// for the format string shared with `render_apply_summary_line`.
#[must_use]
pub(super) fn render_plan_summary_line(actions: &[Action]) -> String {
    let mut none_count: u64 = 0;
    let mut restart_count: u64 = 0;
    let mut recreate_count: u64 = 0;
    for a in actions {
        match a.disruption() {
            plan::Disruption::None => none_count += 1,
            plan::Disruption::Restart => restart_count += 1,
            plan::Disruption::Recreate => recreate_count += 1,
        }
    }
    format!(
        "Plan: {total} actions {tail}",
        total = actions.len(),
        tail = format_disruption_tail(none_count, restart_count, recreate_count),
    )
}

/// Build the shared `(N restart, N recreate, N none).
/// any_recreate: bool` tail used by both `render_plan_summary_line`
/// and `render_apply_summary_line`. Single source of truth for the
/// disruption-parenthetical + `any_recreate` suffix format string,
/// so a future rename of any `Disruption::label()` token or the
/// `any_recreate` key propagates to both surfaces without a parallel
/// edit.
///
/// Order is restart → recreate → none
/// (most-actionable-first for operator scanning), matching both
/// callers. `any_recreate` is `true` ⇔ `recreate > 0`.
#[must_use]
pub(super) fn format_disruption_tail(none: u64, restart: u64, recreate: u64) -> String {
    let any_recreate = recreate > 0;
    format!(
        "({restart} {restart_label}, {recreate} {recreate_label}, \
         {none} {none_label}). any_recreate: {any_recreate}",
        restart = restart,
        restart_label = plan::Disruption::Restart.label(),
        recreate = recreate,
        recreate_label = plan::Disruption::Recreate.label(),
        none = none,
        none_label = plan::Disruption::None.label(),
        any_recreate = any_recreate,
    )
}

/// Build the text-mode apply summary footer. Symmetric with
/// `render_plan_summary_line` on the disruption parenthetical and
/// `any_recreate` suffix; the headline triple
/// (`applied/failed/skipped`) is apply-specific.
///
/// Format:
/// `Apply: A applied, F failed, S skipped (R restart, K recreate, N none). any_recreate: true|false`
///
/// **Outcome-class buckets** (the headline `A applied, F failed, S
/// skipped` triple):
/// - `failed` — `ApplyOutcome::Failed` rows. Includes both
///   per-action handler failures and the synthetic `daemon_reload`
///   Failed row when Manager.Reload itself errored.
/// - `skipped` — outcomes that returned `Ok` but performed no host
///   mutation: `NoOp`, `DryRunSkipped`, `InPlaceSkipped`,
///   `PoolSkipped`. These four variants are the apply-time outcomes
///   that returned Ok with no host mutation. Failed rows always go
///   in `failed` regardless of their `plan_disruption`.
/// - `applied` — host-mutating outcomes: `Created`, `Removed`,
///   `Recreated`, `InPlaceRestarted`, `PoolCreated`, `PoolUpdated`,
///   `PoolRemoved`. The match arm enumerates these explicitly (not a
///   wildcard) so a future variant addition forces a compile-time
///   bucketing decision instead of silently defaulting to `applied`.
///
/// **Disruption parenthetical** (`R restart, K recreate, N none`):
/// derived from each outcome's `disruption()` method. Same vocabulary
/// as the plan footer so operators reading both surfaces get
/// consistent terminology. Includes BOTH successful and failed rows
/// (`Failed.disruption()` returns the action's plan-time worst-case —
/// recreate-class actions stay tagged recreate even when they
/// errored), so a partially-applied recreate-class action that
/// errored mid-way still contributes to the `recreate` count.
/// Delegated to `format_disruption_tail` — single source of
/// truth for the format string shared with `render_plan_summary_line`.
///
/// **`any_recreate`**: true ⇔ any outcome's `disruption()` is
/// `Recreate`. Includes failed Recreate-class actions, matching the
/// plan footer's definition (recreate-class = blast radius class).
///
/// Order is restart → recreate → none (most-actionable-first for
/// operator scanning), matching `render_plan_summary_line`.
///
/// **`fail_fast` caveat**: under `ApplyOptions::fail_fast`, the loop
/// short-circuits on the first action error and unprocessed actions
/// are absent from `result.details` (see the per-action loop's
/// `fail_fast` short-circuit in `apply()`). The footer total
/// (`applied + failed + skipped`) may therefore be less than the
/// originating plan's action count.
#[must_use]
pub(super) fn render_apply_summary_line(result: &apply::ApplyResult) -> String {
    let mut applied: u64 = 0;
    let mut failed: u64 = 0;
    let mut skipped: u64 = 0;
    let mut none_count: u64 = 0;
    let mut restart_count: u64 = 0;
    let mut recreate_count: u64 = 0;
    for (_, outcome) in &result.details {
        match outcome {
            apply::ApplyOutcome::Failed { .. } => failed += 1,
            apply::ApplyOutcome::NoOp
            | apply::ApplyOutcome::DryRunSkipped
            | apply::ApplyOutcome::InPlaceSkipped
            | apply::ApplyOutcome::PoolSkipped => skipped += 1,
            apply::ApplyOutcome::Created
            | apply::ApplyOutcome::Removed
            | apply::ApplyOutcome::Recreated
            | apply::ApplyOutcome::InPlaceRestarted { .. }
            | apply::ApplyOutcome::PoolCreated
            | apply::ApplyOutcome::PoolUpdated
            | apply::ApplyOutcome::PoolRemoved => applied += 1,
        }
        match outcome.disruption() {
            plan::Disruption::None => none_count += 1,
            plan::Disruption::Restart => restart_count += 1,
            plan::Disruption::Recreate => recreate_count += 1,
        }
    }
    format!(
        "Apply: {applied} applied, {failed} failed, {skipped} skipped {tail}",
        applied = applied,
        failed = failed,
        skipped = skipped,
        tail = format_disruption_tail(none_count, restart_count, recreate_count),
    )
}

/// Render every `cmd_apply` post-execution stdout/stderr line for a
/// completed `ApplyResult` to the supplied writers. Splits into three
/// emission sections, all routed by stream.
///
/// **Stream routing**: `noop:` + `ok:` + summary footer → stdout;
/// `fail:` + rollback advisory → stderr.
///
/// **Error semantics**: Returns `Err` on the first write failure to
/// either stream; remaining lines are NOT emitted. The sole
/// production caller swallows the error (`let _ = ...`) so the
/// effective semantics at the call site stay best-effort even though
/// this function short-circuits on first error.
///
/// 1. **Per-action detail loop** (`result.details`, in execution order):
///    - `NoOp(REASON)` → stdout: `noop: REASON [none]` (label-strip
///      collapses the otherwise-verbose `ok: NoOp(REASON) [none]
///      (noop (in sync))` double-tag — the parenthesized REASON
///      inside the label is the operator-facing string).
///    - `Failed { .. }` → STDERR: `fail: LABEL [disruption] (error)`.
///    - all 10 non-NoOp non-Failed `ApplyOutcome` variants → stdout:
///      `ok: LABEL [disruption] (detail)`. Listed exhaustively in
///      the per-action match arm (no wildcard), so adding a new
///      `ApplyOutcome` variant is a compile error here.
///    The `[disruption]` bracket tag (`[none]`/`[restart]`/`[recreate]`)
///    reuses the plan-output vocabulary from `render_action_line` so
///    a single `grep [recreate]` matches
///    both surfaces.
///
/// 2. **Apply summary footer** ([`render_apply_summary_line`]) → stdout.
///    Symmetric with `render_plan_summary_line` (same disruption
///    vocabulary, same applied/failed/skipped+tail format). Emitted
///    after the per-action lines so operators see the rollup at the
///    bottom of the apply output.
///
/// 3. **Rollback advisory** ([`render_rollback_advisory`]) → STDERR.
///    Gated on the renderer returning `Some(...)` so successful
///    applies (and applies whose only failure was a synthetic
///    `daemon_reload` with no recorded undo steps) emit no extra noise.
///    Belongs with the `fail:` rows on stderr, not the success-path
///    summary on stdout.
///
/// **Stream-routing contract**: `noop:` and `ok:` lines plus the
/// summary footer go to `stdout`; `fail:` lines plus the rollback
/// advisory go to `stderr`. Tests pass capture buffers (`&mut Vec<u8>`)
/// for both streams so the routing is verifiable without a TTY.
///
/// `result.failed` retains the typed `GharsError` chain for
/// programmatic consumers (exit-code mapping, undo log advisory); the
/// per-action rendering loop reads `result.details` exclusively, per
/// the contract documented at [`apply::ApplyResult::details`].
pub(super) fn render_apply_emission(
    result: &apply::ApplyResult,
    stdout: &mut impl std::io::Write,
    stderr: &mut impl std::io::Write,
) -> std::io::Result<()> {
    for (label, outcome) in &result.details {
        match outcome {
            apply::ApplyOutcome::NoOp => {
                let reason = label
                    .strip_prefix("NoOp(")
                    .and_then(|s| s.strip_suffix(')'))
                    .unwrap_or(label.as_str());
                // Hardcoded `[none]` for shape parity with `ok:`/`fail:`
                // bracket tags — operators parse all rows with one regex.
                writeln!(stdout, "noop: {reason} [none]")?;
            }
            apply::ApplyOutcome::Failed { .. } => {
                writeln!(
                    stderr,
                    "fail: {label} [{}] ({})",
                    outcome.disruption().label(),
                    outcome.detail(),
                )?;
            }
            // Success/skip variants — route through ok: template. Exhaustive
            // so a future variant addition forces a compile-time routing decision.
            apply::ApplyOutcome::InPlaceSkipped
            | apply::ApplyOutcome::InPlaceRestarted { .. }
            | apply::ApplyOutcome::Recreated
            | apply::ApplyOutcome::Created
            | apply::ApplyOutcome::Removed
            | apply::ApplyOutcome::PoolCreated
            | apply::ApplyOutcome::PoolUpdated
            | apply::ApplyOutcome::PoolSkipped
            | apply::ApplyOutcome::PoolRemoved
            | apply::ApplyOutcome::DryRunSkipped => {
                writeln!(
                    stdout,
                    "ok: {label} [{}] ({})",
                    outcome.disruption().label(),
                    outcome.detail(),
                )?;
            }
        }
    }
    writeln!(stdout, "{}", render_apply_summary_line(result))?;
    if let Some(advisory) = render_rollback_advisory(result) {
        writeln!(stderr, "{advisory}")?;
    }
    Ok(())
}

/// Render the rollback-state advisory for a failed `apply` run,
/// or `None` when no action failed (success path emits no advisory).
/// The advisory walks `result.failed_undo_logs` (populated by
/// `apply()` on every Err path) and produces a multi-line block:
///
/// ```text
/// Rollback advisory: N action(s) failed. Manual cleanup may be required:
///   LABEL_A:
///     - started ghars-runner@foo.service
///     - wrote /etc/systemd/system/ghars-runner@foo.service.d/00-ghars.conf
///   LABEL_B:
///     - created directory /etc/systemd/system/ghars-cache@build.service.d
/// ```
///
/// Per-step descriptions come from [`apply::UndoStep::describe`] —
/// past-tense, byte-content omitted, operator-readable. Steps are
/// listed in REVERSE (LIFO) order — the most recent mutation first —
/// matching the iteration direction of [`apply::undo`] (apply.rs's
/// `log.steps().iter().rev()`). The intent: an operator reading
/// top-to-bottom can apply the inverse of each line and unwind the
/// state in the same order [`apply::undo`] would have, regardless of
/// whether `--rollback-on-failure` ran. The verb tokens below come
/// verbatim from [`apply::UndoStep::describe`] — left column matches
/// the past-tense strings that function emits for each variant
/// (`wrote`, `removed file`, `created directory`, …). Right column
/// is the operator inverse, NOT what `apply::undo` runs (some
/// inverses are reverse-direction and skipped per
/// [`apply::UndoStep::is_reverse_direction`]; see "(lossy)" /
/// "re-run `apply`" entries). When `describe()` gains a variant or
/// changes a verb, this table MUST be updated in lockstep:
/// - `wrote PATH`              → `rm PATH`
/// - `removed file PATH`       → restore from backup (lossy)
/// - `created directory PATH`  → `rmdir PATH`
/// - `removed directory PATH`  → re-run `apply` to recreate
/// - `started UNIT`            → `systemctl stop UNIT`
/// - `stopped UNIT`            → `systemctl start UNIT`
/// - `enabled UNIT`            → `systemctl disable UNIT`
/// - `disabled UNIT`           → `systemctl enable UNIT`
/// - `registered runner NAME …` → `config.sh remove --token <fresh>`
/// - `chmod PATH (was 0oMODE)` → `chmod 0oMODE PATH`
/// - `chown PATH (was UID:GID)` → `chown UID:GID PATH`
///
/// Entries with empty step lists (synthetic `daemon_reload` post-loop
/// failure; actions that errored before recording any side effect)
/// are skipped from the per-label block. Header N counts ONLY entries
/// with non-empty step lists, so header count == body block count
/// under the mixed case (some empty + some non-empty); empty-step
/// failures still surface via the per-action `fail:` lines from the
/// `cmd_apply` detail loop.
///
/// Invariant: `result.failed.len() == result.failed_undo_logs.len()`.
/// `apply::apply` pushes both Vecs in lockstep on every Err arm
/// (per-action arm and synthetic `daemon_reload` arm in apply.rs).
/// The lengths can only diverge in hand-constructed `ApplyResult`
/// test fixtures. `debug_assert_eq!` pins the contract in dev/CI
/// builds; release builds proceed because `n` (the header count)
/// and the body loop both derive from `failed_undo_logs`
/// independently of `failed`.
///
/// Returns `None` when no entry in `failed_undo_logs` has a
/// non-empty step list. A single gate (`n == 0` after filtering)
/// covers both the no-failures case (`result.failed.is_empty()` ⇒
/// length-equal invariant ⇒ `failed_undo_logs.is_empty()` ⇒ `n == 0`)
/// and the all-empty-steps case (synthetic `daemon_reload` post-loop
/// failure; actions that errored before recording any side effect ⇒
/// every entry filtered out ⇒ `n == 0`). Returning `None` keeps
/// stderr clean — the per-action `fail:` lines from the `cmd_apply`
/// detail loop already communicate the failure count and labels;
/// the advisory's purpose is "what to clean up", and silence is
/// more honest than a header rendered by
/// [`format_rollback_advisory_header`] without a body. Pure function
/// (no I/O); the caller (`cmd_apply`) routes the returned text to
/// stderr.
#[must_use]
pub(crate) fn render_rollback_advisory(result: &apply::ApplyResult) -> Option<String> {
    debug_assert_eq!(
        result.failed.len(),
        result.failed_undo_logs.len(),
        "ApplyResult invariant: failed and failed_undo_logs must have equal length",
    );
    // Header N counts ONLY entries with non-empty step lists so the
    // printed count matches the body block count under the mixed
    // case (some empty + some non-empty). This single count subsumes
    // both prior early-return paths: `result.failed.is_empty()` ⇒
    // (length-equal invariant) ⇒ `failed_undo_logs.is_empty()` ⇒
    // `n == 0`; ALL-empty step lists ⇒ `n == 0`. One gate covers both.
    let n = result
        .failed_undo_logs
        .iter()
        .filter(|(_, steps)| !steps.is_empty())
        .count();
    if n == 0 {
        return None;
    }
    let mut out = format_rollback_advisory_header(n);
    for (label, steps) in &result.failed_undo_logs {
        if steps.is_empty() {
            continue;
        }
        // Defense-in-depth escape of the per-failure label.
        // Labels flow from `Action::label()` → `result.failed_undo_logs`
        // keys, derived from operator-supplied runner names and pool
        // names. Upstream `IDENTIFIER_REGEX` rejects control chars at
        // config-load time, so the only path to a hostile label today
        // would require a regex relaxation. Escaping at the render
        // site closes that asymmetry — the per-step bullets below
        // already escape via `step.describe()` + the per-step
        // `escape_control_chars` call inside the step-loop body
        // further down this function, so the label needed parity
        // coverage.
        out.push_str("\n  ");
        out.push_str(&escape_control_chars(label));
        out.push(':');
        // Walk steps in REVERSE (LIFO) to match apply::undo's
        // `log.steps().iter().rev()` direction. The operator's
        // manual-cleanup checklist reads top-to-bottom and undoes
        // the most-recent mutation first.
        //
        // Defense-in-depth escape of the per-step description
        // before stderr emission. `UndoStep::describe()` interpolates
        // operator-supplied paths (drop-in basenames built from runner
        // names) and unit/group/user names; upstream charset
        // validators reject control chars at config-load and
        // render-identity time, but a renderer-side scrub means a
        // future relaxation in those validators cannot leak ANSI
        // escapes into the rollback advisory.
        for step in steps.iter().rev() {
            out.push_str("\n    - ");
            out.push_str(&escape_control_chars(&step.describe()));
        }
    }
    Some(out)
}

/// Single source of truth for the advisory header line in
/// production code. Extracting the format string behind a named
/// function means a future text change ("Rollback advisory:" /
/// "Manual cleanup may be required:") happens in one place at the
/// call site, not scattered across every renderer (mirrors the
/// pattern that lifted Disruption-label tokens behind
/// `Disruption::label()`). Tests
/// continue to hardcode the operator-visible substrings — that's
/// correct for contract pinning: a test that calls this helper
/// would silently pass after a header rename, while a substring
/// assertion fails loudly and signals the operator-visible break.
///
/// Naming follows the project's `format_*` precedent for pure
/// string-building helpers (e.g. `format_disruption_tail` /
/// peers in `render_plan_summary_line`).
pub(super) fn format_rollback_advisory_header(n: usize) -> String {
    format!("Rollback advisory: {n} action(s) failed. Manual cleanup may be required:")
}
