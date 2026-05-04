//! Exit-code mapping helpers (Part 5 of the design spec).
//!
//! Pure functions — no I/O — so tests can pin the truth tables
//! without spinning up D-Bus or the apply runtime.

use crate::apply;
use crate::error::GharsError;
use crate::plan::{self, Action, Plan};
use crate::preflight;

/// Map a top-level `GharsError` to its Part 5 process exit code.
///
/// Called by `main.rs` when `dispatch` returns `Err`. Extracted as a
/// pub function so the mapping can be unit-tested against every
/// variant without spawning a child process. (main.rs is a separate
/// `[[bin]]` target; the binary calls into the lib via `ghars::cli::`.)
///
/// Per-variant mapping (Part 5):
/// - `Config(_, _)`           → 6 (config parse / shape error)
/// - `Validation(_, _)`       → 6 (config-shape rejection: `trust_zone`
///   charset, duplicate caches, `render_identity` defense-in-depth —
///   operator must edit the TOML to recover, same actionable class
///   as Config)
/// - `Interactive(_, _)`      → 7 (`confirm_apply` on non-TTY
///   stdin; distinct from 6 so wrapping scripts can branch on
///   "config is broken" vs "apply needs --auto-approve" without
///   parsing the error message)
/// - `Auth(_, _)`             → 5 (auth-resolve failure outside the
///   per-action accounting; same exit code per-action auth failures
///   route to via `apply_exit_code`)
/// - `Preflight(_, _)`        → 3 (preflight check failure; same
///   exit code `cmd_apply` / `cmd_status` emit via `Ok(3)`)
/// - `GitHub(_, _)`           → 1 (API error)
/// - `Systemd(_, _)`          → 1 (D-Bus / unit error)
/// - `Apply { .. }`           → 1 (should never reach here — apply
///   collects per-action failures into `ApplyResult` and routes
///   through `apply_exit_code`; this arm is the unreachable-by-design
///   safety net)
/// - `Io(_)`                  → 1 (filesystem)
/// - `Tarball(_)`             → 1 (extraction failure)
/// - `Sha256Mismatch { .. }`  → 1 (digest mismatch)
/// - `ApplyLocked { .. }`     → 1 (lock contention)
///
/// The mapping uses an exhaustive `match` (no wildcard) so any future
/// `GharsError` variant addition forces a compile error here, surfacing
/// the design decision at code-review time rather than silently
/// routing a new variant to the catch-all.
#[must_use]
pub fn err_to_exit_code(err: &GharsError) -> i32 {
    match err {
        GharsError::Config(_, _) => 6,
        GharsError::Validation(_, _) => 6,
        GharsError::Interactive(_, _) => 7,
        GharsError::Auth(_, _) => 5,
        GharsError::Preflight(_, _) => 3,
        GharsError::GitHub(_, _) => 1,
        GharsError::Systemd(_, _) => 1,
        GharsError::Apply { .. } => 1,
        GharsError::Io(_) => 1,
        GharsError::Tarball(_, _) => 1,
        GharsError::Sha256Mismatch { .. } => 1,
        GharsError::ApplyLocked { .. } => 1,
    }
}

/// Map (`--quiet`, `-v` count) → tracing-subscriber level filter
/// string. Pure function so the truth table is exhaustively testable.
///
/// Mapping:
/// - `quiet=true,  verbose=0` → "warn"  (suppress info-level chatter)
/// - `quiet=false, verbose=0` → "info"  (default)
/// - any verbose>=1           → "debug" / "trace" regardless of quiet
///
/// `-v` overrides `--quiet` when both are passed because the operator
/// who passed both is asking for MORE verbosity, not less. This
/// matches the convention of GNU coreutils (`tar -v --quiet`) and
/// rsync.
///
/// Used by `main.rs` to compose the `EnvFilter` fallback when
/// `RUST_LOG` is not set; `RUST_LOG` always wins when present.
#[must_use]
pub fn verbose_to_filter_level(quiet: bool, verbose: u8) -> &'static str {
    if quiet && verbose == 0 {
        return "warn";
    }
    match verbose {
        0 => "info",
        1 => "debug",
        _ => "trace",
    }
}

/// Map a slice of `preflight::CheckResult` to the `ghars status`
/// process exit code per Part 5.
///
/// - any `Outcome::Fail` in `health` → 3 (preflight/validation failure)
/// - otherwise → 0
///
/// Pure function (no I/O); pulled out so tests can synthesize health
/// vectors without a real preflight scan. Both
/// `render_status_text` and `render_status_json` delegate to keep the
/// same exit-code contract regardless of output format.
#[must_use]
pub(super) fn status_exit_code(health: &[preflight::CheckResult]) -> i32 {
    if health
        .iter()
        .any(|c| matches!(c.outcome, preflight::Outcome::Fail))
    {
        3
    } else {
        0
    }
}

/// Returns `Some(8)` when the operator opted into
/// `--detailed-exitcode-recreate` AND the plan contains a recreate-
/// class action; otherwise `None` so callers fall through to the
/// existing `--detailed-exitcode` / default-0 logic.
///
/// Plan-side recreate gate. Three lexical direct callers:
/// 1. `cmd_apply` pre-confirm gate (fires BEFORE `confirm_apply` runs,
///    regardless of `--auto-approve`),
/// 2. `cancel_exit_code` (apply-cancel surface),
/// 3. `dry_run_exit_code` (plan + apply-dry-run surfaces).
///
/// CLI surfaces map onto these callers via direct + transitive routing:
/// the `cmd_apply` pre-confirm gate calls this helper directly;
/// `cmd_plan` and `cmd_apply --dry-run` reach it transitively through
/// `dry_run_exit_code`; `cmd_apply`'s cancel path reaches it
/// transitively through `cancel_exit_code`; the post-apply success
/// path reaches NEITHER this helper NOR a delegating wrapper.
///
/// The post-apply path (`apply_exit_code`) does NOT delegate here: it
/// inlines an equivalent `Disruption::Recreate` check against
/// `result.details` (apply-time outcomes) instead of `plan.actions`
/// (plan-time declarations). The two data sources are equivalent for
/// the recreate signal because [`crate::plan::Action::disruption`] and
/// [`crate::apply::ApplyOutcome::disruption`] both return
/// [`crate::plan::Disruption::Recreate`] for the same set of variants.
///
/// Returning `Option` instead of a plain `i32` lets the caller chain
/// `.or_else(|| ...)` with the existing helpers without sprinkling
/// early returns across the command-dispatch path.
#[must_use]
pub(super) fn recreate_exit_code(detailed_exitcode_recreate: bool, plan: &Plan) -> Option<i32> {
    if detailed_exitcode_recreate && plan.has_recreate() {
        Some(8)
    } else {
        None
    }
}

/// Process exit code when the operator cancels at the apply prompt
/// (`y/N` answered N). Pulled out so tests can pin the contract
/// without driving the `cmd_apply` path through a TTY mock.
///
/// Precedence:
/// - `--detailed-exitcode-recreate` set + recreate-class action in
///   `plan` → 8. "Plan contains a recreate the operator must
///   review; do not auto-merge."
/// - else `--detailed-exitcode` set → 2. The plan had pending
///   changes the operator chose not to apply; 2 communicates "diff
///   present, not applied" — terraform-class signal that wrapping
///   scripts can branch on without parsing stderr.
/// - else → 0. Cancelling an interactive prompt is the established
///   CLI convention for "user aborted; not an error".
///
/// Recreate trumps detailed-changes: when both flags fire, 8 is
/// strictly more informative than 2 (recreate implies pending
/// changes, but pending changes do not imply recreate).
#[must_use]
pub(super) fn cancel_exit_code(
    detailed_exitcode: bool,
    detailed_exitcode_recreate: bool,
    plan: &Plan,
) -> i32 {
    if let Some(code) = recreate_exit_code(detailed_exitcode_recreate, plan) {
        return code;
    }
    if detailed_exitcode { 2 } else { 0 }
}

/// Process exit code for `apply --dry-run` (Part 5).
///
/// `--dry-run` is documented as an alias for `ghars plan`; with
/// `--detailed-exitcode`, exit 2 when the plan has any non-NoOp
/// action — terraform `plan -detailed-exitcode` parity. Pulled out
/// so tests pin the contract without spinning up a real D-Bus or
/// the apply runtime.
///
/// Precedence:
/// - `detailed_exitcode_recreate = true`, plan has recreate         → 8
/// - else `detailed_exitcode = false`                                → 0
/// - else `detailed_exitcode = true`, plan all-NoOp                  → 0
/// - else `detailed_exitcode = true`, plan has any non-NoOp action   → 2
#[must_use]
pub(super) fn dry_run_exit_code(
    detailed_exitcode: bool,
    detailed_exitcode_recreate: bool,
    plan: &Plan,
) -> i32 {
    if let Some(code) = recreate_exit_code(detailed_exitcode_recreate, plan) {
        return code;
    }
    if detailed_exitcode && plan.actions.iter().any(|a| !matches!(a, Action::NoOp(_))) {
        2
    } else {
        0
    }
}

/// Map an `ApplyResult` to the process exit code per Part 5.
///
/// Precedence (Part 5):
/// - partial failure         → 4  (some succeeded, some failed)
/// - total failure, any auth → 5
/// - total failure, no auth  → 1
/// - no failures, recreate-class action present + flag set → 8
/// - no failures             → 0  (or 2 with `--detailed-exitcode`)
///
/// Partial failure (4) wins over auth (5) when both apply because 4
/// communicates strictly more to the operator: "some actions landed,
/// others did not — go look at the per-action log". 5 is narrower
/// ("nothing landed, and at least one Auth error explains why");
/// collapsing a partial-success run to 5 would hide the partial
/// progress.
///
/// Failure precedence trumps recreate: both 4 and 5 are
/// stronger than 8. A partial apply leaves the operator with a
/// concrete cleanup task ("some actions landed"); a recreate flag
/// is a plan-shape signal about what the apply WOULD have done.
/// Surfacing 8 over 4 would hide the more-actionable "go check
/// what landed" signal. Same reasoning for 5: auth failure is a
/// structural pre-condition violation; recreate is downstream
/// plan-shape. Recreate (8) only fires on the success path
/// (`result.failed.is_empty()`).
///
/// Recreate detection uses [`apply::ApplyOutcome::disruption`] on
/// every entry of `result.details` so the same rule that drives the
/// `[recreate]` bracket tag also drives this exit-code branch —
/// single source of truth, no risk of plan-time/apply-time drift.
///
/// Pulled out as a pure function so tests synthesize `ApplyResult`
/// values and pin the precedence directly without spinning up D-Bus or
/// the apply runtime.
///
/// Parameter order matches the sibling `cancel_exit_code` /
/// `dry_run_exit_code` / `recreate_exit_code` helpers: detailed-exit
/// flags first, data payload last. A flag-first convention keeps the
/// call sites aligned with the underlying state-machine reading order
/// ("which gates are armed?" → "what does the data say?").
#[must_use]
pub(super) fn apply_exit_code(
    detailed_exitcode: bool,
    detailed_exitcode_recreate: bool,
    result: &apply::ApplyResult,
) -> i32 {
    if result.failed.is_empty() {
        if detailed_exitcode_recreate
            && result
                .details
                .iter()
                .any(|(_, o)| o.disruption() == plan::Disruption::Recreate)
        {
            return 8;
        }
        return if detailed_exitcode { 2 } else { 0 };
    }
    if !result.succeeded.is_empty() {
        return 4;
    }
    let any_auth = result
        .failed
        .iter()
        .any(|(_, e)| matches!(e, GharsError::Auth(_, _)));
    if any_auth { 5 } else { 1 }
}
