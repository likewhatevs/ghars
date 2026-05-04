//! Test module for cli/.
//!
//! Restored from the legacy single-file cli.rs layout. Fixtures stay
//! in this file (the parent of tests sub-files) so every chunk submodule
//! can reach them via `use super::*;` without duplication. Production
//! helpers from sibling cli/ submodules (cmd_*, json, load, render,
//! exit_codes, args) are re-exported here via wildcard `use` so the
//! tests retain the flat-namespace access pattern they had under the
//! original `mod tests { use super::*; }` shape.

#![allow(clippy::unwrap_used)]
#![allow(unused_imports)]

pub(crate) use super::dispatch;
pub(crate) use super::args::*;
pub(crate) use super::cmd_apply::*;
pub(crate) use super::cmd_metrics::*;
pub(crate) use super::cmd_misc::*;
pub(crate) use super::cmd_plan::*;
pub(crate) use super::cmd_status::*;
pub(crate) use super::exit_codes::*;
pub(crate) use super::json::*;
pub(crate) use super::load::*;
pub(crate) use super::render::*;

pub(crate) use std::fs;
pub(crate) use std::io::{self, IsTerminal};

pub(crate) use camino::{Utf8Path, Utf8PathBuf};
pub(crate) use clap::Parser;

pub(crate) use crate::Result;
pub(crate) use crate::apply;
pub(crate) use crate::config::Config;
pub(crate) use crate::error::GharsError;
pub(crate) use crate::paths::Paths;
pub(crate) use crate::plan::{self, Action, Plan};
pub(crate) use crate::preflight;
pub(crate) use crate::state;

/// Placeholder runsvc.sh SHA-256 digest for discovered-runner
/// fixtures. Concrete value is irrelevant to assertions —
/// `execute_remove_runner` does not consult the digest, and the
/// runsvc_wrapper trampoline runs only at runner start time. What
/// matters is that the value is non-empty: a populated annotation
/// mirrors the post-install steady state (a prior
/// `apply.rs::execute_create_runner` would have computed the
/// runsvc.sh digest and written it into the X-Ghars-Runsvc-Sha256
/// annotation in `00-ghars.conf`), distinct from the empty-
/// fallback path that `DiscoveredAnnotations::default` produces
/// when the drop-in is missing entirely.
///
/// 64 ones is a syntactically-valid 256-bit hex digest with no
/// collision risk against any real digest (no real runsvc.sh
/// hashes to all 1s).
const FIXTURE_RUNSVC_SHA256: &str =
    "sha256:1111111111111111111111111111111111111111111111111111111111111111";

fn add_args_for(repo: &str, name: Option<&str>, auth: Option<&str>) -> AddArgs {
    AddArgs {
        repo: repo.into(),
        name: name.map(String::from),
        labels: vec![],
        auth: auth.map(String::from),
        no_apply: true,
    }
}

fn write_minimal_config(path: &Utf8Path) {
    // Minimum viable config that load_config accepts: a defaults
    // block + an [auth.pat] entry the cmd_add validator can find.
    let body = "\
[defaults]

[auth.pat]
kind = \"pat\"
token_env = \"GHARS_PAT\"
";
    fs::write(path.as_std_path(), body).unwrap();
}

fn classify(result: &apply::ApplyResult, detailed_exitcode: bool) -> i32 {
    apply_exit_code(detailed_exitcode, false, result)
}

fn auth_err(msg: &str) -> GharsError {
    GharsError::Auth(msg.into(), "hint".into())
}

fn validation_err(msg: &str) -> GharsError {
    GharsError::Validation(msg.into(), "hint".into())
}

fn pass(name: &str) -> preflight::CheckResult {
    preflight::CheckResult {
        name: name.into(),
        outcome: preflight::Outcome::Pass,
        detail: "ok".into(),
        hint: String::new(),
    }
}

fn fail(name: &str) -> preflight::CheckResult {
    preflight::CheckResult {
        name: name.into(),
        outcome: preflight::Outcome::Fail,
        detail: "broken".into(),
        hint: "fix it".into(),
    }
}

fn warn(name: &str) -> preflight::CheckResult {
    preflight::CheckResult {
        name: name.into(),
        outcome: preflight::Outcome::Warn,
        detail: "advisory".into(),
        hint: "consider".into(),
    }
}

fn skip(name: &str) -> preflight::CheckResult {
    preflight::CheckResult {
        name: name.into(),
        outcome: preflight::Outcome::Skip,
        detail: "n/a".into(),
        hint: String::new(),
    }
}

fn fake_effective_spec(name: &str) -> crate::config::EffectiveRunnerSpec {
    crate::config::EffectiveRunnerSpec {
        name: name.into(),
        url: format!("https://github.com/example/{name}"),
        arch: crate::config::Arch::X86_64,
        labels: vec![name.into()],
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
        runsvc_sha256: String::new(),
        config_source: "/etc/ghars/ghars.toml".into(),
    }
}

fn fake_runner_plan(name: &str) -> plan::RunnerPlan {
    plan::RunnerPlan {
        spec: fake_effective_spec(name),
        resolved_release: None,
        effective_unit_text: String::new(),
        drop_ins: std::collections::BTreeMap::new(),
        spec_hash: "sha256:0".into(),
    }
}

fn fake_identity(name: &str) -> plan::RunnerIdentity {
    plan::RunnerIdentity {
        name: name.into(),
        url: format!("https://github.com/example/{name}"),
        auth_name: "pat".into(),
        trust_zone: "default".into(),
    }
}

fn fake_cache_binding(name: &str) -> crate::config::EffectiveCacheBinding {
    crate::config::EffectiveCacheBinding {
        name: name.into(),
        kinds: vec![crate::config::CacheKind::Ccache],
        size: "10G".into(),
        mode: crate::config::CacheMode::Shared,
        trust_zone: "default".into(),
    }
}

/// Build a recreate-class `RunnerDelta` with the given name +
/// recreate_reasons. All other fields default to the same values
/// callers would otherwise inline. Use for any recreate-class
/// `UpdateRunner` test fixture where only name + reasons matter.
fn recreate_delta(name: &str, reasons: Vec<&'static str>) -> plan::RunnerDelta {
    plan::RunnerDelta {
        identity: fake_identity(name),
        after: fake_runner_plan(name),
        requires_recreate: true,
        recreate_reasons: reasons,
        drift_cause: plan::DriftCause::SpecChanged,
        field_changes: Vec::new(),
        drop_in_changes: Vec::new(),
        before_caches: None,
        before_drop_in_basenames: None,
    }
}

/// Build an in-place `RunnerDelta` (no recreate) with the
/// given name. Symmetric to `recreate_delta` for the `~` sigil
/// branch.
fn inplace_delta(name: &str) -> plan::RunnerDelta {
    plan::RunnerDelta {
        identity: fake_identity(name),
        after: fake_runner_plan(name),
        requires_recreate: false,
        recreate_reasons: vec![],
        drift_cause: plan::DriftCause::SpecChanged,
        field_changes: Vec::new(),
        drop_in_changes: Vec::new(),
        before_caches: None,
        before_drop_in_basenames: None,
    }
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
///    auto-skips the count-expanded `ci-1` via its
///    `explicit_names.contains("ci-1")` arm, so the explicit ci-1's
///    RunnerSpec passes through directly while the count block
///    contributes ci-2 and ci-3.
/// 2. `summary.recreates` is exactly
///    `["CreateRunner(ci-1)", "CreateRunner(ci-2)", "CreateRunner(ci-3)"]`
///    — sorted by `Action::label()` byte order, no duplicates,
///    no extras.
/// 3. `summary.by_disruption.recreate == 3` and
///    `summary.any_recreate == true`.
/// 4. Discriminating-fixture guard: `cfg.runners[0].memory_max`
///    (the count block) exactly equals `count_block_memory_max`.
///    If a future fixture refactor drifts the count block's
///    memory_max, the assertion below becomes non-discriminating
///    (e.g. forward: both sides Some("8G") would silently pass
///    even if precedence broke; inverse: both sides None would
///    silently pass).
/// 5. Discriminating-fixture guard: `cfg.defaults.memory_max` is
///    None. `merge_defaults`'s `runner.memory_max OR defaults.memory_max`
///    or-chain falls through to defaults when the
///    runner-level field is None — if a future fixture sets
///    defaults.memory_max, the explicit-side None case would
///    silently inherit the defaults value, masking the "explicit
///    wins" assertion through the defaults-inheritance path
///    rather than the count-block override path.
/// 6. The plan's `CreateRunner(ci-1)` action carries
///    `spec.memory_max == expected_ci1_memory_max` — the
///    load-bearing precedence pin. With direction-varying
///    fixtures, this assertion proves that the explicit block
///    wins regardless of which side carries more configuration:
///    forward (Some > None) excludes a "count overrides explicit"
///    bug; inverse (None > Some) excludes a "richer-spec wins"
///    bug.
fn assert_explicit_collision_precedence(
    count_block_memory_max: Option<String>,
    explicit_memory_max: Option<String>,
    expected_ci1_memory_max: Option<String>,
) {
    let mut cfg = cfg_with_runner_trust_zone("ci", "default".into());
    cfg.runners[0].count = Some(3);
    cfg.runners[0].memory_max = count_block_memory_max.clone();
    let explicit = crate::config::RunnerSpec {
        name: "ci-1".into(),
        count: None,
        url: "https://github.com/example/ci-1".into(),
        auth: Some("pat".into()),
        labels: Vec::new(),
        memory_max: explicit_memory_max,
        runner_version: None,
        runner_sha256: None,
        runner_tarball: None,
        arch: None,
        caches: Vec::new(),
        trust_zone: "default".into(),
        network: None,
        proxy: None,
        hooks: None,
        hardening: crate::config::Hardening::default(),
        allowed_cpus: None,
        allowed_memory_nodes: None,
    };
    cfg.runners.push(explicit);

    let actual = state::ActualState::default();
    let paths = Paths::default();

    let plan = plan::plan_from(&cfg, &actual, &paths)
        .expect("count+explicit plan_from must succeed");

    // 1. 3 CreateRunner actions total.
    let create_count = plan
        .actions
        .iter()
        .filter(|a| matches!(a, Action::CreateRunner(_)))
        .count();
    assert_eq!(
        create_count, 3,
        "count=3 with explicit ci-1 collision must yield 3 CreateRunner actions \
         (no duplicate ci-1); got {} actions: {:?}",
        plan.actions.len(),
        plan.actions
            .iter()
            .map(|a| format!("{a:?}"))
            .collect::<Vec<_>>(),
    );

    // 2 + 3. summary.recreates exact-match + by_disruption +
    // any_recreate.
    let body = plan_to_json_value(&plan, false);
    let recreates = body["summary"]["recreates"].as_array().unwrap();
    let labels: Vec<&str> = recreates.iter().map(|v| v.as_str().unwrap()).collect();
    assert_eq!(
        labels,
        vec![
            "CreateRunner(ci-1)",
            "CreateRunner(ci-2)",
            "CreateRunner(ci-3)",
        ],
        "summary.recreates must contain ci-1 once (explicit pre-empts count) plus \
         ci-2 and ci-3 from count expansion",
    );
    assert_eq!(body["summary"]["by_disruption"]["recreate"], 3);
    assert_eq!(body["summary"]["any_recreate"], true);

    // 4. Discriminating-fixture guard: count-block memory_max
    // matches the caller's input exactly. If the caller passed
    // None, this catches future drift that flips it to Some; if
    // the caller passed Some, this catches drift that flips it to
    // a different Some. Either drift would make assertion 6 below
    // non-discriminating.
    assert_eq!(
        cfg.runners[0].memory_max, count_block_memory_max,
        "count block memory_max must match the caller's input \
         ({count_block_memory_max:?}) for precedence test to be discriminating",
    );
    // 5. Discriminating-fixture guard: defaults.memory_max is
    // None so merge_defaults's or_else chain can't inject a
    // defaults value into the explicit-side
    // EffectiveRunnerSpec.
    assert!(
        cfg.defaults.memory_max.is_none(),
        "defaults must leave memory_max=None for precedence test to be \
         discriminating via merge_defaults or_else chain",
    );

    // 6. Load-bearing precedence pin: ci-1's plan-emitted spec
    // carries the expected memory_max value.
    let ci1_plan = plan
        .actions
        .iter()
        .find_map(|a| match a {
            Action::CreateRunner(p) if p.spec.name == "ci-1" => Some(p),
            _ => None,
        })
        .expect("CreateRunner(ci-1) must exist in actions");
    assert_eq!(
        ci1_plan.spec.memory_max, expected_ci1_memory_max,
        "explicit-block precedence: ci-1's spec memory_max must equal the \
         explicit block's value ({expected_ci1_memory_max:?}), not the \
         count block's ({count_block_memory_max:?})",
    );
}

fn parse_command(argv: &[&str]) -> Command {
    Cli::try_parse_from(argv).unwrap().command
}

/// Helper for the trust_zone tests: build the minimal Config that
/// `validate_identity_fields` expects, then mutate the runner /
/// pool's trust_zone in-place. We bypass `toml::from_str` because
/// embedding raw `\n` / `\0` in a TOML basic string would also be
/// rejected by the parser before our validator ran — we want to
/// prove our validator catches the chars, not that TOML happens to
/// reject the literal escape sequences.
fn cfg_with_runner_trust_zone(name: &str, trust_zone: String) -> Config {
    let runner = crate::config::RunnerSpec {
        name: name.into(),
        count: None,
        url: format!("https://github.com/example/{name}"),
        auth: Some("pat".into()),
        labels: Vec::new(),
        memory_max: None,
        runner_version: None,
        runner_sha256: None,
        runner_tarball: None,
        arch: None,
        caches: Vec::new(),
        trust_zone,
        network: None,
        proxy: None,
        hooks: None,
        hardening: crate::config::Hardening::default(),
        allowed_cpus: None,
        allowed_memory_nodes: None,
    };
    let mut auth = indexmap::IndexMap::new();
    auth.insert(
        "pat".into(),
        crate::config::AuthSpec::Pat {
            token_env: Some("GHARS_PAT".into()),
            token_file: None,
        },
    );
    Config {
        defaults: crate::config::Defaults::default(),
        auth,
        cache_pools: indexmap::IndexMap::new(),
        networks: indexmap::IndexMap::new(),
        runners: vec![runner],
        proxy: None,
        hooks: None,
    }
}

/// Insert a `[cache_pools.NAME]` of the given kind into `cfg`.
/// Used by the sccache-binding tests to compose pools with
/// distinct kind sets without copy-pasting the literal each time.
fn insert_cache_pool(cfg: &mut Config, name: &str, kinds: Vec<crate::config::CacheKind>) {
    cfg.cache_pools.insert(
        name.into(),
        crate::config::CachePoolSpec {
            kinds,
            size: "200G".into(),
            mode: crate::config::CacheMode::default(),
            trust_zone: "default".into(),
        },
    );
}

/// Build a fixture Config with a single `[auth.NAME]` entry of
/// AuthSpec::Pat and the runner's auth ref pointing at `name`. The
/// 4+ reject tests below all share this scaffold — the helper
/// collapses the boilerplate and pins the auth-name → error
/// scope linkage in one place.
///
/// `cfg_with_runner_trust_zone` inserts `[auth.pat]` by default;
/// this helper unconditionally clears the inherited `[auth.pat]`
/// entry then inserts `[auth.NAME]` so the resulting Config has
/// exactly one auth entry under `name`.
fn cfg_with_pat_auth(name: &str, token_env: Option<&str>, token_file: Option<&str>) -> Config {
    let mut cfg = cfg_with_runner_trust_zone("buckos", "default".into());
    cfg.auth.clear();
    cfg.auth.insert(
        name.into(),
        crate::config::AuthSpec::Pat {
            token_env: token_env.map(String::from),
            token_file: token_file.map(camino::Utf8PathBuf::from),
        },
    );
    cfg.runners[0].auth = Some(name.into());
    cfg
}

/// Run `validate_pat_xor(cfg)`, expect a `GharsError::Validation`,
/// and assert every substring in `msg_parts` appears in the
/// message, every substring in `hint_parts` appears in the
/// hint, and every substring in `must_not_contain` appears in
/// NEITHER the message NOR the hint. Always pins:
///   - variant is `Validation` (no Ok, no other error class).
///   - msg contains the colon-space `auth "NAME": ` scope shape
///     emitted by `prepend_validation_scope`.
///   - msg does NOT contain a redundant `kind = pat`/`kind =
///     "pat"` prefix — the scope already identifies
///     the offending `[auth.NAME]` block and AuthSpec::Pat is the
///     only variant the loop checks.
///   - hint is non-empty.
#[track_caller]
fn assert_pat_xor_rejects(
    cfg: &Config,
    auth_name: &str,
    msg_parts: &[&str],
    hint_parts: &[&str],
    must_not_contain: &[&str],
) {
    let err = validate_pat_xor(cfg).expect_err("validate_pat_xor must reject");
    match err {
        GharsError::Validation(msg, hint) => {
            let expected_quoted = format!("\"{auth_name}\"");
            let expected_scope = format!("auth {expected_quoted}: ");
            assert!(
                msg.contains(&expected_scope),
                "msg must scope to {expected_scope:?} (colon-space format \
                 from prepend_validation_scope); got: {msg}"
            );
            // Scope is `auth "NAME":` — never
            // `kind = pat:` (would duplicate the variant tag the
            // scope already implies).
            assert!(
                !msg.contains("kind = pat"),
                "msg must NOT contain redundant `kind = pat` prefix; got: {msg}"
            );
            assert!(
                !msg.contains("kind = \"pat\""),
                "msg must NOT contain redundant `kind = \"pat\"` prefix; got: {msg}"
            );
            assert!(
                !hint.is_empty(),
                "hint must be non-empty; got blank for auth {auth_name:?}"
            );
            for part in msg_parts {
                assert!(msg.contains(part), "msg must contain {part:?}; got: {msg}");
            }
            for part in hint_parts {
                assert!(
                    hint.contains(part),
                    "hint must contain {part:?}; got: {hint}"
                );
            }
            for part in must_not_contain {
                assert!(
                    !msg.contains(part),
                    "msg must NOT contain {part:?}; got: {msg}"
                );
                assert!(
                    !hint.contains(part),
                    "hint must NOT contain {part:?}; got: {hint}"
                );
            }
        }
        other => panic!("expected GharsError::Validation, got {other:?}"),
    }
}

/// shared helper for `render_rollback_advisory` test fixtures.
/// Every advisory test that drives the renderer with one or more
/// failures must push to BOTH `failed` and `failed_undo_logs` in
/// lockstep — the typed-error tuple and the per-action UndoLog
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
fn push_failed(result: &mut apply::ApplyResult, label: &str, steps: Vec<apply::UndoStep>) {
    result.failed.push((label.into(), validation_err("test")));
    result.failed_undo_logs.push((label.into(), steps));
}

/// Strategy: generate an arbitrary Action variant. Each arm
/// synthesizes a fresh fixture using the deterministic test
/// helpers (`fake_runner_plan`, `fake_identity`,
/// `fake_cache_binding`) over a short ASCII identifier so
/// the resulting Plan parses cleanly through the renderer.
/// The variant distribution is roughly uniform — proptest
/// will reduce to the minimum failing input on a regression.
///
/// The two UpdateRunner arms are split rather than generated
/// from a single bool because the Restart arm must NOT appear
/// in `summary.recreates` — pinning separate strategies makes
/// the `Action::disruption()` → recreate-list mapping
/// load-bearing. A regression that flipped the boundary would
/// surface as a count mismatch in invariant 1.
fn arb_action() -> impl proptest::strategy::Strategy<Value = Action> {
    use proptest::prelude::*;
    prop_oneof![
        // CreateRunner — always Recreate.
        "[a-z]{1,5}".prop_map(|n| Action::CreateRunner(fake_runner_plan(&n))),
        // UpdateRunner with requires_recreate=true — Recreate.
        "[a-z]{1,5}".prop_map(|n| Action::UpdateRunner(plan::RunnerDelta {
            identity: fake_identity(&n),
            after: fake_runner_plan(&n),
            requires_recreate: true,
            recreate_reasons: vec![],
            drift_cause: plan::DriftCause::SpecChanged,
            field_changes: Vec::new(),
            drop_in_changes: Vec::new(),
            before_caches: None,
            before_drop_in_basenames: None,
        })),
        // UpdateRunner with requires_recreate=false — Restart.
        "[a-z]{1,5}".prop_map(|n| Action::UpdateRunner(plan::RunnerDelta {
            identity: fake_identity(&n),
            after: fake_runner_plan(&n),
            requires_recreate: false,
            recreate_reasons: vec![],
            drift_cause: plan::DriftCause::SpecChanged,
            field_changes: Vec::new(),
            drop_in_changes: Vec::new(),
            before_caches: None,
            before_drop_in_basenames: None,
        })),
        // RemoveRunner — Recreate.
        "[a-z]{1,5}".prop_map(|n| Action::RemoveRunner(fake_identity(&n))),
        // CreateCachePool — Recreate.
        "[a-z]{1,5}".prop_map(|n| Action::CreateCachePool(plan::CachePoolPlan {
            binding: fake_cache_binding(&n),
            drop_in_body: String::new(),
            spec_hash: "sha256:0".into(),
        })),
        // UpdateCachePool — Restart.
        "[a-z]{1,5}".prop_map(|n| Action::UpdateCachePool(plan::CachePoolDelta {
            binding: fake_cache_binding(&n),
            drop_in_body: String::new(),
            spec_hash: "sha256:0".into(),
        })),
        // RemoveCachePool — Recreate.
        "[a-z]{1,5}".prop_map(Action::RemoveCachePool),
        // NoOp — Disruption::None. The generator includes it
        // so the test exercises mixes that include
        // disruption=None entries — the production code path
        // counts them under by_disruption.none, never under
        // recreate.
        "[a-z]{1,5}".prop_map(Action::NoOp),
    ]
}

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
fn capture_apply_emission(result: &apply::ApplyResult) -> (String, String) {
    let mut stdout: Vec<u8> = Vec::new();
    let mut stderr: Vec<u8> = Vec::new();
    render_apply_emission(result, &mut stdout, &mut stderr).unwrap();
    (
        String::from_utf8(stdout).unwrap(),
        String::from_utf8(stderr).unwrap(),
    )
}

mod chunk1;
mod chunk2;
mod chunk3;
mod chunk4;
