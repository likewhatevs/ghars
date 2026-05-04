//! Plan-time `systemd-analyze verify` gate (audit #18 / Part 13 Tier 5).
//!
//! Renders every plan-emitted unit + drop-in into a temporary directory
//! arranged the way systemd expects (`<unit>.service` next to its
//! `<unit>.service.d/` overrides), invokes `systemd-analyze --no-pager
//! verify <path>` on each, and surfaces any `Failed to load`,
//! `Assignment outside of section`, `Unknown setting`, etc. errors as
//! plan-level `GharsError::Validation`.
//!
//! Why a dedicated module:
//! - `plan.rs` is pure logic over types; the verify gate shells out
//!   (`Command::new`) and writes files. Keeping that off the
//!   `plan_from` happy path lets `plan.rs` stay deterministic and
//!   side-effect-free.
//! - Tests for the gate need a `Verifier` test seam (mock the
//!   `systemd-analyze` subprocess) without leaking that surface into
//!   the plan API.
//!
//! Apply-time short-circuit: `apply()` does NOT re-run the verify gate
//! at apply time — the contract is "plan-side validation gates the
//! diff before any host mutation". A subsequent `Defaults.foo` change
//! that arrives via apply-only paths (which don't exist today) would
//! re-trigger plan; the gate is at the producer of the rendered
//! bytes, not at the consumer.

use std::collections::BTreeMap;
use std::fs;
use std::path::Path;
use std::process::Command;

use crate::plan::{Action, Plan};
use crate::{GharsError, Result};

/// Trait seam over `systemd-analyze verify <path>`. Production wires
/// [`RealVerifier`] which `Command::new`s the binary; tests inject a
/// fake that returns canned results without depending on a host
/// systemd installation. Trait method takes the unit's full path and
/// returns either `Ok(())` on success or `Err(diagnostic_string)`
/// where the string is the captured stderr from systemd-analyze.
pub trait UnitVerifier {
    /// Run `systemd-analyze --no-pager verify <unit_path>`.
    ///
    /// # Errors
    ///
    /// Returns `Err(stderr_text)` when systemd-analyze exits non-zero;
    /// the caller surfaces the text as a plan validation failure.
    /// `GharsError::Io` wraps spawn failures (binary missing → caller
    /// renders that as a preflight remediation hint).
    fn verify(&self, unit_path: &Path) -> std::result::Result<(), String>;
}

/// Production `UnitVerifier` — shells out to `/usr/bin/systemd-analyze`.
#[derive(Debug, Default)]
pub struct RealVerifier;

impl UnitVerifier for RealVerifier {
    fn verify(&self, unit_path: &Path) -> std::result::Result<(), String> {
        // `--no-pager` keeps output unbuffered + line-oriented for
        // direct stderr capture. `verify <path>` accepts an absolute
        // path; systemd-analyze resolves drop-ins from `<path>.d/`
        // automatically when the file lives in a directory that
        // contains the drop-in subtree.
        let output = Command::new("/usr/bin/systemd-analyze")
            .args([
                "--no-pager",
                "verify",
                unit_path
                    .to_str()
                    .ok_or_else(|| format!("non-UTF-8 path {unit_path:?}"))?,
            ])
            .output()
            .map_err(|e| format!("spawn systemd-analyze: {e}"))?;
        if output.status.success() {
            return Ok(());
        }
        // systemd-analyze writes diagnostics to stderr; stdout is
        // typically empty for `verify`. Concatenate both so the
        // operator gets the complete picture.
        let stderr = String::from_utf8_lossy(&output.stderr);
        let stdout = String::from_utf8_lossy(&output.stdout);
        let mut diag = stderr.into_owned();
        if !stdout.is_empty() {
            diag.push('\n');
            diag.push_str(&stdout);
        }
        Err(diag.trim().to_string())
    }
}

/// Verify every unit + drop-in produced by `plan` using `verifier`.
/// Layout is staged into a fresh subdirectory under
/// `<runtime_dir>/verify/` so the host's live `/etc/systemd/system`
/// is never touched. The directory is removed best-effort after
/// verification — failures here are logged but do not propagate
/// (the verification result is what matters; cleanup is housekeeping).
///
/// # Errors
///
/// - `GharsError::Io` if the staging directory can't be created /
///   written to (filesystem-level failure; can't proceed).
/// - `GharsError::Validation` aggregating all per-unit verification
///   failures (one `Validation` carrying one error per failing
///   unit). The caller (`compute_plan` in cli.rs) surfaces this as
///   a plan failure so the operator sees concrete remediation
///   text per unit.
pub fn verify_plan(
    plan: &Plan,
    runtime_dir: &camino::Utf8Path,
    verifier: &dyn UnitVerifier,
) -> Result<()> {
    let staging_root = runtime_dir.join("verify");
    fs::create_dir_all(staging_root.as_std_path())?;
    // Per-call subdir keyed on PID so concurrent verifies (shouldn't
    // happen — apply.lock serializes — but defense in depth) don't
    // collide on the static unit-name layout below.
    let staging = staging_root.join(format!("plan-{}", std::process::id()));
    if staging.as_std_path().exists() {
        let _ = fs::remove_dir_all(staging.as_std_path());
    }
    fs::create_dir_all(staging.as_std_path())?;

    let result = verify_plan_inner(plan, staging.as_std_path(), verifier);
    // Best-effort cleanup; a failed cleanup must not mask the
    // verification result. Tracing surfaces the residue path so
    // operators can investigate stale dirs under runtime_dir.
    if let Err(e) = fs::remove_dir_all(staging.as_std_path()) {
        tracing::warn!(
            path = %staging,
            error = %e,
            "unit_verify: staging cleanup failed; manual rm may be needed"
        );
    }
    result
}

fn verify_plan_inner(plan: &Plan, staging: &Path, verifier: &dyn UnitVerifier) -> Result<()> {
    // Collect `RenderedUnit` (unit_filename, drop_ins) values for
    // every action that produces a rendered unit + drop-in surface.
    // NoOp, RemoveRunner, and RemoveCachePool produce no rendered
    // bytes — their effect on disk is removal, which has nothing to
    // verify syntax-wise (we cannot verify a file that won't exist).
    let mut units: Vec<RenderedUnit> = Vec::new();
    for action in &plan.actions {
        match action {
            Action::CreateRunner(p) => {
                units.push(rendered_runner_unit(
                    &p.spec.name,
                    &p.effective_unit_text,
                    &p.drop_ins,
                ));
            }
            Action::UpdateRunner(d) => {
                if d.requires_recreate {
                    units.push(rendered_runner_unit(
                        &d.identity.name,
                        &d.after.effective_unit_text,
                        &d.after.drop_ins,
                    ));
                } else {
                    // In-place update: the runner template body is
                    // unchanged (template-level; only drop-ins
                    // diverge), but we still verify the template +
                    // post-change drop-ins as a unit so directive
                    // changes in drop-ins are caught.
                    units.push(rendered_runner_unit(
                        &d.identity.name,
                        &d.after.effective_unit_text,
                        &d.after.drop_ins,
                    ));
                }
            }
            Action::CreateCachePool(p) => {
                units.push(rendered_cache_unit(&p.binding.name, &p.drop_in_body));
            }
            Action::UpdateCachePool(d) => {
                units.push(rendered_cache_unit(&d.binding.name, &d.drop_in_body));
            }
            Action::RemoveRunner(_) | Action::RemoveCachePool(_) | Action::NoOp(_) => {}
        }
    }

    // Stage the static templates once so per-instance verify calls
    // can resolve the parametric template.
    let runner_template = crate::systemd::runner_template_text();
    let cache_template = crate::systemd::cache_template_text();
    fs::write(
        staging.join("ghars-runner@.service"),
        runner_template.as_bytes(),
    )?;
    fs::write(
        staging.join("ghars-cache@.service"),
        cache_template.as_bytes(),
    )?;

    let mut errors: Vec<String> = Vec::new();
    for u in &units {
        // Per-unit drop-in directory.
        let dropin_dir = staging.join(format!("{}.d", u.unit_filename));
        fs::create_dir_all(&dropin_dir)?;
        for (basename, body) in &u.drop_ins {
            fs::write(dropin_dir.join(basename), body.as_bytes())?;
        }
        // Pass the instantiated unit name as a relative path inside
        // staging; systemd-analyze handles `<template>@<instance>.service`
        // resolution against the staging dir.
        let unit_path = staging.join(&u.unit_filename);
        if let Err(diag) = verifier.verify(&unit_path) {
            errors.push(format!("{}: {diag}", u.unit_filename));
        }
    }

    if errors.is_empty() {
        return Ok(());
    }
    Err(GharsError::Validation(
        format!(
            "systemd-analyze verify rejected {} rendered unit(s):\n{}",
            errors.len(),
            errors.join("\n\n")
        ),
        "fix the listed directive errors in your config (or the corresponding ghars systemd template) and re-plan".into(),
    ))
}

/// One unit's worth of bytes for staging into the verify root.
struct RenderedUnit {
    /// Full unit filename (e.g. `ghars-runner@buckos.service`).
    unit_filename: String,
    /// Drop-in basename → body (e.g. `00-ghars.conf` → "...").
    drop_ins: BTreeMap<String, String>,
}

fn rendered_runner_unit(
    name: &str,
    _unit_text: &str,
    drop_ins: &BTreeMap<String, String>,
) -> RenderedUnit {
    // The runner unit is template-instanced as
    // `ghars-runner@<name>.service`. systemd-analyze resolves the
    // template body from the same directory's `ghars-runner@.service`
    // file (staged once by the caller) and applies the drop-ins from
    // `ghars-runner@<name>.service.d/`. The per-instance unit file
    // itself is NOT written; systemd treats `@<instance>.service` as
    // a virtual instantiation of the template.
    RenderedUnit {
        unit_filename: format!("ghars-runner@{name}.service"),
        drop_ins: drop_ins.clone(),
    }
}

fn rendered_cache_unit(name: &str, drop_in_body: &str) -> RenderedUnit {
    let mut drop_ins = BTreeMap::new();
    drop_ins.insert("00-ghars.conf".to_owned(), drop_in_body.to_owned());
    RenderedUnit {
        unit_filename: format!("ghars-cache@{name}.service"),
        drop_ins,
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used)]
mod tests {
    use super::*;
    use std::path::PathBuf;
    use std::sync::Mutex;

    /// Test verifier that records every call and lets the test
    /// configure success/failure per unit-name.
    #[derive(Default)]
    struct StubVerifier {
        calls: Mutex<Vec<PathBuf>>,
        fail_for: Mutex<Vec<String>>,
    }
    impl UnitVerifier for StubVerifier {
        fn verify(&self, unit_path: &Path) -> std::result::Result<(), String> {
            self.calls.lock().unwrap().push(unit_path.to_path_buf());
            let fname = unit_path.file_name().unwrap().to_string_lossy().to_string();
            let fail_set = self.fail_for.lock().unwrap();
            if fail_set.contains(&fname) {
                Err(format!("simulated failure on {fname}"))
            } else {
                Ok(())
            }
        }
    }

    fn empty_plan() -> Plan {
        Plan::default()
    }

    #[test]
    fn verify_empty_plan_calls_no_verifier_and_succeeds() {
        let tmp = tempfile::tempdir().unwrap();
        let runtime = camino::Utf8Path::from_path(tmp.path()).unwrap();
        let verifier = StubVerifier::default();
        let plan = empty_plan();
        verify_plan(&plan, runtime, &verifier).unwrap();
        assert!(verifier.calls.lock().unwrap().is_empty());
    }

    #[test]
    fn verify_calls_systemd_analyze_per_create_runner() {
        let tmp = tempfile::tempdir().unwrap();
        let runtime = camino::Utf8Path::from_path(tmp.path()).unwrap();
        let verifier = StubVerifier::default();
        let plan = Plan {
            actions: vec![
                Action::CreateRunner(crate::plan::RunnerPlan {
                    spec: minimal_effective_spec("buckos"),
                    resolved_release: None,
                    effective_unit_text: "[Unit]\nDescription=test\n".into(),
                    drop_ins: BTreeMap::new(),
                    spec_hash: "sha256:abcd".into(),
                }),
                Action::CreateRunner(crate::plan::RunnerPlan {
                    spec: minimal_effective_spec("ktstr"),
                    resolved_release: None,
                    effective_unit_text: "[Unit]\nDescription=test\n".into(),
                    drop_ins: BTreeMap::new(),
                    spec_hash: "sha256:abcd".into(),
                }),
            ],
            warnings: vec![],
            keep_versions: 2,
        };
        verify_plan(&plan, runtime, &verifier).unwrap();
        let calls = verifier.calls.lock().unwrap();
        assert_eq!(calls.len(), 2);
        let names: Vec<String> = calls
            .iter()
            .map(|p| p.file_name().unwrap().to_string_lossy().to_string())
            .collect();
        assert!(names.contains(&"ghars-runner@buckos.service".to_string()));
        assert!(names.contains(&"ghars-runner@ktstr.service".to_string()));
    }

    #[test]
    fn verify_aggregates_failures_into_validation_error() {
        let tmp = tempfile::tempdir().unwrap();
        let runtime = camino::Utf8Path::from_path(tmp.path()).unwrap();
        let verifier = StubVerifier::default();
        verifier
            .fail_for
            .lock()
            .unwrap()
            .push("ghars-runner@bad.service".to_string());
        let plan = Plan {
            actions: vec![
                Action::CreateRunner(crate::plan::RunnerPlan {
                    spec: minimal_effective_spec("good"),
                    resolved_release: None,
                    effective_unit_text: "[Unit]\nDescription=test\n".into(),
                    drop_ins: BTreeMap::new(),
                    spec_hash: "sha256:abcd".into(),
                }),
                Action::CreateRunner(crate::plan::RunnerPlan {
                    spec: minimal_effective_spec("bad"),
                    resolved_release: None,
                    effective_unit_text: "[Unit]\nDescription=test\n".into(),
                    drop_ins: BTreeMap::new(),
                    spec_hash: "sha256:abcd".into(),
                }),
            ],
            warnings: vec![],
            keep_versions: 2,
        };
        let err = verify_plan(&plan, runtime, &verifier).unwrap_err();
        let GharsError::Validation(msg, _hint) = err else {
            panic!("expected Validation error; got {err:?}");
        };
        assert!(
            msg.contains("ghars-runner@bad.service"),
            "error must name failing unit; got {msg}"
        );
        assert!(
            msg.contains("simulated failure on ghars-runner@bad.service"),
            "error must include verifier diagnostic; got {msg}"
        );
        // Only ONE failure was reported (the "good" one passed),
        // and the message must not falsely include the passing one.
        assert!(
            !msg.contains("simulated failure on ghars-runner@good"),
            "error must not include passing units; got {msg}"
        );
    }

    #[test]
    fn verify_skips_remove_actions() {
        let tmp = tempfile::tempdir().unwrap();
        let runtime = camino::Utf8Path::from_path(tmp.path()).unwrap();
        let verifier = StubVerifier::default();
        // RemoveRunner / RemoveCachePool / NoOp produce no rendered
        // bytes, so the verifier must not be invoked for them.
        let plan = Plan {
            actions: vec![
                Action::RemoveRunner(crate::plan::RunnerIdentity {
                    name: "removed".into(),
                    url: "https://github.com/example/repo".into(),
                    auth_name: "pat".into(),
                    trust_zone: "default".into(),
                }),
                Action::RemoveCachePool("removed-pool".into()),
                Action::NoOp("idempotent".into()),
            ],
            warnings: vec![],
            keep_versions: 2,
        };
        verify_plan(&plan, runtime, &verifier).unwrap();
        assert!(
            verifier.calls.lock().unwrap().is_empty(),
            "remove + noop actions must produce no verify calls"
        );
    }

    #[test]
    fn verify_includes_create_cache_pool_units() {
        let tmp = tempfile::tempdir().unwrap();
        let runtime = camino::Utf8Path::from_path(tmp.path()).unwrap();
        let verifier = StubVerifier::default();
        let plan = Plan {
            actions: vec![Action::CreateCachePool(crate::plan::CachePoolPlan {
                binding: minimal_cache_binding("build"),
                drop_in_body: "[Service]\n".into(),
                spec_hash: "sha256:abcd".into(),
            })],
            warnings: vec![],
            keep_versions: 2,
        };
        verify_plan(&plan, runtime, &verifier).unwrap();
        let calls = verifier.calls.lock().unwrap();
        assert_eq!(calls.len(), 1);
        assert_eq!(
            calls[0].file_name().unwrap().to_string_lossy(),
            "ghars-cache@build.service"
        );
    }

    #[test]
    fn verify_writes_drop_ins_alongside_unit_for_systemd_analyze_to_resolve() {
        // The verifier receives the unit path; before the call,
        // verify_plan must have written 00-ghars.conf to
        // <staging>/<unit>.d/00-ghars.conf so systemd-analyze can
        // resolve drop-ins. Inspect the staging dir at verify time
        // to confirm.
        let tmp = tempfile::tempdir().unwrap();
        let runtime = camino::Utf8Path::from_path(tmp.path()).unwrap();
        struct PeekingVerifier {
            seen_dropin: Mutex<bool>,
        }
        impl UnitVerifier for PeekingVerifier {
            fn verify(&self, unit_path: &Path) -> std::result::Result<(), String> {
                let parent = unit_path.parent().unwrap();
                let fname = unit_path.file_name().unwrap().to_string_lossy().to_string();
                let dropin = parent.join(format!("{fname}.d")).join("00-ghars.conf");
                if dropin.exists() {
                    *self.seen_dropin.lock().unwrap() = true;
                }
                Ok(())
            }
        }
        let verifier = PeekingVerifier {
            seen_dropin: Mutex::new(false),
        };
        let mut drop_ins = BTreeMap::new();
        drop_ins.insert(
            "00-ghars.conf".into(),
            "[Service]\nUser=ghars-tz-default\n".into(),
        );
        let plan = Plan {
            actions: vec![Action::CreateRunner(crate::plan::RunnerPlan {
                spec: minimal_effective_spec("buckos"),
                resolved_release: None,
                effective_unit_text: "[Unit]\nDescription=test\n".into(),
                drop_ins,
                spec_hash: "sha256:abcd".into(),
            })],
            warnings: vec![],
            keep_versions: 2,
        };
        verify_plan(&plan, runtime, &verifier).unwrap();
        assert!(
            *verifier.seen_dropin.lock().unwrap(),
            "drop-in must be written to <unit>.d/ before verify is invoked"
        );
    }

    fn minimal_effective_spec(name: &str) -> crate::config::EffectiveRunnerSpec {
        crate::config::EffectiveRunnerSpec {
            name: name.into(),
            url: "https://github.com/example/repo".into(),
            arch: crate::config::Arch::X86_64,
            labels: vec![],
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
            spec_hash: "sha256:abcd".into(),
            runsvc_sha256: String::new(),
            config_source: "/etc/ghars/ghars.toml".into(),
        }
    }

    fn minimal_cache_binding(name: &str) -> crate::config::EffectiveCacheBinding {
        crate::config::EffectiveCacheBinding {
            name: name.into(),
            kinds: vec![crate::config::CacheKind::Sccache],
            size: "100G".into(),
            mode: crate::config::CacheMode::Shared,
            trust_zone: "default".into(),
        }
    }
}
