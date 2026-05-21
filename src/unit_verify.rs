//! Plan-time `systemd-analyze verify` gate (Part 13 Tier 5).
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
        // direct stderr capture.
        // SYSTEMD_UNIT_PATH search list:
        //   <staging_dir>:/usr/lib/systemd/system:/lib/systemd/system
        //
        // - `<staging_dir>` first so the staged template + drop-ins
        //   (or inlined `merged_body`) win.
        // - `/usr/lib/systemd/system` + `/lib/systemd/system` second
        //   so OS-shipped units (`sysinit.target`, `network-online.
        //   target`, etc. that any non-trivial unit transitively
        //   requires) resolve. Without these, systemd-analyze rejects
        //   the rendered unit with "Unit sysinit.target not found."
        //
        // Deliberately EXCLUDES `/etc/systemd/system` and `/run/systemd
        // /system`. Those are where ghars writes the production drop-
        // ins — including the pre-existing 00-ghars.conf this verify
        // is about to replace. The trailing-colon form (`<dir>:`)
        // per systemd.unit(5) "appends the default" which INCLUDES
        // /etc; the pre-existing drop-in there would merge alongside
        // the staged version and the rendered unit ends up with
        // ExecStart= from BOTH sources, failing "Service has more
        // than one ExecStart= setting" for non-oneshot services.
        // Naming only the OS-shipped roots gives verify enough to
        // resolve dependency targets without exposing it to the
        // host's editable unit tree.
        let staging_dir = unit_path
            .parent()
            .ok_or_else(|| format!("unit_path {unit_path:?} has no parent"))?;
        let search_path = format!(
            "{}:/usr/lib/systemd/system:/lib/systemd/system",
            staging_dir.display(),
        );
        let output = Command::new("/usr/bin/systemd-analyze")
            .env("SYSTEMD_UNIT_PATH", search_path)
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
///   unit). The caller (`cli::cmd_plan::compute_plan`) surfaces this as
///   a plan failure so the operator sees concrete remediation
///   text per unit.
pub fn verify_plan(
    plan: &Plan,
    paths: &crate::paths::Paths,
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

    let result = verify_plan_inner(plan, paths, staging.as_std_path(), verifier);
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

fn verify_plan_inner(
    plan: &Plan,
    paths: &crate::paths::Paths,
    staging: &Path,
    verifier: &dyn UnitVerifier,
) -> Result<()> {
    // Collect `RenderedUnit` (unit_filename, drop_ins) values for
    // every action that produces a rendered unit + drop-in surface.
    // NoOp, RemoveRunner, and RemoveCachePool produce no rendered
    // bytes — their effect on disk is removal, which has nothing to
    // verify syntax-wise (we cannot verify a file that won't exist).
    let mut units: Vec<RenderedUnit> = Vec::new();
    // Track cache pools staged via Create/Update actions vs. cache
    // pools referenced by runner units. Any reference NOT covered by a
    // staged action needs its current on-disk drop-in copied into
    // staging too — otherwise the runner unit's `Requires=ghars-
    // cache@<pool>.service` resolves to the bare cache template (which
    // ghars stages unconditionally below) with no per-instance drop-in
    // and verify rejects the runner with "ghars-cache@<pool>.service:
    // Service has no ExecStart=, ExecStop=, or SuccessAction=.
    // Refusing." The host's /etc/systemd/system is deliberately
    // excluded from SYSTEMD_UNIT_PATH (see `RealVerifier::verify` for
    // why), so the drop-in must arrive via staging.
    let mut staged_cache_pools: std::collections::BTreeSet<String> =
        std::collections::BTreeSet::new();
    let mut referenced_cache_pools: std::collections::BTreeSet<String> =
        std::collections::BTreeSet::new();
    for action in &plan.actions {
        match action {
            Action::CreateRunner(p) => {
                for c in &p.spec.caches {
                    referenced_cache_pools.insert(c.name.clone());
                }
                units.push(rendered_runner_unit(
                    &p.spec.name,
                    &p.effective_unit_text,
                    &p.drop_ins,
                ));
            }
            Action::UpdateRunner(d) => {
                for c in &d.after.spec.caches {
                    referenced_cache_pools.insert(c.name.clone());
                }
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
                staged_cache_pools.insert(p.binding.name.clone());
                units.push(rendered_cache_unit(&p.binding.name, &p.drop_in_body));
            }
            Action::UpdateCachePool(d) => {
                staged_cache_pools.insert(d.binding.name.clone());
                units.push(rendered_cache_unit(&d.binding.name, &d.drop_in_body));
            }
            Action::RemoveRunner(_) | Action::RemoveCachePool(_) | Action::NoOp(_) => {}
        }
    }
    // Backfill cache pools referenced by runner units but not staged
    // via a Create/Update action (the typical case: runners being
    // created or updated against an unchanged pool). Read the current
    // on-disk drop-in from the production unit dir and stage it so
    // the dependency target resolves the same merged shape verify
    // would see at runtime.
    for pool_name in referenced_cache_pools.difference(&staged_cache_pools) {
        let drop_in_path = paths.cache_drop_in_dir(pool_name).join("00-ghars.conf");
        match fs::read_to_string(drop_in_path.as_std_path()) {
            Ok(body) => units.push(rendered_cache_unit(pool_name, &body)),
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => {
                // No on-disk drop-in — pool is referenced but neither
                // staged this plan nor present on disk. Skip staging;
                // verify will surface a clear "ghars-cache@<pool>.
                // service has no ExecStart=" error pointing the
                // operator at the missing pool.
            }
            Err(e) => return Err(GharsError::Io(e)),
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

    // Two-pass staging: write ALL files first, THEN verify. Runner
    // units Requires= cache units, so systemd-analyze needs every
    // dependency file to exist in the staging dir before any verify
    // call. A single interleaved write-then-verify loop fails when
    // plan.actions orders CreateRunner before CreateCachePool.
    for u in &units {
        let dropin_dir = staging.join(format!("{}.d", u.unit_filename));
        fs::create_dir_all(&dropin_dir)?;
        for (basename, body) in &u.drop_ins {
            fs::write(dropin_dir.join(basename), body.as_bytes())?;
        }
        let unit_path = staging.join(&u.unit_filename);
        if let Some(ref merged) = u.merged_body {
            // Cache units: pre-merged template+drop-in body written
            // directly as the instance file.
            fs::write(&unit_path, merged.as_bytes())?;
        } else if let Some(template_path) = template_path_for(&u.unit_filename)
            && !unit_path.exists()
        {
            // Runner units: copy template body to instance path so
            // drop-ins resolve against a real file.
            let template_abs = staging.join(template_path);
            std::fs::copy(&template_abs, &unit_path).map_err(|e| {
                GharsError::Io(std::io::Error::new(
                    e.kind(),
                    format!(
                        "unit_verify: copy {} -> {} failed: {e}",
                        template_abs.display(),
                        unit_path.display()
                    ),
                ))
            })?;
        }
    }

    // Pass 2: verify every unit now that all files are staged.
    let mut errors: Vec<String> = Vec::new();
    for u in &units {
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
    /// When set, this body is written directly as the instance file
    /// instead of copying the template. Used for cache units where
    /// template + drop-in are pre-merged so systemd-analyze doesn't
    /// need to resolve drop-ins (which fails in staging dirs).
    merged_body: Option<String>,
}

fn rendered_runner_unit(
    name: &str,
    _unit_text: &str,
    drop_ins: &BTreeMap<String, String>,
) -> RenderedUnit {
    // The runner unit is template-instanced as
    // `ghars-runner@<name>.service`. The caller stages the template
    // body once at `ghars-runner@.service`, then `verify_plan_inner`
    // copies those bytes to `ghars-runner@<name>.service` as a
    // regular file so the per-instance pathname systemd-analyze
    // receives resolves to a real file with directive bytes (without
    // the copy, systemd-analyze invoked on the instance path reports
    // "Service has no ExecStart=" because it does NOT auto-synthesize
    // a template body from `<prefix>@.service` for direct-path
    // invocations). A symlink was tried first but failed empirically
    // on deploy hosts; a regular file with the instance name keeps
    // the unit-loader's drop-in resolution direct. Drop-ins from
    // `ghars-runner@<name>.service.d/` apply against the copied
    // instance file.
    // Merge template + all drop-ins into a single self-contained unit
    // file. systemd-analyze verify on systemd 252 cannot reliably
    // resolve template instances or drop-ins from staging directories
    // even with SYSTEMD_UNIT_PATH set. The merged file passes
    // verification as a standalone unit.
    let mut merged = crate::systemd::runner_template_text();
    for body in drop_ins.values() {
        merged.push('\n');
        merged.push_str(body);
    }
    RenderedUnit {
        unit_filename: crate::paths::runner_unit_name(name),
        drop_ins: BTreeMap::new(),
        merged_body: Some(merged),
    }
}

fn rendered_cache_unit(name: &str, drop_in_body: &str) -> RenderedUnit {
    // Cache units carry ExecStart= in the per-pool drop-in, not in the
    // template body. systemd-analyze verify cannot reliably resolve
    // template-instance drop-ins in a staging directory (it loads the
    // template body but misses the per-instance .d/ overrides). To work
    // around this, we bake the drop-in content into the instance file
    // body alongside the template text, producing a self-contained unit
    // that passes verification without depending on drop-in resolution.
    // The on-host systemd runtime uses the real template + drop-in
    // layout; this merged form is verify-only.
    let mut merged = crate::systemd::cache_template_text();
    merged.push('\n');
    merged.push_str(drop_in_body);
    RenderedUnit {
        unit_filename: crate::paths::cache_unit_name(name),
        drop_ins: BTreeMap::new(),
        merged_body: Some(merged),
    }
}

/// Return the template filename that backs a template-instanced unit
/// filename (e.g. `ghars-cache@build.service` → `ghars-cache@.service`).
/// Returns `None` for non-template names (no `@` between prefix and
/// `.service`), signalling no symlink is needed.
///
/// The split point is the first `@` followed by anything up to
/// `.service`. Everything from that `@` through the instance segment
/// is dropped, leaving `<prefix>@.service`. We DO NOT support `@.`
/// inside the instance name — the validators upstream reject `@` in
/// runner/pool names, so a `@@`-shaped filename never reaches here.
fn template_path_for(unit_filename: &str) -> Option<String> {
    let at = unit_filename.find('@')?;
    let suffix_start = unit_filename[at + 1..].find(".service")?;
    let template = format!(
        "{prefix_at}{suffix}",
        prefix_at = &unit_filename[..=at],
        suffix = &unit_filename[at + 1 + suffix_start..],
    );
    if template == unit_filename {
        None
    } else {
        Some(template)
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
        verify_plan(&plan, &crate::paths::Paths::default(), runtime, &verifier).unwrap();
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
                    env_file: String::new(),
                    path_file: String::new(),
                    spec_hash: "sha256:abcd".into(),
                }),
                Action::CreateRunner(crate::plan::RunnerPlan {
                    spec: minimal_effective_spec("ktstr"),
                    resolved_release: None,
                    effective_unit_text: "[Unit]\nDescription=test\n".into(),
                    drop_ins: BTreeMap::new(),
                    env_file: String::new(),
                    path_file: String::new(),
                    spec_hash: "sha256:abcd".into(),
                }),
            ],
            warnings: vec![],
            keep_versions: 2,
        };
        verify_plan(&plan, &crate::paths::Paths::default(), runtime, &verifier).unwrap();
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
                    env_file: String::new(),
                    path_file: String::new(),
                    spec_hash: "sha256:abcd".into(),
                }),
                Action::CreateRunner(crate::plan::RunnerPlan {
                    spec: minimal_effective_spec("bad"),
                    resolved_release: None,
                    effective_unit_text: "[Unit]\nDescription=test\n".into(),
                    drop_ins: BTreeMap::new(),
                    env_file: String::new(),
                    path_file: String::new(),
                    spec_hash: "sha256:abcd".into(),
                }),
            ],
            warnings: vec![],
            keep_versions: 2,
        };
        let err =
            verify_plan(&plan, &crate::paths::Paths::default(), runtime, &verifier).unwrap_err();
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
        verify_plan(&plan, &crate::paths::Paths::default(), runtime, &verifier).unwrap();
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
        verify_plan(&plan, &crate::paths::Paths::default(), runtime, &verifier).unwrap();
        let calls = verifier.calls.lock().unwrap();
        assert_eq!(calls.len(), 1);
        assert_eq!(
            calls[0].file_name().unwrap().to_string_lossy(),
            "ghars-cache@build.service"
        );
    }

    #[test]
    fn verify_merges_drop_in_bodies_into_instance_unit_file() {
        // The verifier receives a per-instance unit path with the
        // template body PLUS every drop-in body merged inline.
        // systemd-analyze verify on systemd 252 cannot resolve
        // template instances or drop-ins from staging directories
        // even with SYSTEMD_UNIT_PATH set, so rendered_runner_unit
        // builds a self-contained merged body. Pin the merge so a
        // future refactor that goes back to separate-dropins staging
        // fails here.
        let tmp = tempfile::tempdir().unwrap();
        let runtime = camino::Utf8Path::from_path(tmp.path()).unwrap();
        struct CapturingVerifier {
            seen_body: Mutex<Option<String>>,
        }
        impl UnitVerifier for CapturingVerifier {
            fn verify(&self, unit_path: &Path) -> std::result::Result<(), String> {
                let body = std::fs::read_to_string(unit_path)
                    .unwrap_or_else(|e| panic!("read merged unit {unit_path:?}: {e}"));
                *self.seen_body.lock().unwrap() = Some(body);
                Ok(())
            }
        }
        let verifier = CapturingVerifier {
            seen_body: Mutex::new(None),
        };
        let mut drop_ins = BTreeMap::new();
        let dropin_marker = "[Service]\nUser=ghars-tz-default\n";
        drop_ins.insert("00-ghars.conf".into(), dropin_marker.into());
        let plan = Plan {
            actions: vec![Action::CreateRunner(crate::plan::RunnerPlan {
                spec: minimal_effective_spec("buckos"),
                resolved_release: None,
                effective_unit_text: "[Unit]\nDescription=test\n".into(),
                drop_ins,
                env_file: String::new(),
                path_file: String::new(),
                spec_hash: "sha256:abcd".into(),
            })],
            warnings: vec![],
            keep_versions: 2,
        };
        verify_plan(&plan, &crate::paths::Paths::default(), runtime, &verifier).unwrap();
        let body = verifier
            .seen_body
            .lock()
            .unwrap()
            .clone()
            .expect("verifier must have been invoked");
        assert!(
            body.contains(dropin_marker),
            "merged unit body must contain drop-in content; got:\n{body}"
        );
    }

    #[test]
    fn verify_copies_template_body_to_instance_path() {
        // systemd-analyze invoked on `staging/ghars-cache@build.service`
        // (a template-instanced filename) needs the path to resolve to
        // a file with [Service] body bytes — otherwise it reports
        // "Service has no ExecStart=" even when the drop-in under
        // <unit>.d/ supplies one, because direct-path invocations skip
        // the in-host template synthesis.
        //
        // A symlink (instance → template) would resolve the unit body
        // but systemd's unit-loader treats the symlink as an ALIAS,
        // attaching drop-ins to the template's name rather than the
        // instance's. verify_plan_inner must copy the template bytes
        // to the instance path so the file is a regular file with
        // the instance name, keeping drop-ins under
        // <instance>.service.d/ correctly associated.
        let tmp = tempfile::tempdir().unwrap();
        let runtime = camino::Utf8Path::from_path(tmp.path()).unwrap();
        struct InspectingVerifier {
            saw_regular_file: Mutex<Option<bool>>,
            saw_template_bytes: Mutex<Option<bool>>,
        }
        impl UnitVerifier for InspectingVerifier {
            fn verify(&self, unit_path: &Path) -> std::result::Result<(), String> {
                let meta = std::fs::symlink_metadata(unit_path).unwrap();
                let ft = meta.file_type();
                // Must be a regular file (NOT a symlink) so systemd's
                // unit-loader treats it as the per-instance unit, not
                // as an alias of the template.
                *self.saw_regular_file.lock().unwrap() = Some(ft.is_file() && !ft.is_symlink());
                let body = std::fs::read_to_string(unit_path).unwrap();
                *self.saw_template_bytes.lock().unwrap() =
                    Some(body.contains("Description=ghars cache service"));
                Ok(())
            }
        }
        let verifier = InspectingVerifier {
            saw_regular_file: Mutex::new(None),
            saw_template_bytes: Mutex::new(None),
        };
        let plan = Plan {
            actions: vec![Action::CreateCachePool(crate::plan::CachePoolPlan {
                binding: minimal_cache_binding("build"),
                drop_in_body: "[Service]\n".into(),
                spec_hash: "sha256:abcd".into(),
            })],
            warnings: vec![],
            keep_versions: 2,
        };
        verify_plan(&plan, &crate::paths::Paths::default(), runtime, &verifier).unwrap();
        assert_eq!(
            *verifier.saw_regular_file.lock().unwrap(),
            Some(true),
            "instance unit file must be a regular file (not a symlink); \
             systemd treats symlinks as aliases and attaches drop-ins to \
             the symlink target's name"
        );
        assert_eq!(
            *verifier.saw_template_bytes.lock().unwrap(),
            Some(true),
            "instance file must contain the template body bytes"
        );
    }

    #[test]
    fn template_path_for_strips_instance_segment() {
        assert_eq!(
            template_path_for("ghars-cache@build.service"),
            Some("ghars-cache@.service".to_owned())
        );
        assert_eq!(
            template_path_for("ghars-runner@buckos.service"),
            Some("ghars-runner@.service".to_owned())
        );
    }

    #[test]
    fn template_path_for_returns_none_when_no_instance_segment() {
        // No `@` means non-template; no symlink should be created.
        assert_eq!(template_path_for("plain.service"), None);
        // `@` at the end immediately before `.service` means an empty
        // instance — already the template name itself.
        assert_eq!(template_path_for("ghars-cache@.service"), None);
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
            environment: crate::config::EnvironmentSpec::default(),
            spec_hash: "sha256:abcd".into(),
            config_source: "/etc/ghars/ghars.toml".into(),
            renderer_schema: crate::systemd::RENDERER_SCHEMA,
        }
    }

    fn minimal_cache_binding(name: &str) -> crate::config::EffectiveCacheBinding {
        crate::config::EffectiveCacheBinding {
            name: name.into(),
            kinds: vec![crate::config::CacheKind::Sccache],
            size: "100G".into(),
            mode: crate::config::CacheMode::Shared,
            trust_zone: "default".into(),
            sccache_path: Some("/usr/bin/sccache".into()),
            sleep_path: None,
            server_mode: crate::config::SccacheServerMode::Pooled,
            renderer_schema: crate::systemd::RENDERER_SCHEMA,
        }
    }
}
