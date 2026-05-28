//! apply.rs integration tests.
//!
//! Coverage focus (paths exercisable from integration-test layer with
//! the public traits Tarball / `ConfigShell` + a public Systemd
//! mock):
//!
//! `execute_create_runner` branch coverage:
//!   - local tarball path: `spec.runner_tarball.is_some()` skips
//!     `fetch_or_verify`, calls `verify_local`.
//!   - no-release error: `runner_tarball.is_none()` and
//!     `resolved_release.is_none()` errors with Validation referencing
//!     "no `runner_tarball` and no resolved release".
//!   - mint failure: auth registry missing key → `mint_token` errors.
//!   - `config_shell` failure: `run_register` fails → propagated.
//!
//! `apply()` result accumulation:
//!   - `fail_fast=false` with multi-failure plan: every failure lands
//!     in `result.failed`; `result.ok()` is false.
//!   - `dry_run` skips `daemon_reload` (already covered in-tree via
//!     `dry_run_skips_actions_but_holds_lock`; we add coverage of
//!     `dry_run` with non-NoOp actions).
//!   - `daemon_reload` failure: appended to `result.failed` with label
//!     "`daemon_reload`" and is NOT short-circuited by `fail_fast`.
//!
//! Note on integration-test reachability: the production
//! `write_root_owned` calls `fchown(fd, root:root)`. Integration tests
//! run unprivileged, so any branch that lands on `write_root_owned`
//! will EPERM at the fchown step. We exercise paths that DO NOT hit
//! `write_root_owned` (validation errors, mint errors, `config_shell`
//! errors before the unit-text write) PLUS apply-orchestration paths
//! whose execute_* errors before `write_root_owned` (cache pool create
//! with a systemd that fails on `enable_unit`, etc.).
//!
//! The in-tree #[cfg(test)] mod tests block in apply.rs covers the
//! happy paths via `chown_to_root` cfg(test) no-op. These integration
//! tests cover branches that error BEFORE `write_root_owned`, which is
//! orthogonal coverage.

#![allow(clippy::unwrap_used, clippy::expect_used)]

use camino::{Utf8Path, Utf8PathBuf};
use chrono::Utc;
use ghars::apply::{
    ApplyOptions, ConfigShell, ConfigShellCtx, Deps, Tarball, UndoLog, apply, execute,
};
use ghars::auth::{RegistrationToken, TokenSource};
use ghars::config::{
    Arch, CacheKind, CacheMode, EffectiveCacheBinding, EffectiveRunnerSpec, Hardening,
};
use ghars::error::GharsError;
use ghars::paths::Paths;
use ghars::plan::{Action, CachePoolDelta, CachePoolPlan, Plan, RunnerPlan};
use ghars::systemd::{Systemd, UnitListEntry};
use std::collections::{BTreeMap, HashMap};
use std::sync::Mutex;

// --- Mocks (parallel to the in-tree apply::tests Mocks but at the
//     public Trait surface so the integration-test layer can use them).

#[derive(Default)]
struct TestSystemd {
    calls: Mutex<Vec<String>>,
    fail_daemon_reload: Mutex<bool>,
    fail_enable: Mutex<bool>,
    fail_start: Mutex<bool>,
    properties: Mutex<HashMap<(String, String), String>>,
}

impl TestSystemd {
    fn calls(&self) -> Vec<String> {
        self.calls.lock().unwrap().clone()
    }
    fn record(&self, s: impl Into<String>) {
        self.calls.lock().unwrap().push(s.into());
    }
}

impl Systemd for TestSystemd {
    fn daemon_reload(&self) -> ghars::Result<()> {
        self.record("daemon_reload");
        if *self.fail_daemon_reload.lock().unwrap() {
            return Err(GharsError::Systemd(
                "test: daemon_reload failure".into(),
                "test".into(),
            ));
        }
        Ok(())
    }
    fn start_unit(&self, unit: &str) -> ghars::Result<()> {
        self.record(format!("start_unit({unit})"));
        if *self.fail_start.lock().unwrap() {
            return Err(GharsError::Systemd(
                format!("test: start_unit({unit}) failure"),
                "test".into(),
            ));
        }
        Ok(())
    }
    fn stop_unit(&self, unit: &str) -> ghars::Result<()> {
        self.record(format!("stop_unit({unit})"));
        Ok(())
    }
    fn enable_unit(&self, unit: &str) -> ghars::Result<()> {
        self.record(format!("enable_unit({unit})"));
        if *self.fail_enable.lock().unwrap() {
            return Err(GharsError::Systemd(
                format!("test: enable_unit({unit}) failure"),
                "test".into(),
            ));
        }
        Ok(())
    }
    fn disable_unit(&self, unit: &str) -> ghars::Result<()> {
        self.record(format!("disable_unit({unit})"));
        Ok(())
    }
    fn list_units_filtered(&self, _states: &[&str]) -> ghars::Result<Vec<UnitListEntry>> {
        Ok(vec![])
    }
    fn get_unit_property(&self, unit: &str, _iface: &str, property: &str) -> ghars::Result<String> {
        self.properties
            .lock()
            .unwrap()
            .get(&(unit.into(), property.into()))
            .cloned()
            .ok_or_else(|| {
                GharsError::Systemd(
                    format!("TestSystemd: no property {property} on {unit}"),
                    "fixture".into(),
                )
            })
    }
    fn get_unit_property_u64(&self, unit: &str, iface: &str, property: &str) -> ghars::Result<u64> {
        self.get_unit_property(unit, iface, property)?
            .trim()
            .parse::<u64>()
            .map_err(|e| {
                GharsError::Systemd(
                    format!("TestSystemd: {property} on {unit} not u64: {e}"),
                    "fixture".into(),
                )
            })
    }
    fn get_unit_property_object_path(
        &self,
        _: &str,
        _: &str,
        _: &str,
    ) -> ghars::Result<ghars::systemd::OwnedObjectPath> {
        unreachable!("TestSystemd does not exercise object-path properties")
    }
    fn get_service_property_string(&self, unit: &str, property: &str) -> ghars::Result<String> {
        self.get_unit_property(unit, "org.freedesktop.systemd1.Service", property)
    }
    fn get_service_property_u64(&self, unit: &str, property: &str) -> ghars::Result<u64> {
        self.get_unit_property_u64(unit, "org.freedesktop.systemd1.Service", property)
    }
    fn lookup_dynamic_user_by_name(&self, _name: &str) -> ghars::Result<Option<u32>> {
        // Default to the test process's UID so the production
        // post-start chown succeeds (chown-to-self requires no
        // CAP_CHOWN). Tests that exercise polling explicitly are
        // covered by the post-StartUnit DynamicUser chown+tighten
        // dedicated test files.
        use std::os::unix::fs::MetadataExt;
        let uid = std::fs::metadata("/proc/self")
            .map(|m| m.uid())
            .unwrap_or(0);
        Ok(Some(uid))
    }
}

#[derive(Default)]
#[allow(clippy::struct_field_names)]
struct TestTarball {
    fail_fetch: Mutex<bool>,
    fail_verify_local: Mutex<bool>,
    fail_install: Mutex<bool>,
}

impl Tarball for TestTarball {
    fn fetch_or_verify(
        &self,
        _url: &str,
        _dest_path: &Utf8Path,
        _expected_sha256: &str,
    ) -> ghars::Result<()> {
        if *self.fail_fetch.lock().unwrap() {
            return Err(GharsError::Tarball("test: fetch failure".into(), None));
        }
        Ok(())
    }
    fn verify_local(&self, _path: &Utf8Path) -> ghars::Result<()> {
        if *self.fail_verify_local.lock().unwrap() {
            return Err(GharsError::Tarball(
                "test: verify_local failure".into(),
                None,
            ));
        }
        Ok(())
    }
    fn install_binary(
        &self,
        _tarball_path: &Utf8Path,
        _state_dir: &Utf8Path,
        runner_home: &Utf8Path,
        _runner_name: &str,
        version: &str,
    ) -> ghars::Result<Utf8PathBuf> {
        if *self.fail_install.lock().unwrap() {
            return Err(GharsError::Tarball("test: install failure".into(), None));
        }
        let bin = runner_home.join(format!("bin.{version}"));
        std::fs::create_dir_all(bin.as_std_path())?;
        Ok(bin)
    }
    fn prune_old_versions(
        &self,
        _runner_home: &Utf8Path,
        _keep_versions: u32,
    ) -> ghars::Result<usize> {
        Ok(0)
    }
}

#[derive(Default)]
struct TestConfigShell {
    fail_register: Mutex<bool>,
}

impl ConfigShell for TestConfigShell {
    fn run_register(&self, ctx: &ConfigShellCtx<'_>) -> ghars::Result<()> {
        if *self.fail_register.lock().unwrap() {
            return Err(GharsError::Apply {
                action: format!("config.sh register({})", ctx.name),
                source: Box::new(GharsError::Io(std::io::Error::other(
                    "test: register failure",
                ))),
            });
        }
        // Mirror the production behaviour: ensure runner_home exists.
        // The real config.sh writes .runner / .credentials there;
        // tests don't model those files for the orchestration code
        // path.
        std::fs::create_dir_all(ctx.runner_home.as_std_path())?;
        Ok(())
    }
    fn run_remove(&self, _ctx: &ConfigShellCtx<'_>) -> ghars::Result<()> {
        Ok(())
    }
}

struct TestTokenSource {
    name: String,
    fail_mint: bool,
}

impl TokenSource for TestTokenSource {
    fn name(&self) -> &str {
        &self.name
    }
    fn mint_registration_token(&self, _runner_url: &str) -> ghars::Result<RegistrationToken> {
        if self.fail_mint {
            return Err(GharsError::Auth(
                format!("test: mint failed for {}", self.name),
                "test fixture".into(),
            ));
        }
        Ok(RegistrationToken {
            value: "REG-TOKEN".into(),
            expires_at: Utc::now(),
            source: format!("test:{}", self.name),
        })
    }
    fn mint_removal_token(&self, _runner_url: &str) -> ghars::Result<RegistrationToken> {
        Ok(RegistrationToken {
            value: "RM-TOKEN".into(),
            expires_at: Utc::now(),
            source: format!("test:{}", self.name),
        })
    }
}

fn make_paths(tmp: &tempfile::TempDir) -> Paths {
    let root = Utf8PathBuf::from_path_buf(tmp.path().to_path_buf()).unwrap();
    Paths {
        state_dir: root.join("state"),
        cache_dir: root.join("cache"),
        logs_dir: root.join("logs"),
        unit_dir: root.join("units"),
        credentials_dir: root.join("creds"),
        runtime_dir: root.join("run"),
        config_dir: root.join("etc"),
        resolved_conf_d: root.join("resolved.conf.d"),
    }
}

fn make_spec(name: &str, _prefix: &Utf8Path) -> EffectiveRunnerSpec {
    EffectiveRunnerSpec {
        name: name.into(),
        url: "https://github.com/example/repo".into(),
        arch: Arch::X86_64,
        labels: vec!["self-hosted".into(), "linux".into()],
        memory_max: None,
        runner_version: Some("2.334.0".into()),
        runner_sha256: None,
        runner_tarball: None,
        auth_name: "pat".into(),
        caches: vec![],
        trust_zone: "default".into(),
        network: None,
        proxy: None,
        hooks: None,
        hardening: Hardening::default(),
        allowed_cpus: None,
        allowed_memory_nodes: None,
        environment: ghars::config::EnvironmentSpec::default(),
        spec_hash: "sha256:dead".into(),
        config_source: "/etc/ghars/ghars.toml".into(),
        renderer_schema: ghars::systemd::RENDERER_SCHEMA,
    }
}

fn make_runner_plan(name: &str, prefix: &Utf8Path) -> RunnerPlan {
    let spec = make_spec(name, prefix);
    let mut drop_ins: BTreeMap<String, String> = BTreeMap::new();
    drop_ins.insert(
        "00-ghars.conf".into(),
        "[Unit]\nX-Ghars-Spec-Hash=sha256:dead\n".into(),
    );
    // Populate via real renderers (post-snapshot-coverage uniformity). The env_file
    // and path_file pre-renderers are `pub(crate)`; integration
    // tests reach them via `render_runner_unit` which calls them
    // internally and exposes the bytes on `RenderedUnit.env_file`
    // and `.path_file`. Apply-orchestration tests here drive
    // CreateRunner only — apply reads env/path bytes from
    // install_binary's rendered output, not from these fields —
    // so empty strings were functionally harmless. Using the real
    // renderers anyway keeps test-fixture bytes uniform across the
    // suite (matches make_runner_plan in src/apply/tests/common.rs).
    let rendered = ghars::systemd::render_runner_unit(&spec).unwrap();
    RunnerPlan {
        spec,
        resolved_release: None,
        effective_unit_text: "[Unit]\nDescription=test\n".into(),
        drop_ins,
        env_file: rendered.env_file,
        path_file: rendered.path_file,
        cleanup_script: rendered.cleanup_script,
        spec_hash: "sha256:dead".into(),
    }
}

fn make_pool_plan(name: &str) -> CachePoolPlan {
    CachePoolPlan {
        binding: EffectiveCacheBinding {
            name: name.into(),
            kinds: vec![CacheKind::Ccache],
            size: "200G".into(),
            mode: CacheMode::Shared,
            trust_zone: "default".into(),
            sccache_path: None,
            sleep_path: Some("/usr/bin/sleep".into()),
            server_mode: ghars::config::SccacheServerMode::Pooled,
            renderer_schema: ghars::systemd::RENDERER_SCHEMA,
        },
        drop_in_body: "[Service]\nExecStart=/usr/bin/sleep infinity\n".into(),
        spec_hash: "sha256:abcd".into(),
    }
}

fn deps<'a>(
    systemd: &'a TestSystemd,
    auth: &'a HashMap<String, Box<dyn TokenSource>>,
    tarball: &'a TestTarball,
    config_shell: &'a TestConfigShell,
) -> Deps<'a> {
    Deps {
        systemd,
        auth,
        tarball,
        config_shell,
    }
}

// --- execute_create_runner branch coverage --------------------------------

#[test]
fn create_runner_errors_when_no_release_and_no_local_tarball() {
    // Plan with `runner_tarball=None` and `resolved_release=None`
    // must error with a Validation error before any Tarball method is
    // called.
    let tmp = tempfile::tempdir().unwrap();
    let paths = make_paths(&tmp);
    std::fs::create_dir_all(paths.runtime_dir.as_std_path()).unwrap();
    let plan = make_runner_plan("a", &paths.state_dir);
    // plan.spec.runner_tarball = None; plan.resolved_release = None.
    let systemd = TestSystemd::default();
    let mut auth_map: HashMap<String, Box<dyn TokenSource>> = HashMap::new();
    auth_map.insert(
        "pat".into(),
        Box::new(TestTokenSource {
            name: "pat".into(),
            fail_mint: false,
        }),
    );
    let tarball = TestTarball::default();
    let config_shell = TestConfigShell::default();
    let d = deps(&systemd, &auth_map, &tarball, &config_shell);
    let action = Action::CreateRunner(plan);
    let err = execute(&action, &d, &paths, &mut UndoLog::new(), 2, false)
        .expect_err("must error on no release + no tarball");
    let msg = format!("{err}");
    assert!(
        msg.contains("no runner_tarball") || msg.contains("resolved release"),
        "expected no-source error: {msg}"
    );
}

#[test]
fn create_runner_errors_when_auth_registry_missing_key() {
    // Plan has spec.auth_name = "pat" but auth registry is empty →
    // mint_token errors with `auth source "pat" referenced by runner
    // is not in the registry`.
    let tmp = tempfile::tempdir().unwrap();
    let paths = make_paths(&tmp);
    std::fs::create_dir_all(paths.runtime_dir.as_std_path()).unwrap();
    let mut plan = make_runner_plan("a", &paths.state_dir);
    plan.spec.runner_tarball = Some(Utf8PathBuf::from("/tmp/local-tarball.tar.gz"));
    let systemd = TestSystemd::default();
    let auth_map: HashMap<String, Box<dyn TokenSource>> = HashMap::new();
    let tarball = TestTarball::default();
    let config_shell = TestConfigShell::default();
    let d = deps(&systemd, &auth_map, &tarball, &config_shell);
    let action = Action::CreateRunner(plan);
    let err = execute(&action, &d, &paths, &mut UndoLog::new(), 2, false)
        .expect_err("must error on missing auth");
    let msg = format!("{err}");
    assert!(msg.contains("auth") && msg.contains("pat"), "{msg}");
}

#[test]
fn create_runner_errors_when_token_mint_fails() {
    // Auth registry has the key but the mint call itself errors.
    let tmp = tempfile::tempdir().unwrap();
    let paths = make_paths(&tmp);
    std::fs::create_dir_all(paths.runtime_dir.as_std_path()).unwrap();
    let mut plan = make_runner_plan("a", &paths.state_dir);
    plan.spec.runner_tarball = Some(Utf8PathBuf::from("/tmp/local-tarball.tar.gz"));
    let systemd = TestSystemd::default();
    let mut auth_map: HashMap<String, Box<dyn TokenSource>> = HashMap::new();
    auth_map.insert(
        "pat".into(),
        Box::new(TestTokenSource {
            name: "pat".into(),
            fail_mint: true,
        }),
    );
    let tarball = TestTarball::default();
    let config_shell = TestConfigShell::default();
    let d = deps(&systemd, &auth_map, &tarball, &config_shell);
    let action = Action::CreateRunner(plan);
    let err = execute(&action, &d, &paths, &mut UndoLog::new(), 2, false)
        .expect_err("must error on mint failure");
    assert!(format!("{err}").contains("mint failed"));
}

#[test]
fn create_runner_errors_when_verify_local_fails() {
    // Local tarball path: spec.runner_tarball is Some(...). The
    // tarball trait's `verify_local` is failing — must surface.
    let tmp = tempfile::tempdir().unwrap();
    let paths = make_paths(&tmp);
    std::fs::create_dir_all(paths.runtime_dir.as_std_path()).unwrap();
    let mut plan = make_runner_plan("a", &paths.state_dir);
    plan.spec.runner_tarball = Some(Utf8PathBuf::from("/tmp/local-tarball.tar.gz"));
    let systemd = TestSystemd::default();
    let mut auth_map: HashMap<String, Box<dyn TokenSource>> = HashMap::new();
    auth_map.insert(
        "pat".into(),
        Box::new(TestTokenSource {
            name: "pat".into(),
            fail_mint: false,
        }),
    );
    let tarball = TestTarball::default();
    *tarball.fail_verify_local.lock().unwrap() = true;
    let config_shell = TestConfigShell::default();
    let d = deps(&systemd, &auth_map, &tarball, &config_shell);
    let action = Action::CreateRunner(plan);
    let err = execute(&action, &d, &paths, &mut UndoLog::new(), 2, false)
        .expect_err("must error on verify_local failure");
    assert!(format!("{err}").contains("verify_local failure"));
}

#[test]
fn create_runner_errors_when_install_binary_fails() {
    let tmp = tempfile::tempdir().unwrap();
    let paths = make_paths(&tmp);
    std::fs::create_dir_all(paths.runtime_dir.as_std_path()).unwrap();
    let mut plan = make_runner_plan("a", &paths.state_dir);
    plan.spec.runner_tarball = Some(Utf8PathBuf::from("/tmp/local-tarball.tar.gz"));
    let systemd = TestSystemd::default();
    let mut auth_map: HashMap<String, Box<dyn TokenSource>> = HashMap::new();
    auth_map.insert(
        "pat".into(),
        Box::new(TestTokenSource {
            name: "pat".into(),
            fail_mint: false,
        }),
    );
    let tarball = TestTarball::default();
    *tarball.fail_install.lock().unwrap() = true;
    let config_shell = TestConfigShell::default();
    let d = deps(&systemd, &auth_map, &tarball, &config_shell);
    let action = Action::CreateRunner(plan);
    let err = execute(&action, &d, &paths, &mut UndoLog::new(), 2, false)
        .expect_err("must error on install_binary failure");
    assert!(format!("{err}").contains("install failure"));
}

#[test]
fn create_runner_errors_when_config_shell_register_fails() {
    let tmp = tempfile::tempdir().unwrap();
    let paths = make_paths(&tmp);
    std::fs::create_dir_all(paths.runtime_dir.as_std_path()).unwrap();
    let mut plan = make_runner_plan("a", &paths.state_dir);
    plan.spec.runner_tarball = Some(Utf8PathBuf::from("/tmp/local-tarball.tar.gz"));
    let systemd = TestSystemd::default();
    let mut auth_map: HashMap<String, Box<dyn TokenSource>> = HashMap::new();
    auth_map.insert(
        "pat".into(),
        Box::new(TestTokenSource {
            name: "pat".into(),
            fail_mint: false,
        }),
    );
    let tarball = TestTarball::default();
    let config_shell = TestConfigShell::default();
    *config_shell.fail_register.lock().unwrap() = true;
    let d = deps(&systemd, &auth_map, &tarball, &config_shell);
    let action = Action::CreateRunner(plan);
    let err = execute(&action, &d, &paths, &mut UndoLog::new(), 2, false)
        .expect_err("must error on register failure");
    assert!(format!("{err}").contains("register"));
}

// --- apply() result accumulation ---------------------------------------

#[test]
fn apply_fail_fast_false_accumulates_multiple_failures() {
    // Build a plan with two cache pools that both fail at enable_unit
    // (TestSystemd's fail_enable is global). With fail_fast=false,
    // both failures must land in result.failed.
    let tmp = tempfile::tempdir().unwrap();
    let paths = make_paths(&tmp);
    std::fs::create_dir_all(paths.runtime_dir.as_std_path()).unwrap();
    let plan = Plan {
        actions: vec![
            Action::CreateCachePool(make_pool_plan("a")),
            Action::CreateCachePool(make_pool_plan("b")),
        ],
        warnings: vec![],
        keep_versions: 2,
    };
    let systemd = TestSystemd::default();
    *systemd.fail_enable.lock().unwrap() = true;
    let auth_map: HashMap<String, Box<dyn TokenSource>> = HashMap::new();
    let tarball = TestTarball::default();
    let config_shell = TestConfigShell::default();
    let opts = ApplyOptions {
        fail_fast: false,
        ..ApplyOptions::default()
    };
    let d = deps(&systemd, &auth_map, &tarball, &config_shell);
    let result = apply(&plan, &d, &paths, &opts).unwrap();
    // Both pool creates failed. fail_fast=false → both accumulated.
    // With root running unprivileged in CI, write_root_owned errors
    // before enable_unit fires; so there may be some other accumulated
    // failures in the chain, but we accept any state where:
    //  - result.ok() is false
    //  - result.failed has at least 2 entries (one for pool a, one for
    //    pool b — neither was short-circuited)
    assert!(
        !result.ok(),
        "expected at least one failure; result={result:?}"
    );
    let pool_a_failed = result
        .failed
        .iter()
        .any(|(label, _)| label.contains("CreateCachePool(a)"));
    let pool_b_failed = result
        .failed
        .iter()
        .any(|(label, _)| label.contains("CreateCachePool(b)"));
    assert!(
        pool_a_failed && pool_b_failed,
        "fail_fast=false must accumulate BOTH pool failures; got: {:?}",
        result.failed.iter().map(|(l, _)| l).collect::<Vec<_>>()
    );
}

#[test]
fn apply_fail_fast_true_short_circuits_on_first_failure() {
    let tmp = tempfile::tempdir().unwrap();
    let paths = make_paths(&tmp);
    std::fs::create_dir_all(paths.runtime_dir.as_std_path()).unwrap();
    let plan = Plan {
        actions: vec![
            Action::CreateCachePool(make_pool_plan("first")),
            Action::CreateCachePool(make_pool_plan("second")),
        ],
        warnings: vec![],
        keep_versions: 2,
    };
    let systemd = TestSystemd::default();
    *systemd.fail_enable.lock().unwrap() = true;
    let auth_map: HashMap<String, Box<dyn TokenSource>> = HashMap::new();
    let tarball = TestTarball::default();
    let config_shell = TestConfigShell::default();
    let opts = ApplyOptions {
        fail_fast: true,
        ..ApplyOptions::default()
    };
    let d = deps(&systemd, &auth_map, &tarball, &config_shell);
    let result = apply(&plan, &d, &paths, &opts).unwrap();
    assert!(!result.ok());
    // First failure recorded; second NEVER attempted. result.failed
    // contains exactly one entry whose label is the first action.
    assert_eq!(result.failed.len(), 1);
    assert!(result.failed[0].0.contains("CreateCachePool(first)"));
    // Second pool was not attempted — neither succeeded nor failed.
    let second_attempted = result
        .succeeded
        .iter()
        .any(|s| s.contains("CreateCachePool(second)"))
        || result
            .failed
            .iter()
            .any(|(l, _)| l.contains("CreateCachePool(second)"));
    assert!(
        !second_attempted,
        "fail_fast=true must short-circuit before second action: {result:?}"
    );
}

#[test]
fn apply_dry_run_skips_all_non_noop_actions() {
    // dry_run=true → every action recorded in result.skipped, no
    // execute_* calls, no daemon_reload at the end.
    let tmp = tempfile::tempdir().unwrap();
    let paths = make_paths(&tmp);
    std::fs::create_dir_all(paths.runtime_dir.as_std_path()).unwrap();
    let plan = Plan {
        actions: vec![
            Action::CreateCachePool(make_pool_plan("dry")),
            Action::NoOp("nothing to do".into()),
        ],
        warnings: vec![],
        keep_versions: 2,
    };
    let systemd = TestSystemd::default();
    let auth_map: HashMap<String, Box<dyn TokenSource>> = HashMap::new();
    let tarball = TestTarball::default();
    let config_shell = TestConfigShell::default();
    let opts = ApplyOptions {
        dry_run: true,
        ..ApplyOptions::default()
    };
    let d = deps(&systemd, &auth_map, &tarball, &config_shell);
    let result = apply(&plan, &d, &paths, &opts).unwrap();
    assert!(result.ok());
    // Both actions skipped (CreateCachePool because dry_run, NoOp
    // because NoOp).
    assert_eq!(result.skipped.len(), 2);
    assert!(result.failed.is_empty());
    // No systemd calls at all — daemon_reload skipped under dry_run.
    let calls = systemd.calls();
    assert!(
        calls.is_empty(),
        "dry_run must not call any systemd methods: {calls:?}"
    );
}

#[test]
fn apply_daemon_reload_failure_appends_to_result_failed() {
    // Successful per-action loop, then daemon_reload errors. The
    // failure must be recorded with label "daemon_reload" and
    // result.ok() returns false.
    let tmp = tempfile::tempdir().unwrap();
    let paths = make_paths(&tmp);
    std::fs::create_dir_all(paths.runtime_dir.as_std_path()).unwrap();
    let plan = Plan {
        actions: vec![Action::NoOp("idempotent".into())],
        warnings: vec![],
        keep_versions: 2,
    };
    let systemd = TestSystemd::default();
    *systemd.fail_daemon_reload.lock().unwrap() = true;
    let auth_map: HashMap<String, Box<dyn TokenSource>> = HashMap::new();
    let tarball = TestTarball::default();
    let config_shell = TestConfigShell::default();
    let opts = ApplyOptions::default();
    let d = deps(&systemd, &auth_map, &tarball, &config_shell);
    let result = apply(&plan, &d, &paths, &opts).unwrap();
    assert!(!result.ok());
    assert!(
        result
            .failed
            .iter()
            .any(|(label, _)| label == "daemon_reload"),
        "daemon_reload failure must be recorded: {:?}",
        result.failed.iter().map(|(l, _)| l).collect::<Vec<_>>()
    );
}

#[test]
fn apply_dry_run_holds_lock_during_run() {
    // dry_run still acquires the apply.lock; a concurrent acquire
    // must observe ApplyLocked. We can't easily verify mid-run lock
    // hold from outside, but we verify the lock is RELEASED after
    // dry_run completes — a fresh acquire succeeds.
    let tmp = tempfile::tempdir().unwrap();
    let paths = make_paths(&tmp);
    std::fs::create_dir_all(paths.runtime_dir.as_std_path()).unwrap();
    let plan = Plan {
        actions: vec![Action::NoOp("dry".into())],
        warnings: vec![],
        keep_versions: 2,
    };
    let systemd = TestSystemd::default();
    let auth_map: HashMap<String, Box<dyn TokenSource>> = HashMap::new();
    let tarball = TestTarball::default();
    let config_shell = TestConfigShell::default();
    let opts = ApplyOptions {
        dry_run: true,
        ..ApplyOptions::default()
    };
    let d = deps(&systemd, &auth_map, &tarball, &config_shell);
    apply(&plan, &d, &paths, &opts).unwrap();
    // After Drop, lock released — re-acquire succeeds.
    let _lock = ghars::apply::acquire_lock(&paths).unwrap();
}

#[test]
fn apply_records_success_for_noop_actions_in_skipped_not_succeeded() {
    // NoOp is treated as skipped, not succeeded. Verify the contract.
    let tmp = tempfile::tempdir().unwrap();
    let paths = make_paths(&tmp);
    std::fs::create_dir_all(paths.runtime_dir.as_std_path()).unwrap();
    let plan = Plan {
        actions: vec![
            Action::NoOp("foo: in sync".into()),
            Action::NoOp("bar: in sync".into()),
        ],
        warnings: vec![],
        keep_versions: 2,
    };
    let systemd = TestSystemd::default();
    let auth_map: HashMap<String, Box<dyn TokenSource>> = HashMap::new();
    let tarball = TestTarball::default();
    let config_shell = TestConfigShell::default();
    let opts = ApplyOptions::default();
    let d = deps(&systemd, &auth_map, &tarball, &config_shell);
    let result = apply(&plan, &d, &paths, &opts).unwrap();
    assert!(result.ok(), "{:?}", result.failed);
    assert!(result.succeeded.is_empty());
    assert_eq!(result.skipped.len(), 2);
    // daemon_reload still called (non-dry-run).
    assert!(systemd.calls().iter().any(|c| c == "daemon_reload"));
}

#[test]
fn apply_empty_plan_still_runs_daemon_reload() {
    // Edge case: empty actions list. apply() must still call
    // daemon_reload at the end (matches Part 8 — the call is
    // unconditional outside dry_run, and idempotent so an empty
    // plan re-issuing it is safe).
    let tmp = tempfile::tempdir().unwrap();
    let paths = make_paths(&tmp);
    std::fs::create_dir_all(paths.runtime_dir.as_std_path()).unwrap();
    let plan = Plan {
        actions: vec![],
        warnings: vec![],
        keep_versions: 2,
    };
    let systemd = TestSystemd::default();
    let auth_map: HashMap<String, Box<dyn TokenSource>> = HashMap::new();
    let tarball = TestTarball::default();
    let config_shell = TestConfigShell::default();
    let opts = ApplyOptions::default();
    let d = deps(&systemd, &auth_map, &tarball, &config_shell);
    let result = apply(&plan, &d, &paths, &opts).unwrap();
    assert!(result.ok());
    assert!(result.skipped.is_empty());
    assert!(result.succeeded.is_empty());
    assert_eq!(systemd.calls(), vec!["daemon_reload"]);
}

#[test]
fn apply_remove_cache_pool_records_action_label_on_success() {
    // Pure remove with empty fs state — execute_remove_cache_pool's
    // stop/disable + dir-cleanup paths are no-ops (dirs don't exist),
    // so the action succeeds and lands in result.succeeded.
    let tmp = tempfile::tempdir().unwrap();
    let paths = make_paths(&tmp);
    std::fs::create_dir_all(paths.runtime_dir.as_std_path()).unwrap();
    let plan = Plan {
        actions: vec![Action::RemoveCachePool("absent".into())],
        warnings: vec![],
        keep_versions: 2,
    };
    let systemd = TestSystemd::default();
    let auth_map: HashMap<String, Box<dyn TokenSource>> = HashMap::new();
    let tarball = TestTarball::default();
    let config_shell = TestConfigShell::default();
    let opts = ApplyOptions::default();
    let d = deps(&systemd, &auth_map, &tarball, &config_shell);
    let result = apply(&plan, &d, &paths, &opts).unwrap();
    assert!(result.ok(), "{:?}", result.failed);
    assert!(
        result
            .succeeded
            .iter()
            .any(|s| s.contains("RemoveCachePool(absent)"))
    );
}

// Suppress unused-warning for fields the test fixture doesn't yet
// exercise but keeps available for future expansion.
#[allow(dead_code)]
fn _references_to_keep_imports() -> CachePoolDelta {
    CachePoolDelta {
        binding: EffectiveCacheBinding {
            name: "x".into(),
            kinds: vec![CacheKind::Ccache],
            size: "1G".into(),
            mode: CacheMode::Shared,
            trust_zone: "default".into(),
            sccache_path: None,
            sleep_path: Some("/usr/bin/sleep".into()),
            server_mode: ghars::config::SccacheServerMode::Pooled,
            renderer_schema: ghars::systemd::RENDERER_SCHEMA,
        },
        drop_in_body: String::new(),
        spec_hash: String::new(),
    }
}

// ---------- failed / failed_undo_logs ordering invariant tests --------
//
// `apply::apply` populates two parallel Vecs on every per-action error
// arm: `result.failed: Vec<(String, GharsError)>` and
// `result.failed_undo_logs: Vec<(String, Vec<UndoStep>)>`. The
// production code pushes both within the same loop iteration
// (apply.rs: per-action arm pushes failed first, then failed_undo_logs
// alongside; synthetic post-loop daemon_reload arm does the same with
// empty steps). This pairing is the load-bearing invariant
// `failed[i].0 == failed_undo_logs[i].0` for every i, plus
// `failed.len() == failed_undo_logs.len()`. The advisory renderer
// (`render_rollback_advisory`) and the `--rollback-on-failure`
// resolver depend on it.
//
// These tests pin the invariant from the integration-test layer where
// real `apply::apply` runs end-to-end. The proptest feeds N random
// CreateCachePool actions through the failure path; the two directed
// siblings cover fail_fast=true (single-failure short-circuit) and the
// daemon_reload-only failure (post-loop arm with empty step list).

proptest::proptest! {
    /// Property: with `fail_fast=false` and N (2..=8) CreateCachePool
    /// actions all forced to fail (TestSystemd::fail_enable=true),
    /// the per-action arm pushes both Vecs in lockstep so:
    /// (a) `failed.len() == failed_undo_logs.len()` (universal length
    ///     invariant), and
    /// (b) `failed[i].0 == failed_undo_logs[i].0` for every i (pair
    ///     ordering invariant — the advisory renderer relies on this
    ///     to attribute step lists to the right action).
    ///
    /// Why proptest over a fixed N: a future refactor that decouples
    /// the two Vec pushes (e.g. moves the typed-error push to a
    /// post-loop sweep) would still pass a fixed-N=2 directed test if
    /// it happens to produce a length-equal Vec. Sweeping 2..=8 forces
    /// the lockstep push to hold across the whole loop body.
    ///
    /// Bounds rationale: 2 = minimum multi-action lockstep (n=1 covered
    /// by directed fail_fast sibling); 8 = practical ceiling for proptest
    /// runtime (each case creates a tempdir + runs apply end-to-end).
    #[test]
    fn apply_failed_and_failed_undo_logs_share_label_ordering(n in 2usize..=8) {
        let tmp = tempfile::tempdir().unwrap();
        let paths = make_paths(&tmp);
        std::fs::create_dir_all(paths.runtime_dir.as_std_path()).unwrap();
        let actions: Vec<Action> = (0..n)
            .map(|i| Action::CreateCachePool(make_pool_plan(&format!("p{i}"))))
            .collect();
        let plan = Plan {
            actions,
            warnings: vec![],
            keep_versions: 2,
        };
        let systemd = TestSystemd::default();
        *systemd.fail_enable.lock().unwrap() = true;
        let auth_map: HashMap<String, Box<dyn TokenSource>> = HashMap::new();
        let tarball = TestTarball::default();
            let config_shell = TestConfigShell::default();
        let opts = ApplyOptions {
            fail_fast: false,
            ..ApplyOptions::default()
        };
        let d = deps(&systemd, &auth_map, &tarball, &config_shell);
        let result = apply(&plan, &d, &paths, &opts).unwrap();
        // Pre-assertion: prevent trivially-passing proptest by pinning
        // that all N actions actually failed before checking lockstep.
        proptest::prop_assert_eq!(result.failed.len(), n, "all N actions must have failed");
        // Universal length invariant.
        proptest::prop_assert_eq!(
            result.failed.len(),
            result.failed_undo_logs.len(),
            "failed and failed_undo_logs lengths must agree"
        );
        // Pair-ordering invariant — every label in failed[i] matches
        // the label in failed_undo_logs[i].
        for i in 0..result.failed.len() {
            proptest::prop_assert_eq!(
                &result.failed[i].0,
                &result.failed_undo_logs[i].0,
                "label-pair ordering invariant violated at index {}", i
            );
        }
    }
}

/// Directed sibling to the proptest: with `fail_fast=true` and 3
/// actions where the first action fails, the per-action arm pushes
/// to BOTH `failed` and `failed_undo_logs` once and then short-
/// circuits — so both Vecs end with exactly one entry (the first
/// action's label) and the actions after it are never attempted.
/// Pins that the lockstep invariant holds even on the fail-fast
/// short-circuit return path (apply.rs: the `if opts.fail_fast`
/// arm returns Ok(result) AFTER both pushes, not before).
#[test]
fn apply_fail_fast_pushes_failed_and_undo_logs_in_lockstep() {
    let tmp = tempfile::tempdir().unwrap();
    let paths = make_paths(&tmp);
    std::fs::create_dir_all(paths.runtime_dir.as_std_path()).unwrap();
    let plan = Plan {
        actions: vec![
            Action::CreateCachePool(make_pool_plan("first")),
            Action::CreateCachePool(make_pool_plan("second")),
            Action::CreateCachePool(make_pool_plan("third")),
        ],
        warnings: vec![],
        keep_versions: 2,
    };
    let systemd = TestSystemd::default();
    *systemd.fail_enable.lock().unwrap() = true;
    let auth_map: HashMap<String, Box<dyn TokenSource>> = HashMap::new();
    let tarball = TestTarball::default();
    let config_shell = TestConfigShell::default();
    let opts = ApplyOptions {
        fail_fast: true,
        ..ApplyOptions::default()
    };
    let d = deps(&systemd, &auth_map, &tarball, &config_shell);
    let result = apply(&plan, &d, &paths, &opts).unwrap();
    assert_eq!(
        result.failed.len(),
        1,
        "fail_fast must short-circuit at the first failure: {:?}",
        result.failed
    );
    assert_eq!(
        result.failed_undo_logs.len(),
        1,
        "failed_undo_logs must match failed length under fail_fast: {:?}",
        result
            .failed_undo_logs
            .iter()
            .map(|(l, _)| l)
            .collect::<Vec<_>>()
    );
    assert_eq!(
        result.failed[0].0, result.failed_undo_logs[0].0,
        "lockstep invariant on the single failed entry under fail_fast"
    );
    assert!(
        result.failed[0].0.contains("CreateCachePool(first)"),
        "first action's label expected: got {:?}",
        result.failed[0].0
    );
    // Pin that fail_fast's early-return goes through the synthetic
    // post-loop daemon_reload call before returning — protects against
    // a future refactor that short-circuits BEFORE daemon_reload, which
    // would leave systemd state out-of-sync with on-disk units.
    assert!(
        systemd
            .calls
            .lock()
            .unwrap()
            .iter()
            .any(|c| c.contains("daemon_reload")),
        "fail_fast must call daemon_reload before early-return"
    );
}

/// Directed sibling: post-loop synthetic `daemon_reload` failure
/// path. All real actions succeed; the tail call to
/// `deps.systemd.daemon_reload()` errors. apply.rs's synthetic arm
/// (apply.rs: post-loop) pushes `label="daemon_reload`" to BOTH
/// `failed` and `failed_undo_logs` — the latter with an empty
/// `Vec<UndoStep>` because the synthetic step has no per-action
/// `UndoLog` (every per-action log was consumed at action-end above).
/// Pins:
/// (a) lengths still agree post-synthetic-push;
/// (b) pair-ordering invariant holds (label strings match);
/// (c) the synthetic `UndoLog` Vec is empty (not absent) — load-bearing
///     for the advisory's empty-body filter (`failed_undo_logs.iter()
///     .filter(|(_, s)| !s.is_empty())`) which strips the synthetic
///     row from the rendered cleanup checklist.
#[test]
fn apply_daemon_reload_failure_pushes_lockstep_with_empty_undo_log() {
    let tmp = tempfile::tempdir().unwrap();
    let paths = make_paths(&tmp);
    std::fs::create_dir_all(paths.runtime_dir.as_std_path()).unwrap();
    // NoOp succeeds (no host mutation); daemon_reload failure is the
    // only entry that lands in failed/failed_undo_logs.
    let plan = Plan {
        actions: vec![Action::NoOp("idempotent".into())],
        warnings: vec![],
        keep_versions: 2,
    };
    let systemd = TestSystemd::default();
    *systemd.fail_daemon_reload.lock().unwrap() = true;
    let auth_map: HashMap<String, Box<dyn TokenSource>> = HashMap::new();
    let tarball = TestTarball::default();
    let config_shell = TestConfigShell::default();
    let opts = ApplyOptions::default();
    let d = deps(&systemd, &auth_map, &tarball, &config_shell);
    let result = apply(&plan, &d, &paths, &opts).unwrap();
    assert_eq!(
        result.failed.len(),
        result.failed_undo_logs.len(),
        "lengths must agree across the synthetic post-loop push"
    );
    let daemon_reload_idx = result
        .failed
        .iter()
        .position(|(l, _)| l == "daemon_reload")
        .expect("daemon_reload entry must be in failed");
    assert_eq!(
        result.failed[daemon_reload_idx].0, result.failed_undo_logs[daemon_reload_idx].0,
        "synthetic daemon_reload label must match across both Vecs"
    );
    assert!(
        result.failed_undo_logs[daemon_reload_idx].1.is_empty(),
        "synthetic daemon_reload undo log must be empty (no per-action steps): {:?}",
        result.failed_undo_logs[daemon_reload_idx].1
    );
    // Uniqueness pin: daemon_reload must appear exactly once in the
    // failed Vec — the synthetic post-loop arm fires once per apply()
    // invocation, even if the per-action loop also produced failures.
    // A future refactor that double-pushes (e.g. catching the
    // daemon_reload error in both the loop body and the post-loop arm)
    // would silently inflate the count.
    assert_eq!(
        result
            .failed
            .iter()
            .filter(|(l, _)| l == "daemon_reload")
            .count(),
        1,
        "daemon_reload must appear exactly once in failed Vec"
    );
}
