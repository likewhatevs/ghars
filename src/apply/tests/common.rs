//! Shared mocks + fixtures used across the [`super`] test submodules.

use std::collections::{BTreeMap, HashMap};
use std::sync::Mutex;

use camino::{Utf8Path, Utf8PathBuf};
use chrono::Utc;

use crate::Result;
use crate::auth::{RegistrationToken, TokenSource};
use crate::config::{Arch, EffectiveRunnerSpec, Hardening};
use crate::error::GharsError;
use crate::paths::Paths;
use crate::plan::{CachePoolPlan, RunnerPlan};
use crate::systemd::{Systemd, UnitListEntry};

use super::super::shell::{ConfigShell, ConfigShellCtx};
use super::super::tarball::Tarball;

#[derive(Default)]
pub(super) struct MockSystemd {
    calls: Mutex<Vec<String>>,
    properties: Mutex<HashMap<(String, String), String>>,
    // Optional fault-injection. When `fail_stop_unit` is
    // Some(name), `stop_unit(name)` returns Err with a recognisable
    // message rather than recording the call. Used by recreate-path
    // tests that need execute_remove_runner to fail at its very
    // first systemd call so execute_create_runner is provably never
    // dispatched.
    pub(super) fail_stop_unit: Mutex<Option<String>>,
    // Wiring: when `fail_daemon_reload_message` is Some(msg),
    // `daemon_reload()` returns Err carrying `msg` verbatim inside
    // a `GharsError::Systemd` instead of recording the call. Used
    // by the post-loop daemon_reload escape-pin test to inject a
    // hostile control-char payload into the synthetic Failed-row
    // construction site in `apply` (post-loop daemon_reload arm).
    pub(super) fail_daemon_reload_message: Mutex<Option<String>>,
    // Per-DynamicUser-name UID map. Populated by
    // set_dynamic_user_uid() so tests can simulate systemd's
    // Manager.LookupDynamicUserByName behavior — Ok(Some(uid))
    // when the name is allocated, Ok(None) otherwise.
    pub(super) dynamic_user_uids: Mutex<HashMap<String, u32>>,
    // When `true`, lookup_dynamic_user_by_name returns Ok(None)
    // unconditionally — simulating systemd's
    // `BUS_ERROR_NO_SUCH_DYNAMIC_USER` reply for a never-realized
    // name. Lets tests exercise poll_dynamic_user_uid's
    // budget-exhaustion error path without stalling for the full
    // production 5s budget (use the `_with_budget` variant with a
    // small Duration). Default `false` so existing tests inherit
    // the test-process-uid fallback at line 174.
    pub(super) force_no_dynamic_user: Mutex<bool>,
}

impl MockSystemd {
    pub(super) fn record(&self, s: impl Into<String>) {
        self.calls.lock().unwrap().push(s.into());
    }
    pub(super) fn calls_snapshot(&self) -> Vec<String> {
        self.calls.lock().unwrap().clone()
    }
    pub(super) fn set_property(&self, unit: &str, prop: &str, value: &str) {
        self.properties
            .lock()
            .unwrap()
            .insert((unit.into(), prop.into()), value.into());
    }
    /// Simulate systemd having allocated a transient UID for a
    /// `DynamicUser=yes` name. Calls to
    /// `lookup_dynamic_user_by_name(name)` return `Ok(Some(uid))`
    /// when the name was set here; absent names return `Ok(None)`
    /// matching systemd's `BUS_ERROR_NO_SUCH_DYNAMIC_USER` reply.
    pub(super) fn set_dynamic_user_uid(&self, name: &str, uid: u32) {
        self.dynamic_user_uids
            .lock()
            .unwrap()
            .insert(name.into(), uid);
    }
    /// Force `lookup_dynamic_user_by_name` to return `Ok(None)`
    /// unconditionally (simulating a DynamicUser name that
    /// systemd never realized). Lets tests exercise
    /// `poll_dynamic_user_uid`'s budget-exhaustion error path.
    pub(super) fn set_force_no_dynamic_user(&self) {
        *self.force_no_dynamic_user.lock().unwrap() = true;
    }
}

impl Systemd for MockSystemd {
    // Failure path bypasses the call recorder: when
    // `fail_daemon_reload_message` is Some, the Err returns
    // BEFORE `record("daemon_reload")` runs, so a test asserting
    // "daemon_reload was called once" against `calls` would see
    // zero entries on this path. Symmetric with the precedent at
    // `stop_unit` below — `fail_stop_unit` likewise short-circuits
    // before recording. Tests that need to observe the failure
    // should assert against `result.failed` / `result.details`,
    // not `calls`.
    fn daemon_reload(&self) -> Result<()> {
        if let Some(msg) = self.fail_daemon_reload_message.lock().unwrap().as_deref() {
            return Err(GharsError::Systemd(msg.into(), "test".into()));
        }
        self.record("daemon_reload");
        Ok(())
    }
    fn start_unit(&self, unit: &str) -> Result<()> {
        self.record(format!("start_unit({unit})"));
        Ok(())
    }
    fn stop_unit(&self, unit: &str) -> Result<()> {
        if let Some(target) = self.fail_stop_unit.lock().unwrap().as_deref()
            && target == unit
        {
            return Err(GharsError::Systemd(
                format!("mock: stop_unit({unit}) injected failure"),
                "test injected fault via MockSystemd::fail_stop_unit".into(),
            ));
        }
        self.record(format!("stop_unit({unit})"));
        Ok(())
    }
    fn enable_unit(&self, unit: &str) -> Result<()> {
        self.record(format!("enable_unit({unit})"));
        Ok(())
    }
    fn disable_unit(&self, unit: &str) -> Result<()> {
        self.record(format!("disable_unit({unit})"));
        Ok(())
    }
    fn list_units_filtered(&self, _states: &[&str]) -> Result<Vec<UnitListEntry>> {
        Ok(vec![])
    }
    fn get_unit_property(&self, unit: &str, _iface: &str, property: &str) -> Result<String> {
        // MockSystemd reuses its `properties` map regardless of the
        // queried interface — tests fix property names so the
        // interface argument is informational. Real DbusSystemd
        // routes to Properties.Get(iface, prop).
        self.properties
            .lock()
            .unwrap()
            .get(&(unit.to_string(), property.to_string()))
            .cloned()
            .ok_or_else(|| {
                GharsError::Systemd(
                    format!("MockSystemd: no property {property} on {unit}"),
                    "test fixture missing — call set_property before driving the unit".into(),
                )
            })
    }
    fn get_unit_property_u64(&self, unit: &str, iface: &str, property: &str) -> Result<u64> {
        // MockSystemd stores fixture values as strings even when the
        // production wire signature is u64/u32 — tests typically
        // set_property("MainPID", "1234") and the mock parses on
        // read. Real DbusSystemd uses zvariant typed conversion.
        let s = self.get_unit_property(unit, iface, property)?;
        s.trim().parse::<u64>().map_err(|e| {
            GharsError::Systemd(
                format!("MockSystemd: property {property} on {unit} not u64: {e}"),
                "test fixture stored a non-numeric string".into(),
            )
        })
    }
    fn get_unit_property_object_path(
        &self,
        _unit: &str,
        _iface: &str,
        _property: &str,
    ) -> Result<zbus::zvariant::OwnedObjectPath> {
        unreachable!("apply.rs MockSystemd does not exercise object-path properties")
    }
    fn get_service_property_string(&self, unit: &str, property: &str) -> Result<String> {
        self.get_unit_property(unit, "org.freedesktop.systemd1.Service", property)
    }
    fn get_service_property_u64(&self, unit: &str, property: &str) -> Result<u64> {
        self.get_unit_property_u64(unit, "org.freedesktop.systemd1.Service", property)
    }
    fn lookup_dynamic_user_by_name(&self, name: &str) -> Result<Option<u32>> {
        // Forced-not-realized override: when
        // `set_force_no_dynamic_user()` has fired, return
        // Ok(None) unconditionally to let the test exercise
        // `poll_dynamic_user_uid`'s budget-exhaustion error path
        // without stalling for the production 5s budget.
        if *self.force_no_dynamic_user.lock().unwrap() {
            return Ok(None);
        }
        // Explicit set_dynamic_user_uid override takes precedence.
        // Default: return the TEST PROCESS's own UID so chown-to-this-UID
        // succeeds without CAP_CHOWN (Linux allows chown to your own
        // UID for any user). Without this default, the production
        // poll_dynamic_user_uid loop would spin for 5s per test that
        // calls execute_create_runner, making the suite painfully
        // slow.
        if let Some(uid) = self.dynamic_user_uids.lock().unwrap().get(name).copied() {
            return Ok(Some(uid));
        }
        use std::os::unix::fs::MetadataExt;
        let uid = std::fs::metadata("/proc/self")
            .map(|m| m.uid())
            .unwrap_or(0);
        Ok(Some(uid))
    }
}

#[derive(Default)]
pub(super) struct MockTokenSource {
    pub(super) name: String,
    pub(super) registration_calls: Mutex<Vec<String>>,
    pub(super) removal_calls: Mutex<Vec<String>>,
}

impl TokenSource for MockTokenSource {
    fn name(&self) -> &str {
        &self.name
    }
    fn mint_registration_token(&self, runner_url: &str) -> Result<RegistrationToken> {
        self.registration_calls
            .lock()
            .unwrap()
            .push(runner_url.into());
        Ok(RegistrationToken {
            value: "REG-TOKEN".into(),
            expires_at: Utc::now(),
            source: format!("mock:{}", self.name),
        })
    }
    fn mint_removal_token(&self, runner_url: &str) -> Result<RegistrationToken> {
        self.removal_calls.lock().unwrap().push(runner_url.into());
        Ok(RegistrationToken {
            value: "RM-TOKEN".into(),
            expires_at: Utc::now(),
            source: format!("mock:{}", self.name),
        })
    }
}

#[derive(Default)]
pub(super) struct MockTarball {
    pub(super) fetched: Mutex<Vec<(String, String, String)>>,
    pub(super) installed: Mutex<Vec<(String, String, String, String)>>,
    pub(super) pruned: Mutex<Vec<(String, u32)>>,
}

impl Tarball for MockTarball {
    fn fetch_or_verify(
        &self,
        url: &str,
        dest_path: &Utf8Path,
        expected_sha256: &str,
    ) -> Result<()> {
        self.fetched.lock().unwrap().push((
            url.into(),
            dest_path.to_string(),
            expected_sha256.into(),
        ));
        // Materialize a placeholder so callers can `verify_local`
        // it later if they want.
        if let Some(parent) = dest_path.parent() {
            std::fs::create_dir_all(parent.as_std_path())?;
        }
        std::fs::write(dest_path.as_std_path(), b"mock-tarball")?;
        Ok(())
    }
    fn verify_local(&self, _path: &Utf8Path) -> Result<()> {
        Ok(())
    }
    fn install_binary(
        &self,
        tarball_path: &Utf8Path,
        _state_dir: &Utf8Path,
        runner_home: &Utf8Path,
        runner_name: &str,
        version: &str,
    ) -> Result<Utf8PathBuf> {
        self.installed.lock().unwrap().push((
            tarball_path.to_string(),
            runner_home.to_string(),
            runner_name.into(),
            version.into(),
        ));
        let bin = runner_home.join(format!("bin.{version}"));
        std::fs::create_dir_all(bin.as_std_path())?;
        // Mirror real actions/runner tarball layout: upstream
        // `Misc/layoutbin/runsvc.sh` installs into `_layout/bin/`
        // per the dir.proj `<Copy SourceFiles="@(LayoutBinFiles)"
        // DestinationFolder=".../_layout/bin/..."/>` rule, so the
        // published tarball ships runsvc.sh at
        // `bin.X.Y.Z/bin/runsvc.sh`, NOT at `bin.X.Y.Z/runsvc.sh`.
        // The systemd drop-in's ExecStart= and ConditionPathExists=
        // both point at this nested path.
        let inner_bin = bin.join("bin");
        std::fs::create_dir_all(inner_bin.as_std_path())?;
        let runsvc = inner_bin.join("runsvc.sh");
        std::fs::write(
            runsvc.as_std_path(),
            b"#!/bin/bash\n# mock runsvc from tarball\nexit 0\n",
        )?;
        // Mirror production: upstream actions/runner tar header sets
        // runsvc.sh to 0o755 (executable). std::fs::write produces
        // 0o644 from umask 0o022 by default, so without this chmod
        // the mock would diverge from real install_runner_binary's
        // tar-header preservation. The bin-tree-integrity regression
        // test asserts the post-create mode matches this, so the
        // mock's mode IS the test's pinned production-equivalent
        // value.
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(
            runsvc.as_std_path(),
            std::fs::Permissions::from_mode(0o755),
        )?;
        Ok(bin)
    }
    fn prune_old_versions(&self, runner_home: &Utf8Path, keep_versions: u32) -> Result<usize> {
        self.pruned
            .lock()
            .unwrap()
            .push((runner_home.to_string(), keep_versions));
        Ok(0)
    }
}

#[derive(Default)]
pub(super) struct MockConfigShell {
    pub(super) registered: Mutex<Vec<(String, String, String)>>,
    pub(super) removed: Mutex<Vec<String>>,
}

impl ConfigShell for MockConfigShell {
    fn run_register(&self, ctx: &ConfigShellCtx<'_>) -> Result<()> {
        self.registered
            .lock()
            .unwrap()
            .push((ctx.name.into(), ctx.url.into(), ctx.token.into()));
        // Ensure runner_home exists; the real config.sh writes
        // .runner / .credentials / .credentials_rsaparams there at
        // register time. The mock writes all three at mode 0o600 to
        // mirror the worst-case production shape:
        //   - `.runner` / `.credentials` — upstream IOUtil.SaveObject
        //     uses File.WriteAllText (Runner.Sdk/Util/IOUtil.cs:42)
        //     with no explicit mode, so the resulting file inherits
        //     `0o666 & ~umask`. ghars normally runs at umask 0o022
        //     → 0o644, but a custom-spawned ghars (cron / nspawn
        //     wrapper / hostile init) could inherit umask 0o077 →
        //     0o600. The post-config.sh chmod loop in
        //     execute_create_runner normalizes both files to 0o644
        //     so the DynamicUser-allocated runner process can read
        //     them regardless of ghars's invoking umask.
        //   - `.credentials_rsaparams` — upstream explicitly chmods
        //     to 0o600 in
        //     src/Runner.Listener/Configuration/RSAFileKeyManager.cs:33
        //     (the RSA key signs OAuth assertions for credential
        //     refresh). The post-config.sh chmod loop normalizes
        //     this to 0o644 so the DynamicUser-allocated runner
        //     process can read the key for refresh signing.
        // Tests that assert the post-create modes rely on this
        // mock writing the 0o600 baseline for all three so the
        // chmod-to-0o644 is observable.
        use std::os::unix::fs::PermissionsExt;
        let home = ctx.runner_home.as_std_path();
        std::fs::create_dir_all(home)?;
        for (basename, body) in &[
            (".runner", &b"{\"mock_runner\":\"...\"}"[..]),
            (".credentials", &b"{\"mock_creds\":\"...\"}"[..]),
            (".credentials_rsaparams", &b"{\"mock_rsa_params\":\"...\"}"[..]),
        ] {
            let path = home.join(basename);
            std::fs::write(&path, body)?;
            std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o600))?;
        }
        Ok(())
    }
    fn run_remove(&self, ctx: &ConfigShellCtx<'_>) -> Result<()> {
        self.removed.lock().unwrap().push(ctx.name.into());
        Ok(())
    }
}

pub(super) fn make_paths(tmp: &tempfile::TempDir) -> Paths {
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

pub(super) fn make_spec(name: &str, _prefix: &Utf8Path) -> EffectiveRunnerSpec {
    EffectiveRunnerSpec {
        environment: crate::config::EnvironmentSpec::default(),
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
        spec_hash: "sha256:dead".into(),
        config_source: "/etc/ghars/ghars.toml".into(),
        renderer_schema: crate::systemd::RENDERER_SCHEMA,
    }
}

pub(super) fn make_release() -> crate::github::Release {
    crate::github::Release {
        version: "2.334.0".into(),
        sha256: "deadbeef".into(),
        tarball_url: "https://example.test/runner.tar.gz".into(),
        tarball_name: "runner.tar.gz".into(),
    }
}

pub(super) fn make_runner_plan(name: &str, prefix: &Utf8Path) -> RunnerPlan {
    let spec = make_spec(name, prefix);
    let mut drop_ins: BTreeMap<String, String> = BTreeMap::new();
    drop_ins.insert(
        "00-ghars.conf".into(),
        "[Unit]\nX-Ghars-Spec-Hash=sha256:dead\n".into(),
    );
    // Populate env_file/path_file from the actual renderers so tests
    // that drive execute_update_runner observe the same bytes the
    // in-place block would write in production. Pre-fix these were
    // empty strings; the in-place block (runners.rs:653-667)
    // happily wrote those empty bytes into bin.X.Y.Z/.env|.path on
    // every UpdateRunner test path, masking a regression where the
    // helper output diverged from real renderer output.
    let env_file = crate::systemd::render_runner_env_file(&spec).unwrap();
    let path_file = crate::systemd::render_runner_path_file(&spec).unwrap();
    RunnerPlan {
        spec,
        resolved_release: Some(make_release()),
        effective_unit_text: "[Unit]\nDescription=mock\n".into(),
        drop_ins,
        env_file,
        path_file,
        spec_hash: "sha256:dead".into(),
    }
}

pub(super) fn running_as_root_apply_test_helper() -> bool {
    use std::os::unix::fs::MetadataExt;
    std::fs::metadata("/proc/self")
        .map(|m| m.uid() == 0)
        .unwrap_or(false)
}

pub(super) fn make_pool_plan(name: &str, kinds: Vec<crate::config::CacheKind>) -> CachePoolPlan {
    let serves_sccache = kinds.contains(&crate::config::CacheKind::Sccache);
    let binding = crate::config::EffectiveCacheBinding {
        name: name.into(),
        kinds,
        size: "200G".into(),
        mode: crate::config::CacheMode::Shared,
        trust_zone: "default".into(),
        // Populate only the path the renderer will actually read for
        // this kind set (sccache_path for sccache-serving pools,
        // sleep_path for ccache-only). The renderer returns an error
        // (GharsError::Validation) if it needs the field and the
        // binding holds None.
        sccache_path: serves_sccache.then(|| "/usr/bin/sccache".into()),
        sleep_path: (!serves_sccache).then(|| "/usr/bin/sleep".into()),
        renderer_schema: crate::systemd::RENDERER_SCHEMA,
    };
    let body =
        crate::systemd::render_cache_drop_in(&binding, "/etc/ghars/ghars.toml", "sha256:abcd")
            .unwrap();
    CachePoolPlan {
        binding,
        drop_in_body: body,
        spec_hash: "sha256:abcd".into(),
    }
}
