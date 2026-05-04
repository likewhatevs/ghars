//! Tests for `apply::pools` (cache-pool create / update / remove).

use std::collections::HashMap;

use camino::Utf8PathBuf;

use crate::auth::TokenSource;
use crate::error::GharsError;
use crate::plan::CachePoolDelta;

use super::super::outcome::ApplyOutcome;
use super::super::pools::{
    execute_create_cache_pool, execute_remove_cache_pool, execute_update_cache_pool,
};
use super::super::undo::{Deps, UndoLog};
use super::common::{
    MockConfigShell, MockSystemd, MockTarball, make_paths, make_pool_plan,
};

#[test]
fn create_cache_pool_writes_template_drop_in_and_provisions_group() {
    let tmp = tempfile::tempdir().unwrap();
    let paths = make_paths(&tmp);
    std::fs::create_dir_all(paths.runtime_dir.as_std_path()).unwrap();
    let plan = make_pool_plan(
        "build",
        vec![
            crate::config::CacheKind::Sccache,
            crate::config::CacheKind::Ccache,
        ],
    );
    let systemd = MockSystemd::default();
    let auth_map: HashMap<String, Box<dyn TokenSource>> = HashMap::new();
    let tarball = MockTarball::default();
    let config_shell = MockConfigShell::default();
    let deps = Deps {
        systemd: &systemd,
        auth: &auth_map,
        tarball: &tarball,
        config_shell: &config_shell,
    };
    execute_create_cache_pool(&plan, &deps, &paths, &mut UndoLog::new()).unwrap();
    // Template unit body matches the canonical Part 9b template.
    let template = paths.cache_template_unit_file();
    assert!(template.as_std_path().exists());
    let template_body = std::fs::read_to_string(template.as_std_path()).unwrap();
    assert!(template_body.contains("Description=ghars cache service"));
    assert!(template_body.contains("CacheDirectory=ghars/pools/%i"));
    // Drop-in landed.
    let drop_in = paths.cache_drop_in_dir("build").join("00-ghars.conf");
    assert!(drop_in.as_std_path().exists());
    let drop_in_body = std::fs::read_to_string(drop_in.as_std_path()).unwrap();
    assert!(drop_in_body.contains("X-Ghars-Pool-Name=build"));
    assert!(drop_in_body.contains("ExecStart=/usr/bin/sccache --start-server"));
    assert!(drop_in_body.contains("SCCACHE_NO_DAEMON=1"));
    // No groupadd: cache reach is socket-DAC + BindPaths under
    // DynamicUser; the per-pool group concept is gone.
    // Systemd was called: enable + daemon_reload + start.
    let calls = systemd.calls_snapshot();
    assert!(
        calls
            .iter()
            .any(|c| c == "enable_unit(ghars-cache@build.service)")
    );
    assert!(
        calls
            .iter()
            .any(|c| c == "start_unit(ghars-cache@build.service)")
    );
    assert!(calls.iter().any(|c| c == "daemon_reload"));
}

#[test]
fn remove_cache_pool_cleans_up_dir_dropin_and_group() {
    let tmp = tempfile::tempdir().unwrap();
    let paths = make_paths(&tmp);
    std::fs::create_dir_all(paths.runtime_dir.as_std_path()).unwrap();
    // Pre-stage a drop-in dir + pool dir as if a prior apply had
    // created them.
    let drop_in_dir = paths.cache_drop_in_dir("build");
    std::fs::create_dir_all(drop_in_dir.as_std_path()).unwrap();
    std::fs::write(
        drop_in_dir.join("00-ghars.conf").as_std_path(),
        b"[Service]\n",
    )
    .unwrap();
    let pool_dir = paths.cache_pool_dir("build");
    std::fs::create_dir_all(pool_dir.join("sccache").as_std_path()).unwrap();
    std::fs::write(
        pool_dir.join("sccache/blob").as_std_path(),
        b"cache content",
    )
    .unwrap();

    let systemd = MockSystemd::default();
    let auth_map: HashMap<String, Box<dyn TokenSource>> = HashMap::new();
    let tarball = MockTarball::default();
    let config_shell = MockConfigShell::default();
    let deps = Deps {
        systemd: &systemd,
        auth: &auth_map,
        tarball: &tarball,
        config_shell: &config_shell,
    };
    execute_remove_cache_pool("build", &deps, &paths, &mut UndoLog::new()).unwrap();
    // Drop-in dir gone.
    assert!(!drop_in_dir.as_std_path().exists());
    // Pool dir gone — backing storage no longer leaks.
    assert!(!pool_dir.as_std_path().exists());
    // No groupdel: there's no per-pool group under DynamicUser.
    // Systemd was called: stop + disable.
    let calls = systemd.calls_snapshot();
    assert!(
        calls
            .iter()
            .any(|c| c == "stop_unit(ghars-cache@build.service)")
    );
    assert!(
        calls
            .iter()
            .any(|c| c == "disable_unit(ghars-cache@build.service)")
    );
}

#[test]
fn remove_cache_pool_rejects_symlink_at_pool_dir() {
    // SEC: defense-in-depth pin. If the per-pool storage dir
    // path resolves to a symlink (operator tampering, slipped
    // parent-dir perms), execute_remove_cache_pool's
    // guard_home_dir_rmrf call must reject before fs::remove_dir_all
    // would unlink the symlink target. The runner-side
    // execute_remove_runner uses the same guard; this test pins
    // the symmetric protection on the cache-pool side.
    let tmp = tempfile::tempdir().unwrap();
    let paths = make_paths(&tmp);
    std::fs::create_dir_all(paths.runtime_dir.as_std_path()).unwrap();
    // Plant a real target dir somewhere unrelated, then symlink
    // the expected pool_dir at it. The symlink at pool_dir
    // makes guard_home_dir_rmrf fire its symlink-rejection arm.
    let real_target = Utf8PathBuf::from_path_buf(tmp.path().join("real-target"))
        .unwrap();
    std::fs::create_dir_all(real_target.as_std_path()).unwrap();
    std::fs::write(real_target.join("important-data.bin").as_std_path(), b"sensitive")
        .unwrap();
    let pool_root = paths.cache_pool_root();
    std::fs::create_dir_all(pool_root.as_std_path()).unwrap();
    let pool_dir = paths.cache_pool_dir("hostile");
    std::os::unix::fs::symlink(real_target.as_std_path(), pool_dir.as_std_path())
        .unwrap();

    let systemd = MockSystemd::default();
    let auth_map: HashMap<String, Box<dyn TokenSource>> = HashMap::new();
    let tarball = MockTarball::default();
    let config_shell = MockConfigShell::default();
    let deps = Deps {
        systemd: &systemd,
        auth: &auth_map,
        tarball: &tarball,
        config_shell: &config_shell,
    };
    let err = execute_remove_cache_pool("hostile", &deps, &paths, &mut UndoLog::new())
        .expect_err("symlink at pool_dir must be rejected by guard_home_dir_rmrf");
    assert!(
        matches!(err, GharsError::Validation(_, _)),
        "expected Validation, got {err:?}"
    );
    // Defense-in-depth: target must NOT have been touched. The
    // pre-fix path would have followed the symlink and removed
    // important-data.bin via remove_dir_all.
    assert!(
        real_target.join("important-data.bin").as_std_path().exists(),
        "remove_dir_all must NOT follow symlinked pool_dir"
    );
}

#[test]
fn cache_pool_template_is_idempotent_on_second_create() {
    // Two pool creations land in the same apply — second write must
    // succeed (template path already exists). truncate=true on
    // OpenOptions handles overwrite.
    let tmp = tempfile::tempdir().unwrap();
    let paths = make_paths(&tmp);
    std::fs::create_dir_all(paths.runtime_dir.as_std_path()).unwrap();
    let plan_a = make_pool_plan("a", vec![crate::config::CacheKind::Ccache]);
    let plan_b = make_pool_plan("b", vec![crate::config::CacheKind::Sccache]);
    let systemd = MockSystemd::default();
    let auth_map: HashMap<String, Box<dyn TokenSource>> = HashMap::new();
    let tarball = MockTarball::default();
    let config_shell = MockConfigShell::default();
    let deps = Deps {
        systemd: &systemd,
        auth: &auth_map,
        tarball: &tarball,
        config_shell: &config_shell,
    };
    execute_create_cache_pool(&plan_a, &deps, &paths, &mut UndoLog::new()).unwrap();
    execute_create_cache_pool(&plan_b, &deps, &paths, &mut UndoLog::new()).unwrap();
    // Template still readable + matches canonical body.
    let template_body =
        std::fs::read_to_string(paths.cache_template_unit_file().as_std_path()).unwrap();
    assert!(template_body.contains("CacheDirectory=ghars/pools/%i"));
    // Both pool drop-ins present and distinct.
    let body_a = std::fs::read_to_string(
        paths
            .cache_drop_in_dir("a")
            .join("00-ghars.conf")
            .as_std_path(),
    )
    .unwrap();
    let body_b = std::fs::read_to_string(
        paths
            .cache_drop_in_dir("b")
            .join("00-ghars.conf")
            .as_std_path(),
    )
    .unwrap();
    assert!(body_a.contains("X-Ghars-Pool-Name=a"));
    assert!(body_a.contains("ExecStart=/usr/bin/sleep infinity"));
    assert!(body_b.contains("X-Ghars-Pool-Name=b"));
    assert!(body_b.contains("ExecStart=/usr/bin/sccache --start-server"));
}

/// Build a `CachePoolDelta` whose `drop_in_body` is a stable
/// non-empty byte string. The skip tests prepopulate that exact
/// body on disk and assert the byte-equality short-circuit fires.
fn skip_test_cache_delta(name: &str) -> CachePoolDelta {
    CachePoolDelta {
        binding: crate::config::EffectiveCacheBinding {
            name: name.into(),
            kinds: vec![crate::config::CacheKind::Ccache],
            size: "100G".into(),
            mode: crate::config::CacheMode::Shared,
            trust_zone: "default".into(),
        },
        drop_in_body: "[Service]\nEnvironment=GHARS_TEST=1\n".into(),
        spec_hash: "sha256:cafe".into(),
    }
}

/// When the 00-ghars.conf drop-in on disk byte-matches what
/// `execute_update_cache_pool` would render AND the drop-in
/// directory already existed (CreateDir wouldn't fire), the
/// in-place pool path skips daemon-reload + stop + start entirely
/// and returns `PoolSkipped`. Symmetric with the runner-side
/// `execute_update_runner_in_place_skips_restart_when_bytes_match`.
#[test]
fn execute_update_cache_pool_skips_restart_when_bytes_match() {
    let tmp = tempfile::tempdir().unwrap();
    let paths = make_paths(&tmp);
    let systemd = MockSystemd::default();
    let tarball = MockTarball::default();
    let config_shell = MockConfigShell::default();
    let auth_map: HashMap<String, Box<dyn TokenSource>> = HashMap::new();
    let deps = Deps {
        systemd: &systemd,
        auth: &auth_map,
        tarball: &tarball,
        config_shell: &config_shell,
    };
    let delta = skip_test_cache_delta("build");
    // Prepopulate: drop-in dir exists (so CreateDir does NOT
    // count as a mutation) AND the 00-ghars.conf bytes already
    // match the rendered body. This is exactly the "next
    // apply after a successful prior apply, no config drift"
    // shape the optimization targets.
    let drop_in_dir = paths.cache_drop_in_dir(&delta.binding.name);
    std::fs::create_dir_all(drop_in_dir.as_std_path()).unwrap();
    std::fs::write(
        drop_in_dir.join("00-ghars.conf").as_std_path(),
        delta.drop_in_body.as_bytes(),
    )
    .unwrap();
    let mut log = UndoLog::new();
    let outcome = execute_update_cache_pool(&delta, &deps, &paths, &mut log).unwrap();

    assert_eq!(outcome, ApplyOutcome::PoolSkipped);
    let calls = systemd.calls_snapshot();
    assert!(
        calls.is_empty(),
        "skip path must not touch systemd; got: {calls:?}",
    );
    assert!(
        log.is_empty(),
        "skip path must not push any UndoStep (no writes, no unit ops); got len={}",
        log.len(),
    );
}

/// When the 00-ghars.conf drop-in on disk diverges from the
/// rendered body, `read_then_write_if_changed` writes through and
/// the daemon-reload + stop + start cycle fires. Returns
/// `PoolUpdated`, never `PoolSkipped`.
#[test]
fn execute_update_cache_pool_restarts_when_drop_in_differs() {
    let tmp = tempfile::tempdir().unwrap();
    let paths = make_paths(&tmp);
    let systemd = MockSystemd::default();
    let tarball = MockTarball::default();
    let config_shell = MockConfigShell::default();
    let auth_map: HashMap<String, Box<dyn TokenSource>> = HashMap::new();
    let deps = Deps {
        systemd: &systemd,
        auth: &auth_map,
        tarball: &tarball,
        config_shell: &config_shell,
    };
    let delta = skip_test_cache_delta("build");
    // Drop-in dir exists, but the on-disk body diverges from
    // delta.drop_in_body — the byte-equality check in
    // read_then_write_if_changed must detect the mismatch and
    // route to the write + restart cycle.
    let drop_in_dir = paths.cache_drop_in_dir(&delta.binding.name);
    std::fs::create_dir_all(drop_in_dir.as_std_path()).unwrap();
    std::fs::write(
        drop_in_dir.join("00-ghars.conf").as_std_path(),
        b"[Service]\nEnvironment=GHARS_DRIFT=stale\n",
    )
    .unwrap();
    let mut log = UndoLog::new();
    let outcome = execute_update_cache_pool(&delta, &deps, &paths, &mut log).unwrap();

    assert_eq!(outcome, ApplyOutcome::PoolUpdated);
    let calls = systemd.calls_snapshot();
    assert!(
        calls.iter().any(|c| c == "daemon_reload"),
        "drop-in drift must trigger daemon_reload; got: {calls:?}",
    );
    assert!(
        calls
            .iter()
            .any(|c| c.starts_with("stop_unit(ghars-cache@build")),
        "drop-in drift must stop the unit; got: {calls:?}",
    );
    assert!(
        calls
            .iter()
            .any(|c| c.starts_with("start_unit(ghars-cache@build")),
        "drop-in drift must start the unit; got: {calls:?}",
    );
    // Confirm the on-disk bytes were rewritten to the rendered
    // body — read_then_write_if_changed only writes when bytes
    // differ.
    let after_disk = std::fs::read(drop_in_dir.join("00-ghars.conf").as_std_path()).unwrap();
    assert_eq!(after_disk, delta.drop_in_body.as_bytes());
}

/// First-time pool update where the drop-in directory does
/// NOT exist beforehand. CreateDir is itself a mutation, so even
/// if the (yet-to-be-written) 00-ghars.conf would byte-match a
/// hypothetical prior body, the skip gate must NOT fire on this
/// path — daemon-reload + restart still has to run because
/// systemd has no record of the freshly-planted directory.
/// Mirrors the runner-side CreateDir-counts-as-change semantic
/// (`files_changed += 1` when `!drop_in_dir_existed`).
#[test]
fn execute_update_cache_pool_restarts_on_first_drop_in_dir_create() {
    let tmp = tempfile::tempdir().unwrap();
    let paths = make_paths(&tmp);
    let systemd = MockSystemd::default();
    let tarball = MockTarball::default();
    let config_shell = MockConfigShell::default();
    let auth_map: HashMap<String, Box<dyn TokenSource>> = HashMap::new();
    let deps = Deps {
        systemd: &systemd,
        auth: &auth_map,
        tarball: &tarball,
        config_shell: &config_shell,
    };
    let delta = skip_test_cache_delta("build");
    // Deliberately do NOT create cache_drop_in_dir beforehand —
    // execute_update_cache_pool must observe drop_in_dir_existed
    // == false, count CreateDir as a mutation, and proceed to
    // restart.
    let mut log = UndoLog::new();
    let outcome = execute_update_cache_pool(&delta, &deps, &paths, &mut log).unwrap();

    assert_eq!(outcome, ApplyOutcome::PoolUpdated);
    let calls = systemd.calls_snapshot();
    assert!(
        calls.iter().any(|c| c == "daemon_reload"),
        "first-time CreateDir must trigger daemon_reload; got: {calls:?}",
    );
    assert!(
        calls
            .iter()
            .any(|c| c.starts_with("stop_unit(ghars-cache@build")),
        "first-time CreateDir must stop the unit; got: {calls:?}",
    );
    assert!(
        calls
            .iter()
            .any(|c| c.starts_with("start_unit(ghars-cache@build")),
        "first-time CreateDir must start the unit; got: {calls:?}",
    );
}
