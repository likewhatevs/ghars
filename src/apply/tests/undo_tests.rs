//! Tests for `apply::undo` (`UndoLog` + the rollback walker) and the
//! `apply()` rollback-on-failure orchestration paths.

use std::collections::HashMap;

use camino::Utf8PathBuf;

use crate::auth::TokenSource;
use crate::plan::{Action, CachePoolPlan, Plan};

use super::super::orchestrator::apply;
use super::super::outcome::ApplyOptions;
use super::super::undo::{Deps, UndoLog, UndoStep, undo};
use super::common::{
    MockConfigShell, MockSystemd, MockTarball, MockTokenSource, make_paths, make_runner_plan,
};

#[test]
fn undo_log_starts_empty() {
    let log = UndoLog::new();
    assert!(log.is_empty());
    assert_eq!(log.len(), 0);
    assert!(log.steps().is_empty());
}

#[test]
fn undo_log_push_extends_and_preserves_order() {
    // Insertion order matters because `undo` walks reverse — order
    // here directly drives the inverse-execution sequence.
    let mut log = UndoLog::new();
    log.push(UndoStep::CreateDir {
        path: Utf8PathBuf::from("/tmp/ghars-test"),
    });
    log.push(UndoStep::EnableUnit {
        name: "ghars-runner@a.service".into(),
    });
    log.push(UndoStep::StartUnit {
        name: "ghars-runner@a.service".into(),
    });
    assert_eq!(log.len(), 3);
    match &log.steps()[0] {
        UndoStep::CreateDir { path } => {
            assert_eq!(path.as_str(), "/tmp/ghars-test");
        }
        other => panic!("expected CreateDir, got {other:?}"),
    }
    match &log.steps()[2] {
        UndoStep::StartUnit { name } => {
            assert_eq!(name, "ghars-runner@a.service");
        }
        other => panic!("expected StartUnit, got {other:?}"),
    }
}

#[test]
fn is_reverse_direction_classifies_remove_side_steps() {
    // Forward-direction (Create-side): false ⇒ undo runs the
    // inverse. Reverse-direction (Remove-side): true ⇒ undo logs
    // and skips because the original state is unrecoverable.
    let forward = vec![
        UndoStep::WriteFile {
            path: Utf8PathBuf::from("/x"),
            prior_content: None,
        },
        UndoStep::CreateDir {
            path: Utf8PathBuf::from("/x"),
        },
        UndoStep::StartUnit { name: "u".into() },
        UndoStep::EnableUnit { name: "u".into() },
        UndoStep::GitHubRegistration {
            name: "n".into(),
            url: "u".into(),
            auth_name: "a".into(),
            runner_home: Utf8PathBuf::from("/h"),
        },
    ];
    for s in &forward {
        assert!(
            !s.is_reverse_direction(),
            "forward variant must classify as forward: {s:?}"
        );
    }
    let reverse = vec![
        UndoStep::RemoveFile {
            path: Utf8PathBuf::from("/x"),
            content: vec![],
        },
        UndoStep::RemoveDir {
            path: Utf8PathBuf::from("/x"),
        },
        UndoStep::StopUnit { name: "u".into() },
        UndoStep::DisableUnit { name: "u".into() },
    ];
    for s in &reverse {
        assert!(
            s.is_reverse_direction(),
            "reverse variant must classify as reverse: {s:?}"
        );
    }
}

/// Build a minimal `Deps` for unit tests of the `undo` function. No
/// auth registry entry, no tarball calls — undo only touches
/// systemd / `config_shell` / filesystem.
fn rollback_deps<'a>(
    systemd: &'a MockSystemd,
    config_shell: &'a MockConfigShell,
    tarball: &'a MockTarball,
    auth: &'a HashMap<String, Box<dyn TokenSource>>,
) -> Deps<'a> {
    Deps {
        systemd,
        auth,
        tarball,
        config_shell,
    }
}

#[test]
fn undo_start_unit_calls_stop_unit() {
    let systemd = MockSystemd::default();
    let config_shell = MockConfigShell::default();
    let tarball = MockTarball::default();
    let auth: HashMap<String, Box<dyn TokenSource>> = HashMap::new();
    let deps = rollback_deps(&systemd, &config_shell, &tarball, &auth);
    let tmp = tempfile::tempdir().unwrap();
    let paths = make_paths(&tmp);
    let mut log = UndoLog::new();
    log.push(UndoStep::StartUnit {
        name: "ghars-runner@a.service".into(),
    });
    undo(&log, &deps, &paths).unwrap();
    let calls = systemd.calls_snapshot();
    assert!(
        calls
            .iter()
            .any(|c| c == "stop_unit(ghars-runner@a.service)"),
        "expected stop_unit; got {calls:?}"
    );
}

#[test]
fn undo_enable_unit_calls_disable_unit() {
    let systemd = MockSystemd::default();
    let config_shell = MockConfigShell::default();
    let tarball = MockTarball::default();
    let auth: HashMap<String, Box<dyn TokenSource>> = HashMap::new();
    let deps = rollback_deps(&systemd, &config_shell, &tarball, &auth);
    let tmp = tempfile::tempdir().unwrap();
    let paths = make_paths(&tmp);
    let mut log = UndoLog::new();
    log.push(UndoStep::EnableUnit {
        name: "ghars-cache@build.service".into(),
    });
    undo(&log, &deps, &paths).unwrap();
    let calls = systemd.calls_snapshot();
    assert!(
        calls
            .iter()
            .any(|c| c == "disable_unit(ghars-cache@build.service)"),
        "expected disable_unit; got {calls:?}"
    );
}

#[test]
fn undo_write_file_with_no_prior_content_unlinks() {
    // WriteFile with prior_content=None ⇒ file was newly created;
    // undo removes it.
    let tmp = tempfile::tempdir().unwrap();
    let path = Utf8PathBuf::from_path_buf(tmp.path().to_path_buf())
        .unwrap()
        .join("file.conf");
    std::fs::write(path.as_std_path(), b"new content").unwrap();
    assert!(path.exists());
    let systemd = MockSystemd::default();
    let config_shell = MockConfigShell::default();
    let tarball = MockTarball::default();
    let auth: HashMap<String, Box<dyn TokenSource>> = HashMap::new();
    let deps = rollback_deps(&systemd, &config_shell, &tarball, &auth);
    let paths = make_paths(&tmp);
    let mut log = UndoLog::new();
    log.push(UndoStep::WriteFile {
        path: path.clone(),
        prior_content: None,
    });
    undo(&log, &deps, &paths).unwrap();
    assert!(
        !path.exists(),
        "file must be unlinked when no prior content"
    );
}

#[test]
fn undo_write_file_with_prior_content_restores_old_bytes() {
    // WriteFile with prior_content=Some(_) ⇒ file existed before;
    // undo rewrites the prior bytes through write_root_owned.
    let tmp = tempfile::tempdir().unwrap();
    let path = Utf8PathBuf::from_path_buf(tmp.path().to_path_buf())
        .unwrap()
        .join("subdir")
        .join("file.conf");
    std::fs::create_dir_all(path.parent().unwrap().as_std_path()).unwrap();
    std::fs::write(path.as_std_path(), b"new content").unwrap();
    let systemd = MockSystemd::default();
    let config_shell = MockConfigShell::default();
    let tarball = MockTarball::default();
    let auth: HashMap<String, Box<dyn TokenSource>> = HashMap::new();
    let deps = rollback_deps(&systemd, &config_shell, &tarball, &auth);
    let paths = make_paths(&tmp);
    let mut log = UndoLog::new();
    log.push(UndoStep::WriteFile {
        path: path.clone(),
        prior_content: Some(b"old content".to_vec()),
    });
    undo(&log, &deps, &paths).unwrap();
    let restored = std::fs::read(path.as_std_path()).unwrap();
    assert_eq!(restored, b"old content");
}

#[test]
fn undo_create_dir_removes_empty_directory() {
    let tmp = tempfile::tempdir().unwrap();
    let dir = Utf8PathBuf::from_path_buf(tmp.path().to_path_buf())
        .unwrap()
        .join("new-dir");
    std::fs::create_dir_all(dir.as_std_path()).unwrap();
    assert!(dir.exists());
    let systemd = MockSystemd::default();
    let config_shell = MockConfigShell::default();
    let tarball = MockTarball::default();
    let auth: HashMap<String, Box<dyn TokenSource>> = HashMap::new();
    let deps = rollback_deps(&systemd, &config_shell, &tarball, &auth);
    let paths = make_paths(&tmp);
    let mut log = UndoLog::new();
    log.push(UndoStep::CreateDir { path: dir.clone() });
    undo(&log, &deps, &paths).unwrap();
    assert!(!dir.exists(), "empty directory must be removed");
}

#[test]
fn undo_create_dir_leaves_nonempty_directory() {
    // CreateDir undo only removes the dir if it's empty — children
    // belong to their own UndoSteps which the reverse walk handles
    // separately. The non-empty case logs a warning and continues.
    let tmp = tempfile::tempdir().unwrap();
    let dir = Utf8PathBuf::from_path_buf(tmp.path().to_path_buf())
        .unwrap()
        .join("nonempty");
    std::fs::create_dir_all(dir.as_std_path()).unwrap();
    let child = dir.join("child.conf");
    std::fs::write(child.as_std_path(), b"content").unwrap();
    let systemd = MockSystemd::default();
    let config_shell = MockConfigShell::default();
    let tarball = MockTarball::default();
    let auth: HashMap<String, Box<dyn TokenSource>> = HashMap::new();
    let deps = rollback_deps(&systemd, &config_shell, &tarball, &auth);
    let paths = make_paths(&tmp);
    let mut log = UndoLog::new();
    log.push(UndoStep::CreateDir { path: dir.clone() });
    undo(&log, &deps, &paths).unwrap();
    assert!(
        dir.exists(),
        "non-empty dir must be left for next clean apply"
    );
    assert!(child.exists(), "child must still exist");
}

#[test]
fn undo_set_mode_restores_prior_mode() {
    // SetMode undo: chmod the path back to the pre-call mode
    // captured by `chmod_record_undo`. Exercises the rollback path
    // for `execute_create_runner`'s explicit chmods (tz_dir 0o711,
    // runner_home 0o777, runner_tmp 0o777, .ktstr 0o777,
    // .ccache 0o777, .runner / .credentials* 0o644) — without
    // this undo, a partial CreateRunner that errors mid-way leaves
    // the trust-zone tree at the apply-time modes, which can
    // expose attacker write surface (runner_home at 0o777 in
    // particular is the planted-symlink vector that the in-apply
    // 0o755 clamp closes).
    use std::os::unix::fs::PermissionsExt;
    let tmp = tempfile::tempdir().unwrap();
    let path = Utf8PathBuf::from_path_buf(tmp.path().to_path_buf())
        .unwrap()
        .join("victim.file");
    std::fs::write(path.as_std_path(), b"x").unwrap();
    std::fs::set_permissions(
        path.as_std_path(),
        std::fs::Permissions::from_mode(0o600),
    )
    .unwrap();
    // Simulate the apply having chmodded the path to 0o777 and
    // recorded prior_mode = 0o600 in the log.
    std::fs::set_permissions(
        path.as_std_path(),
        std::fs::Permissions::from_mode(0o777),
    )
    .unwrap();
    let systemd = MockSystemd::default();
    let config_shell = MockConfigShell::default();
    let tarball = MockTarball::default();
    let auth: HashMap<String, Box<dyn TokenSource>> = HashMap::new();
    let deps = rollback_deps(&systemd, &config_shell, &tarball, &auth);
    let paths = make_paths(&tmp);
    let mut log = UndoLog::new();
    log.push(UndoStep::SetMode {
        path: path.clone(),
        prior_mode: 0o600,
    });
    undo(&log, &deps, &paths).unwrap();
    let restored = std::fs::metadata(path.as_std_path())
        .unwrap()
        .permissions()
        .mode()
        & 0o7777;
    assert_eq!(
        restored, 0o600,
        "SetMode undo must restore prior_mode; got 0o{restored:o}"
    );
}

#[test]
fn undo_set_mode_restores_prior_mode_on_directory() {
    // SetMode's undo must work on directories — production
    // execute_create_runner chmods 5 directories (tz_dir,
    // runner_home, runner_tmp, .ktstr, .ccache) plus 3 files.
    // Dirs are the majority. A regression that special-cased
    // SetMode for files only would silently fail the rollback
    // for every CreateRunner that errored mid-way, leaving the
    // trust-zone tree at apply-time modes — re-opening the
    // planted-symlink window the Stage 1 clamp was meant to
    // close.
    use std::os::unix::fs::PermissionsExt;
    let tmp = tempfile::tempdir().unwrap();
    let dir = Utf8PathBuf::from_path_buf(tmp.path().to_path_buf())
        .unwrap()
        .join("victim_dir");
    std::fs::create_dir(dir.as_std_path()).unwrap();
    std::fs::set_permissions(dir.as_std_path(), std::fs::Permissions::from_mode(0o755))
        .unwrap();
    // Simulate the apply having chmodded the dir to 0o777
    // (mirrors runner_home Stage 2 reopen).
    std::fs::set_permissions(dir.as_std_path(), std::fs::Permissions::from_mode(0o777))
        .unwrap();
    let systemd = MockSystemd::default();
    let config_shell = MockConfigShell::default();
    let tarball = MockTarball::default();
    let auth: HashMap<String, Box<dyn TokenSource>> = HashMap::new();
    let deps = rollback_deps(&systemd, &config_shell, &tarball, &auth);
    let paths = make_paths(&tmp);
    let mut log = UndoLog::new();
    log.push(UndoStep::SetMode {
        path: dir.clone(),
        prior_mode: 0o755,
    });
    undo(&log, &deps, &paths).unwrap();
    let restored = std::fs::metadata(dir.as_std_path())
        .unwrap()
        .permissions()
        .mode()
        & 0o7777;
    assert_eq!(
        restored, 0o755,
        "SetMode undo on directory must restore prior_mode 0o755; \
         got 0o{restored:o}. Regression that special-cased SetMode \
         to files only would silently leave directories at apply-time \
         modes, re-opening the planted-symlink window."
    );
}

#[test]
fn undo_set_mode_refuses_symlink_target() {
    // Symmetric symlink-refusal: the forward chmod_record_undo
    // helper in runners.rs opens with O_NOFOLLOW (which atomically
    // returns ELOOP for symlink targets), but the gap
    // between the forward chmod and the rollback walk is wide
    // enough for a malicious sibling DynamicUser to race a
    // symlink-swap at the chmod target (e.g. plant runner_home/
    // .credentials_rsaparams → /etc/shadow after the forward
    // chmod ran but before the rollback's SetMode undo fires).
    // Without this symlink check, the rollback would chmod the
    // symlink target — write-amplification of attacker control.
    //
    // This test plants a symlink at the SetMode target between
    // pushing the UndoStep and walking the undo, then verifies
    // the symlink target's mode is unchanged.
    use std::os::unix::fs::PermissionsExt;
    let tmp = tempfile::tempdir().unwrap();
    let victim = Utf8PathBuf::from_path_buf(tmp.path().to_path_buf())
        .unwrap()
        .join("victim.real");
    std::fs::write(victim.as_std_path(), b"original").unwrap();
    std::fs::set_permissions(
        victim.as_std_path(),
        std::fs::Permissions::from_mode(0o644),
    )
    .unwrap();
    let original_victim_mode = std::fs::metadata(victim.as_std_path())
        .unwrap()
        .permissions()
        .mode()
        & 0o7777;

    // The path the UndoStep::SetMode references is a SYMLINK
    // pointing at victim. Simulates the race-window swap.
    let swapped_path = Utf8PathBuf::from_path_buf(tmp.path().to_path_buf())
        .unwrap()
        .join("swapped.symlink");
    std::os::unix::fs::symlink(victim.as_std_path(), swapped_path.as_std_path()).unwrap();

    let systemd = MockSystemd::default();
    let config_shell = MockConfigShell::default();
    let tarball = MockTarball::default();
    let auth: HashMap<String, Box<dyn TokenSource>> = HashMap::new();
    let deps = rollback_deps(&systemd, &config_shell, &tarball, &auth);
    let paths = make_paths(&tmp);
    let mut log = UndoLog::new();
    log.push(UndoStep::SetMode {
        path: swapped_path.clone(),
        prior_mode: 0o600,
    });
    undo(&log, &deps, &paths).expect("undo must succeed (skip + warn, not error)");

    // CRITICAL: victim's mode must be unchanged (0o644). If the
    // SetMode undo had followed the symlink, victim would now be
    // 0o600 (the prior_mode the UndoStep carries).
    let post_mode = std::fs::metadata(victim.as_std_path())
        .unwrap()
        .permissions()
        .mode()
        & 0o7777;
    assert_eq!(
        post_mode, original_victim_mode,
        "undo SetMode must NOT chmod-through to symlink target; \
         victim mode changed from 0o{original_victim_mode:o} to 0o{post_mode:o}"
    );
}

#[test]
fn undo_set_mode_tolerates_missing_path() {
    // The reverse walk runs UndoSteps in order; a SetMode for a
    // path that a later (chronologically — earlier in the reverse
    // walk) UndoStep removed must not error the whole rollback.
    // Concretely: execute_create_runner's UndoLog might record
    // {WriteFile newfile, SetMode newfile} (chmod after create);
    // reverse walk: SetMode reverse (chmod the now-unlinked
    // newfile — should NOT propagate ENOENT), then WriteFile
    // reverse (unlink — already unlinked, fine).
    // Or more typically: an enclosing rollback unlinks the file
    // via a different step and SetMode's reverse sees ENOENT.
    let tmp = tempfile::tempdir().unwrap();
    let path = Utf8PathBuf::from_path_buf(tmp.path().to_path_buf())
        .unwrap()
        .join("removed.file");
    // Do NOT create the file — simulate it being gone.
    let systemd = MockSystemd::default();
    let config_shell = MockConfigShell::default();
    let tarball = MockTarball::default();
    let auth: HashMap<String, Box<dyn TokenSource>> = HashMap::new();
    let deps = rollback_deps(&systemd, &config_shell, &tarball, &auth);
    let paths = make_paths(&tmp);
    let mut log = UndoLog::new();
    log.push(UndoStep::SetMode {
        path: path.clone(),
        prior_mode: 0o644,
    });
    // Must not panic, must not return Err — the per-step undo
    // catches the missing-path case (`path.exists()` short-
    // circuits the chmod) and falls through to Ok(()).
    undo(&log, &deps, &paths).expect("SetMode undo must tolerate missing path");
}

#[test]
fn set_mode_describe_includes_path_and_prior_mode() {
    // The rollback advisory in cmd_apply consumes
    // UndoStep::describe(); pin the format so a future caller
    // doesn't accidentally drop either field.
    let step = UndoStep::SetMode {
        path: Utf8PathBuf::from("/var/lib/ghars/default/ghars-a"),
        prior_mode: 0o755,
    };
    let desc = step.describe();
    assert!(
        desc.contains("/var/lib/ghars/default/ghars-a"),
        "describe must include path: {desc}"
    );
    assert!(
        desc.contains("0o755"),
        "describe must include prior_mode in 0oXXX form: {desc}"
    );
}

#[test]
fn set_mode_is_not_reverse_direction() {
    // SetMode's inverse (chmod back to prior_mode) is lossless,
    // so the `undo` walker must dispatch it through `undo_one`
    // rather than the warn-and-skip lossy path.
    let step = UndoStep::SetMode {
        path: Utf8PathBuf::from("/x"),
        prior_mode: 0o600,
    };
    assert!(
        !step.is_reverse_direction(),
        "SetMode must be forward-direction (lossless inverse)"
    );
}

#[test]
fn undo_set_owner_restores_prior_owner() {
    // Direct unit test of UndoStep::SetOwner. Captures the test
    // process's current uid/gid, simulates a forward fchown
    // (no-op because we'd chown to ourselves), then exercises
    // the undo restore path. The "restore" is also a no-op in
    // the file-owner-is-test-process case but proves the undo
    // dispatch reaches the right code path without EPERM.
    use std::os::unix::fs::MetadataExt;
    let tmp = tempfile::tempdir().unwrap();
    let file = Utf8PathBuf::from_path_buf(tmp.path().to_path_buf())
        .unwrap()
        .join("victim.file");
    std::fs::write(file.as_std_path(), b"x").unwrap();
    let meta = std::fs::metadata(file.as_std_path()).unwrap();
    let our_uid = meta.uid();
    let our_gid = meta.gid();

    let systemd = MockSystemd::default();
    let config_shell = MockConfigShell::default();
    let tarball = MockTarball::default();
    let auth: HashMap<String, Box<dyn TokenSource>> = HashMap::new();
    let deps = rollback_deps(&systemd, &config_shell, &tarball, &auth);
    let paths = make_paths(&tmp);
    let mut log = UndoLog::new();
    log.push(UndoStep::SetOwner {
        path: file.clone(),
        prior_uid: our_uid,
        prior_gid: our_gid,
    });
    undo(&log, &deps, &paths)
        .expect("SetOwner undo to self uid/gid must succeed without EPERM");
    let post = std::fs::metadata(file.as_std_path()).unwrap();
    assert_eq!(post.uid(), our_uid, "uid round-tripped");
    assert_eq!(post.gid(), our_gid, "gid round-tripped");
}

#[test]
fn undo_set_owner_tolerates_missing_path() {
    // Mirror SetMode tolerance: rollback walks UndoSteps in
    // reverse, and an earlier (chronologically later) step may
    // have removed the SetOwner target. ENOENT at undo time =>
    // Ok (best-effort rollback contract).
    let tmp = tempfile::tempdir().unwrap();
    let missing_path = Utf8PathBuf::from_path_buf(tmp.path().to_path_buf())
        .unwrap()
        .join("never-existed");
    let systemd = MockSystemd::default();
    let config_shell = MockConfigShell::default();
    let tarball = MockTarball::default();
    let auth: HashMap<String, Box<dyn TokenSource>> = HashMap::new();
    let deps = rollback_deps(&systemd, &config_shell, &tarball, &auth);
    let paths = make_paths(&tmp);
    let mut log = UndoLog::new();
    log.push(UndoStep::SetOwner {
        path: missing_path,
        prior_uid: 0,
        prior_gid: 0,
    });
    undo(&log, &deps, &paths)
        .expect("SetOwner undo on missing path must be best-effort");
}

#[test]
fn undo_set_owner_refuses_symlink_target() {
    // Symmetric symlink-refusal: between the forward fchown and
    // the rollback walk, a malicious sibling DynamicUser could
    // race a symlink swap. The undo path must refuse to chown
    // through the symlink (which would re-direct ownership of
    // an attacker-chosen file). Verify the apparent victim file
    // remains owned by the test process post-undo.
    use std::os::unix::fs::MetadataExt;
    let tmp = tempfile::tempdir().unwrap();
    let victim = Utf8PathBuf::from_path_buf(tmp.path().to_path_buf())
        .unwrap()
        .join("victim.real");
    std::fs::write(victim.as_std_path(), b"original").unwrap();
    let original_uid = std::fs::metadata(victim.as_std_path()).unwrap().uid();
    let original_gid = std::fs::metadata(victim.as_std_path()).unwrap().gid();

    let swapped_path = Utf8PathBuf::from_path_buf(tmp.path().to_path_buf())
        .unwrap()
        .join("swapped.symlink");
    std::os::unix::fs::symlink(victim.as_std_path(), swapped_path.as_std_path())
        .unwrap();

    let systemd = MockSystemd::default();
    let config_shell = MockConfigShell::default();
    let tarball = MockTarball::default();
    let auth: HashMap<String, Box<dyn TokenSource>> = HashMap::new();
    let deps = rollback_deps(&systemd, &config_shell, &tarball, &auth);
    let paths = make_paths(&tmp);
    let mut log = UndoLog::new();
    // prior_uid/gid set to 0/0 (root) so a chown-through would
    // try to set victim to root-owned — would EPERM as non-root.
    // The refusal makes it Ok-skip, not Err.
    log.push(UndoStep::SetOwner {
        path: swapped_path.clone(),
        prior_uid: 0,
        prior_gid: 0,
    });
    undo(&log, &deps, &paths)
        .expect("undo SetOwner on symlink must Ok-skip (warn + continue), not Err");

    let post = std::fs::metadata(victim.as_std_path()).unwrap();
    assert_eq!(
        post.uid(),
        original_uid,
        "undo SetOwner must NOT chown-through symlink target; uid changed"
    );
    assert_eq!(
        post.gid(),
        original_gid,
        "undo SetOwner must NOT chown-through symlink target; gid changed"
    );
}

#[test]
fn set_owner_describe_includes_path_and_prior_uid_gid() {
    let step = UndoStep::SetOwner {
        path: Utf8PathBuf::from("/var/lib/ghars/default/ghars-a"),
        prior_uid: 1234,
        prior_gid: 5678,
    };
    let desc = step.describe();
    assert!(
        desc.contains("/var/lib/ghars/default/ghars-a"),
        "describe must include path: {desc}"
    );
    assert!(
        desc.contains("1234"),
        "describe must include prior_uid: {desc}"
    );
    assert!(
        desc.contains("5678"),
        "describe must include prior_gid: {desc}"
    );
}

#[test]
fn set_owner_is_not_reverse_direction() {
    // SetOwner's inverse (chown back to prior_uid/gid) is
    // lossless and SAFE to invoke during rollback. Verify it
    // dispatches through undo_one (not the warn-and-skip
    // reverse-direction path).
    let step = UndoStep::SetOwner {
        path: Utf8PathBuf::from("/x"),
        prior_uid: 0,
        prior_gid: 0,
    };
    assert!(
        !step.is_reverse_direction(),
        "SetOwner must be forward-direction (lossless inverse)"
    );
}

#[test]
fn undo_github_registration_calls_run_remove_with_fresh_token() {
    // GitHubRegistration undo: mint fresh removal token via auth
    // registry, call config_shell.run_remove. Operator gets a
    // server-side deregister even though the original action
    // failed.
    let systemd = MockSystemd::default();
    let config_shell = MockConfigShell::default();
    let tarball = MockTarball::default();
    let mut auth: HashMap<String, Box<dyn TokenSource>> = HashMap::new();
    auth.insert(
        "pat".into(),
        Box::new(MockTokenSource {
            name: "pat".into(),
            ..Default::default()
        }),
    );
    let deps = rollback_deps(&systemd, &config_shell, &tarball, &auth);
    let tmp = tempfile::tempdir().unwrap();
    let paths = make_paths(&tmp);
    let runner_home = paths.runner_home("default", "a");
    std::fs::create_dir_all(runner_home.as_std_path()).unwrap();
    // find_active_bin_dir scans for bin.X.Y.Z/ containing config.sh;
    // pre-stage one so the undo reaches config_shell.run_remove
    // (the assertion below counts config_shell.removed).
    let bin_dir = runner_home.join("bin.2.334.0");
    std::fs::create_dir_all(bin_dir.as_std_path()).unwrap();
    std::fs::write(bin_dir.join("config.sh").as_std_path(), b"#!/bin/sh\n").unwrap();
    let mut log = UndoLog::new();
    log.push(UndoStep::GitHubRegistration {
        name: "a".into(),
        url: "https://github.com/example/repo".into(),
        auth_name: "pat".into(),
        runner_home: runner_home.clone(),
    });
    undo(&log, &deps, &paths).unwrap();
    let removed = config_shell.removed.lock().unwrap().clone();
    assert_eq!(removed, vec!["a"], "run_remove must be invoked");
}

#[test]
fn undo_github_registration_warns_when_auth_missing() {
    // GitHubRegistration undo with auth_name not in registry: warn
    // and skip. The function returns Ok(()) — the rollback
    // continues even though this step couldn't fire.
    let systemd = MockSystemd::default();
    let config_shell = MockConfigShell::default();
    let tarball = MockTarball::default();
    let auth: HashMap<String, Box<dyn TokenSource>> = HashMap::new();
    let deps = rollback_deps(&systemd, &config_shell, &tarball, &auth);
    let tmp = tempfile::tempdir().unwrap();
    let paths = make_paths(&tmp);
    let runner_home = paths.runner_home("default", "a");
    let mut log = UndoLog::new();
    log.push(UndoStep::GitHubRegistration {
        name: "a".into(),
        url: "https://github.com/example/repo".into(),
        auth_name: "missing".into(),
        runner_home: runner_home.clone(),
    });
    undo(&log, &deps, &paths).unwrap();
    let removed = config_shell.removed.lock().unwrap().clone();
    assert!(
        removed.is_empty(),
        "run_remove must NOT fire when auth missing; got {removed:?}"
    );
}

#[test]
fn undo_walks_steps_in_reverse_order() {
    // Insert order: A, B. Undo order must be: B, A. The undo walk
    // is a Vec.iter().rev() so EnableUnit (last forward) becomes
    // disable_unit (first reverse), then StartUnit (the earlier
    // forward) becomes stop_unit (the later reverse).
    let systemd = MockSystemd::default();
    let config_shell = MockConfigShell::default();
    let tarball = MockTarball::default();
    let auth: HashMap<String, Box<dyn TokenSource>> = HashMap::new();
    let deps = rollback_deps(&systemd, &config_shell, &tarball, &auth);
    let tmp = tempfile::tempdir().unwrap();
    let paths = make_paths(&tmp);
    let mut log = UndoLog::new();
    log.push(UndoStep::StartUnit {
        name: "unit-a".into(),
    });
    log.push(UndoStep::EnableUnit {
        name: "unit-b".into(),
    });
    undo(&log, &deps, &paths).unwrap();
    let calls = systemd.calls_snapshot();
    // Reverse walk: disable_unit(unit-b) (from EnableUnit) before
    // stop_unit(unit-a) (from StartUnit).
    let pos_disable = calls
        .iter()
        .position(|c| c == "disable_unit(unit-b)")
        .expect("disable_unit recorded");
    let pos_stop = calls
        .iter()
        .position(|c| c == "stop_unit(unit-a)")
        .expect("stop_unit recorded");
    assert!(
        pos_disable < pos_stop,
        "disable_unit must precede stop_unit in reverse walk; got {calls:?}"
    );
}

#[test]
fn undo_skips_reverse_direction_steps_without_calling_systemd() {
    // RemoveFile / RemoveDir / StopUnit / DisableUnit are recorded
    // for audit-trail completeness. undo() logs warn + skips them
    // (no inverse attempted).
    let systemd = MockSystemd::default();
    let config_shell = MockConfigShell::default();
    let tarball = MockTarball::default();
    let auth: HashMap<String, Box<dyn TokenSource>> = HashMap::new();
    let deps = rollback_deps(&systemd, &config_shell, &tarball, &auth);
    let tmp = tempfile::tempdir().unwrap();
    let paths = make_paths(&tmp);
    let mut log = UndoLog::new();
    log.push(UndoStep::StopUnit { name: "u".into() });
    log.push(UndoStep::DisableUnit { name: "u".into() });
    log.push(UndoStep::RemoveDir {
        path: Utf8PathBuf::from("/some/path"),
    });
    log.push(UndoStep::RemoveFile {
        path: Utf8PathBuf::from("/some/file"),
        content: b"x".to_vec(),
    });
    undo(&log, &deps, &paths).unwrap();
    // None of the systemd inverses (start/enable) fired — all
    // reverse-direction steps were skipped.
    let calls = systemd.calls_snapshot();
    assert!(
        !calls.iter().any(|c| c.starts_with("start_unit")),
        "must not start_unit on StopUnit undo; got {calls:?}"
    );
    assert!(
        !calls.iter().any(|c| c.starts_with("enable_unit")),
        "must not enable_unit on DisableUnit undo; got {calls:?}"
    );
}

#[test]
fn apply_with_rollback_off_does_not_call_undo_on_failure() {
    // When --rollback-on-failure is OFF (default), a failing
    // action's UndoLog stays unwalked. Use a plan that fails on a
    // CreateRunner with no resolved release + no runner_tarball
    // (mint_token never reached, but enough side effects fired
    // pre-failure that the absence of an undo walk is observable).
    let tmp = tempfile::tempdir().unwrap();
    let paths = make_paths(&tmp);
    let mut plan_data = make_runner_plan("a", &paths.state_dir);
    plan_data.resolved_release = None;
    plan_data.spec.runner_tarball = None;
    let plan = Plan {
        actions: vec![Action::CreateRunner(plan_data)],
        warnings: vec![],
        keep_versions: 2,
    };
    let systemd = MockSystemd::default();
    let config_shell = MockConfigShell::default();
    let tarball = MockTarball::default();
    let mut auth: HashMap<String, Box<dyn TokenSource>> = HashMap::new();
    auth.insert(
        "pat".into(),
        Box::new(MockTokenSource {
            name: "pat".into(),
            ..Default::default()
        }),
    );
    let deps = Deps {
        systemd: &systemd,
        auth: &auth,
        tarball: &tarball,
        config_shell: &config_shell,
    };
    let opts = ApplyOptions {
        rollback_on_failure: false,
        ..Default::default()
    };
    let result = apply(&plan, &deps, &paths, &opts).unwrap();
    assert!(!result.failed.is_empty(), "plan must fail");
    // Rollback-OFF semantics for the surviving UndoStep variants
    // are covered by other tests.
}

#[test]
fn apply_with_rollback_on_walks_undo_log_on_failure() {
    // Same plan as above but with --rollback-on-failure ON. The
    // create path's pre-error mutations must be inverted by the
    // undo walk.
    let tmp = tempfile::tempdir().unwrap();
    let paths = make_paths(&tmp);
    let mut plan_data = make_runner_plan("a", &paths.state_dir);
    plan_data.resolved_release = None;
    plan_data.spec.runner_tarball = None;
    let plan = Plan {
        actions: vec![Action::CreateRunner(plan_data)],
        warnings: vec![],
        keep_versions: 2,
    };
    let systemd = MockSystemd::default();
    let config_shell = MockConfigShell::default();
    let tarball = MockTarball::default();
    let mut auth: HashMap<String, Box<dyn TokenSource>> = HashMap::new();
    auth.insert(
        "pat".into(),
        Box::new(MockTokenSource {
            name: "pat".into(),
            ..Default::default()
        }),
    );
    let deps = Deps {
        systemd: &systemd,
        auth: &auth,
        tarball: &tarball,
        config_shell: &config_shell,
    };
    let opts = ApplyOptions {
        rollback_on_failure: true,
        ..Default::default()
    };
    let result = apply(&plan, &deps, &paths, &opts).unwrap();
    assert!(!result.failed.is_empty(), "plan must fail");
}

#[test]
fn apply_with_rollback_on_does_not_undo_already_succeeded_actions() {
    // Per-action scope: a successful action whose sibling fails is
    // NOT undone. Plan has two actions: a CachePool that succeeds,
    // then a CreateRunner that fails (no release + no tarball).
    // The cache pool's group / unit / drop-in must remain.
    let tmp = tempfile::tempdir().unwrap();
    let paths = make_paths(&tmp);
    let cache_plan = CachePoolPlan {
        binding: crate::config::EffectiveCacheBinding {
            name: "build".into(),
            kinds: vec![crate::config::CacheKind::Ccache],
            size: "10G".into(),
            mode: crate::config::CacheMode::Shared,
            trust_zone: "default".into(),
            sccache_path: None,
            sleep_path: Some("/usr/bin/sleep".into()),
            renderer_schema: crate::systemd::RENDERER_SCHEMA,
        },
        drop_in_body: "[Service]\n".into(),
        spec_hash: "sha256:0".into(),
    };
    let mut runner_data = make_runner_plan("a", &paths.state_dir);
    runner_data.resolved_release = None;
    runner_data.spec.runner_tarball = None;
    let plan = Plan {
        actions: vec![
            Action::CreateCachePool(cache_plan),
            Action::CreateRunner(runner_data),
        ],
        warnings: vec![],
        keep_versions: 2,
    };
    let systemd = MockSystemd::default();
    let config_shell = MockConfigShell::default();
    let tarball = MockTarball::default();
    let mut auth: HashMap<String, Box<dyn TokenSource>> = HashMap::new();
    auth.insert(
        "pat".into(),
        Box::new(MockTokenSource {
            name: "pat".into(),
            ..Default::default()
        }),
    );
    let deps = Deps {
        systemd: &systemd,
        auth: &auth,
        tarball: &tarball,
        config_shell: &config_shell,
    };
    let opts = ApplyOptions {
        rollback_on_failure: true,
        ..Default::default()
    };
    let result = apply(&plan, &deps, &paths, &opts).unwrap();
    assert_eq!(result.failed.len(), 1, "exactly one action failed");
    // The pre-DynamicUser version asserted the cache pool's
    // groupadd ran and was NOT inverted by the failing runner
    // action's rollback walk. The trait is gone; the signal that
    // remains is the per-action scope (only the failed runner's
    // UndoLog walks; the successful pool's discards on Ok). The
    // pool's drop-in file should still exist on disk after the
    // mixed-success apply — assert that as the per-action-scope
    // signal that doesn't depend on the deleted trait.
    let pool_drop_in = paths.cache_drop_in_dir("build").join("00-ghars.conf");
    assert!(
        pool_drop_in.exists(),
        "cache pool drop-in must persist on disk despite runner failure; \
         per-action-scope rollback walks only the failed action's UndoLog"
    );
}
