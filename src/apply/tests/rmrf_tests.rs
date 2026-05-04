//! Tests for `apply::rmrf::guard_home_dir_rmrf`.

use camino::{Utf8Path, Utf8PathBuf};

use super::super::rmrf::guard_home_dir_rmrf;

#[test]
fn guard_home_dir_rmrf_rejects_root() {
    let err = guard_home_dir_rmrf(
        Utf8Path::new("/"),
        Utf8Path::new("/var/lib/ghars"),
        "buckos",
    )
    .unwrap_err();
    assert!(format!("{err}").contains("/"));
}

#[test]
fn guard_home_dir_rmrf_rejects_prefix_itself() {
    let err = guard_home_dir_rmrf(
        Utf8Path::new("/var/lib/ghars"),
        Utf8Path::new("/var/lib/ghars"),
        "buckos",
    )
    .unwrap_err();
    assert!(format!("{err}").contains("prefix"));
}

#[test]
fn guard_home_dir_rmrf_rejects_outside_prefix() {
    let err = guard_home_dir_rmrf(
        Utf8Path::new("/etc/passwd"),
        Utf8Path::new("/var/lib/ghars"),
        "buckos",
    )
    .unwrap_err();
    assert!(format!("{err}").contains("expected"));
}

#[test]
fn guard_home_dir_rmrf_accepts_canonical_path() {
    guard_home_dir_rmrf(
        Utf8Path::new("/var/lib/ghars/buckos"),
        Utf8Path::new("/var/lib/ghars"),
        "buckos",
    )
    .unwrap();
}

#[test]
fn guard_home_dir_rmrf_rejects_path_separator_in_name() {
    let err = guard_home_dir_rmrf(
        Utf8Path::new("/var/lib/ghars/foo/bar"),
        Utf8Path::new("/var/lib/ghars"),
        "foo/bar",
    )
    .unwrap_err();
    assert!(
        format!("{err}").contains("expected") || format!("{err}").contains("path separator")
    );
}

#[test]
fn guard_home_dir_rmrf_rejects_symlink_at_home_path() {
    // SEC-NEW: if an attacker plants a symlink at the
    // runner home path pointing to (e.g.) /etc, the guard must
    // reject before rmrf runs. Std's modern remove_dir_all also
    // detects this and unlinks-the-symlink rather than following
    // — but the guard rejects explicitly so a future std
    // regression cannot reintroduce the attack.
    let tmp = tempfile::tempdir().unwrap();
    let prefix = Utf8PathBuf::from_path_buf(tmp.path().to_path_buf()).unwrap();
    // Create a symlink at <prefix>/buckos pointing to a real
    // directory elsewhere; the path-string check passes (it
    // equals <prefix>/buckos), so only the symlink check catches
    // it.
    let target = tmp.path().join("attacker-target");
    std::fs::create_dir_all(&target).unwrap();
    let runner_home = prefix.join("buckos");
    std::os::unix::fs::symlink(&target, runner_home.as_std_path()).unwrap();

    let err = guard_home_dir_rmrf(&runner_home, &prefix, "buckos").unwrap_err();
    let msg = format!("{err}");
    assert!(
        msg.contains("symlink"),
        "rejection must mention symlink, got: {msg}"
    );
}

#[test]
fn guard_home_dir_rmrf_accepts_real_dir_through_symlinked_prefix() {
    // Defensive control: if the prefix is itself a symlink
    // (operators sometimes alias /var/lib through a tmpfs path),
    // canonicalization must resolve both sides consistently and
    // accept the real home. This pins the round-trip equivalence:
    // the canonicalize branch in guard_home_dir_rmrf must NOT
    // false-positive on a benign prefix-level symlink.
    let tmp = tempfile::tempdir().unwrap();
    let real_prefix = tmp.path().join("real_prefix");
    std::fs::create_dir_all(real_prefix.join("buckos")).unwrap();
    let aliased = tmp.path().join("aliased");
    std::os::unix::fs::symlink(&real_prefix, &aliased).unwrap();

    let prefix_u = Utf8PathBuf::from_path_buf(aliased.clone()).unwrap();
    let home_u = Utf8PathBuf::from_path_buf(aliased.join("buckos")).unwrap();
    guard_home_dir_rmrf(&home_u, &prefix_u, "buckos").unwrap();
}

#[test]
fn guard_home_dir_rmrf_accepts_real_dir_under_real_prefix() {
    // Positive control for the symlink/canonicalize branch: when
    // both prefix and home are real directories with no symlinks
    // anywhere, the guard returns Ok.
    let tmp = tempfile::tempdir().unwrap();
    let prefix = Utf8PathBuf::from_path_buf(tmp.path().to_path_buf()).unwrap();
    let home = prefix.join("buckos");
    std::fs::create_dir_all(home.as_std_path()).unwrap();

    guard_home_dir_rmrf(&home, &prefix, "buckos").unwrap();
}
