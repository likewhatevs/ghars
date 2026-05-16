//! Tests for `apply::gc` (`gc_stale_temp_files` + `gc_stale_staging_dirs`).

use std::fs::OpenOptions;
use std::path::Path;

use super::super::gc::{
    STALE_TEMP_AGE_SECS, gc_stale_staging_dirs, gc_stale_temp_files, parse_staging_dir_suffix,
    parse_temp_file_suffix,
};
use super::common::make_paths;

/// Plant a synthetic `.NAME.tmp.PID.COUNTER` file in `dir`,
/// optionally back-dating its mtime past `STALE_TEMP_AGE_SECS`.
fn plant_temp_file(dir: &Path, name: &str, age_secs: Option<u64>) -> std::path::PathBuf {
    std::fs::create_dir_all(dir).unwrap();
    let path = dir.join(name);
    std::fs::write(&path, b"stale temp\n").unwrap();
    if let Some(secs) = age_secs {
        let new_mtime = std::time::SystemTime::now() - std::time::Duration::from_secs(secs);
        // utimensat via std: filetime crate isn't pulled in;
        // use SetFileTimes through the OpenOptions handle.
        let f = OpenOptions::new().write(true).open(&path).unwrap();
        f.set_modified(new_mtime).unwrap();
    }
    path
}

#[test]
fn gc_stale_temp_files_removes_aged_dead_pid_temp_files() {
    let tmp = tempfile::tempdir().unwrap();
    let paths = make_paths(&tmp);
    // PID 999999 is reserved for testing — well beyond
    // typical PID_MAX (32768 default, 4194304 max). Combined with
    // an mtime past the 60s gate, this file must be removed.
    let stale = plant_temp_file(
        paths.unit_dir.as_std_path(),
        ".ghars-runner@a.service.tmp.999999.0",
        Some(STALE_TEMP_AGE_SECS + 30),
    );
    assert!(stale.exists(), "fixture invariant: planted file must exist");

    gc_stale_temp_files(&paths);

    assert!(
        !stale.exists(),
        "stale temp file (dead PID, mtime > {STALE_TEMP_AGE_SECS}s) must be removed",
    );
}

#[test]
fn gc_stale_temp_files_preserves_recent_temp_files() {
    let tmp = tempfile::tempdir().unwrap();
    let paths = make_paths(&tmp);
    // Recent file (no back-dating) — even with a stale-looking
    // PID, the mtime gate must keep it. Protects against ripping
    // an in-flight write_root_owned out from under a concurrent
    // call. (The lock prevents cross-process races; this guards
    // a future caller that drops the lock somehow.)
    let recent = plant_temp_file(
        paths.unit_dir.as_std_path(),
        ".ghars-runner@b.service.tmp.999999.5",
        None,
    );
    assert!(recent.exists(), "fixture invariant");

    gc_stale_temp_files(&paths);

    assert!(
        recent.exists(),
        "recent temp file (mtime < {STALE_TEMP_AGE_SECS}s) must be preserved",
    );
}

#[test]
fn gc_stale_temp_files_preserves_files_with_our_pid() {
    let tmp = tempfile::tempdir().unwrap();
    let paths = make_paths(&tmp);
    let our_pid = std::process::id();
    // Even if old, embedded-PID-equals-us means a future call in
    // this process might still be holding the temp open. Defensive
    // skip — apply.lock keeps cross-process collisions out, but
    // intra-process collisions need the PID guard.
    let same_pid = plant_temp_file(
        paths.unit_dir.as_std_path(),
        &format!(".ghars-runner@c.service.tmp.{our_pid}.0"),
        Some(STALE_TEMP_AGE_SECS + 30),
    );
    assert!(same_pid.exists(), "fixture invariant");

    gc_stale_temp_files(&paths);

    assert!(
        same_pid.exists(),
        "temp file with our own PID must be preserved (defensive guard)",
    );
}

#[test]
fn gc_stale_temp_files_preserves_non_temp_files() {
    let tmp = tempfile::tempdir().unwrap();
    let paths = make_paths(&tmp);
    std::fs::create_dir_all(paths.unit_dir.as_std_path()).unwrap();
    let cases = [
        "ghars-runner@a.service",           // no leading dot
        ".hidden-not-a-temp",               // dot but no .tmp.PID.COUNTER
        ".something.tmp.notanumber.0",      // PID component non-numeric
        ".something.tmp.999999.notanumber", // counter non-numeric
        ".something.tmp.999999",            // missing counter component
        "regular.conf",                     // operator-dropped file
    ];
    let mut planted: Vec<std::path::PathBuf> = Vec::new();
    for name in cases {
        planted.push(plant_temp_file(
            paths.unit_dir.as_std_path(),
            name,
            Some(STALE_TEMP_AGE_SECS + 30),
        ));
    }

    gc_stale_temp_files(&paths);

    for p in &planted {
        assert!(
            p.exists(),
            "non-temp file or unparseable name must be preserved: {p:?}",
        );
    }
}

#[test]
fn gc_stale_temp_files_scans_runner_drop_in_dir() {
    let tmp = tempfile::tempdir().unwrap();
    let paths = make_paths(&tmp);
    let drop_in_dir = paths.unit_dir.join("ghars-runner@a.service.d");
    let stale = plant_temp_file(
        drop_in_dir.as_std_path(),
        ".10-memory.conf.tmp.999999.0",
        Some(STALE_TEMP_AGE_SECS + 30),
    );
    assert!(stale.exists(), "fixture invariant");

    gc_stale_temp_files(&paths);

    assert!(
        !stale.exists(),
        "GC must scan ghars-runner@*.service.d/ subdirectories",
    );
}

#[test]
fn gc_stale_temp_files_scans_cache_pool_drop_in_dir() {
    let tmp = tempfile::tempdir().unwrap();
    let paths = make_paths(&tmp);
    let drop_in_dir = paths.unit_dir.join("ghars-cache@build.service.d");
    let stale = plant_temp_file(
        drop_in_dir.as_std_path(),
        ".00-ghars.conf.tmp.999999.0",
        Some(STALE_TEMP_AGE_SECS + 30),
    );
    assert!(stale.exists(), "fixture invariant");

    gc_stale_temp_files(&paths);

    assert!(
        !stale.exists(),
        "GC must scan ghars-cache@*.service.d/ subdirectories",
    );
}

#[test]
fn gc_stale_temp_files_scans_nft_d_and_netns_d() {
    let tmp = tempfile::tempdir().unwrap();
    let paths = make_paths(&tmp);
    let nft = paths.config_dir.join("nft.d");
    let netns = paths.config_dir.join("netns.d");
    let stale_nft = plant_temp_file(
        nft.as_std_path(),
        ".a-host.nft.tmp.999999.0",
        Some(STALE_TEMP_AGE_SECS + 30),
    );
    let stale_netns = plant_temp_file(
        netns.as_std_path(),
        ".a.toml.tmp.999999.0",
        Some(STALE_TEMP_AGE_SECS + 30),
    );

    gc_stale_temp_files(&paths);

    assert!(!stale_nft.exists(), "GC must scan config_dir/nft.d");
    assert!(!stale_netns.exists(), "GC must scan config_dir/netns.d");
}

#[test]
fn gc_stale_temp_files_tolerates_missing_dirs() {
    // No fs::create_dir_all on any dir — every dir is missing.
    // gc must complete without panic and without error.
    let tmp = tempfile::tempdir().unwrap();
    let paths = make_paths(&tmp);
    gc_stale_temp_files(&paths);
    // Reaching here = pass.
}

// ---- gc_stale_staging_dirs --------------------------------------------

/// Plant a synthetic `<state_dir>/.staging/<name>-<version>-<pid>/`
/// directory, optionally back-dating its mtime past
/// `STALE_TEMP_AGE_SECS`. Returns the planted path so the test can
/// assert presence / absence after the GC pass.
fn plant_staging_dir(
    state_dir: &Path,
    name: &str,
    version: &str,
    pid: i32,
    age_secs: Option<u64>,
) -> std::path::PathBuf {
    let staging_root = state_dir.join(".staging");
    std::fs::create_dir_all(&staging_root).unwrap();
    let dir = staging_root.join(format!("{name}-{version}-{pid}"));
    std::fs::create_dir_all(&dir).unwrap();
    // Drop a sentinel file so the dir is non-empty, matching the
    // partial-extract leftover state in production.
    std::fs::write(dir.join("sentinel"), b"partial extract\n").unwrap();
    if let Some(secs) = age_secs {
        let new_mtime = std::time::SystemTime::now() - std::time::Duration::from_secs(secs);
        // utimensat via std: filetime crate isn't pulled in;
        // mirror plant_temp_file's set_modified handle pattern but
        // on the directory inode (Linux supports SetFileTimes on
        // dirs through std::fs::File::open).
        let f = OpenOptions::new()
            .read(true)
            .open(&dir)
            .expect("open staging dir for set_modified");
        f.set_modified(new_mtime).unwrap();
    }
    dir
}

#[test]
fn gc_stale_staging_dirs_removes_aged_dead_pid_dir() {
    let tmp = tempfile::tempdir().unwrap();
    let paths = make_paths(&tmp);
    // PID 999999 exceeds typical PID_MAX (32768 default, 4194304
    // max). Combined with mtime past the 60s gate the dir must be
    // removed. Mirror gc_stale_temp_files_removes_aged_dead_pid_temp_files.
    let stale = plant_staging_dir(
        paths.state_dir.as_std_path(),
        "buckos",
        "2.334.0",
        999_999,
        Some(STALE_TEMP_AGE_SECS + 30),
    );
    assert!(stale.exists(), "fixture invariant: planted dir must exist");

    gc_stale_staging_dirs(&paths);

    assert!(
        !stale.exists(),
        "stale staging dir (dead PID, mtime > {STALE_TEMP_AGE_SECS}s) must be removed",
    );
}

#[test]
fn gc_stale_staging_dirs_preserves_recent_dir() {
    let tmp = tempfile::tempdir().unwrap();
    let paths = make_paths(&tmp);
    // Recent staging dir (no back-dating) — even with a clearly
    // stale-looking PID, the mtime gate must keep it. Protects
    // against GC ripping an in-flight `install_runner_binary`
    // staging tree out from under a concurrent extract. The lock
    // prevents cross-process races; this guards a future caller
    // that drops the lock somehow.
    let recent = plant_staging_dir(
        paths.state_dir.as_std_path(),
        "buckos",
        "2.334.0",
        999_999,
        None,
    );
    assert!(recent.exists(), "fixture invariant");

    gc_stale_staging_dirs(&paths);

    assert!(
        recent.exists(),
        "recent staging dir (mtime < {STALE_TEMP_AGE_SECS}s) must be preserved",
    );
}

#[test]
fn gc_stale_staging_dirs_preserves_dir_with_our_pid() {
    let tmp = tempfile::tempdir().unwrap();
    let paths = make_paths(&tmp);
    let our_pid = i32::try_from(std::process::id()).unwrap_or(i32::MAX);
    // Even old, embedded-PID-equals-us means a future caller in
    // this process might still hold the staging tree open.
    // Defensive skip — apply.lock keeps cross-process collisions
    // out, but intra-process collisions need the PID guard.
    let same_pid = plant_staging_dir(
        paths.state_dir.as_std_path(),
        "buckos",
        "2.334.0",
        our_pid,
        Some(STALE_TEMP_AGE_SECS + 30),
    );
    assert!(same_pid.exists(), "fixture invariant");

    gc_stale_staging_dirs(&paths);

    assert!(
        same_pid.exists(),
        "staging dir with our own PID must be preserved (defensive guard)",
    );
}

#[test]
fn gc_stale_staging_dirs_preserves_unparseable_dir_names() {
    let tmp = tempfile::tempdir().unwrap();
    let paths = make_paths(&tmp);
    let staging_root = paths.state_dir.join(".staging");
    std::fs::create_dir_all(staging_root.as_std_path()).unwrap();
    // Names that don't match {name}-{version}-{pid} — the trailing
    // '-' or non-numeric trailing component must NOT parse.
    let cases = [
        "no-trailing-pid-marker", // last segment "marker" not numeric
        "missingdash",            // no dashes at all
        "ends-with-",             // empty trailing component
    ];
    let mut planted: Vec<std::path::PathBuf> = Vec::new();
    for name in cases {
        let dir = staging_root.as_std_path().join(name);
        std::fs::create_dir_all(&dir).unwrap();
        let new_mtime =
            std::time::SystemTime::now() - std::time::Duration::from_secs(STALE_TEMP_AGE_SECS + 30);
        let f = OpenOptions::new().read(true).open(&dir).unwrap();
        f.set_modified(new_mtime).unwrap();
        planted.push(dir);
    }

    gc_stale_staging_dirs(&paths);

    for p in &planted {
        assert!(
            p.exists(),
            "unparseable staging-dir name must be preserved: {p:?}",
        );
    }
}

#[test]
fn gc_stale_staging_dirs_tolerates_missing_staging_root() {
    // No `.staging` directory at all — gc must return without
    // panic. Mirror gc_stale_temp_files_tolerates_missing_dirs.
    let tmp = tempfile::tempdir().unwrap();
    let paths = make_paths(&tmp);
    gc_stale_staging_dirs(&paths);
    // Reaching here = pass.
}

/// Pin that gc removes the entire staging tree
/// (not just the leaf directory). extract.rs's partial-extract
/// state typically contains nested files and subdirectories — the
/// distinction between `fs::remove_dir` (refuses non-empty dirs)
/// and `fs::remove_dir_all` (recurses) is load-bearing. Without
/// this test a future cleanup pass could accidentally swap to
/// `remove_dir` and orphan the contents permanently.
#[test]
fn gc_stale_staging_dirs_removes_nested_contents() {
    let tmp = tempfile::tempdir().unwrap();
    let paths = make_paths(&tmp);
    // Build the staging tree manually so we can back-date the
    // root mtime AFTER populating all children. plant_staging_dir
    // sets the mtime once at construction, but adding child
    // entries below updates the directory's mtime back to "now"
    // (see VFS dir mtime semantics: any namespace operation in
    // the directory bumps it). We have to back-date as the LAST
    // step or the age gate will skip the dir.
    let staging_root = paths.state_dir.join(".staging");
    std::fs::create_dir_all(staging_root.as_std_path()).unwrap();
    let stale = staging_root.as_std_path().join("buckos-2.334.0-999999");
    std::fs::create_dir_all(&stale).unwrap();
    // Mimic the actions runner tarball partial-extract layout —
    // nested directories with files inside, plus a deeper subdir.
    // remove_dir would refuse all of these; remove_dir_all
    // recursively removes them.
    let bin_dir = stale.join("bin");
    std::fs::create_dir_all(&bin_dir).unwrap();
    std::fs::write(bin_dir.join("Runner.Listener"), b"partial binary\n").unwrap();
    std::fs::write(bin_dir.join("Runner.Worker"), b"partial binary\n").unwrap();
    let externals = stale.join("externals").join("node20").join("bin");
    std::fs::create_dir_all(&externals).unwrap();
    std::fs::write(externals.join("node"), b"partial node\n").unwrap();
    // Sentinel at the root level too.
    std::fs::write(stale.join("config.sh"), b"partial config\n").unwrap();
    // Back-date the root staging dir's mtime AFTER all children
    // are written. gc reads `entry.metadata()` on the root entry
    // (not on children) for the age comparison.
    let new_mtime =
        std::time::SystemTime::now() - std::time::Duration::from_secs(STALE_TEMP_AGE_SECS + 30);
    let f = OpenOptions::new().read(true).open(&stale).unwrap();
    f.set_modified(new_mtime).unwrap();
    assert!(
        stale.exists(),
        "fixture invariant: staging tree must exist before gc"
    );
    assert!(
        externals.exists(),
        "fixture invariant: nested subtree must exist before gc"
    );

    gc_stale_staging_dirs(&paths);

    // Entire tree must be gone — the leaf directory AND every
    // ancestor between it and the root.
    assert!(
        !stale.exists(),
        "staging dir must be removed (proves remove_dir_all, not remove_dir)"
    );
    assert!(
        !externals.exists(),
        "nested subtree must be removed (proves recursive walk)"
    );
    // The .staging/ root itself must remain — gc only sweeps
    // children, not the parent.
    assert!(
        paths.state_dir.join(".staging").as_std_path().exists(),
        ".staging/ root must persist after sweeping a child"
    );
}

/// Pin the no-op contract on an empty
/// `.staging/`. After a previous gc pass the parent stays as an
/// empty dir; subsequent gc invocations must NOT remove the
/// parent (`extract.rs::install_runner_binary` calls
/// `fs::create_dir_all(&staging_root)` on every install but the
/// idempotent guarantee holds whether or not we delete the root)
/// and must NOT panic. Pairs with the missing-root test above.
#[test]
fn gc_stale_staging_dirs_no_op_on_empty_staging_root() {
    let tmp = tempfile::tempdir().unwrap();
    let paths = make_paths(&tmp);
    let staging_root = paths.state_dir.join(".staging");
    std::fs::create_dir_all(staging_root.as_std_path()).unwrap();
    assert!(
        staging_root.as_std_path().exists(),
        "fixture invariant: empty .staging/ must exist before gc"
    );
    let entries_before: Vec<_> = std::fs::read_dir(staging_root.as_std_path())
        .unwrap()
        .collect::<std::result::Result<_, _>>()
        .unwrap();
    assert!(
        entries_before.is_empty(),
        "fixture invariant: .staging/ must be empty before gc"
    );

    gc_stale_staging_dirs(&paths);

    // .staging/ must still exist and still be empty.
    assert!(
        staging_root.as_std_path().exists(),
        "empty .staging/ must persist (gc only sweeps children)"
    );
    let entries_after: Vec<_> = std::fs::read_dir(staging_root.as_std_path())
        .unwrap()
        .collect::<std::result::Result<_, _>>()
        .unwrap();
    assert!(
        entries_after.is_empty(),
        ".staging/ must remain empty after gc on empty input"
    );
}

/// What this test pins: a symlink under
/// `.staging/` whose name parses as `<name>-<version>-<pid>` —
/// with a dead PID and a back-dated mtime past
/// `STALE_TEMP_AGE_SECS` so neither own-PID nor age can cause the
/// skip — survives `gc_stale_staging_dirs` AND its target stays
/// untouched.
///
/// What this test does NOT prove: that the explicit
/// `ft.is_symlink()` gate is load-bearing. `entry.file_type()` is
/// lstat-style, so symlinks report `is_dir() == false`; if the
/// explicit gate were deleted, `!ft.is_dir()` would still skip
/// symlinks. The two gates produce the same observable behavior
/// under lstat semantics — this assertion alone cannot
/// distinguish them.
///
/// Why the explicit gate exists anyway: defense-in-depth + intent
/// signaling. The hostile case is an attacker who can write to
/// `.staging/` replacing a real staging tree with a symlink to
/// e.g. `/etc` and relying on a future regression of the lstat
/// invariant (or a refactor that switches to `metadata()` —
/// which DOES follow symlinks) to redirect `remove_dir_all`
/// outside the staging root. Symmetric to `gc_stale_temp_files`'s
/// `!is_file()` symlink-skip pattern.
#[test]
fn gc_stale_staging_dirs_skips_symlink_entries() {
    let tmp = tempfile::tempdir().unwrap();
    let paths = make_paths(&tmp);
    let staging_root = paths.state_dir.join(".staging");
    std::fs::create_dir_all(staging_root.as_std_path()).unwrap();
    // Create a "victim" directory the symlink points to —
    // bystander we must NOT touch.
    let victim = tmp.path().join("victim-bystander");
    std::fs::create_dir_all(&victim).unwrap();
    std::fs::write(victim.join("sentinel"), b"do not delete\n").unwrap();
    // Place the symlink at a name that would otherwise look like a
    // legitimate staging entry: `<name>-<version>-<aged-pid>`. PID
    // 999_999 is far past typical PID_MAX so this name is
    // unambiguously not our own.
    let trap = staging_root.as_std_path().join("buckos-2.334.0-999999");
    std::os::unix::fs::symlink(&victim, &trap).unwrap();
    // Back-date the symlink's own mtime past `STALE_TEMP_AGE_SECS`
    // so the age gate aligns for removal. std::fs::File::open
    // follows symlinks, so set_modified on a File handle would
    // touch the *target* — we need lutimes semantics. nix's
    // `utimensat` with `UtimensatFlags::NoFollowSymlink` and
    // `dirfd = None` (relative to CWD) is the portable
    // equivalent.
    let new_mtime_since_epoch = (std::time::SystemTime::now()
        - std::time::Duration::from_secs(STALE_TEMP_AGE_SECS + 30))
    .duration_since(std::time::UNIX_EPOCH)
    .expect("test clock must be after UNIX epoch");
    let ts = nix::sys::time::TimeSpec::from_duration(new_mtime_since_epoch);
    let dirfd = std::fs::File::open("/").unwrap();
    nix::sys::stat::utimensat(
        &dirfd,
        trap.as_path(),
        &ts,
        &ts,
        nix::sys::stat::UtimensatFlags::NoFollowSymlink,
    )
    .expect("utimensat AT_SYMLINK_NOFOLLOW must succeed on the test runner");
    assert!(
        std::fs::symlink_metadata(&trap)
            .unwrap()
            .file_type()
            .is_symlink(),
        "fixture invariant: planted entry must be a symlink"
    );

    gc_stale_staging_dirs(&paths);

    // The symlink itself must persist (gc skipped it) AND the
    // victim directory must remain untouched.
    assert!(
        std::fs::symlink_metadata(&trap).is_ok(),
        "symlink under .staging/ must be preserved (defense-in-depth)"
    );
    assert!(
        victim.join("sentinel").exists(),
        "victim directory pointed at by symlink must NOT be removed"
    );
}

#[test]
fn parse_staging_dir_suffix_rejects_unparseable_inputs() {
    // Inputs that don't match the trailing `-NUM` shape must
    // return None so the caller's foreign-name skip kicks in.
    for name in ["noseparators", "trailing-nondigit", "ends-with-", ""] {
        assert!(
            parse_staging_dir_suffix(name).is_none(),
            "unparseable name must not yield a PID: {name:?}",
        );
    }
}

#[test]
fn parse_staging_dir_suffix_accepts_versioned_runner_name() {
    // Real-world shape: name + version + pid where version itself
    // contains hyphens (e.g. a release-candidate suffix). The
    // right-split must pick the trailing PID and leave the rest
    // alone — production names like `buckos-2.334.0-rc1-12345`
    // still parse to PID 12345.
    let pid = parse_staging_dir_suffix("buckos-2.334.0-rc1-12345");
    assert_eq!(pid, Some(12345));
    // Plain name + version: also parses.
    let pid2 = parse_staging_dir_suffix("buckos-2.334.0-9999");
    assert_eq!(pid2, Some(9999));
}

/// 4i: directive-named contract pin for `parse_staging_dir_suffix`,
/// symmetric with the `parse_temp_file_suffix` tests below.
/// Documents the four cases the convergence team called out:
/// - canonical `<name>-<version>-<pid>` → Some(pid)
/// - non-numeric trailing → None
/// - single-segment / no hyphen → None
/// - 2-segment shape `foo-1.2.3` → None
///
/// The helper's contract is `name.rsplit_once('-')?` then
/// `pid_str.parse::<i32>().ok()`. `rsplit_once('-')` returns the
/// content AFTER the LAST `-`, so `"foo-1.2.3"` rsplits to
/// `("foo", "1.2.3")`. `"1.2.3"` is not a valid i32 (contains
/// dots), so the parse fails and the helper returns `None`.
/// Strings whose post-last-hyphen segment is not a bare integer
/// are all rejected — this means the GC's foreign-skip is
/// shape-aware in practice: directory names that happen to
/// contain hyphens but whose tail is a dotted version (rather
/// than a PID) do not match.
#[test]
fn parse_staging_dir_pid_directive_cases() {
    assert_eq!(
        parse_staging_dir_suffix("foo-1.2.3-12345"),
        Some(12345),
        "valid name-version-pid shape must parse"
    );
    assert_eq!(
        parse_staging_dir_suffix("foo-1.2.3"),
        None,
        "trailing segment `1.2.3` (after the last `-`) fails i32::parse → None"
    );
    assert_eq!(
        parse_staging_dir_suffix("foo-1.2.3-abc"),
        None,
        "non-numeric trailing segment rejects"
    );
    assert_eq!(
        parse_staging_dir_suffix("nodashes"),
        None,
        "no hyphen rejects"
    );
}

#[test]
fn parse_temp_file_suffix_rejects_unparseable_inputs() {
    // Direct test of the helper since it gates everything.
    assert!(
        parse_temp_file_suffix("ghars-runner@a.service").is_none(),
        "no leading dot ⇒ None"
    );
    assert!(
        parse_temp_file_suffix(".hidden-no-tmp").is_none(),
        "no .tmp.PID.COUNTER segment ⇒ None"
    );
    assert!(
        parse_temp_file_suffix(".x.tmp.foo.0").is_none(),
        "non-numeric PID ⇒ None"
    );
    assert!(
        parse_temp_file_suffix(".x.tmp.999.bar").is_none(),
        "non-numeric counter ⇒ None"
    );
    assert!(
        parse_temp_file_suffix(".x.tmp.999").is_none(),
        "missing counter ⇒ None"
    );
    assert_eq!(
        parse_temp_file_suffix(".ghars-runner@a.service.tmp.42.7"),
        Some((42, 7)),
        "canonical shape parses"
    );
}
