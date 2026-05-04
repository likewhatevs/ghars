//! `guard_home_dir_rmrf` — defense-in-depth gate around the recursive
//! removal of a runner home (or per-pool storage dir).

use std::ffi::OsStr;
use std::fs;
use std::path::Path;

use camino::Utf8Path;

use crate::Result;
use crate::error::GharsError;

/// Refuse to recursively remove `home_dir` unless it is the canonical
/// `<prefix>/<name>` path. This guards against five failure modes:
/// 1. `home_dir == "/"` (or any root-equivalent) — never delete root.
/// 2. `home_dir == prefix` — never delete the prefix itself; only its
///    per-runner child.
/// 3. The runner name contains a path separator or `.`/`..`.
/// 4. `home_dir` is itself a symlink (SEC-NEW): would let an attacker
///    repoint the rmrf target to an arbitrary path. Std's modern
///    `remove_dir_all` already detects this and only unlinks the
///    symlink, but the guard rejects it explicitly so a future std
///    regression cannot reintroduce the attack.
/// 5. `home_dir`'s canonical form (after symlink resolution on every
///    path component) does not equal `<canon_prefix>/<runner_name>` —
///    catches symlink injection at any intermediate component, e.g. a
///    parent directory that has been renamed and replaced with a
///    symlink to `/etc`.
///
/// Filesystem checks (4 and 5) only fire when `home_dir` exists.
/// `execute_remove_runner` gates the rmrf on `runner_home.exists()`, and
/// the existing string-only checks (1, 2, 3) catch the bogus-path
/// cases that filesystem-free callers (current tests) need.
///
/// # Errors
///
/// `GharsError::Validation` with a hint pointing at the spec's `name`
/// field when any guard fails.
pub fn guard_home_dir_rmrf(
    home_dir: &Utf8Path,
    prefix: &Utf8Path,
    runner_name: &str,
) -> Result<()> {
    if home_dir.as_str() == "/" || home_dir.as_os_str() == OsStr::new("/") {
        return Err(GharsError::Validation(
            format!("refusing rmrf on `/` for runner {runner_name:?}"),
            "ghars never deletes the filesystem root; check the runner's prefix".into(),
        ));
    }
    if home_dir == prefix {
        return Err(GharsError::Validation(
            format!(
                "refusing rmrf on prefix {prefix} for runner {runner_name:?}; \
                 home dir must be a child of the prefix"
            ),
            "this means the per-runner subdirectory was lost; check the runner's spec".into(),
        ));
    }
    let expected = prefix.join(runner_name);
    if home_dir != expected {
        return Err(GharsError::Validation(
            format!(
                "refusing rmrf on {home_dir} for runner {runner_name:?}; \
                 expected {expected}"
            ),
            "the runner's home directory does not match `<prefix>/<name>`; \
             this can happen if the spec's name contains path separators or `..`"
                .into(),
        ));
    }
    // Component-level safety: the runner name itself must be a single
    // path component (no `/`, no `..`). The IDENTIFIER_REGEX validator
    // upstream already rejects this, but the guard repeats the check
    // because apply runs on the deserialized spec whose validation may
    // have been bypassed by tests.
    if runner_name.contains('/') || runner_name == "." || runner_name == ".." {
        return Err(GharsError::Validation(
            format!("runner name {runner_name:?} contains path separator or `.`/`..`"),
            "runner names must satisfy IDENTIFIER_REGEX".into(),
        ));
    }
    // SEC-NEW: filesystem-level symlink rejection + canonicalization.
    // Only fire when the path actually exists on disk; the caller
    // (`execute_remove_runner`) already gates the rmrf on
    // `runner_home.exists()` and the existing string checks above
    // cover the bogus-path test cases that don't touch the fs.
    let home_std: &Path = home_dir.as_std_path();
    let home_lmeta = match fs::symlink_metadata(home_std) {
        Ok(m) => m,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(()),
        Err(e) => return Err(GharsError::Io(e)),
    };
    if home_lmeta.file_type().is_symlink() {
        // Std's modern `remove_dir_all` lstats first and unlinks the
        // symlink rather than following it. We still reject here so
        // the runner home is replaced from a clean baseline
        // — a symlink at the home path means the parent directory's
        // permissions slipped (parent should be root-owned 0755 per
        // SEC-11) and apply should not silently paper over that.
        return Err(GharsError::Validation(
            format!(
                "refusing rmrf: {home_dir} is a symlink (runner {runner_name:?}); \
                 the parent directory's permissions allowed a symlink to be \
                 planted in place of the runner home"
            ),
            "investigate <prefix> ownership/mode; SEC-11 requires the parent \
             to be root:root mode 0755"
                .into(),
        ));
    }
    // Canonicalize home_dir + prefix and verify the canonical home
    // resolves to <canon_prefix>/<runner_name> exactly. Catches a
    // parent-component symlink swap: even if the leaf is a real
    // directory, a renamed-and-replaced ancestor would point the
    // rmrf at the wrong tree.
    let canon_home = fs::canonicalize(home_std).map_err(GharsError::Io)?;
    let canon_prefix = fs::canonicalize(prefix.as_std_path()).map_err(GharsError::Io)?;
    let expected_canon = canon_prefix.join(runner_name);
    if canon_home != expected_canon {
        return Err(GharsError::Validation(
            format!(
                "refusing rmrf: canonical {} differs from expected {} \
                 (runner {runner_name:?}); a path component is a symlink \
                 pointing outside the prefix",
                canon_home.display(),
                expected_canon.display()
            ),
            "investigate the runner home's parent chain for symlinks; this \
             usually means an operator manually relocated the runner tree"
                .into(),
        ));
    }
    Ok(())
}
