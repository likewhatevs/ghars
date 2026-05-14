//! Path-normalization helpers shared across config-load validators and
//! render-time bind-emission gates.

use camino::Utf8Path;

/// Whether `path` resolves to the filesystem root (`/`) after
/// component-walk normalization. Catches operator-supplied paths
/// whose textual form differs from `/` but whose resolved bind
/// target is the host root: `//`, `///`, `/.`, `/./`, `/foo/..`,
/// `/foo/bar/../..`, etc.
///
/// Walks `Path::components()` and tracks normalized depth:
/// - `RootDir`, `CurDir` (`.`) are no-ops.
/// - `ParentDir` (`..`) decrements depth, saturating at 0 — climbing
///   above root stays at root, matching Linux kernel semantics for
///   `/..`.
/// - `Normal` (operator-named component) increments depth.
///
/// A final depth of 0 means every `Normal` component was cancelled
/// by a `ParentDir`, leaving only root.
///
/// Accepts: `/etc`, `/etc/`, `/foo/../bar`, `/foo/./bar`.
/// Rejects: `/`, `//`, `///`, `/.`, `/./`, `/foo/..`,
/// `/foo/bar/../..`, `/.//.`.
pub(crate) fn binds_filesystem_root(path: &Utf8Path) -> bool {
    use std::path::Component;
    let mut depth: i64 = 0;
    for c in path.as_std_path().components() {
        match c {
            Component::RootDir | Component::CurDir => {}
            Component::ParentDir => {
                if depth > 0 {
                    depth -= 1;
                }
            }
            Component::Normal(_) => {
                depth += 1;
            }
            Component::Prefix(_) => {
                // Windows-only; ignore on Linux.
            }
        }
    }
    depth == 0
}
