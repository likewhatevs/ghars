//! [`Tarball`] trait + [`RealTarball`] production implementation.

use camino::{Utf8Path, Utf8PathBuf};

use crate::Result;
use crate::error::GharsError;
use crate::extract::install_runner_binary;
use crate::extract::{download_and_verify, verify_local_tarball};

/// Tarball provider seam. Production wires a [`RealTarball`] that
/// shells out to `extract::download_and_verify` /
/// `extract::install_runner_binary`. Tests inject a fake that records
/// calls without touching the network or filesystem.
pub trait Tarball {
    /// Ensure a tarball exists at `dest_path` whose SHA256 matches
    /// `expected_sha256`, downloading from `url` only when necessary.
    ///
    /// # Errors
    ///
    /// Returns `GharsError::Tarball` / `GharsError::Sha256Mismatch` /
    /// `GharsError::Io` per the underlying extract.rs contract.
    fn fetch_or_verify(&self, url: &str, dest_path: &Utf8Path, expected_sha256: &str)
    -> Result<()>;

    /// Verify a pre-downloaded local tarball is still safe to use
    /// (regular file, not a symlink). Mirrors `extract::verify_local_tarball`.
    ///
    /// # Errors
    ///
    /// `GharsError::Tarball` if the file is missing, a symlink, or no
    /// longer regular.
    fn verify_local(&self, path: &Utf8Path) -> Result<()>;

    /// Extract `tarball_path` into `<runner_home>/bin.<version>/`
    /// (root-owned, atomic via staging). Returns the final
    /// `bin.<version>` directory path.
    ///
    /// # Errors
    ///
    /// Returns the underlying `GharsError::Tarball` / `GharsError::Io`
    /// from `extract::install_runner_binary`.
    fn install_binary(
        &self,
        tarball_path: &Utf8Path,
        state_dir: &Utf8Path,
        runner_home: &Utf8Path,
        runner_name: &str,
        version: &str,
    ) -> Result<Utf8PathBuf>;

    /// Prune old `bin.X.Y.Z/` trees under `runner_home` after a
    /// successful install, retaining the `keep_versions` most-recent
    /// by mtime plus the directory the `bin` symlink resolves to
    /// (Part 9f retention). Best-effort: returns `Ok(prune_count)`
    /// even if individual removals fail (the operator's next apply
    /// retries).
    ///
    /// # Errors
    ///
    /// `GharsError::Validation` if `keep_versions == 0`.
    /// `GharsError::Io` if `read_dir(runner_home)` fails.
    fn prune_old_versions(&self, runner_home: &Utf8Path, keep_versions: u32) -> Result<usize>;
}

/// Production tarball provider. Wraps the public functions in
/// [`crate::extract`] verbatim.
#[derive(Debug, Default)]
pub struct RealTarball;

impl Tarball for RealTarball {
    fn fetch_or_verify(
        &self,
        url: &str,
        dest_path: &Utf8Path,
        expected_sha256: &str,
    ) -> Result<()> {
        // On SHA256 mismatch the destination is deleted; if the file is
        // already present and correct, no download. download_and_verify
        // already implements both paths.
        download_and_verify(
            url,
            dest_path,
            expected_sha256,
            std::time::Duration::from_secs(300),
        )
    }

    fn verify_local(&self, path: &Utf8Path) -> Result<()> {
        verify_local_tarball(path)
    }

    fn install_binary(
        &self,
        tarball_path: &Utf8Path,
        state_dir: &Utf8Path,
        runner_home: &Utf8Path,
        runner_name: &str,
        version: &str,
    ) -> Result<Utf8PathBuf> {
        install_runner_binary(tarball_path, state_dir, runner_home, runner_name, version)
    }

    fn prune_old_versions(&self, runner_home: &Utf8Path, keep_versions: u32) -> Result<usize> {
        crate::extract::prune_old_bin_versions(runner_home, keep_versions)
    }
}

pub(super) fn spawn_err(prog: &str, e: &std::io::Error) -> GharsError {
    GharsError::Io(std::io::Error::new(e.kind(), format!("spawn {prog}: {e}")))
}
