//! Apply engine: execute a `Plan` against the host.
//!
//! Design spec: Part 3 (`apply.rs`) + Part 8 ("Execution order in
//! `apply()`", `apply.lock` semantics).
//!
//! Layout:
//! - [`apply`](orchestrator::apply) is the entry point. It acquires
//!   the file lock, sorts the plan into the canonical phase order
//!   documented in Part 8, dispatches each `Action` to its
//!   `execute_*` handler, then issues a single `daemon_reload` and
//!   releases the lock.
//! - All systemd, auth, and tarball operations are taken via trait
//!   objects (`&dyn Systemd`, `&dyn TokenSource`) and the [`Tarball`]
//!   trait so tests can inject in-memory mocks.
//! - [`guard_home_dir_rmrf`] refuses to delete anything outside
//!   `<state_dir>/<trust_zone>/ghars-<runner-name>` — defends against
//!   a corrupted trust_zone root (the `prefix` parameter is sourced
//!   from `paths.trust_zone_home(&identity.trust_zone)` at the call
//!   site) causing apply to recursively remove `/`, the prefix
//!   itself, or a path outside the prefix.
//! - `verify_runner_netns` post-start check — `readlink
//!   /proc/PID/ns/net` must differ from `readlink /proc/1/ns/net` when
//!   `spec.network.is_some()`. If they match the runner has fallen back
//!   to the host netns and the action aborts with `GharsError::Apply`.

mod audit;
mod gc;
mod lock;
mod netns;
mod orchestrator;
mod outcome;
mod phases;
mod pools;
mod rmrf;
mod runners;
mod shell;
mod tarball;
mod undo;
mod writes;

#[cfg(test)]
mod tests;

pub use lock::{ApplyLock, acquire_lock, pid_is_alive};
pub use orchestrator::{apply, execute};
pub use outcome::{ApplyOptions, ApplyOutcome, ApplyResult};
pub use rmrf::guard_home_dir_rmrf;
pub use shell::{ConfigShell, ConfigShellCtx, RealConfigShell};
pub use tarball::{RealTarball, Tarball};
pub use undo::{AuthRegistry, Deps, UndoLog, UndoStep, undo};
pub use writes::_spec_runner_home;
