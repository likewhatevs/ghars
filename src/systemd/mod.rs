//! Systemd adapter: D-Bus trait + `zbus` blocking-API implementation,
//! plus unit-text and drop-in generation.
//!
//! Design spec: Part 3 (`systemd.rs`) + Part 9 (template + drop-ins) +
//! Part 9b (unified per-pool cache service) + Part 9c (netns +
//! ghars-net@.service template + nft rule generation) + Part 9d
//! (proxy drop-in) + Part 9e (hooks drop-in).
//!
//! Boundaries:
//! - The `Systemd` trait is the mock seam for tests.
//! - `DbusSystemd` calls the `org.freedesktop.systemd1.Manager`
//!   interface over the system bus via `zbus::blocking`.
//! - Unit-text + drop-in + nft rule rendering are pure functions; no
//!   D-Bus, no filesystem.
//! - `validate_drop_in` enforces the reset-on-empty rule on every
//!   generated drop-in body before it leaves the renderer.
//!
//! `ghars-net@.service` and `ghars-cache@.service` template bodies are
//! emitted as static helpers because they don't vary per-runner; only
//! their per-instance drop-ins do.
//!
//! Module layout:
//! - [`dbus`]: `Systemd` trait, `DbusSystemd`, `UnitListEntry`, decode
//!   helpers, the reset-on-empty validator (`validate_drop_in`).
//! - [`units`]: `RenderedUnit`, template-text functions
//!   (`runner_template_text` / `cache_template_text` /
//!   `netns_template_text`), `render_runner_unit`, every `render_*`
//!   helper, `render_cache_drop_in`, and `check_identity_field`.
//! - [`nft`]: `NftRules`, `render_nft_rules`, and the host-/ns-side nft
//!   rule renderers.

mod dbus;
mod nft;
mod templates;
mod units;

pub use dbus::{DbusSystemd, OwnedObjectPath, Systemd, UnitListEntry, validate_drop_in};
pub use nft::{NftRules, render_nft_rules};
pub use templates::{cache_template_text, netns_template_text, runner_template_text};
pub use units::{RENDERER_SCHEMA, RenderedUnit, render_cache_drop_in, render_runner_unit};

// `check_identity_field` is `pub(crate)` in `units`; re-export at the
// matching visibility so existing call sites at
// `crate::systemd::check_identity_field` (cli.rs / plan.rs) continue to
// resolve after the split.
pub(crate) use units::check_identity_field;

// `render_runner_env_file` / `render_runner_path_file` are pure pre-
// renderers for the bin.X.Y.Z/.env|.path files. The `units` submodule
// is private to `crate::systemd`, so these helpers are not reachable
// at `crate::systemd::units::...`. Production code consumes the bytes
// via `RenderedUnit { env_file, path_file }` returned from
// `render_runner_unit` (which calls them as intra-module helpers);
// `RenderedUnit` is re-exported publicly above. The only callers at
// `crate::systemd::...` live in `src/apply/tests/` and rebuild
// canonical plan bytes for assertion. Gate the re-export on
// `cfg(test)` so non-test builds don't emit an unused-import warning.
#[cfg(test)]
pub(crate) use units::{render_runner_env_file, render_runner_path_file};
