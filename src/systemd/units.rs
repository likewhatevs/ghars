//! Unit-text and drop-in generation for systemd unit files.
//!
//! Splits from the (previously monolithic) `systemd.rs` module:
//! - Static template bodies: `runner_template_text`,
//!   `netns_template_text`, `cache_template_text`.
//! - Per-runner drop-in renderer: [`render_runner_unit`] +
//!   [`RenderedUnit`].
//! - Per-pool cache drop-in renderer: [`render_cache_drop_in`].
//! - Defense-in-depth identity field validator:
//!   [`check_identity_field`].
//! - Internal `HardeningProfile` and `render_*` helpers
//!   (memory, hardening, `cache_pool`, `resolv_bind`, network, numa,
//!   proxy, hooks, lognamespace).
//!
//! All renderers are pure functions: no D-Bus, no filesystem.

use std::collections::BTreeMap;
use std::fmt::Write;

use camino::Utf8Path;
use ipnet::IpNet;

use crate::config::{
    CacheKind, EffectiveCacheBinding, EffectiveRunnerSpec, EtcBindStyle, Hardening, NetworkMode,
};
use crate::path_util::binds_filesystem_root;
use crate::{GharsError, Result};

use super::dbus::validate_drop_in;
use super::templates::runner_template_text;

// --- Hardening profile ---------------------------------------------------

/// Hardening defaults — match the Python tool's profile (see Part 9,
/// the doc-comments on `Hardening` in `config.rs`). `None` on a
/// `Hardening` field means "inherit"; the renderer translates each
/// option to a concrete bool / list at render time.
//
// One bool per systemd directive is the natural shape — bitflags would
// obscure the per-directive label. Pedantic clippy suggests refactoring
// >3 bools; here the labels are load-bearing for readability.
#[allow(clippy::struct_excessive_bools)]
struct HardeningProfile {
    kvm: bool,
    restrict_realtime: bool,
    protect_control_groups: bool,
    restrict_suid_sgid: bool,
    private_devices: bool,
    private_ipc: bool,
}

impl HardeningProfile {
    fn from(h: &Hardening) -> Self {
        Self {
            kvm: h.kvm.unwrap_or(true),
            restrict_realtime: h.restrict_realtime.unwrap_or(false),
            protect_control_groups: h.protect_control_groups.unwrap_or(false),
            restrict_suid_sgid: h.restrict_suid_sgid.unwrap_or(true),
            private_devices: h.private_devices.unwrap_or(true),
            private_ipc: h.private_ipc.unwrap_or(true),
        }
    }
}

fn yes_no(b: bool) -> &'static str {
    if b { "yes" } else { "no" }
}

// --- Rendered output ----------------------------------------------------

/// Result of `render_runner_unit`: the canonical template body plus
/// the per-instance drop-ins keyed by basename (e.g.
/// `00-ghars.conf`), plus any warnings the renderer wants to surface
/// to the operator (rendered into plan output).
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct RenderedUnit {
    /// Canonical template body — installed once at
    /// `/etc/systemd/system/ghars-runner@.service`.
    pub template: String,
    /// Drop-in basename → contents. Installed under the per-instance
    /// drop-in directory (`ghars-runner@NAME.service.d/`).
    pub drop_ins: BTreeMap<String, String>,
    /// Body of the runner's `.env` file (`<bin_dir>/.env`).
    /// `Runner.Listener::LoadAndSetEnv` reads this ONCE at runner-process
    /// start and sets each `KEY=VALUE` via
    /// `Environment.SetEnvironmentVariable`; worker / workflow-step
    /// subprocesses inherit through fork+exec. Distinct from systemd
    /// `Environment=` directives, which bind to the systemd unit
    /// process and are inherited the same way once
    /// Runner.Listener spawns — `.env` keys ride a separate
    /// `LoadAndSetEnv` pathway.
    pub env_file: String,
    /// Body of the runner's `.path` file (`<bin_dir>/.path`).
    /// `runsvc.sh` runs `export PATH=$(cat .path)` ONCE at script
    /// start; inherited across exec by every subprocess. Single line,
    /// newline-terminated.
    pub path_file: String,
    /// Render-time advisories surfaced to the plan engine. The plan
    /// engine concatenates these into `Plan.warnings` so apply prints
    /// them before executing. Examples: "kvm=false drops /dev/kvm rw
    /// — workflows that need KVM will fail".
    pub warnings: Vec<String>,
}

/// Monotonic schema number for the renderer output surface. Bumped
/// when any byte of any drop-in, template, `env_file`, or `path_file`
/// emitted by `render_*` could change across upgrades for the same
/// `EffectiveRunnerSpec` input — even if the operator's TOML is
/// byte-identical.
///
/// Fed into `spec_hash` and `cache_pool_hash` via dedicated
/// `renderer_schema` fields on `EffectiveRunnerSpec` and
/// `EffectiveCacheBinding` so the on-disk `X-Ghars-Spec-Hash`
/// annotation captures the schema. A ghars binary upgrade that
/// changes renderer behavior MUST bump this number; otherwise plan
/// emits `NoOp` on every runner and operators must `rm -rf` drop-in
/// dirs to force convergence (the bug this constant exists to
/// prevent).
///
/// Cosmetic refactors (comment edits, internal helper renames,
/// formatting) do NOT bump this number — only behavior changes that
/// would alter the bytes a downstream consumer (systemd, runsvc.sh,
/// Runner.Listener) reads from the rendered files.
///
/// Decision rule for contributors: if your change requires re-
/// accepting any `.snap` under `tests/snapshots/python_parity_unit_*`
/// AND the byte change reflects observable systemd / runner behavior
/// (not pure formatting or comment shuffling), bump this constant.
/// If unsure, bump — false positives (an unnecessary bump) cost one
/// cycle of in-place rewrites per managed runner on the next apply;
/// false negatives (a missed bump) leave operators stranded on stale
/// drop-ins requiring manual `rm -rf` to force convergence (the bug
/// this constant exists to prevent).
pub const RENDERER_SCHEMA: u32 = 4;


// --- Runner unit + drop-ins renderer (Part 9 / 9d / 9e) ------------------

/// Render the canonical runner unit template + all applicable
/// drop-ins for an effective runner spec.
///
/// Drop-ins emitted (ranges per Part 9):
/// - `00-ghars.conf` — identity annotations (always)
/// - `10-memory.conf` — `MemoryMax=` (when set)
/// - `15-resolv.conf` — `/etc/resolv.conf` bind source (always; switches
///   between host's resolv.conf and the netns-private file in
///   `/run/ghars/netns-resolv/<name>` based on the runner's network mode)
/// - `20-hardening.conf` — per-field hardening overrides
/// - `30-cache-pool.conf` — ccache/sccache pool bindings (when caches non-empty)
/// - `40-network.conf` — netns binding + cgroup-BPF directives in
///   Netns mode; cgroup-BPF directives only (no `NetworkNamespacePath=`,
///   no `Requires=ghars-net@`) in Open mode when any of
///   `ip_allow` / `ip_deny` / `restrict_address_families` is
///   non-empty; skipped entirely when Open mode has none of those
///   set
/// - `50-numa.conf` — `AllowedCPUs=` / `AllowedMemoryNodes=` (when set)
/// - `60-proxy.conf` — proxy env + CA-trust env (when proxy resolved)
/// - `70-hooks.conf` — pre/post-job hook env + `BindReadOnlyPaths` (when hooks resolved)
/// - `80-lognamespace.conf` — `LogNamespace=ghars-NAME` (always)
///
/// # Errors
///
/// Returns `GharsError::Validation` when:
/// - `render_identity` (via [`check_identity_field`]) finds a `\n`,
///   `\r`, `\0`, or other control character in any interpolated
///   X-Ghars-* field — defense-in-depth against unit-text injection.
///   The error message names the offending field and the
///   character class.
/// - The reset-on-empty validator finds any generated drop-in body
///   about to emit a list-typed directive with a bare `=`. Such an
///   output is a generator bug; the validator is a safety net.
pub fn render_runner_unit(spec: &EffectiveRunnerSpec) -> Result<RenderedUnit> {
    let mut drop_ins: BTreeMap<String, String> = BTreeMap::new();
    let mut warnings: Vec<String> = Vec::new();

    drop_ins.insert("00-ghars.conf".into(), render_identity(spec)?);

    if let Some(body) = render_memory(spec)? {
        drop_ins.insert("10-memory.conf".into(), body);
    }

    // 15-resolv.conf — always present. Binds /etc/resolv.conf into the
    // runner's mount namespace from the right source for the runner's
    // network mode. Open mode binds the host's /etc/resolv.conf; Netns
    // mode binds /run/ghars/netns-resolv/<name> (written by
    // `_netns-setup` from the operator's DnsMode). The template's
    // BindReadOnlyPaths intentionally OMITS /etc/resolv.conf because
    // systemd's mount-list dedup keeps the FIRST same-destination entry
    // (per src/core/namespace.c:drop_duplicates), so a drop-in cannot
    // override the template's source. Splitting it out into its own
    // drop-in is the only correct way to swap sources per runner.
    drop_ins.insert("15-resolv.conf".into(), render_resolv_bind(spec));

    if let Some(body) = render_hardening(spec, &mut warnings)? {
        drop_ins.insert("20-hardening.conf".into(), body);
    }

    if let Some(body) = render_cache_pool(spec)? {
        drop_ins.insert("30-cache-pool.conf".into(), body);
    }

    if let Some(body) = render_network(spec)? {
        drop_ins.insert("40-network.conf".into(), body);
    }

    if let Some(body) = render_numa(spec)? {
        drop_ins.insert("50-numa.conf".into(), body);
    }

    if let Some(body) = render_proxy(spec)? {
        drop_ins.insert("60-proxy.conf".into(), body);
    }

    if let Some(body) = render_hooks(spec)? {
        drop_ins.insert("70-hooks.conf".into(), body);
    }

    drop_ins.insert("80-lognamespace.conf".into(), render_lognamespace(spec));

    // Reset-on-empty validator — applied to EVERY generated drop-in.
    for (name, body) in &drop_ins {
        validate_drop_in(name, body)?;
    }

    let env_file = render_runner_env_file(spec)?;
    let path_file = render_runner_path_file(spec)?;
    Ok(RenderedUnit {
        template: runner_template_text(),
        drop_ins,
        env_file,
        path_file,
        warnings,
    })
}

/// Body of the runner's `.env` file. actions/runner's
/// `Runner.Listener` calls `LoadAndSetEnv` ONCE at process start
/// (`src/Runner.Listener/Program.cs` Main), reads `.env`, and sets each
/// `KEY=VALUE` into the process environment via
/// `Environment.SetEnvironmentVariable`. Worker processes that
/// `Runner.Listener` forks inherit those env vars across exec, so
/// workflow steps see them.
///
/// Distinct from the systemd `Environment=` directives in
/// `00-ghars.conf` / `30-cache-pool.conf`: those bind to the systemd
/// unit's process tree and are present in the runner process's
/// environment when `Runner.Listener` starts. `.env` adds the env vars
/// that need to land specifically in workflow steps via
/// `LoadAndSetEnv`'s explicit propagation path (some keys, like
/// `CCACHE_DIR`, ride both layers for redundancy). The runner unit's
/// next stop+start picks up `.env` changes — see
/// `render_identity` (LAYER 1) and this function (LAYER 2).
///
/// Output is deterministic: framework lines are fixed-order
/// (LANG → trust_zone-derived → per-cache loop). The per-cache loop
/// iterates `spec.caches` in source order; `lower_to_effective` sorts
/// `caches` by name before the spec reaches this renderer, so two
/// runners with the same caches produce byte-identical `.env` content.
pub(crate) fn render_runner_env_file(spec: &EffectiveRunnerSpec) -> Result<String> {
    let check = |field: &str, value: &str| -> Result<()> {
        check_identity_field(field, value)
            .map_err(|e| crate::error::prepend_validation_scope("render_runner_env_file", e))
    };
    check("trust_zone", &spec.trust_zone)?;
    for binding in &spec.caches {
        check("caches[].name", &binding.name)?;
        check("caches[].size", &binding.size)?;
    }

    let mut s = String::new();
    s.push_str("LANG=C.UTF-8\n");
    // CCACHE_DIR is gated on the runner having at least one ccache-
    // kind binding. The .ccache dir at this path is created in
    // execute_create_runner ONLY when the same binding gate is
    // satisfied (see `has_ccache` check in apply/runners.rs). The
    // two must stay symmetric: if the runner has no ccache binding,
    // the dir is not created AND the env var is not emitted. Otherwise
    // the unconditional ccache wrappers in PATH (units.rs PATH file)
    // would intercept `gcc` / `cc` calls and try to write to a non-
    // existent dir whose parent (/var/lib/ghars/<TRUST_ZONE>/) is
    // 0o711 root-owned — the DynamicUser worker cannot mkdir it,
    // ccache falls back to its XDG default (HOME/.ccache) which lands
    // in runner_home (per-runner, owned by the DynamicUser, mode
    // 0o777 at runtime). Per-runner ephemeral cache is correct for
    // no-ccache-binding runners; trust-zone-shared cache is the
    // operator opt-in via [[runner]].caches.
    let has_ccache = spec
        .caches
        .iter()
        .any(|b| b.kinds.contains(&CacheKind::Ccache));
    if has_ccache {
        let _ = writeln!(s, "CCACHE_DIR=/var/lib/ghars/{}/.ccache", spec.trust_zone);
    }
    let _ = writeln!(s, "KTSTR_LOCK_DIR=/var/lib/ghars/{}/.ktstr", spec.trust_zone);
    let _ = writeln!(s, "KTSTR_CACHE_DIR=/var/lib/ghars/{}/.ktstr", spec.trust_zone);
    for binding in &spec.caches {
        if binding.kinds.contains(&CacheKind::Ccache) {
            let _ = writeln!(s, "CCACHE_MAXSIZE={}", binding.size);
        }
        if binding.kinds.contains(&CacheKind::Sccache) {
            let _ = writeln!(
                s,
                "SCCACHE_SERVER_UDS=/run/ghars/cache-{}.sock",
                binding.name
            );
            s.push_str("SCCACHE_NO_DAEMON=1\n");
            let _ = writeln!(s, "SCCACHE_CACHE_SIZE={}", binding.size);
            let _ = writeln!(
                s,
                "SCCACHE_DIR=/var/cache/ghars/pools/{}/sccache",
                binding.name
            );
        }
    }
    // LAYER 3: operator-declared env vars (BTreeMap alphabetical
    // iteration → deterministic .env bytes regardless of operator's
    // TOML key order). Appended AFTER framework keys so existing
    // runners with empty `[runner.environment].vars` produce
    // byte-identical .env (no spurious in-place rewrite on the
    // .env/.path-elevation deploy). Operator keys colliding with
    // framework keys are
    // rejected at config-load via the deny-list in
    // crate::validators::validate_environment_spec, so values
    // reaching here are validation-clean.
    //
    // Defense-in-depth re-validation: check the value via
    // check_identity_field at render time too — config-load is the
    // primary gate but direct construct sites (test fixtures) might
    // bypass the load path.
    for (key, value) in &spec.environment.vars {
        check("environment.vars[].key", key)?;
        check("environment.vars[].value", value)?;
        let _ = writeln!(s, "{key}={value}");
    }
    Ok(s)
}

/// Body of the runner's `.path` file. `runsvc.sh` runs at runner-
/// process start (the unit's `ExecStart=`) and executes
/// `export PATH=$(cat .path)` once per process — `Runner.Listener`
/// and every worker process inherit this PATH. Subsequent runs of
/// upstream `env.sh` (only invoked at runner re-config time, not at
/// every job) would `echo $PATH >.path` and overwrite this file with
/// the runner process's `$PATH`, which would NOT include the ccache
/// wrappers or `.cargo/bin`. ghars writes this file pre-emptively so
/// workflow steps get the correct PATH from the first job onwards.
///
/// The framework prefix `/usr/lib64/ccache:/usr/lib/ccache` must come
/// FIRST so that bare `gcc` / `cc` invocations resolve to the ccache
/// wrappers (otherwise ccache misses 100% of compile calls). The
/// per-runner `.cargo/bin` segment is included so cargo-installed
/// binaries land on PATH for workflow steps. System path tail comes
/// last in the standard sbin-before-bin order.
pub(crate) fn render_runner_path_file(spec: &EffectiveRunnerSpec) -> Result<String> {
    let check = |field: &str, value: &str| -> Result<()> {
        check_identity_field(field, value)
            .map_err(|e| crate::error::prepend_validation_scope("render_runner_path_file", e))
    };
    check("trust_zone", &spec.trust_zone)?;
    check("name", &spec.name)?;
    for p in &spec.environment.path_prepend {
        check("environment.path_prepend[]", p.as_str())?;
    }
    for p in &spec.environment.path_append {
        check("environment.path_append[]", p.as_str())?;
    }
    Ok(format!(
        "{path}\n",
        path = compose_runner_path(spec)
    ))
}

/// Compose the runner's PATH string from framework segments and
/// operator additions. OPTION C layering:
///   `ccache_wrappers` → operator `path_prepend` → .cargo/bin →
///   `system_tail` → operator `path_append`
/// ccache wrappers stay at position 0 unconditionally — operator
/// `path_prepend` cannot shadow `gcc` / `cc` and break the compile
/// cache (which would miss 100% if ccache wrappers were not first
/// in PATH). Shared between `render_runner_path_file` and
/// `render_identity`'s `Environment=PATH=` line so both sites emit
/// the identical PATH string (eliminates the LAYER 1/2 PATH drift
/// class).
pub(crate) fn compose_runner_path(spec: &EffectiveRunnerSpec) -> String {
    let mut segments: Vec<String> = Vec::with_capacity(
        2 + spec.environment.path_prepend.len() + 1 + 6 + spec.environment.path_append.len(),
    );
    // ccache wrappers ALWAYS first.
    segments.push("/usr/lib64/ccache".into());
    segments.push("/usr/lib/ccache".into());
    // Operator path_prepend lands BETWEEN ccache and .cargo/bin so
    // operator paths cannot shadow the ccache wrappers.
    for p in &spec.environment.path_prepend {
        segments.push(p.as_str().into());
    }
    // Per-runner .cargo/bin.
    segments.push(format!(
        "/var/lib/ghars/{tz}/ghars-{name}/.cargo/bin",
        tz = spec.trust_zone,
        name = spec.name
    ));
    // System tail (sbin-before-bin order).
    segments.push("/usr/local/sbin".into());
    segments.push("/usr/local/bin".into());
    segments.push("/usr/sbin".into());
    segments.push("/usr/bin".into());
    segments.push("/sbin".into());
    segments.push("/bin".into());
    // Operator path_append lands AFTER system tail (typical
    // "fallback paths" semantics).
    for p in &spec.environment.path_append {
        segments.push(p.as_str().into());
    }
    segments.join(":")
}

/// Defense-in-depth: reject any value about to be interpolated
/// into a `00-ghars.conf` line that contains characters which would
/// break out of the `Key=Value` boundary or corrupt the systemd unit
/// parser. `\n` / `\r` would inject a new directive line; `\0` is a
/// shell / parser hazard; other control chars produce undefined
/// behavior in the X-Ghars-* annotation parser at
/// `state::extract_x_ghars`.
///
/// Called from many render and validation sites (none privileged):
/// - The `render_*` helpers in this file (memory, hardening, cache,
///   network, numa, proxy, hooks, identity) gate every interpolated
///   field before bytes hit disk.
/// - `cli::validate_identity_fields` — config-load gate so the
///   operator sees the offending block name (`runner "NAME"` /
///   `cache_pool "NAME"`) before the planner runs.
/// - `plan::plan_from` — defense-in-depth on the synthesized
///   `config_source` value.
///
/// The error message itself is bare (no caller-site prefix). The
/// `render_identity` caller (this file, just below) wraps with
/// `"render_identity:"` so plan-time render errors name the
/// rejecting function. The `cli::load::validate_identity_fields`
/// caller wraps with the offending block name (`runner "NAME":` /
/// `cache_pool "NAME":`); the `plan::compute` caller propagates the
/// bare error (`config_source` is composed from `paths.config_dir`,
/// no operator-meaningful scope to prepend). Hardcoding
/// `"render_identity:"` here would mislead
/// operators when the rejection actually fires at config-load time.
pub(crate) fn check_identity_field(field: &str, value: &str) -> Result<()> {
    if let Some(bad) = value
        .chars()
        .find(|c| *c == '\n' || *c == '\r' || *c == '\0' || c.is_control())
    {
        let class = if bad == '\n' {
            "newline"
        } else if bad == '\r' {
            "carriage return"
        } else if bad == '\0' {
            "NUL byte"
        } else {
            "control character"
        };
        return Err(GharsError::Validation(
            format!(
                "field {field:?} contains forbidden {class}; \
                 X-Ghars-* annotations must be single-line, control-free"
            ),
            "fix the offending value upstream (likely a config edit added \
             a stray newline or terminal escape)"
                .into(),
        ));
    }
    Ok(())
}

/// Defense-in-depth: reject Hardening list-typed entries whose raw form
/// differs from the trimmed form (i.e. surrounding whitespace).
/// `render_hardening` emits these entries via `Vec::join(" ")` verbatim
/// into systemd directive bodies (`RestrictAddressFamilies=`,
/// `SystemCallFilter=`, `CapabilityBoundingSet=`, `BindReadOnlyPaths=`),
/// so a whitespace-padded token would produce different on-disk bytes
/// (and a different `spec_hash`) from the equivalent unpadded form,
/// triggering a spurious in-place `UpdateRunner` cascade across
/// cosmetically-equivalent TOML.
///
/// Coverage role per field:
/// - `extra_capabilities`, `extra_syscalls`: `validators::validate_extra_capabilities`
///   / `validate_extra_syscalls` already enforce `raw != trimmed` at
///   config-load; this renderer-side check is defense-in-depth for
///   direct-construct callers that build `Hardening { extra_syscalls:
///   vec!["  read  ".into()], ... }` programmatically and skip
///   `cli::load`.
/// - `restrict_address_families`: `validators::validate_restrict_address_families`
///   uses the anchored regex `AF_FAMILY_RE = ^AF_[A-Z0-9_]+$` which
///   implicitly rejects whitespace-padded entries via the shape check;
///   the renderer-side check is the explicit safety net for
///   direct-construct callers.
/// - `bind_readonly_paths`: no config-load validator exists; the
///   renderer-side check is the primary whitespace defense.
/// - `extra_bind_paths`: `validators::validate_extra_bind_paths` catches
///   leading whitespace via `starts_with('/')` but lets trailing
///   whitespace through; the renderer-side check closes the trailing
///   gap.
///
/// Mirrors `check_identity_field`'s renderer-side control-char
/// rejection above.
fn check_no_whitespace_padding(field: &str, value: &str) -> Result<()> {
    if value != value.trim() {
        return Err(GharsError::Validation(
            format!(
                "field {field:?} entry {value:?} has surrounding whitespace; \
                 hardening list entries must be unpadded — whitespace-padded \
                 tokens render to different drop-in bytes than the equivalent \
                 unpadded form and trigger a spurious in-place UpdateRunner \
                 cascade across cosmetically-equivalent specs (the next \
                 `ghars apply` would restart your runners even though \
                 systemd's runtime effect is identical to the unpadded form)"
            ),
            "remove the leading/trailing whitespace from the token".into(),
        ));
    }
    Ok(())
}

/// SEC-12 defense gate for `BindReadOnlyPaths=` emission. Rejects
/// paths that would produce a malformed or sandbox-defeating
/// directive:
///
/// 1. Empty (`""`) — misclassification guard; `binds_filesystem_root`
///    would return true for the empty path, but the operator's actual
///    mistake is an empty entry.
/// 2. Non-absolute — systemd rejects relative paths at unit-load;
///    surface the error at plan time instead.
/// 3. Embedded whitespace — systemd whitespace-splits
///    `BindReadOnlyPaths` entries, so a space would silently bind
///    additional host paths.
/// 4. Colon (`:`) — systemd parses `SOURCE:DESTINATION[:OPTIONS]`,
///    so a colon remaps the bind target to an unintended sandbox
///    path.
/// 5. Component-walk root equivalence (`/`, `/foo/..`, `//`, `/.`) —
///    binding root overlays the entire host filesystem on top of the
///    runner template's isolation layer (`TemporaryFileSystem=/:ro` +
///    the curated `BindReadOnlyPaths` set).
///
/// `label` is the FULL operator-facing identifier the caller wants
/// surfaced in the error message (e.g.
/// `"hardening.bind_readonly_paths[]"`). The helper does not impose
/// a scope prefix; each call site owns its own namespace string so
/// the message names the operator's TOML path, not a fixed scope.
///
/// FIRST/ONLY root-equivalence gate for Hardening bind paths and
/// `proxy.ca_certs[].path` today. `validate_extra_bind_paths`
/// checks empty / non-absolute / SEC-01 denylist at config-load but
/// has no root-equivalence, whitespace, or colon check;
/// `bind_readonly_paths` has no config-load validator at all;
/// `proxy.ca_certs[].path` has no config-load path-shape validator.
/// `render_hooks` has a parallel root-parent check (defense-in-depth
/// on top of `validators::validate_hook_script`'s config-load
/// root-parent rejection). A config-load companion for any of
/// these would convert the corresponding gate into defense-in-depth.
fn check_no_root_bind(label: &str, path: &Utf8Path) -> Result<()> {
    if path.as_str().is_empty() {
        return Err(GharsError::Validation(
            format!("{label} entry is empty"),
            "remove the empty path from the list, or replace it with an \
             absolute path (e.g. /etc/pki/ca-trust/source/anchors)"
                .into(),
        ));
    }
    if !path.as_std_path().is_absolute() {
        return Err(GharsError::Validation(
            format!("{label} entry `{path}` is not an absolute path"),
            "use an absolute path (e.g. /etc/pki/ca-trust/source/anchors)".into(),
        ));
    }
    if path.as_str().chars().any(char::is_whitespace) {
        return Err(GharsError::Validation(
            format!(
                "{label} entry `{path}` contains whitespace; systemd \
                 whitespace-splits BindReadOnlyPaths entries, so an embedded \
                 space would silently bind additional host paths into the \
                 runner sandbox"
            ),
            "remove whitespace from the path; paths with spaces cannot be \
             expressed in BindReadOnlyPaths without quoting, which systemd \
             does not support for this directive"
                .into(),
        ));
    }
    if path.as_str().contains(':') {
        return Err(GharsError::Validation(
            format!(
                "{label} entry `{path}` contains `:` which systemd parses as a \
                 SOURCE:DESTINATION separator in BindReadOnlyPaths directives; \
                 the rendered bind would map a different source onto an \
                 unintended destination inside the runner sandbox"
            ),
            "remove the colon from the path; if you need a SOURCE:DESTINATION \
             mapping, use a 99-*.conf operator drop-in via systemctl edit"
                .into(),
        ));
    }
    if binds_filesystem_root(path) {
        return Err(GharsError::Validation(
            format!(
                "{label} entry `{path}` resolves to filesystem root \
                 (SEC-12); BindReadOnlyPaths=/ would expose the entire host \
                 into the runner sandbox"
            ),
            "use a narrower path (e.g. /etc/pki/ca-trust/source/anchors) \
             instead of the filesystem root; if you genuinely need whole-host \
             exposure, use a 99-*.conf operator drop-in via systemctl edit"
                .into(),
        ));
    }
    Ok(())
}

/// Validate every interpolated field in `spec` against the identity
/// regex BEFORE the renderer writes any bytes. Fail-fast so an
/// upstream caller's re-render yields the same error each time and
/// never produces a partially-written buffer.
///
/// `runner_tarball` is hashed (sha256 of the path) before emission so
/// the rendered value cannot carry control chars — the path string
/// itself never appears in the unit, so no check is needed for it.
fn validate_identity_fields(spec: &EffectiveRunnerSpec) -> Result<()> {
    let check = |field: &str, value: &str| -> Result<()> {
        check_identity_field(field, value)
            .map_err(|e| crate::error::prepend_validation_scope("render_identity", e))
    };
    check("spec_hash", &spec.spec_hash)?;
    check("name", &spec.name)?;
    check("url", &spec.url)?;
    check("auth_name", &spec.auth_name)?;
    for label in &spec.labels {
        check("labels[]", label)?;
    }
    for binding in &spec.caches {
        check("caches[].name", &binding.name)?;
    }
    check("config_source", &spec.config_source)?;
    if let Some(v) = spec.runner_version.as_deref() {
        check("runner_version", v)?;
    }
    if let Some(sha) = spec.runner_sha256.as_deref() {
        check("runner_sha256", sha)?;
    }
    check("trust_zone", &spec.trust_zone)?;
    Ok(())
}

fn render_identity(spec: &EffectiveRunnerSpec) -> Result<String> {
    validate_identity_fields(spec)?;

    let mut s = String::new();
    s.push_str("[Unit]\n");
    let _ = writeln!(s, "X-Ghars-Spec-Hash={}", spec.spec_hash);
    let _ = writeln!(s, "X-Ghars-Runner-Name={}", spec.name);
    let _ = writeln!(s, "X-Ghars-Runner-Url={}", spec.url);
    let _ = writeln!(s, "X-Ghars-Auth-Name={}", spec.auth_name);
    // Emit Labels and Arch as annotations so the plan engine can
    // reconstruct the recreate-bound subset of an already-applied
    // EffectiveRunnerSpec from the on-disk unit text. Without these,
    // a labels-only or arch-only edit falls through to the
    // `uncovered` in-place arm in `plan_from` — the apply path
    // would still rewrite the runner unit on the spec_hash diff,
    // but it would do so without the typed recreate reason that
    // GitHub-side registration needs (labels/arch are bound to the
    // registration token), so the runner would land in production
    // with the OLD label/arch metadata still active on GitHub's
    // side. Stage 1 detection on these annotations is what flips
    // the change to a true recreate so the runner re-registers.
    // Comma-joined labels mirrors the existing X-Ghars-Caches format.
    //
    // Labels arrive pre-sorted by `merge_defaults` (set semantics —
    // GitHub matches workflow `runs-on:` against the registered label
    // set order-independently). The defensive sort here mirrors the
    // caches comment below: any future caller that builds an
    // `EffectiveRunnerSpec` directly bypasses `merge_defaults`'s
    // sort, so re-sorting at the emission site keeps the on-disk
    // `X-Ghars-Labels=` annotation canonical regardless. Without
    // this, an unsorted-Vec direct-construct caller would emit a
    // non-canonical annotation and the plan classifier's sorted
    // comparison would silently mask the divergence.
    let mut label_names: Vec<&str> = spec.labels.iter().map(String::as_str).collect();
    label_names.sort_unstable();
    let _ = writeln!(s, "X-Ghars-Labels={}", label_names.join(","));
    let arch_str = match spec.arch {
        crate::config::Arch::X86_64 => "x86_64",
        crate::config::Arch::Aarch64 => "aarch64",
    };
    let _ = writeln!(s, "X-Ghars-Arch={arch_str}");
    // emit X-Ghars-Caches unconditionally (matches the X-Ghars-Labels
    // pattern at render_identity above) so the planner can detect
    // caches-list shrinks. Without an unconditional emit, a runner
    // whose caches list goes from `["a"]` → `[]` would have no
    // on-disk record of the prior membership, so the in-place path
    // could not compute a set diff against `DiscoveredAnnotations`
    // to detect the removed cache. Empty value is parsed as
    // `Some(vec![])` by the classifier (see DiscoveredAnnotations
    // labels handling).
    //
    // caches arrive pre-sorted by lower_to_effective. The defensive
    // sort here mirrors the labels emission above: any future caller
    // that builds an `EffectiveRunnerSpec` directly bypasses
    // `lower_to_effective`'s sort, so re-sorting at the emission site
    // keeps the on-disk `X-Ghars-Caches=` annotation canonical
    // regardless. Without this, an unsorted-Vec direct-construct
    // caller would emit a non-canonical annotation and the plan
    // classifier's sorted comparison would silently mask the
    // divergence.
    let mut cache_names: Vec<&str> = spec.caches.iter().map(|c| c.name.as_str()).collect();
    cache_names.sort_unstable();
    let _ = writeln!(s, "X-Ghars-Caches={}", cache_names.join(","));
    let _ = writeln!(s, "X-Ghars-Config-Source={}", spec.config_source);
    // runner_version is filled by the plan pipeline before APPLY-time
    // re-render (lower_to_effective rejects tarball+no-version; the
    // intersection arm fills in-place candidates from the discovered
    // X-Ghars-Effective-Version annotation; resolve_plan_releases
    // fills CreateRunner + recreate UpdateRunner from the release-API
    // lookup before execute_create_runner re-renders). At PLAN time,
    // however, render_runner_unit is called via into_runner_plan
    // BEFORE resolve_plan_releases runs, so runner_version may still
    // be None for "implicit-latest" CreateRunner previews. Emit an
    // empty rvalue rather than fail — the operator-facing
    // `ghars plan --diff` shows the placeholder, and the apply path
    // re-renders with the resolved version before writing to disk.
    // The discovered annotation can be a Some("") for runners that
    // were originally applied with the implicit-latest pattern; the
    // intersection-arm fill skips empty values, leaving them to
    // re-resolve via the apply-time path.
    let _ = writeln!(
        s,
        "X-Ghars-Effective-Version={}",
        spec.runner_version.as_deref().unwrap_or("")
    );
    // runner_sha256 is operator-supplied SHA256 of the runner
    // tarball — recreate-class. Emitted only when set so a missing
    // line means "operator did not pin a digest" (resolves through
    // the releases API). An empty `=` would conflate "operator
    // explicitly cleared the pin" with "field never set" at parse
    // time. Emit nothing when None; the classifier treats absence as
    // "skip this field" not "differs from empty".
    if let Some(sha) = spec.runner_sha256.as_deref()
        && !sha.is_empty()
    {
        let _ = writeln!(s, "X-Ghars-Runner-Sha256={sha}");
    }
    // runner_tarball is an operator-supplied local path to a
    // pre-downloaded tarball. The PATH itself leaks operator
    // environment (mount points, usernames, kernel-private dirs) so
    // we emit a SHA256 of the path string instead. The hash is
    // sufficient for change detection — a change to the tarball
    // path produces a new hash, even though the operator's path is
    // never persisted in the on-disk artifact. No emission when
    // None (same rationale as runner_sha256 above). The empty-string
    // gate below is the renderer-side mirror of the merge-time
    // normalization at `merge_defaults` — defense-in-depth for
    // direct-construct callers (test fixtures, future programmatic
    // spec builders) that bypass `cli::load`. The operator-facing
    // TOML pathway is already gated by `validate_runner_tarball` at
    // config-load (`Path::new("").is_absolute() == false`). Idiom
    // matches the immediate-sister `runner_sha256` let-chain above
    // for adjacent-code consistency.
    if let Some(tarball) = spec.runner_tarball.as_deref()
        && !tarball.as_str().is_empty()
    {
        use sha2::{Digest, Sha256};
        let mut h = Sha256::new();
        h.update(tarball.as_str().as_bytes());
        let _ = writeln!(
            s,
            "X-Ghars-Runner-Tarball-Hash=sha256:{}",
            hex::encode(h.finalize())
        );
    }
    // trust_zone is in EffectiveRunnerSpec spec_hash but has
    // no runner-unit body dependency once cache-pool cross-references
    // validate. Annotated so the classifier can detect an isolated
    // trust_zone change as in-place (FieldChange but no recreate
    // reason — see plan.rs::classify_recreate_reasons_from_annotations).
    let _ = writeln!(s, "X-Ghars-Trust-Zone={}", spec.trust_zone);
    // network mode (open|netns). Recreate-class — see
    // classifier. Emitted unconditionally; "open" is the canonical
    // string for "no [network] block referenced or NetworkMode::Open".
    let net_mode = match spec.network.as_ref().map(|n| &n.spec.mode) {
        Some(crate::config::NetworkMode::Netns) => "netns",
        Some(crate::config::NetworkMode::Open) | None => "open",
    };
    let _ = writeln!(s, "X-Ghars-Network-Mode={net_mode}");
    // X-Ghars-Netns-Subnet is Netns-only (the documented
    // "filesystem-layout" annotation table flags it that way). The
    // binding's `subnet` field is `Some` exactly when
    // `lower_to_effective` allocated a /30, which it does only for
    // Netns mode — so gating on `subnet.is_some()` is equivalent to
    // gating on `mode == Netns`, expressed as a presence check
    // against the field that actually carries the value.
    if let Some(net) = &spec.network
        && let Some(subnet) = net.subnet
    {
        let _ = writeln!(s, "X-Ghars-Netns-Subnet={subnet}");
    }
    // X-Ghars-Dns + X-Ghars-Ipv6: surface network sub-fields that
    // the runner unit's body doesn't otherwise carry (dns drives
    // /run/ghars/netns-resolv/<name> via `ghars _netns-setup`;
    // ipv6 is reserved for future ULA support). Without these
    // annotations the classifier sees a spec_hash flip on
    // dns/ipv6 edit but no Stage 1 FieldChange — falls through
    // to the uncovered arm. Emitting them here gives the
    // classifier a recreate/in-place signal + gives operators a
    // `systemctl cat` view of which dns/ipv6 mode the runner
    // currently has. Both are gated on `spec.network.is_some()`
    // since they're NetworkSpec sub-fields. Routed as in-place
    // (FieldChange, no recreate reason) per classifier — dns
    // mode change re-runs netns _netns-setup on the next side-
    // unit restart; ipv6 currently must be `Disabled` (Enabled
    // hard-errors at apply per config.rs `Ipv6Mode::Enabled`
    // comment), so the annotation is defensive forward-compat.
    //
    // Emitted for BOTH Netns and Open NetworkMode (gate is
    // `spec.network.is_some()`, not `mode == Netns`). Open-mode
    // values are validator-constrained today (Forward / Disabled
    // per `validators::validate_network_spec` open-mode branch), so
    // the emission is trivially-valued — but keeps the annotation
    // surface consistent across modes, future-proofs against
    // validator relaxations that allow Open-mode dns/ipv6
    // customization, and lets `systemctl cat` carry the same
    // surface for every network-bound runner.
    if let Some(net) = &spec.network {
        let dns_str = crate::config::dns_to_annotation(&net.spec.dns);
        let _ = writeln!(s, "X-Ghars-Dns={dns_str}");
        let ipv6_str = crate::config::ipv6_to_annotation(net.spec.ipv6);
        let _ = writeln!(s, "X-Ghars-Ipv6={ipv6_str}");
    }
    // [Service] is always emitted: User=ghars-tz-<TRUST_ZONE> binds
    // the runner unit to the trust_zone's DynamicUser allocation
    // (template body declares DynamicUser=yes; this drop-in pins the
    // name so runners with the same trust_zone share the transient
    // UID/GID systemd allocates per User= name).
    s.push('\n');
    s.push_str("[Service]\n");
    let _ = writeln!(s, "User=ghars-tz-{}", spec.trust_zone);
    // WorkingDirectory + HOME stamp the per-runner home. ghars creates
    // and manages the runner home during apply. StateDirectory= is NOT
    // used because DynamicUser=yes + StateDirectory= would trigger
    // systemd's private-dir + symlink dance at the runner home path
    // (per systemd/src/core/exec-invoke.c:3080-3166 — invariant
    // across all currently-supported systemd versions; verified
    // present in v261), which conflicts with the regular directory
    // ghars already created and breaks ghars's later O_NOFOLLOW-
    // protected operations on the path. The full sandbox
    // (TemporaryFileSystem, BindReadOnlyPaths, DynamicUser) still
    // applies -- only the auto-chown is lost.
    // BindPaths= makes the runner home writable inside the sandbox.
    let _ = writeln!(
        s,
        "BindPaths=/var/lib/ghars/{}",
        spec.trust_zone
    );
    // WorkingDirectory points at the versioned bin dir so the runner
    // finds ./externals/, ./bin/Runner.Listener, etc. relative to cwd.
    // `version` falls back to "latest" when runner_version is None.
    // The bytes on disk are pinned for the CreateRunner and
    // recreate-class UpdateRunner paths (resolve_plan_releases fills
    // runner_version BEFORE execute_create_runner re-renders).
    // The in-place UpdateRunner arm has a different ordering: the
    // intersection-arm fill at compute.rs tries to inherit
    // runner_version from the discovered X-Ghars-Effective-Version
    // annotation, but if that annotation is absent/empty/invalid,
    // the candidate stays None — plan-time-rendered drop-ins (with
    // literal "latest" in WorkingDirectory) get written to disk via
    // read_then_write_if_changed BEFORE the .env/.path rewrite at
    // execute_update_runner's missing-runner_version ok_or_else
    // hard-errors. Moving the hard-error to plan time would close
    // the write-then-error ordering; until then, the legacy-edge
    // case lands broken-from-birth bytes before failing the apply.
    let version = spec.runner_version.as_deref().unwrap_or("latest");
    let _ = writeln!(
        s,
        "WorkingDirectory=/var/lib/ghars/{}/ghars-{}/bin.{}",
        spec.trust_zone, spec.name, version
    );
    // ExecStart reset-then-set: the template intentionally omits
    // ExecStart= because the path includes the runner version (only
    // known at apply time after install). The empty assignment clears
    // any inherited ExecStart= (defense in depth — the template
    // currently has none, but operators may add one via 99-*.conf);
    // the second line provides the canonical absolute path to the
    // tarball's runsvc.sh under the versioned bin dir's `bin/`
    // subdir. Upstream layout: actions/runner's `Misc/layoutbin/`
    // files install into `_layout/bin/` per the project's build
    // target (`<Copy SourceFiles="@(LayoutBinFiles)"
    // DestinationFolder=".../_layout/bin/..."/>`), so the published
    // tarball ships runsvc.sh at `bin.X.Y.Z/bin/runsvc.sh`, NOT at
    // `bin.X.Y.Z/runsvc.sh`.
    let _ = writeln!(s, "ExecStart=");
    let _ = writeln!(
        s,
        "ExecStart=/bin/bash /var/lib/ghars/{}/ghars-{}/bin.{}/bin/runsvc.sh",
        spec.trust_zone, spec.name, version
    );
    let _ = writeln!(
        s,
        "Environment=HOME=/var/lib/ghars/{}/ghars-{}",
        spec.trust_zone, spec.name
    );
    // Shared with render_runner_path_file via compose_runner_path so
    // Site B (Environment=PATH= here) and Site A (.path file) emit
    // the identical PATH string — eliminates the LAYER 1/2 PATH-drift
    // class. Operator environment.path_prepend / path_append land in
    // the composed string per OPTION C.
    let _ = writeln!(s, "Environment=PATH={}", compose_runner_path(spec));
    // TMPDIR under the runner home so the sccache server (separate unit
    // with its own PrivateTmp) can hash input files. Without this, cargo
    // builds in /tmp which is private to the runner unit and invisible
    // to ghars-cache@.service.
    let _ = writeln!(
        s,
        "Environment=TMPDIR=/var/lib/ghars/{}/ghars-{}/tmp",
        spec.trust_zone, spec.name
    );
    let _ = writeln!(
        s,
        "Environment=KTSTR_LOCK_DIR=/var/lib/ghars/{}/.ktstr",
        spec.trust_zone
    );
    let _ = writeln!(
        s,
        "Environment=KTSTR_CACHE_DIR=/var/lib/ghars/{}/.ktstr",
        spec.trust_zone
    );
    // LAYER 3 (Site B): operator-declared env vars appended after
    // framework Environment= directives. Same BTreeMap iteration as
    // render_runner_env_file (Site A) — operator's MY_VAR lands in
    // BOTH 00-ghars.conf (here) and .env (Site A) per the api-reviewer
    // HARD REQ: a future renderer refactor that drops one layer would
    // re-create the LAYER 1/2 drift class the in-place .env/.path
    // rewrite fixed for framework-emitted built-ins.
    //
    // %-escape: operator values containing `%` must be emitted as
    // `%%` here because systemd parses %-specifiers in Environment=
    // values (per `systemd.exec(5)`). Site A (.env) carries the same
    // operator value VERBATIM because Runner.Listener's LoadAndSetEnv
    // (.NET) does not interpret `%`. Escape-on-Site-B + verbatim-on-
    // Site-A yields IDENTICAL effective values seen by both consumers
    // (operator's literal value preserved end-to-end).
    //
    // Defense-in-depth re-validation: check the value via
    // check_identity_field at render time too — config-load is the
    // primary gate but direct construct sites (test fixtures) might
    // bypass the load path.
    for (key, value) in &spec.environment.vars {
        check_identity_field("environment.vars[].key", key)?;
        check_identity_field("environment.vars[].value", value)?;
        let escaped = value.replace('%', "%%");
        let _ = writeln!(s, "Environment={key}={escaped}");
    }
    // ConditionPathExists is a [Unit]-section directive; emit a
    // separate [Unit] section AFTER [Service] (drop-in sections can
    // appear in any order — systemd merges by section name). The path
    // mirrors the ExecStart= target above — the tarball's runsvc.sh
    // at `bin.X.Y.Z/bin/runsvc.sh` (upstream `Misc/layoutbin/`
    // installs into `_layout/bin/`).
    s.push_str("\n[Unit]\n");
    let _ = writeln!(
        s,
        "ConditionPathExists=/var/lib/ghars/{}/ghars-{}/bin.{}/bin/runsvc.sh",
        spec.trust_zone, spec.name, version
    );
    Ok(s)
}

fn render_memory(spec: &EffectiveRunnerSpec) -> Result<Option<String>> {
    let Some(m) = spec.memory_max.as_deref() else {
        return Ok(None);
    };
    if m.is_empty() {
        return Ok(None);
    }
    // Defense-in-depth: `memory_max` is an operator-supplied free-
    // form String (config.rs `EffectiveRunnerSpec.memory_max:
    // Option<String>`) interpolated directly into `MemoryMax=`. A
    // newline would inject a new directive line; NUL/control chars would
    // corrupt the systemd unit parser the same way the
    // `check_identity_field` gate already prevents in `render_identity`.
    check_identity_field("memory_max", m)?;
    let mut s = String::new();
    s.push_str("[Service]\n");
    let _ = writeln!(s, "MemoryMax={m}");
    Ok(Some(s))
}

/// Validate every operator-supplied list entry in `Hardening` against
/// the identity-field + whitespace-padding gates before the renderer
/// touches the drop-in bytes. A newline in any of these values would
/// otherwise inject a new directive line at unit-load time
/// (`CapabilityBoundingSet`, `SystemCallFilter`, `BindReadOnlyPaths`,
/// `RestrictAddressFamilies`, `extra_bind_paths`). Whitespace padding is
/// rejected so direct-construct callers bypassing cli/load.rs can't
/// produce different on-disk bytes than the equivalent unpadded form.
fn validate_hardening_entries(h: &Hardening) -> Result<()> {
    for entry in &h.restrict_address_families {
        check_identity_field("restrict_address_families[]", entry)?;
        check_no_whitespace_padding("restrict_address_families[]", entry)?;
    }
    for entry in &h.extra_syscalls {
        check_identity_field("extra_syscalls[]", entry)?;
        check_no_whitespace_padding("extra_syscalls[]", entry)?;
    }
    for entry in &h.extra_capabilities {
        check_identity_field("extra_capabilities[]", entry)?;
        check_no_whitespace_padding("extra_capabilities[]", entry)?;
    }
    if let Some(paths) = &h.bind_readonly_paths {
        for p in paths {
            check_identity_field("bind_readonly_paths[]", p.as_str())?;
            check_no_whitespace_padding("bind_readonly_paths[]", p.as_str())?;
            check_no_root_bind("hardening.bind_readonly_paths[]", p)?;
        }
    }
    for p in &h.extra_bind_paths {
        check_identity_field("extra_bind_paths[]", p.as_str())?;
        check_no_whitespace_padding("extra_bind_paths[]", p.as_str())?;
        check_no_root_bind("hardening.extra_bind_paths[]", p)?;
    }
    Ok(())
}

/// True iff the operator touched at least one hardening directive in
/// a way the template's canonical defaults don't already cover. The
/// renderer emits a drop-in only when this returns true.
fn hardening_needs_drop_in(h: &Hardening) -> bool {
    let touches_scalar = h.kvm.is_some()
        || h.restrict_realtime.is_some()
        || h.protect_control_groups.is_some()
        || h.restrict_suid_sgid.is_some()
        || h.private_devices.is_some()
        || h.private_ipc.is_some();
    let has_lists = !h.restrict_address_families.is_empty()
        || !h.extra_syscalls.is_empty()
        || !h.extra_capabilities.is_empty()
        || !h.extra_bind_paths.is_empty()
        || h.bind_readonly_paths.is_some();
    let has_etc_override = h.etc_bind_style != EtcBindStyle::default();
    touches_scalar || has_lists || has_etc_override
}

fn render_hardening(
    spec: &EffectiveRunnerSpec,
    warnings: &mut Vec<String>,
) -> Result<Option<String>> {
    let h = &spec.hardening;
    let profile = HardeningProfile::from(h);

    validate_hardening_entries(h)?;
    if !hardening_needs_drop_in(h) {
        return Ok(None);
    }

    let mut s = String::new();
    s.push_str("[Service]\n");

    if h.kvm.is_some() {
        // The runner template grants `DeviceAllow=/dev/kvm rw`. systemd
        // treats `DeviceAllow` as list-typed and the only way to revoke
        // a template-level grant from a drop-in is the empty-reset
        // pattern (a drop-in cannot subtract a specific entry). When
        // the operator opts out of KVM via `hardening.kvm = false` we
        // emit `DeviceAllow=` and follow it with no further entries —
        // the resulting set is empty, combined with the template's
        // `DevicePolicy=closed` this denies all device access.
        //
        // The reset-on-empty validator treats `DeviceAllow`
        // INTENTIONALLY as not-protected (see RESET_ON_EMPTY_DIRECTIVES
        // doc-comment) precisely so this branch can land. The other
        // directives in that list have multi-entry templates where an
        // empty reset would silently disable hardening; `DeviceAllow`
        // has a single template entry and revoking it is the operator's
        // documented intent.
        if profile.kvm {
            s.push_str("DeviceAllow=/dev/kvm rw\n");
        } else {
            s.push_str("DeviceAllow=\n");
            warnings.push(format!(
                "runner {name}: hardening.kvm=false drops DeviceAllow=/dev/kvm rw; \
                workflows that need KVM access (nested virtualization, KVM-based \
                test harnesses) will fail",
                name = spec.name
            ));
        }
    }
    if h.restrict_realtime.is_some() {
        let _ = writeln!(s, "RestrictRealtime={}", yes_no(profile.restrict_realtime));
    }
    if h.protect_control_groups.is_some() {
        let _ = writeln!(
            s,
            "ProtectControlGroups={}",
            yes_no(profile.protect_control_groups)
        );
    }
    if h.restrict_suid_sgid.is_some() {
        let _ = writeln!(s, "RestrictSUIDSGID={}", yes_no(profile.restrict_suid_sgid));
    }
    if h.private_devices.is_some() {
        let _ = writeln!(s, "PrivateDevices={}", yes_no(profile.private_devices));
    }
    if h.private_ipc.is_some() {
        let _ = writeln!(s, "PrivateIPC={}", yes_no(profile.private_ipc));
    }

    if !h.restrict_address_families.is_empty() {
        // Defense-in-depth canonical-lex sort. The production path
        // sorts AND dedups at `plan::merge_hardening` before the
        // renderer sees it; this renderer-side sort closes the
        // ORDERING gap (not the duplicate-emission gap) for
        // direct-construct callers (test fixtures, future
        // programmatic spec builders) that bypass the merge layer
        // and would otherwise emit non-canonical bytes / spurious
        // `spec_hash` drift across cosmetically-equivalent
        // operator-supplied orderings. Renderer-side dedup is
        // deliberately omitted to mirror the established
        // `render_network` / `render_identity` / `render_cache_drop_in`
        // pattern (all existing renderer sort sites also omit
        // dedup); a sibling-sweep that adds dedup uniformly across
        // all renderer sort sites is tracked separately. Set-semantic safe per
        // systemd.exec(5) — RestrictAddressFamilies= unions across
        // drop-in lines; token shape gated upstream by
        // `validate_restrict_address_families` (AF_FAMILY_RE) which
        // rejects `~`-prefix tokens at config load. Mirrors the
        // labels + caches sorts at `render_identity`, the pool-kinds
        // sort at `render_cache_drop_in`, and the network-side
        // restrict_address_families sort at `render_network`.
        let mut families: Vec<&str> = h
            .restrict_address_families
            .iter()
            .map(String::as_str)
            .collect();
        families.sort_unstable();
        let _ = writeln!(
            s,
            "RestrictAddressFamilies={}",
            families.join(" ")
        );
    }

    if !h.extra_syscalls.is_empty() {
        // Append-style — systemd treats consecutive SystemCallFilter=
        // lines as union, so adding new tokens through a drop-in
        // grows the allowlist instead of replacing it.
        //
        // Defense-in-depth canonical-lex sort (mirror of
        // `restrict_address_families` block above for the
        // ordering-gap-only scope and the renderer-side-dedup
        // carve-out). Production path sorts upstream at
        // `plan::merge_hardening`; direct-construct callers bypass
        // that, so the renderer sort closes the ordering gap.
        // Set-semantic safe: token shape gated upstream by
        // `validate_extra_syscalls` (SYSCALL_NAME_RE) which rejects
        // `~`-prefix / `@`-prefix tokens at config-load, so the
        // first-token mode-switch hazard documented at
        // `systemd/src/core/load-fragment.c` config_parse_syscall_filter
        // cannot arise from sort reordering.
        let mut syscalls: Vec<&str> = h
            .extra_syscalls
            .iter()
            .map(String::as_str)
            .collect();
        syscalls.sort_unstable();
        let _ = writeln!(s, "SystemCallFilter={}", syscalls.join(" "));
    }

    if !h.extra_capabilities.is_empty() {
        // Same union semantics for CapabilityBoundingSet=. The runner
        // template (`runner_template_text`) sets the base bounding
        // set to empty (no CAP_SETUID/CAP_SETGID — DynamicUser=
        // handles privilege identity, no setuid syscall); appending
        // caps here UNIONS with that empty base — the operator's
        // tokens become the runner's full bounding set. Operators who
        // want a strictly-empty bounding set leave `extra_capabilities`
        // empty and the template's empty value stands.
        //
        // Defense-in-depth canonical-lex sort (mirror of
        // `restrict_address_families` and `extra_syscalls` blocks
        // above for the ordering-gap-only scope and the
        // renderer-side-dedup carve-out). Production path sorts
        // upstream at `plan::merge_hardening`; direct-construct
        // callers bypass that, so the renderer sort closes the
        // ordering gap. Set-semantic safe: token shape gated upstream
        // by `validate_extra_capabilities` (CAP_RE) which rejects
        // `~`-prefix tokens at config-load.
        //
        // bind_readonly_paths + extra_bind_paths are NOT sorted here
        // by design — see the BindReadOnlyPaths blocks below; the
        // upstream `plan::merge_hardening` doc-comment cites
        // mount_path_compare's PID-1-user-space resort as the
        // reason operator order is preserved for spec_hash
        // byte-equality.
        let mut caps: Vec<&str> = h
            .extra_capabilities
            .iter()
            .map(String::as_str)
            .collect();
        caps.sort_unstable();
        let _ = writeln!(
            s,
            "CapabilityBoundingSet={}",
            caps.join(" ")
        );
    }

    // BindReadOnlyPaths handling. systemd.exec(5)
    // documents BindReadOnlyPaths as a list-typed directive: each
    // assignment APPENDS to the cumulative list, and only the
    // empty-reset form (`BindReadOnlyPaths=`) clears it. Both
    // bind_readonly_paths and extra_bind_paths therefore APPEND to the
    // template's accumulated list — neither replaces it. The
    // reset-on-empty validator (the `RESET_ON_EMPTY_DIRECTIVES`
    // list) forbids a managed drop-in from emitting the bare-`=`
    // reset form, so this generator only ever appends. Operators
    // who want to *narrow* the bind-readonly set must use a
    // 99-*.conf operator drop-in (which the validator does NOT
    // police).
    if let Some(paths) = &h.bind_readonly_paths
        && !paths.is_empty()
    {
        // Emit the operator's chosen entries on one
        // BindReadOnlyPaths= line. Multiple assignments would
        // also append; one line is the deterministic form. The
        // generator's branch above filters out the empty case,
        // so the reset-on-empty rule is never violated here.
        let joined = paths
            .iter()
            .map(|p| p.as_str())
            .collect::<Vec<_>>()
            .join(" ");
        let _ = writeln!(s, "BindReadOnlyPaths={joined}");
    }
    if !h.extra_bind_paths.is_empty() {
        let joined = h
            .extra_bind_paths
            .iter()
            .map(|p| p.as_str())
            .collect::<Vec<_>>()
            .join(" ");
        let _ = writeln!(s, "BindReadOnlyPaths={joined}");
    }

    if h.etc_bind_style == EtcBindStyle::Broad {
        // Broad: bind whole /etc. Append; the template's curated /etc
        // entries remain (BindReadOnlyPaths is list-typed; appending
        // /etc widens coverage without resetting).
        s.push_str("BindReadOnlyPaths=/etc\n");
    }

    Ok(Some(s))
}

fn render_cache_pool(spec: &EffectiveRunnerSpec) -> Result<Option<String>> {
    if spec.caches.is_empty() {
        return Ok(None);
    }
    // Defense-in-depth: `binding.size` is an operator-supplied
    // free-form String (config.rs `EffectiveCacheBinding.size: String`)
    // interpolated into `Environment=CCACHE_MAXSIZE=` and
    // `Environment=SCCACHE_CACHE_SIZE=` lines. A newline would terminate
    // the env value and inject another directive. `binding.name` is
    // already validated by `validate_cache_pool_name` at config load, so
    // it does not need a separate gate here.
    for c in &spec.caches {
        check_identity_field("caches[].size", &c.size)?;
    }
    let mut s = String::new();
    // Track whether any structurally-meaningful directive landed in the
    // body. ccache-only specs hit no emission site (the Ccache branch
    // is empty per LAYER 1/2 contract); without this gate the renderer
    // would write a `[Service]\n` stub drop-in to disk for every
    // ccache-only runner, polluting `systemctl cat` and the in-place
    // diff path. Returning None when nothing meaningful was emitted
    // lets the apply layer's DropInChangeKind::Removed branch delete
    // any pre-existing stub on first apply post-deploy.
    let mut emitted_anything = false;
    let unit_section_pools: Vec<&EffectiveCacheBinding> = spec
        .caches
        .iter()
        .filter(|c| c.kinds.contains(&CacheKind::Sccache))
        .collect();
    if !unit_section_pools.is_empty() {
        // [Unit] Requires=/After= the per-pool sccache server unit.
        // ccache-only pools do NOT have a server unit (filesystem-only
        // mechanism via shared HOME under trust_zone), so they are
        // omitted from this list.
        s.push_str("[Unit]\n");
        for c in &unit_section_pools {
            let _ = writeln!(s, "Requires=ghars-cache@{}.service", c.name);
            let _ = writeln!(s, "After=ghars-cache@{}.service", c.name);
        }
        s.push('\n');
        emitted_anything = true;
    }
    s.push_str("[Service]\n");
    let mut bind_paths: Vec<String> = Vec::new();
    let mut needs_run_ghars = false;
    for c in &spec.caches {
        let pool_dir = format!("/var/cache/ghars/pools/{}", c.name);
        if c.kinds.contains(&CacheKind::Ccache) {
            // ccache uses filesystem mode: the shared $HOME/.cache/ccache/
            // directory under the trust_zone-shared HOME is the entire
            // mechanism. No daemon, no Requires=, no BindPaths to a
            // pool dir — runners with the same trust_zone share the
            // ccache directory by virtue of the shared DynamicUser UID.
            //
            // CCACHE_DIR + CCACHE_MAXSIZE are emitted ONLY by LAYER 2
            // (`render_runner_env_file` → `bin.X.Y.Z/.env`). No LAYER 1
            // `Environment=` emission here: Runner.Listener's
            // `LoadAndSetEnv` runs AS THE FIRST STATEMENT of `Main` —
            // BEFORE any subprocess spawn, BEFORE HostContext setup,
            // BEFORE any other Runner.Listener code — and (verified
            // in actions/runner at `src/Runner.Listener/Program.cs`)
            // reads `.env` line-by-line, calling
            // `Environment.SetEnvironmentVariable` per line. So a
            // LAYER 1 `Environment=CCACHE_DIR=` here would be
            // overwritten by LAYER 2 before any consumer reads it,
            // making it dead code that misleads operators reading
            // `systemctl cat` (the per-pool path it would show is
            // never the path actually used at runtime).
            //
            // ccache invocation path: workflow step runs `gcc` →
            // PATH wrapper at `/usr/lib64/ccache/gcc` → ccache reads
            // CCACHE_DIR from process env → trust-zone-shared path
            // from LAYER 2.
        }
        if c.kinds.contains(&CacheKind::Sccache) {
            let _ = writeln!(
                s,
                "Environment=SCCACHE_SERVER_UDS=/run/ghars/cache-{}.sock",
                c.name
            );
            // Pool-side server is the sole owner; runners are clients.
            // SCCACHE_NO_DAEMON=1 prevents auto-spawn.
            s.push_str("Environment=SCCACHE_NO_DAEMON=1\n");
            let _ = writeln!(s, "Environment=SCCACHE_CACHE_SIZE={}", c.size);
            needs_run_ghars = true;
            // Pool dir is also bound so sccache disk reads succeed even
            // when the runner needs to inspect cache shape locally.
            if !bind_paths.contains(&pool_dir) {
                bind_paths.push(pool_dir);
            }
            emitted_anything = true;
        }
    }
    if needs_run_ghars {
        bind_paths.push("/run/ghars".into());
    }
    if !bind_paths.is_empty() {
        // BindPaths is list-typed; emitting a non-empty value APPENDS
        // to the template's set (the template has no BindPaths line —
        // it relies on TemporaryFileSystem=/:ro + selective rebinds).
        // The reset-on-empty validator passes because we only get
        // here with at least one entry.
        let _ = writeln!(s, "BindPaths={}", bind_paths.join(" "));
    }
    if !emitted_anything {
        return Ok(None);
    }
    Ok(Some(s))
}

/// `15-resolv.conf` — always emitted. Binds /etc/resolv.conf in the
/// runner's mount namespace from the source appropriate for the
/// runner's network mode:
/// - Open / no-network: host's `/etc/resolv.conf` (same path → same
///   path; runner inherits the host resolver).
/// - Netns: `/run/ghars/netns-resolv/<name>` (written by
///   `ghars _netns-setup` from the operator's `DnsMode`).
///
/// Always-emitted so the template can omit the path entirely; see
/// `render_runner_unit` for why the override-via-drop-in pattern fails
/// (systemd's mount-list dedup keeps the FIRST entry per destination).
fn render_resolv_bind(spec: &EffectiveRunnerSpec) -> String {
    let mut s = String::new();
    s.push_str("[Service]\n");
    let netns_mode = matches!(
        spec.network.as_ref().map(|n| &n.spec.mode),
        Some(NetworkMode::Netns),
    );
    if netns_mode {
        // The netns helper writes the source file at unit start; if
        // the file is missing the bind fails — fail-closed. No `-`
        // prefix.
        let _ = writeln!(
            s,
            "BindReadOnlyPaths=/run/ghars/netns-resolv/{}:/etc/resolv.conf",
            spec.name
        );
    } else {
        s.push_str("BindReadOnlyPaths=/etc/resolv.conf\n");
    }
    s
}

fn render_network(spec: &EffectiveRunnerSpec) -> Result<Option<String>> {
    let Some(net) = spec.network.as_ref() else {
        return Ok(None);
    };
    let netns_mode = matches!(net.spec.mode, NetworkMode::Netns);
    let has_cgroup_bpf_directives = !net.spec.ip_allow.is_empty()
        || !net.spec.ip_deny.is_empty()
        || !net.spec.restrict_address_families.is_empty();
    // Defense in depth against direct-construct callers (test
    // fixtures, future programmatic spec builders) that bypass
    // `lower_to_effective`. The lowering pipeline already collapses
    // Open + all-empty policy to `spec.network = None`, so this
    // branch is unreachable on the production path; an Open binding
    // with no directives reaching `render_network` is therefore a
    // bug-shaped input we'd rather render as "no drop-in" than
    // emit an empty `[Service]` section. Netns mode always emits
    // because the namespace bind itself is the load-bearing
    // contribution regardless of cgroup-BPF policy.
    if !netns_mode && !has_cgroup_bpf_directives {
        return Ok(None);
    }
    // Defense-in-depth: `restrict_address_families[]` is the only
    // operator-supplied free-form String surface in this renderer's
    // body. It is joined with `" "` and emitted on a
    // `RestrictAddressFamilies=` line, so a newline anywhere in an
    // entry would inject a new directive. `ip_allow` / `ip_deny` are
    // typed (`Vec<IpNet>`) so they cannot carry control chars;
    // `spec.name` is gated by `validate_runner_name` upstream.
    //
    // `check_no_whitespace_padding` mirrors the renderer-side gate the
    // sister `render_hardening` already runs for the same field on
    // `Hardening::restrict_address_families`. The canonical config-load
    // gate for `NetworkSpec.restrict_address_families` is the
    // `AF_FAMILY_RE` shape-check at `validators::validate_restrict_address_families`
    // which implicitly rejects whitespace-padded tokens; this renderer
    // gate is the explicit safety net for direct-construct callers.
    for entry in &net.spec.restrict_address_families {
        check_identity_field("network.restrict_address_families[]", entry)?;
        check_no_whitespace_padding("network.restrict_address_families[]", entry)?;
    }
    let mut s = String::new();
    if netns_mode {
        // Netns mode: pull in the per-runner `ghars-net@` side-unit so
        // the namespace bind-mount exists before the runner unit's
        // `NetworkNamespacePath=` join. `BindsTo` couples the
        // lifecycle so a failed netns side-unit also stops the runner.
        s.push_str("[Unit]\n");
        let _ = writeln!(s, "Requires=ghars-net@{}.service", spec.name);
        let _ = writeln!(s, "BindsTo=ghars-net@{}.service", spec.name);
        let _ = writeln!(s, "After=ghars-net@{}.service", spec.name);
        s.push('\n');
    }
    s.push_str("[Service]\n");

    if netns_mode {
        // Fail-closed: NetworkNamespacePath= refuses to start when the
        // bind-mount path is missing or unjoinable. systemd's
        // exec_invoke() opens the path via `open_shareable_ns_path`
        // and returns EXIT_NETWORK on failure (see the
        // `network_namespace_path` branch in
        // `src/core/exec-invoke.c::exec_invoke`).
        let _ = writeln!(s, "NetworkNamespacePath=/var/run/netns/ghars-{}", spec.name);
    }

    // Cgroup-BPF defense in depth. Emitted in BOTH modes when the
    // operator populates the corresponding NetworkSpec field — Netns
    // pairs them with the nft layer for belt-and-suspenders, Open
    // mode relies on them as the sole egress / family gate at the
    // systemd layer (no namespace, no nft).
    //
    // Defense-in-depth canonical-lex sort for direct-construct
    // callers that bypass `lower_to_effective` (test fixtures). The
    // production path canonicalizes upstream at
    // `canonicalize_network_spec` in `compute.rs` (set-semantic for
    // both fields per systemd's cgroup-BPF Set + LPM-trie data
    // structures). Mirror of `restrict_address_families` 2-site
    // pattern below.
    let mut ip_allow_sorted: Vec<&IpNet> = net.spec.ip_allow.iter().collect();
    ip_allow_sorted.sort_unstable();
    for cidr in ip_allow_sorted {
        let _ = writeln!(s, "IPAddressAllow={cidr}");
    }
    let mut ip_deny_sorted: Vec<&IpNet> = net.spec.ip_deny.iter().collect();
    ip_deny_sorted.sort_unstable();
    for cidr in ip_deny_sorted {
        let _ = writeln!(s, "IPAddressDeny={cidr}");
    }
    if !net.spec.restrict_address_families.is_empty() {
        // Canonical-lex-order sort. Defense-in-depth for
        // direct-construct callers that bypass `lower_to_effective`
        // (test fixtures). The production path canonicalizes
        // upstream at `canonicalize_network_spec` in `compute.rs`,
        // so `spec_hash` and the rendered drop-in body are both
        // permutation-invariant across operator-supplied
        // `[network.NAME].restrict_address_families` TOML reorders.
        // Mirror of the labels + caches defensive sorts at
        // `render_identity` and the X-Ghars-Pool-Kinds sort at
        // `render_cache_drop_in`.
        let mut families: Vec<&str> = net
            .spec
            .restrict_address_families
            .iter()
            .map(String::as_str)
            .collect();
        families.sort_unstable();
        let _ = writeln!(s, "RestrictAddressFamilies={}", families.join(" "));
    }

    Ok(Some(s))
}

fn render_numa(spec: &EffectiveRunnerSpec) -> Result<Option<String>> {
    // Treat `Some("")` identically to `None` for both fields (mirror
    // of `render_memory`'s empty-string short-circuit). Without this, a
    // direct-construct `EffectiveRunnerSpec` with `Some("")` would
    // emit `AllowedCPUs=` / `AllowedMemoryNodes=` (reset directives)
    // that aren't operator intent. Production paths normalize at
    // `merge_defaults`, but defense-in-depth at the renderer protects
    // direct-construct callers.
    let cpus = spec
        .allowed_cpus
        .as_deref()
        .filter(|s| !s.is_empty());
    let mems = spec
        .allowed_memory_nodes
        .as_deref()
        .filter(|s| !s.is_empty());
    if cpus.is_none() && mems.is_none() {
        return Ok(None);
    }
    // Defense-in-depth: both fields are operator-supplied
    // strings interpolated into AllowedCPUs= / AllowedMemoryNodes=.
    // A newline anywhere would inject a new directive line.
    if let Some(c) = cpus {
        check_identity_field("allowed_cpus", c)?;
    }
    if let Some(m) = mems {
        check_identity_field("allowed_memory_nodes", m)?;
    }
    let mut s = String::new();
    s.push_str("[Service]\n");
    if let Some(c) = cpus {
        let _ = writeln!(s, "AllowedCPUs={c}");
    }
    if let Some(m) = mems {
        let _ = writeln!(s, "AllowedMemoryNodes={m}");
    }
    Ok(Some(s))
}

fn render_proxy(spec: &EffectiveRunnerSpec) -> Result<Option<String>> {
    let Some(proxy) = spec.proxy.as_ref() else {
        return Ok(None);
    };
    if proxy.http.is_none()
        && proxy.https.is_none()
        && proxy.no_proxy.is_empty()
        && proxy.ca_certs.is_empty()
    {
        return Ok(None);
    }
    // Defense-in-depth: every operator-supplied string about to
    // be interpolated into a 60-proxy.conf body must clear
    // check_identity_field BEFORE bytes are written. The proxy fields
    // appear in `Environment=...` directives — a newline would
    // terminate the env var and inject a new directive (or, for
    // path bindings below, escape into BindReadOnlyPaths).
    if let Some(http) = &proxy.http {
        check_identity_field("proxy.http", http)?;
    }
    if let Some(https) = &proxy.https {
        check_identity_field("proxy.https", https)?;
    }
    for entry in &proxy.no_proxy {
        check_identity_field("proxy.no_proxy[]", entry)?;
    }
    for binding in &proxy.ca_certs {
        check_identity_field("proxy.ca_certs[].env", &binding.env)?;
        check_identity_field("proxy.ca_certs[].path", binding.path.as_str())?;
        check_no_root_bind("proxy.ca_certs[].path", &binding.path)?;
    }
    let mut s = String::new();
    s.push_str("[Service]\n");
    if let Some(http) = &proxy.http {
        // Both upper- and lower-case env vars so apps that read either
        // find a value.
        let _ = writeln!(s, "Environment=HTTP_PROXY={http}");
        let _ = writeln!(s, "Environment=http_proxy={http}");
    }
    if let Some(https) = &proxy.https {
        let _ = writeln!(s, "Environment=HTTPS_PROXY={https}");
        let _ = writeln!(s, "Environment=https_proxy={https}");
    }
    if !proxy.no_proxy.is_empty() {
        let joined = proxy.no_proxy.join(",");
        let _ = writeln!(s, "Environment=NO_PROXY={joined}");
        let _ = writeln!(s, "Environment=no_proxy={joined}");
    }
    let mut bind_paths: Vec<String> = Vec::new();
    for binding in &proxy.ca_certs {
        let _ = writeln!(s, "Environment={}={}", binding.env, binding.path);
        // No `-` prefix: a missing CA cert must FAIL the unit, not silently
        // tolerate absence. Tolerating absence here lets the runner connect
        // through the proxy with the system trust store as a fallback —
        // that's MITM if the proxy is untrusted (SEC-08).
        bind_paths.push(binding.path.to_string());
    }
    if !bind_paths.is_empty() {
        let _ = writeln!(s, "BindReadOnlyPaths={}", bind_paths.join(" "));
    }
    Ok(Some(s))
}

fn render_hooks(spec: &EffectiveRunnerSpec) -> Result<Option<String>> {
    let Some(h) = spec.hooks.as_ref() else {
        return Ok(None);
    };
    if h.pre_job.is_none() && h.post_job.is_none() {
        return Ok(None);
    }
    // Defense-in-depth: `pre_job` / `post_job` are operator-supplied
    // host paths (config.rs `HooksSpec` fields are `Option<Utf8PathBuf>`)
    // interpolated into `Environment=ACTIONS_RUNNER_HOOK_JOB_*` and
    // `BindReadOnlyPaths=` lines. A newline embedded in the Utf8 path
    // string (Utf8PathBuf is a UTF-8 wrapper, not a control-char filter)
    // would split the env value or escape into a separate
    // BindReadOnlyPaths directive. Validate both bytes-on-disk surfaces
    // before any are written.
    if let Some(p) = &h.pre_job {
        check_identity_field("hooks.pre_job", p.as_str())?;
    }
    if let Some(p) = &h.post_job {
        check_identity_field("hooks.post_job", p.as_str())?;
    }
    let mut s = String::new();
    s.push_str("[Service]\n");
    if let Some(p) = &h.pre_job {
        let _ = writeln!(s, "Environment=ACTIONS_RUNNER_HOOK_JOB_STARTED={p}");
    }
    if let Some(p) = &h.post_job {
        let _ = writeln!(s, "Environment=ACTIONS_RUNNER_HOOK_JOB_COMPLETED={p}");
    }
    // Bind the parent directory of each hook script (deduped if pre and
    // post share the parent). Hook scripts must be reachable through
    // the runner's mount namespace.
    //
    // SEC-12 defense-in-depth: `check_no_root_bind` refuses to emit
    // `BindReadOnlyPaths=/` if any hook's parent resolves to the
    // filesystem root via component-walk normalization.
    // `validators::validate_hook_script` applies the same check at
    // config-load via `crate::path_util::binds_filesystem_root`, but
    // keeping the check here covers any caller that bypasses the
    // validator (programmatic EffectiveRunnerSpec construction, future
    // test harnesses).
    let mut parents: Vec<String> = Vec::new();
    for (field, opt_p) in [
        ("hooks.pre_job", &h.pre_job),
        ("hooks.post_job", &h.post_job),
    ] {
        let Some(p) = opt_p else {
            continue;
        };
        if let Some(parent) = p.parent() {
            let parent_str = parent.to_string();
            if parent_str.is_empty() {
                continue;
            }
            check_no_root_bind(&format!("{field} parent directory for `{p}`"), parent)?;
            if !parents.contains(&parent_str) {
                parents.push(parent_str);
            }
        }
    }
    if !parents.is_empty() {
        let _ = writeln!(s, "BindReadOnlyPaths={}", parents.join(" "));
    }
    Ok(Some(s))
}

fn render_lognamespace(spec: &EffectiveRunnerSpec) -> String {
    let mut s = String::new();
    s.push_str("[Service]\n");
    // SyslogIdentifier gives every runner a clean per-runner tag in
    // journal output regardless of systemd version.
    let _ = writeln!(s, "SyslogIdentifier=ghars-{}", spec.name);
    // LogNamespace= provides full journal isolation (separate journal
    // files per runner) but requires systemd 254+ with journald
    // namespace support. On older systemd (250-253) the directive is
    // silently ignored -- runners still log to the default journal
    // and ghars logs filters by unit name. No conditional needed:
    // systemd drops unknown/unsupported directives without failing
    // the unit.
    let _ = writeln!(s, "LogNamespace=ghars-{}", spec.name);
    s
}

// --- Cache service drop-in (Part 9b) ------------------------------------

/// Render the per-pool drop-in `00-ghars.conf` for
/// `ghars-cache@NAME.service`. Shape varies by `kinds` (ccache only,
/// sccache only, both).
///
/// # Errors
///
/// Returns `GharsError::Validation` from the reset-on-empty
/// validator.
// Pedantic clippy flags ccache/sccache local bindings as confusable;
// the variant names are load-bearing (they ARE the schema's
// CacheKind values) and renaming would obscure the mapping.
#[allow(clippy::similar_names)]
pub fn render_cache_drop_in(
    binding: &EffectiveCacheBinding,
    config_source: &str,
    spec_hash: &str,
) -> Result<String> {
    // Defense-in-depth: three operator/composer-supplied
    // strings interpolate into this drop-in body —
    //   * `binding.size` (operator-supplied, free-form String) →
    //     `Environment=SCCACHE_CACHE_SIZE=` / `Environment=CCACHE_MAXSIZE=`
    //   * `config_source` (composed at plan time from
    //     `paths.config_dir`; already gated by `plan_from`'s
    //     identity-field check, but a future caller that bypasses
    //     `plan_from` would still skip it without this gate) →
    //     `X-Ghars-Config-Source=`
    //   * `spec_hash` (deterministically derived from canonicalized
    //     config; in production cannot contain control chars but the
    //     gate is cheap defense-in-depth in case a future hash format
    //     adds free-form metadata) → `X-Ghars-Spec-Hash=`
    // `binding.name` is gated upstream by `validate_cache_pool_name`
    // (IDENTIFIER_RE charset + identifier-shape) at config load.
    // `binding.kinds` is a typed enum so it cannot carry control chars.
    check_identity_field("caches[].size", &binding.size)?;
    check_identity_field("config_source", config_source)?;
    check_identity_field("spec_hash", spec_hash)?;
    let serves_ccache = binding.kinds.contains(&CacheKind::Ccache);
    let serves_sccache = binding.kinds.contains(&CacheKind::Sccache);

    let mut s = String::new();
    s.push_str("[Unit]\n");
    let _ = writeln!(s, "X-Ghars-Spec-Hash={spec_hash}");
    let _ = writeln!(s, "X-Ghars-Pool-Name={}", binding.name);
    // Defense-in-depth sort: render emits kinds in canonical
    // alphabetical order regardless of operator-supplied
    // `[cache_pools.NAME].kinds` Vec order. Mirrors the labels +
    // caches defensive sorts at `render_identity` — labels
    // (`merge_defaults`), caches (`lower_to_effective` per-runner
    // caches Vec), and pool kinds (`canonicalize_kinds()` at both
    // `into_cache_pool_plan` and the inner loop of
    // `lower_to_effective`) are all sorted at the lowering boundary
    // too, so `cache_pool_hash` / `spec_hash` and this renderer
    // agree on canonical order and the full drop-in body is
    // byte-stable across operator TOML reorders. The renderer-site
    // sort here remains the load-bearing gate for any
    // direct-construct caller that bypasses the lowering layer
    // (test fixtures, future programmatic paths).
    let mut pool_kinds: Vec<&str> = binding.kinds.iter().map(|k| k.label()).collect();
    pool_kinds.sort_unstable();
    let _ = writeln!(s, "X-Ghars-Pool-Kinds={}", pool_kinds.join(","));
    let _ = writeln!(s, "X-Ghars-Config-Source={config_source}");
    s.push('\n');

    s.push_str("[Service]\n");
    // The cache template declares `DynamicUser=yes` without a User=
    // line so the per-pool drop-in can pin the User= name to the
    // pool's trust_zone. systemd allocates the same transient UID for
    // every unit that names `ghars-tz-<TRUST_ZONE>` as User= and
    // recycles it when the last such unit stops. The cache server
    // sharing its UID with the runners in the same trust_zone is what
    // makes owner-DAC reach work for the sccache UDS (mode 0600) and
    // the CacheDirectory (mode 0750). Runners in OTHER trust_zones
    // run at a different UID and are denied at AF_UNIX connect()
    // / path traversal. Validators upstream guarantee every runner
    // referencing `pool` has the same trust_zone as the pool, so this
    // emission is consistent with the runner unit's own User= name
    // (set in the per-runner 00-ghars.conf drop-in).
    let _ = writeln!(s, "User=ghars-tz-{}", binding.trust_zone);
    if serves_sccache {
        let _ = writeln!(
            s,
            "Environment=SCCACHE_DIR=%C/ghars/pools/{}/sccache",
            binding.name
        );
        let _ = writeln!(s, "Environment=SCCACHE_CACHE_SIZE={}", binding.size);
        let _ = writeln!(
            s,
            "Environment=SCCACHE_SERVER_UDS=%t/ghars/cache-{}.sock",
            binding.name
        );
        s.push_str("Environment=SCCACHE_NO_DAEMON=1\n");
        // SCCACHE_IDLE_TIMEOUT=0 prevents the server from exiting
        // mid-shift. Mismatch between server idle timeout and runner
        // restart cycles would force re-init of the on-disk cache.
        s.push_str("Environment=SCCACHE_IDLE_TIMEOUT=0\n");
    }
    if serves_ccache {
        // No CCACHE_DIR / CCACHE_MAXSIZE emission here. This drop-in
        // is on the CACHE POOL unit (`ghars-cache@NAME.service`),
        // not the runner unit. For ccache-only pools, the cache pool
        // unit's ExecStart is `<sleep_path> infinity` (the stub at
        // the `else` branch below) — it never reads CCACHE_*. For
        // combined-kind pools the cache pool unit runs
        // `sccache --start-server` (the `if serves_sccache` ExecStart
        // below); sccache is a separate tool whose documented config
        // surface uses SCCACHE_* exclusively, no CCACHE_* reads.
        //
        // Workflow-step ccache invocations get CCACHE_DIR from the
        // RUNNER unit's LAYER 2 `.env` (trust-zone-shared, gated on
        // `has_ccache` by `render_runner_env_file`), NOT from this
        // cache-pool-unit drop-in. Prior emission was dead code that
        // misled operators reading `systemctl cat
        // ghars-cache@NAME.service` (the per-pool path it showed was
        // never the path actually consumed at runtime).
    }

    if serves_sccache {
        // sccache_path is the plan-time resolution of either the
        // operator pin (`[cache_pools.NAME].sccache_path = "/..."`)
        // or the canonical-search auto-detect (`/usr/local/bin/sccache`
        // then `/usr/bin/sccache`). The plan layer guarantees `Some`
        // here: `resolve_cache_pool_paths` produces `Some(path)`
        // exactly when `kinds.contains(Sccache)`, which is the
        // `serves_sccache` branch we're in. None at this site is a
        // plan-layer invariant violation, not an operator-facing
        // error, so the renderer treats it as a programmer bug.
        let sccache_path = binding.sccache_path.as_ref().ok_or_else(|| {
            GharsError::Validation(
                format!(
                    "render_cache_drop_in: binding for pool '{}' serves sccache \
                     but sccache_path is None; resolve_cache_pool_paths should have populated it",
                    binding.name
                ),
                "this is a ghars bug — the plan layer must resolve sccache_path \
                 before invoking the renderer for sccache-serving pools"
                    .into(),
            )
        })?;
        // Defense-in-depth: the operator-pinned path arrives via a
        // pre-validated absolute Utf8PathBuf, but a future caller that
        // constructs an EffectiveCacheBinding programmatically could
        // bypass that gate; check the bytes here too so the rendered
        // unit cannot smuggle a newline or NUL into ExecStart=.
        check_identity_field("caches[].sccache_path", sccache_path.as_str())?;
        let _ = writeln!(s, "ExecStart={sccache_path} --start-server");
        // sccache --start-server forks: parent exits, child listens.
        // Override the template's Type=simple for sccache pools.
        s.push_str("Type=forking\n");
        // mode enforcement is in the cache template via UMask=0077,
        // not a per-pool ExecStartPost. Kernel-enforced at vfs_mknod
        // time (Linux net/unix/af_unix.c:unix_bind_bsd:1349) so there
        // is no TOCTOU window between bind() and a chmod shim. See the
        // UMask= comment in cache_template_text() for the full
        // mechanism + citations.
        let _ = writeln!(
            s,
            "ReadWritePaths=%C/ghars/pools/{pool} %t/ghars /var/lib/ghars/{tz}",
            pool = binding.name, tz = binding.trust_zone
        );
    } else {
        // ccache-only pool — the unit exists to own the CacheDirectory
        // and act as a Requires= anchor (StopWhenUnneeded handles
        // lifecycle). sleep infinity is the simplest way to keep
        // Type=simple alive without consuming resources. sleep_path
        // is the plan-time resolution of either the operator pin
        // (`[cache_pools.NAME].sleep_path = "/..."`) or the
        // canonical-search auto-detect (`/usr/bin/sleep` then
        // `/bin/sleep`). The plan layer guarantees `Some` for the
        // ccache-only branch we're in (symmetric with sccache_path
        // above) — None here is a programmer bug, not operator-facing.
        let sleep_path = binding.sleep_path.as_ref().ok_or_else(|| {
            GharsError::Validation(
                format!(
                    "render_cache_drop_in: binding for ccache-only pool '{}' \
                     has sleep_path = None; resolve_cache_pool_paths should have populated it",
                    binding.name
                ),
                "this is a ghars bug — the plan layer must resolve sleep_path \
                 before invoking the renderer for ccache-only pools"
                    .into(),
            )
        })?;
        check_identity_field("caches[].sleep_path", sleep_path.as_str())?;
        let _ = writeln!(s, "ExecStart={sleep_path} infinity");
        let _ = writeln!(s, "ReadWritePaths=%C/ghars/pools/{}", binding.name);
    }

    validate_drop_in(&format!("ghars-cache@{}/00-ghars.conf", binding.name), &s)?;
    Ok(s)
}

// --- Test surface --------------------------------------------------------

#[cfg(test)]
#[path = "units_tests/mod.rs"]
mod tests;
