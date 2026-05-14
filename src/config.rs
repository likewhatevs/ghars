//! Config schema (TOML-driven) and `[defaults]` merge logic.
//!
//! Design spec: Part 3 (`config.rs`) and Part 4 (TOML schema + example).
//!
//! All public types are serde-derived for round-trip via TOML and JSON
//! (the latter for `--json` plan output and snapshot tests). Each
//! struct uses `deny_unknown_fields` so typos at the operator's TOML
//! surface fail at load time rather than silently dropping to default.
//! Forward-evolving schema is handled by adding fields with
//! `#[serde(default)]`, not by tolerating unknown keys.

use std::collections::BTreeMap;
use std::net::IpAddr;

use camino::Utf8PathBuf;
use indexmap::IndexMap;
use ipnet::IpNet;
use serde::{Deserialize, Serialize};

use crate::Result;

/// Default for the serde `#[serde(default)]` attribute on
/// `EffectiveRunnerSpec.renderer_schema` and
/// `EffectiveCacheBinding.renderer_schema`: when the field is absent
/// from input (e.g. older plan JSON predating the field), substitute
/// the runtime constant instead of erroring.
fn default_renderer_schema() -> u32 {
    crate::systemd::RENDERER_SCHEMA
}

/// Deserialize-with helper for the renderer_schema fields: consume
/// the operator-supplied u32 from input, then DROP it and return the
/// runtime constant. Combined with `#[serde(default)]` this makes the
/// field's deserialized value ALWAYS equal to
/// `crate::systemd::RENDERER_SCHEMA` regardless of what arrives in
/// input. Defense-in-depth against future deserialization sites
/// (plan-cache sidecar, replay tool, RPC) that would otherwise let
/// an operator spoof the schema number and bypass the hash-
/// participation contract.
///
/// Consuming the input (rather than `IgnoredAny`) preserves error-on-
/// malformed-type behavior: a JSON string where a u32 is expected
/// still fails deserialization at parse, just like the un-hardened
/// shape. Only the integer value is dropped.
fn renderer_schema_from_runtime<'de, D>(d: D) -> std::result::Result<u32, D::Error>
where
    D: serde::Deserializer<'de>,
{
    let _ignored = u32::deserialize(d)?;
    Ok(crate::systemd::RENDERER_SCHEMA)
}

/// Identifier regex shared by runner names, auth keys, cache pool keys,
/// network keys: `^[a-z]([a-z0-9-]*[a-z0-9])?$`. One rule everywhere
/// (Part 3).
pub const IDENTIFIER_REGEX: &str = r"^[a-z]([a-z0-9-]*[a-z0-9])?$";

/// Maximum identifier length (after the `-N` suffix is appended for
/// count blocks). 64 chars (Part 3).
pub const IDENTIFIER_MAX_LEN: usize = 64;

/// Top-level config (parsed from `/etc/ghars/ghars.toml`).
///
/// `[[runner]]` blocks hold both literal-named runners (`count` unset
/// or `1`) and prefix runners (`count > 1` expanded to `name-1` ..
/// `name-N`). `RunnerGroupSpec` and `RunnerOverride` are not part of
/// the schema (Part 3 / Part 4).
#[derive(Debug, Clone, Default, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct Config {
    /// Global defaults inherited by every `[[runner]]` (Part 3).
    #[serde(default)]
    pub defaults: Defaults,

    /// `[auth.NAME]` table — keyed by identifier. The only place auth
    /// is declared; runners reference one by name.
    #[serde(default)]
    pub auth: IndexMap<String, AuthSpec>,

    /// `[cache_pools.NAME]` table — keyed by identifier. ccache and/or
    /// sccache pools.
    #[serde(default)]
    pub cache_pools: IndexMap<String, CachePoolSpec>,

    /// `[network.NAME]` table — keyed by identifier. Each entry
    /// declares an explicit network policy with `mode = "netns"`
    /// (per-runner namespace) or `mode = "open"` (host netns +
    /// optional cgroup-BPF policy). A runner with no `network`
    /// reference at all uses the host netns implicitly with no
    /// cgroup-BPF policy.
    #[serde(default, rename = "network")]
    pub networks: IndexMap<String, NetworkSpec>,

    /// Top-level proxy config — singleton. Most deployments use one
    /// proxy. Per-runner overrides via `[[runner]].proxy`.
    #[serde(default)]
    pub proxy: Option<ProxySpec>,

    /// Top-level job hooks — singleton. Per-runner overrides via
    /// `[[runner]].hooks`.
    #[serde(default)]
    pub hooks: Option<HooksSpec>,

    /// `[[runner]]` array. Each entry produces 1 (no `count`) or N
    /// (count = N) effective runners after expansion.
    #[serde(default, rename = "runner")]
    pub runners: Vec<RunnerSpec>,
}

/// Global defaults inherited field-by-field by every runner. The
/// merge rules are documented in Part 3's "Defaults merge rules"
/// table; the implementation lives in the merge function.
#[derive(Debug, Clone, Default, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct Defaults {
    /// Default GitHub Actions runner version (e.g. `"2.334.0"`).
    pub runner_version: Option<String>,
    /// Default tarball SHA256 (64 hex). Only meaningful with
    /// `runner_version`.
    pub runner_sha256: Option<String>,
    /// Default `[auth.NAME]` reference (Part 3).
    pub auth: Option<String>,
    /// Default `MemoryMax=` value as a free-form string parsed by
    /// `bytesize` at validate time (e.g. `"110G"`).
    pub memory_max: Option<String>,
    /// Default extra labels concatenated with each runner's labels
    /// (dedup, preserve order — see Part 3 merge table).
    #[serde(default)]
    pub labels: Vec<String>,
    /// Default `[network.NAME]` reference. None ≡ host netns with
    /// no cgroup-BPF policy (the implicit-Open shape). Set to a
    /// `[network.NAME]` key when every runner without an explicit
    /// `network` field should resolve through the same network
    /// policy block (Netns or Open with cgroup-BPF directives).
    pub network: Option<String>,
    /// Default CPU architecture for tarball selection. None ≡ host
    /// arch (uname -m).
    pub arch: Option<Arch>,
    /// Default per-field hardening overrides. Each runner can override
    /// further; `Hardening`'s `Default` impl is "all None" → inherit
    /// the canonical Python-tool profile.
    #[serde(default)]
    pub hardening: Hardening,
    /// How many `bin.X.Y.Z/` directories to retain under each runner
    /// home after a successful tarball install. The pruner keeps the
    /// N most recent by mtime (current install + (N-1) rollback
    /// targets) and removes the rest. None ≡ effective default of 2:
    /// the freshly-installed bin tree plus one rollback target.
    /// Operators with disk pressure can set this lower (e.g. 1 = no
    /// rollback retention) or higher (e.g. 5 = keep more rollback
    /// targets). Set to a non-zero value; zero would prune the
    /// just-installed bin dir.
    pub keep_versions: Option<u32>,
    /// Default operator-declared environment composition (env vars +
    /// PATH additions). Inherited by every runner; per-runner
    /// `environment` overrides per-key for `vars` (runner-set keys win)
    /// and appends additively for `path_prepend` / `path_append`
    /// (defaults entries first, then runner entries, dedup).
    #[serde(default)]
    pub environment: EnvironmentSpec,
    // No `slice` field. All ghars-managed units use
    // `Slice=system.slice` unconditionally.
}

/// Effective `keep_versions` value when `Defaults.keep_versions` is
/// `None`. Two retention slots = current bin tree + one rollback
/// target (matches the typical upgrade-then-rollback flow).
pub const DEFAULT_KEEP_VERSIONS: u32 = 2;

/// One `[[runner]]` declaration. When `count` is None or 1 the
/// `name` is the literal runner name; when `count > 1` it is the
/// prefix and ghars expands to `name-1` .. `name-{count}`.
/// `RunnerGroupSpec` and `RunnerOverride` are not part of the schema.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct RunnerSpec {
    /// Runner name (or prefix when `count > 1`). Must match
    /// `IDENTIFIER_REGEX`, ≤ `IDENTIFIER_MAX_LEN` chars after the
    /// largest possible suffix is appended (Part 3 / Part 4).
    pub name: String,

    /// Optional runner-count for "give me N identical runners".
    /// Default None ≡ 1 runner with `name` as-is. When `Some(n)`,
    /// `name` is the prefix and ghars generates `name-1` through
    /// `name-n`. Validated `1..=1024` (/24 IP pool headroom under the
    /// default netns subnet). Diverging config across the count = NOT
    /// supported here — declare a separate `[[runner]]` block for
    /// the divergent runner. The count block AUTO-SKIPS any index
    /// whose generated name matches an explicit
    /// `[[runner]] name = "..."` block elsewhere.
    #[serde(default)]
    pub count: Option<u32>,

    /// Repo or org URL (e.g. `https://github.com/example/buckos`).
    pub url: String,

    /// Reference to a key in `[auth.NAME]`. The ONLY way to specify
    /// auth on a runner — token paths are not declared inline.
    pub auth: Option<String>,

    /// Per-runner labels, concatenated (dedup, preserve order) with
    /// `defaults.labels`.
    #[serde(default)]
    pub labels: Vec<String>,

    /// Per-runner `MemoryMax=` override.
    pub memory_max: Option<String>,
    /// Per-runner runner version override.
    pub runner_version: Option<String>,
    /// Per-runner tarball SHA256 override.
    pub runner_sha256: Option<String>,
    /// Path to a pre-downloaded tarball; bypasses release-API lookup.
    pub runner_tarball: Option<Utf8PathBuf>,

    /// CPU architecture override. None ≡ defaults.arch ≡ host arch.
    pub arch: Option<Arch>,

    /// References to keys in `[cache_pools.NAME]`. Ordered, dedup-on-
    /// validate.
    #[serde(default)]
    pub caches: Vec<String>,

    /// Cache trust zone. The runner can only reference cache pools
    /// whose `trust_zone` matches this value. Default `"default"` —
    /// all runners share one zone unless operator declares otherwise
    /// (SEC-03 fix).
    #[serde(default = "default_trust_zone")]
    pub trust_zone: String,

    /// Reference to a key in `[network.NAME]`. None ≡ implicit Open
    /// (host netns).
    pub network: Option<String>,

    /// Per-runner proxy override (replaces top-level `[proxy]` for
    /// this runner). None ≡ inherit top-level `[proxy]` or no proxy.
    pub proxy: Option<ProxySpec>,

    /// Per-runner hooks override. None ≡ inherit top-level `[hooks]`
    /// or none.
    pub hooks: Option<HooksSpec>,

    /// Per-runner hardening overrides; merged field-by-field over
    /// `defaults.hardening`.
    #[serde(default)]
    pub hardening: Hardening,

    /// `AllowedCPUs=` (cgroup v2 cpuset). Free-form CPU list parsed
    /// at validate time (e.g. `"0-15"`).
    pub allowed_cpus: Option<String>,
    /// `AllowedMemoryNodes=` (cgroup v2 cpuset).
    pub allowed_memory_nodes: Option<String>,
    /// Per-runner operator-declared environment composition. Merges
    /// with `[defaults.environment]` per-key for `vars` (runner-set
    /// keys override defaults), additively for `path_prepend` /
    /// `path_append` (defaults entries first, then runner entries,
    /// dedup). Operator-set keys are validated against a deny-list
    /// (security + ghars-owned keys) and a POSIX env-var-name regex
    /// at config-load.
    #[serde(default)]
    pub environment: EnvironmentSpec,
    // No `slice` field. All units use Slice=system.slice
    // unconditionally.
}

/// A runner spec after count-expansion + `[defaults]` merge. Plan/apply
/// consume this; the count expander produces one `EffectiveRunnerSpec`
/// per generated runner. The merge logic lives with the loader; the
/// fields below are the SHAPE that the unit-text generator and plan
/// engine require.
///
/// Resolved bindings (`auth_name`, `caches`, `network`) carry the
/// looked-up auxiliary data inline so downstream code never needs to
/// re-traverse the parent `Config`.
///
/// `Serialize` is required by `plan::spec_hash`: the canonicalizer
/// round-trips this through `serde_json::Value` (whose `Object` map is
/// `BTreeMap`-backed by default → keys land in sorted order).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct EffectiveRunnerSpec {
    /// Final runner name (post count-expansion).
    pub name: String,
    /// Repo / org URL.
    pub url: String,
    /// CPU architecture (resolved against host arch when omitted).
    pub arch: Arch,
    /// Effective labels after `concat(defaults.labels, runner.labels)`
    /// + dedup (preserves order). Empty after merge ⇒ defaults to
    /// `[name]` per Python parity.
    pub labels: Vec<String>,
    /// Free-form `MemoryMax=` value. None ⇒ no `10-memory.conf` drop-in.
    pub memory_max: Option<String>,
    /// Pinned runner version (e.g. `"2.334.0"`). None ⇒ release-API
    /// resolved at apply time (CreateRunner + recreate UpdateRunner
    /// paths), or inherited from the discovered
    /// `X-Ghars-Effective-Version` annotation for in-place updates
    /// of already-installed runners. Tarball-pinned runners
    /// (`runner_tarball.is_some()`) MUST set this on the runner or
    /// in `[defaults]` — the release-API lookup is skipped for
    /// tarball-pinned and the version string is required to name
    /// the on-disk `bin.X.Y.Z` directory.
    pub runner_version: Option<String>,
    /// Pinned tarball SHA256 (64 hex). Only meaningful with
    /// `runner_version`.
    pub runner_sha256: Option<String>,
    /// Pre-downloaded local tarball (bypasses release-API lookup).
    pub runner_tarball: Option<Utf8PathBuf>,
    /// Resolved auth reference key (e.g. `"pat"`, `"gh-app-prod"`).
    /// Drives the X-Ghars-Auth-Name annotation; the actual `AuthSpec`
    /// is looked up by `apply` via the auth registry.
    pub auth_name: String,
    /// Cache pool bindings — one per referenced pool, in source order.
    /// Carries the resolved kinds + size so the 30-cache-pool drop-in
    /// renders without further lookups.
    pub caches: Vec<EffectiveCacheBinding>,
    /// Cache trust zone (Part 3 / SEC-03).
    pub trust_zone: String,
    /// Network binding. None ⇒ implicit `Open` (host netns) with no
    /// cgroup-BPF policy. Some(b) ⇒ either `Netns` mode (resolved
    /// `NetworkSpec` + allocated /30 in `b.subnet`) or `Open` mode
    /// with at least one cgroup-BPF policy field populated
    /// (`ip_allow` / `ip_deny` / `restrict_address_families`); in the
    /// Open-mode case `b.subnet` is `None` because no per-runner
    /// netns is allocated.
    pub network: Option<EffectiveNetworkBinding>,
    /// Resolved proxy spec (None ⇒ no proxy, no 60-proxy drop-in).
    pub proxy: Option<ProxySpec>,
    /// Resolved hooks spec (None ⇒ no hooks, no 70-hooks drop-in).
    pub hooks: Option<HooksSpec>,
    /// Final hardening overrides (defaults merged with runner-level).
    pub hardening: Hardening,
    /// `AllowedCPUs=` (cgroup v2 cpuset). None ⇒ no 50-numa drop-in.
    pub allowed_cpus: Option<String>,
    /// `AllowedMemoryNodes=` (cgroup v2 cpuset).
    pub allowed_memory_nodes: Option<String>,
    /// Effective operator-declared environment composition after the
    /// `[defaults]` ⇒ `[[runner]]` merge. `vars` is `BTreeMap<String,
    /// String>` so iteration is alphabetical — operator key reorders
    /// in TOML produce identical .env bytes (no spurious in-place
    /// rewrite + restart on cosmetic edits). `path_prepend` and
    /// `path_append` preserve operator source order (defaults entries
    /// first, runner entries appended, dedup defense-in-depth).
    ///
    /// Renders into Sites A (.env file) and B (00-ghars.conf
    /// `Environment=` directives) APPENDED after framework-emitted
    /// keys (LAYER 3 of the composition pipeline). Operator keys that
    /// collide with framework keys (CCACHE_DIR, KTSTR_*, LANG, HOME,
    /// PATH, TMPDIR, SCCACHE_*, HTTP_PROXY etc.) are rejected at
    /// config-load via the deny-list — operator overrides cannot
    /// reach LAYER 3 because they fail validation. See
    /// `crate::validators::validate_environment_spec`.
    ///
    /// Single source of truth for CCACHE_DIR / KTSTR_* / SCCACHE_*
    /// emission lives in `crate::systemd::units` renderers — do not
    /// add a second construction site for framework keys.
    pub environment: EnvironmentSpec,
    /// Spec hash (sha256 of canonical JSON). The generator emits
    /// this verbatim into the X-Ghars-Spec-Hash annotation; computing
    /// it is the loader's responsibility.
    pub spec_hash: String,
    /// Source path that produced this spec (e.g.
    /// `"/etc/ghars/ghars.toml"`). Drives X-Ghars-Config-Source.
    pub config_source: String,
    /// Renderer schema number captured at `lower_to_effective` time
    /// from [`crate::systemd::RENDERER_SCHEMA`]. Participates in the
    /// canonical-JSON `spec_hash` so a ghars binary upgrade that
    /// bumps the constant flips every managed runner's spec_hash,
    /// driving the `apply` in-place rewrite path (which is what
    /// rewrites the on-disk drop-ins to match the new renderer
    /// output). Operators never set this directly. NOT
    /// `#[serde(skip)]` — its participation in the hash domain is
    /// the entire point of the field.
    ///
    /// Deserialize-side defense: `#[serde(default)]` provides the
    /// runtime constant when the field is absent (e.g. older plan
    /// JSON), and `#[serde(deserialize_with)]` consumes any input
    /// value but ALWAYS returns the runtime constant. No future
    /// deserialization site (plan-cache sidecar, replay tool, RPC
    /// interface) can let an operator spoof the schema number and
    /// defeat the hash-participation contract. Serialize path is
    /// unaffected — the runtime value is what `spec_hash` consumes.
    #[serde(
        default = "default_renderer_schema",
        deserialize_with = "renderer_schema_from_runtime"
    )]
    pub renderer_schema: u32,
}

/// One cache pool reference resolved against `[cache_pools.NAME]`. The
/// renderer needs `name` for the unit name (`ghars-cache@NAME`),
/// `kinds` to pick which Environment lines emit, and `size` for the
/// `CCACHE_MAXSIZE` / `SCCACHE_CACHE_SIZE` drop-in values.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct EffectiveCacheBinding {
    /// Pool key (matches `[cache_pools.NAME]`).
    pub name: String,
    /// Kinds the pool serves.
    pub kinds: Vec<CacheKind>,
    /// Pool size as a free-form string (parsed by `bytesize` upstream).
    pub size: String,
    /// Sharing mode (Shared / Isolated). Renderer doesn't currently
    /// branch on this — informational, retained for plan output.
    pub mode: CacheMode,
    /// Pool trust zone (must match runner's `trust_zone`; validated
    /// upstream).
    pub trust_zone: String,
    /// Resolved absolute path to the sccache binary. `Some` iff
    /// `kinds.contains(Sccache)`; `None` for ccache-only pools.
    /// Populated at plan time from `CachePoolSpec.sccache_path` (when
    /// the operator pinned it explicitly) or from auto-detection
    /// (`/usr/local/bin/sccache` then `/usr/bin/sccache`). Renderer
    /// emits this verbatim as the unit's `ExecStart=` when the pool
    /// serves sccache.
    ///
    /// `#[serde(skip)]` keeps this out of `cache_pool_hash` and
    /// `spec_hash`: the resolved value depends on host filesystem
    /// state (which `/usr/{local/,}bin/sccache` is present), not on
    /// the operator's config. Including it in the canonical-JSON
    /// hash would flip the X-Ghars-Spec-Hash annotation between
    /// hosts whose sccache lives at different prefixes, driving
    /// spurious recreate-class plans.
    #[serde(skip, default)]
    pub sccache_path: Option<Utf8PathBuf>,
    /// Resolved absolute path to the sleep binary. `Some` iff the pool
    /// is ccache-only (`!kinds.contains(Sccache)`); `None` when the
    /// pool serves sccache (the sccache server takes `ExecStart` and
    /// sleep is never invoked). Populated at plan time from
    /// `CachePoolSpec.sleep_path` (when the operator pinned it
    /// explicitly) or from auto-detection (`/usr/bin/sleep` then
    /// `/bin/sleep`). Renderer emits this as `ExecStart=PATH infinity`
    /// for ccache-only pools so the unit stays active and its
    /// `CacheDirectory=` remains owned.
    ///
    /// `#[serde(skip)]` for the same reason as `sccache_path` above:
    /// host-resolved value must not feed `cache_pool_hash` or
    /// `spec_hash`.
    #[serde(skip, default)]
    pub sleep_path: Option<Utf8PathBuf>,
    /// Renderer schema number captured at binding-resolution time
    /// from [`crate::systemd::RENDERER_SCHEMA`]. Mirror of
    /// `EffectiveRunnerSpec::renderer_schema` for the cache-pool
    /// hash domain — a renderer change that flips
    /// `render_cache_drop_in` output for the same `(name, kinds,
    /// size, mode, trust_zone)` bumps the constant, which flips
    /// `cache_pool_hash` and drives the in-place pool-rewrite path.
    ///
    /// NOT `#[serde(skip)]` — participation in the `cache_pool_hash`
    /// domain is the entire point of the field. Contrast with
    /// `sccache_path` / `sleep_path` above (host-resolved binary
    /// paths whose value depends on host filesystem layout, not
    /// renderer behavior; those MUST stay `#[serde(skip)]` so the
    /// hash doesn't flip between hosts whose sccache lives at
    /// different prefixes).
    ///
    /// Deserialize-side defense: same shape as
    /// `EffectiveRunnerSpec::renderer_schema` —
    /// `#[serde(deserialize_with)]` consumes any operator-supplied
    /// value but always returns the runtime constant, preventing
    /// future deserialization sites from letting an operator spoof
    /// the schema number and defeat the hash-participation contract.
    #[serde(
        default = "default_renderer_schema",
        deserialize_with = "renderer_schema_from_runtime"
    )]
    pub renderer_schema: u32,
}

/// One network reference resolved against `[network.NAME]`.
/// Produced when there are render-time artifacts to emit:
///
/// - `mode = "netns"` references ALWAYS produce a binding — the
///   namespace bind itself is the load-bearing artifact, so the
///   binding is required even when every cgroup-BPF policy field
///   is empty.
/// - `mode = "open"` references produce a binding ONLY when at
///   least one of `ip_allow` / `ip_deny` /
///   `restrict_address_families` is non-empty. An Open block with
///   all three empty is semantically identical to "no network
///   reference" (no namespace bind, no policy directives) and
///   `lower_to_effective` collapses it back to
///   `EffectiveRunnerSpec.network = None`.
///
/// A runner with NO `[network.NAME]` reference at all leaves
/// `EffectiveRunnerSpec.network == None` directly. The renderer +
/// classifier branch on `spec.mode` to decide which artifacts to
/// emit; under this contract `Some(binding)` means "there are
/// directives to render" uniformly, which keeps Stage 1/Stage 2
/// classifier intuition aligned and avoids spurious `spec_hash`
/// flips on no-op Open blocks.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct EffectiveNetworkBinding {
    /// Network key (matches `[network.NAME]`).
    pub name: String,
    /// Resolved spec.
    pub spec: NetworkSpec,
    /// Allocated /30 for this runner (host side `.x+1`, runner side
    /// `.x+2`). `Some` only for `mode = "netns"` bindings; Open-mode
    /// bindings have no namespace and therefore no /30 of their own,
    /// so the field is `None` and the netns subnet pool is left for
    /// runners that actually need a slot. Drives
    /// `X-Ghars-Netns-Subnet=` + nft rule generation, both gated on
    /// `Some`.
    pub subnet: Option<IpNet>,
}

/// Why a call to `EffectiveNetworkBinding::netns_subnet` could not
/// produce an `IpNet`. Both variants encode code-bug shapes: the
/// lowering pipeline guarantees `Netns ⇔ Some(subnet)` and
/// `Open ⇔ None`, so reachable failures here mean a direct-construct
/// caller (test fixture, future programmatic spec builder) built a
/// contradictory shape. The enum lets each call site (nft.rs,
/// apply/netns.rs) wrap the variant into its own error type with a
/// site-specific message, instead of passing an opaque caller-label
/// string into the helper.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum NetnsSubnetError {
    /// The binding's mode is `Open` — there is no per-runner /30 to
    /// extract. Open-mode runners share the host netns; cgroup-BPF
    /// directives (`IPAddressAllow=` / `IPAddressDeny=` /
    /// `RestrictAddressFamilies=`) apply at the cgroup layer
    /// without a subnet.
    OpenMode,
    /// The binding's mode is `Netns` but `subnet` is `None` — the
    /// mode⇒subnet contract is broken. `lower_to_effective`
    /// allocates a /30 from the v0.1 64-slot pool whenever it
    /// constructs a Netns binding; reaching this variant means a
    /// caller bypassed the lowering pipeline.
    NetnsMissingSubnet,
}

impl EffectiveNetworkBinding {
    /// Extract the netns `/30` subnet from a binding. Returns
    /// `Ok(/30)` only when the binding is Netns mode AND a subnet
    /// is present.
    ///
    /// Centralizes the mode⇒subnet contract check that nft rule
    /// generation and apply-side netns provisioning both perform.
    /// Each call site wraps the returned `NetnsSubnetError` variants
    /// into the error type it needs (`GharsError::Validation` for
    /// the renderer, `GharsError::Apply` for the apply path) with a
    /// site-specific message naming the offending shape and the
    /// runner. The helper itself does not produce a `GharsError` so
    /// callers retain control over the error wrapper, the action
    /// label, and the hint string.
    ///
    /// # Errors
    ///
    /// Returns `NetnsSubnetError::OpenMode` for Open-mode bindings
    /// (no namespace, no /30 to extract) and
    /// `NetnsSubnetError::NetnsMissingSubnet` for Netns bindings
    /// missing a subnet (mode⇒subnet contract violation, code bug).
    pub fn netns_subnet(&self) -> std::result::Result<IpNet, NetnsSubnetError> {
        match (self.spec.mode, self.subnet) {
            (NetworkMode::Netns, Some(s)) => Ok(s),
            (NetworkMode::Netns, None) => Err(NetnsSubnetError::NetnsMissingSubnet),
            (NetworkMode::Open, _) => Err(NetnsSubnetError::OpenMode),
        }
    }
}

/// CPU architecture marker for tarball selection.
#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum Arch {
    /// `x86_64`.
    X86_64,
    /// `aarch64`.
    Aarch64,
}

/// Per-field hardening overrides. Each field is `Option<bool>` (or
/// equivalent) so `None` ≡ "inherit ghars's canonical profile" and
/// `Some(...)` ≡ "explicit override". Driven by the user's real
/// configs being STRICTER than the Python tool in 7+ directives.
#[derive(Debug, Clone, Default, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct Hardening {
    /// `DeviceAllow=/dev/kvm rw`. None ≡ true (Python default).
    pub kvm: Option<bool>,
    /// `RestrictRealtime=`. None ≡ false (Python default; KVM vCPU
    /// `SCHED_FIFO`).
    pub restrict_realtime: Option<bool>,
    /// `ProtectControlGroups=`. None ≡ no (Python default; buck2
    /// nested virt).
    pub protect_control_groups: Option<bool>,
    /// `RestrictSUIDSGID=`. None ≡ true (Python default).
    pub restrict_suid_sgid: Option<bool>,
    /// `PrivateDevices=`. None ≡ true (Python default).
    pub private_devices: Option<bool>,
    /// `PrivateIPC=`. None ≡ true (Python default).
    pub private_ipc: Option<bool>,
    /// `RestrictAddressFamilies=`. Empty Vec ≡ unset; non-empty Vec
    /// emits the directive with the listed AF_ tokens. Composes with
    /// the parallel `NetworkSpec.restrict_address_families` field
    /// across drop-ins (`20-hardening.conf` + `40-network.conf` both
    /// emit a `RestrictAddressFamilies=` line; systemd unions them
    /// at unit-load time per `systemd.exec(5)`). The hardening side
    /// widens the allowlist for every runner regardless of network
    /// mode; the network-spec side narrows it per-`[network.NAME]`
    /// block.
    #[serde(default)]
    pub restrict_address_families: Vec<String>,
    /// Append to the canonical syscall allowlist. Tokens land on the
    /// `SystemCallFilter=@system-service ...` line.
    #[serde(default)]
    pub extra_syscalls: Vec<String>,
    /// `BindReadOnlyPaths` style: `Curated` (Python default, narrow
    /// /etc list) or `Broad` (whole /etc bound).
    #[serde(default)]
    pub etc_bind_style: EtcBindStyle,
    /// APPENDS operator entries to the template's `BindReadOnlyPaths`
    /// set at render time. `None` ≡ use the template's curated set
    /// (or whole /etc per `etc_bind_style`). `Some(list)` widens the
    /// template via a second `BindReadOnlyPaths=` line that systemd
    /// unions with the template's at unit-load time. At the merge
    /// boundary, a runner-side `Some(...)` REPLACES any
    /// `[defaults].hardening.bind_readonly_paths` value (`.or_else()`
    /// pick — runner wins; defaults inherited only when runner-side
    /// is `None`); distinct from `extra_bind_paths` which is additive
    /// across both layers. The reset-on-empty validator forbids a
    /// bare-`=` clear, so operator entries can only widen the
    /// template at render time — narrowing requires a `99-*.conf`
    /// operator drop-in.
    pub bind_readonly_paths: Option<Vec<Utf8PathBuf>>,
    /// Additional `BindReadOnlyPaths` entries APPENDED to the
    /// template's set (or to `bind_readonly_paths` if set). Use this
    /// to keep the defaults but add (e.g.) proxy CA bundles.
    #[serde(default)]
    pub extra_bind_paths: Vec<Utf8PathBuf>,
    /// Additional `CapabilityBoundingSet=` entries (rarely needed).
    #[serde(default)]
    pub extra_capabilities: Vec<String>,
}

/// Operator-declared environment composition for runners. Operator-
/// supplied env vars and PATH additions, merged with framework-emitted
/// built-ins (LANG / CCACHE_DIR / KTSTR_* / SCCACHE_* / HOME / PATH /
/// TMPDIR / HTTP_PROXY family / ACTIONS_RUNNER_HOOK_* and per-binding
/// cache vars). Precedence is framework < defaults < runner, enforced
/// at composition time; framework-owned keys are additionally rejected
/// at config-load via the deny-list in
/// `crate::validators::validate_environment_spec` so operator overrides
/// never reach the renderer.
///
/// The merged result lands in BOTH Site A (.env file consumed by
/// Runner.Listener::LoadAndSetEnv for workflow steps) AND Site B
/// (00-ghars.conf `Environment=` directives consumed by systemd for
/// the runner unit process). The two layers carry the same merged
/// keys; without the both-sites pin a future renderer refactor could
/// silently drop one layer and re-create the LAYER 1/2 drift class.
///
/// Map type rationale: `BTreeMap` for `vars` gives alphabetical
/// iteration order so operator key reorders in TOML produce identical
/// `.env` bytes — no spurious in-place rewrite + restart cycle on
/// cosmetic edits. `spec_hash` is already invariant under reorder via
/// `serde_json::Value`'s BTreeMap-backed Object (see
/// `EffectiveRunnerSpec` doc-comment above), but `.env` byte stability
/// also needs the BTreeMap directly because the renderer iterates in
/// type order.
#[derive(Debug, Clone, Default, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct EnvironmentSpec {
    /// Operator-supplied env vars. Per-key overlay across the
    /// defaults / runner merge: runner-set keys win, then defaults,
    /// then framework built-ins. Validated at config-load against
    /// the deny-list (security-critical LD_*, shell-hijack BASH_ENV
    /// etc., ghars-owned CCACHE_DIR etc., HTTP_PROXY family,
    /// ACTIONS_RUNNER_INPUT_TOKEN, etc.) and the POSIX env-var-name
    /// regex `^[A-Z_][A-Z0-9_]*$`. Values are checked for control
    /// characters (`\n` / `\r` / `\0`) at config-load via the same
    /// `check_identity_field` gate the renderer uses for systemd
    /// directive interpolation. Values containing `%` are
    /// double-escaped (`%%`) in the 00-ghars.conf `Environment=`
    /// emission so systemd's specifier expansion does not consume
    /// operator-literal data; the `.env` emission carries the value
    /// verbatim (Runner.Listener LoadAndSetEnv does not interpret
    /// `%`).
    #[serde(default)]
    pub vars: BTreeMap<String, String>,
    /// Paths prepended to the runner's PATH. Lands BETWEEN the
    /// framework ccache wrappers (`/usr/lib64/ccache`,
    /// `/usr/lib/ccache`) and the per-runner `.cargo/bin` segment.
    /// ccache stays at position 0 unconditionally — operator paths
    /// cannot shadow `gcc` / `cc` and break the compile cache.
    /// Additive across defaults + runner (defaults entries first,
    /// then runner entries, dedup defense-in-depth). Each entry must
    /// be an absolute path (validator rejects relative paths, paths
    /// containing `:` (PATH separator), and control characters).
    #[serde(default)]
    pub path_prepend: Vec<Utf8PathBuf>,
    /// Paths appended to the runner's PATH AFTER the system tail
    /// (`/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:
    /// /bin`). Additive across defaults + runner.
    #[serde(default)]
    pub path_append: Vec<Utf8PathBuf>,
}

/// `BindReadOnlyPaths=` template style — Curated keeps the narrow
/// /etc list, Broad binds the whole /etc tree.
#[derive(Debug, Clone, Copy, Default, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum EtcBindStyle {
    /// Narrow /etc list (Python tool default).
    #[default]
    Curated,
    /// Whole /etc tree bound (user's actual config).
    Broad,
}

/// Proxy configuration. Generates `HTTP_PROXY` / `HTTPS_PROXY` /
/// `NO_PROXY` env vars + an extensible CA-trust env-var list.
#[derive(Debug, Clone, Default, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct ProxySpec {
    /// `HTTP_PROXY` value (e.g. `"http://192.0.2.84:3128"`).
    pub http: Option<String>,
    /// `HTTPS_PROXY` value (often the same URL as `http`).
    pub https: Option<String>,
    /// Hosts/CIDRs to bypass. Emitted as both `NO_PROXY` and
    /// `no_proxy`.
    #[serde(default)]
    pub no_proxy: Vec<String>,
    /// CA-bundle env var bindings — each entry maps an env-var name
    /// to a host file path. Common entries: `NODE_EXTRA_CA_CERTS`,
    /// `REQUESTS_CA_BUNDLE`, `SSL_CERT_FILE`, `CURL_CA_BUNDLE`.
    /// Extensible — operators can add new pairs without ghars schema
    /// changes.
    #[serde(default)]
    pub ca_certs: Vec<CaCertBinding>,
}

impl ProxySpec {
    /// Whether all fields are unset / empty. An empty ProxySpec is
    /// semantically equivalent to no proxy configuration at all —
    /// `render_proxy` returns `Ok(None)` for both `None` and
    /// `Some(empty)`, so the two shapes produce identical render
    /// output. Collapsing `Some(empty)` to `None` at the loader
    /// normalization layer eliminates a spec_hash dark input: pre-
    /// normalization the canonical-JSON of `Some(ProxySpec{..})`
    /// differed from `None` and the two would flip spec_hash on
    /// operator toggle, but the rendered drop-in body bytes were
    /// identical.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.http.is_none()
            && self.https.is_none()
            && self.no_proxy.is_empty()
            && self.ca_certs.is_empty()
    }
}

/// One CA-bundle env-var binding (`env=PATH`) for `[proxy.ca_certs]`.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct CaCertBinding {
    /// Env var name (e.g. `"NODE_EXTRA_CA_CERTS"`).
    pub env: String,
    /// Absolute path to the CA file. Must be readable through the
    /// runner's mount namespace; ghars adds it to
    /// `BindReadOnlyPaths` if needed.
    pub path: Utf8PathBuf,
}

/// Job hooks. Maps to `ACTIONS_RUNNER_HOOK_JOB_STARTED` and
/// `ACTIONS_RUNNER_HOOK_JOB_COMPLETED` env vars on the runner.
#[derive(Debug, Clone, Default, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct HooksSpec {
    /// Path to a host-readable script run before each job.
    pub pre_job: Option<Utf8PathBuf>,
    /// Path to a host-readable script run after each job.
    pub post_job: Option<Utf8PathBuf>,
}

impl HooksSpec {
    /// Whether both hook fields are unset. An empty HooksSpec
    /// produces no `ACTIONS_RUNNER_HOOK_JOB_*` env vars —
    /// `render_hooks` returns `Ok(None)` for both `None` and
    /// `Some(empty)`. Collapsing `Some(empty)` to `None` at the
    /// loader normalization layer eliminates the parallel spec_hash
    /// dark input.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.pre_job.is_none() && self.post_job.is_none()
    }
}

/// Auth source. The `kind` discriminator is serialized as a TOML/JSON tag (e.g.
/// `kind = "pat"`) — `serde(tag = "kind", rename_all = "snake_case")`.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(tag = "kind", rename_all = "snake_case", deny_unknown_fields)]
pub enum AuthSpec {
    /// GitHub App. octocrab handles JWT minting + installation-token
    /// caching.
    GithubApp {
        /// GitHub App ID (numeric).
        app_id: u64,
        /// Installation ID (numeric).
        installation_id: u64,
        /// Path to the App's PEM-encoded private key.
        private_key_path: Utf8PathBuf,
    },
    /// GitHub PAT (any token type with appropriate permissions).
    /// ghars is token-type-agnostic — accepts any GitHub Personal
    /// Access Token the operator provides (classic, fine-grained,
    /// or any future kind) and forwards it to octocrab as a Bearer
    /// credential. GitHub validates server-side. Exactly one of
    /// `token_env` / `token_file` MUST be set; enforced at apply
    /// time by `PatToken::new` (auth.rs).
    Pat {
        /// Read the PAT from this environment variable at apply time.
        token_env: Option<String>,
        /// Read the PAT from this file at apply time. File must be
        /// mode 0600 owned by root.
        token_file: Option<Utf8PathBuf>,
    },
    /// Interactive prompt: print URL, read a pre-minted REGISTRATION
    /// TOKEN (not a PAT) from stdin. The registration token is the
    /// short-lived value GitHub's "Add new self-hosted runner" UI
    /// generates; expires in 1h. TTY required.
    Interactive,
    /// Pre-minted REGISTRATION TOKEN (not a PAT) in a file. Same
    /// short-lived token as `Interactive`, sourced from a file
    /// instead of pasted at apply time.
    TokenFile {
        /// Absolute path to the token file.
        path: Utf8PathBuf,
    },
}

/// Cache pool declaration. ccache via cooperative flock on a shared
/// dir; sccache via per-pool single-server unit; both can co-exist
/// in one pool.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct CachePoolSpec {
    /// Which kinds the pool hosts. Values are `ccache`, `sccache`.
    pub kinds: Vec<CacheKind>,
    /// Pool size as a free-form string parsed by `bytesize` at
    /// validate time (e.g. `"200G"`).
    pub size: String,
    /// Sharing mode — `Shared` (default) lets multiple runners
    /// reference the pool; `Isolated` enforces a single-referencer
    /// validation.
    #[serde(default)]
    pub mode: CacheMode,
    /// Cache trust zone. Default `"default"` — leave unset and the
    /// field is invisible to operators who don't care about cross-
    /// repo poisoning (all runners + pools share the same zone,
    /// validator always passes). Capability stays available for
    /// deployments that DO need it (SEC-03 fix). Validator: for
    /// each cache pool, the `trust_zone` of every runner referencing
    /// it must equal the pool's `trust_zone`; mismatch = config-time
    /// error.
    #[serde(default = "default_trust_zone")]
    pub trust_zone: String,
    /// Optional override for the sccache binary path. Must be
    /// absolute when set (validator-enforced). When omitted, plan-time
    /// resolution auto-detects by probing `/usr/local/bin/sccache`
    /// then `/usr/bin/sccache` via `Path::exists`. Only consulted when
    /// `kinds` contains `Sccache`; ccache-only pools never read this
    /// field. Hit with `Some` to force a specific install location
    /// (e.g. a sidecar /opt prefix).
    #[serde(default)]
    pub sccache_path: Option<Utf8PathBuf>,
    /// Optional override for the sleep binary path. Must be absolute
    /// when set (validator-enforced). When omitted, plan-time
    /// resolution auto-detects by probing `/usr/bin/sleep` then
    /// `/bin/sleep` via `Path::exists`. Only consulted when the pool
    /// is ccache-only (`!kinds.contains(Sccache)`); sccache-serving
    /// pools use the sccache process as the unit's `ExecStart` so sleep
    /// is never invoked.
    #[serde(default)]
    pub sleep_path: Option<Utf8PathBuf>,
}

/// Default trust zone — used by both `RunnerSpec.trust_zone` and
/// `CachePoolSpec.trust_zone` (SEC-03).
fn default_trust_zone() -> String {
    "default".into()
}

/// Per-pool cache kind. ccache, sccache, and ktstr.
#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum CacheKind {
    /// ccache via cooperative flock on a shared dir.
    Ccache,
    /// sccache via per-pool single-server.
    Sccache,
    /// ktstr (kernel scheduler test harness) cache-pool marker.
    /// Currently a forward-compatibility declaration: declaring
    /// `[cache_pools.NAME] kinds = ["ktstr"]` parses cleanly and
    /// passes both validator layers, but does NOT yet gate
    /// runtime behavior. `KTSTR_LOCK_DIR` + `KTSTR_CACHE_DIR` env
    /// vars (rendered at `render_runner_env_file` +
    /// `render_runner_drop_in`) and the
    /// `/var/lib/ghars/<TRUST_ZONE>/.ktstr` dir materialization
    /// (in `execute_create_runner`) are still UNCONDITIONAL for
    /// every runner regardless of binding. Pool-side: ktstr-only
    /// pools currently route through the per-pool `sleep` stub
    /// fall-through branch of `render_cache_drop_in` like
    /// ccache-only pools (no daemon, no `ExecStart` beyond the
    /// idle keepalive). The runtime-gating work — mirroring the
    /// `has_ccache` gate at the env-emission + dir-creation sites
    /// + bumping `RENDERER_SCHEMA` so existing deploys cascade
    /// through the in-place rewrite path — is tracked as a
    /// follow-up task.
    Ktstr,
}

impl CacheKind {
    /// Every `CacheKind` variant — shared iteration target for code
    /// that needs to fan out over the kind set (e.g. the
    /// `validate_no_duplicate_cache_kinds` config-load gate and the
    /// `lower_to_effective` plan-time gate, both of which iterate
    /// here to enforce singleton-per-kind). Adding a variant here
    /// surfaces every consumer at compile time via exhaustive
    /// `match self.label()` arms.
    pub const ALL: &'static [Self] = &[Self::Ccache, Self::Sccache, Self::Ktstr];

    /// Operator-facing label matching the TOML enum-rename
    /// (`#[serde(rename_all = "snake_case")]` above): lowercase
    /// `"ccache"` / `"sccache"` / `"ktstr"`. Used by validator error
    /// messages so the operator sees the same identifier they wrote
    /// in `[cache_pools.NAME].kinds = ["..."]`.
    #[must_use]
    pub fn label(self) -> &'static str {
        match self {
            Self::Ccache => "ccache",
            Self::Sccache => "sccache",
            Self::Ktstr => "ktstr",
        }
    }
}

/// Pool sharing mode. `Shared` is the default; `Isolated` rejects
/// configs where >1 runner references the pool (sccache pools are
/// always shared regardless of this setting).
#[derive(Debug, Clone, Copy, Default, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum CacheMode {
    /// Multiple runners share the pool.
    #[default]
    Shared,
    /// Single runner exclusive.
    Isolated,
}

/// `[network.NAME]` declaration. Drives nft rule generation +
/// per-runner netns artifacts for `mode = "netns"` blocks, and
/// cgroup-BPF policy directives (`IPAddressAllow=` /
/// `IPAddressDeny=` / `RestrictAddressFamilies=`) for either mode
/// when the corresponding fields are populated. A runner with no
/// `[network.NAME]` reference at all uses the host netns
/// implicitly with no extra cgroup-BPF policy; declaring
/// `mode = "open"` explicitly is only useful when the operator
/// wants to add cgroup-BPF / address-family restrictions on top of
/// the host netns.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct NetworkSpec {
    /// Network mode. `Netns` allocates a per-runner network
    /// namespace; `Open` keeps the runner in the host netns.
    pub mode: NetworkMode,

    /// Allowed egress destinations. Each entry: addr (`IpAddr` or
    /// CIDR), port (single / range / set), proto (tcp/udp/both),
    /// optional comment. Maps directly to
    /// `ip daddr ADDR PROTO dport PORT accept`.
    #[serde(default)]
    pub allowed_egress: Vec<EgressRule>,

    /// CIDRs for systemd's `IPAddressAllow=` (cgroup-BPF layer).
    /// Honored in BOTH modes: emitted as the `IPAddressAllow=`
    /// directive which feeds the per-runner cgroup-BPF egress
    /// allowlist. Under `Netns`, this is one of two independent
    /// egress gates — the other being the nft rules generated
    /// from `allowed_egress` above, which enforce port + proto
    /// at the packet layer inside the namespace. The two gates
    /// use different input fields (`ip_allow` vs
    /// `allowed_egress`) and enforce at different layers, so
    /// they are complementary rather than redundant. Under
    /// `Open`, the cgroup-BPF layer is the sole egress gate at
    /// the systemd layer (no namespace, no nft). Runners with
    /// no `[network.NAME]` reference at all emit no cgroup-BPF
    /// policy — see the struct-level doc above.
    #[serde(default)]
    pub ip_allow: Vec<IpNet>,

    /// CIDRs for systemd's `IPAddressDeny=` (cgroup-BPF layer).
    /// Honored in BOTH `Netns` and `Open` modes: emitted as the
    /// `IPAddressDeny=` directive which feeds the per-runner
    /// cgroup-BPF egress denylist. cgroup-BPF and netns are
    /// orthogonal kernel subsystems — the directive applies at
    /// the cgroup layer regardless of whether the runner has its
    /// own netns. Not consumed by `nft` rule generation; see
    /// `ip_allow` above for the cgroup-BPF vs nft layer split.
    #[serde(default)]
    pub ip_deny: Vec<IpNet>,

    /// `AF_*` allowlist for systemd `RestrictAddressFamilies=`. Empty
    /// Vec ≡ unset. Field name mirrors the systemd directive and the
    /// parallel `Hardening.restrict_address_families` field so a
    /// reader of either site sees the same name pointing at the same
    /// underlying directive — `Hardening` widens the allowlist for
    /// every runner regardless of network mode, this field narrows
    /// it per-`[network.NAME]` block (and works in BOTH netns and
    /// open modes since the directive lives at the cgroup layer, not
    /// the namespace layer).
    #[serde(default)]
    pub restrict_address_families: Vec<String>,

    /// DNS resolution policy inside the netns. Default `Forward` (use
    /// the host's systemd-resolved via a `DNSStubListenerExtra=`
    /// binding on the veth IP). Override with
    /// `dns = { mode = "static", servers = [...] }` when the host
    /// doesn't run systemd-resolved or operator wants explicit
    /// upstream nameservers. No no-DNS mode is provided.
    #[serde(default)]
    pub dns: DnsMode,

    /// IPv6 inside the netns. Default `Disabled`. v0.2 will allocate
    /// a /64 from a configurable ULA pool when set to `Enabled`.
    #[serde(default)]
    pub ipv6: Ipv6Mode,
}

/// Network mode. `Netns` ≡ full per-runner network namespace via
/// `ghars-net@RUNNER.service` + veth + nft rules; `Open` ≡ runner
/// shares the host netns (no namespace, no veth, no nft) but may
/// still carry cgroup-BPF policy (`IPAddressAllow=` /
/// `IPAddressDeny=` / `RestrictAddressFamilies=`) on the runner
/// unit. Only `Open` and `Netns` modes are supported.
#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum NetworkMode {
    /// Runner shares the host network namespace. The
    /// `[network.NAME]` block may still carry `ip_allow` /
    /// `ip_deny` / `restrict_address_families` to apply
    /// cgroup-BPF / address-family restrictions on top of the
    /// host netns.
    Open,
    /// Per-runner network namespace via `ghars-net@%i.service`,
    /// with veth + nft rules enforcing `allowed_egress`. Cgroup-BPF
    /// directives layered alongside as defense in depth.
    Netns,
}

/// One egress allow rule. addr is parsed as `IpAddr` or `IpNet` at
/// validate time; bad values reject with serde-derived spans.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct EgressRule {
    /// Destination address. Validate-time parsed as IPv4/IPv6 single
    /// or CIDR (e.g. `"192.168.2.84"` or `"192.168.2.0/24"`).
    pub addr: String,
    /// Destination port (single, set, or range).
    pub port: PortSpec,
    /// L4 protocol. Defaults to `Tcp`.
    #[serde(default)]
    pub proto: Proto,
    /// Optional comment for nft rule generation. Operator-controlled
    /// — sanitized at generate time (SEC-30).
    pub comment: Option<String>,
}

/// Port specification. Single port, set of ports, or inclusive range.
/// Untagged enum — operator writes `port = 53` or `port = [53, 80]`
/// or `port = { start = 1024, end = 65535 }`.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(untagged)]
pub enum PortSpec {
    /// Single port.
    Single(u16),
    /// Set of discrete ports.
    Set(Vec<u16>),
    /// Inclusive range `[start, end]`.
    Range {
        /// Inclusive low end.
        start: u16,
        /// Inclusive high end.
        end: u16,
    },
}

/// L4 protocol token for an `EgressRule`. `Both` emits one rule for
/// each of tcp and udp.
#[derive(Debug, Clone, Copy, Default, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum Proto {
    /// TCP only (default).
    #[default]
    Tcp,
    /// UDP only.
    Udp,
    /// Both TCP and UDP — generator emits two nft rules.
    Both,
}

/// DNS policy inside a Netns runner. Default `Forward` uses the
/// host's systemd-resolved via `DNSStubListenerExtra=` on the veth
/// IP; `Static` lists explicit upstream nameservers and bypasses
/// systemd-resolved.
///
/// `serde(tag = "mode", content = "servers")` matches the design
/// example `dns = { mode = "static", servers = ["1.1.1.1"] }`.
#[derive(Debug, Clone, Default, Serialize, Deserialize, PartialEq, Eq)]
#[serde(
    tag = "mode",
    content = "servers",
    rename_all = "snake_case",
    deny_unknown_fields
)]
pub enum DnsMode {
    /// v1 default. Use the host's systemd-resolved via the veth.
    /// Preflight verifies systemd-resolved is active.
    #[default]
    Forward,
    /// Explicit nameservers. Validator rejects empty list.
    Static {
        /// One or more upstream DNS server IPs.
        servers: Vec<IpAddr>,
    },
}

/// Render `DnsMode` to the operator-facing annotation form used in
/// `X-Ghars-Dns=` (00-ghars.conf drop-in) and `FieldChange` before/
/// after values: `forward` for `Forward`, `static:<comma-csv>` for
/// `Static { servers }`. Matches the plain-string convention of
/// every other `X-Ghars-*` annotation (`X-Ghars-Network-Mode=netns`,
/// `X-Ghars-Labels=foo,bar`) rather than serde-JSON — JSON for
/// `Static` produces a nested `{"mode":"static","servers":{"servers":
/// [...]}}` shape (struct-variant + tag+content serde quirk) that
/// is ugly in `systemctl cat` and inconsistent with the rest of the
/// annotation surface.
///
/// Free fn (not `impl DnsMode` method) so `.map(dns_to_annotation)`
/// composition at [`crate::plan::classify`] works without closure
/// indirection.
#[must_use]
pub(crate) fn dns_to_annotation(dns: &DnsMode) -> String {
    match dns {
        DnsMode::Forward => "forward".to_owned(),
        DnsMode::Static { servers } => {
            let joined: Vec<String> = servers.iter().map(|ip| ip.to_string()).collect();
            format!("static:{}", joined.join(","))
        }
    }
}

/// Inverse of [`dns_to_annotation`] for the on-disk
/// `X-Ghars-Dns=` annotation: `forward` → `Forward`,
/// `static:<comma-csv>` → `Static { servers }`. Returns `None` for
/// malformed input (unknown prefix, unparseable IP), matching the
/// absent-annotation semantics in [`crate::plan::classify`] — the
/// classifier skips its dns comparison rather than crashing on a
/// hand-edited drop-in or a future schema mismatch.
///
/// `static:` with an empty server list parses to `Static { servers:
/// vec![] }`, but validators reject that at config-load
/// ([`crate::validators::validate_dns_mode`]) — round-trip safety
/// here matches whatever the renderer emitted.
///
/// Non-empty unparseable input emits a `tracing::warn!` so an
/// operator who hand-edited the drop-in or upgraded across an
/// incompatible annotation format gets a journal hint rather than
/// a silent skip. Exactly empty input (`""`) is silent — treated
/// identically to absent annotation, the legacy-runner path.
/// Whitespace-only input (e.g. `" "`) is NOT empty at the helper
/// boundary and DOES warn; whitespace IS a value, just an
/// unrecognized one.
///
/// NOTE on the end-to-end body-parse path: `ParsedUnit::from_text`
/// trims `value` before storing it in the section, so an on-disk
/// drop-in body containing `X-Ghars-Dns= ` (whitespace value) is
/// silently flattened to `""` upstream of this helper and reaches
/// `dns_from_annotation` as the empty string — taking the silent
/// legacy-runner path, NOT the whitespace-warn path. The
/// whitespace-warn contract is enforceable only for direct
/// callers (helper-level tests, future synthetic call sites)
/// whose input bypasses the systemd-unit parser.
#[must_use]
pub(crate) fn dns_from_annotation(s: &str) -> Option<DnsMode> {
    if s == "forward" {
        return Some(DnsMode::Forward);
    }
    let Some(rest) = s.strip_prefix("static:") else {
        if !s.is_empty() {
            tracing::warn!(
                value = %s,
                "X-Ghars-Dns: unrecognized prefix; expected `forward` or `static:<csv>` — skipping dns comparison"
            );
        }
        return None;
    };
    if rest.is_empty() {
        return Some(DnsMode::Static { servers: Vec::new() });
    }
    let parsed: Option<Vec<IpAddr>> =
        rest.split(',').map(|t| t.parse::<IpAddr>().ok()).collect();
    if parsed.is_none() {
        tracing::warn!(
            value = %s,
            "X-Ghars-Dns: `static:` payload contains an unparseable IP — skipping dns comparison"
        );
    }
    parsed.map(|servers| DnsMode::Static { servers })
}

/// Render `Ipv6Mode` to the operator-facing annotation form used in
/// `X-Ghars-Ipv6=` (00-ghars.conf drop-in): `disabled` / `enabled`.
/// Plain snake_case enum string matching the X-Ghars-Network-Mode
/// convention.
///
/// Free fn (symmetric with [`dns_to_annotation`]) — keeps the
/// dns/ipv6 helper pair shaped uniformly.
#[must_use]
pub(crate) fn ipv6_to_annotation(ipv6: Ipv6Mode) -> &'static str {
    match ipv6 {
        Ipv6Mode::Disabled => "disabled",
        Ipv6Mode::Enabled => "enabled",
    }
}

/// Inverse of [`ipv6_to_annotation`] for the on-disk
/// `X-Ghars-Ipv6=` annotation: `disabled` → `Disabled`,
/// `enabled` → `Enabled`. Returns `None` for malformed input.
///
/// Non-empty unparseable input emits a `tracing::warn!`; exactly
/// empty input (`""`) is silent (the legacy-runner path).
/// Whitespace-only input warns at the helper boundary — it's a
/// value, just an unrecognized one.
///
/// NOTE on the end-to-end body-parse path: same upstream-trim
/// caveat as [`dns_from_annotation`] — `ParsedUnit::from_text`
/// strips whitespace from values, so an on-disk
/// `X-Ghars-Ipv6= ` body reaches this helper as `""` and takes
/// the silent legacy-runner path. The whitespace-warn fires only
/// for direct callers.
#[must_use]
pub(crate) fn ipv6_from_annotation(s: &str) -> Option<Ipv6Mode> {
    match s {
        "disabled" => Some(Ipv6Mode::Disabled),
        "enabled" => Some(Ipv6Mode::Enabled),
        "" => None,
        other => {
            tracing::warn!(
                value = %other,
                "X-Ghars-Ipv6: expected `disabled` or `enabled` — skipping ipv6 comparison"
            );
            None
        }
    }
}

/// IPv6 inside the netns. Default `Disabled`. v0.2 will support
/// `Enabled` with ULA allocation.
#[derive(Debug, Clone, Copy, Default, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum Ipv6Mode {
    /// IPv6 disabled inside the netns.
    #[default]
    Disabled,
    /// Reserved for v0.2; v0.1 apply errors with "IPv6 inside netns
    /// is V0.2 — set ipv6 = disabled or omit".
    Enabled,
}

/// Load + parse the config file at `path` and run structural
/// validation.
///
/// # Errors
///
/// Returns `GharsError::Config` on parse failure and
/// `GharsError::Validation` on structural / cross-reference failure.
pub fn load(_path: &camino::Utf8Path) -> crate::Result<Config> {
    todo!("config loader")
}

/// Validate every `[network.NAME]` block in `config` using the
/// validators in `crate::validators`. Each block is checked against
/// the mode-scoped invariants (Netns requires egress-or-ip_allow;
/// Open rejects `allowed_egress` / non-Forward `dns` /
/// `ipv6 = Enabled`) and the per-rule shape validators (egress rule
/// address + port shape, DNS mode). Iterates the `cfg.networks`
/// `IndexMap` in source order and returns on the first failure —
/// matches `load`'s contract; multi-error reporting is a separate
/// feature.
///
/// Called by `cli::load_config` (alongside the four other post-load
/// validators that live in `cli.rs`) so every CLI entry point that
/// accepts a Config — `cmd_validate`, `cmd_plan`, `cmd_apply`, `cmd_status`,
/// `cmd_add` — runs this gate uniformly. Each network's per-rule errors
/// carry the network name in the message so the operator can locate
/// the offending block.
///
/// # Errors
///
/// Returns `GharsError::Validation` on the first failing rule. The
/// message is prefixed with `[network.NAME]:` so the operator sees
/// which block caused the failure.
pub(crate) fn validate_networks(cfg: &Config) -> Result<()> {
    for (name, spec) in &cfg.networks {
        crate::validators::validate_network_spec(spec)
            .map_err(|e| crate::error::prepend_validation_scope(&format!("[network.{name}]"), e))?;
    }
    Ok(())
}

/// Validate every operator-declared environment block in `config` —
/// `[defaults.environment]` and every `[[runner]].environment`. Calls
/// `crate::validators::validate_environment_spec` per block, prepending
/// the scope (`[defaults.environment]:` / `[runner.NAME.environment]:`)
/// so the operator can locate the offending block.
///
/// # Errors
///
/// Returns `GharsError::Validation` on the first failing key / value /
/// path entry. The error names the offending input + tier rationale
/// (security-critical / shell-hijack / ghars-owned / POSIX-shape /
/// path-syntax) so the operator learns the security model from the
/// rejection.
pub(crate) fn validate_environments(cfg: &Config) -> Result<()> {
    crate::validators::validate_environment_spec(&cfg.defaults.environment)
        .map_err(|e| crate::error::prepend_validation_scope("[defaults.environment]", e))?;
    for runner in &cfg.runners {
        crate::validators::validate_environment_spec(&runner.environment).map_err(|e| {
            crate::error::prepend_validation_scope(
                &format!("[runner.{}.environment]", runner.name),
                e,
            )
        })?;
    }
    Ok(())
}

/// Validate every operator-set `runner_version` field in `config` —
/// `[defaults].runner_version` and every `[[runner]].runner_version`.
/// Calls `crate::validators::validate_version` (X.Y.Z form gate) per
/// value, prepending the scope (`[defaults]:` / `[runner.NAME]:`)
/// so the operator can locate the offending block.
///
/// Closes the gap where operator typos like `"2.334.0 "` (trailing
/// space) or `"2.334"` (missing patch) propagate through merge +
/// lowering and land as literal directory names on disk (`bin.2.334.0 /`)
/// before any error surfaces. The `validate_version` helper itself
/// already lives in `crate::validators`; this wrapper exists so the
/// `cli::load_config` gate chain can invoke it uniformly with the
/// other config-load validators.
///
/// Note: this gate does NOT cover the release-API resolution path
/// (`crate::github::resolve_plan_releases`), which already runs
/// `validate_version` on every returned version string per the
/// `resolve_release_for_runner` impl. Operators whose `runner_version`
/// is `None` (release-API-resolved at apply time) inherit that
/// downstream validation. The wrapper here is the missing config-load
/// gate for OPERATOR-SET values.
///
/// # Errors
///
/// Returns `GharsError::Validation` on the first failing value with
/// the scope prefix naming the offending block.
pub(crate) fn validate_runner_versions(cfg: &Config) -> Result<()> {
    if let Some(v) = &cfg.defaults.runner_version {
        crate::validators::validate_version(v)
            .map_err(|e| crate::error::prepend_validation_scope("[defaults]", e))?;
    }
    for runner in &cfg.runners {
        if let Some(v) = &runner.runner_version {
            crate::validators::validate_version(v).map_err(|e| {
                crate::error::prepend_validation_scope(
                    &format!("[runner.{}]", runner.name),
                    e,
                )
            })?;
        }
    }
    Ok(())
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used)]
mod tests {
    use super::*;
    use ipnet::IpNet;

    fn netns_spec(allowed: Vec<EgressRule>) -> NetworkSpec {
        NetworkSpec {
            mode: NetworkMode::Netns,
            allowed_egress: allowed,
            ip_allow: vec![],
            ip_deny: vec![],
            restrict_address_families: vec![],
            dns: DnsMode::default(),
            ipv6: Ipv6Mode::default(),
        }
    }

    #[test]
    fn validate_networks_propagates_per_network_failures() {
        // A bad EgressRule.port=0 inside a [network.ci-net] block must
        // surface with the network name in the error message so the
        // operator can find the offending block.
        let mut cfg = Config::default();
        cfg.networks.insert(
            "ci-net".into(),
            netns_spec(vec![EgressRule {
                addr: "10.0.0.1".into(),
                port: PortSpec::Single(0),
                proto: Proto::default(),
                comment: None,
            }]),
        );
        let err = validate_networks(&cfg).expect_err("must reject");
        let msg = format!("{err}");
        assert!(msg.contains("[network.ci-net]"));
        assert!(msg.contains("port 0"));
    }

    #[test]
    fn validate_networks_propagates_dns_static_empty() {
        // Static DNS with empty servers must reject and identify the
        // network.
        let mut cfg = Config::default();
        let mut spec = netns_spec(vec![EgressRule {
            addr: "10.0.0.1".into(),
            port: PortSpec::Single(443),
            proto: Proto::default(),
            comment: None,
        }]);
        spec.dns = DnsMode::Static { servers: vec![] };
        cfg.networks.insert("isolated".into(), spec);
        let err = validate_networks(&cfg).expect_err("must reject");
        assert!(format!("{err}").contains("[network.isolated]"));
    }

    #[test]
    fn validate_networks_accepts_valid_setup() {
        let mut cfg = Config::default();
        cfg.networks.insert(
            "ok".into(),
            NetworkSpec {
                mode: NetworkMode::Netns,
                allowed_egress: vec![EgressRule {
                    addr: "192.168.2.84".into(),
                    port: PortSpec::Single(3128),
                    proto: Proto::default(),
                    comment: Some("squid proxy".into()),
                }],
                ip_allow: vec!["192.168.2.84/32".parse::<IpNet>().unwrap()],
                ip_deny: vec![],
                restrict_address_families: vec!["AF_UNIX".into(), "AF_INET".into()],
                dns: DnsMode::Forward,
                ipv6: Ipv6Mode::Disabled,
            },
        );
        validate_networks(&cfg).unwrap();
    }

    #[test]
    fn validate_networks_with_no_networks_is_no_op() {
        // Open-mode runners don't get a [network.NAME] block at all.
        // Empty IndexMap should validate cleanly.
        let cfg = Config::default();
        validate_networks(&cfg).unwrap();
    }

    #[test]
    fn validate_networks_rejects_bad_egress_comment_via_toml() {
        // SEC-30 end-to-end: parse a TOML config that carries an
        // EgressRule.comment containing the canonical attack char
        // (`"`), feed it through validate_networks, and assert that
        //   1. the validator REJECTS it,
        //   2. the error names the offending network block (the
        //      `[network.NAME]:` prefix added by validate_networks),
        //   3. the error mentions the disallowed-character class so
        //      the operator can locate the offender in their TOML.
        // This pins the full deserialize → validate → reject path
        // that earlier convergence flagged as not exercised end-to-end.
        let toml_text = r#"
            [defaults]

            [network.ci-net]
            mode = "netns"
            allowed_egress = [
              { addr = "1.2.3.4", port = 80, comment = "bad\"quote" }
            ]
            ip_allow = []
            ip_deny = []
        "#;
        let cfg: Config = toml::from_str(toml_text).expect("TOML must parse");
        let err = validate_networks(&cfg).expect_err("must reject bad comment");
        let msg = format!("{err}");
        assert!(
            msg.contains("[network.ci-net]"),
            "error must name the network block; got: {msg}"
        );
        assert!(
            msg.contains("disallowed character"),
            "error must point at the comment validator; got: {msg}"
        );
    }

    #[test]
    fn validate_runner_versions_rejects_defaults_typo() {
        // Operator typo "2.334" (missing patch) at [defaults] must
        // reject at config-load with the [defaults] scope prefix.
        let mut cfg = Config::default();
        cfg.defaults.runner_version = Some("2.334".into());
        let err = validate_runner_versions(&cfg).expect_err("malformed defaults version must reject");
        let msg = format!("{err}");
        assert!(
            msg.contains("[defaults]"),
            "error must name the [defaults] block; got: {msg}"
        );
        assert!(
            msg.contains("X.Y.Z"),
            "error must mention X.Y.Z form expectation; got: {msg}"
        );
    }

    #[test]
    fn validate_runner_versions_rejects_per_runner_typo_with_runner_scope() {
        // Operator typo "2.334.0 " (trailing space) on a specific
        // runner must reject with [runner.NAME] scope so operator
        // finds the offending [[runner]] block.
        let mut cfg = Config::default();
        cfg.runners.push(RunnerSpec {
            name: "buckos".into(),
            count: None,
            url: "https://github.com/example/buckos".into(),
            auth: None,
            labels: vec![],
            memory_max: None,
            runner_version: Some("2.334.0 ".into()),
            runner_sha256: None,
            runner_tarball: None,
            arch: None,
            caches: vec![],
            trust_zone: "default".into(),
            network: None,
            proxy: None,
            hooks: None,
            hardening: Hardening::default(),
            allowed_cpus: None,
            allowed_memory_nodes: None,
            environment: EnvironmentSpec::default(),
        });
        let err = validate_runner_versions(&cfg)
            .expect_err("trailing-space version must reject");
        let msg = format!("{err}");
        assert!(
            msg.contains("[runner.buckos]"),
            "error must name the [runner.NAME] block; got: {msg}"
        );
        assert!(
            msg.contains("X.Y.Z"),
            "error must mention X.Y.Z form; got: {msg}"
        );
    }

    #[test]
    fn validate_runner_versions_accepts_valid_x_y_z() {
        // Positive case: well-formed runner_version values on both
        // sides pass cleanly.
        let mut cfg = Config::default();
        cfg.defaults.runner_version = Some("2.321.0".into());
        cfg.runners.push(RunnerSpec {
            name: "buckos".into(),
            count: None,
            url: "https://github.com/example/buckos".into(),
            auth: None,
            labels: vec![],
            memory_max: None,
            runner_version: Some("2.334.0".into()),
            runner_sha256: None,
            runner_tarball: None,
            arch: None,
            caches: vec![],
            trust_zone: "default".into(),
            network: None,
            proxy: None,
            hooks: None,
            hardening: Hardening::default(),
            allowed_cpus: None,
            allowed_memory_nodes: None,
            environment: EnvironmentSpec::default(),
        });
        validate_runner_versions(&cfg).expect("valid X.Y.Z versions must pass");
    }

    #[test]
    fn renderer_schema_deserialize_ignores_spoofed_value_and_returns_runtime_const() {
        // Defense-in-depth: a future deserialization site (plan-cache
        // sidecar, replay tool, RPC) consuming JSON that an operator
        // could craft must NOT be able to spoof the renderer_schema
        // field to bypass the hash-participation contract. The
        // `#[serde(deserialize_with)]` shim consumes the operator-
        // supplied u32 then returns the runtime constant
        // unconditionally.
        let runtime = crate::systemd::RENDERER_SCHEMA;
        // Use a value guaranteed != runtime constant (u32::MAX is
        // far past any plausible RENDERER_SCHEMA value).
        let spoofed: u32 = u32::MAX;
        assert_ne!(
            spoofed, runtime,
            "test fixture sanity: spoofed value must differ from runtime constant"
        );

        // EffectiveCacheBinding has the narrower deserialize surface;
        // use it for the smoke test rather than EffectiveRunnerSpec
        // (which has many more required fields).
        let json = format!(
            r#"{{
                "name": "build",
                "kinds": ["ccache"],
                "size": "10G",
                "mode": "shared",
                "trust_zone": "default",
                "renderer_schema": {spoofed}
            }}"#
        );
        let binding: EffectiveCacheBinding =
            serde_json::from_str(&json).expect("must deserialize");
        assert_eq!(
            binding.renderer_schema, runtime,
            "deserialize_with must drop operator-supplied {spoofed} and return runtime constant {runtime}; got {actual}",
            actual = binding.renderer_schema
        );
    }

    #[test]
    fn renderer_schema_deserialize_fills_runtime_const_when_field_missing() {
        // The `#[serde(default = "default_renderer_schema")]` shim
        // covers the case where older plan JSON (or a future replay
        // tool stripping the field) omits renderer_schema entirely.
        // Without it, deserialize would error on the missing field;
        // with it, the runtime constant fills in.
        let runtime = crate::systemd::RENDERER_SCHEMA;
        let json = r#"{
            "name": "build",
            "kinds": ["ccache"],
            "size": "10G",
            "mode": "shared",
            "trust_zone": "default"
        }"#;
        let binding: EffectiveCacheBinding =
            serde_json::from_str(json).expect("must deserialize with missing renderer_schema");
        assert_eq!(
            binding.renderer_schema, runtime,
            "missing renderer_schema must default to runtime constant"
        );
    }

    #[test]
    fn validate_runner_versions_accepts_none_on_both_sides() {
        // Both sides unset is the common operator pattern (release-
        // API resolution at apply time). Must pass cleanly so
        // operators that don't pin a version aren't gated here.
        let mut cfg = Config::default();
        cfg.runners.push(RunnerSpec {
            name: "buckos".into(),
            count: None,
            url: "https://github.com/example/buckos".into(),
            auth: None,
            labels: vec![],
            memory_max: None,
            runner_version: None,
            runner_sha256: None,
            runner_tarball: None,
            arch: None,
            caches: vec![],
            trust_zone: "default".into(),
            network: None,
            proxy: None,
            hooks: None,
            hardening: Hardening::default(),
            allowed_cpus: None,
            allowed_memory_nodes: None,
            environment: EnvironmentSpec::default(),
        });
        validate_runner_versions(&cfg).expect("None on both sides must pass (release-API path)");
    }

    #[test]
    fn validate_networks_accepts_safe_egress_comment_via_toml() {
        // Positive E2E pair for the rejection test above: a comment
        // that uses only safe-set chars (`+` and `/` exercised
        // explicitly to pin the post-`+`-readd allowlist) must
        // pass through validate_networks → validate_egress_rule →
        // validate_egress_comment cleanly.
        let toml_text = r#"
            [defaults]

            [network.ci-net]
            mode = "netns"
            allowed_egress = [
              { addr = "8.8.8.8", port = 53, comment = "primary+secondary 8.8.4.4/32" }
            ]
            ip_allow = []
            ip_deny = []
        "#;
        let cfg: Config = toml::from_str(toml_text).expect("TOML must parse");
        validate_networks(&cfg).expect("safe comment must pass");
    }
}
