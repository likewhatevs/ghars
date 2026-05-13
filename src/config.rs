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

use std::net::IpAddr;

use camino::Utf8PathBuf;
use indexmap::IndexMap;
use ipnet::IpNet;
use serde::{Deserialize, Serialize};

use crate::Result;

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
    /// arch (uname -m) (#39).
    pub arch: Option<Arch>,
    /// Default per-field hardening overrides. Each runner can override
    /// further; `Hardening`'s `Default` impl is "all None" → inherit
    /// the canonical Python-tool profile (#41).
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

    /// CPU architecture override. None ≡ defaults.arch ≡ host arch
    /// (#39).
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
    /// `defaults.hardening` (#41).
    #[serde(default)]
    pub hardening: Hardening,

    /// `AllowedCPUs=` (cgroup v2 cpuset). Free-form CPU list parsed
    /// at validate time (e.g. `"0-15"`).
    pub allowed_cpus: Option<String>,
    /// `AllowedMemoryNodes=` (cgroup v2 cpuset).
    pub allowed_memory_nodes: Option<String>,
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
    /// resolved at plan time.
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
    /// Spec hash (sha256 of canonical JSON). The generator emits
    /// this verbatim into the X-Ghars-Spec-Hash annotation; computing
    /// it is the loader's responsibility.
    pub spec_hash: String,
    /// Source path that produced this spec (e.g.
    /// `"/etc/ghars/ghars.toml"`). Drives X-Ghars-Config-Source.
    pub config_source: String,
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

/// CPU architecture marker for tarball selection (#39).
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
/// configs being STRICTER than the Python tool in 7+ directives
/// (#41).
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
    /// Explicit `BindReadOnlyPaths` replacement list. None ≡ use the
    /// template's curated set (or whole /etc per `etc_bind_style`).
    /// Some(list) ≡ REPLACE the template's `BindReadOnlyPaths` entirely
    /// (the reset-on-empty validator gates safety).
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

/// `BindReadOnlyPaths=` template style — Curated keeps the narrow
/// /etc list, Broad binds the whole /etc tree (#41).
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
    /// `HTTP_PROXY` value (e.g. `"http://192.168.2.84:3128"`).
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
/// `ACTIONS_RUNNER_HOOK_JOB_COMPLETED` env vars on the runner
/// (#40).
#[derive(Debug, Clone, Default, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct HooksSpec {
    /// Path to a host-readable script run before each job.
    pub pre_job: Option<Utf8PathBuf>,
    /// Path to a host-readable script run after each job.
    pub post_job: Option<Utf8PathBuf>,
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

/// Per-pool cache kind. ccache and sccache only.
#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum CacheKind {
    /// ccache via cooperative flock on a shared dir.
    Ccache,
    /// sccache via per-pool single-server.
    Sccache,
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
    /// Honored in BOTH modes: under `Netns` emitted alongside the
    /// nft rules as defense in depth, under `Open` it is the sole
    /// egress allowlist at the systemd layer (no namespace, no
    /// nft).
    #[serde(default)]
    pub ip_allow: Vec<IpNet>,

    /// CIDRs for systemd's `IPAddressDeny=` (cgroup-BPF layer).
    /// Honored in both `Netns` and `Open` modes — the directive
    /// applies at the cgroup layer regardless of whether the
    /// runner has its own netns.
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

/// IPv6 inside the netns. Default `Disabled`. v0.2 will support
/// `Enabled` with ULA allocation (#56).
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
