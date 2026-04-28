//! Config schema (TOML-driven) and `[defaults]` merge logic.
//!
//! Design spec: Part 3 (`config.rs`) and Part 4 (TOML schema + example).
//!
//! All public types are serde-derived for round-trip via TOML and JSON
//! (the latter for `--json` plan output and snapshot tests). Each
//! struct uses `deny_unknown_fields` so typos at the operator's TOML
//! surface fail at load time rather than silently dropping to default.
//! (F19 — "won't fix": forward-evolving schema is handled by adding
//! fields with `#[serde(default)]`, not by tolerating unknown keys.)
//!
//! The actual config loader (`load`) and the count-expansion + defaults-
//! merge functions are stubbed and land in subsequent B1 tasks.

use std::net::IpAddr;

use camino::Utf8PathBuf;
use indexmap::IndexMap;
use ipnet::IpNet;
use serde::{Deserialize, Serialize};

use crate::Result;

/// Identifier regex shared by runner names, auth keys, cache pool keys,
/// network keys: `^[a-z]([a-z0-9-]*[a-z0-9])?$`. One rule everywhere
/// (Part 3 / F11).
pub const IDENTIFIER_REGEX: &str = r"^[a-z]([a-z0-9-]*[a-z0-9])?$";

/// Maximum identifier length (after the `-N` suffix is appended for
/// count blocks). 64 chars (Part 3 / F11).
pub const IDENTIFIER_MAX_LEN: usize = 64;

/// Top-level config (parsed from `/etc/ghars/ghars.toml`).
///
/// `[[runner]]` blocks hold both literal-named runners (`count` unset
/// or `1`) and prefix runners (`count > 1` expanded to `name-1` ..
/// `name-N`). `RunnerGroupSpec` and `RunnerOverride` are not part of
/// the schema — F76 amended (Part 3 / Part 4).
#[derive(Debug, Clone, Default, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct Config {
    /// Global defaults inherited by every `[[runner]]` (Part 3).
    #[serde(default)]
    pub defaults: Defaults,

    /// `[auth.NAME]` table — keyed by identifier. The only place auth
    /// is declared; runners reference one by name (F12).
    #[serde(default)]
    pub auth: IndexMap<String, AuthSpec>,

    /// `[cache_pools.NAME]` table — keyed by identifier. ccache and/or
    /// sccache pools (F47, F50, F51, F68).
    #[serde(default)]
    pub cache_pools: IndexMap<String, CachePoolSpec>,

    /// `[network.NAME]` table — keyed by identifier. Open mode is
    /// implicit (a runner with no `network` reference uses the host
    /// netns); explicit `[network.NAME]` entries declare Netns mode
    /// (F75 amended).
    #[serde(default, rename = "network")]
    pub networks: IndexMap<String, NetworkSpec>,

    /// Top-level proxy config — singleton. Most deployments use one
    /// proxy. Per-runner overrides via `[[runner]].proxy` (R2 / #38).
    #[serde(default)]
    pub proxy: Option<ProxySpec>,

    /// Top-level job hooks — singleton. Per-runner overrides via
    /// `[[runner]].hooks` (R3 / #40).
    #[serde(default)]
    pub hooks: Option<HooksSpec>,

    /// `[[runner]]` array. Each entry produces 1 (no `count`) or N
    /// (count = N) effective runners after expansion (F76 amended).
    #[serde(default, rename = "runner")]
    pub runners: Vec<RunnerSpec>,
}

/// Global defaults inherited field-by-field by every runner. The
/// merge rules are documented in Part 3's "Defaults merge rules"
/// table; the implementation lives in the merge function (B1
/// follow-up).
#[derive(Debug, Clone, Default, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct Defaults {
    /// Default user override. NOT set in v0.1 — each runner gets an
    /// auto-generated `ghars-RUNNERNAME` system user for cross-runner
    /// isolation (SEC-27 fix). Setting `user` here forces a shared UID
    /// across ALL runners; apply emits a `WARNING: shared UID disables
    /// cross-runner isolation`.
    pub user: Option<String>,
    /// Default state-dir prefix (typically `/var/lib/ghars`).
    pub prefix: Option<Utf8PathBuf>,
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
    /// Default `[network.NAME]` reference. None ≡ implicit Open mode.
    pub network: Option<String>,
    /// Default CPU architecture for tarball selection. None ≡ host
    /// arch (uname -m) (#39).
    pub arch: Option<Arch>,
    /// Default per-field hardening overrides. Each runner can override
    /// further; `Hardening`'s `Default` impl is "all None" → inherit
    /// the canonical Python-tool profile (#41).
    #[serde(default)]
    pub hardening: Hardening,
    // F72: no `slice` field. All ghars-managed units use
    // `Slice=system.slice` unconditionally.
}

/// One `[[runner]]` declaration. When `count` is None or 1 the
/// `name` is the literal runner name; when `count > 1` it is the
/// prefix and ghars expands to `name-1` .. `name-{count}` (F76
/// amended — `RunnerGroupSpec` and `RunnerOverride` are removed).
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
    /// `[[runner]] name = "..."` block elsewhere (F76 amended).
    #[serde(default)]
    pub count: Option<u32>,

    /// Repo or org URL (e.g. `https://github.com/example/buckos`).
    pub url: String,

    /// Reference to a key in `[auth.NAME]`. The ONLY way to specify
    /// auth on a runner — token paths are not declared inline (F12).
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

    /// User override (rarely set — auto-`ghars-RUNNERNAME` is the
    /// secure default).
    pub user: Option<String>,
    /// State-dir prefix override.
    pub prefix: Option<Utf8PathBuf>,

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
    /// (host netns) (F16, F75 amended).
    pub network: Option<String>,

    /// Per-runner proxy override (replaces top-level `[proxy]` for
    /// this runner). None ≡ inherit top-level `[proxy]` or no proxy
    /// (R2 / #38).
    pub proxy: Option<ProxySpec>,

    /// Per-runner hooks override. None ≡ inherit top-level `[hooks]`
    /// or none (R3 / #40).
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
    // F72: no `slice` field. All units use Slice=system.slice
    // unconditionally.
}

/// A runner spec after count-expansion + `[defaults]` merge. Plan/apply
/// consume this; the count expander produces one `EffectiveRunnerSpec`
/// per generated runner. The merge logic lives with the loader (B1
/// follow-up); the fields below are the SHAPE that the unit-text
/// generator (B2 / Part 9) and plan engine (B3 / Part 8) require.
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
    /// Resolved system user (`ghars-NAME` by default; explicit override
    /// when `defaults.user` or `runner.user` was set).
    pub user: String,
    /// State-dir prefix (typically `/var/lib/ghars`).
    pub prefix: Utf8PathBuf,
    /// Effective labels after `concat(defaults.labels, runner.labels)`
    /// + dedup (preserves order). Empty after merge ⇒ defaults to
    /// `[name]` per Python parity (`install_gha_runner.py:1627`, F34).
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
    /// Network binding. None ⇒ implicit `Open` (host netns); Some(b) ⇒
    /// `Netns` mode with the resolved `NetworkSpec` + allocated /30.
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
    /// Spec hash (sha256 of canonical JSON; F17). The generator emits
    /// this verbatim into the X-Ghars-Spec-Hash annotation; computing
    /// it is the loader's responsibility.
    pub spec_hash: String,
    /// SHA256 of the runsvc.sh script that was extracted into
    /// `<prefix>/<name>/runsvc.sh` from the runner tarball. Format
    /// `"sha256:HEX"` (lowercase hex). Drives the
    /// `X-Ghars-Runsvc-Sha256` annotation in the `00-ghars.conf`
    /// drop-in (Part 17 SEC-02). The runsvc-wrapper binary reads this
    /// at unit start, recomputes sha256 of the on-disk
    /// `/var/lib/ghars/<name>/runsvc.sh`, and refuses to exec on
    /// mismatch. Empty string until the tarball install phase records
    /// the digest (apply.rs `execute_create_runner` wires it in).
    ///
    /// `#[serde(skip)]` keeps this out of `plan::spec_hash` — plan
    /// runs before install, doesn't know the runsvc.sh content yet,
    /// and re-runs of plan would otherwise oscillate the hash between
    /// "" (pre-install) and the real digest (post-install). The
    /// annotation value lives entirely in the rendered drop-in; the
    /// spec-hash continues to capture only user-visible config.
    #[serde(skip, default)]
    pub runsvc_sha256: String,
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
}

/// One network reference resolved against `[network.NAME]`. Only
/// rendered when `mode = "netns"` — `Open` mode does not get an
/// `EffectiveNetworkBinding`, leaving `EffectiveRunnerSpec.network ==
/// None` so the 40-network drop-in is skipped.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct EffectiveNetworkBinding {
    /// Network key (matches `[network.NAME]`).
    pub name: String,
    /// Resolved spec.
    pub spec: NetworkSpec,
    /// Allocated /30 for this runner (host side `.x+1`, runner side
    /// `.x+2`). Drives X-Ghars-Netns-Subnet + nft rule generation.
    pub subnet: IpNet,
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
    /// SCHED_FIFO).
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
    /// emits the directive with the listed AF_ tokens.
    #[serde(default)]
    pub restrict_address_families: Vec<String>,
    /// Append to the canonical syscall allowlist. Tokens land on the
    /// `SystemCallFilter=@system-service ...` line.
    #[serde(default)]
    pub extra_syscalls: Vec<String>,
    /// `BindReadOnlyPaths` style: `Curated` (Python default, narrow
    /// /etc list) or `Broad` (whole /etc bound). User uses Broad
    /// (#41).
    #[serde(default)]
    pub etc_bind_style: EtcBindStyle,
    /// Explicit `BindReadOnlyPaths` replacement list. None ≡ use the
    /// template's curated set (or whole /etc per `etc_bind_style`).
    /// Some(list) ≡ REPLACE the template's BindReadOnlyPaths entirely
    /// (F48 reset-on-empty validator gates safety) (R4).
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
/// `NO_PROXY` env vars + an extensible CA-trust env-var list (R2 /
/// #38).
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

/// Auth source. The ONLY way to express auth in v0.1 (F12). The
/// `kind` discriminator is serialized as a TOML/JSON tag (e.g.
/// `kind = "pat"`) — `serde(tag = "kind", rename_all = "snake_case")`.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(tag = "kind", rename_all = "snake_case", deny_unknown_fields)]
pub enum AuthSpec {
    /// GitHub App. octocrab handles JWT minting + installation-token
    /// caching (F73, F77).
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
/// dir (F50); sccache via per-pool single-server unit (F51); both
/// can co-exist in one pool (F68).
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
}

/// Default trust zone — used by both `RunnerSpec.trust_zone` and
/// `CachePoolSpec.trust_zone` (SEC-03).
fn default_trust_zone() -> String {
    "default".into()
}

/// Per-pool cache kind. ccache and sccache only; "Generic" was
/// dropped — no defined semantics (F14).
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
/// always shared regardless — F47/F51).
#[derive(Debug, Clone, Copy, Default, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum CacheMode {
    /// Multiple runners share the pool.
    #[default]
    Shared,
    /// Single runner exclusive.
    Isolated,
}

/// `[network.NAME]` declaration. Drives nft rule generation for the
/// netns mode; `Open` is implicit (no `[network.NAME]` entry needed)
/// (F75 amended, R1).
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct NetworkSpec {
    /// Network mode. `Netns` is the only non-Open mode in v0.1
    /// (F75 amended).
    pub mode: NetworkMode,

    /// Allowed egress destinations. Each entry: addr (IpAddr or
    /// CIDR), port (single / range / set), proto (tcp/udp/both),
    /// optional comment. Maps directly to
    /// `ip daddr ADDR PROTO dport PORT accept` (R1).
    #[serde(default)]
    pub allowed_egress: Vec<EgressRule>,

    /// CIDRs for systemd's `IPAddressAllow=` (cgroup-BPF layer);
    /// emitted alongside the netns nft rules as defense in depth.
    #[serde(default)]
    pub ip_allow: Vec<IpNet>,

    /// CIDRs for systemd's `IPAddressDeny=`.
    #[serde(default)]
    pub ip_deny: Vec<IpNet>,

    /// `AF_*` allowlist for systemd `RestrictAddressFamilies=`. Empty
    /// Vec ≡ unset.
    #[serde(default)]
    pub address_families: Vec<String>,

    /// DNS resolution policy inside the netns. Default `Forward` (use
    /// the host's systemd-resolved via a `DNSStubListenerExtra=`
    /// binding on the veth IP). Override with
    /// `dns = { mode = "static", servers = [...] }` when the host
    /// doesn't run systemd-resolved or operator wants explicit
    /// upstream nameservers. NO no-DNS mode (F79c).
    #[serde(default)]
    pub dns: DnsMode,

    /// IPv6 inside the netns. Default `Disabled`. v0.2 will allocate
    /// a /64 from a configurable ULA pool when set to `Enabled`.
    #[serde(default)]
    pub ipv6: Ipv6Mode,
    // F75 amended: `loopback` field REMOVED — was a cgroup-nft
    // workaround (mark-and-check pattern); netns has its own private
    // `lo` so the workaround is unnecessary.
}

/// Network mode. `Open` ≡ no isolation (host netns); `Netns` ≡ full
/// network namespace via `ghars-net@RUNNER.service` + per-runner
/// veth + nft rules. `CgroupNft` and `BpfFilter` were REMOVED —
/// either weaker fallbacks or redundant (F75 amended).
#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum NetworkMode {
    /// No isolation; runner shares the host network namespace.
    Open,
    /// Per-runner network namespace via `ghars-net@%i.service`.
    Netns,
}

/// One egress allow rule. addr is parsed as `IpAddr` or `IpNet` at
/// validate time; bad values reject with serde-derived spans (R1).
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
/// systemd-resolved (F79c).
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
    todo!("config loader: B1")
}

/// Validate every `[network.NAME]` block in `config` using the
/// validators in `crate::validators` (egress rule address + port
/// shape, DNS mode, netns-requires-egress-or-ip-allow). Iterates the
/// `cfg.networks` IndexMap in source order and returns on the first
/// failure — matches `load`'s contract; multi-error reporting is a
/// separate feature.
///
/// Called by `cli::load_config` (alongside the four other post-load
/// validators that live in `cli.rs`) so every CLI entry point that
/// accepts a Config — cmd_validate, cmd_plan, cmd_apply, cmd_status,
/// cmd_add — runs this gate uniformly. Each network's per-rule errors
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
            address_families: vec![],
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
                address_families: vec!["AF_UNIX".into(), "AF_INET".into()],
                dns: DnsMode::Forward,
                ipv6: Ipv6Mode::Disabled,
            },
        );
        validate_networks(&cfg).unwrap();
    }

    #[test]
    fn validate_networks_with_no_networks_is_no_op() {
        // Open-mode runners don't get a [network.NAME] block at all
        // (per F75 amended). Empty IndexMap should validate cleanly.
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
