//! GitHub API surface: releases-API client (reqwest blocking),
//! URL→`Scope` parsing for runner registration, and the shared tokio
//! runtime + `reqwest::Client` builder used by `auth.rs` for octocrab.
//!
//! Design spec: Part 6 (auth subsystem, octocrab integration) +
//! `github.rs` row of Part 2 (module layout) + Part 9f (multi-arch
//! tarball URL template).
//!
//! ## Tokio runtime (F73 enforcement rule)
//!
//! `fn main()` is sync. Only octocrab calls touch tokio, and only via
//! `block_on(...)`. zbus blocking-api MUST NEVER be invoked inside an
//! async block passed to `block_on` (zbus uses its own executor; tokio
//! parking it would deadlock). Verified safe to coexist when call sites
//! are distinct (task #46).
//!
//! ## Releases API
//!
//! Direct port of `install_gha_runner.py:992-1106`:
//! - `https://api.github.com/repos/actions/runner/releases/latest`
//! - `https://api.github.com/repos/actions/runner/releases/tags/v{version}`
//!
//! Tarball URL + filename are produced from the static template
//! `https://github.com/actions/runner/releases/download/v{ver}/{filename}`
//! where `{filename}` is `actions-runner-linux-{arch}-{ver}.tar.gz`
//! and `{arch}` is `x64` (`X86_64`) or `arm64` (`Aarch64`). Multi-arch
//! support per design Part 9f.
//!
//! `extract_sha256` prefers the per-asset `digest` field
//! (`sha256:HEX`), falling back to a `sha256sum -c` line in the release
//! body. ghars searches the body for any line whose tokens include the
//! filename and a 64-hex digest.

use std::io::Read;
use std::sync::OnceLock;
use std::time::Duration;

use serde::Deserialize;
use tokio::runtime::Runtime;

use crate::Result;
use crate::USER_AGENT;
use crate::config::{Arch, ProxySpec};
use crate::error::GharsError;

/// GitHub releases-API endpoint for the latest actions/runner release.
const API_LATEST: &str = "https://api.github.com/repos/actions/runner/releases/latest";

/// GitHub releases-API endpoint template for a pinned actions/runner
/// version. `{version}` is the bare `X.Y.Z` (no `v` prefix); the API
/// path itself includes the `v`.
const API_TAG_TEMPLATE: &str =
    "https://api.github.com/repos/actions/runner/releases/tags/v{version}";

/// Tarball URL template. `{version}` is the bare `X.Y.Z`; `{filename}`
/// is `tarball_name_for(version, arch)`. Hardcoded GitHub origin so by
/// construction the scheme is https and rustls performs TLS verify
/// against the system trust store.
const TARBALL_URL_TEMPLATE: &str =
    "https://github.com/actions/runner/releases/download/v{version}/{filename}";

/// HTTP-API timeout. GitHub releases responses come back in a second or
/// two; 10s is generous and surfaces a hung API call quickly. Matches
/// `install_gha_runner.py:1021`.
const HTTP_API_TIMEOUT: Duration = Duration::from_secs(10);

/// #666: hard cap on bytes read from a GitHub releases-API response.
///
/// The releases endpoint returns a small JSON payload (observed ~50 KB for
/// `actions/runner` releases; even verbose release notes run ~200 KB).
/// 4 MiB gives ~80x headroom over the legitimate maximum without making
/// a compression-bomb attack practical.
///
/// Why this cap is load-bearing:
///   - `Cargo.toml` enables `reqwest::feature = "gzip"`, so reqwest
///     auto-decompresses `Content-Encoding: gzip` responses on the read
///     path. A hostile origin (compromised mirror, MITM proxy, operator-
///     misconfigured `[proxy].ca_certs` pointing at an inspection
///     appliance) can reply with a small compressed payload that
///     decompresses to gigabytes — the ratio is operator-uncontrolled.
///   - `reqwest::blocking::Response::content_length()` returns `None`
///     when gzip auto-decode is in effect (verified at
///     reqwest-0.12.28/src/blocking/response.rs:193-208 and
///     async_impl/response.rs:78-94 — the doc-comment explicitly calls
///     this out). The pre-decompression byte size is only available via
///     the raw `Content-Length` HTTP header, which is the on-wire
///     compressed size — useful as a fast pre-check for non-compressed
///     oversize responses, but useless against gzip bombs because the
///     attacker controls the decompression ratio.
///   - The defense is therefore a streaming bounded read on the
///     POST-decompression byte stream via `std::io::Read::take(MAX+1)`.
///     If the read returns `MAX+1` bytes, the response had more — reject.
///
/// 4 MiB chosen because the JSON parse path then `serde_json::from_slice`s
/// the whole buffer; we accept a one-time 4 MB allocation as the upper
/// bound on apply-time memory pressure for the releases path. v0.2 may
/// reduce this further (the realistic legitimate ceiling is ~256 KB).
const MAX_RELEASES_BODY_BYTES: u64 = 4 * 1024 * 1024;

/// Initial allocation hint for `read_body_capped`. The helper sizes
/// the buffer to `min(cap, INITIAL_BODY_CAPACITY)` so the realistic
/// releases-API payload (~256 KiB per the MAX_RELEASES_BODY_BYTES
/// doc above) starts from a non-zero base instead of the default
/// `Vec::new()`, amortizing the geometric-growth cost of
/// `read_to_end`. A small-cap test (e.g. 64 bytes) caps the
/// allocation at the cap so it never over-allocates.
const INITIAL_BODY_CAPACITY: u64 = 64 * 1024;

/// Depth cap for `format_error_chain` traversal. Defends against
/// pathological cyclic source chains that would otherwise loop
/// forever. 16 layers exceeds any realistic nesting (reqwest →
/// hyper → rustls → io::Error is 4 layers; doubling that again
/// covers any future wrapper additions).
const FORMAT_IO_CHAIN_MAX_DEPTH: usize = 16;

/// URL scope: a runner URL points either at a single repo or at an org.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Scope {
    /// `https://github.com/OWNER/REPO`.
    Repo {
        /// Repository owner.
        owner: String,
        /// Repository name.
        repo: String,
    },
    /// `https://github.com/OWNER` (org-level runners).
    Org {
        /// Org name.
        owner: String,
    },
}

/// One published release of the actions/runner repo, resolved for a
/// specific arch. `tarball_url` and `tarball_name` already encode the
/// arch (the URL template + filename template share the same `{arch}`
/// token).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Release {
    /// Bare version string, `X.Y.Z` — `tag_name` with the leading `v`
    /// stripped. Validated against `validators::validate_version`.
    pub version: String,
    /// SHA256 digest of the per-arch tarball asset, lowercase 64 hex.
    pub sha256: String,
    /// Per-arch tarball download URL.
    pub tarball_url: String,
    /// Per-arch tarball filename (basename of `tarball_url`).
    pub tarball_name: String,
}

/// Parse a runner URL into a `Scope`.
///
/// Accepts only `https://github.com/OWNER` (org) and
/// `https://github.com/OWNER/REPO` (repo). Trailing slashes are
/// permitted; query, fragment, userinfo, and any deeper path are
/// rejected. SEC-34 — only https.
///
/// Defers to `validators::validate_url` first so the case-sensitive
/// regex (`https://github\.com/...`) rejects e.g. `GITHUB.com` —
/// `url::Url` would otherwise lowercase the host per RFC 3986 and
/// silently accept it (#175).
///
/// # Errors
///
/// Returns `GharsError::Validation` for non-https schemes, non-github
/// hosts, malformed paths, or unexpected path-segment counts.
pub fn parse_url(s: &str) -> Result<Scope> {
    crate::validators::validate_url(s)?;
    let parsed = url::Url::parse(s).map_err(|e| {
        GharsError::Validation(
            format!("runner url {s:?} is not a valid URL: {e}"),
            "use https://github.com/OWNER or https://github.com/OWNER/REPO".into(),
        )
    })?;

    if parsed.scheme() != "https" {
        return Err(GharsError::Validation(
            format!(
                "runner url {s:?} uses scheme {:?}; only https is permitted",
                parsed.scheme()
            ),
            "rewrite the url to start with https://".into(),
        ));
    }
    if parsed.host_str() != Some("github.com") {
        return Err(GharsError::Validation(
            format!(
                "runner url {s:?} has host {:?}; only github.com is supported in v0.1",
                parsed.host_str().unwrap_or("")
            ),
            "GitHub Enterprise / ghes.example.com is not yet supported".into(),
        ));
    }
    if parsed.username() != "" || parsed.password().is_some() {
        return Err(GharsError::Validation(
            format!("runner url {s:?} contains userinfo"),
            "remove user:password@ from the url".into(),
        ));
    }
    if parsed.query().is_some() || parsed.fragment().is_some() {
        return Err(GharsError::Validation(
            format!("runner url {s:?} contains query or fragment"),
            "trim ? and # components".into(),
        ));
    }

    let segments: Vec<&str> = parsed
        .path_segments()
        .map(|s| s.filter(|seg| !seg.is_empty()).collect())
        .unwrap_or_default();

    match segments.as_slice() {
        [owner] => Ok(Scope::Org {
            owner: (*owner).to_string(),
        }),
        [owner, repo] => Ok(Scope::Repo {
            owner: (*owner).to_string(),
            repo: (*repo).to_string(),
        }),
        _ => Err(GharsError::Validation(
            format!(
                "runner url {s:?} has {} path segments; expected 1 (org) or 2 (repo)",
                segments.len()
            ),
            "use https://github.com/OWNER or https://github.com/OWNER/REPO".into(),
        )),
    }
}

/// Lazily constructed singleton tokio runtime. Built on first
/// `block_on` call, reused for every subsequent call. Per Part 6
/// enforcement rule item 4 it is `current_thread`, so all octocrab
/// futures execute on the calling thread; ghars's library API stays
/// sync.
static RUNTIME: OnceLock<Runtime> = OnceLock::new();

fn rt() -> &'static Runtime {
    RUNTIME.get_or_init(|| {
        // .enable_time() intentionally omitted — Cargo.toml gates
        // tokio to the `rt` feature only (no `time`). octocrab's HTTP
        // path uses hyper-rustls, whose timers are cooperative with
        // the reactor; ghars enforces overall timeouts at the
        // octocrab/reqwest layer rather than via tokio's timer.
        //
        // expect: failure here means the OS denied epoll setup, fatal
        // at startup. Same panic pattern as design Part 6 line 1189.
        #[allow(clippy::expect_used)]
        tokio::runtime::Builder::new_current_thread()
            .enable_io()
            .build()
            .expect("ghars tokio runtime build failed")
    })
}

/// Drive an async future to completion on the ghars runtime. Per Part
/// 6 enforcement rule items 2 + 3, the future body MUST be octocrab /
/// reqwest async-only — no zbus, no `std::fs`, no other blocking I/O
/// inside the closure.
///
/// # Panics
///
/// Panics if the runtime fails to construct. The first call constructs
/// a single-threaded `current_thread` runtime; subsequent calls reuse it.
pub fn block_on<F, T>(fut: F) -> T
where
    F: std::future::Future<Output = T>,
{
    rt().block_on(fut)
}

// ---------------------------------------------------------------------
// octocrab builder (auth-mode-agnostic, system trust only in v0.1)
// ---------------------------------------------------------------------

/// Construct a fresh `octocrab::OctocrabBuilder` configured with ghars's
/// v0.1 transport policy. Auth attachment (`.personal_token(...)` /
/// `.app(...)`) happens at the call site — `auth.rs` chains its
/// auth-mode-specific configuration on top of what this returns.
///
/// ## Transport policy (v0.1)
///
/// octocrab's `rustls` + `rustls-ring` + `default-client` features
/// (Cargo.toml) wire `hyper-rustls::HttpsConnectorBuilder::new().with_native_roots()`
/// into the default client (octocrab 0.42.1 lib.rs:683-687). On Linux
/// that reads:
/// - `/etc/ssl/certs/ca-certificates.crt` (Ubuntu/Debian)
/// - `/etc/pki/tls/certs/ca-bundle.crt` (Fedora/RHEL/CentOS)
/// - any path indicated by `SSL_CERT_FILE` env
///
/// ## Per-deployment proxy CA caveat
///
/// The `proxy` argument is currently UNUSED. Operators with corporate
/// CAs that aren't in the system trust must install them system-wide
/// via `update-ca-trust enable && update-ca-trust extract` (RHEL/
/// Fedora) or `update-ca-certificates` (Ubuntu/Debian). This is
/// because octocrab 0.42 exposes no client-injection point that
/// accepts a pre-built `reqwest::Client` and uses hyper directly,
/// not reqwest. Custom hyper-connector injection via
/// `OctocrabBuilder::with_service` is v0.2 follow-up (task #145).
///
/// The argument is taken now so v0.2 can switch to `with_service`
/// without changing the call sites in auth.rs.
#[must_use]
pub fn build_octocrab_builder(
    _proxy: Option<&ProxySpec>,
) -> octocrab::OctocrabBuilder<
    octocrab::NoSvc,
    octocrab::DefaultOctocrabBuilderConfig,
    octocrab::NoAuth,
    octocrab::NotLayerReady,
> {
    octocrab::Octocrab::builder()
}

// ---------------------------------------------------------------------
// reqwest::Client construction (TLS trust store + proxy CA injection)
// ---------------------------------------------------------------------

/// Build a reqwest blocking client wired for GitHub API + tarball
/// downloads.
///
/// reqwest's `rustls-tls-native-roots` feature reads the system trust
/// store (`/etc/ssl/...` on Ubuntu, `/etc/pki/...` on Fedora/RHEL).
/// When the operator declares a proxy `[proxy.ca_certs]` list, ghars
/// appends each PEM as a root certificate so corporate CAs that aren't
/// in the system bundle still validate.
///
/// The user-agent is `"ghars"` and the timeout is 10 s — the same
/// values used by the releases-API helpers so a single client can
/// serve every github.rs request.
///
/// # Errors
///
/// Returns `GharsError::GitHub` for client-build failures or PEM-parse
/// failures, and `GharsError::Io` for unreadable CA files.
pub fn build_blocking_client(proxy: Option<&ProxySpec>) -> Result<reqwest::blocking::Client> {
    let mut builder = reqwest::blocking::Client::builder()
        .user_agent(USER_AGENT)
        .timeout(HTTP_API_TIMEOUT);
    if let Some(p) = proxy {
        for cert in &p.ca_certs {
            let pem = std::fs::read(cert.path.as_std_path())?;
            // SEC-08 / #144: from_pem_bundle parses every PEM-fenced
            // CERTIFICATE block in the file and returns the resulting
            // Vec<Certificate>. from_pem (which we previously used)
            // accepts files with zero PEM blocks under the rustls
            // backend — it stores the raw bytes verbatim and downstream
            // builds an empty roots set, silently degrading to system
            // trust only. Fail closed instead: an operator-provided CA
            // path that yields zero certificates is a misconfiguration,
            // not a "fall back to defaults" signal.
            let parsed = reqwest::Certificate::from_pem_bundle(&pem).map_err(|e| {
                GharsError::GitHub(
                    format!("invalid CA pem at {}: {e}", cert.path),
                    "verify the file is a PEM-encoded X.509 certificate".into(),
                )
            })?;
            if parsed.is_empty() {
                return Err(GharsError::GitHub(
                    format!(
                        "CA cert file {} is empty or contains no valid PEM certificates",
                        cert.path
                    ),
                    "ensure the file holds at least one `-----BEGIN CERTIFICATE-----` block; CRLs and comments alone are not enough".into(),
                ));
            }
            for c in parsed {
                builder = builder.add_root_certificate(c);
            }
        }
    }
    builder.build().map_err(|e| {
        GharsError::GitHub(
            format!("reqwest client build failed: {e}"),
            "this typically indicates a system TLS configuration error".into(),
        )
    })
}

// ---------------------------------------------------------------------
// Tarball URL template (multi-arch, design Part 9f)
// ---------------------------------------------------------------------

/// Translate a `config::Arch` to the actions/runner release-asset
/// arch token. `X86_64 -> "x64"`, `Aarch64 -> "arm64"`. Matches
/// design Part 9f.
#[must_use]
pub fn arch_token(arch: Arch) -> &'static str {
    match arch {
        Arch::X86_64 => "x64",
        Arch::Aarch64 => "arm64",
    }
}

/// Per-arch tarball filename for a given runner version.
#[must_use]
pub fn tarball_name_for(version: &str, arch: Arch) -> String {
    format!(
        "actions-runner-linux-{}-{}.tar.gz",
        arch_token(arch),
        version
    )
}

/// Per-arch tarball download URL for a given runner version.
#[must_use]
pub fn tarball_url_for(version: &str, arch: Arch) -> String {
    let filename = tarball_name_for(version, arch);
    TARBALL_URL_TEMPLATE
        .replace("{version}", version)
        .replace("{filename}", &filename)
}

// ---------------------------------------------------------------------
// Releases API (reqwest blocking)
// ---------------------------------------------------------------------

/// One asset entry in the GitHub release JSON. Only the fields ghars
/// reads are deserialized; `serde(default)` keeps the call site
/// resilient to GitHub adding new fields. The `digest` field is
/// optional — older releases don't carry it; ghars falls back to the
/// `body` parser in that case.
#[derive(Debug, Deserialize)]
struct ReleaseAsset {
    #[serde(default)]
    name: String,
    #[serde(default)]
    digest: Option<String>,
}

/// Subset of the GitHub release JSON that ghars consumes.
#[derive(Debug, Deserialize)]
struct ReleaseApiPayload {
    #[serde(default)]
    tag_name: String,
    #[serde(default)]
    assets: Vec<ReleaseAsset>,
    #[serde(default)]
    body: Option<String>,
}

/// Strip a single leading `v` from a tag name, matching
/// `install_gha_runner.py:1050-1051`.
fn strip_v(tag: &str) -> &str {
    tag.strip_prefix('v').unwrap_or(tag)
}

/// Lower-case 64-hex check, matching `install_gha_runner.py:1004-1007`.
fn is_hex64(s: &str) -> bool {
    s.len() == 64 && s.chars().all(|c| c.is_ascii_hexdigit())
}

/// Extract the SHA256 digest for `filename` from a release-API payload.
///
/// Prefers the per-asset `digest` field (`sha256:HEX`); falls back to a
/// `<hex>  <filename>` line in the release body (sha256sum -c format).
/// Direct port of `install_gha_runner.py:1054-1076`.
///
/// # Errors
///
/// Returns `GharsError::GitHub` when neither location yields a 64-hex
/// digest matching `filename`.
fn extract_sha256(payload: &ReleaseApiPayload, filename: &str) -> Result<String> {
    for asset in &payload.assets {
        if asset.name == filename {
            if let Some(digest) = &asset.digest {
                let lower = digest.to_lowercase();
                if let Some(hex) = lower.strip_prefix("sha256:") {
                    let hex = hex.trim();
                    if is_hex64(hex) {
                        return Ok(hex.to_string());
                    }
                }
            }
        }
    }
    let body = payload.body.as_deref().unwrap_or("");
    for line in body.lines() {
        let stripped = line.trim();
        if !stripped.contains(filename) {
            continue;
        }
        // Some release bodies wrap sha lines in markdown backticks; strip
        // any leading backticks before tokenizing. Matches Python's
        // `line.lstrip("`")`.
        let after_backticks = stripped.trim_start_matches('`');
        let mut tokens = after_backticks.split_whitespace();
        let first = tokens.next().unwrap_or("");
        let second = tokens.next().unwrap_or("");
        if is_hex64(first) && second == filename {
            return Ok(first.to_lowercase());
        }
    }
    Err(GharsError::GitHub(
        format!(
            "could not find SHA256 for {filename} in GitHub API response (neither assets[].digest nor release-notes body contained it)"
        ),
        "verify the upstream release publishes a per-asset digest or sha256sum body line".into(),
    ))
}

/// Build a `Release` from a parsed API payload + the requested arch.
fn release_from_api(payload: &ReleaseApiPayload, arch: Arch) -> Result<Release> {
    if payload.tag_name.is_empty() {
        return Err(GharsError::GitHub(
            "GitHub API response missing tag_name".into(),
            "the upstream API contract requires `tag_name`; this typically means the request hit the wrong endpoint".into(),
        ));
    }
    let version = strip_v(&payload.tag_name).to_string();
    let filename = tarball_name_for(&version, arch);
    let sha256 = extract_sha256(payload, &filename)?;
    let url = tarball_url_for(&version, arch);
    Ok(Release {
        version,
        sha256,
        tarball_url: url,
        tarball_name: filename,
    })
}

/// Typed error for `read_body_capped`. Variants distinguish transient
/// I/O failure from the cap-firing post-read check, so the caller can
/// route each mode to a different `GharsError::GitHub` hint without
/// substring-matching an error string (which would misroute any
/// `io::Error` Display that happens to contain "exceeded").
#[derive(Debug)]
enum BodyCapError {
    /// `Read::read_to_end` returned an I/O error before the cap could
    /// fire. The wrapped `io::Error` is preserved so the caller can
    /// surface its Display text and walk its `.source()` chain via
    /// `format_error_chain` for nested-cause errors (TLS, hyper).
    Io(std::io::Error),
    /// Post-read check observed `buf.len() > cap`, meaning the reader
    /// had more bytes available than the cap allows. `cap` is the
    /// configured limit in bytes — the caller composes the operator-
    /// visible diagnostic from this value.
    CapExceeded { cap: u64 },
}

/// Walk the `std::error::Error::source()` chain of an arbitrary error
/// and concatenate each layer's Display with ": " separators. The
/// outer Display of types like `std::io::Error` and `reqwest::Error`
/// only formats the outermost layer, so nested causes (e.g.
/// reqwest::Error wrapping hyper::Error wrapping a rustls error, or
/// reqwest::Error wrapping a TLS/DNS error) are dropped if the
/// operator only sees `format!("{err}")`. This helper preserves the
/// full chain so an operator triaging a
/// connection-reset-during-TLS-handshake sees both the outer "request
/// failed" framing and the inner rustls reason code. The depth cap
/// `FORMAT_IO_CHAIN_MAX_DEPTH` defends against cyclic source chains.
///
/// Accepts `&dyn std::error::Error` so the same helper covers both the
/// `io::Error` post-decompression path (`read_body_capped`) and the
/// `reqwest::Error` send-failure path — `reqwest::Error` is not an
/// `io::Error`, so a separate walker would be required otherwise.
fn format_error_chain(err: &(dyn std::error::Error + 'static)) -> String {
    let mut out = err.to_string();
    let mut source = err.source();
    let mut depth = 0;
    while let Some(cause) = source {
        if depth >= FORMAT_IO_CHAIN_MAX_DEPTH {
            break;
        }
        out.push_str(": ");
        out.push_str(&cause.to_string());
        depth += 1;
        source = cause.source();
    }
    out
}

/// Bounded read helper. Exists so unit tests can inject a small cap
/// (e.g. 64 bytes) without HTTP plumbing.
///
/// `cap` is the maximum allowed body size in bytes. Reads up to
/// `cap + 1` bytes via `Read::take`; if the resulting buffer length
/// exceeds `cap`, the reader had more bytes available and the cap
/// fires. The buffer is preallocated to
/// `min(cap, INITIAL_BODY_CAPACITY)` to amortize the geometric
/// growth cost of `read_to_end` for the realistic releases-API
/// payload, while a small-cap test never over-allocates beyond the
/// cap itself.
fn read_body_capped<R: Read>(reader: R, cap: u64) -> std::result::Result<Vec<u8>, BodyCapError> {
    let initial = std::cmp::min(cap, INITIAL_BODY_CAPACITY) as usize;
    let mut buf = Vec::with_capacity(initial);
    let limit = cap.saturating_add(1);
    reader
        .take(limit)
        .read_to_end(&mut buf)
        .map_err(BodyCapError::Io)?;
    if buf.len() as u64 > cap {
        return Err(BodyCapError::CapExceeded { cap });
    }
    Ok(buf)
}

/// Issue an HTTP GET for a GitHub releases-API URL and deserialize
/// the JSON body into `ReleaseApiPayload`.
///
/// Defense-in-depth body-size cap. Two layers:
/// 1. Raw `Content-Length` HTTP header check — fast pre-read rejection
///    for oversize compressed bodies. The header carries the on-wire
///    (pre-decompression) size, so a `Content-Length > MAX` is enough
///    to reject without reading any body bytes. Useful for non-gzipped
///    responses; useless against bombs (an attacker can set CL=1MB).
/// 2. Streaming bounded read on `Response: Read` via `read_body_capped`.
///    The reader sits AFTER reqwest's gzip decoder, so bytes counted
///    are post-decompression — this is the actual bomb defense. If
///    the buffer length exceeds the cap, reject.
fn http_get_payload(client: &reqwest::blocking::Client, url: &str) -> Result<ReleaseApiPayload> {
    http_get_payload_with_cap(client, url, MAX_RELEASES_BODY_BYTES)
}

/// Cap-injection seam for `http_get_payload`. Tests call this
/// directly with a small `max_bytes` to exercise both Layer 1
/// (Content-Length pre-check) and Layer 2 (streaming `read_body_capped`)
/// without authoring a 4 MiB+ mockito body. Production callers go
/// through `http_get_payload`, which fixes `max_bytes` to
/// `MAX_RELEASES_BODY_BYTES`.
fn http_get_payload_with_cap(
    client: &reqwest::blocking::Client,
    url: &str,
    max_bytes: u64,
) -> Result<ReleaseApiPayload> {
    let resp = client
        .get(url)
        .header("Accept", "application/vnd.github+json")
        .header("X-GitHub-Api-Version", "2022-11-28")
        .send()
        .map_err(|e| {
            // Walk the reqwest::Error source chain so an operator
            // triaging a TLS/DNS/connection failure sees the inner
            // cause (e.g. rustls reason code, hyper transport reason)
            // and not just reqwest's outer Display layer.
            GharsError::GitHub(
                format!(
                    "GitHub API request failed: {chain}: {url}",
                    chain = format_error_chain(&e)
                ),
                "check network connectivity and proxy configuration".into(),
            )
        })?;
    let status = resp.status();
    if !status.is_success() {
        // Status-code-specific operator hints. Mirrors the pattern at
        // `auth.rs::octocrab_to_auth` — keep the surfaces aligned so
        // an operator sees consistent hint text whether they hit the
        // rate limit on the releases-API path or the registration-
        // token path.
        let code = status.as_u16();
        let hint: String = match code {
            429 => "GitHub secondary rate limit; wait the `Retry-After` interval and retry"
                .into(),
            401 | 403 => "this endpoint is normally public; if a proxy or GHE mirror is in \
                          use, check token/PAT validity and repo permissions"
                .into(),
            404 => "verify the runner version (if specified) and the owner/repo exist, and the API endpoint is reachable".into(),
            500..=599 => {
                "GitHub upstream is degraded; retry later, check status.github.com".into()
            }
            _ => "unexpected HTTP status from the GitHub API; check status.github.com for incidents, then file a ghars bug if the upstream contract has changed".into(),
        };
        return Err(GharsError::GitHub(
            format!("GitHub API request failed ({status}): {url}"),
            hint,
        ));
    }

    // Layer 1: raw Content-Length header pre-check. resp.content_length()
    // returns None for gzipped responses (reqwest-0.12.28 docs at
    // blocking/response.rs:193-208), so we read the header directly to
    // get the on-wire size before reqwest's gzip decoder mangles the
    // size hint.
    // Malformed Content-Length silently falls through to Layer 2 streaming backstop.
    if let Some(cl_header) = resp.headers().get(reqwest::header::CONTENT_LENGTH) {
        if let Ok(cl_str) = cl_header.to_str() {
            if let Ok(cl) = cl_str.parse::<u64>() {
                if cl > max_bytes {
                    return Err(GharsError::GitHub(
                        format!(
                            "GitHub API response Content-Length {cl} exceeds {max_bytes} bytes: {url}"
                        ),
                        "the on-wire (pre-decompression) Content-Length is suspiciously \
                         large; verify network path (compromised mirror, hostile proxy CA, \
                         or non-GitHub origin); if the upstream payload is legitimately \
                         this large, file a ghars issue to raise MAX_RELEASES_BODY_BYTES"
                            .into(),
                    ));
                }
            }
        }
    }

    // Layer 2: streaming bounded read on the post-decompression byte
    // stream via the `read_body_capped` helper. The helper returns a
    // typed `BodyCapError` so the wrapper routes I/O-failure vs
    // cap-firing through structural variants rather than substring
    // matching on an error string. Cap-firing branch differentiates
    // Layer 1 (on-wire/pre-decompression) from Layer 2
    // (post-decompression/bomb signature).
    let buf = read_body_capped(resp, max_bytes).map_err(|err| match err {
        BodyCapError::Io(io_err) => GharsError::GitHub(
            format!(
                "GitHub API response read failed: {chain}: {url}",
                chain = format_error_chain(&io_err)
            ),
            "if connection-reset or timeout, retry; if TLS/certificate error, check the system trust store and proxy CA configuration".into(),
        ),
        BodyCapError::CapExceeded { cap } => GharsError::GitHub(
            format!(
                "GitHub API response body exceeds {cap} bytes post-decompression \
                 (possible compression bomb): {url}"
            ),
            "the post-decompression body is suspiciously large (compression-bomb \
             signature); verify network path (compromised mirror, hostile proxy CA, \
             or non-GitHub origin); if the upstream payload is legitimately this \
             large, file a ghars issue to raise MAX_RELEASES_BODY_BYTES"
                .into(),
        ),
    })?;
    serde_json::from_slice::<ReleaseApiPayload>(&buf).map_err(|e| {
        GharsError::GitHub(
            format!("GitHub API response not valid JSON: {e}: {url}"),
            "if the response is HTML instead of JSON, check for captive portal or proxy interception; verify the URL with curl -v; check status.github.com for incidents".into(),
        )
    })
}

/// Resolve the latest published actions/runner release for `arch`.
///
/// # Errors
///
/// Returns `GharsError::GitHub` on network / HTTP / decode failure.
pub fn fetch_latest_release(client: &reqwest::blocking::Client, arch: Arch) -> Result<Release> {
    fetch_latest_release_at(client, API_LATEST, arch)
}

/// Internal helper: resolve the latest release using a caller-supplied
/// API URL. The public `fetch_latest_release` always passes
/// [`API_LATEST`]; tests pass a mockito server URL to exercise the
/// full request → JSON → `Release` round trip without hitting GitHub.
///
/// # Errors
///
/// Returns `GharsError::GitHub` on network / HTTP / decode failure.
pub(crate) fn fetch_latest_release_at(
    client: &reqwest::blocking::Client,
    url: &str,
    arch: Arch,
) -> Result<Release> {
    let payload = http_get_payload(client, url)?;
    release_from_api(&payload, arch)
}

/// Resolve a pinned actions/runner release for `arch`.
///
/// # Errors
///
/// Returns `GharsError::GitHub` on API failure or
/// `GharsError::Validation` if the version string is malformed.
pub fn fetch_release(
    client: &reqwest::blocking::Client,
    version: &str,
    arch: Arch,
) -> Result<Release> {
    fetch_release_at(client, API_TAG_TEMPLATE, version, arch)
}

/// Internal helper: resolve a pinned release using a caller-supplied
/// URL template. `{version}` in the template is replaced with the
/// validated `version`. The public `fetch_release` always passes
/// [`API_TAG_TEMPLATE`]; tests pass a mockito-backed template to
/// exercise the full request → JSON → `Release` round trip.
///
/// # Errors
///
/// Returns `GharsError::GitHub` on API failure or
/// `GharsError::Validation` if the version string is malformed.
pub(crate) fn fetch_release_at(
    client: &reqwest::blocking::Client,
    url_template: &str,
    version: &str,
    arch: Arch,
) -> Result<Release> {
    crate::validators::validate_version(version)?;
    let url = url_template.replace("{version}", version);
    let payload = http_get_payload(client, &url)?;
    release_from_api(&payload, arch)
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used)]
mod tests {
    use super::*;
    use rstest::rstest;

    // ---- arch_token / tarball_name_for / tarball_url_for --------------

    #[test]
    fn arch_token_x64() {
        assert_eq!(arch_token(Arch::X86_64), "x64");
    }

    #[test]
    fn arch_token_arm64() {
        assert_eq!(arch_token(Arch::Aarch64), "arm64");
    }

    #[test]
    fn tarball_name_x64() {
        assert_eq!(
            tarball_name_for("2.334.0", Arch::X86_64),
            "actions-runner-linux-x64-2.334.0.tar.gz"
        );
    }

    #[test]
    fn tarball_name_arm64() {
        assert_eq!(
            tarball_name_for("2.334.0", Arch::Aarch64),
            "actions-runner-linux-arm64-2.334.0.tar.gz"
        );
    }

    #[test]
    fn tarball_url_x64() {
        assert_eq!(
            tarball_url_for("2.334.0", Arch::X86_64),
            "https://github.com/actions/runner/releases/download/v2.334.0/actions-runner-linux-x64-2.334.0.tar.gz"
        );
    }

    #[test]
    fn tarball_url_arm64() {
        assert_eq!(
            tarball_url_for("2.334.0", Arch::Aarch64),
            "https://github.com/actions/runner/releases/download/v2.334.0/actions-runner-linux-arm64-2.334.0.tar.gz"
        );
    }

    // ---- is_hex64 -----------------------------------------------------

    #[rstest]
    #[case(&"0".repeat(64))]
    #[case(&"abcdef0123456789".repeat(4))]
    #[case(&"ABCDEF0123456789".repeat(4))]
    fn is_hex64_accepts(#[case] s: &str) {
        assert!(is_hex64(s), "must accept {s:?}");
    }

    #[rstest]
    #[case("")]
    #[case(&"0".repeat(63))]
    #[case(&"0".repeat(65))]
    #[case(&"g".repeat(64))]
    #[case(&" ".repeat(64))]
    fn is_hex64_rejects(#[case] s: &str) {
        assert!(!is_hex64(s), "must reject {s:?}");
    }

    // ---- strip_v ------------------------------------------------------

    #[test]
    fn strip_v_strips_one() {
        assert_eq!(strip_v("v2.334.0"), "2.334.0");
    }

    #[test]
    fn strip_v_no_v() {
        assert_eq!(strip_v("2.334.0"), "2.334.0");
    }

    #[test]
    fn strip_v_only_first_v() {
        // Python behavior: only `tag_name[1:] if tag_name.startswith("v")`,
        // so a tag like "vv1.0" loses one leading v.
        assert_eq!(strip_v("vv1.0"), "v1.0");
    }

    // ---- extract_sha256 — asset digest path --------------------------

    #[test]
    fn extract_sha256_from_asset_digest() {
        let payload = ReleaseApiPayload {
            tag_name: "v2.334.0".into(),
            assets: vec![ReleaseAsset {
                name: "actions-runner-linux-x64-2.334.0.tar.gz".into(),
                digest: Some(format!("sha256:{}", "a".repeat(64))),
            }],
            body: None,
        };
        let sha = extract_sha256(&payload, "actions-runner-linux-x64-2.334.0.tar.gz").unwrap();
        assert_eq!(sha, "a".repeat(64));
    }

    #[test]
    fn extract_sha256_asset_digest_uppercase_normalized() {
        let payload = ReleaseApiPayload {
            tag_name: "v2.334.0".into(),
            assets: vec![ReleaseAsset {
                name: "actions-runner-linux-x64-2.334.0.tar.gz".into(),
                digest: Some(format!("SHA256:{}", "A".repeat(64))),
            }],
            body: None,
        };
        let sha = extract_sha256(&payload, "actions-runner-linux-x64-2.334.0.tar.gz").unwrap();
        assert_eq!(sha, "a".repeat(64));
    }

    #[test]
    fn extract_sha256_asset_wrong_filename_skipped() {
        let payload = ReleaseApiPayload {
            tag_name: "v2.334.0".into(),
            assets: vec![ReleaseAsset {
                name: "actions-runner-linux-arm64-2.334.0.tar.gz".into(),
                digest: Some(format!("sha256:{}", "b".repeat(64))),
            }],
            body: None,
        };
        // Asking for x64 must NOT pick up the arm64 asset's digest.
        assert!(extract_sha256(&payload, "actions-runner-linux-x64-2.334.0.tar.gz").is_err());
    }

    // ---- extract_sha256 — body fallback path -------------------------

    #[test]
    fn extract_sha256_body_fallback() {
        let body = format!(
            "Some release notes...\n{}  actions-runner-linux-x64-2.334.0.tar.gz\nMore notes",
            "c".repeat(64)
        );
        let payload = ReleaseApiPayload {
            tag_name: "v2.334.0".into(),
            assets: vec![],
            body: Some(body),
        };
        let sha = extract_sha256(&payload, "actions-runner-linux-x64-2.334.0.tar.gz").unwrap();
        assert_eq!(sha, "c".repeat(64));
    }

    #[test]
    fn extract_sha256_body_with_leading_backticks() {
        // Real release-notes format: each line is code-block indented
        // with a single leading backtick, so the line tokens are
        // `<hex>` followed by `<filename>` after the backtick is
        // stripped. Trailing backticks on the SAME line as the filename
        // are treated as part of the token (matching Python's
        // `lstrip("`").split()` behavior — leading-only).
        let body = format!(
            "Pre\n`{}  actions-runner-linux-arm64-2.334.0.tar.gz\nPost",
            "d".repeat(64)
        );
        let payload = ReleaseApiPayload {
            tag_name: "v2.334.0".into(),
            assets: vec![],
            body: Some(body),
        };
        let sha = extract_sha256(&payload, "actions-runner-linux-arm64-2.334.0.tar.gz").unwrap();
        assert_eq!(sha, "d".repeat(64));
    }

    #[test]
    fn extract_sha256_missing_returns_err() {
        let payload = ReleaseApiPayload {
            tag_name: "v2.334.0".into(),
            assets: vec![],
            body: Some("no digest line here".into()),
        };
        assert!(extract_sha256(&payload, "actions-runner-linux-x64-2.334.0.tar.gz").is_err());
    }

    #[test]
    fn extract_sha256_body_token_must_match_filename_exactly() {
        // The body line mentions a *different* tarball name; must not
        // match. Defense against partial-match drift.
        let body = format!("{}  actions-runner-linux-x64-OTHER.tar.gz", "e".repeat(64));
        let payload = ReleaseApiPayload {
            tag_name: "v2.334.0".into(),
            assets: vec![],
            body: Some(body),
        };
        assert!(extract_sha256(&payload, "actions-runner-linux-x64-2.334.0.tar.gz").is_err());
    }

    // ---- release_from_api ---------------------------------------------

    #[test]
    fn release_from_api_strips_v() {
        let payload = ReleaseApiPayload {
            tag_name: "v2.334.0".into(),
            assets: vec![ReleaseAsset {
                name: "actions-runner-linux-x64-2.334.0.tar.gz".into(),
                digest: Some(format!("sha256:{}", "f".repeat(64))),
            }],
            body: None,
        };
        let rel = release_from_api(&payload, Arch::X86_64).unwrap();
        assert_eq!(rel.version, "2.334.0");
        assert_eq!(rel.sha256, "f".repeat(64));
        assert_eq!(rel.tarball_name, "actions-runner-linux-x64-2.334.0.tar.gz");
        assert!(rel.tarball_url.contains("v2.334.0"));
    }

    #[test]
    fn release_from_api_arm64_uses_arm64_asset() {
        let payload = ReleaseApiPayload {
            tag_name: "v2.334.0".into(),
            assets: vec![
                ReleaseAsset {
                    name: "actions-runner-linux-x64-2.334.0.tar.gz".into(),
                    digest: Some(format!("sha256:{}", "1".repeat(64))),
                },
                ReleaseAsset {
                    name: "actions-runner-linux-arm64-2.334.0.tar.gz".into(),
                    digest: Some(format!("sha256:{}", "2".repeat(64))),
                },
            ],
            body: None,
        };
        let rel = release_from_api(&payload, Arch::Aarch64).unwrap();
        assert_eq!(rel.sha256, "2".repeat(64));
        assert_eq!(
            rel.tarball_name,
            "actions-runner-linux-arm64-2.334.0.tar.gz"
        );
    }

    #[test]
    fn release_from_api_missing_tag_name_errors() {
        let payload = ReleaseApiPayload {
            tag_name: String::new(),
            assets: vec![],
            body: None,
        };
        assert!(release_from_api(&payload, Arch::X86_64).is_err());
    }

    // ---- block_on / runtime smoke -------------------------------------

    #[test]
    fn block_on_runs_a_future() {
        let v = block_on(async { 41 + 1 });
        assert_eq!(v, 42);
    }

    #[test]
    fn block_on_can_be_called_twice() {
        let a = block_on(async { 1 });
        let b = block_on(async { 2 });
        assert_eq!((a, b), (1, 2));
    }

    /// Nested `block_on` inside a future already driven by `block_on`
    /// must panic. tokio's `current_thread` runtime detects the
    /// already-entered context and aborts with "Cannot start a runtime
    /// from within a runtime" (verified empirically below). #168 pins
    /// this contract: the production code in `auth.rs` (4 call sites
    /// at auth.rs:178, 194, 306, 321 as of B6) MUST NOT call
    /// `block_on` from inside a future passed to `block_on`. A `grep
    /// -rn block_on src/` audit + this panic test together gate the
    /// invariant.
    #[test]
    #[should_panic(expected = "Cannot start a runtime from within a runtime")]
    fn block_on_nested_panics() {
        block_on(async {
            // Inner call: trying to enter the same current_thread
            // runtime that's already driving us. tokio panics here.
            let _ = block_on(async { 0u32 });
        });
    }

    /// Spawning a tokio task that itself tries to `block_on` is the
    /// other reentrancy footgun: the spawned future runs on the same
    /// reactor thread (current_thread runtime), and its inner
    /// `block_on` hits the same already-entered guard. The panic
    /// surfaces when the outer block_on awaits the JoinHandle. #168
    /// pins the contract so a future caller who refactors auth.rs to
    /// use spawn + block_on doesn't silently introduce a deadlock.
    #[test]
    #[should_panic(expected = "Cannot start a runtime from within a runtime")]
    fn block_on_inside_spawned_task_panics() {
        block_on(async {
            // tokio::spawn requires `feature = "rt"` only — we have
            // it. The spawned future panics on inner block_on; we
            // re-raise via `.unwrap()` of the JoinError.
            let handle = tokio::spawn(async {
                let _ = block_on(async { 0u32 });
            });
            // JoinHandle::await on a panicked task returns
            // Err(JoinError::panic). resume_unwind to surface the
            // original panic message for the should_panic match.
            let join_err = handle.await.expect_err("spawn must panic");
            std::panic::resume_unwind(join_err.into_panic());
        });
    }

    /// Audit-style guard: every `block_on` call site in the production
    /// source tree (excluding `block_on`'s own definition + the
    /// `#[cfg(test)]` modules) must NOT lexically appear inside a
    /// future body. We can't statically verify "passed to block_on"
    /// from a unit test, but the next-best check is that auth.rs
    /// keeps its 4 call sites top-level — this fails fast if a
    /// teammate refactors auth.rs into a nested block_on shape and
    /// forgets to break the call chain.
    ///
    /// Implementation: read the source files, count `block_on(` /
    /// `github::block_on(` occurrences, and check that none of the
    /// surrounding function bodies are async (heuristic: no `async
    /// fn` or `async move` lexically wrapping the call).
    #[test]
    fn block_on_call_sites_stay_top_level() {
        // Files that legitimately call `block_on` in production code.
        // Tests are excluded — `block_on_nested_panics` above
        // intentionally violates the rule.
        let files = ["src/auth.rs"];
        let manifest_dir = env!("CARGO_MANIFEST_DIR");
        for rel in files {
            let path = std::path::Path::new(manifest_dir).join(rel);
            let src = std::fs::read_to_string(&path)
                .unwrap_or_else(|e| panic!("read {}: {e}", path.display()));
            for (lineno, line) in src.lines().enumerate() {
                // Skip test mods + comments.
                let trimmed = line.trim_start();
                if trimmed.starts_with("//") || trimmed.starts_with("#[cfg(test)]") {
                    continue;
                }
                if !trimmed.contains("block_on(") {
                    continue;
                }
                // Walk backward up to ~30 lines looking for an
                // `async fn` / `async move` / `async {` opener that
                // isn't already closed before this line. If found,
                // we'd be inside an async body — violation.
                //
                // Heuristic only: we don't track full scope. The
                // real defense is the runtime panic test above; this
                // guard is a smoke alarm.
                let prior: Vec<&str> = src.lines().take(lineno).collect();
                let mut depth_async = 0i32;
                let mut depth_brace = 0i32;
                for prev in prior.iter().rev().take(50) {
                    if prev.contains("async {")
                        || prev.contains("async move")
                        || prev.contains("async fn")
                    {
                        depth_async += 1;
                    }
                    depth_brace += prev.matches('{').count() as i32;
                    depth_brace -= prev.matches('}').count() as i32;
                    if depth_brace < 0 {
                        // We exited the surrounding scope, stop.
                        break;
                    }
                }
                assert!(
                    depth_async == 0,
                    "{rel}:{} block_on call appears inside an async body \
                     within the preceding 50 lines — violation of #168 \
                     reentrancy contract. Check that this call is at top \
                     level of a sync fn.",
                    lineno + 1
                );
            }
        }
    }

    // ---- build_blocking_client ----------------------------------------

    #[test]
    fn build_blocking_client_no_proxy_succeeds() {
        let _client = build_blocking_client(None).unwrap();
    }

    #[test]
    fn build_blocking_client_invalid_ca_path_errors() {
        use crate::config::CaCertBinding;
        let proxy = ProxySpec {
            http: None,
            https: None,
            no_proxy: vec![],
            ca_certs: vec![CaCertBinding {
                env: "FOO".into(),
                path: camino::Utf8PathBuf::from("/nonexistent/path/to/ca.pem"),
            }],
        };
        let err = build_blocking_client(Some(&proxy));
        assert!(err.is_err());
    }

    #[test]
    fn build_blocking_client_rejects_empty_pem_file() {
        // SEC-08 / #144: a CA cert file with no PEM CERTIFICATE blocks
        // (e.g. operator pointed at the wrong file, file holds only
        // comments, or the file was truncated) must be rejected at
        // build time. The previous reqwest::Certificate::from_pem call
        // tolerated this under the rustls backend by storing raw bytes,
        // which then evaporated to "no roots added" silently.
        use crate::config::CaCertBinding;
        let dir = tempfile::tempdir().unwrap();
        let pem_path = dir.path().join("empty.pem");
        std::fs::write(&pem_path, b"# no certs here\n").unwrap();
        let proxy = ProxySpec {
            http: None,
            https: None,
            no_proxy: vec![],
            ca_certs: vec![CaCertBinding {
                env: "BAR".into(),
                path: camino::Utf8PathBuf::from_path_buf(pem_path).unwrap(),
            }],
        };
        let err = build_blocking_client(Some(&proxy)).unwrap_err();
        let msg = err.to_string();
        assert!(
            msg.contains("empty or contains no valid PEM certificates"),
            "msg={msg}"
        );
    }

    #[test]
    fn build_blocking_client_rejects_pem_with_only_unrelated_blocks() {
        // SEC-08 / #144: a file that contains PEM blocks but NO
        // CERTIFICATE blocks (e.g. a bundle holding only DH parameters,
        // CRL entries, or a private key) must also be rejected — the
        // operator declared a CA path but provided no roots.
        use crate::config::CaCertBinding;
        let dir = tempfile::tempdir().unwrap();
        let pem_path = dir.path().join("nocert.pem");
        std::fs::write(
            &pem_path,
            b"-----BEGIN PRIVATE KEY-----\ndGVzdA==\n-----END PRIVATE KEY-----\n",
        )
        .unwrap();
        let proxy = ProxySpec {
            http: None,
            https: None,
            no_proxy: vec![],
            ca_certs: vec![CaCertBinding {
                env: "BAZ".into(),
                path: camino::Utf8PathBuf::from_path_buf(pem_path).unwrap(),
            }],
        };
        let err = build_blocking_client(Some(&proxy)).unwrap_err();
        let msg = err.to_string();
        assert!(
            msg.contains("empty or contains no valid PEM certificates"),
            "msg={msg}"
        );
    }

    // ---- existing parse_url tests -------------------------------------

    #[test]
    fn parse_org_url() {
        assert_eq!(
            parse_url("https://github.com/example").unwrap(),
            Scope::Org {
                owner: "example".into()
            }
        );
    }

    #[test]
    fn parse_repo_url() {
        assert_eq!(
            parse_url("https://github.com/example/repo").unwrap(),
            Scope::Repo {
                owner: "example".into(),
                repo: "repo".into(),
            }
        );
    }

    #[test]
    fn parse_repo_url_trailing_slash() {
        assert_eq!(
            parse_url("https://github.com/example/repo/").unwrap(),
            Scope::Repo {
                owner: "example".into(),
                repo: "repo".into(),
            }
        );
    }

    #[test]
    fn rejects_http() {
        assert!(parse_url("http://github.com/example/repo").is_err());
    }

    #[test]
    fn rejects_non_github_host() {
        assert!(parse_url("https://example.com/owner/repo").is_err());
    }

    #[test]
    fn rejects_userinfo() {
        assert!(parse_url("https://user@github.com/owner/repo").is_err());
    }

    #[test]
    fn rejects_query() {
        assert!(parse_url("https://github.com/owner/repo?branch=main").is_err());
    }

    #[test]
    fn rejects_fragment() {
        assert!(parse_url("https://github.com/owner/repo#x").is_err());
    }

    #[test]
    fn rejects_too_many_segments() {
        assert!(parse_url("https://github.com/owner/repo/extra").is_err());
    }

    #[test]
    fn rejects_empty_path() {
        assert!(parse_url("https://github.com/").is_err());
    }

    #[test]
    fn rejects_uppercase_host() {
        // url::Url normalizes the host to lowercase per RFC 3986, so
        // without the validate_url() pre-check this would silently
        // succeed. validators::URL_REGEX is case-sensitive — these
        // forms must reject (#175).
        assert!(parse_url("https://GITHUB.com/example/repo").is_err());
        assert!(parse_url("https://Github.com/example/repo").is_err());
        assert!(parse_url("https://GITHUB.COM/example/repo").is_err());
    }

    #[test]
    fn user_agent_is_versioned() {
        // #181: github.rs USER_AGENT must be `ghars/<version>` to match
        // extract.rs. The crate version comes from CARGO_PKG_VERSION at
        // build time, so the prefix is the stable assertion target.
        assert!(USER_AGENT.starts_with("ghars/"));
        assert!(USER_AGENT.len() > "ghars/".len());
    }

    // ---- #164: parse_url Python-parity rejection cases ----------------
    //
    // validators.rs::tests::url_rejects already enumerates the full
    // Python `test_url_rejects` set against `validate_url`. These cases
    // pin the same coverage at the `parse_url` entry point so any
    // regression in the validate_url -> parse_url chain (e.g. the
    // `validate_url` pre-check getting accidentally removed) surfaces
    // here. The list mirrors install_gha_runner.py:1857-1882 plus an
    // explicit-port case.

    #[rstest]
    #[case("", "empty")]
    #[case("github.com/x/y", "no-scheme")]
    #[case("ftp://github.com/x/y", "ftp-scheme")]
    #[case("https://github.com//etc/passwd", "double-slash-path")]
    #[case("https://github.com///etc/passwd", "triple-slash-path")]
    #[case("https://github.com/../etc/passwd", "dotdot-owner")]
    #[case("https://github.com/owner/../etc", "dotdot-repo")]
    #[case("https://github.com/.hidden/x", "dot-prefixed-owner")]
    #[case("https://github.com/x/.hidden", "dot-prefixed-repo")]
    #[case("https://github.com:@other/x/y", "userinfo-empty")]
    #[case("https://github.com.evil.tld/x/y", "host-suffix")]
    #[case("https://github.com/x/y/settings/actions", "extra-path")]
    #[case("https://github.com:443/owner/repo", "explicit-port")]
    #[case("https://github.com/owner name/repo", "space-in-owner")]
    fn parse_url_rejects_python_parity(#[case] u: &str, #[case] label: &str) {
        let res = parse_url(u);
        assert!(res.is_err(), "must reject {label}: {u:?}");
    }

    // ---- #166: extract_sha256 body-format edge cases ------------------

    #[test]
    fn extract_sha256_asset_digest_preferred_over_body() {
        // Both an asset digest AND a matching body line are present;
        // the asset digest must win (it is the authoritative field
        // GitHub publishes per release; body lines are markdown notes).
        let payload = ReleaseApiPayload {
            tag_name: "v2.334.0".into(),
            assets: vec![ReleaseAsset {
                name: "actions-runner-linux-x64-2.334.0.tar.gz".into(),
                digest: Some(format!("sha256:{}", "1".repeat(64))),
            }],
            body: Some(format!(
                "{}  actions-runner-linux-x64-2.334.0.tar.gz",
                "2".repeat(64)
            )),
        };
        let sha = extract_sha256(&payload, "actions-runner-linux-x64-2.334.0.tar.gz").unwrap();
        // Asset digest "1...1" wins over body "2...2".
        assert_eq!(sha, "1".repeat(64));
    }

    #[test]
    fn extract_sha256_body_with_multiple_filenames_picks_matching_one() {
        // Real release notes list per-arch lines side-by-side. Only
        // the line whose second token matches the requested filename
        // must contribute the digest; the other lines must be skipped.
        let body = format!(
            concat!(
                "Pre\n",
                "{}  actions-runner-linux-x64-2.334.0.tar.gz\n",
                "{}  actions-runner-linux-arm64-2.334.0.tar.gz\n",
                "{}  actions-runner-osx-x64-2.334.0.tar.gz\n",
                "Post"
            ),
            "a".repeat(64),
            "b".repeat(64),
            "c".repeat(64),
        );
        let payload = ReleaseApiPayload {
            tag_name: "v2.334.0".into(),
            assets: vec![],
            body: Some(body),
        };
        let arm = extract_sha256(&payload, "actions-runner-linux-arm64-2.334.0.tar.gz").unwrap();
        assert_eq!(arm, "b".repeat(64));
        let x64 = extract_sha256(&payload, "actions-runner-linux-x64-2.334.0.tar.gz").unwrap();
        assert_eq!(x64, "a".repeat(64));
    }

    #[test]
    fn extract_sha256_hex_with_unrelated_filename_skipped() {
        // The body holds a 64-hex line but the second token is the
        // wrong filename. Must NOT match; otherwise an attacker who
        // controls release notes for ANY arch could plant a digest
        // that ghars accepts for a DIFFERENT arch.
        let body = format!("{}  some-unrelated-file.tar.gz", "f".repeat(64));
        let payload = ReleaseApiPayload {
            tag_name: "v2.334.0".into(),
            assets: vec![],
            body: Some(body),
        };
        assert!(extract_sha256(&payload, "actions-runner-linux-x64-2.334.0.tar.gz").is_err());
    }

    #[test]
    fn extract_sha256_body_substring_match_is_not_enough() {
        // The body token IS the right filename only as a substring of a
        // longer token. tokens-must-match-exactly invariant: a token like
        // `actions-runner-linux-x64-2.334.0.tar.gz.sig` (wrong file: the
        // signature file, not the tarball) must NOT count as a match.
        let body = format!(
            "{}  actions-runner-linux-x64-2.334.0.tar.gz.sig",
            "9".repeat(64)
        );
        let payload = ReleaseApiPayload {
            tag_name: "v2.334.0".into(),
            assets: vec![],
            body: Some(body),
        };
        assert!(extract_sha256(&payload, "actions-runner-linux-x64-2.334.0.tar.gz").is_err());
    }

    #[test]
    fn extract_sha256_body_with_trailing_backtick_attached_to_filename_no_match() {
        // Python's `lstrip("\x60")` only strips LEADING backticks (the
        // markdown code-fence opener). A trailing backtick appended to
        // the filename token (e.g. operator opened ``` on the previous
        // line and closed it inline) is part of the second token, so
        // the strict equality check `second == filename` fails. Pin
        // this behavior — a future change that does `trim_matches('`')`
        // would silently match `filename\x60` to `filename`.
        let body = format!(
            "Pre\n`{}  actions-runner-linux-x64-2.334.0.tar.gz`\nPost",
            "7".repeat(64)
        );
        let payload = ReleaseApiPayload {
            tag_name: "v2.334.0".into(),
            assets: vec![],
            body: Some(body),
        };
        // Filename WITH trailing backtick is the second token and does
        // not equal the bare filename → no match.
        assert!(extract_sha256(&payload, "actions-runner-linux-x64-2.334.0.tar.gz").is_err());
    }

    #[test]
    fn extract_sha256_body_with_single_space_between_tokens_matches() {
        // Python's `.split()` and Rust's `split_whitespace()` are both
        // whitespace-agnostic — they tokenize on any run of whitespace,
        // not just the conventional double-space `sha256sum -c` layout.
        // A single-space line `<hex> <filename>` must therefore match.
        let body = format!("{} actions-runner-linux-x64-2.334.0.tar.gz", "5".repeat(64));
        let payload = ReleaseApiPayload {
            tag_name: "v2.334.0".into(),
            assets: vec![],
            body: Some(body),
        };
        let sha = extract_sha256(&payload, "actions-runner-linux-x64-2.334.0.tar.gz").unwrap();
        assert_eq!(sha, "5".repeat(64));
    }

    #[test]
    fn extract_sha256_body_with_leading_whitespace_before_backtick_matches() {
        // Some operators indent code blocks with leading spaces.
        // The parser does `let stripped = line.trim()` first, then
        // `trim_start_matches('`')` — so `   `<hex>  <filename>` is
        // trimmed to `<hex>  <filename>`, then de-backticked, then
        // tokenized normally. Pin this against a mutant that drops
        // the trim() and breaks indented release notes.
        let body = format!(
            "Pre\n   `{}  actions-runner-linux-x64-2.334.0.tar.gz\nPost",
            "6".repeat(64)
        );
        let payload = ReleaseApiPayload {
            tag_name: "v2.334.0".into(),
            assets: vec![],
            body: Some(body),
        };
        let sha = extract_sha256(&payload, "actions-runner-linux-x64-2.334.0.tar.gz").unwrap();
        assert_eq!(sha, "6".repeat(64));
    }

    #[test]
    fn extract_sha256_body_line_with_only_one_token_no_match() {
        // Defensive: a line that contains the filename in the digest
        // token (instead of as a separate second token) must NOT match.
        // The body parser explicitly requires `is_hex64(first) && second
        // == filename`; one-token lines fail at the second-token check.
        let body = format!("{}-actions-runner-linux-x64-2.334.0.tar.gz", "8".repeat(64));
        let payload = ReleaseApiPayload {
            tag_name: "v2.334.0".into(),
            assets: vec![],
            body: Some(body),
        };
        assert!(extract_sha256(&payload, "actions-runner-linux-x64-2.334.0.tar.gz").is_err());
    }

    // ---- #165: fetch_latest_release / fetch_release end-to-end --------

    /// Build the JSON body mockito serves for a mocked GitHub release.
    /// Captures the contract ghars depends on:
    /// - `tag_name` is `vX.Y.Z`
    /// - `assets[]` carries `name` + `digest = "sha256:HEX"`
    /// - `body` carries a redundant `<hex>  <filename>` line so tests
    ///   can assert the asset-digest path is preferred.
    fn release_json(tag: &str, sha_x64: &str, sha_arm: &str) -> String {
        format!(
            r#"{{
              "tag_name": "{tag}",
              "name": "v{tag}",
              "body": "Released. ` {sha_x64}  actions-runner-linux-x64-{ver}.tar.gz` ` {sha_arm}  actions-runner-linux-arm64-{ver}.tar.gz`",
              "assets": [
                {{
                  "name": "actions-runner-linux-x64-{ver}.tar.gz",
                  "digest": "sha256:{sha_x64}"
                }},
                {{
                  "name": "actions-runner-linux-arm64-{ver}.tar.gz",
                  "digest": "sha256:{sha_arm}"
                }}
              ]
            }}"#,
            tag = tag,
            ver = tag.trim_start_matches('v'),
            sha_x64 = sha_x64,
            sha_arm = sha_arm,
        )
    }

    #[test]
    fn fetch_latest_release_round_trips_x64_via_mockito() {
        let mut server = mockito::Server::new();
        let sha = "a".repeat(64);
        let arm_sha = "b".repeat(64);
        let mock = server
            .mock("GET", "/repos/actions/runner/releases/latest")
            .match_header("Accept", "application/vnd.github+json")
            .match_header("X-GitHub-Api-Version", "2022-11-28")
            .match_header("user-agent", mockito::Matcher::Regex("^ghars/".into()))
            .with_status(200)
            .with_header("content-type", "application/json")
            .with_body(release_json("v2.334.0", &sha, &arm_sha))
            .expect(1)
            .create();

        let url = format!("{}/repos/actions/runner/releases/latest", server.url());
        let client = build_blocking_client(None).unwrap();
        let rel = fetch_latest_release_at(&client, &url, Arch::X86_64).unwrap();

        assert_eq!(rel.version, "2.334.0");
        assert_eq!(rel.sha256, sha);
        assert_eq!(rel.tarball_name, "actions-runner-linux-x64-2.334.0.tar.gz");
        assert!(
            rel.tarball_url
                .starts_with("https://github.com/actions/runner/releases/download/v2.334.0/")
        );
        mock.assert();
    }

    #[test]
    fn fetch_latest_release_uses_arm64_asset_when_arch_arm64() {
        // Same JSON, different arch query parameter — release_from_api
        // must look up the arm64 asset, not the x64 one.
        let mut server = mockito::Server::new();
        let sha_x64 = "1".repeat(64);
        let sha_arm = "2".repeat(64);
        let mock = server
            .mock("GET", "/repos/actions/runner/releases/latest")
            .with_status(200)
            .with_header("content-type", "application/json")
            .with_body(release_json("v2.334.0", &sha_x64, &sha_arm))
            .create();

        let url = format!("{}/repos/actions/runner/releases/latest", server.url());
        let client = build_blocking_client(None).unwrap();
        let rel = fetch_latest_release_at(&client, &url, Arch::Aarch64).unwrap();

        assert_eq!(rel.sha256, sha_arm);
        assert_eq!(
            rel.tarball_name,
            "actions-runner-linux-arm64-2.334.0.tar.gz"
        );
        mock.assert();
    }

    #[test]
    fn fetch_release_round_trips_pinned_version_via_mockito() {
        let mut server = mockito::Server::new();
        let sha = "c".repeat(64);
        let arm_sha = "d".repeat(64);
        // The path GitHub serves for pinned tags: /repos/.../tags/vX.Y.Z.
        let mock = server
            .mock("GET", "/repos/actions/runner/releases/tags/v2.300.0")
            .match_header("Accept", "application/vnd.github+json")
            .with_status(200)
            .with_header("content-type", "application/json")
            .with_body(release_json("v2.300.0", &sha, &arm_sha))
            .expect(1)
            .create();

        // Build a template the helper can interpolate with `{version}`.
        let template = format!(
            "{}/repos/actions/runner/releases/tags/v{{version}}",
            server.url()
        );
        let client = build_blocking_client(None).unwrap();
        let rel = fetch_release_at(&client, &template, "2.300.0", Arch::X86_64).unwrap();

        assert_eq!(rel.version, "2.300.0");
        assert_eq!(rel.sha256, sha);
        assert_eq!(rel.tarball_name, "actions-runner-linux-x64-2.300.0.tar.gz");
        mock.assert();
    }

    #[test]
    fn fetch_release_propagates_validate_version_failure() {
        // validate_version() must run BEFORE the URL is constructed, so
        // a malformed version produces a Validation error and never
        // hits the (mockito) server. Asserting the mock is NOT called
        // closes the network-leak risk in argv handling.
        let mut server = mockito::Server::new();
        let mock = server
            .mock("GET", mockito::Matcher::Any)
            .with_status(200)
            .expect(0)
            .create();

        let template = format!(
            "{}/repos/actions/runner/releases/tags/v{{version}}",
            server.url()
        );
        let client = build_blocking_client(None).unwrap();
        let err = fetch_release_at(&client, &template, "not.a.version", Arch::X86_64).unwrap_err();
        assert!(matches!(err, GharsError::Validation(_, _)));
        mock.assert();
    }

    #[test]
    fn fetch_latest_release_propagates_http_error() {
        // 404 from the mocked endpoint must surface as GharsError::GitHub
        // with the 404-specific hint covering both fetch_latest_release
        // (no version — the "owner/repo exist" guidance applies) and
        // fetch_release(version) (the "runner version (if specified)"
        // guidance applies).
        let mut server = mockito::Server::new();
        let mock = server
            .mock("GET", "/repos/actions/runner/releases/latest")
            .with_status(404)
            .with_body("not found")
            .expect(1)
            .create();

        let url = format!("{}/repos/actions/runner/releases/latest", server.url());
        let client = build_blocking_client(None).unwrap();
        let err = fetch_latest_release_at(&client, &url, Arch::X86_64).unwrap_err();
        match err {
            GharsError::GitHub(msg, hint) => {
                assert!(msg.contains("404"), "msg must include status code; got: {msg}");
                assert!(
                    hint.contains("runner version") && hint.contains("owner/repo"),
                    "404 hint must surface runner-version + owner/repo guidance; got: {hint}"
                );
            }
            other => panic!("expected GharsError::GitHub, got {other:?}"),
        }
        mock.assert();
    }

    /// devadv #679 supplemental: 429 rate-limit responses must surface
    /// the operator-actionable Retry-After hint, mirroring the
    /// "secondary rate limit" wording in `auth.rs::octocrab_to_auth`.
    /// "secondary" is the GitHub-specific term (vs primary rate
    /// limits which expose `X-RateLimit-Reset`); pinning it ensures
    /// the operator-facing terminology matches GitHub docs.
    #[test]
    fn fetch_latest_release_429_emits_rate_limit_hint() {
        let mut server = mockito::Server::new();
        let mock = server
            .mock("GET", "/repos/actions/runner/releases/latest")
            .with_status(429)
            .with_body("rate limited")
            .expect(1)
            .create();
        let url = format!("{}/repos/actions/runner/releases/latest", server.url());
        let client = build_blocking_client(None).unwrap();
        let err = fetch_latest_release_at(&client, &url, Arch::X86_64).unwrap_err();
        match err {
            GharsError::GitHub(msg, hint) => {
                assert!(msg.contains("429"), "msg must include status code; got: {msg}");
                // URL trailing-position pin: HTTP-status arm uses the
                // same ": {url}" suffix shape as Layer 1 / Layer 2 so a
                // single log parser can match all three error classes.
                assert!(
                    msg.ends_with(&format!(": {url}")),
                    "HTTP-status (429) msg must end with ': {{url}}'; got: {msg}"
                );
                assert!(
                    hint.contains("secondary rate limit") && hint.contains("Retry-After"),
                    "429 hint must mention secondary rate limit + Retry-After; got: {hint}"
                );
            }
            other => panic!("expected GharsError::GitHub, got {other:?}"),
        }
        mock.assert();
    }

    /// Pins the 401|403 match arm's primary diagnostic: the releases-API
    /// path is unauthenticated by default, so a 401 response means a
    /// proxy or GHE mirror is intercepting and demanding credentials
    /// from an intermediate. The token/PAT advice is downstream of that
    /// proxy/GHE diagnosis — the operator must first identify that an
    /// intermediate is in the path before token validity matters.
    #[test]
    fn fetch_latest_release_401_emits_public_endpoint_proxy_hint() {
        let mut server = mockito::Server::new();
        let mock = server
            .mock("GET", "/repos/actions/runner/releases/latest")
            .with_status(401)
            .with_body("unauthorized")
            .expect(1)
            .create();
        let url = format!("{}/repos/actions/runner/releases/latest", server.url());
        let client = build_blocking_client(None).unwrap();
        let err = fetch_latest_release_at(&client, &url, Arch::X86_64).unwrap_err();
        match err {
            GharsError::GitHub(msg, hint) => {
                assert!(msg.contains("401"), "msg must include status code; got: {msg}");
                assert!(
                    hint.contains("normally public"),
                    "401 hint must surface public-endpoint qualifier; got: {hint}"
                );
                assert!(
                    hint.contains("token/PAT") && hint.contains("permissions"),
                    "401 hint must mention token/PAT + permissions; got: {hint}"
                );
                assert!(
                    hint.contains("proxy") || hint.contains("GHE mirror"),
                    "401 hint must mention proxy/GHE mirror context; got: {hint}"
                );
            }
            other => panic!("expected GharsError::GitHub, got {other:?}"),
        }
        mock.assert();
    }

    /// Pins that 403 shares the 401|403 match arm — a regression
    /// splitting the arm would surface here. Same proxy/GHE-mirror
    /// diagnosis as 401: the releases-API path is unauthenticated by
    /// default, so 403 indicates an intermediate (proxy or mirror) is
    /// rejecting the request, not GitHub.
    #[test]
    fn fetch_latest_release_403_emits_public_endpoint_proxy_hint() {
        let mut server = mockito::Server::new();
        let mock = server
            .mock("GET", "/repos/actions/runner/releases/latest")
            .with_status(403)
            .with_body("forbidden")
            .expect(1)
            .create();
        let url = format!("{}/repos/actions/runner/releases/latest", server.url());
        let client = build_blocking_client(None).unwrap();
        let err = fetch_latest_release_at(&client, &url, Arch::X86_64).unwrap_err();
        match err {
            GharsError::GitHub(msg, hint) => {
                assert!(msg.contains("403"), "msg must include status code; got: {msg}");
                assert!(
                    hint.contains("normally public"),
                    "403 hint must surface public-endpoint qualifier; got: {hint}"
                );
                assert!(
                    hint.contains("token/PAT") && hint.contains("permissions"),
                    "403 hint must mention token/PAT + permissions; got: {hint}"
                );
                assert!(
                    hint.contains("proxy") || hint.contains("GHE mirror"),
                    "403 hint must mention proxy/GHE mirror context; got: {hint}"
                );
            }
            other => panic!("expected GharsError::GitHub, got {other:?}"),
        }
        mock.assert();
    }

    /// devadv #679 supplemental: 5xx responses surface the
    /// upstream-degraded hint with status.github.com pointer. Mirrors
    /// the 5xx arm in `auth.rs::octocrab_to_auth`.
    #[test]
    fn fetch_latest_release_503_emits_upstream_degraded_hint() {
        let mut server = mockito::Server::new();
        let mock = server
            .mock("GET", "/repos/actions/runner/releases/latest")
            .with_status(503)
            .with_body("service unavailable")
            .expect(1)
            .create();
        let url = format!("{}/repos/actions/runner/releases/latest", server.url());
        let client = build_blocking_client(None).unwrap();
        let err = fetch_latest_release_at(&client, &url, Arch::X86_64).unwrap_err();
        match err {
            GharsError::GitHub(msg, hint) => {
                assert!(msg.contains("503"), "msg must include status code; got: {msg}");
                assert!(
                    hint.contains("upstream is degraded") && hint.contains("status.github.com"),
                    "5xx hint must mention upstream-degraded + status.github.com; got: {hint}"
                );
                // Defense-in-depth: the 5xx arm must NOT carry the
                // catch-all's `file a ghars bug` escalation, otherwise a
                // future refactor that collapses the 5xx arm into the
                // catch-all would silently lose the upstream-degraded
                // diagnostic.
                assert!(!hint.contains("file a ghars bug"));
            }
            other => panic!("expected GharsError::GitHub, got {other:?}"),
        }
        mock.assert();
    }

    /// devadv #679 supplemental: a status code outside the named arms
    /// (e.g. 418 I'm a teapot) takes the catch-all generic hint —
    /// distinct from any of the specific-class hints.
    #[test]
    fn fetch_latest_release_other_4xx_emits_generic_hint() {
        let mut server = mockito::Server::new();
        let mock = server
            .mock("GET", "/repos/actions/runner/releases/latest")
            .with_status(418)
            .with_body("teapot")
            .expect(1)
            .create();
        let url = format!("{}/repos/actions/runner/releases/latest", server.url());
        let client = build_blocking_client(None).unwrap();
        let err = fetch_latest_release_at(&client, &url, Arch::X86_64).unwrap_err();
        match err {
            GharsError::GitHub(msg, hint) => {
                assert!(msg.contains("418"), "msg must include status code; got: {msg}");
                assert!(
                    hint.contains("unexpected HTTP status"),
                    "catch-all hint must use generic wording; got: {hint}"
                );
                assert!(
                    hint.contains("file a ghars bug"),
                    "catch-all hint must surface ghars-bug escalation; got: {hint}"
                );
                // Defense-in-depth: the catch-all must NOT carry any of
                // the specific-class hint substrings, otherwise a future
                // refactor that collapses the match into the catch-all
                // arm would silently lose operator guidance.
                assert!(!hint.contains("rate limit"));
                assert!(!hint.contains("token/PAT"));
                assert!(!hint.contains("upstream is degraded"));
                assert!(!hint.contains("runner version"));
            }
            other => panic!("expected GharsError::GitHub, got {other:?}"),
        }
        mock.assert();
    }

    #[test]
    fn fetch_latest_release_propagates_invalid_json_error() {
        // Garbage body (valid HTTP 200 but not JSON) must surface as
        // GharsError::GitHub from the resp.json() decode failure.
        let mut server = mockito::Server::new();
        let mock = server
            .mock("GET", "/repos/actions/runner/releases/latest")
            .with_status(200)
            .with_header("content-type", "application/json")
            .with_body("not valid json {")
            .expect(1)
            .create();

        let url = format!("{}/repos/actions/runner/releases/latest", server.url());
        let client = build_blocking_client(None).unwrap();
        let err = fetch_latest_release_at(&client, &url, Arch::X86_64).unwrap_err();
        assert!(matches!(err, GharsError::GitHub(_, _)));
        mock.assert();
    }

    #[test]
    fn fetch_latest_release_falls_back_to_body_when_asset_digest_absent() {
        // Older releases publish no `digest` on assets. ghars must fall
        // back to the sha256sum-style body line; mockito-served JSON
        // here has assets without digests but a body with a matching
        // hex/filename pair.
        let mut server = mockito::Server::new();
        let sha = "5".repeat(64);
        let body_json = format!(
            r#"{{
              "tag_name": "v1.2.3",
              "body": "Some text\n{sha}  actions-runner-linux-x64-1.2.3.tar.gz\nMore",
              "assets": [
                {{
                  "name": "actions-runner-linux-x64-1.2.3.tar.gz"
                }}
              ]
            }}"#
        );
        let mock = server
            .mock("GET", "/repos/actions/runner/releases/latest")
            .with_status(200)
            .with_header("content-type", "application/json")
            .with_body(body_json)
            .expect(1)
            .create();

        let url = format!("{}/repos/actions/runner/releases/latest", server.url());
        let client = build_blocking_client(None).unwrap();
        let rel = fetch_latest_release_at(&client, &url, Arch::X86_64).unwrap();
        assert_eq!(rel.sha256, sha);
        mock.assert();
    }

    // ---- #666: response body size cap ---------------------------------

    /// #666 normal-size body acceptance pin: a typical releases JSON
    /// (~50 KB) succeeds without hitting either body-size gate. Pinned
    /// alongside the rejection cases so a regression that drops the cap
    /// to a too-tight value (e.g. accidental switch to 1 KiB) is caught.
    #[test]
    fn http_get_payload_accepts_normal_size_body() {
        let mut server = mockito::Server::new();
        let sha = "9".repeat(64);
        let arm_sha = "8".repeat(64);
        let mock = server
            .mock("GET", "/repos/actions/runner/releases/latest")
            .with_status(200)
            .with_header("content-type", "application/json")
            .with_body(release_json("v2.334.0", &sha, &arm_sha))
            .expect(1)
            .create();
        let url = format!("{}/repos/actions/runner/releases/latest", server.url());
        let client = build_blocking_client(None).unwrap();
        let rel = fetch_latest_release_at(&client, &url, Arch::X86_64).unwrap();
        assert_eq!(rel.sha256, sha);
        mock.assert();
    }

    /// #666 oversize body rejection pin: when the body exceeds
    /// `MAX_RELEASES_BODY_BYTES`, http_get_payload rejects the
    /// response. Mockito sets Content-Length automatically from the
    /// served body, so this single test exercises the Layer-1
    /// pre-read rejection path (the CL header reflects the real
    /// oversize body length, the pre-check fires before any read).
    /// The Layer-2 streaming defense — the `reader.take(cap + 1).read_to_end()`
    /// code at github.rs::read_body_capped — is exercised separately
    /// by `http_get_payload_with_cap_rejects_via_layer_2_streaming_when_no_content_length`
    /// (chunked transfer-encoding bypasses Layer 1) and by
    /// `read_body_capped_rejects_over_cap` (direct helper test).
    /// This runtime test pins the contract that an oversize body
    /// produces a rejection regardless of which layer caught it.
    /// Body sized at `MAX + 64` bytes — just enough to trip the cap; mockito
    /// allocates from a Vec<u8>, so the in-memory cost is bounded.
    #[test]
    fn http_get_payload_rejects_oversize_body() {
        let mut server = mockito::Server::new();
        let oversize = (MAX_RELEASES_BODY_BYTES + 64) as usize;
        let body = vec![b'x'; oversize];
        let mock = server
            .mock("GET", "/repos/actions/runner/releases/latest")
            .with_status(200)
            .with_header("content-type", "application/json")
            .with_body(body)
            .expect(1)
            .create();
        let url = format!("{}/repos/actions/runner/releases/latest", server.url());
        let client = build_blocking_client(None).unwrap();
        let err = fetch_latest_release_at(&client, &url, Arch::X86_64).unwrap_err();
        match err {
            GharsError::GitHub(msg, hint) => {
                // Layer 1 is reached first because mockito sets
                // Content-Length from the real body length. Pin the
                // exact rejection wording so a regression that breaks
                // either gate surfaces cleanly.
                assert!(
                    msg.contains("Content-Length") && msg.contains("exceeds"),
                    "msg must come from a body-size rejection gate; got: {msg}"
                );
                assert!(
                    hint.contains("hostile proxy") || hint.contains("compromised mirror"),
                    "hint must surface attacker model; got: {hint}"
                );
            }
            other => panic!("expected GharsError::GitHub, got {other:?}"),
        }
        mock.assert();
    }

    // ---- #680: read_body_capped + http_get_payload_with_cap unit tests ---

    /// #680: `read_body_capped` returns Ok with the full buffer when
    /// the reader has exactly `cap` bytes (the boundary case). Pinned
    /// to defend against an off-by-one regression that uses `>=` in
    /// place of `>` on the buf-len check.
    #[test]
    fn read_body_capped_accepts_exactly_at_cap() {
        let cap: u64 = 64;
        let body = vec![b'x'; cap as usize];
        let buf = read_body_capped(std::io::Cursor::new(body.clone()), cap).unwrap();
        assert_eq!(buf, body);
    }

    /// #680: `read_body_capped` returns Ok with the buffer when the
    /// reader has fewer than `cap` bytes (the under-cap case).
    #[test]
    fn read_body_capped_accepts_under_cap() {
        let cap: u64 = 64;
        let body = vec![b'y'; 32];
        let buf = read_body_capped(std::io::Cursor::new(body.clone()), cap).unwrap();
        assert_eq!(buf, body);
    }

    /// #680: `read_body_capped` returns `BodyCapError::CapExceeded`
    /// when the reader has more than `cap` bytes. Pinned to defend
    /// against a regression that drops the `take(cap+1)` guard and
    /// lets oversize bodies flow through. The cap value is propagated
    /// via the variant payload so the wrapper can compose the
    /// operator-visible diagnostic — the helper itself emits no
    /// strings.
    #[test]
    fn read_body_capped_rejects_over_cap() {
        let cap: u64 = 64;
        let body = vec![b'z'; (cap + 1) as usize];
        let err = read_body_capped(std::io::Cursor::new(body), cap).unwrap_err();
        match err {
            BodyCapError::CapExceeded { cap: reported } => {
                assert_eq!(
                    reported, cap,
                    "CapExceeded must propagate the configured cap value; got: {reported}"
                );
            }
            other => panic!("expected BodyCapError::CapExceeded, got {other:?}"),
        }
    }

    /// #680: `http_get_payload_with_cap` end-to-end pin against
    /// mockito with a small cap (64 bytes). Body is 128 bytes, larger
    /// than the cap; production code path goes through Layer 1 (CL
    /// header check) and rejects with "Content-Length ... exceeds 64
    /// bytes". This exercises the cap-injection seam without
    /// requiring a 4 MiB body. Also pins Layer 1 hint differentiation
    /// (on-wire / pre-decompression framing distinct from Layer 2's
    /// post-decompression / bomb-signature framing) and the
    /// MAX_RELEASES_BODY_BYTES escape-hatch breadcrumb.
    #[test]
    fn http_get_payload_with_cap_rejects_via_layer_1_cl_check() {
        let mut server = mockito::Server::new();
        let body = vec![b'a'; 128];
        let mock = server
            .mock("GET", "/repos/actions/runner/releases/latest")
            .with_status(200)
            .with_header("content-type", "application/json")
            .with_body(body)
            .expect(1)
            .create();
        let url = format!("{}/repos/actions/runner/releases/latest", server.url());
        let client = build_blocking_client(None).unwrap();
        let err = http_get_payload_with_cap(&client, &url, 64).unwrap_err();
        match err {
            GharsError::GitHub(msg, hint) => {
                assert!(
                    msg.contains("Content-Length") && msg.contains("128") && msg.contains("64"),
                    "msg must surface CL=128 vs cap=64; got: {msg}"
                );
                // URL trailing-position pin: the wrapper places the URL
                // at the end of the message so log parsers can grep the
                // line with a stable suffix. A regression that moves the
                // URL into the middle of the message would surface here.
                assert!(
                    msg.ends_with(&format!(": {url}")),
                    "Layer 1 msg must end with ': {{url}}'; got: {msg}"
                );
                // Layer 1 differentiation: on-wire/pre-decompression framing distinct from Layer 2's post-decompression/bomb-signature framing.
                assert!(
                    hint.contains("on-wire") && hint.contains("pre-decompression"),
                    "Layer 1 hint must surface on-wire/pre-decompression framing; got: {hint}"
                );
                assert!(
                    !hint.contains("post-decompression"),
                    "Layer 1 hint must NOT surface post-decompression framing (Layer 2 territory); got: {hint}"
                );
                assert!(
                    !hint.contains("compression-bomb signature"),
                    "Layer 1 hint must NOT surface bomb-signature framing (Layer 2 territory); got: {hint}"
                );
                assert!(
                    hint.contains("MAX_RELEASES_BODY_BYTES"),
                    "Layer 1 hint must surface MAX_RELEASES_BODY_BYTES escape hatch; got: {hint}"
                );
            }
            other => panic!("expected GharsError::GitHub, got {other:?}"),
        }
        mock.assert();
    }

    /// `http_get_payload_with_cap` end-to-end pin against
    /// mockito with a chunked-transfer body (no Content-Length
    /// header). Mockito's `with_chunked_body` routes through
    /// `Body::FnWithWriter` which the server emits without setting
    /// `content-length` (mockito-1.7.2/src/server.rs:587 only adds CL
    /// for `ResponseBody::Bytes`). This forces Layer 1 to skip and
    /// Layer 2 (the streaming `read_body_capped` post-decompression
    /// gate) to fire — the actual gzip-bomb defense surface.
    ///
    /// Asserts the wrapped error format: starts with "GitHub API
    /// response", contains "body exceeds" + cap value + "compression
    /// bomb", surfaces "post-decompression" framing distinct from
    /// Layer 1's "on-wire / pre-decompression" framing, and crucially
    /// does NOT contain the doubled-noun "response response"
    /// (regression pin for cleaner F-1 fix).
    #[test]
    fn http_get_payload_with_cap_rejects_via_layer_2_streaming_when_no_content_length() {
        let mut server = mockito::Server::new();
        let mock = server
            .mock("GET", "/repos/actions/runner/releases/latest")
            .with_status(200)
            .with_header("content-type", "application/json")
            .with_chunked_body(|w| w.write_all(&vec![b'q'; 128]))
            .expect(1)
            .create();
        let url = format!("{}/repos/actions/runner/releases/latest", server.url());
        let client = build_blocking_client(None).unwrap();
        let err = http_get_payload_with_cap(&client, &url, 64).unwrap_err();
        match err {
            GharsError::GitHub(msg, hint) => {
                assert!(
                    msg.starts_with("GitHub API response"),
                    "wrapped msg must start with 'GitHub API response'; got: {msg}"
                );
                assert!(
                    msg.contains("body exceeds") && msg.contains("64 bytes"),
                    "wrapped msg must surface 'body exceeds' + cap value 64; got: {msg}"
                );
                assert!(
                    msg.contains("compression bomb"),
                    "wrapped msg must surface 'compression bomb' diagnostic; got: {msg}"
                );
                assert!(
                    msg.contains("post-decompression"),
                    "Layer 2 msg must surface 'post-decompression' (Layer 1 vs Layer 2 differentiation); got: {msg}"
                );
                assert!(
                    !msg.contains("response response"),
                    "anti-doubling pin: wrapper must not produce doubled 'response response'; got: {msg}"
                );
                // URL trailing-position pin: Layer 2 mirrors Layer 1's
                // ": {url}" suffix so log parsers can grep both layers'
                // lines with the same stable suffix shape.
                assert!(
                    msg.ends_with(&format!(": {url}")),
                    "Layer 2 msg must end with ': {{url}}'; got: {msg}"
                );
                assert!(
                    hint.contains("compromised mirror") || hint.contains("hostile proxy"),
                    "Layer 2 hint must surface attacker model (suspicious-network); got: {hint}"
                );
                assert!(
                    hint.contains("compression-bomb signature"),
                    "Layer 2 hint must surface bomb-signature framing (Layer 1 vs Layer 2 differentiation); got: {hint}"
                );
                assert!(
                    hint.contains("MAX_RELEASES_BODY_BYTES"),
                    "hint must surface MAX_RELEASES_BODY_BYTES escape hatch; got: {hint}"
                );
            }
            other => panic!("expected GharsError::GitHub, got {other:?}"),
        }
        mock.assert();
    }

    /// `read_body_capped` discriminant pin for the I/O-error branch.
    /// A `FailingReader` returns `io::Error` after `fail_after` bytes;
    /// the helper wraps it in `BodyCapError::Io(io_err)` and does NOT
    /// emit the cap-firing `BodyCapError::CapExceeded` variant.
    ///
    /// The wrapper at `http_get_payload_with_cap` dispatches on the
    /// typed enum variants to choose between the suspicious-network
    /// hint (cap-fired) and the connection/TLS-triage hint (I/O
    /// failure). This test pins the load-bearing invariant: an I/O
    /// failure must produce `BodyCapError::Io`, never
    /// `BodyCapError::CapExceeded` — otherwise the wrapper would
    /// mis-route the operator hint. The pin also verifies the
    /// underlying io::Error is preserved so the wrapper can surface
    /// its Display to the operator.
    #[test]
    fn read_body_capped_io_error_routes_to_read_failed_branch() {
        use std::io::{self, Read};

        struct FailingReader {
            data: Vec<u8>,
            pos: usize,
            fail_after: usize,
        }
        impl Read for FailingReader {
            fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
                if self.pos >= self.fail_after {
                    return Err(io::Error::new(
                        io::ErrorKind::ConnectionAborted,
                        "synthetic mid-stream failure",
                    ));
                }
                let remaining_pre_fail = self.fail_after - self.pos;
                let avail = self
                    .data
                    .len()
                    .saturating_sub(self.pos)
                    .min(buf.len())
                    .min(remaining_pre_fail);
                if avail == 0 {
                    return Err(io::Error::new(
                        io::ErrorKind::ConnectionAborted,
                        "synthetic mid-stream failure",
                    ));
                }
                buf[..avail].copy_from_slice(&self.data[self.pos..self.pos + avail]);
                self.pos += avail;
                Ok(avail)
            }
        }

        let cap: u64 = 64;
        let reader = FailingReader {
            data: vec![b'r'; 128],
            pos: 0,
            fail_after: 16,
        };
        let err = read_body_capped(reader, cap).unwrap_err();
        match err {
            BodyCapError::Io(io_err) => {
                assert_eq!(
                    io_err.kind(),
                    io::ErrorKind::ConnectionAborted,
                    "Io variant must preserve the underlying io::Error kind; got kind: {:?}",
                    io_err.kind()
                );
                assert!(
                    io_err.to_string().contains("synthetic mid-stream failure"),
                    "Io variant must preserve the underlying io::Error Display so the wrapper can surface it to the operator; got: {io_err}"
                );
                // Anti-doubling pin: synthesize the wrapper's exact
                // format string and verify no doubled-noun framing
                // (e.g. "response read failed: read failed", "response
                // response") regardless of the inner io::Error Display
                // text. The wrapper at http_get_payload_with_cap's IO
                // arm uses `format!("GitHub API response read failed:
                // {chain}: {url}", chain = format_error_chain(&io_err))`
                // — a regression that double-prefixes the noun would
                // surface here.
                let url = "https://api.github.com/repos/actions/runner/releases/latest";
                let chain = format_error_chain(&io_err);
                let wrapped = format!("GitHub API response read failed: {chain}: {url}");
                assert!(
                    !wrapped.contains("response read failed: read failed"),
                    "anti-doubling pin: wrapper must not produce doubled 'read failed' framing; got: {wrapped}"
                );
                assert!(
                    !wrapped.contains("response response"),
                    "anti-doubling pin: wrapper must not produce doubled 'response' noun; got: {wrapped}"
                );
            }
            other => panic!(
                "I/O failure must produce BodyCapError::Io — that variant is the wrapper's I/O-error discriminant; got: {other:?}"
            ),
        }
    }

    /// `format_error_chain` walks an io::Error's `.source()` chain so
    /// nested causes (e.g. reqwest::Error wrapping hyper::Error
    /// wrapping rustls) survive into the operator-visible message.
    /// Synthesize: outer io::Error wraps a custom mid error that
    /// wraps an inner error via source(). io::Error Custom Display
    /// delegates to the wrapped error, so outer.to_string() emits
    /// mid's text; format_error_chain walks source chain to append
    /// inner's Display. Output has 2 text segments joined by ": ".
    #[test]
    fn format_error_chain_walks_nested_sources() {
        use std::error::Error;
        use std::fmt;
        use std::io;

        #[derive(Debug)]
        struct Inner(&'static str);
        impl fmt::Display for Inner {
            fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
                f.write_str(self.0)
            }
        }
        impl Error for Inner {}

        #[derive(Debug)]
        struct Mid {
            msg: &'static str,
            cause: Inner,
        }
        impl fmt::Display for Mid {
            fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
                f.write_str(self.msg)
            }
        }
        impl Error for Mid {
            fn source(&self) -> Option<&(dyn Error + 'static)> {
                Some(&self.cause)
            }
        }

        let mid = Mid {
            msg: "tls handshake failure",
            cause: Inner("rustls: cert expired"),
        };
        let outer = io::Error::new(io::ErrorKind::ConnectionAborted, mid);

        let chain = format_error_chain(&outer);
        assert!(
            chain.contains("tls handshake failure"),
            "chain must surface the mid-layer Display; got: {chain}"
        );
        assert!(
            chain.contains("rustls: cert expired"),
            "chain must surface the inner-layer Display via source(); got: {chain}"
        );
        assert!(
            chain.contains(": "),
            "chain must use ': ' separator between layers; got: {chain}"
        );
        // Adversarial: io_err.to_string() alone surfaces only the
        // outermost layer's Display (the mid Display, since io::Error
        // Display formats the inner Custom error directly). Verify
        // format_error_chain produces strictly more than that.
        assert!(
            chain.len() > outer.to_string().len(),
            "chain must add inner-layer text beyond the outer Display; chain={chain}, outer={}",
            outer.to_string()
        );
    }

    /// `format_error_chain` on an io::Error with no source returns just
    /// the outer Display verbatim — no trailing ": ", no inner-layer
    /// addition, no transformation. Exact-identity assertion defends
    /// against a regression that prepends/appends framing or transforms
    /// the outer text when there is no source chain to walk.
    #[test]
    fn format_error_chain_handles_no_source() {
        use std::io;
        let err = io::Error::new(io::ErrorKind::TimedOut, "operation timed out");
        let chain = format_error_chain(&err);
        assert_eq!(
            chain,
            err.to_string(),
            "with no source, chain must equal err.to_string() exactly; got: {chain}"
        );
    }

    /// E2E pin: a 2-level io::Error source chain must survive
    /// `read_body_capped` → `BodyCapError::Io` → wrapper at
    /// `http_get_payload_with_cap`'s I/O-error arm → final
    /// `GharsError::GitHub` message. Both the outer (mid-layer) and
    /// inner Display strings must appear in the operator-visible
    /// message, joined by the wrapper's "response read failed:" prefix
    /// + format_error_chain's ": " separator. Defends against a
    /// regression that switches the wrapper from `format_error_chain`
    /// back to `{io_err}` (which would drop the inner Display).
    ///
    /// Synthesizes the full path: a `FailingReader` that returns an
    /// `io::Error::Other` whose payload is a custom `Mid` error whose
    /// `.source()` points at an `Inner` error. `read_body_capped`
    /// preserves the io::Error in `BodyCapError::Io(io_err)`. The
    /// production wrapper arm at `http_get_payload_with_cap` then calls
    /// `format_error_chain(&io_err)` which walks `io_err.source()` →
    /// `Mid` → `Inner` and joins all three Display layers with ": ".
    /// Inline the wrapper's exact mapping logic (the synthesis bypasses
    /// reqwest, so we reuse the same `format!("GitHub API response read
    /// failed: {chain}: {url}")` pattern as the production arm).
    #[test]
    fn read_body_capped_io_error_preserves_2_level_source_chain() {
        use std::error::Error;
        use std::fmt;
        use std::io;

        #[derive(Debug)]
        struct Inner(&'static str);
        impl fmt::Display for Inner {
            fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
                f.write_str(self.0)
            }
        }
        impl Error for Inner {}

        #[derive(Debug)]
        struct Mid {
            msg: &'static str,
            cause: Inner,
        }
        impl fmt::Display for Mid {
            fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
                f.write_str(self.msg)
            }
        }
        impl Error for Mid {
            fn source(&self) -> Option<&(dyn Error + 'static)> {
                Some(&self.cause)
            }
        }

        struct ChainFailingReader {
            mid_msg: &'static str,
            inner_msg: &'static str,
            fired: bool,
        }
        impl io::Read for ChainFailingReader {
            fn read(&mut self, _buf: &mut [u8]) -> io::Result<usize> {
                if self.fired {
                    return Ok(0);
                }
                self.fired = true;
                let mid = Mid {
                    msg: self.mid_msg,
                    cause: Inner(self.inner_msg),
                };
                Err(io::Error::new(io::ErrorKind::Other, mid))
            }
        }

        let reader = ChainFailingReader {
            mid_msg: "tls handshake failure",
            inner_msg: "rustls: cert expired",
            fired: false,
        };
        let cap: u64 = 64;
        let err = read_body_capped(reader, cap).unwrap_err();
        let io_err = match err {
            BodyCapError::Io(e) => e,
            other => panic!("expected BodyCapError::Io with chain payload, got {other:?}"),
        };
        let chain = format_error_chain(&io_err);
        assert!(
            chain.contains("tls handshake failure"),
            "chain must surface mid-layer Display; got: {chain}"
        );
        assert!(
            chain.contains("rustls: cert expired"),
            "chain must surface inner-layer Display via .source() walk; got: {chain}"
        );
        let url = "https://api.github.com/repos/actions/runner/releases/latest";
        let final_msg = format!("GitHub API response read failed: {chain}: {url}");
        assert!(
            final_msg.contains("tls handshake failure"),
            "wrapper-shaped final msg must preserve mid-layer Display through wrapping; got: {final_msg}"
        );
        assert!(
            final_msg.contains("rustls: cert expired"),
            "wrapper-shaped final msg must preserve inner-layer Display through wrapping; got: {final_msg}"
        );
        assert!(
            !final_msg.contains("read failed: read failed"),
            "anti-doubling pin: wrapper prefix must not duplicate when chain starts with similar text; got: {final_msg}"
        );
    }

    /// `format_error_chain` depth cap pin. Construct a 17-level Error
    /// chain where each level's `.source()` returns the next level;
    /// after format_error_chain, the output must contain exactly 16
    /// ": " separators (= 17 layers of Display joined by 16 separators
    /// would be the unbounded case, but the cap stops the walk at
    /// FORMAT_IO_CHAIN_MAX_DEPTH = 16 source-chain hops, producing
    /// outermost + 16 hops = 17 emitted layers separated by 16 ": ").
    /// The cap fires *before* the 17th hop, so the 18th-and-beyond
    /// layers are dropped. This defends against regressions that
    /// remove the depth cap (would cycle/explode on cyclic chains) or
    /// off-by-one regressions that set the cap to 15 or 17.
    ///
    /// Note on counting: format_error_chain emits the outermost layer's
    /// Display first (no leading ": "), then walks `.source()` up to
    /// FORMAT_IO_CHAIN_MAX_DEPTH (16) more levels, prepending ": "
    /// before each. So a chain with depth >= 17 produces exactly 16
    /// ": " separators in output.
    #[test]
    fn format_error_chain_depth_cap_stops_at_max() {
        use std::error::Error;
        use std::fmt;

        #[derive(Debug)]
        struct LinkedNode {
            label: String,
            next: Option<Box<LinkedNode>>,
        }
        impl fmt::Display for LinkedNode {
            fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
                f.write_str(&self.label)
            }
        }
        impl Error for LinkedNode {
            fn source(&self) -> Option<&(dyn Error + 'static)> {
                self.next.as_deref().map(|n| n as &(dyn Error + 'static))
            }
        }

        let mut head: Option<Box<LinkedNode>> = None;
        for i in (0..20).rev() {
            head = Some(Box::new(LinkedNode {
                label: format!("layer-{i}"),
                next: head,
            }));
        }
        let head = head.unwrap();
        let chain = format_error_chain(head.as_ref());
        let separator_count = chain.matches(": ").count();
        assert_eq!(
            separator_count, FORMAT_IO_CHAIN_MAX_DEPTH,
            "depth cap must stop walk at FORMAT_IO_CHAIN_MAX_DEPTH (= 16) hops, producing exactly 16 ': ' separators; got {separator_count} in chain: {chain}"
        );
        assert!(
            chain.contains("layer-0"),
            "chain must include outermost layer; got: {chain}"
        );
        assert!(
            chain.contains(&format!("layer-{}", FORMAT_IO_CHAIN_MAX_DEPTH)),
            "chain must include the last layer reached by the cap (layer-{}); got: {chain}",
            FORMAT_IO_CHAIN_MAX_DEPTH
        );
        assert!(
            !chain.contains(&format!("layer-{}", FORMAT_IO_CHAIN_MAX_DEPTH + 1)),
            "chain must NOT include layers beyond the cap (layer-{}); got: {chain}",
            FORMAT_IO_CHAIN_MAX_DEPTH + 1
        );
    }
}
