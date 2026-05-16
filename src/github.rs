//! GitHub API surface: releases-API client (reqwest blocking),
//! URL→`Scope` parsing for runner registration, and the shared tokio
//! runtime + `reqwest::Client` builder used by `auth.rs` for octocrab.
//!
//! Design spec: Part 6 (auth subsystem, octocrab integration) +
//! `github.rs` row of Part 2 (module layout) + Part 9f (multi-arch
//! tarball URL template).
//!
//! ## Tokio runtime (Part 6 enforcement rule)
//!
//! `fn main()` is sync. Only octocrab calls touch tokio, and only via
//! `block_on(...)`. zbus blocking-api MUST NEVER be invoked inside an
//! async block passed to `block_on` (zbus uses its own executor; tokio
//! parking it would deadlock). Verified safe to coexist when call sites
//! are distinct.
//!
//! ## Releases API
//!
//! Direct port of the legacy Python install tool's release lookup:
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
use crate::error::{GharsError, format_error_chain, human_bytes};

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
/// the legacy Python install tool's HTTP timeout.
const HTTP_API_TIMEOUT: Duration = Duration::from_secs(10);

/// Hard cap on bytes read from a GitHub releases-API response.
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
///     when gzip auto-decode is in effect (the doc-comment on the
///     blocking response explicitly calls this out). The
///     pre-decompression byte size is only available via
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
/// bound on apply-time memory pressure for the releases path (realistic
/// legitimate ceiling is ~256 KB).
const MAX_RELEASES_BODY_BYTES: u64 = 4 * 1024 * 1024;

/// Initial allocation hint for `read_body_capped`. The helper sizes
/// the buffer to `min(cap, INITIAL_BODY_CAPACITY)` so the realistic
/// releases-API payload (~256 KiB per the `MAX_RELEASES_BODY_BYTES`
/// doc above) starts from a non-zero base instead of the default
/// `Vec::new()`, amortizing the geometric-growth cost of
/// `read_to_end`. A small-cap test (e.g. 64 bytes) caps the
/// allocation at the cap so it never over-allocates.
const INITIAL_BODY_CAPACITY: u64 = 64 * 1024;

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

/// Check if a runner with `name` is registered at the given `url`.
/// Returns `true` if found, `false` if not. Errors on API failures.
pub fn runner_is_registered(
    client: &reqwest::blocking::Client,
    url: &str,
    name: &str,
    pat: Option<&str>,
) -> Result<bool> {
    let scope = parse_url(url)?;
    let api_url = match &scope {
        Scope::Repo { owner, repo } => {
            format!("https://api.github.com/repos/{owner}/{repo}/actions/runners")
        }
        Scope::Org { owner } => {
            format!("https://api.github.com/orgs/{owner}/actions/runners")
        }
    };
    // Use a direct HTTP request instead of http_get_payload (which
    // deserializes into ReleaseApiPayload). The runners endpoint
    // returns a different JSON shape.
    let mut req = client
        .get(&api_url)
        .header("Accept", "application/vnd.github+json");
    if let Some(token) = pat {
        req = req.header("Authorization", format!("Bearer {token}"));
    }
    let resp = req.send().map_err(|e| {
        GharsError::GitHub(
            format!(
                "GitHub runners API request failed: {}: {api_url}",
                format_error_chain(&e)
            ),
            "check network connectivity".into(),
        )
    })?;
    if !resp.status().is_success() {
        return Err(GharsError::GitHub(
            format!("GitHub runners API returned {}: {api_url}", resp.status()),
            "check PAT scopes (needs admin:org or repo admin)".into(),
        ));
    }
    let body = resp.text().map_err(|e| {
        GharsError::GitHub(format!("cannot read runners response: {e}"), String::new())
    })?;
    let json: serde_json::Value = serde_json::from_str(&body).map_err(|e| {
        GharsError::GitHub(
            format!("cannot parse runners list JSON: {e}"),
            "unexpected response shape from GitHub runners API".into(),
        )
    })?;
    let empty = Vec::new();
    let runners = json
        .get("runners")
        .and_then(|r| r.as_array())
        .unwrap_or(&empty);
    Ok(runners
        .iter()
        .any(|r| r.get("name").and_then(|n| n.as_str()) == Some(name)))
}

/// Query the GitHub runners API and return a map of runner name to
/// status string (`"online"` or `"offline"`). Paginates automatically.
pub fn list_runner_statuses(
    client: &reqwest::blocking::Client,
    url: &str,
    pat: Option<&str>,
) -> Result<std::collections::HashMap<String, String>> {
    let scope = parse_url(url)?;
    let base_url = match &scope {
        Scope::Repo { owner, repo } => {
            format!("https://api.github.com/repos/{owner}/{repo}/actions/runners")
        }
        Scope::Org { owner } => {
            format!("https://api.github.com/orgs/{owner}/actions/runners")
        }
    };
    let mut statuses = std::collections::HashMap::new();
    let mut page = 1u32;
    let max_pages = 50u32;
    loop {
        let api_url = format!("{base_url}?per_page=100&page={page}");
        let mut req = client
            .get(&api_url)
            .header("Accept", "application/vnd.github+json");
        if let Some(token) = pat {
            req = req.header("Authorization", format!("Bearer {token}"));
        }
        let resp = req.send().map_err(|e| {
            GharsError::GitHub(
                format!(
                    "GitHub runners API request failed: {}: {api_url}",
                    format_error_chain(&e)
                ),
                "check network connectivity".into(),
            )
        })?;
        if !resp.status().is_success() {
            return Err(GharsError::GitHub(
                format!("GitHub runners API returned {}: {api_url}", resp.status()),
                "check PAT scopes (needs admin:org or repo admin)".into(),
            ));
        }
        let body = resp.text().map_err(|e| {
            GharsError::GitHub(format!("cannot read runners response: {e}"), String::new())
        })?;
        let json: serde_json::Value = serde_json::from_str(&body).map_err(|e| {
            GharsError::GitHub(
                format!("cannot parse runners list JSON: {e}"),
                "unexpected response shape from GitHub runners API".into(),
            )
        })?;
        let empty = Vec::new();
        let runners = json
            .get("runners")
            .and_then(|r| r.as_array())
            .unwrap_or(&empty);
        if runners.is_empty() {
            break;
        }
        for r in runners {
            if let (Some(name), Some(status)) = (
                r.get("name").and_then(|n| n.as_str()),
                r.get("status").and_then(|s| s.as_str()),
            ) {
                statuses.insert(name.to_owned(), status.to_owned());
            }
        }
        let total = json
            .get("total_count")
            .and_then(serde_json::Value::as_u64)
            .unwrap_or(0);
        if statuses.len() as u64 >= total || page >= max_pages {
            break;
        }
        page += 1;
    }
    Ok(statuses)
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
/// silently accept it.
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
                "runner url {s:?} has host {:?}; only github.com is supported",
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
        // at startup.
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
            // SEC-08: from_pem_bundle parses every PEM-fenced
            // CERTIFICATE block in the file and returns the resulting
            // Vec<Certificate>. The alternative `from_pem` accepts
            // files with zero PEM blocks under the rustls backend —
            // it stores the raw bytes verbatim and downstream builds
            // an empty roots set, silently degrading to system trust
            // only. The from_pem_bundle + is_empty pair below fails
            // closed: an operator-provided CA path that yields zero
            // certificates is a misconfiguration, not a "fall back
            // to defaults" signal.
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

/// Strip a single leading `v` from a tag name, matching the legacy
/// Python install tool's `strip_v` helper.
fn strip_v(tag: &str) -> &str {
    tag.strip_prefix('v').unwrap_or(tag)
}

/// Lower-case 64-hex check, matching the legacy Python install tool's
/// digest-shape check.
fn is_hex64(s: &str) -> bool {
    s.len() == 64 && s.chars().all(|c| c.is_ascii_hexdigit())
}

/// Extract the SHA256 digest for `filename` from a release-API payload.
///
/// Prefers the per-asset `digest` field (`sha256:HEX`); falls back to a
/// `<hex>  <filename>` line in the release body (sha256sum -c format).
/// Direct port of the legacy Python install tool's digest extractor.
///
/// # Errors
///
/// Returns `GharsError::GitHub` when neither location yields a 64-hex
/// digest matching `filename`.
fn extract_sha256(payload: &ReleaseApiPayload, filename: &str) -> Result<String> {
    for asset in &payload.assets {
        if asset.name == filename
            && let Some(digest) = &asset.digest
        {
            let lower = digest.to_lowercase();
            if let Some(hex) = lower.strip_prefix("sha256:") {
                let hex = hex.trim();
                if is_hex64(hex) {
                    return Ok(hex.to_string());
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
///
/// Naming: `_capped` (past participle on the result), not `_with_cap`
/// (suffix used by the `http_download_with_cap` / `http_get_payload_with_cap`
/// pair). Those siblings are CAP-INJECTION SEAMS — each is paired
/// with a no-suffix production wrapper (`http_download` /
/// `http_get_payload`) that hardcodes `MAX_*_BYTES`, and the
/// `_with_cap` variant is the test-only entry point that takes the
/// cap as a parameter. `read_body_capped` has no such pair: every
/// caller (production at `http_get_payload_with_cap` and every
/// `read_body_capped_*` direct unit test below) passes `cap`
/// explicitly. Renaming to `read_body_with_cap` would suggest a
/// `read_body` no-cap sibling that doesn't exist. The current name
/// describes the OUTPUT invariant (the returned body is bounded by
/// `cap`), which matches the function's actual contract.
///
/// ## `cap == u64::MAX` silently disables the cap
///
/// `cap.saturating_add(1)` at `u64::MAX` returns `u64::MAX`, so
/// `Read::take(u64::MAX)` never short-circuits the read; the
/// post-read check `buf.len() as u64 > cap` then requires
/// `buf.len() > u64::MAX`, which is unreachable on any 64-bit
/// `usize`. The sole production caller fixes
/// `cap = MAX_RELEASES_BODY_BYTES` (4 MiB), so this edge case has
/// no production exposure today. The debug-build `debug_assert!`
/// below traps it during development to surface any future caller
/// that passes `u64::MAX` (or a value computed to it) before it
/// ships.
fn read_body_capped<R: Read>(reader: R, cap: u64) -> std::result::Result<Vec<u8>, BodyCapError> {
    debug_assert!(
        cap < u64::MAX,
        "read_body_capped: cap == u64::MAX silently disables the cap (saturating_add(1) returns u64::MAX, take never fires); pass a finite cap"
    );
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

/// Like [`http_get_payload`] but injects a Bearer token into the
/// request when `pat` is `Some`. Falls back to unauthenticated when
/// `None`.
fn http_get_payload_authenticated(
    client: &reqwest::blocking::Client,
    url: &str,
    pat: Option<&str>,
) -> Result<ReleaseApiPayload> {
    // Build a one-off client with the Bearer token baked in so the
    // existing http_get_payload_with_cap flow handles status codes,
    // body capping, and error formatting uniformly.
    if let Some(token) = pat {
        let authed_client = reqwest::blocking::Client::builder()
            .user_agent(crate::USER_AGENT)
            .timeout(HTTP_API_TIMEOUT)
            .default_headers({
                let mut h = reqwest::header::HeaderMap::new();
                h.insert(
                    reqwest::header::AUTHORIZATION,
                    reqwest::header::HeaderValue::from_str(&format!("Bearer {token}"))
                        .unwrap_or_else(|_| reqwest::header::HeaderValue::from_static("")),
                );
                h
            })
            .build()
            .map_err(|e| {
                GharsError::GitHub(
                    format!("cannot build authenticated HTTP client: {e}"),
                    "check PAT value".into(),
                )
            })?;
        http_get_payload_with_cap(&authed_client, url, MAX_RELEASES_BODY_BYTES)
    } else {
        http_get_payload_with_cap(client, url, MAX_RELEASES_BODY_BYTES)
    }
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
            401 | 403 => format!(
                "GitHub returned {code} — typically (a) the auth principal lacks the \
                 required permissions / scopes for this endpoint or the credential \
                 has been revoked (PAT scopes / token validity, App installation \
                 grants, or fine-grained PAT permissions, depending on the source); \
                 or (b) the releases endpoint is normally public, so a proxy or GHE \
                 mirror in the path is intercepting and demanding token/PAT \
                 credentials from an intermediate"
            ),
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

    // Layer 1: raw Content-Length header pre-check via the shared
    // `http_cap::content_length_exceeds` helper. Malformed
    // Content-Length silently falls through to Layer 2 streaming
    // backstop inside `read_body_capped`.
    if let Some(cl) = crate::http_cap::content_length_exceeds(resp.headers(), max_bytes) {
        return Err(GharsError::GitHub(
            format!(
                "GitHub API response Content-Length {cl_h} ({cl} bytes) exceeds {max_h} ({max_bytes} bytes): {url}",
                cl_h = human_bytes(cl),
                max_h = human_bytes(max_bytes)
            ),
            "the on-wire (pre-decompression) Content-Length is suspiciously \
                         large; verify network path (compromised mirror, hostile proxy CA, \
                         or non-GitHub origin); if the upstream payload is legitimately \
                         this large, file a ghars issue to raise MAX_RELEASES_BODY_BYTES"
                .into(),
        ));
    }

    // Layer 2: streaming bounded read on the post-decompression byte
    // stream via the `read_body_capped` helper. The helper returns a
    // typed `BodyCapError` so the wrapper routes I/O-failure vs
    // cap-firing through structural variants rather than substring
    // matching on an error string. Cap-firing branch differentiates
    // Layer 1 (on-wire/pre-decompression) from Layer 2
    // (post-decompression).
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
                "GitHub API response body exceeds {cap_h} ({cap} bytes) post-decompression: {url}",
                cap_h = human_bytes(cap)
            ),
            "the post-decompression body is larger than expected; this can indicate \
             a deliberately-crafted payload OR a legitimately large upstream response; \
             check status.github.com, then file a ghars issue to raise \
             MAX_RELEASES_BODY_BYTES if the payload is genuine"
                .into(),
        ),
    })?;
    // Empty-body pre-check: routes the surprising-but-success class
    // (HTTP 204/205, or a misbehaving proxy that returns 200 with a
    // zero-byte body) to a self-explanatory error before
    // `serde_json::from_slice` would emit the unhelpful "EOF while
    // parsing a value at line 1 column 0". The releases-API contract
    // requires a non-empty JSON object on success; an empty body is
    // never a legitimate payload here.
    if buf.is_empty() {
        return Err(GharsError::GitHub(
            format!("GitHub API response had empty body on a {status} response: {url}"),
            "the releases API returns a JSON object on success; a 204 No Content / 205 Reset Content / zero-byte 200 response indicates either an HTTP-method-rewriting proxy, a captive portal stripping the body, or an upstream contract change; verify the URL with curl -v and check status.github.com for incidents".into(),
        ));
    }
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

/// Like [`fetch_latest_release`] but adds Bearer auth when a PAT is
/// available. Raises the rate limit from 60 to 5000 req/hr.
pub fn fetch_latest_release_authenticated(
    client: &reqwest::blocking::Client,
    arch: Arch,
    pat: Option<&str>,
) -> Result<Release> {
    let payload = http_get_payload_authenticated(client, API_LATEST, pat)?;
    release_from_api(&payload, arch)
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

/// Like [`fetch_release`] but adds Bearer auth when a PAT is available.
pub fn fetch_release_authenticated(
    client: &reqwest::blocking::Client,
    version: &str,
    arch: Arch,
    pat: Option<&str>,
) -> Result<Release> {
    crate::validators::validate_version(version)?;
    let url = API_TAG_TEMPLATE.replace("{version}", version);
    let payload = http_get_payload_authenticated(client, &url, pat)?;
    release_from_api(&payload, arch)
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
#[path = "github_tests_a.rs"]
mod tests_a;

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used)]
#[path = "github_tests_b.rs"]
mod tests_b;
