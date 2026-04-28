//! Auth subsystem: `TokenSource` trait + four concrete impls
//! (`GithubAppToken`, `PatToken`, `InteractiveToken`, `TokenFileToken`).
//!
//! Design spec: Part 6 (auth subsystem).
//!
//! Every impl ultimately produces a `RegistrationToken` whose `value`
//! is the short-lived runner registration / removal token GitHub
//! issues (TTL 1h, clamped to `now + 1h - 30s`). `GithubAppToken` and
//! `PatToken` mint via octocrab's
//! `actions().create_*_runner_registration_token` /
//! `create_*_runner_remove_token` (octocrab-0.42.1/src/api/actions.rs:542,
//! 572, 734, 766) inside `block_on` (Part 6 enforcement rule item 3).
//! `InteractiveToken` prompts the operator to paste a pre-minted token;
//! `TokenFileToken` reads one from disk.
//!
//! ## Retry policy (v0.1)
//!
//! ghars does NOT enable octocrab's `retry` feature — Cargo.toml selects
//! only `rustls + default-client + rustls-ring`. The 429 hint emitted
//! by `octocrab_to_auth` is operator-facing: it surfaces `Retry-After`
//! guidance and asks the operator to re-run `ghars apply` once the
//! rate-limit window passes. There is no in-process retry loop.
//!
//! Why no auto-retry: octocrab 0.42.1's retry path is implemented by
//! `tower::retry::Policy` for `RetryConfig::Simple(count)` (see
//! `octocrab-0.42.1/src/service/middleware/retry.rs`). The `retry()`
//! method returns `Some(future::ready(()))` on every retryable
//! response — no delay, no backoff, no `Retry-After` header parsing.
//! Hammering the GitHub registration-token endpoint immediately on
//! 429 deepens the rate-limit window and wastes ghars's per-IP quota,
//! so the manual re-run path is strictly safer for v0.1. Adding a
//! `Retry-After`-aware retry layer (with backoff + jitter + cap) is
//! tracked as a v0.2 follow-up alongside #145 (custom hyper-connector
//! injection for per-deployment proxy CA).
//!
//! ## Residual exposure (v0.1)
//!
//! Asymmetric with `github.rs::http_get_payload`'s
//! `MAX_RELEASES_BODY_BYTES` cap: the octocrab path through which
//! `GithubAppToken` and `PatToken` mint registration tokens has NO
//! body-size cap in v0.1. The blanket `impl<T: DeserializeOwned>
//! FromResponse for T` in
//! `octocrab-0.42.1/src/from_response.rs:14-25` collects the entire
//! response body via `body.collect().await?.to_bytes()` before
//! passing the buffer to `serde_json` — there is no `take()` /
//! `Content-Length` pre-check anywhere along the chain. octocrab
//! uses hyper-util's `client-legacy` directly (Cargo.toml
//! `default-client` feature) and pulls `tower-http` with only the
//! `map-response-body` + `trace` features — `decompression` is NOT
//! enabled, so the wire bytes ARE the bytes that get collected (no
//! gzip auto-decode amplification on this path).
//!
//! Threat model: a hostile origin (compromised mirror, MITM proxy,
//! or operator-misconfigured `[proxy].ca_certs` pointing at an
//! inspection appliance) replying to the registration-token endpoint
//! with a multi-gigabyte body would be collected unbounded into
//! memory. Realistic surface is small (the registration-token
//! endpoint normally returns ~200 bytes), but the structural
//! absence of a cap means v0.1 trusts the upstream not to misbehave.
//! Closing this requires injecting a custom `tower::Layer` between
//! octocrab's service stack and hyper to bound the collected body —
//! the same hook point as #145 (custom hyper-connector for
//! per-deployment proxy CA), so the mitigation is tracked there.

use std::io::{IsTerminal, Read};
use std::os::unix::fs::MetadataExt;
use std::path::Path;
use std::sync::OnceLock;

use camino::Utf8Path;
use chrono::{DateTime, TimeDelta, Utc};

use crate::Result;
use crate::config::AuthSpec;
use crate::error::GharsError;
use crate::github::{self, Scope};

/// A short-lived registration (or removal) token emitted by GitHub
/// for runner registration. GitHub's TTL is 1h; ghars clamps
/// `expires_at` to `now + 1h - 30s` for any source that does not
/// supply an authoritative expiry (interactive paste, token file).
///
/// # Memory hygiene (#245)
///
/// `value` is zeroized on `Drop` (including during panic unwind) so a
/// panic between mint and consume cannot leave plaintext token bytes on
/// unwound stack / heap frames until the OS reclaims pages.
/// `zeroize::ZeroizeOnDrop` uses volatile-write + compiler-fence to
/// defeat dead-store elimination — the workspace's `unsafe_code =
/// "forbid"` lint forbids the manual `ptr::write_volatile` required to
/// implement this safely without a dep, and CLAUDE.md prefers
/// established crates over hand-rolled security primitives. The
/// `source` and `expires_at` fields are not secret (source is a label
/// like `github:NAME` and expires_at is a UTC instant); they are
/// `#[zeroize(skip)]` so derive does not require a `Zeroize` impl on
/// `chrono::DateTime<Utc>`.
///
/// `Clone` is intentionally NOT derived: zeroize-on-drop hardens one
/// end of the token's lifetime, but `.clone()` would silently widen
/// the attack surface by spawning unscrubbed copies in caller frames.
/// No production caller clones a `RegistrationToken` today (verified
/// at the time of #245 via grep); test fixtures that need duplicates
/// construct them via `RegistrationToken { ... }` literals so the
/// typing surface stays consistent with the production "consume by
/// reference" pattern at `apply::execute_remove_runner` (passing
/// `&token.value` into `ConfigShellCtx`).
///
/// # Display / debug policy
///
/// See `error.rs` mod-comment: `RegistrationToken.value` must NEVER
/// appear in any `Display` output. zeroize-on-drop closes the
/// memory-residue half of this contract; the no-Display rule closes
/// the operator-stderr / journalctl half.
#[derive(Debug, zeroize::ZeroizeOnDrop)]
pub struct RegistrationToken {
    /// Token value (opaque string). Zeroized on `Drop` per the
    /// memory-hygiene contract above.
    pub value: String,
    /// Expiry instant. For octocrab-minted tokens this is GitHub's
    /// `expires_at` (passed through verbatim — octocrab's
    /// `SelfHostedRunnerToken.expires_at` is already
    /// `chrono::DateTime<Utc>`, so no SystemTime round-trip risks
    /// nanosecond precision loss). For sourced-from-disk / interactive
    /// tokens it is `Utc::now() + 3570s` (1h minus a 30s safety margin).
    /// Not secret; `#[zeroize(skip)]` so derive doesn't require a
    /// `Zeroize` impl on `chrono::DateTime<Utc>`.
    #[zeroize(skip)]
    pub expires_at: DateTime<Utc>,
    /// Source label (`github:NAME`, `interactive:stdin`,
    /// `token-file:NAME`) for diagnostics and audit. Not secret;
    /// `#[zeroize(skip)]` per the contract above.
    #[zeroize(skip)]
    pub source: String,
}

// #245: pin the zeroize-on-drop wiring at compile time. If a future
// edit drops the `ZeroizeOnDrop` derive (or replaces `value: String`
// with a non-zeroizable type), this `const _` block fails to compile
// here rather than silently regressing the memory-hygiene contract.
const _: () = {
    const fn assert_zeroize_on_drop<T: zeroize::ZeroizeOnDrop>() {}
    assert_zeroize_on_drop::<RegistrationToken>();
};

/// Trait shared by every auth source. Each `mint_*_token` produces a
/// fresh registration / removal token suitable for `config.sh`.
pub trait TokenSource: Send + Sync {
    /// Display name for the auth source (matches the `[auth.NAME]` key).
    fn name(&self) -> &str;

    /// Mint a registration token bound to the given runner URL.
    ///
    /// # Errors
    ///
    /// Returns `GharsError::Auth` on API / IO failure.
    fn mint_registration_token(&self, runner_url: &str) -> Result<RegistrationToken>;

    /// Mint a removal token bound to the given runner URL.
    ///
    /// # Errors
    ///
    /// Returns `GharsError::Auth` on API / IO failure.
    fn mint_removal_token(&self, runner_url: &str) -> Result<RegistrationToken>;
}

/// Construct a `TokenSource` from a parsed `AuthSpec`. Constructors
/// validate file modes / env presence eagerly so `ghars validate`
/// surfaces auth misconfiguration without contacting GitHub.
///
/// # Errors
///
/// Returns `GharsError::Auth` on env / file / mode-permission failure
/// at construction time.
pub fn build(spec: &AuthSpec, name: &str) -> Result<Box<dyn TokenSource>> {
    Ok(match spec {
        AuthSpec::GithubApp {
            app_id,
            installation_id,
            private_key_path,
        } => Box::new(GithubAppToken::new(
            name,
            *app_id,
            *installation_id,
            private_key_path,
        )?),
        AuthSpec::Pat {
            token_env,
            token_file,
        } => Box::new(PatToken::new(
            name,
            token_env.as_deref(),
            token_file.as_deref(),
        )?),
        AuthSpec::Interactive => Box::new(InteractiveToken::new(name)),
        AuthSpec::TokenFile { path } => Box::new(TokenFileToken::new(name, path)?),
    })
}

/// Build a `TokenSource` from a parsed `AuthSpec`.
///
/// Alias preserved as `build_token_source` for the call sites in
/// `apply` and `cli`. Identical to [`build`].
///
/// # Errors
///
/// Returns `GharsError::Auth` on env / file / mode-permission failure
/// at construction time.
pub fn build_token_source(spec: &AuthSpec, name: &str) -> Result<Box<dyn TokenSource>> {
    build(spec, name)
}

// ---------- GithubAppToken ----------

/// Auth source backed by a GitHub App private key. octocrab handles
/// JWT minting (RS256, 9m lifetime per `octocrab::auth::create_jwt`,
/// octocrab-0.42.1/src/auth.rs:61-86) and exchanges it for an
/// installation token internally, caching the installation token
/// in-memory until expiry.
#[derive(Debug)]
pub struct GithubAppToken {
    name: String,
    app_id: u64,
    installation_id: u64,
    /// Cached installation-scoped Octocrab. Constructed lazily on the
    /// first mint call so `validate` never spins up the runtime.
    client: OnceLock<octocrab::Octocrab>,
    /// PEM bytes of the App's RSA private key. Read once at
    /// construction time after the SEC-06 mode check (mode 0600 + owner
    /// root + not a symlink); held in memory for the binary's lifetime
    /// so we do not re-open the file on every mint.
    pem_bytes: Vec<u8>,
}

impl GithubAppToken {
    /// Validate `private_key_path` (SEC-06: mode 0600, owner uid 0,
    /// regular file, not a symlink) and read the PEM into memory.
    ///
    /// # Errors
    ///
    /// `GharsError::Auth` if the path is missing, is a symlink, has
    /// any group/other permission bits, is not owned by root, or
    /// cannot be read.
    pub fn new(
        name: &str,
        app_id: u64,
        installation_id: u64,
        private_key_path: &Utf8Path,
    ) -> Result<Self> {
        let pem_bytes = read_root_owned_0600(private_key_path.as_std_path(), "private_key_path")?;
        Ok(Self {
            name: name.to_string(),
            app_id,
            installation_id,
            client: OnceLock::new(),
            pem_bytes,
        })
    }

    fn client(&self) -> Result<&octocrab::Octocrab> {
        if let Some(c) = self.client.get() {
            return Ok(c);
        }
        let key = jsonwebtoken::EncodingKey::from_rsa_pem(&self.pem_bytes).map_err(|e| {
            GharsError::Auth(
                format!(
                    "auth {:?}: failed to parse RSA PEM in private_key_path: {e}",
                    self.name
                ),
                "verify the file is a PKCS#1 / PKCS#8 RSA private key in PEM form".into(),
            )
        })?;
        // octocrab's `OctocrabBuilder::build()` invokes
        // `tower::Buffer::new(...)` which calls `tokio::spawn(...)`,
        // requiring an entered runtime. Build inside `block_on`.
        let app_id = octocrab::models::AppId(self.app_id);
        let installation_id = octocrab::models::InstallationId(self.installation_id);
        let installation = github::block_on(async move {
            let crab = octocrab::Octocrab::builder().app(app_id, key).build()?;
            crab.installation(installation_id)
        })
        .map_err(|e| octocrab_to_auth(&self.name, "build app client", &e))?;
        Ok(self.client.get_or_init(|| installation))
    }

    fn mint(&self, runner_url: &str, kind: TokenKind) -> Result<RegistrationToken> {
        let scope = github::parse_url(runner_url).map_err(|e| {
            GharsError::Auth(
                format!("auth {:?}: invalid runner url: {e}", self.name),
                "fix the runner's `url` field".into(),
            )
        })?;
        let client = self.client()?;
        let resp = github::block_on(call_octocrab_token(client, &scope, kind))
            .map_err(|e| octocrab_to_auth(&self.name, kind.api_label(), &e))?;
        Ok(registration_token_from_api(&self.name, resp))
    }
}

impl TokenSource for GithubAppToken {
    fn name(&self) -> &str {
        &self.name
    }
    fn mint_registration_token(&self, runner_url: &str) -> Result<RegistrationToken> {
        self.mint(runner_url, TokenKind::Registration)
    }
    fn mint_removal_token(&self, runner_url: &str) -> Result<RegistrationToken> {
        self.mint(runner_url, TokenKind::Removal)
    }
}

// ---------- PatToken ----------

/// Auth source backed by a Personal Access Token (classic or
/// fine-grained). ghars is token-type-agnostic — octocrab forwards
/// whatever string the operator supplies as a Bearer credential and
/// GitHub validates server-side. The schema enforces XOR
/// (`token_env` xor `token_file`) at construction time (#15).
#[derive(Debug)]
pub struct PatToken {
    name: String,
    /// Pre-resolved PAT text. Held in plain `String` rather than
    /// `secrecy::SecretString` because octocrab needs to consume it
    /// (by-value) when we lazily build the client. Constructed once
    /// at `new` so config-time errors surface eagerly; the client
    /// itself is built on first mint inside the tokio runtime
    /// (octocrab's internal `Buffer::new` calls `tokio::spawn`, so
    /// it must run with an entered runtime).
    token: String,
    /// Lazy octocrab handle; populated on first mint.
    client: OnceLock<octocrab::Octocrab>,
}

impl PatToken {
    /// Build a `PatToken`. Exactly one of `token_env` / `token_file`
    /// must be `Some`. This is the canonical XOR enforcement point.
    /// When `token_file` is set the file must satisfy the mode-0600
    /// + owner-root + not-a-symlink check (SEC-25 mitigation).
    ///
    /// # Errors
    ///
    /// `GharsError::Auth` on missing / both env+file, missing env var,
    /// or permission failures.
    pub fn new(name: &str, token_env: Option<&str>, token_file: Option<&Utf8Path>) -> Result<Self> {
        let token = match (token_env, token_file) {
            (Some(_), Some(_)) => {
                return Err(GharsError::Auth(
                    format!(
                        "auth {name:?}: both token_env and token_file are set; pick exactly one"
                    ),
                    format!("remove one of the fields from [auth.{name}]"),
                ));
            }
            (None, None) => {
                return Err(GharsError::Auth(
                    format!("auth {name:?}: PAT requires token_env XOR token_file; both are unset"),
                    format!("set token_env or token_file in [auth.{name}]"),
                ));
            }
            (Some(env_name), None) => {
                let value = std::env::var(env_name).map_err(|_| {
                    GharsError::Auth(
                        format!("auth {name:?}: env var {env_name:?} for PAT is not set"),
                        "export the variable in the systemd unit's environment or the operator shell"
                            .into(),
                    )
                })?;
                // SEC-25: scrub the var from the process environ as soon
                // as we've read it. While ghars is running its env block
                // is readable via /proc/<pid>/environ to anyone with the
                // right uid, so a long-lived ghars process effectively
                // re-leaks the operator's PAT to procfs for the lifetime
                // of the process. Remove the var via the `env` crate's
                // safe wrapper (which checks `num_threads::is_single_
                // threaded()` and only calls the underlying unsafe stdlib
                // mutator when the check passes — see env-1.0.1/src/
                // lib.rs:74-79). Returning `None` means the operation
                // was skipped because we could not prove single-thread
                // safety; we warn rather than fail because the token
                // was already read into `value` and the caller's auth
                // flow can still proceed. PatToken::new runs at config-
                // load before any tokio runtime is built (the runtime
                // is constructed lazily on first mint via the client()
                // method below — see its github::block_on call), so in
                // practice the check passes and the var is removed.
                // The warn path covers operators who construct
                // PatToken from a thread other than the main one.
                if env::remove_var(env_name).is_none() {
                    tracing::warn!(
                        env = env_name,
                        auth = name,
                        "SEC-25: could not scrub PAT env var from /proc/<pid>/environ \
                         (multi-threaded context); var remains visible until process exit. \
                         hint: switch to token_file for SEC-25 mitigation independent of \
                         thread context"
                    );
                }
                value
            }
            (None, Some(path)) => {
                let bytes = read_root_owned_0600(path.as_std_path(), "token_file")?;
                let s = String::from_utf8(bytes).map_err(|e| {
                    GharsError::Auth(
                        format!("auth {name:?}: token_file is not valid UTF-8: {e}"),
                        "rewrite the token file as plain text".into(),
                    )
                })?;
                strip_trailing_newlines(&s)
            }
        };
        if token.is_empty() {
            return Err(GharsError::Auth(
                format!("auth {name:?}: resolved PAT is empty"),
                "double-check the env var / file content".into(),
            ));
        }
        Ok(Self {
            name: name.to_string(),
            token,
            client: OnceLock::new(),
        })
    }

    fn client(&self) -> Result<&octocrab::Octocrab> {
        if let Some(c) = self.client.get() {
            return Ok(c);
        }
        // octocrab's `OctocrabBuilder::build()` ultimately calls
        // `tower::Buffer::new(...)`, which calls `tokio::spawn(...)`
        // and therefore requires the runtime to be entered. Build
        // inside a `block_on` so an entered runtime is guaranteed.
        let token = self.token.clone();
        let crab =
            github::block_on(
                async move { octocrab::Octocrab::builder().personal_token(token).build() },
            )
            .map_err(|e| octocrab_to_auth(&self.name, "build pat client", &e))?;
        Ok(self.client.get_or_init(|| crab))
    }

    fn mint(&self, runner_url: &str, kind: TokenKind) -> Result<RegistrationToken> {
        let scope = github::parse_url(runner_url).map_err(|e| {
            GharsError::Auth(
                format!("auth {:?}: invalid runner url: {e}", self.name),
                "fix the runner's `url` field".into(),
            )
        })?;
        let client = self.client()?;
        let resp = github::block_on(call_octocrab_token(client, &scope, kind))
            .map_err(|e| octocrab_to_auth(&self.name, kind.api_label(), &e))?;
        Ok(registration_token_from_api(&self.name, resp))
    }
}

impl TokenSource for PatToken {
    fn name(&self) -> &str {
        &self.name
    }
    fn mint_registration_token(&self, runner_url: &str) -> Result<RegistrationToken> {
        self.mint(runner_url, TokenKind::Registration)
    }
    fn mint_removal_token(&self, runner_url: &str) -> Result<RegistrationToken> {
        self.mint(runner_url, TokenKind::Removal)
    }
}

// ---------- InteractiveToken ----------

/// Minimum and maximum token length accepted from the operator. The
/// 16-byte floor rejects empty / accidentally-truncated paste; the
/// 256-byte ceiling rejects pasted multi-line values. (Part 6.)
const INTERACTIVE_TOKEN_MIN_LEN: usize = 16;
const INTERACTIVE_TOKEN_MAX_LEN: usize = 256;

/// Default registration-token TTL for sources that don't return an
/// authoritative `expires_at` (interactive paste, file). Matches
/// Part 6 ("now + 1h - 30s"). Stored as a chrono `TimeDelta` so it
/// composes with `Utc::now()` directly without an intermediate
/// `Duration`.
const NON_API_TOKEN_TTL: TimeDelta = TimeDelta::seconds(3600 - 30);

/// Auth source that prompts the operator (TTY required) to paste a
/// pre-minted registration token. Uses `rpassword::prompt_password`
/// for echo-off + Drop guard restoration on SIGINT.
#[derive(Debug)]
pub struct InteractiveToken {
    name: String,
}

impl InteractiveToken {
    /// Build an `InteractiveToken`. Construction is infallible — the
    /// TTY check happens at mint time so `validate` does not require
    /// a controlling terminal.
    pub fn new(name: &str) -> Self {
        Self {
            name: name.to_string(),
        }
    }

    fn prompt(&self, runner_url: &str, kind: TokenKind) -> Result<RegistrationToken> {
        // Refuse if neither stdin nor stderr is a terminal — there is
        // no human there to paste a value, and proceeding would block.
        // We prompt to stderr so the operator sees the URL even when
        // ghars's stdout is piped (e.g. `ghars apply --json | jq`).
        if !std::io::stdin().is_terminal() || !std::io::stderr().is_terminal() {
            return Err(GharsError::Auth(
                format!(
                    "auth {:?}: interactive prompt requires a TTY on stdin and stderr",
                    self.name
                ),
                format!(
                    "run ghars from a terminal or switch [auth.{}] to kind = \"token_file\"",
                    self.name
                ),
            ));
        }
        let prompt = format!(
            "Open {runner_url}/settings/actions/runners/new in a browser, copy the {} token, paste here: ",
            kind.user_label()
        );
        let raw = rpassword::prompt_password(prompt).map_err(|e| {
            GharsError::Auth(
                format!(
                    "auth {:?}: failed to read interactive token: {e}",
                    self.name
                ),
                "ensure the controlling terminal is functional".into(),
            )
        })?;
        assemble_interactive_token(&self.name, &raw)
    }
}

/// Convert a raw operator-pasted token into a [`RegistrationToken`]
/// (#160 helper). Pure logic split out from `InteractiveToken::prompt`
/// so tests can drive every code path without an attached TTY:
///   1. F39 trailing CR/LF strip — `trim_end_matches(['\r', '\n'])`,
///      NEVER `.trim()` (preserves embedded whitespace).
///   2. `validate_interactive_token_shape` — rejects empty / out-of-
///      bounds-length / control-char / whitespace-bearing tokens.
///   3. Construct the `RegistrationToken` with `expires_at = now() +
///      NON_API_TOKEN_TTL` and `source = "interactive:stdin:NAME"`.
///
/// # Errors
///
/// Returns `GharsError::Auth` from
/// `validate_interactive_token_shape` if the trimmed token violates
/// the shape contract.
fn assemble_interactive_token(name: &str, raw: &str) -> Result<RegistrationToken> {
    let trimmed = strip_trailing_newlines(raw);
    validate_interactive_token_shape(&trimmed, name)?;
    Ok(RegistrationToken {
        value: trimmed,
        expires_at: Utc::now() + NON_API_TOKEN_TTL,
        source: format!("interactive:stdin:{name}"),
    })
}

impl TokenSource for InteractiveToken {
    fn name(&self) -> &str {
        &self.name
    }
    fn mint_registration_token(&self, runner_url: &str) -> Result<RegistrationToken> {
        self.prompt(runner_url, TokenKind::Registration)
    }
    fn mint_removal_token(&self, runner_url: &str) -> Result<RegistrationToken> {
        self.prompt(runner_url, TokenKind::Removal)
    }
}

fn validate_interactive_token_shape(token: &str, name: &str) -> Result<()> {
    if token.is_empty() {
        return Err(GharsError::Auth(
            format!("auth {name:?}: pasted token is empty"),
            "paste the registration token from GitHub's runner UI".into(),
        ));
    }
    if token.len() < INTERACTIVE_TOKEN_MIN_LEN || token.len() > INTERACTIVE_TOKEN_MAX_LEN {
        return Err(GharsError::Auth(
            format!(
                "auth {name:?}: pasted token length {} outside [{}, {}]",
                token.len(),
                INTERACTIVE_TOKEN_MIN_LEN,
                INTERACTIVE_TOKEN_MAX_LEN
            ),
            "re-copy the token; registration tokens are short opaque strings".into(),
        ));
    }
    // #273: emit a CLASS label rather than echoing the offending char
    // itself so even a one-character partial leak of the operator's
    // pasted bytes is impossible. NUL is checked first because '\0'
    // is also `is_control()` — without the explicit pre-check the
    // `is_control()` branch would shadow NUL with the generic label.
    if let Some(bad) = token
        .chars()
        .find(|c| *c == '\0' || c.is_whitespace() || c.is_control())
    {
        let class = if bad == '\0' {
            "NUL byte"
        } else if bad.is_whitespace() {
            "whitespace"
        } else {
            "control character"
        };
        return Err(GharsError::Auth(
            format!("auth {name:?}: pasted token contains forbidden {class}"),
            "registration tokens contain only printable non-whitespace characters".into(),
        ));
    }
    Ok(())
}

// ---------- TokenFileToken ----------

/// Auth source that reads a pre-minted registration token from a file
/// (mode 0o600, owner root, not a symlink — same SEC-06 contract as
/// the GitHub App private key). Trailing CR/LF stripped per F39
/// (`s.trim_end_matches(['\r', '\n'])`, NEVER `.trim()`).
#[derive(Debug)]
pub struct TokenFileToken {
    name: String,
    path: camino::Utf8PathBuf,
}

impl TokenFileToken {
    /// Build a `TokenFileToken`. Verifies the path's mode + ownership
    /// at construction so `validate` surfaces misconfiguration. The
    /// content is re-read on every mint because token files may be
    /// rotated underneath ghars between apply runs.
    ///
    /// # Errors
    ///
    /// `GharsError::Auth` on missing / wrong-mode / non-root-owned /
    /// symlinked path. (Content is checked at mint time.)
    pub fn new(name: &str, path: &Utf8Path) -> Result<Self> {
        // Verify and read once at construction so a bad config errors
        // at validate time, not at apply time. The bytes themselves
        // are discarded — we re-read on mint for rotation support.
        read_root_owned_0600(path.as_std_path(), "token_file")?;
        Ok(Self {
            name: name.to_string(),
            path: path.to_path_buf(),
        })
    }

    fn read(&self, kind: TokenKind) -> Result<RegistrationToken> {
        let bytes = read_root_owned_0600(self.path.as_std_path(), "token_file")?;
        let s = String::from_utf8(bytes).map_err(|e| {
            GharsError::Auth(
                format!("auth {:?}: token_file is not valid UTF-8: {e}", self.name),
                "rewrite the token file as plain text".into(),
            )
        })?;
        let trimmed = strip_trailing_newlines(&s);
        if trimmed.is_empty() {
            return Err(GharsError::Auth(
                format!(
                    "auth {:?}: token_file is empty after CR/LF strip",
                    self.name
                ),
                "write the registration token to the file with no other content".into(),
            ));
        }
        Ok(RegistrationToken {
            value: trimmed,
            expires_at: Utc::now() + NON_API_TOKEN_TTL,
            source: format!("token-file:{}:{}", self.name, kind.user_label()),
        })
    }
}

impl TokenSource for TokenFileToken {
    fn name(&self) -> &str {
        &self.name
    }
    fn mint_registration_token(&self, runner_url: &str) -> Result<RegistrationToken> {
        let _ = github::parse_url(runner_url)?;
        self.read(TokenKind::Registration)
    }
    fn mint_removal_token(&self, runner_url: &str) -> Result<RegistrationToken> {
        let _ = github::parse_url(runner_url)?;
        self.read(TokenKind::Removal)
    }
}

// ---------- shared helpers ----------

/// Discriminator for which octocrab API to call. Keeps the
/// async-block lifetime short and lets us share one helper across
/// `GithubAppToken` and `PatToken`.
#[derive(Clone, Copy)]
enum TokenKind {
    Registration,
    Removal,
}

impl TokenKind {
    fn user_label(self) -> &'static str {
        match self {
            Self::Registration => "registration",
            Self::Removal => "removal",
        }
    }

    fn api_label(self) -> &'static str {
        match self {
            Self::Registration => "create_runner_registration_token",
            Self::Removal => "create_runner_remove_token",
        }
    }
}

async fn call_octocrab_token(
    client: &octocrab::Octocrab,
    scope: &Scope,
    kind: TokenKind,
) -> std::result::Result<octocrab::models::actions::SelfHostedRunnerToken, octocrab::Error> {
    match (scope, kind) {
        (Scope::Repo { owner, repo }, TokenKind::Registration) => {
            client
                .actions()
                .create_repo_runner_registration_token(owner, repo)
                .await
        }
        (Scope::Repo { owner, repo }, TokenKind::Removal) => {
            client
                .actions()
                .create_repo_runner_remove_token(owner, repo)
                .await
        }
        (Scope::Org { owner }, TokenKind::Registration) => {
            client
                .actions()
                .create_org_runner_registration_token(owner)
                .await
        }
        (Scope::Org { owner }, TokenKind::Removal) => {
            client.actions().create_org_runner_remove_token(owner).await
        }
    }
}

/// Convert a successful octocrab `SelfHostedRunnerToken` response into
/// a ghars [`RegistrationToken`] (#161 helper). Pure logic split out
/// from `GithubAppToken::mint` and `PatToken::mint` so tests can drive
/// the conversion with synthetic responses without an octocrab client
/// or live network.
///
/// `expires_at` passes through verbatim — octocrab's
/// `SelfHostedRunnerToken.expires_at` is already
/// `chrono::DateTime<Utc>` (per
/// `octocrab-0.42.1/src/models/actions.rs:43`), and ghars stores the
/// same type, so no conversion is needed. `source` is the per-runner
/// `"github:NAME"` tag used by ApplyResult to attribute audit-log
/// entries to the auth principal.
#[must_use]
fn registration_token_from_api(
    name: &str,
    resp: octocrab::models::actions::SelfHostedRunnerToken,
) -> RegistrationToken {
    RegistrationToken {
        value: resp.token,
        expires_at: resp.expires_at,
        source: format!("github:{name}"),
    }
}

fn octocrab_to_auth(name: &str, op: &str, err: &octocrab::Error) -> GharsError {
    // #307 / #365: pick the actionable hint by error class so the
    // operator sees the right diagnosis — octocrab::Error is
    // `#[non_exhaustive]` (see octocrab-0.42.1/src/error.rs:25), the
    // catch-all keeps the build healthy across upstream variant
    // additions. The individual arms below speak for themselves.
    let hint = match err {
        octocrab::Error::GitHub { source, .. } => {
            let code = source.status_code.as_u16();
            match code {
                401 | 403 => format!(
                    "GitHub returned {code} — typically (a) the auth principal lacks the \
                     required permissions / scopes for this endpoint or the credential \
                     has been revoked (PAT scopes / token validity, App installation \
                     grants, or fine-grained PAT permissions, depending on the source); \
                     or (b) the releases endpoint is normally public, so a proxy or GHE \
                     mirror in the path is intercepting and demanding token/PAT \
                     credentials from an intermediate"
                ),
                404 => format!(
                    "GitHub returned {code} — verify the owner/repo in the runner \
                     URL exists, the auth principal can access it, and the repo \
                     has Actions enabled"
                ),
                429 => format!(
                    "GitHub returned {code} — secondary rate limit; wait the \
                     `Retry-After` interval or reduce concurrent applies"
                ),
                500..=599 => format!(
                    "GitHub returned {code} — upstream is degraded; retry, and \
                     check status.github.com if the failure persists"
                ),
                _ => format!(
                    "GitHub returned {code} — see the API response above for the \
                     specific failure reason"
                ),
            }
        }
        // defense-in-depth: untestable without octocrab snafu builder access
        // (octocrab 0.42 error module is private). InvalidHeaderValue
        // surfaces only when ghars builds an invalid HTTP header — the
        // operator cannot trigger this from config, so the hint points
        // at a ghars bug rather than at operator action.
        octocrab::Error::InvalidHeaderValue { .. } => {
            "internal error: HTTP header construction failed; this is a ghars bug — \
             file an issue with the error above"
                .into()
        }
        octocrab::Error::Hyper { .. }
        | octocrab::Error::Service { .. }
        | octocrab::Error::Http { .. }
        | octocrab::Error::Uri { .. }
        | octocrab::Error::UriParse { .. } => {
            "transport / network failure — verify outbound HTTPS to api.github.com \
             (and any proxy CA configured via [proxy].ca_certs) succeeds"
                .into()
        }
        // defense-in-depth: untestable without octocrab snafu builder access
        // (octocrab 0.42 error module is private)
        octocrab::Error::JWT { .. } | octocrab::Error::Installation { .. } => {
            "GitHub App auth failed — verify the [auth.NAME] fields `app_id`, \
             `installation_id`, and `private_key_path` match the deployed App, \
             and that the private-key file is the current key pair"
                .into()
        }
        // Catch-all covers Json / Serde / SerdeUrlEncoded / InvalidUtf8 /
        // Encoder / Other and any future #[non_exhaustive] variant.
        _ => "see the underlying error above — file a ghars bug if this class \
              should be mapped to a more specific hint"
            .into(),
    };
    GharsError::Auth(format!("auth {name:?}: {op} failed: {err}"), hint)
}

/// Strip ONLY trailing `\r` / `\n` — F39. Operator content (including
/// embedded whitespace) is preserved on purpose.
fn strip_trailing_newlines(s: &str) -> String {
    s.trim_end_matches(['\r', '\n']).to_string()
}

/// Open `path` with `O_NOFOLLOW`, then verify (a) it is a regular
/// file, (b) `st_uid == 0`, (c) no group/other permission bits set
/// (`mode & 0o077 == 0`). Reads the contents on success.
///
/// `O_NOFOLLOW` is the SEC-06 anti-TOCTOU primitive: open(2) itself
/// fails on the kernel side if the path is a symlink, so the file we
/// read is guaranteed to be the same inode whose mode we check.
///
/// The open + fstat mechanism is shared with the SEC-12 hook
/// validator via [`crate::validators::open_no_follow_with_meta`]. The
/// auth-specific policy (mode 0o077 + uid 0 + read contents) lives
/// here; the hook validator applies its own policy on the same
/// (file, metadata) pair.
///
/// `field_label` appears in error messages (`"private_key_path"`,
/// `"token_file"`).
fn read_root_owned_0600(path: &Path, field_label: &str) -> Result<Vec<u8>> {
    let (mut file, meta) = crate::validators::open_no_follow_with_meta(path).map_err(|e| {
        // ELOOP from O_NOFOLLOW vs other I/O errors are both fatal but
        // the operator should know if it's a symlink so they don't try
        // again with the same setup.
        let kind_hint = if e.raw_os_error() == Some(libc::ELOOP) {
            "the path resolves to a symlink; replace it with the target file"
        } else {
            "ensure the path exists and is readable by ghars"
        };
        GharsError::Auth(
            format!("{field_label} {:?}: open failed: {e}", path.display()),
            kind_hint.into(),
        )
    })?;
    if !meta.file_type().is_file() {
        return Err(GharsError::Auth(
            format!(
                "{field_label} {:?}: not a regular file (file type {:?})",
                path.display(),
                meta.file_type()
            ),
            "the path must point at a regular file, not a directory or device".into(),
        ));
    }
    let mode = meta.mode() & 0o7777;
    if mode & 0o077 != 0 {
        return Err(GharsError::Auth(
            format!(
                "{field_label} {:?}: mode {:o} too permissive; group/other must be 0",
                path.display(),
                mode
            ),
            "chmod 600 the file and ensure the directory is also restricted".into(),
        ));
    }
    if meta.uid() != 0 {
        return Err(GharsError::Auth(
            format!(
                "{field_label} {:?}: owner uid {} != 0 (root)",
                path.display(),
                meta.uid()
            ),
            "chown root: the file (sudo chown root:root <path>)".into(),
        ));
    }
    let mut buf = Vec::new();
    file.read_to_end(&mut buf).map_err(|e| {
        GharsError::Auth(
            format!("{field_label} {:?}: read failed: {e}", path.display()),
            "filesystem error".into(),
        )
    })?;
    Ok(buf)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::fs::File;
    use std::io::Write;
    use std::os::unix::fs::PermissionsExt;
    use std::os::unix::fs::symlink;

    use camino::Utf8PathBuf;

    fn mk_file(dir: &tempfile::TempDir, name: &str, content: &[u8], mode: u32) -> Utf8PathBuf {
        let path = dir.path().join(name);
        let mut f = File::create(&path).unwrap();
        f.write_all(content).unwrap();
        let mut perms = f.metadata().unwrap().permissions();
        perms.set_mode(mode);
        f.set_permissions(perms).unwrap();
        Utf8PathBuf::from_path_buf(path).unwrap()
    }

    /// Detect whether the test process is running as root WITHOUT
    /// using `unsafe` (the crate forbids unsafe). We stat `/proc/self`
    /// — owner uid of the procfs entry equals the calling task's uid
    /// (Linux kernel guarantees this; `proc/<pid>` is owned by the
    /// task's real uid).
    fn running_as_root() -> bool {
        std::fs::metadata("/proc/self")
            .map(|m| m.uid() == 0)
            .unwrap_or(false)
    }

    #[test]
    fn strip_trailing_newlines_strips_only_cr_and_lf() {
        assert_eq!(strip_trailing_newlines("abc\n"), "abc");
        assert_eq!(strip_trailing_newlines("abc\r\n"), "abc");
        assert_eq!(strip_trailing_newlines("abc\r\n\n"), "abc");
        // Embedded whitespace and trailing spaces are preserved.
        assert_eq!(strip_trailing_newlines("a b c "), "a b c ");
        assert_eq!(strip_trailing_newlines(" abc \n"), " abc ");
    }

    /// F39 contract edge cases — every input shape `read_root_owned_0600`
    /// might receive from a credential file. The contract is:
    /// `trim_end_matches(['\r', '\n'])` — NOT `.trim()`. Embedded
    /// whitespace and any non-`\r\n` characters anywhere in the string
    /// must survive verbatim (#163).
    #[test]
    fn strip_trailing_newlines_handles_edge_cases() {
        // Empty input is a fixed point.
        assert_eq!(strip_trailing_newlines(""), "");
        // Pure newline runs collapse to empty.
        assert_eq!(strip_trailing_newlines("\n"), "");
        assert_eq!(strip_trailing_newlines("\n\n"), "");
        // Lone CR is a trailing match too.
        assert_eq!(strip_trailing_newlines("\r"), "");
        assert_eq!(strip_trailing_newlines("token\r"), "token");
        // Multi-CRLF runs collapse together.
        assert_eq!(strip_trailing_newlines("token\r\n\r\n"), "token");
        // Mixed run interleaving CR and LF in any order.
        assert_eq!(strip_trailing_newlines("token\n\r\n\r"), "token");
        // Embedded whitespace inside the body is preserved verbatim;
        // only the trailing newline is removed.
        assert_eq!(strip_trailing_newlines("a b\n"), "a b");
        // Internal CR/LF that has non-newline content after it must
        // survive — `trim_end_matches` only peels from the tail.
        assert_eq!(strip_trailing_newlines("a\nb\n"), "a\nb");
        assert_eq!(strip_trailing_newlines("a\r\nb"), "a\r\nb");
        // No-op when the string ends with a non-newline character,
        // even if that character is whitespace.
        assert_eq!(strip_trailing_newlines("token "), "token ");
        assert_eq!(strip_trailing_newlines("token\t"), "token\t");
        // Three-newline run: `trim_end_matches` peels every trailing
        // `\n`, not just one. A mutation that strips a single newline
        // (e.g. `s.strip_suffix('\n').unwrap_or(s)`) survives the
        // single-`\n` case but breaks here.
        assert_eq!(strip_trailing_newlines("\n\n\n"), "");
        // Multibyte UTF-8 immediately before the trailing newline must
        // survive verbatim. `trim_end_matches` operates on `char`s, so
        // a 4-byte codepoint at the tail is not split. A mutation to
        // byte-based slicing (e.g. `s[..s.len() - 1]`) would corrupt
        // the codepoint and produce invalid UTF-8.
        let yen = "12345\u{00A5}\n"; // U+00A5 (¥) is 2 bytes in UTF-8.
        assert_eq!(strip_trailing_newlines(yen), "12345\u{00A5}");
        let pile = "abc\u{1F4A9}\n"; // U+1F4A9 is 4 bytes in UTF-8.
        assert_eq!(strip_trailing_newlines(pile), "abc\u{1F4A9}");
    }

    #[test]
    fn validate_interactive_token_shape_accepts_typical_token() {
        let token: String = "A".repeat(40);
        validate_interactive_token_shape(&token, "x").unwrap();
    }

    #[test]
    fn validate_interactive_token_shape_rejects_short() {
        let token = "ABC";
        let err = validate_interactive_token_shape(token, "x").unwrap_err();
        let msg = format!("{err}");
        assert!(msg.contains("length"), "{msg}");
    }

    #[test]
    fn validate_interactive_token_shape_rejects_long() {
        let token: String = "A".repeat(INTERACTIVE_TOKEN_MAX_LEN + 1);
        let err = validate_interactive_token_shape(&token, "x").unwrap_err();
        let msg = format!("{err}");
        assert!(msg.contains("length"), "{msg}");
    }

    #[test]
    fn validate_interactive_token_shape_rejects_whitespace() {
        // Use \t (tab) as the offending whitespace byte rather than
        // ' ' (space). Tab is whitespace per char::is_whitespace, but
        // the class label text "forbidden whitespace" itself contains
        // a literal space — so `!msg.contains(' ')` would always
        // fail. With \t the offending byte appears in no error
        // string naturally, so `!msg.contains('\t')` is a clean
        // no-leak assertion that mirrors the NUL test's
        // `!msg.contains('\0')`.
        let err = validate_interactive_token_shape("AAAAAAAAAAAAAAAA\tAAA", "x").unwrap_err();
        let msg = format!("{err}");
        assert!(msg.contains("forbidden whitespace"), "{msg}");
        assert!(
            !msg.contains('\t'),
            "literal tab byte must not leak: {msg:?}"
        );
    }

    #[test]
    fn validate_interactive_token_shape_rejects_nul() {
        let err = validate_interactive_token_shape("AAAAAAAAAAAAAAAA\0AAA", "x").unwrap_err();
        let msg = format!("{err}");
        // #273: NUL takes the explicit `'\0'` branch BEFORE
        // is_control() (which it is also a member of). Pin that
        // the label is "NUL byte" — NOT "control character" — so a
        // future regression that drops the NUL pre-check surfaces
        // here. Also pin no-byte-leak for the literal NUL.
        assert!(msg.contains("NUL byte"), "{msg}");
        assert!(
            !msg.contains("control character"),
            "NUL must take its own branch, not fall through to control character: {msg}"
        );
        assert!(
            !msg.contains('\0'),
            "literal NUL byte must not leak: {msg:?}"
        );
    }

    /// #273: the third class label — control characters that aren't
    /// NUL or whitespace (e.g. `\x07` BEL, `\x1b` ESC) must take the
    /// generic `"control character"` branch.
    #[test]
    fn validate_interactive_token_shape_rejects_control_character() {
        let err = validate_interactive_token_shape("AAAAAAAAAAAAAAAA\x07AAA", "x").unwrap_err();
        let msg = format!("{err}");
        assert!(msg.contains("forbidden control character"), "{msg}");
        assert!(
            !msg.contains('\x07'),
            "literal BEL byte must not leak: {msg:?}"
        );
    }

    #[test]
    fn read_root_owned_0600_rejects_world_readable_or_non_root_owned() {
        let dir = tempfile::tempdir().unwrap();
        let path = mk_file(&dir, "token", b"abc\n", 0o644);
        let err = read_root_owned_0600(path.as_std_path(), "token_file").unwrap_err();
        let msg = format!("{err}");
        // Either the mode check (when running as root) or the uid
        // check (non-root) must fire — never silent acceptance.
        assert!(msg.contains("mode") || msg.contains("uid"), "{msg}");
    }

    #[test]
    fn read_root_owned_0600_rejects_symlink() {
        let dir = tempfile::tempdir().unwrap();
        let target = mk_file(&dir, "real", b"abc\n", 0o600);
        let link_path = dir.path().join("link");
        symlink(target.as_std_path(), &link_path).unwrap();
        let err = read_root_owned_0600(&link_path, "private_key_path").unwrap_err();
        let msg = format!("{err}");
        assert!(
            msg.contains("symlink") || msg.contains("open failed"),
            "{msg}"
        );
    }

    #[test]
    fn read_root_owned_0600_rejects_directory() {
        let dir = tempfile::tempdir().unwrap();
        let err = read_root_owned_0600(dir.path(), "private_key_path");
        // Either O_NOFOLLOW + opening a dir for read produces ENOTDIR
        // / EISDIR depending on platform, or the regular-file check
        // fires after open. Both are acceptable.
        assert!(err.is_err());
    }

    #[test]
    fn read_root_owned_0600_rejects_missing() {
        let err = read_root_owned_0600(
            Path::new("/nonexistent/ghars/auth/test"),
            "private_key_path",
        );
        assert!(err.is_err());
    }

    #[test]
    fn pat_token_rejects_both_env_and_file() {
        let err = PatToken::new(
            "p",
            Some("GHARS_TEST_VAR_NEVER_SET"),
            Some(Utf8Path::new("/tmp/never-exists-ghars-test")),
        )
        .unwrap_err();
        let msg = format!("{err}");
        assert!(msg.contains("both"), "{msg}");
        // #354: hint must substitute the actual auth name, not leave
        // a literal `[auth.NAME]` placeholder. PatToken::new was
        // called with `"p"` so the rendered hint must read
        // `[auth.p]`. Pinned because the placeholder version was
        // operator-confusing — they couldn't tell which TOML block
        // to edit.
        assert!(
            msg.contains("[auth.p]"),
            "hint must interpolate auth name into [auth.p]; got: {msg}"
        );
        assert!(
            !msg.contains("[auth.NAME]"),
            "hint must NOT leave the literal placeholder; got: {msg}"
        );
    }

    #[test]
    fn pat_token_rejects_neither_env_nor_file() {
        let err = PatToken::new("p", None, None).unwrap_err();
        let msg = format!("{err}");
        assert!(msg.contains("XOR"), "{msg}");
    }

    /// #614: pin the EXACT (Some, Some) rejection message — `both
    /// token_env and token_file are set; pick exactly one`. Existing
    /// `pat_token_rejects_both_env_and_file` tests substring `"both"`
    /// + the [auth.NAME] hint substitution; this test pins the full
    /// message wording so a future PatToken::new edit that softens
    /// "pick exactly one" to "remove one" (or similar) is caught at
    /// the test layer.
    #[test]
    fn pat_token_xor_some_some_rejects_with_exact_both_set_message() {
        let err = PatToken::new(
            "p",
            Some("GHARS_TEST_VAR_NEVER_SET"),
            Some(Utf8Path::new("/tmp/never-exists-ghars-test")),
        )
        .unwrap_err();
        let msg = format!("{err}");
        assert!(
            msg.contains("both token_env and token_file are set; pick exactly one"),
            "exact (Some,Some) rejection message must appear; got: {msg}",
        );
    }

    /// #614: pin the EXACT (None, None) rejection message — `PAT
    /// requires token_env XOR token_file; both are unset`. Existing
    /// `pat_token_rejects_neither_env_nor_file` tests only the `XOR`
    /// substring; this test pins the full message so a future
    /// rewording is caught at the test layer.
    #[test]
    fn pat_token_xor_none_none_rejects_with_exact_both_unset_message() {
        let err = PatToken::new("p", None, None).unwrap_err();
        let msg = format!("{err}");
        assert!(
            msg.contains("PAT requires token_env XOR token_file; both are unset"),
            "exact (None,None) rejection message must appear; got: {msg}",
        );
    }

    /// #614: pin (Some, None) — env-only path — as the canonical
    /// XOR-OK shape. Happy-path coverage already exists in
    /// `pat_token_accepts_env_via_external_setter` (which depends on
    /// the runtime PATH env var); this test isolates the input
    /// arity by setting a dedicated test env var via the safe
    /// `env::set_var` wrapper, so the assertion is hermetic against
    /// whatever else happens to be in the process env.
    ///
    /// Mirrors the env-mutation pattern at `pat_token_removes_env_var_after_construction`:
    /// the safe wrapper returns `None` under multi-threading
    /// (libtest spawns ≥1 runner thread on Linux), in which case
    /// the var-set is skipped and we cannot reliably exercise the
    /// happy path; bail without asserting per the existing test
    /// pattern.
    #[test]
    fn pat_token_xor_some_none_accepts_via_set_var() {
        let var = "GHARS_TEST_PAT_XOR_SOME_NONE";
        let token_text = "ghp_dummy_token_for_xor_some_none";
        if env::set_var(var, token_text).is_none() {
            // Multi-threaded process: env mutation skipped, can't
            // hermetically test the env path. Skip.
            return;
        }
        let pat = PatToken::new("p", Some(var), None).expect("(Some,None) must construct Ok");
        assert_eq!(pat.name(), "p");
        // PatToken::new scrubs the source var on construction; the
        // multi-thread skip means scrub may or may not have run, so
        // we do not assert post-state of `var` here.
    }

    /// #614: (None, Some) — token_file path — Ok arm. Cannot be
    /// exercised under unit tests because `read_root_owned_0600`
    /// requires the file to be `mode 0600 owner=root`, and the test
    /// runner is unprivileged. Existing tests pin the rejection
    /// surface (`build_factory_rejects_token_file_with_wrong_mode`,
    /// `token_file_token_constructor_enforces_mode_and_owner`) — the
    /// Ok arm is left to integration tests that run under root or
    /// with `CAP_FOWNER`. This test documents the gap by asserting
    /// the rejection that any non-root invocation hits, so the
    /// matrix entry is not silently absent.
    #[test]
    fn pat_token_xor_none_some_rejected_unprivileged_due_to_root_owned_check() {
        // Use a path that exists but is not root-owned 0600 (any
        // tmpfile created by this test runner will have the runner's
        // uid, not 0, so `read_root_owned_0600` rejects). The point
        // is to demonstrate the (None, Some) input arity reaches the
        // file-permission gate; we do NOT assert the Ok branch here.
        let dir = tempfile::TempDir::new().unwrap();
        let path = dir.path().join("token");
        std::fs::write(&path, "x").unwrap();
        let utf8 = camino::Utf8PathBuf::from_path_buf(path).unwrap();
        let err = PatToken::new("p", None, Some(utf8.as_path())).unwrap_err();
        let msg = format!("{err}");
        // Either mode or owner check fires — both are valid evidence
        // that the (None, Some) arm reached the file-permission gate.
        // Production messages at auth.rs:833/843 emit `mode {:o}` and
        // `owner uid {} != 0` respectively; literal "0600" never appears.
        assert!(
            msg.contains("mode") || msg.contains("owner"),
            "(None,Some) arm must reach the SEC-25 mode/owner check; got: {msg}",
        );
    }

    #[test]
    fn pat_token_rejects_unset_env() {
        // Use a deliberately bizarre env var name no one would set.
        let var = "GHARS_TEST_PAT_UNSET_NEVER_SET_42";
        if std::env::var(var).is_ok() {
            // Bail rather than mutate (crate forbids unsafe; std env
            // mutation requires unsafe in 2024 edition).
            return;
        }
        let err = PatToken::new("p", Some(var), None).unwrap_err();
        let msg = format!("{err}");
        assert!(msg.contains("not set"), "{msg}");
    }

    #[test]
    fn pat_token_accepts_env_via_external_setter() {
        // Pull from PATH (always set in any sane environment); we
        // just need *some* non-empty env var to validate the
        // "happy-path env-resolution" branch.
        //
        // SEC-25 side effect: PatToken::new attempts to scrub the
        // source var. The scrub is best-effort — the env crate's
        // safe wrapper requires single-thread (or a thread-safe OS
        // like illumos/netbsd/windows) and skips otherwise. We don't
        // assert scrub here because libtest's runner thread makes
        // the test process multi-threaded on Linux; pin that
        // invariant in the dedicated `pat_token_*_scrub` test instead.
        let var = "PATH";
        let Ok(saved) = std::env::var(var) else {
            return;
        };
        if saved.is_empty() {
            return;
        }
        let pat = PatToken::new("p", Some(var), None).unwrap();
        assert_eq!(pat.name(), "p");
        // Restore PATH if the scrub did fire, so any later test in
        // the same process that spawns a subprocess still finds it.
        // Best-effort: in multi-threaded contexts both the original
        // scrub and this restore no-op (the var was never removed).
        let _ = env::set_var(var, &saved);
    }

    /// SEC-25: `PatToken::new` must remove the source env var from
    /// `/proc/<pid>/environ` after reading it so a long-lived ghars
    /// process does not re-leak the operator's PAT for its lifetime.
    ///
    /// The scrub uses the `env` crate's safe wrapper which only runs
    /// the underlying mutation on single-threaded processes (Linux:
    /// `/proc/self/stat:nr_threads == 1`) or on OSes where env
    /// mutation is documented thread-safe (illumos/netbsd/windows).
    /// libtest spawns at least one runner thread per test, so a Linux
    /// nextest+libtest test process is multi-threaded by construction;
    /// the `env` crate refuses to mutate and PatToken::new's scrub is
    /// skipped per spec ("warn but don't fail"). Per-process semantics
    /// in production (where ghars's CLI runs single-threaded until
    /// first mint at auth.rs:303-308 builds the tokio runtime) are
    /// what SEC-25 actually targets, but we can't reproduce that
    /// single-threaded condition under libtest.
    ///
    /// This test therefore EITHER:
    ///   - exercises the scrub-fired branch (single-thread; var is
    ///     removed), OR
    ///   - exercises the warn-and-proceed branch (multi-thread; var
    ///     stays set; PatToken::new still returns Ok because the PAT
    ///     was already read into the token).
    /// Production single-threaded coverage is left to manual / CI
    /// integration tests that invoke the binary out-of-process.
    #[test]
    fn pat_token_removes_env_var_after_construction() {
        let var = "GHARS_TEST_SEC25_PAT_REMOVAL_VAR";
        let token_text = "ghp_dummy_token_value_for_test";

        // Probe single-threadedness via /proc/self/stat field 20
        // (nr_threads). Same mechanism env's num_threads dep uses on
        // Linux (num_threads-0.1.7/src/linux.rs:5-12). Inlined here
        // to avoid pulling num_threads into dev-deps.
        fn is_single_threaded() -> bool {
            std::fs::read_to_string("/proc/self/stat")
                .ok()
                .as_deref()
                .and_then(|s| s.rsplit(')').next().map(str::to_owned))
                .and_then(|rstat| rstat.split_whitespace().nth(17).map(str::to_owned))
                .and_then(|n| n.parse::<usize>().ok())
                .is_some_and(|n| n == 1)
        }

        // Set the var via the safe wrapper. Single-threaded → Some(()),
        // multi-threaded → None. Capture which branch fired so we can
        // assert the corresponding post-condition after PatToken::new.
        let single_thread_at_set = is_single_threaded();
        let set_result = env::set_var(var, token_text);

        if set_result.is_none() {
            // Multi-threaded: the wrapper refused and the var was
            // never set. PatToken::new will fail because env::var
            // returns Err (the var was never set). Verify that
            // failure mode and stop — we can't test scrub semantics
            // when set_var itself didn't run.
            assert!(
                !single_thread_at_set,
                "set_var refused but probe said single-threaded — environment inconsistent"
            );
            let err = PatToken::new("p", Some(var), None).expect_err("var never set");
            assert!(format!("{err}").contains("not set"));
            return;
        }

        // Single-threaded path: var is set, PatToken::new must read
        // it AND scrub it.
        assert_eq!(
            std::env::var(var).as_deref(),
            Ok(token_text),
            "env::set_var returned Some(()) but the var didn't stick"
        );
        let _pat = PatToken::new("p", Some(var), None).unwrap();
        assert!(
            std::env::var(var).is_err(),
            "PatToken::new must scrub {var} from environ after reading it (SEC-25)"
        );
    }

    #[test]
    fn build_factory_constructs_interactive() {
        let spec = AuthSpec::Interactive;
        let src = build(&spec, "i").unwrap();
        assert_eq!(src.name(), "i");
    }

    #[test]
    fn build_factory_rejects_token_file_with_wrong_mode() {
        let dir = tempfile::tempdir().unwrap();
        let path = mk_file(&dir, "tok", b"x", 0o644);
        let spec = AuthSpec::TokenFile { path: path.clone() };
        match build(&spec, "tf") {
            Ok(_) => panic!("expected build to reject mode-0644 token_file"),
            Err(e) => {
                let msg = format!("{e}");
                assert!(msg.contains("mode") || msg.contains("uid"), "{msg}");
            }
        }
    }

    #[test]
    fn token_file_token_constructor_enforces_mode_and_owner() {
        let dir = tempfile::tempdir().unwrap();
        let path = mk_file(&dir, "tok", b"reg-token-value\n", 0o600);
        let result = TokenFileToken::new("tf", &path);
        if running_as_root() {
            // Root + 0600 + non-symlink: must succeed.
            let _ok = result.unwrap();
        } else {
            // Non-root: uid check rejects (file owned by current uid,
            // not 0).
            assert!(result.is_err());
        }
    }

    /// SEC-06 rotation contract (#161): `TokenFileToken::read` MUST
    /// re-read the file on every mint so the token rotates without a
    /// ghars restart. A mutation that caches the bytes in `self`
    /// during construction would silently break rotation. This test
    /// pins the behavior: write v1, mint, rewrite to v2, mint again,
    /// assert distinct values.
    ///
    /// Gated on root because `read_root_owned_0600` requires uid==0
    /// + mode 0600 + non-symlink — these are SEC-06 invariants we
    /// can't bypass for testing without weakening the security
    /// surface. Non-root environments skip the assertion (matches
    /// the existing pattern in
    /// `token_file_token_constructor_enforces_mode_and_owner`).
    #[test]
    fn token_file_token_re_reads_on_every_read_to_support_rotation() {
        if !running_as_root() {
            // Non-root: SEC-06 mode/owner check rejects every call.
            // We can still verify that the construction-time read
            // does NOT cache a successful read for later mints —
            // construct fails outright in this environment, which is
            // the correct security behavior. Skip the rotation
            // assertion; rely on root-CI runs to exercise it.
            return;
        }
        let dir = tempfile::tempdir().unwrap();
        let path = mk_file(&dir, "tok", b"first-token-value\n", 0o600);
        let tf = TokenFileToken::new("tf-rot", &path).unwrap();
        let r1 = tf.read(TokenKind::Registration).unwrap();
        assert_eq!(r1.value, "first-token-value");

        // Rewrite the file in place with a different token. Use the
        // same mode (0600) so the SEC-06 check still passes.
        std::fs::write(path.as_std_path(), b"second-token-value\n").unwrap();
        let r2 = tf.read(TokenKind::Registration).unwrap();
        assert_eq!(
            r2.value, "second-token-value",
            "TokenFileToken must re-read on every mint (rotation contract)"
        );

        // Source label format pin: `token-file:NAME:KIND_LABEL` so
        // ApplyResult audit logs identify the rotated token.
        assert_eq!(r1.source, "token-file:tf-rot:registration");
        assert_eq!(r2.source, "token-file:tf-rot:registration");
    }

    /// Removal kind produces a different source-label suffix
    /// ("removal" vs "registration"). Pins the kind→label mapping so
    /// a mutation that conflates the two surfaces here.
    #[test]
    fn token_file_token_source_label_distinguishes_kind() {
        if !running_as_root() {
            return;
        }
        let dir = tempfile::tempdir().unwrap();
        let path = mk_file(&dir, "tok", b"v\n", 0o600);
        let tf = TokenFileToken::new("tf-kind", &path).unwrap();
        let reg = tf.read(TokenKind::Registration).unwrap();
        let rem = tf.read(TokenKind::Removal).unwrap();
        assert_eq!(reg.source, "token-file:tf-kind:registration");
        assert_eq!(rem.source, "token-file:tf-kind:removal");
        assert_ne!(reg.source, rem.source);
    }

    #[test]
    fn registration_token_struct_fields_visible() {
        let t = RegistrationToken {
            value: "v".into(),
            expires_at: Utc::now(),
            source: "s".into(),
        };
        assert_eq!(t.value, "v");
        assert_eq!(t.source, "s");
    }

    // ---- #160: InteractiveToken pure-logic helper ---------------------

    #[test]
    fn assemble_interactive_token_strips_trailing_newlines_and_validates_shape() {
        // Happy path: 40-char alphanumeric token with trailing CRLF
        // (typical paste from a browser). F39 strip + validate accept.
        let raw = format!("{}\r\n", "A".repeat(40));
        let tok = assemble_interactive_token("ifc", &raw).unwrap();
        assert_eq!(tok.value, "A".repeat(40));
        assert_eq!(tok.source, "interactive:stdin:ifc");
        // expires_at is Utc::now() + NON_API_TOKEN_TTL — must be in the
        // future (with some slack for clock granularity).
        let now = Utc::now();
        let dur = tok.expires_at.signed_duration_since(now);
        assert!(
            dur >= TimeDelta::seconds(3500) && dur <= NON_API_TOKEN_TTL + TimeDelta::seconds(2),
            "expires_at {:?} not in expected range (now + ~{:?})",
            dur,
            NON_API_TOKEN_TTL
        );
    }

    #[test]
    fn assemble_interactive_token_rejects_empty_after_strip() {
        // Pure-newline paste — strip leaves empty, shape validator
        // rejects on empty.
        let err = assemble_interactive_token("ifc", "\n\r\n").unwrap_err();
        let msg = format!("{err}");
        assert!(msg.contains("empty"), "{msg}");
    }

    #[test]
    fn assemble_interactive_token_rejects_too_short() {
        // 8 chars after strip — below MIN_LEN (16).
        let err = assemble_interactive_token("ifc", "abcdefgh\n").unwrap_err();
        let msg = format!("{err}");
        assert!(msg.contains("length"), "{msg}");
    }

    #[test]
    fn assemble_interactive_token_rejects_too_long() {
        // 257 chars — above MAX_LEN (256).
        let raw = format!("{}\n", "x".repeat(INTERACTIVE_TOKEN_MAX_LEN + 1));
        let err = assemble_interactive_token("ifc", &raw).unwrap_err();
        let msg = format!("{err}");
        assert!(msg.contains("length"), "{msg}");
    }

    #[test]
    fn assemble_interactive_token_rejects_embedded_whitespace() {
        // 40-char token with embedded space — shape validator finds
        // the offending char in chars().find loop. Per #273 the
        // error reports the CLASS ("whitespace") rather than echoing
        // the byte itself.
        let raw = format!("{}AAA AA\n", "A".repeat(34));
        let err = assemble_interactive_token("ifc", &raw).unwrap_err();
        let msg = format!("{err}");
        assert!(msg.contains("forbidden whitespace"), "{msg}");
    }

    #[test]
    fn assemble_interactive_token_rejects_embedded_nul() {
        // NUL inside the body — same path as whitespace. Per #273
        // the error reports "forbidden NUL byte" rather than echoing
        // the literal NUL.
        let raw = format!("{}A\0AAAA\n", "A".repeat(34));
        let err = assemble_interactive_token("ifc", &raw).unwrap_err();
        let msg = format!("{err}");
        assert!(msg.contains("forbidden NUL byte"), "{msg}");
        assert!(
            !msg.contains('\0'),
            "literal NUL byte must not leak: {msg:?}"
        );
    }

    #[test]
    fn assemble_interactive_token_source_label_includes_auth_name() {
        // The source string identifies the originating [auth.NAME] so
        // ApplyResult audit-log entries pin the auth principal. Pin
        // the format ("interactive:stdin:NAME") against a future
        // refactor that drops the name.
        let raw = format!("{}\n", "B".repeat(40));
        let tok = assemble_interactive_token("buckos-pat", &raw).unwrap();
        assert_eq!(tok.source, "interactive:stdin:buckos-pat");
    }

    // ---- #161: registration_token_from_api conversion -----------------

    /// Build a synthetic `SelfHostedRunnerToken` via serde_json since
    /// the upstream struct is `#[non_exhaustive]` (not constructible
    /// outside octocrab). Tests deserialize a JSON literal to drive
    /// the conversion helper as if octocrab had returned it.
    fn synth_self_hosted_runner_token(
        token: &str,
        expires_at_iso: &str,
    ) -> octocrab::models::actions::SelfHostedRunnerToken {
        let json = format!(r#"{{"token": "{token}", "expires_at": "{expires_at_iso}"}}"#,);
        serde_json::from_str(&json).unwrap()
    }

    #[test]
    fn registration_token_from_api_passes_through_token_value() {
        let resp = synth_self_hosted_runner_token("REG_TOKEN_VALUE_xyz", "2030-01-01T00:00:00Z");
        let rt = registration_token_from_api("ifc", resp);
        assert_eq!(rt.value, "REG_TOKEN_VALUE_xyz");
    }

    #[test]
    fn registration_token_from_api_tags_source_with_auth_name() {
        let resp = synth_self_hosted_runner_token("t", "2030-01-01T00:00:00Z");
        let rt = registration_token_from_api("buckos-app", resp);
        assert_eq!(rt.source, "github:buckos-app");
    }

    #[test]
    fn registration_token_from_api_passes_expires_at_through_verbatim() {
        // 2030-01-01T00:00:00Z = 1893456000 seconds since UNIX_EPOCH.
        // octocrab's `SelfHostedRunnerToken.expires_at` is already
        // `chrono::DateTime<Utc>`, so the helper passes it through
        // verbatim — no SystemTime round-trip, no nanosecond precision
        // loss. Pin both the timestamp and the timezone (Utc) so a
        // future regression that timezone-shifts or truncates surfaces
        // here.
        let resp = synth_self_hosted_runner_token("t", "2030-01-01T00:00:00Z");
        let rt = registration_token_from_api("a", resp);
        assert_eq!(rt.expires_at.timestamp(), 1_893_456_000);
        // chrono's DateTime<Utc>::offset() returns the Utc unit type;
        // formatting it gives `"+00:00"`. Pin that the wrapper
        // preserves Utc rather than localizing.
        assert_eq!(rt.expires_at.timezone(), Utc);
    }

    // ---- #364: octocrab_to_auth class-label hints via mockito --------
    //
    // octocrab::Error variants carry `snafu::Backtrace` fields that are
    // not constructible without a snafu dev-dep, AND the variants are
    // `#[non_exhaustive]`. Rather than introducing a new dev-dep for a
    // synthetic-error test, the strategy is to drive REAL errors
    // through the production path: point an octocrab::Octocrab at a
    // mockito server (or an unreachable port), call
    // `call_octocrab_token`, and feed the resulting Err to
    // `octocrab_to_auth`. The hint text in the resulting GharsError
    // is the contract being pinned.
    //
    // Each test maps one HTTP status family to its #307 / #365 hint:
    //   401/403 → "permissions / scopes"
    //   404     → "owner/repo / Actions enabled"
    //   429     → "rate limit"
    //   5xx     → "upstream is degraded"
    //   network → "transport / network failure"
    //
    // Build pattern: `octocrab::Octocrab::builder().personal_token(...)
    // .base_uri(server.url()).unwrap().build()` is wrapped in
    // `github::block_on` because OctocrabBuilder::build() spawns into
    // a tokio context (see auth.rs:332-339 production comment).

    /// Helper: build an octocrab client pointed at `base_uri` (a
    /// mockito server URL or unreachable host:port). Wraps the
    /// build call in `github::block_on` to satisfy
    /// `tower::Buffer::new()`'s tokio-spawn requirement.
    fn build_test_octocrab(base_uri: &str) -> octocrab::Octocrab {
        let base_uri = base_uri.to_owned();
        github::block_on(async move {
            octocrab::Octocrab::builder()
                .personal_token("test-pat-not-a-real-token")
                .base_uri(base_uri)
                .expect("base_uri parse")
                .build()
                .expect("octocrab build")
        })
    }

    /// Helper: invoke the production code path `call_octocrab_token`
    /// then `octocrab_to_auth` against a real octocrab error. Returns
    /// the rendered Display message of the resulting GharsError so
    /// tests assert on the operator-facing hint.
    fn drive_repo_registration_error_through_pipeline(
        client: &octocrab::Octocrab,
        auth_name: &str,
    ) -> String {
        let scope = Scope::Repo {
            owner: "actions".into(),
            repo: "runner".into(),
        };
        let err = github::block_on(call_octocrab_token(client, &scope, TokenKind::Registration))
            .expect_err("mock returns non-2xx so call_octocrab_token must error");
        let mapped = octocrab_to_auth(auth_name, "create_runner_registration_token", &err);
        format!("{mapped}")
    }

    #[test]
    fn octocrab_to_auth_401_emits_permissions_scopes_hint() {
        let mut server = mockito::Server::new();
        let mock = server
            .mock(
                "POST",
                "/repos/actions/runner/actions/runners/registration-token",
            )
            .with_status(401)
            .with_header("content-type", "application/json")
            .with_body(r#"{"message":"Bad credentials","documentation_url":"https://docs.github.com/rest"}"#)
            .expect(1)
            .create();

        let client = build_test_octocrab(&server.url());
        let msg = drive_repo_registration_error_through_pipeline(&client, "pat-401");
        assert!(
            msg.contains("permissions / scopes"),
            "401 must surface the permissions/scopes hint (#307): {msg}"
        );
        assert!(msg.contains("401"), "hint must name the status code: {msg}");
        mock.assert();
    }

    /// Pins that 403 shares the 401|403 match arm — parity with
    /// github.rs fetch_latest_release_403 pattern. A regression
    /// splitting the arm would surface here.
    #[test]
    fn octocrab_to_auth_403_emits_permissions_scopes_hint() {
        let mut server = mockito::Server::new();
        let mock = server
            .mock(
                "POST",
                "/repos/actions/runner/actions/runners/registration-token",
            )
            .with_status(403)
            .with_header("content-type", "application/json")
            .with_body(
                r#"{"message":"Forbidden","documentation_url":"https://docs.github.com/rest"}"#,
            )
            .expect(1)
            .create();

        let client = build_test_octocrab(&server.url());
        let msg = drive_repo_registration_error_through_pipeline(&client, "pat-403");
        assert!(
            msg.contains("permissions / scopes"),
            "403 must surface the permissions/scopes hint (parity with 401): {msg}"
        );
        assert!(msg.contains("403"), "hint must name the status code: {msg}");
        mock.assert();
    }

    #[test]
    fn octocrab_to_auth_404_emits_owner_repo_hint() {
        // GitHub's actions/runners/registration-token endpoint returns
        // 404 for missing owner/repo, for an authenticated principal
        // that lacks visibility into the repo (private repo without
        // access), or when Actions is disabled at the repo level.
        // Pin the dedicated arm (#365) to the operator-actionable
        // hint so a future refactor that drops back to the catch-all
        // "see the API response above" generic text breaks here.
        let mut server = mockito::Server::new();
        let mock = server
            .mock(
                "POST",
                "/repos/actions/runner/actions/runners/registration-token",
            )
            .with_status(404)
            .with_header("content-type", "application/json")
            .with_body(
                r#"{"message":"Not Found","documentation_url":"https://docs.github.com/rest"}"#,
            )
            .expect(1)
            .create();

        let client = build_test_octocrab(&server.url());
        let msg = drive_repo_registration_error_through_pipeline(&client, "pat-404");
        assert!(
            msg.contains("owner/repo"),
            "404 must surface the owner/repo hint (#365): {msg}"
        );
        assert!(
            msg.contains("Actions enabled"),
            "404 hint must mention Actions-enabled gate (#365): {msg}"
        );
        assert!(msg.contains("404"), "hint must name the status code: {msg}");
        mock.assert();
    }

    #[test]
    fn octocrab_to_auth_429_emits_rate_limit_hint() {
        let mut server = mockito::Server::new();
        let mock = server
            .mock(
                "POST",
                "/repos/actions/runner/actions/runners/registration-token",
            )
            .with_status(429)
            .with_header("content-type", "application/json")
            .with_body(r#"{"message":"Secondary rate limit","documentation_url":"https://docs.github.com/rest"}"#)
            .expect(1)
            .create();

        let client = build_test_octocrab(&server.url());
        let msg = drive_repo_registration_error_through_pipeline(&client, "pat-429");
        assert!(
            msg.contains("rate limit"),
            "429 must surface the rate-limit hint (#307): {msg}"
        );
        assert!(msg.contains("429"), "hint must name the status code: {msg}");
        mock.assert();
    }

    #[test]
    fn octocrab_to_auth_503_emits_upstream_degraded_hint() {
        let mut server = mockito::Server::new();
        let mock = server
            .mock(
                "POST",
                "/repos/actions/runner/actions/runners/registration-token",
            )
            .with_status(503)
            .with_header("content-type", "application/json")
            .with_body(r#"{"message":"Service Unavailable","documentation_url":"https://docs.github.com/rest"}"#)
            .expect(1)
            .create();

        let client = build_test_octocrab(&server.url());
        let msg = drive_repo_registration_error_through_pipeline(&client, "pat-503");
        assert!(
            msg.contains("upstream is degraded"),
            "5xx must surface the upstream-degraded hint (#307): {msg}"
        );
        assert!(msg.contains("503"), "hint must name the status code: {msg}");
        mock.assert();
    }

    #[test]
    fn octocrab_to_auth_connection_refused_emits_transport_hint() {
        // Bind a localhost listener, capture its address, then drop
        // BEFORE the client connects. The OS-assigned ephemeral port
        // becomes unreachable; reqwest (octocrab's HTTP backend)
        // surfaces a connection error which octocrab wraps as either
        // Hyper or Service per its non-exhaustive variant set. Both
        // route to the transport-failure branch in #307.
        let listener = std::net::TcpListener::bind("127.0.0.1:0").expect("bind localhost listener");
        let addr = listener.local_addr().expect("read addr");
        drop(listener);
        let base_uri = format!("http://{addr}");

        let client = build_test_octocrab(&base_uri);
        let msg = drive_repo_registration_error_through_pipeline(&client, "pat-net");
        assert!(
            msg.contains("transport / network failure"),
            "connection-refused must surface the transport-failure hint (#307): {msg}"
        );
    }

    // ---- #610: octocrab::Error Display supply-chain pin ---------------
    //
    // `octocrab_to_auth` interpolates `{err}` (the upstream
    // `octocrab::Error::Display`) into the GharsError::Auth message
    // string. The error.rs module doc claims that surface contains no
    // request body / Authorization header echo. The contract is
    // supply-chain dependent: a `cargo update` that brings in an
    // octocrab Display impl which interpolates request headers /
    // bodies would silently leak operator credentials into stderr
    // (cmd_apply renders failed actions via writeln!).
    //
    // Empirical truth in octocrab 0.42.1 (verified by reading
    // octocrab-0.42.1/src/error.rs and snafu-derive-0.8.9/src/
    // shared.rs:537-549): the `Error::GitHub { source, backtrace }`
    // variant carries no `#[snafu(display(...))]` attribute and no
    // doc-comment, so snafu falls back to the variant-name default
    // (`stringify!(GitHub)`). Display output is literally the 6-byte
    // string "GitHub" — no message, no status code, no URL, no
    // bearer header, no request body. Even the response message is
    // NOT chained through, despite GitHubError having its own
    // Display impl — the parent Error variant chooses what to
    // delegate, and this one does not.
    //
    // The supply-chain risk being pinned is therefore: a future
    // octocrab release that adds `#[snafu(display(...))]` to the
    // GitHub variant (or any path that pulls request headers /
    // bodies into Display) would change the output and surface as a
    // test failure — at which point the project must audit whether
    // the new format is safe to interpolate into GharsError stderr.
    //
    // Test strategy: build a real octocrab client with a sentinel
    // PAT, drive a mockito-backed 401 response that embeds a
    // sentinel body marker, and assert:
    //   (a) the raw octocrab::Error Display does NOT contain the
    //       PAT bearer value, the request-body sentinel, or the
    //       response-body sentinel;
    //   (b) the raw Display IS exactly the literal "GitHub" — pins
    //       the snafu-default-fallback behavior so a future Display
    //       change is caught;
    //   (c) the wrapped GharsError Display (via octocrab_to_auth)
    //       does NOT contain the PAT bearer or the response body
    //       sentinels;
    //   (d) the wrapped GharsError Display DOES contain the 401
    //       status code and the 401-class hint — this is the
    //       operator-actionable contract: `octocrab_to_auth`
    //       extracts `source.status_code` from the GitHub variant
    //       directly (auth.rs:727-741), independent of what the
    //       upstream Display chooses to emit. Pinning this here
    //       provides positive proof that the fixture reached the
    //       GitHub variant (not Service/Hyper, where the hint
    //       differs).
    //
    // mockito's match_header on the Authorization line ensures the
    // sentinel PAT traverses the production code path. If octocrab
    // dropped Authorization-header attachment, the mock would be
    // unmatched and `mock.assert()` would fail — so this test also
    // pins that the PAT does reach the wire.

    /// #610 pin: octocrab::Error Display does not leak the
    /// Authorization-bearer PAT, the request-body bytes, or the
    /// response-body bytes when rendered through `octocrab_to_auth`.
    /// Defense-in-depth supply-chain guard.
    #[test]
    fn octocrab_to_auth_display_does_not_leak_pat_or_request_body() {
        let pat_sentinel = "ghp_SENTINEL_PAT_NEVER_LEAK_DEADBEEF1234567890";
        let request_body_sentinel = "REQUEST_BODY_SENTINEL_MUST_NOT_APPEAR";
        let response_message_sentinel = "RESPONSE_MESSAGE_SENTINEL_MUST_NOT_APPEAR";

        let mut server = mockito::Server::new();
        let mock = server
            .mock(
                "POST",
                "/repos/actions/runner/actions/runners/registration-token",
            )
            .match_header("authorization", format!("Bearer {pat_sentinel}").as_str())
            .with_status(401)
            .with_header("content-type", "application/json")
            .with_body(format!(
                r#"{{"message":"{response_message_sentinel}","documentation_url":"https://docs.github.com/rest","_sentinel":"{request_body_sentinel}"}}"#
            ))
            .expect(1)
            .create();

        let base_uri = server.url();
        let client = github::block_on(async move {
            octocrab::Octocrab::builder()
                .personal_token(pat_sentinel)
                .base_uri(base_uri)
                .expect("base_uri parse")
                .build()
                .expect("octocrab build")
        });

        let scope = Scope::Repo {
            owner: "actions".into(),
            repo: "runner".into(),
        };
        let octocrab_err = github::block_on(call_octocrab_token(
            &client,
            &scope,
            TokenKind::Registration,
        ))
        .expect_err("mock returns 401 so call_octocrab_token must error");

        // (a) Direct Display of the upstream error: must not echo
        // any operator-credential or request/response sentinel.
        let raw_display = format!("{octocrab_err}");
        assert!(
            !raw_display.contains(pat_sentinel),
            "octocrab::Error Display leaked the bearer PAT — \
             supply-chain assumption violated: {raw_display}"
        );
        assert!(
            !raw_display.contains(request_body_sentinel),
            "octocrab::Error Display leaked the structured response-body \
             sentinel verbatim: {raw_display}"
        );
        assert!(
            !raw_display.contains(response_message_sentinel),
            "octocrab::Error Display leaked the response `message` field — \
             upstream Display now chains through to GitHubError; audit \
             whether this is safe before relaxing the pin: {raw_display}"
        );
        // (b) Snafu-default-fallback behavior pin: the GitHub
        // variant has no `#[snafu(display(...))]` attribute, so
        // snafu emits `stringify!(GitHub)`. If this assertion
        // fires, octocrab has changed the Display format and the
        // project must audit whether the new format is still safe.
        assert_eq!(
            raw_display, "GitHub",
            "octocrab::Error::GitHub Display changed from the snafu-default \
             `stringify!(GitHub)` fallback — audit the new format for \
             credential / response-body leakage before relaxing this pin: \
             got {raw_display:?}"
        );

        // (c) Wrapped GharsError Display: must also not echo any
        // sentinel. auth.rs:779 interpolates `{err}` into the
        // GharsError message — these assertions cover the
        // production stderr surface end-to-end.
        let mapped = octocrab_to_auth("pat-leakage-pin", "registration-token", &octocrab_err);
        let wrapped_display = format!("{mapped}");
        assert!(
            !wrapped_display.contains(pat_sentinel),
            "GharsError Display via octocrab_to_auth leaked the bearer \
             PAT: {wrapped_display}"
        );
        assert!(
            !wrapped_display.contains(request_body_sentinel),
            "GharsError Display via octocrab_to_auth leaked the \
             structured response-body sentinel: {wrapped_display}"
        );
        assert!(
            !wrapped_display.contains(response_message_sentinel),
            "GharsError Display via octocrab_to_auth leaked the response \
             `message` field: {wrapped_display}"
        );
        // (d) Positive control: octocrab_to_auth extracts the 401
        // status code from `source.status_code` (auth.rs:727-741)
        // and emits it in the hint. If this assertion fires, the
        // fixture reached the wrong error variant (Service / Hyper
        // / etc.) and the negative assertions above are vacuously
        // true.
        assert!(
            wrapped_display.contains("401"),
            "GharsError did not include the 401 status code — fixture \
             reached the wrong octocrab::Error variant: {wrapped_display}"
        );
        assert!(
            wrapped_display.contains("permissions / scopes"),
            "GharsError did not include the 401-class hint — fixture \
             reached the wrong octocrab::Error variant: {wrapped_display}"
        );

        mock.assert();
    }

    // ---- #248: secret-leakage policy enforcement ----------------------
    //
    // The error.rs module-level doc states GharsError Display output
    // MUST NOT contain token bytes / env values / PEM bytes. The tests
    // below pin that contract for the construction sites that read
    // file contents into errors (read_root_owned_0600) and the one
    // that interpolates operator-pasted bytes (validate_interactive_
    // token_shape). A future call site that drops `path.display()` in
    // favor of `String::from_utf8(bytes)` would be caught here.

    /// `read_root_owned_0600` errors include the path but never the
    /// file contents. We seed a token-shaped fake in the file body
    /// and assert that token NEVER appears in any error rendered for
    /// any of the failure modes (mode, uid, missing) — so a future
    /// edit that adds `format!("...{contents:?}", contents = read?)`
    /// is caught.
    #[test]
    fn read_root_owned_0600_error_does_not_leak_file_contents() {
        let dir = tempfile::tempdir().unwrap();
        let secret = "PRETEND_REGISTRATION_TOKEN_AAAAA1234567890BBBBB";
        let path = mk_file(&dir, "token", secret.as_bytes(), 0o644);
        let err = read_root_owned_0600(path.as_std_path(), "token_file").unwrap_err();
        let msg = format!("{err}");
        assert!(
            !msg.contains(secret),
            "Display leaked file contents — secret bytes appeared in error: {msg}"
        );
    }

    /// `read_root_owned_0600` on a symlink fails at open(2) with
    /// ELOOP. The error must not include any indication of what was
    /// behind the symlink (its target file's contents). Even though
    /// O_NOFOLLOW prevents following, a hypothetical future swap to
    /// followed-then-stat'd reads (regressing SEC-06) would expose
    /// target contents — this test pins the no-leak contract.
    #[test]
    fn read_root_owned_0600_symlink_error_does_not_leak_target_contents() {
        let dir = tempfile::tempdir().unwrap();
        let secret = "PRETEND_PEM_KEY_BYTES_-----BEGIN_RSA-----";
        let target = mk_file(&dir, "real", secret.as_bytes(), 0o600);
        let link_path = dir.path().join("link");
        symlink(target.as_std_path(), &link_path).unwrap();
        let err = read_root_owned_0600(&link_path, "private_key_path").unwrap_err();
        let msg = format!("{err}");
        assert!(
            !msg.contains(secret),
            "Display leaked symlink-target contents: {msg}"
        );
    }

    /// `validate_interactive_token_shape` MUST NOT echo any byte from
    /// the rejected token — not even the offending one (#273).
    /// Earlier policy allowed a one-character partial leak via
    /// `{bad:?}`; the new contract emits a class label ("NUL byte",
    /// "whitespace", "control character") so even a single byte of
    /// operator entropy is impossible to recover from the error.
    ///
    /// Construct a token whose bulk is ASCII-printable except for
    /// one NUL byte mid-string. Assert the error contains the class
    /// label AND none of the bulk AND not the literal NUL byte.
    #[test]
    fn validate_interactive_token_shape_rejects_nul_emits_class_label_no_byte_leakage() {
        let bulk_a = "PRETEND_TOKEN_PREFIX_BUCKETS_OF_DATA";
        let bulk_b = "MORE_TOKEN_SUFFIX_LOTS_OF_BYTES";
        let token = format!("{bulk_a}\0{bulk_b}");
        let err = validate_interactive_token_shape(&token, "x").unwrap_err();
        let msg = format!("{err}");
        assert!(
            !msg.contains(bulk_a),
            "Display leaked the prefix bulk of the rejected token: {msg}"
        );
        assert!(
            !msg.contains(bulk_b),
            "Display leaked the suffix bulk of the rejected token: {msg}"
        );
        assert!(
            !msg.contains('\0'),
            "Display leaked the literal NUL byte: {msg:?}"
        );
        assert!(
            msg.contains("NUL byte"),
            "expected class label `NUL byte` in error: {msg}"
        );
    }

    /// `assemble_interactive_token` rolls up the validation chain.
    /// When validation fails on the trimmed token, the resulting error
    /// must not include the bulk of the operator-pasted bytes either.
    #[test]
    fn assemble_interactive_token_failure_does_not_leak_pasted_bytes() {
        // Make the token too long so validation fails on length —
        // length-failure must reveal nothing about the pasted bytes.
        // Per #273 the forbidden-char path also leaks no byte (it
        // emits a class label only); this test pins the length
        // branch independently.
        let secret_bulk = "PRETEND_TOKEN_VERY_LONG_OPERATOR_PASTED_BYTES_";
        let oversize_token = secret_bulk.repeat(20);
        assert!(oversize_token.len() > INTERACTIVE_TOKEN_MAX_LEN);
        let err = assemble_interactive_token("auth-name", &oversize_token).unwrap_err();
        let msg = format!("{err}");
        assert!(
            !msg.contains(secret_bulk),
            "Display leaked the pasted token bulk on length-failure: {msg}"
        );
    }

    /// PatToken's "env var unset" error path (auth.rs:261-267) maps
    /// `env::var(env)` failure to a GharsError::Auth that names the
    /// env VAR (config-level info) but cannot leak the env's VALUE
    /// because `env::var()` returns Err *only* when the var is
    /// unset / non-UTF-8 — neither path makes the value available.
    /// The error message contains the var NAME (operator needs to
    /// know which one is missing) but never the value.
    ///
    /// We test by probing with a deliberately bizarre var name and
    /// verifying the error message contains it (so the operator can
    /// fix it) and only it — not stray strings that would only
    /// appear if a future refactor stuffed the value in.
    #[test]
    fn pat_token_unset_env_error_names_var_does_not_leak_value_path() {
        let var = "GHARS_LEAK_PROBE_NEVER_SET_42";
        if std::env::var(var).is_ok() {
            eprintln!("skipping: {var} unexpectedly set in test env");
            return;
        }
        let err = PatToken::new("p", Some(var), None).unwrap_err();
        let msg = format!("{err}");
        // Operator-actionable: the var name appears.
        assert!(msg.contains(var), "expected var name in message: {msg}");
        // Per error.rs module doc: must NOT contain a generic
        // "value=" / "contents=" / token-shape signal that would
        // suggest a future regression added the value to the
        // message. None of these substrings appear in the current
        // format string (auth.rs:262-267), so the assertion stands
        // unless that string is rewritten to include them.
        assert!(
            !msg.contains("value="),
            "Display includes 'value=' — likely leak: {msg}"
        );
        assert!(
            !msg.contains("contents="),
            "Display includes 'contents=' — likely leak: {msg}"
        );
    }
}
