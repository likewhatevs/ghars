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
//! `create_*_runner_remove_token` inside `block_on`
//! (Part 6 enforcement rule item 3).
//! `InteractiveToken` prompts the operator to paste a pre-minted token;
//! `TokenFileToken` reads one from disk.
//!
//! ## Retry policy
//!
//! No in-process retry. The 429 hint surfaced by `octocrab_to_auth`
//! asks the operator to re-run `ghars apply` once the rate-limit
//! window passes. Auto-retry without `Retry-After` parsing would
//! deepen the rate-limit window and waste ghars's per-IP quota;
//! octocrab 0.42's retry path doesn't parse `Retry-After` so we
//! don't enable it.
//!
//! ## Residual exposure
//!
//! Asymmetric with `github.rs::http_get_payload`'s
//! `MAX_RELEASES_BODY_BYTES` cap: the octocrab path through which
//! `GithubAppToken` and `PatToken` mint registration tokens has NO
//! body-size cap. octocrab's blanket `FromResponse` impl collects
//! the entire response body before passing it to `serde_json` —
//! no `take()` / `Content-Length` pre-check. Threat model: a hostile
//! origin (compromised mirror, MITM proxy) replying with a multi-
//! gigabyte body is collected unbounded. Realistic surface is small
//! (registration-token endpoint normally returns ~200 bytes), but
//! the structural absence of a cap means ghars trusts the upstream.
//! Closing this requires injecting a custom `tower::Layer` between
//! octocrab's service stack and hyper.

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
/// # Memory hygiene
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
/// like `github:NAME` and `expires_at` is a UTC instant); they are
/// `#[zeroize(skip)]` so derive does not require a `Zeroize` impl on
/// `chrono::DateTime<Utc>`.
///
/// `Clone` is intentionally NOT derived: zeroize-on-drop hardens one
/// end of the token's lifetime, but `.clone()` would silently widen
/// the attack surface by spawning unscrubbed copies in caller frames.
/// No production caller clones a `RegistrationToken` today (verified via grep);
/// test fixtures that need duplicates construct them via
/// `RegistrationToken { ... }` literals so the typing surface stays
/// consistent with the production "consume by reference" pattern at
/// `apply::execute_remove_runner` (passing `&token.value` into
/// `ConfigShellCtx`).
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
    /// `chrono::DateTime<Utc>`, so no `SystemTime` round-trip risks
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

// Pin the zeroize-on-drop wiring at compile time. If a future
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
/// JWT minting (RS256, 9m lifetime per `octocrab::auth::create_jwt`)
/// and exchanges it for an installation token internally, caching
/// the installation token in-memory until expiry.
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
/// (`token_env` xor `token_file`) at construction time.
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
                // mutator when the check passes). Returning `None` means
                // the operation was skipped because we could not prove
                // single-thread safety; we warn rather than fail
                // because the token
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
    #[must_use]
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

/// Convert a raw operator-pasted token into a [`RegistrationToken`].
/// Pure logic split out from `InteractiveToken::prompt`
/// so tests can drive every code path without an attached TTY:
///   1. Trailing CR/LF strip — `trim_end_matches(['\r', '\n'])`,
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
    // Emit a CLASS label rather than echoing the offending char
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
/// the GitHub App private key). Trailing CR/LF stripped via
/// `s.trim_end_matches(['\r', '\n'])`, NEVER `.trim()`.
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
/// a ghars [`RegistrationToken`]. Pure logic split out
/// from `GithubAppToken::mint` and `PatToken::mint` so tests can drive
/// the conversion with synthetic responses without an octocrab client
/// or live network.
///
/// `expires_at` passes through verbatim — octocrab's
/// `SelfHostedRunnerToken.expires_at` is already
/// `chrono::DateTime<Utc>`, and ghars stores the same type, so no
/// conversion is needed. `source` is the per-runner `"github:NAME"`
/// tag used by `ApplyResult` to attribute audit-log entries to the
/// auth principal.
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
    // Pick the actionable hint by error class so the operator sees
    // the right diagnosis — octocrab::Error is `#[non_exhaustive]`,
    // so the catch-all keeps the build healthy across upstream
    // variant additions. The individual arms below speak for
    // themselves.
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

/// Strip ONLY trailing `\r` / `\n`. Operator content (including
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
    // Reject the setuid (0o4000), setgid (0o2000), and sticky
    // (0o1000) bits on credential files. None are needed for
    // credential storage — ghars reads the file as root via this
    // helper; setuid/setgid/sticky on a regular credential file is
    // either operator confusion or a hostile setup. setuid/setgid
    // on a regular file does nothing without exec permission, but
    // pinning them off keeps the filesystem state unambiguous.
    if mode & 0o7000 != 0 {
        return Err(GharsError::Auth(
            format!(
                "{field_label} {:?}: mode {:o} has setuid/setgid/sticky bits set; \
                 credential files must be plain regular-file perms",
                path.display(),
                mode
            ),
            "chmod 600 the file (drop the special bits): `sudo chmod 0600 <path>`".into(),
        ));
    }
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

/// Resolve a PAT value from an [`AuthSpec`] for API use (releases,
/// runner-list, registration-check). Returns `None` when the spec is
/// not a PAT, the env var is unset/empty, or the file is unreadable.
///
/// Mirrors `PatToken::new`'s read path: the env var is read directly
/// (no scrubbing — this is an API-side helper, not the per-runner
/// constructor); the file path goes through `read_root_owned_0600` so
/// SEC-25 (root-owned + 0o600 + `O_NOFOLLOW`) is enforced consistently
/// across mint-and-discard sites.
///
/// File-read failures are logged via `tracing::warn!` before falling
/// through to `None`. Without the warn the caller's API call silently
/// degrades from authenticated (5000 req/hr) to unauthenticated
/// (60 req/hr), masking SEC-25 mode/owner mismatches that the operator
/// needs to see.
#[must_use]
pub fn resolve_pat_for_api(spec: &AuthSpec) -> Option<String> {
    let AuthSpec::Pat {
        token_env,
        token_file,
    } = spec
    else {
        return None;
    };
    if let Some(env_var) = token_env
        && let Ok(val) = std::env::var(env_var)
        && !val.is_empty()
    {
        return Some(val);
    }
    if let Some(path) = token_file {
        match read_root_owned_0600(path.as_std_path(), "token_file") {
            Ok(bytes) => match String::from_utf8(bytes) {
                Ok(s) => {
                    let trimmed = strip_trailing_newlines(&s);
                    if !trimmed.is_empty() {
                        return Some(trimmed);
                    }
                    tracing::warn!(path = %path, "token_file is empty after trim");
                }
                Err(e) => {
                    tracing::warn!(path = %path, error = %e, "token_file is not valid UTF-8");
                }
            },
            Err(e) => {
                tracing::warn!(
                    path = %path,
                    error = %e,
                    "token_file unreadable (SEC-25 mode/owner check); API call will be unauthenticated"
                );
            }
        }
    }
    None
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used)]
#[path = "auth_tests.rs"]
mod tests;
