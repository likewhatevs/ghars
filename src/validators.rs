//! Pure validators for individual fields: identifier regex, GitHub URL
//! shape, sha256 64-hex, runner version `X.Y.Z`, label charset, memory
//! grammar, CIDR.
//!
//! Behavior ported field-for-field from the legacy Python install
//! tool. Every regex and rejection case is preserved verbatim so the
//! v0.1 parity tests reuse the Python suite directly.

// Module-local regexes are compile-time-constant patterns. `Regex::new`
// here is unfallible by inspection; using `expect` makes the panic site
// concrete if a future edit breaks a pattern.
#![allow(clippy::expect_used)]

use std::fs::{File, Metadata, OpenOptions};
use std::os::unix::fs::{MetadataExt, OpenOptionsExt};
use std::path::Path;
use std::str::FromStr;
use std::sync::LazyLock;

use camino::Utf8Path;
use ipnet::IpNet;
use regex::Regex;

use crate::config::{IDENTIFIER_MAX_LEN, IDENTIFIER_REGEX};
use crate::{GharsError, Result};

/// Maximum length of the shared identifier (re-exported for symmetry).
pub const NAME_MAX_LEN: usize = IDENTIFIER_MAX_LEN;

/// Maximum length of a Linux user name accepted by `validate_user`.
///
/// systemd's strict-mode `valid_user_group_name` (src/basic/user-util.c:824)
/// caps user names at `SYSTEMD_GROUP_NAME_MAX` chars (= utmpx ut_user
/// length minus the NUL terminator). The unit-template runner uses
/// User=, which goes through that strict check, so the cap here
/// matches the same limit applied to group names.
pub const USER_MAX_LEN: usize = SYSTEMD_GROUP_NAME_MAX;

/// systemd strict-mode `valid_user_group_name` caps user and group
/// names at `sizeof_field(struct utmpx, ut_user) - 1 = 31` chars.
/// Verified at systemd src/basic/user-util.c:824 and glibc
/// bits/utmpx.h:36 (`__UT_NAMESIZE = 32`, includes NUL terminator).
/// Both [`USER_MAX_LEN`] and the cache-pool / runner-name caps derive
/// from this single source.
pub(crate) const SYSTEMD_GROUP_NAME_MAX: usize = 31;

/// Prefix `apply::cache_pool_group` prepends to a pool name to form
/// the per-pool group name (consumed by the gpasswd / groupadd /
/// groupdel call sites in apply.rs). Centralized so
/// `CACHE_POOL_NAME_MAX_LEN` derives from `prefix.len()` instead of a
/// hand-counted constant — a future rename of the prefix automatically
/// adjusts the pool-name cap. systemd's per-pool drop-in does not use
/// this prefix: the cache server's `User=` is set to
/// `ghars-tz-<TRUST_ZONE>` (sibling DynamicUser of the runners in the
/// same trust_zone), and the pool-group machinery survives only as a
/// transitional surface that the DynamicUser pivot removes wholesale.
pub(crate) const CACHE_GROUP_PREFIX: &str = "ghars-cache-";

/// Prefix `plan::merge_defaults` prepends to runner.name to form the
/// per-runner system user. Centralized so `RUNNER_NAME_MAX_LEN` derives
/// from `prefix.len()` instead of a hand-counted constant.
pub(crate) const RUNNER_USER_PREFIX: &str = "ghars-";

/// Maximum length of a `[cache_pools.NAME]` key.
///
/// `apply::cache_pool_group` produces the per-pool group as
/// `"{CACHE_GROUP_PREFIX}{name}"`. systemd's strict-mode
/// `valid_user_group_name` rejects group names longer than
/// [`SYSTEMD_GROUP_NAME_MAX`] chars, so the largest pool name that
/// yields a valid group is `SYSTEMD_GROUP_NAME_MAX -
/// CACHE_GROUP_PREFIX.len()`. The fuzz invariant in
/// `apply::cache_pool_group_props` already pins the 31-char ceiling on
/// the OUTPUT; this cap pushes the gate UPSTREAM to config-load so the
/// operator gets a scoped error (`cache_pool "NAME": ...`) instead of an
/// opaque `groupadd: name too long` failure during `apply`.
pub const CACHE_POOL_NAME_MAX_LEN: usize = SYSTEMD_GROUP_NAME_MAX - CACHE_GROUP_PREFIX.len();

/// Maximum length of a `[[runner]] name`.
///
/// `plan::merge_defaults` produces the per-runner user as
/// `"{RUNNER_USER_PREFIX}{name}"`. systemd's strict-mode
/// `valid_user_group_name` rejects names longer than
/// [`SYSTEMD_GROUP_NAME_MAX`] chars, so the largest runner name that
/// yields a valid user is `SYSTEMD_GROUP_NAME_MAX -
/// RUNNER_USER_PREFIX.len()`. Netns-mode runners face a tighter cap
/// [`NETNS_RUNNER_NAME_MAX_LEN`] enforced by
/// `cli::validate_netns_runner_name_lengths`.
pub const RUNNER_NAME_MAX_LEN: usize = SYSTEMD_GROUP_NAME_MAX - RUNNER_USER_PREFIX.len();

// Compile-time underflow guard: if a future edit ever made
// `CACHE_GROUP_PREFIX.len() >= SYSTEMD_GROUP_NAME_MAX`, the const
// subtraction above would panic at compile time on usize underflow,
// but the panic message would be opaque ("attempt to subtract with
// overflow"). This explicit `assert!` surfaces the invariant by name so
// the compile error names the offending invariant directly.
const _: () = assert!(SYSTEMD_GROUP_NAME_MAX > CACHE_GROUP_PREFIX.len());

// Compile-time underflow guard for the runner-user derivation,
// symmetric to the cache-pool guard above.
const _: () = assert!(SYSTEMD_GROUP_NAME_MAX > RUNNER_USER_PREFIX.len());

/// Linux interface-name buffer size from `<linux/if.h>`. The kernel
/// stores network device names in a fixed-width array of this size,
/// where the last byte is reserved for the trailing NUL — so a NAME's
/// usable byte length is `IFNAMSIZ - 1` (15 chars). `dev_valid_name`
/// in `net/core/dev.c` enforces this on every netlink RTM_NEWLINK.
/// ghars's per-runner veth interface naming inherits this hard cap.
pub const IFNAMSIZ: usize = 16;

/// Suffix `netns::host_veth_name` / `netns::runner_veth_name` append
/// to disambiguate the host vs runner end of the per-runner veth
/// pair. Both ends share the same byte length, so the rendered cap
/// derivation is symmetric.
pub(crate) const VETH_SIDE_SUFFIX: &str = "-h";

/// Bytes consumed by the prefix + suffix in the rendered veth name
/// shape `"{RUNNER_USER_PREFIX}{instance}{VETH_SIDE_SUFFIX}"` (host
/// side; runner side has the same length). Used to derive the largest
/// acceptable runner name in netns mode.
///
/// Derived from [`RUNNER_USER_PREFIX`] + [`VETH_SIDE_SUFFIX`] (rather
/// than hand-counting the two literal segments) so a future rename
/// of either bookend automatically adjusts the cap.
pub const VETH_NAME_OVERHEAD: usize = RUNNER_USER_PREFIX.len() + VETH_SIDE_SUFFIX.len();

/// Largest runner name (or count-block prefix + numeric suffix) whose
/// rendered veth interface name `"ghars-{name}-h"` still fits the
/// kernel's `IFNAMSIZ - 1 = 15` limit when running in netns mode.
///
/// Concretely: `15 - 8 = 7` chars. ghars only enforces this cap on
/// runners whose effective network mode resolves to `Netns` —
/// see `cli::validate_netns_runner_name_lengths`. Open-mode runners
/// inherit only the global `RUNNER_NAME_MAX_LEN` cap (derived from
/// systemd's strict-mode user-name limit).
pub const NETNS_RUNNER_NAME_MAX_LEN: usize = IFNAMSIZ - 1 - VETH_NAME_OVERHEAD;

// Compile-time underflow guard for the netns runner-name derivation,
// symmetric to the cache-pool / runner-user guards above. If a future
// edit ever made `VETH_NAME_OVERHEAD + 1 >= IFNAMSIZ`, the const
// subtraction above would underflow at compile time; the explicit
// assert names the invariant ("the rendered veth name shape requires
// at least one operator-controlled char to remain after the prefix +
// suffix").
const _: () = assert!(IFNAMSIZ > VETH_NAME_OVERHEAD + 1);

/// Reserved top-level filesystem paths that `--prefix` MUST NOT equal.
///
/// Mirrors the legacy Python install tool's reserved-path check.
/// `/` and one-segment directories under it like `/etc`, `/var`,
/// `/usr`. Refuses both because writing runner state into these
/// would clobber the host.
const TOP_LEVEL_RESERVED: &[&str] = &[
    "/", "/bin", "/sbin", "/boot", "/dev", "/etc", "/home", "/lib", "/lib32", "/lib64", "/proc",
    "/root", "/run", "/srv", "/sys", "/tmp", "/usr", "/var",
];

static IDENTIFIER_RE: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(IDENTIFIER_REGEX).expect("IDENTIFIER_REGEX is a compile-time constant")
});

static USER_RE: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r"^[a-z_][a-z0-9_-]{0,30}$").expect("USER_REGEX is a compile-time constant")
});

static PREFIX_RE: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r"^/[A-Za-z0-9/_.-]+$").expect("PREFIX_REGEX is a compile-time constant")
});

static VERSION_RE: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r"^[0-9]+\.[0-9]+\.[0-9]+$").expect("VERSION_REGEX is a compile-time constant")
});

static SHA256_RE: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r"^[0-9a-fA-F]{64}$").expect("SHA256_REGEX is a compile-time constant")
});

static LABEL_RE: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r"^[a-zA-Z0-9._-]+$").expect("LABEL_REGEX is a compile-time constant")
});

static MEMORY_MAX_RE: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r"^[0-9]+[KMGT]?$").expect("MEMORY_MAX_REGEX is a compile-time constant")
});

static MEMORY_MAX_PCT_RE: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r"^[0-9]+%$").expect("MEMORY_MAX_PCT_REGEX is a compile-time constant")
});

// GitHub repo URL. Form: https://github.com/OWNER[/REPO][.git][/].
// OWNER and REPO segments match GitHub's own rules: start with an
// alphanumeric, continue with alphanumerics, dots, hyphens, or
// underscores. Anchored on both ends so `is_match` enforces the same
// fullmatch semantics as Python's `URL_REGEX.fullmatch`.
static URL_RE: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(
        r"^https://github\.com/[A-Za-z0-9][A-Za-z0-9._-]*(?:/[A-Za-z0-9][A-Za-z0-9._-]*)?(?:\.git)?/?$",
    )
    .expect("URL_REGEX is a compile-time constant")
});

fn validation(msg: impl Into<String>, hint: impl Into<String>) -> GharsError {
    GharsError::Validation(msg.into(), hint.into())
}

/// Validate a shared identifier (runner name, auth key, cache pool key,
/// network key): `^[a-z]([a-z0-9-]*[a-z0-9])?$`, 1..=`IDENTIFIER_MAX_LEN`.
///
/// # Errors
///
/// Returns `GharsError::Validation` when `s` is empty, exceeds the
/// length cap, or doesn't match the identifier shape.
pub fn validate_identifier(s: &str) -> Result<()> {
    if s.is_empty() {
        return Err(validation(
            "identifier is required",
            "provide a non-empty key",
        ));
    }
    if s.len() > IDENTIFIER_MAX_LEN {
        return Err(validation(
            format!("identifier too long: {} > {IDENTIFIER_MAX_LEN}", s.len()),
            format!("shorten the identifier to ≤{IDENTIFIER_MAX_LEN} characters"),
        ));
    }
    if !IDENTIFIER_RE.is_match(s) {
        return Err(validation(
            format!("identifier invalid: {s:?} must match {IDENTIFIER_REGEX}"),
            "use lowercase letters, digits, and dashes; start with a letter, end with a letter or digit",
        ));
    }
    Ok(())
}

/// Validate a runner name.
///
/// Runs `validate_identifier` first (charset + identifier-shape +
/// `IDENTIFIER_MAX_LEN` cap), then enforces the tighter
/// `RUNNER_NAME_MAX_LEN` cap so the derived per-runner user name
/// `"{RUNNER_USER_PREFIX}{name}"` (produced by `plan::merge_defaults`)
/// fits inside systemd's `SYSTEMD_GROUP_NAME_MAX`-char name limit. The
/// same length-cap pattern as `validate_cache_pool_name`.
///
/// # Errors
///
/// `GharsError::Validation` for any identifier-shape failure, or when
/// `name.len() > RUNNER_NAME_MAX_LEN`.
pub fn validate_runner_name(name: &str) -> Result<()> {
    validate_identifier(name)?;
    if name.len() > RUNNER_NAME_MAX_LEN {
        return Err(validation(
            format!(
                "runner name too long: {} > {RUNNER_NAME_MAX_LEN} \
                 (derived user \"{RUNNER_USER_PREFIX}{name}\" would exceed \
                 systemd's {SYSTEMD_GROUP_NAME_MAX}-char name limit)",
                name.len(),
            ),
            format!("shorten the [[runner]] name to ≤{RUNNER_NAME_MAX_LEN} characters"),
        ));
    }
    Ok(())
}

/// Validate a `[cache_pools.NAME]` key.
///
/// Runs `validate_identifier` first (charset + identifier-shape +
/// `IDENTIFIER_MAX_LEN` cap), then enforces the tighter
/// `CACHE_POOL_NAME_MAX_LEN` cap so the derived group name
/// `"{CACHE_GROUP_PREFIX}{name}"` fits inside systemd's
/// `SYSTEMD_GROUP_NAME_MAX`-char group-name limit
/// (`apply::cache_pool_group`).
///
/// # Errors
///
/// `GharsError::Validation` for any identifier-shape failure, or when
/// `name.len() > CACHE_POOL_NAME_MAX_LEN`.
pub fn validate_cache_pool_name(name: &str) -> Result<()> {
    validate_identifier(name)?;
    if name.len() > CACHE_POOL_NAME_MAX_LEN {
        return Err(validation(
            format!(
                "cache pool name too long: {} > {CACHE_POOL_NAME_MAX_LEN} \
                 (derived group \"{CACHE_GROUP_PREFIX}{name}\" would exceed \
                 systemd's {SYSTEMD_GROUP_NAME_MAX}-char group-name limit)",
                name.len(),
            ),
            format!(
                "shorten the cache pool name to ≤{CACHE_POOL_NAME_MAX_LEN} characters \
                 (applies to both [cache_pools.NAME] keys and [[runner]].caches references)"
            ),
        ));
    }
    Ok(())
}

/// Validate a GitHub repo or org URL.
///
/// Accepts `https://github.com/OWNER[/REPO][.git][/]`. Rejects non-https
/// schemes, userinfo, host suffixes, path traversal, query/fragment, and
/// anything beyond the optional `/REPO[.git]` segment.
///
/// # Errors
///
/// Returns `GharsError::Validation` for empty input or any pattern
/// mismatch. Matches the legacy Python install tool's URL validator.
pub fn validate_url(u: &str) -> Result<()> {
    if u.is_empty() {
        return Err(validation(
            "url is required",
            "set the url field to https://github.com/OWNER[/REPO] in your ghars.toml",
        ));
    }
    if !URL_RE.is_match(u) {
        return Err(validation(
            format!("url must be of the form https://github.com/OWNER[/REPO] (got: {u})"),
            "non-https schemes, userinfo, query/fragment, and traversal segments are rejected",
        ));
    }
    Ok(())
}

/// Validate a prefix path (`--prefix`).
///
/// Rejects empty input, non-allowed characters, `..` segments, top-level
/// reserved directories (`/`, `/etc`, `/var`, ...), and symlinks. The
/// symlink check is `lstat`-based — symlink-to-regular does not pass.
///
/// # Errors
///
/// Returns `GharsError::Validation` for any of the above conditions.
/// Matches the legacy Python install tool's prefix validator.
pub fn validate_prefix(p: &str) -> Result<()> {
    if p.is_empty() {
        return Err(validation(
            "prefix is empty",
            "set the prefix field to an absolute path like \"/opt/gha\" in your ghars.toml",
        ));
    }
    if !PREFIX_RE.is_match(p) {
        return Err(validation(
            format!(
                "prefix contains disallowed characters; must match {} (got: {p})",
                PREFIX_RE.as_str()
            ),
            "only A-Z, a-z, 0-9, '/', '_', '.', '-' are allowed",
        ));
    }
    if p.contains("..") {
        return Err(validation(
            format!("prefix must not contain '..': {p}"),
            "use an absolute path with no traversal segments",
        ));
    }
    if TOP_LEVEL_RESERVED.contains(&p) {
        return Err(validation(
            format!("prefix refuses top-level directory: {p}"),
            "use a dedicated path under /opt, /srv, or /var/lib",
        ));
    }
    // `symlink_metadata` is lstat — it does NOT follow the link, so a
    // symlink-to-regular-dir is detected here rather than silently passing.
    if let Ok(stat) = std::fs::symlink_metadata(p) {
        if stat.file_type().is_symlink() {
            return Err(validation(
                format!("prefix is a symlink; resolve and pass the real path: {p}"),
                "run `readlink -f` and pass the resolved path",
            ));
        }
    }
    Ok(())
}

/// Validate a Linux user name (`--user`).
///
/// `^[a-z_][a-z0-9_-]{0,30}$` — first char must be lowercase letter or
/// underscore; trailing chars may include digits or dashes; max
/// [`USER_MAX_LEN`] (= [`SYSTEMD_GROUP_NAME_MAX`] = 31) chars.
///
/// systemd's strict-mode `valid_user_group_name`
/// (src/basic/user-util.c:824) rejects user names longer than
/// [`SYSTEMD_GROUP_NAME_MAX`] chars; the runner template uses `User=`,
/// so a 32-char name accepted by the regex would be refused by systemd
/// at unit-load time with an opaque error. The explicit length gate
/// below mirrors the layered pattern in [`validate_runner_name`] /
/// [`validate_cache_pool_name`] so the operator sees a length-scoped
/// error before the regex check fires.
///
/// # Errors
///
/// Returns `GharsError::Validation` for empty input, length above
/// [`USER_MAX_LEN`], or pattern mismatch.
/// Matches the legacy Python install tool's user validator.
pub fn validate_user(u: &str) -> Result<()> {
    if u.is_empty() {
        return Err(validation(
            "user is empty",
            "set the user field to a lowercase identifier like \"gha\" in your ghars.toml",
        ));
    }
    if u.len() > USER_MAX_LEN {
        return Err(validation(
            format!(
                "user too long: {} > {USER_MAX_LEN} \
                 (systemd strict-mode `valid_user_group_name` caps user/group \
                 names at {SYSTEMD_GROUP_NAME_MAX} chars)",
                u.len(),
            ),
            format!("shorten the user name to ≤{USER_MAX_LEN} characters"),
        ));
    }
    if !USER_RE.is_match(u) {
        return Err(validation(
            format!("user invalid: {u:?} must match {}", USER_RE.as_str()),
            "Linux user names: lowercase or '_' first char, then 0-30 of [a-z0-9_-]",
        ));
    }
    Ok(())
}

/// Validate a `MemoryMax=` value.
///
/// Accepts: `<integer>[K|M|G|T]`, `<N>%` with 1..=100, or `infinity`.
/// An empty input is also accepted (defaults are not user error).
///
/// # Errors
///
/// Returns `GharsError::Validation` for any other shape or out-of-range
/// percent. Matches the legacy Python install tool's memory-max validator.
pub fn validate_memory_max(m: &str) -> Result<()> {
    if m.is_empty() {
        return Ok(());
    }
    if m == "infinity" {
        return Ok(());
    }
    if MEMORY_MAX_PCT_RE.is_match(m) {
        let pct_str = &m[..m.len() - 1];
        let pct: u32 = pct_str.parse().map_err(|_| {
            validation(
                format!("memory-max percentage out of range: {m}"),
                "use an integer percent in 1..=100, e.g. 50%",
            )
        })?;
        if !(1..=100).contains(&pct) {
            return Err(validation(
                format!("memory-max percentage out of range: {m}"),
                "use an integer percent in 1..=100, e.g. 50%",
            ));
        }
        return Ok(());
    }
    if !MEMORY_MAX_RE.is_match(m) {
        return Err(validation(
            format!("memory-max invalid: {m:?} (expected <integer>[K|M|G|T], <N>%, or 'infinity')"),
            "examples: 110G, 4M, 512K, 50%, infinity",
        ));
    }
    Ok(())
}

/// Validate a comma-separated label list (`--labels`).
///
/// Empty CSV is accepted (no labels to add). Each non-empty segment must
/// match `^[a-zA-Z0-9._-]+$`. Empty segments (leading/trailing/adjacent
/// commas) are rejected.
///
/// # Errors
///
/// Returns `GharsError::Validation` for empty entries (leading,
/// trailing, or adjacent commas) or for any token that fails the
/// label charset.
pub fn validate_labels(csv: &str) -> Result<()> {
    if csv.is_empty() {
        return Ok(());
    }
    for part in csv.split(',') {
        if part.is_empty() {
            return Err(validation(
                format!("labels contains empty entry (trailing/adjacent commas): {csv}"),
                "remove duplicate commas; pass labels as comma-separated tokens",
            ));
        }
        if !LABEL_RE.is_match(part) {
            return Err(validation(
                format!("labels entry invalid: {part:?} (allowed: a-zA-Z0-9._-)"),
                "use only alphanumerics, '.', '_', or '-' in label tokens",
            ));
        }
    }
    Ok(())
}

/// Validate a sha256 digest (64 hex chars, case-insensitive).
///
/// # Errors
///
/// Returns `GharsError::Validation` if the input is not 64 hex digits.
pub fn validate_sha256(h: &str) -> Result<()> {
    if !SHA256_RE.is_match(h) {
        return Err(validation(
            format!("runner-sha256 must be 64 hex digits (got: {h})"),
            "paste the full sha256 from the GitHub release notes",
        ));
    }
    Ok(())
}

/// Validate a runner version of the shape `X.Y.Z`.
///
/// # Errors
///
/// Returns `GharsError::Validation` if the input does not match `X.Y.Z`.
pub fn validate_version(v: &str) -> Result<()> {
    if !VERSION_RE.is_match(v) {
        return Err(validation(
            format!("runner-version must be in X.Y.Z form (got: {v})"),
            "examples: 2.321.0, 1.0.0",
        ));
    }
    Ok(())
}

/// Validate a pre-existing runner tarball path.
///
/// The lstat check runs before `is_file` so symlink-to-regular does NOT
/// silently pass — the security review wants pinned local paths only.
///
/// Gates applied (in order):
/// 1. Path is absolute. Relative paths resolve against `process CWD`,
///    which varies between `ghars validate` (operator's shell), `ghars
///    apply` (root via sudo), and a future systemd-driven invocation
///    (no CWD guarantee). Pinning to absolute eliminates that footgun.
/// 2. Path exists.
/// 3. Path is not a symlink (lstat-style check before `is_file`).
/// 4. Path is a regular file.
/// 5. File begins with the gzip magic bytes `1f 8b`. Operators
///    occasionally point `--runner-tarball` at a freshly-downloaded
///    HTML error page, a JPEG, or a partial download. Catching it
///    here surfaces an actionable "not a gzip archive" error at
///    config-load time instead of an opaque `extract_tarball` failure
///    deep inside `apply` (after partial state mutations).
///
/// # Errors
///
/// Returns `GharsError::Validation` for any failed gate. Matches the
/// legacy Python install tool's tarball-path checks plus the
/// absolute-path and magic-byte gates ghars adds for stronger
/// config-load validation.
pub fn validate_runner_tarball(path: &str) -> Result<()> {
    let p = Path::new(path);
    if !p.is_absolute() {
        return Err(validation(
            format!("runner_tarball path must be absolute, got relative: {path}"),
            "relative paths resolve against process CWD which varies between \
             invocations (operator shell vs. root apply); use an absolute path",
        ));
    }
    if !p.exists() {
        return Err(validation(
            format!("runner-tarball file does not exist: {path}"),
            "download the tarball locally and pass the resolved path",
        ));
    }
    // lstat first: catch symlink-to-regular before is_file() sees through it.
    let lstat = std::fs::symlink_metadata(p).map_err(|e| {
        validation(
            format!("runner-tarball stat failed for {path}: {e}"),
            "verify file permissions and existence",
        )
    })?;
    if lstat.file_type().is_symlink() {
        return Err(validation(
            format!("runner-tarball must be a regular file, not a symlink: {path}"),
            "resolve the link and pass the real path",
        ));
    }
    if !p.is_file() {
        return Err(validation(
            format!("runner-tarball is not a regular file: {path}"),
            "point [[runner]].runner_tarball at a regular .tar.gz file",
        ));
    }
    // Read just enough bytes to confirm the gzip magic (RFC 1952 §2.3.1:
    // ID1 = 0x1f, ID2 = 0x8b). A 2-byte read can't miss the prefix; a
    // partial read (file < 2 bytes) is also a rejection because the
    // archive could not possibly contain a valid header. Read errors
    // surface as Validation rather than Io so the operator sees a
    // single class of "config can't be loaded" rather than mixed error
    // kinds.
    let mut magic = [0u8; 2];
    let mut f = std::fs::File::open(p).map_err(|e| {
        validation(
            format!("runner-tarball cannot be opened for magic-byte check: {path}: {e}"),
            "verify the file is readable by the user invoking ghars",
        )
    })?;
    use std::io::Read;
    let n = f.read(&mut magic).map_err(|e| {
        validation(
            format!("runner-tarball read failed during magic-byte check: {path}: {e}"),
            "verify the file is readable and not truncated",
        )
    })?;
    if n < 2 || magic != [0x1f, 0x8b] {
        // Render what we ACTUALLY saw so the operator can attribute
        // the file format from the error message alone (no `xxd`
        // trip required). Three branches:
        //   - n == 0: file is empty (could not read first byte)
        //   - n == 1: only one byte was read (file < 2 bytes)
        //   - n == 2: full prefix in `magic` — print both bytes
        let got = match n {
            0 => "<empty file>".to_string(),
            1 => format!("{:02x} (1 byte)", magic[0]),
            _ => format!("{:02x} {:02x}", magic[0], magic[1]),
        };
        return Err(validation(
            format!(
                "runner-tarball file does not appear to be a gzip archive \
                 (expected magic bytes 1f 8b, got: {got}): {path}"
            ),
            "point [[runner]].runner_tarball at a real .tar.gz file \
             (operators occasionally feed a saved HTML error page or \
             partial download here)",
        ));
    }
    Ok(())
}

/// Validate a CIDR string (IPv4 or IPv6) using `ipnet::IpNet::from_str`.
///
/// # Errors
///
/// Returns `GharsError::Validation` for any input that does not parse
/// as a CIDR. Used by `[network.NAME] ip_allow / ip_deny` validation.
pub fn validate_cidr(s: &str) -> Result<()> {
    IpNet::from_str(s).map_err(|e| {
        validation(
            format!("cidr invalid: {s:?} ({e})"),
            "use forms like 192.168.1.0/24 or fd00::/64",
        )
    })?;
    Ok(())
}

/// Validate a single L4 port number: must be in `1..=65535`. Port 0 is
/// rejected — nft's `dport` matchers accept it but it never matches a
/// real packet (kernel TCP/UDP source/dest ports are 16-bit unsigned
/// and can't actually be 0 on the wire), so its presence indicates a
/// config typo (forgetting to fill in the port).
///
/// # Errors
///
/// Returns `GharsError::Validation` when `port == 0`. (Range check
/// against 65535 is handled at the type level — `u16::MAX == 65535`.)
pub fn validate_port(port: u16) -> Result<()> {
    if port == 0 {
        return Err(validation(
            "egress port 0 is invalid",
            "ports must be in 1..=65535; nft `dport 0` never matches a real packet",
        ));
    }
    Ok(())
}

/// Validate a `[[network.NAME].allowed_egress]` rule.
///
/// Checks:
/// - `addr` parses as `IpAddr` or `IpNet` (single host or CIDR).
/// - Port (single, set, or range) — every port in the spec is
///   non-zero; for `Range`, `start <= end` and both endpoints are
///   non-zero. Empty `Set` rejected (rule with no ports is a no-op).
///
/// # Errors
///
/// Returns `GharsError::Validation` on the first failure.
pub fn validate_egress_rule(rule: &crate::config::EgressRule) -> Result<()> {
    // Address must parse as either an IpAddr (single host) or IpNet
    // (CIDR). `IpNet::from_str` accepts both `"1.2.3.4"` (treats as
    // /32) and `"1.2.3.0/24"`. Try IpAddr first since `1.2.3.4`
    // parses as IpAddr cleanly; fall back to IpNet.
    if std::net::IpAddr::from_str(&rule.addr).is_err() && IpNet::from_str(&rule.addr).is_err() {
        return Err(validation(
            format!("egress addr invalid: {:?}", rule.addr),
            "use an IPv4/IPv6 address (e.g. 192.168.2.84) or CIDR (e.g. 192.168.2.0/24)",
        ));
    }

    match &rule.port {
        crate::config::PortSpec::Single(p) => validate_port(*p)?,
        crate::config::PortSpec::Set(ports) => {
            if ports.is_empty() {
                return Err(validation(
                    "egress port set is empty",
                    "list at least one port, e.g. port = [80, 443]",
                ));
            }
            for p in ports {
                validate_port(*p)?;
            }
        }
        crate::config::PortSpec::Range { start, end } => {
            validate_port(*start)?;
            validate_port(*end)?;
            if start > end {
                return Err(validation(
                    format!("egress port range start > end: {start}-{end}"),
                    "swap the values so start <= end",
                ));
            }
        }
    }

    if let Some(c) = rule.comment.as_deref() {
        validate_egress_comment(c)?;
    }
    Ok(())
}

/// Validate an `EgressRule.comment` for nft string-literal safety
/// (SEC-30). The renderer interpolates the comment between `"` chars
/// into an nft rule like `comment "..."`; any character that breaks
/// out of that string literal — `"` itself, `\`, control chars,
/// shell metas — is rejected here so the renderer can rely on every
/// reachable comment being literal-safe. Allowlist:
/// `[A-Za-z0-9 _.,:/+\-]`.
///
/// # Errors
///
/// Returns `GharsError::Validation` naming the offending character
/// (in debug-printable form) and its 0-indexed byte position so the
/// operator can locate it in the TOML source.
pub fn validate_egress_comment(comment: &str) -> Result<()> {
    if let Some((idx, ch)) = comment
        .char_indices()
        .find(|(_, c)| !is_safe_comment_char(*c))
    {
        return Err(validation(
            format!(
                "egress rule comment contains disallowed character {ch:?} at byte position {idx}"
            ),
            "comments may only contain ASCII letters, digits, spaces, and any of `_.,:/+-`",
        ));
    }
    Ok(())
}

fn is_safe_comment_char(c: char) -> bool {
    c.is_ascii_alphanumeric() || matches!(c, ' ' | '_' | '.' | ',' | ':' | '/' | '+' | '-')
}

/// Validate a `[[network.NAME].dns]` mode.
///
/// Checks:
/// - For `DnsMode::Static { servers }`, `servers` is non-empty
///   (a Static binding with no upstream resolvers is identical to
///   "DNS broken inside netns" — the operator almost certainly forgot
///   to fill in the servers list).
/// - `DnsMode::Forward` (the default) needs no inputs to validate
///   here; the host must have systemd-resolved active, which is a
///   preflight check, not a config-time concern.
///
/// # Errors
///
/// Returns `GharsError::Validation` on empty Static servers list.
pub fn validate_dns_mode(dns: &crate::config::DnsMode) -> Result<()> {
    match dns {
        crate::config::DnsMode::Forward => Ok(()),
        crate::config::DnsMode::Static { servers } => {
            if servers.is_empty() {
                return Err(validation(
                    "dns mode = static requires at least one server",
                    "set dns = { mode = \"static\", servers = [\"1.1.1.1\"] } or omit dns to use Forward",
                ));
            }
            Ok(())
        }
    }
}

/// Validate every field of a `NetworkSpec`. Aggregates
/// `validate_egress_rule` over all entries and `validate_dns_mode`
/// over the resolved DNS policy. Also requires at least one of
/// `allowed_egress` / `ip_allow` for `NetworkMode::Netns` (a netns
/// runner with neither is fully isolated and almost certainly a
/// misconfiguration; mirrors the design's "validation" subsection
/// in Part 9c).
///
/// # Errors
///
/// Returns `GharsError::Validation` on the first failing rule.
pub fn validate_network_spec(spec: &crate::config::NetworkSpec) -> Result<()> {
    for rule in &spec.allowed_egress {
        validate_egress_rule(rule)?;
    }
    validate_dns_mode(&spec.dns)?;
    if matches!(spec.mode, crate::config::NetworkMode::Netns)
        && spec.allowed_egress.is_empty()
        && spec.ip_allow.is_empty()
    {
        return Err(validation(
            "netns network has no allowed_egress and no ip_allow",
            "a fully-isolated netns runner can't reach the network at all; \
            list at least one allowed_egress entry or ip_allow CIDR",
        ));
    }
    Ok(())
}

/// Normalize a prefix path: strip a single trailing `/` unless the
/// prefix is the root `"/"` itself.
///
/// Mirrors the legacy Python install tool's prefix normalization.
/// The validator does not require a normalized form; this helper
/// makes equality comparisons stable (e.g. `/opt/gha` vs `/opt/gha/`).
#[must_use]
pub fn normalize_prefix(p: &str) -> String {
    if p != "/" && p.ends_with('/') {
        p.trim_end_matches('/').to_string()
    } else {
        p.to_string()
    }
}

/// Linux capabilities ghars refuses to add to `CapabilityBoundingSet=`
/// via `Hardening.extra_capabilities`. Each entry, granted on top of
/// the runner's default bounding set, defeats the runner-isolation
/// invariant the systemd hardening profile is enforcing:
/// - `CAP_SYS_ADMIN` — superuser-equivalent in practice (mount,
///   pivot_root, ptrace any task, ioctl on block devices, set hostname,
///   ...).
/// - `CAP_SYS_PTRACE` — ptrace any process the runner UID can reach,
///   undermining cross-runner isolation (SEC-28) and per-runner UID
///   separation (SEC-27).
/// - `CAP_SYS_MODULE` — load arbitrary kernel modules; full kernel
///   compromise from the runner.
/// - `CAP_SYS_RAWIO` — direct port I/O and `/dev/mem`-equivalent
///   primitives; reads physical memory.
/// - `CAP_NET_RAW` — craft raw L2/L3 packets, bypassing the netns
///   egress allowlist and reaching the host's neighbor cache.
///
/// SEC-01. Tokens are matched case-insensitively against the input —
/// operators write either `CAP_SYS_ADMIN` or `cap_sys_admin`, both
/// reject. The check trims whitespace before comparison so
/// `" CAP_SYS_ADMIN "` is also caught.
const DENY_EXTRA_CAPABILITIES: &[&str] = &[
    "CAP_SYS_ADMIN",
    "CAP_SYS_PTRACE",
    "CAP_SYS_MODULE",
    "CAP_SYS_RAWIO",
    "CAP_NET_RAW",
];

/// Filesystem paths ghars refuses to add to `BindReadOnlyPaths=` /
/// `BindPaths=` via `Hardening.extra_bind_paths`. Mounting any of
/// these into the runner namespace re-exposes a host-control surface
/// the systemd profile takes care to hide:
/// - `/proc/sys` — kernel sysctls. Read-only is enough for
///   fingerprinting; a future regression that grew a `read_write`
///   bool on the binding would be one config edit from re-enabling
///   write access.
/// - `/sys/kernel/security` — securityfs (SELinux, AppArmor, IMA).
/// - `/proc/sysrq-trigger` — even read-only mount makes the file
///   path present, and a misconfigured drop-in could escalate the
///   binding to writable.
/// - `/dev/kmem`, `/dev/mem` — raw kernel/physical memory.
/// - `/dev/kmsg` — kernel ring buffer. Read-only is still an
///   info-leak (the runner can read all dmesg output, including
///   driver / module / hardware fingerprints).
/// - `/dev/kallsyms` — kernel symbol-to-address map. Even read-only
///   defeats KASLR.
/// - `/proc/kcore` — pseudo-file backing a full kernel-memory dump.
///   Read-only is full kernel-state exfiltration.
///
/// Per-PID procfs subtrees (`/proc/<pid>` and below) are rejected
/// separately by [`PROC_PID_RE`] because they cannot be enumerated
/// statically — any positive integer matches.
///
/// Path comparison is component-prefix exact: `/proc/sys`,
/// `/proc/sys/`, and `/proc/sys/net/...` all reject. Plain
/// `starts_with` would mis-match `/dev/memfoo` against `/dev/mem`.
const DENY_EXTRA_BIND_PATHS: &[&str] = &[
    "/proc/sys",
    "/sys/kernel/security",
    "/proc/sysrq-trigger",
    "/dev/kmem",
    "/dev/mem",
    "/dev/kmsg",
    "/dev/kallsyms",
    "/proc/kcore",
];

/// Per-PID procfs subtree matcher. Rejects any path that names a
/// `/proc/<pid>` directory or anything underneath it. Mounting another
/// process's procfs entry into the runner namespace exposes its
/// `cmdline`, `environ`, `maps`, `status`, file descriptors, and
/// (with `CAP_SYS_PTRACE` granted) memory.
///
/// Anchored at the start so `/foo/proc/123` does not match;
/// `($|/)` after the digit run ensures `/proc/123` and `/proc/123/x`
/// match while `/procmon` and `/proc/12abc` do not. Static + lazy so
/// the regex compiles once.
static PROC_PID_RE: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r"^/proc/[0-9]+($|/)").expect("PROC_PID_REGEX is a compile-time constant")
});

/// Validate `Hardening.extra_capabilities` (SEC-01).
///
/// Each entry must satisfy:
/// - Non-empty after trim.
/// - Match the systemd capability-token shape `CAP_[A-Z0-9_]+`
///   (case-insensitive). Anything else is a typo or a confused
///   operator pasting raw `capabilities(7)` text.
/// - Not appear in [`DENY_EXTRA_CAPABILITIES`].
///
/// # Errors
///
/// Returns `GharsError::Validation` on the first offending token. The
/// message names the rejected capability and the reason; the hint
/// suggests the safer alternative (drop the entry, or open a feature
/// request that justifies the cap with a concrete attack model).
pub fn validate_extra_capabilities(caps: &[String]) -> Result<()> {
    static CAP_RE: LazyLock<Regex> = LazyLock::new(|| {
        Regex::new(r"^CAP_[A-Z0-9_]+$").expect("CAP_REGEX is a compile-time constant")
    });
    for raw in caps {
        let trimmed = raw.trim();
        if trimmed.is_empty() {
            return Err(validation(
                "extra_capabilities entry is empty",
                "remove the empty token from [hardening.extra_capabilities]",
            ));
        }
        // Comparison against the deny list is case-insensitive so
        // `cap_sys_admin` cannot smuggle past via lowercase.
        let upper = trimmed.to_ascii_uppercase();
        if !CAP_RE.is_match(&upper) {
            return Err(validation(
                format!("extra_capabilities entry {trimmed:?} is not a CAP_* token",),
                "use systemd capability tokens like CAP_NET_BIND_SERVICE; \
                 see capabilities(7) for the full list",
            ));
        }
        for deny in DENY_EXTRA_CAPABILITIES {
            if upper == *deny {
                return Err(validation(
                    format!(
                        "extra_capabilities entry {deny} is denied (SEC-01); \
                         granting it defeats ghars's runner sandbox",
                    ),
                    "drop the entry; if you have a concrete need, open an \
                     issue describing the capability use case",
                ));
            }
        }
    }
    Ok(())
}

/// Validate `Hardening.extra_bind_paths` (SEC-01).
///
/// Each path must satisfy:
/// - Non-empty.
/// - Absolute (`/`-prefixed).
/// - Not equal to or under any [`DENY_EXTRA_BIND_PATHS`] entry.
/// - Not a per-PID procfs path (matched by [`PROC_PID_RE`]).
///
/// # Errors
///
/// Returns `GharsError::Validation` on the first offending entry,
/// naming both the rejected path and the deny entry / regex that
/// matched.
pub fn validate_extra_bind_paths(paths: &[camino::Utf8PathBuf]) -> Result<()> {
    for path in paths {
        let p: &Utf8Path = path.as_path();
        let s = p.as_str();
        if s.is_empty() {
            return Err(validation(
                "extra_bind_paths entry is empty",
                "remove the empty path from [hardening.extra_bind_paths]",
            ));
        }
        if !s.starts_with('/') {
            return Err(validation(
                format!("extra_bind_paths entry {s:?} is not absolute"),
                "use an absolute path (e.g. /etc/pki/ca-trust/source/anchors)",
            ));
        }
        for deny in DENY_EXTRA_BIND_PATHS {
            // Component-prefix match: `entry == deny` OR `entry`
            // starts with `deny + "/"`. Plain `starts_with` would
            // mis-match `/dev/memfoo` against `/dev/mem`.
            if s == *deny || s.starts_with(&format!("{deny}/")) {
                return Err(validation(
                    format!(
                        "extra_bind_paths entry {s:?} is denied: matches {deny} \
                         (SEC-01)",
                    ),
                    "this path exposes a host control surface; drop it or \
                     bind a narrower subdirectory that does not include \
                     the denied prefix",
                ));
            }
        }
        // Per-PID procfs subtree — must use a regex because <pid> is
        // unbounded. Matches `/proc/123`, `/proc/123/`, `/proc/123/x`;
        // does NOT match `/proc/sys` (handled by the static deny list
        // above), `/procmon`, or `/proc/123abc`.
        if PROC_PID_RE.is_match(s) {
            return Err(validation(
                format!(
                    "extra_bind_paths entry {s:?} is denied: matches per-PID \
                     procfs subtree /proc/<pid> (SEC-01)",
                ),
                "another process's procfs entry exposes its cmdline / environ / \
                 maps / fds; bind /proc/self instead if the runner needs to read \
                 its own state",
            ));
        }
    }
    Ok(())
}

/// Open `path` with `O_NOFOLLOW` and return the file handle paired
/// with metadata read from the opened file descriptor (fstat). The
/// (file, metadata) pair is TOCTOU-safe: kernel-side `O_NOFOLLOW`
/// rejects symlink components in `path`'s final segment at open(2)
/// time, and `File::metadata` reads metadata of THE SAME open inode
/// rather than re-walking the path. Callers can subsequently
/// read/exec from `file` knowing the metadata describes the inode
/// they received.
///
/// Pure mechanism — no policy. Callers (auth, validators) own the
/// regular-file / mode / uid checks and own the
/// `GharsError`-variant choice. Errors propagate as bare
/// `std::io::Error` so each caller wraps them with the variant
/// matching their subsystem.
///
/// # Errors
///
/// `std::io::Error` from `OpenOptions::open` (notably `ELOOP` when
/// the path is a symlink — `e.raw_os_error() == Some(libc::ELOOP)`)
/// or from `File::metadata` (rare; only on a vanished inode or fs
/// fault).
pub(crate) fn open_no_follow_with_meta(path: &Path) -> std::io::Result<(File, Metadata)> {
    let file = OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_NOFOLLOW)
        .open(path)?;
    let meta = file.metadata()?;
    Ok((file, meta))
}

/// Validate a hooks pre/post-job script (SEC-12).
///
/// `path` is a host file ghars hands to the runner via the
/// `ACTIONS_RUNNER_HOOK_JOB_STARTED` /
/// `ACTIONS_RUNNER_HOOK_JOB_COMPLETED` environment variables. Because
/// the runner exec's it, ghars enforces at validate time:
///
/// 1. **Absolute path.** Relative paths would be resolved against
///    the runner's cwd at exec time, which is operator-controllable
///    via working-directory drop-ins. Reject anything that doesn't
///    start with `/`.
/// 2. **No symlinks.** Resolved by opening with `O_NOFOLLOW` via
///    [`open_no_follow_with_meta`]. The kernel returns `ELOOP` if
///    the final path component is a symlink, so the file handle we
///    hold is the same inode whose metadata we check (closes the
///    lstat-then-exec TOCTOU window the lstat-only approach left
///    open).
/// 3. **Regular file.** Directories, sockets, devices reject.
/// 4. **Owner-execute bit set** (`mode & 0o100`). Without it the
///    runner cannot exec the script regardless of group/other bits.
/// 5. **Owner UID is 0** (root). Per design Part 17 SEC-12, hooks
///    land in runner state that is never owned by the runner user;
///    root ownership is the only way to prevent the runner user from
///    rewriting its own hook between apply and the next job.
///
/// The check is intentionally narrower than what apply does at job
/// runtime — we want a config-time reject so `ghars validate` flags
/// misconfiguration before any runner unit ever starts.
///
/// # Errors
///
/// Returns `GharsError::Validation` for any failed check.
pub fn validate_hook_script(path: &Utf8Path) -> Result<()> {
    let s = path.as_str();
    if !s.starts_with('/') {
        return Err(validation(
            format!("hook script {path}: not absolute (SEC-12)"),
            "use an absolute path; relative paths resolve against the \
             runner's cwd at exec time, which is operator-controllable",
        ));
    }
    // SEC-12 hardening: reject hook scripts whose parent is `/`
    // (i.e. paths like `/foo.sh`). The runner unit binds the hook's
    // parent directory into the sandbox via `BindReadOnlyPaths=`;
    // a hook at `/foo.sh` would emit `BindReadOnlyPaths=/`, exposing
    // the entire host filesystem to the runner. Operators should
    // place hooks under a dedicated subdirectory (e.g.
    // `/usr/local/lib/ghars-hooks/foo.sh`) so the bind targets a
    // narrow tree.
    if let Some(parent) = path.parent() {
        if parent.as_str() == "/" || parent.as_str().is_empty() {
            return Err(validation(
                format!(
                    "hook script {path}: parent directory is `/` (SEC-12); \
                     BindReadOnlyPaths=/ would expose the entire host to the runner"
                ),
                "place the hook under a dedicated subdirectory \
                 (e.g. /usr/local/lib/ghars-hooks/<name>.sh) so the \
                 BindReadOnlyPaths bind targets a narrow tree",
            ));
        }
    }
    let std_path: &Path = path.as_std_path();
    let (_file, meta) = open_no_follow_with_meta(std_path).map_err(|e| {
        // ELOOP from O_NOFOLLOW is the symlink-rejection path; report
        // it specifically so the operator doesn't conflate it with a
        // missing-file error.
        let hint = if e.raw_os_error() == Some(libc::ELOOP) {
            "the path is a symlink; resolve it with `readlink -f` and pass the real path"
        } else {
            "verify the path exists and is readable by ghars"
        };
        validation(
            format!("hook script {path}: open failed: {e} (SEC-12)"),
            hint,
        )
    })?;
    if !meta.file_type().is_file() {
        return Err(validation(
            format!(
                "hook script {path}: not a regular file (file type {:?})",
                meta.file_type()
            ),
            "point hooks.{pre,post}_job at a regular file",
        ));
    }
    let mode = meta.mode();
    // 0o100 == S_IXUSR. Owner-execute is the minimum exec gate; group
    // / world bits are the operator's call as long as ownership is
    // root (next check). `mode & 0o100 == 0` ⇒ owner cannot exec.
    if mode & 0o100 == 0 {
        return Err(validation(
            format!("hook script {path}: mode {mode:o} missing owner-execute bit (SEC-12)",),
            "chmod u+x the script so the runner can execute it",
        ));
    }
    if meta.uid() != 0 {
        return Err(validation(
            format!(
                "hook script {path}: owner uid {} != 0 (root) (SEC-12)",
                meta.uid(),
            ),
            "chown root: the script (sudo chown root:root <path>) so the \
             runner user cannot rewrite the file under itself",
        ));
    }
    // SEC-12 hardening: reject group-writable and world-writable
    // hook scripts. Owner-only mutation is the trust premise — if
    // any non-root principal can rewrite the script, the
    // root-owned-script gate above is moot. `0o022` covers both
    // S_IWGRP (0o020) and S_IWOTH (0o002). Operator remediation:
    // `chmod go-w <path>`. We do NOT also reject the setuid /
    // setgid bits here — the file is invoked via the unit's
    // ExecStart= which runs at the runner's DynamicUser identity
    // regardless of file-mode bits, so set[ug]id has no effect.
    if mode & 0o022 != 0 {
        return Err(validation(
            format!(
                "hook script {path}: mode {mode:o} has group/world-writable bits set (SEC-12)",
            ),
            "chmod go-w <path> so only root can modify the script",
        ));
    }
    Ok(())
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used)]
mod tests {
    use super::*;
    use rstest::rstest;
    use tempfile::TempDir;

    // ---- runner_name --------------------------------------------------

    #[rstest]
    #[case("myrunner")]
    #[case("a")]
    #[case("r0")]
    #[case("runner-1")]
    #[case("ci-node-42")]
    #[case("run--ner")]
    fn runner_name_accepts(#[case] name: &str) {
        validate_runner_name(name).expect("must accept");
    }

    #[rstest]
    #[case("")]
    #[case("-runner")]
    #[case("runner-")]
    #[case("1runner")]
    #[case("Runner")]
    #[case("myRunner")]
    #[case("runner_x")]
    #[case("runner.x")]
    #[case("runner/x")]
    #[case("..")]
    #[case(".")]
    #[case("runner with space")]
    #[case("runner$x")]
    #[case("runner;x")]
    #[case("runner`x")]
    #[case("runner|x")]
    #[case("runner\nx")]
    #[case("rünner")]
    #[case("-")]
    fn runner_name_rejects(#[case] name: &str) {
        assert!(validate_runner_name(name).is_err(), "must reject {name:?}");
    }

    #[test]
    fn runner_name_rejects_too_long() {
        // Past `IDENTIFIER_MAX_LEN` always rejects (was the only cap
        // before the runner-cap was introduced); pinned here so a future
        // loosening of the identifier layer doesn't silently re-introduce
        // 65+ char names.
        let s = "a".repeat(IDENTIFIER_MAX_LEN + 1);
        assert!(validate_runner_name(&s).is_err());
    }

    /// `validate_runner_name` must accept a runner name at the cap.
    /// `RUNNER_NAME_MAX_LEN` chars + "ghars-" 6-char prefix =
    /// `SYSTEMD_GROUP_NAME_MAX` (31), the systemd strict-mode user-name
    /// limit. This pin catches off-by-one shrinks of
    /// `RUNNER_NAME_MAX_LEN`.
    #[test]
    fn runner_name_accepts_max_len() {
        let s = "a".repeat(RUNNER_NAME_MAX_LEN);
        validate_runner_name(&s).expect("must accept exactly max len");
    }

    /// `validate_runner_name` must reject one char past the cap. The
    /// error message must mention the limit and the derived user name
    /// so the operator can act without guessing.
    #[test]
    fn runner_name_rejects_one_past_max_len() {
        let s = "a".repeat(RUNNER_NAME_MAX_LEN + 1);
        let err = validate_runner_name(&s).expect_err("must reject one past max");
        match err {
            GharsError::Validation(msg, hint) => {
                assert!(
                    msg.contains("too long") && msg.contains(&RUNNER_NAME_MAX_LEN.to_string()),
                    "msg must name the cap; got: {msg}"
                );
                assert!(
                    msg.contains(RUNNER_USER_PREFIX)
                        && msg.contains(&SYSTEMD_GROUP_NAME_MAX.to_string()),
                    "msg must explain the derived-user rationale; got: {msg}"
                );
                assert!(
                    hint.contains(&RUNNER_NAME_MAX_LEN.to_string()),
                    "hint must restate the cap; got: {hint}"
                );
            }
            other => panic!("expected Validation, got {other:?}"),
        }
    }

    /// For every length from `RUNNER_NAME_MAX_LEN + 1` through
    /// `IDENTIFIER_MAX_LEN`, rejection must come from the runner-name
    /// length layer (msg names "ghars-"), NOT the identifier length
    /// layer. Symmetric to
    /// `cache_pool_name_rejects_via_pool_cap_not_identifier_cap_above_max_len`.
    #[test]
    fn runner_name_rejects_via_runner_cap_not_identifier_cap_above_max_len() {
        for len in (RUNNER_NAME_MAX_LEN + 1)..=IDENTIFIER_MAX_LEN {
            let s = "a".repeat(len);
            let err = validate_runner_name(&s).expect_err("must reject");
            match &err {
                GharsError::Validation(msg, _) => {
                    assert!(
                        msg.contains(RUNNER_USER_PREFIX),
                        "len={len}: rejection must come from runner-name layer, got: {msg}"
                    );
                }
                other => panic!("len={len}: expected Validation, got {other:?}"),
            }
        }
    }

    /// Boundary above `IDENTIFIER_MAX_LEN`: at `IDENTIFIER_MAX_LEN + 1`,
    /// rejection MUST come from `validate_identifier` (the outer-and-
    /// first layer), not from the runner-name cap. Symmetric counterpart
    /// to `runner_name_rejects_via_runner_cap_not_identifier_cap_above_max_len`
    /// — together they pin the layered-validator contract:
    /// ≤`RUNNER_NAME_MAX_LEN` accept,
    /// `(RUNNER_NAME_MAX_LEN+1)..=IDENTIFIER_MAX_LEN` fail at runner-name
    /// layer (msg contains `RUNNER_USER_PREFIX`),
    /// `>IDENTIFIER_MAX_LEN` fail at identifier layer (msg does NOT
    /// contain `RUNNER_USER_PREFIX`). Mirrors
    /// `cache_pool_name_above_identifier_cap_rejects_via_identifier_cap_not_pool_cap`.
    #[test]
    fn runner_name_above_identifier_cap_rejects_via_identifier_cap_not_runner_cap() {
        let s = "a".repeat(IDENTIFIER_MAX_LEN + 1);
        let err = validate_runner_name(&s).expect_err("must reject");
        match &err {
            GharsError::Validation(msg, _) => {
                assert!(
                    !msg.contains(RUNNER_USER_PREFIX),
                    "len=IDENTIFIER_MAX_LEN+1: rejection must come from identifier layer, got: {msg}"
                );
            }
            other => panic!("expected Validation, got {other:?}"),
        }
    }

    // ---- cache_pool_name ---------------------------------------------

    /// `validate_cache_pool_name` must accept a pool name at the cap.
    /// `CACHE_POOL_NAME_MAX_LEN` chars + "ghars-cache-" 12-char prefix =
    /// `SYSTEMD_GROUP_NAME_MAX` (31), the systemd strict-mode group-name
    /// limit. This pin catches off-by-one shrinks of
    /// `CACHE_POOL_NAME_MAX_LEN`.
    #[test]
    fn cache_pool_name_accepts_max_len() {
        let s = "a".repeat(CACHE_POOL_NAME_MAX_LEN);
        validate_cache_pool_name(&s).expect("must accept exactly max len");
    }

    /// `validate_cache_pool_name` must reject one char past the cap.
    /// `CACHE_POOL_NAME_MAX_LEN + 1` chars → group name >
    /// `SYSTEMD_GROUP_NAME_MAX` → systemd rejects. The error message
    /// must mention the limit and the derived group name so the
    /// operator can act without guessing.
    #[test]
    fn cache_pool_name_rejects_one_past_max_len() {
        let s = "a".repeat(CACHE_POOL_NAME_MAX_LEN + 1);
        let err = validate_cache_pool_name(&s).expect_err("must reject one past max");
        match err {
            GharsError::Validation(msg, hint) => {
                assert!(
                    msg.contains("too long") && msg.contains(&CACHE_POOL_NAME_MAX_LEN.to_string()),
                    "msg must name the cap; got: {msg}"
                );
                assert!(
                    msg.contains("ghars-cache-") && msg.contains("31"),
                    "msg must explain the derived-group rationale; got: {msg}"
                );
                assert!(
                    hint.contains(&CACHE_POOL_NAME_MAX_LEN.to_string()),
                    "hint must restate the cap; got: {hint}"
                );
            }
            other => panic!("expected Validation, got {other:?}"),
        }
    }

    /// Single-char pool name must pass — exercises the lower boundary
    /// of the identifier shape (the regex `^[a-z]([a-z0-9-]*[a-z0-9])?$`
    /// allows length-1 inputs via the inner-group `?`). A regression
    /// that off-by-one'd `validate_identifier`'s `is_empty` gate or
    /// tightened the regex would surface here.
    #[test]
    fn cache_pool_name_accepts_one_char() {
        validate_cache_pool_name("a").expect("single-char pool must pass");
    }

    /// For every length from `CACHE_POOL_NAME_MAX_LEN + 1` through
    /// `IDENTIFIER_MAX_LEN`, rejection must come from the cache-pool
    /// length layer (msg names "ghars-cache-"), NOT the identifier
    /// length layer. Without this pin, a future refactor that flipped
    /// the order — `validate_identifier` first with a tighter cap, or
    /// `validate_cache_pool_name` shrinking below the identifier cap —
    /// would silently regress the operator-facing diagnostic so the
    /// `≤{CACHE_POOL_NAME_MAX_LEN}` hint never lands.
    #[test]
    fn cache_pool_name_rejects_via_pool_cap_not_identifier_cap_above_max_len() {
        for len in (CACHE_POOL_NAME_MAX_LEN + 1)..=IDENTIFIER_MAX_LEN {
            let s = "a".repeat(len);
            let err = validate_cache_pool_name(&s).expect_err("must reject");
            match &err {
                GharsError::Validation(msg, _) => {
                    assert!(
                        msg.contains("ghars-cache-"),
                        "len={len}: rejection must come from cache-pool layer, got: {msg}"
                    );
                }
                other => panic!("len={len}: expected Validation, got {other:?}"),
            }
        }
    }

    /// Boundary above `IDENTIFIER_MAX_LEN`: at `IDENTIFIER_MAX_LEN + 1`,
    /// rejection MUST come from `validate_identifier` (the outer-and-first
    /// layer), not from the cache-pool cap. Symmetric counterpart to the
    /// `above_max_len` test — together they pin the layered-validator
    /// contract: ≤`CACHE_POOL_NAME_MAX_LEN` accept,
    /// `(CACHE_POOL_NAME_MAX_LEN+1)..=IDENTIFIER_MAX_LEN` fail at
    /// cache-pool layer (msg contains "ghars-cache-"),
    /// `>IDENTIFIER_MAX_LEN` fail at identifier layer (msg does NOT
    /// contain "ghars-cache-"). A regression that re-ordered the
    /// validators would surface here.
    #[test]
    fn cache_pool_name_above_identifier_cap_rejects_via_identifier_cap_not_pool_cap() {
        let s = "a".repeat(IDENTIFIER_MAX_LEN + 1);
        let err = validate_cache_pool_name(&s).expect_err("must reject");
        match &err {
            GharsError::Validation(msg, _) => {
                assert!(
                    !msg.contains("ghars-cache-"),
                    "len=IDENTIFIER_MAX_LEN+1: rejection must come from identifier layer, got: {msg}"
                );
            }
            other => panic!("expected Validation, got {other:?}"),
        }
    }

    // ---- url ----------------------------------------------------------

    #[rstest]
    #[case("https://github.com/OWNER/REPO")]
    #[case("https://github.com/example/repo")]
    #[case("https://github.com/octo-org/my.repo")]
    #[case("https://github.com/a-/b_")]
    #[case("https://github.com/owner/repo.git")]
    #[case("https://github.com/owner/repo/")]
    #[case("https://github.com/owner")]
    #[case("https://github.com/owner.git")]
    fn url_accepts(#[case] u: &str) {
        validate_url(u).expect("must accept");
    }

    #[rstest]
    #[case("", "empty")]
    #[case("http://github.com/x/y", "http-scheme")]
    #[case("https://gitlab.com/x/y", "wrong-host")]
    #[case("github.com/x/y", "no-scheme")]
    #[case("ftp://github.com/x/y", "ftp-scheme")]
    #[case("https://github.com//etc/passwd", "double-slash-path")]
    #[case("https://github.com///etc/passwd", "triple-slash-path")]
    #[case("https://github.com/../etc/passwd", "dotdot-owner")]
    #[case("https://github.com/owner/../etc", "dotdot-repo")]
    #[case("https://github.com/.hidden/x", "dot-prefixed-owner")]
    #[case("https://github.com/x/.hidden", "dot-prefixed-repo")]
    #[case("https://attacker@github.com/x/y", "userinfo")]
    #[case("https://github.com:@other/x/y", "userinfo-empty")]
    #[case("https://github.com.evil.tld/x/y", "host-suffix")]
    #[case("https://github.com/x/y/settings/actions", "extra-path")]
    #[case("https://github.com/x/y?foo=bar", "query-string")]
    #[case("https://github.com/x/y#fragment", "fragment")]
    #[case("https://github.com/", "trailing-slash-only")]
    #[case("https://github.com", "no-path-no-slash")]
    #[case("https://GITHUB.com/x/y", "uppercase-host")]
    #[case("https://github.com/owner name/repo", "space-in-owner")]
    // `.git` may only be followed by an optional trailing slash. A trailing
    // path segment past `.git` is past the regex anchor and must not match.
    // Without this case, a future regex weakening that drops the trailing-
    // anchor `/?$` (e.g. accidental `/?` without `$`) could let "look-alike"
    // URLs through that point at unrelated GitHub paths.
    #[case(
        "https://github.com/owner/repo.git/extra",
        "trailing-path-after-dot-git"
    )]
    // Owner segments must start with `[A-Za-z0-9]`. A leading `..` flunks
    // the first-char anchor regardless of what follows, but the `dotdot-
    // owner` case above pins only the path-traversal `/..` form (full-
    // segment). This case pins the embedded form `..foo` to catch a regex
    // edit that broadens the first-char class.
    #[case("https://github.com/..foo/repo", "leading-dotdot-owner")]
    // Owner/repo segments are ASCII-only by `[A-Za-z0-9._-]`. A multibyte
    // codepoint anywhere in the segment must fail the regex. Without this
    // case a future regex broadening (e.g. `\w` swap, which in some regex
    // dialects is Unicode-aware) could silently accept homoglyph attacks
    // like `https://github.com/üser/repo`.
    #[case("https://github.com/üser/repo", "multibyte-owner")]
    #[case("https://github.com/owner/répo", "multibyte-repo")]
    fn url_rejects(#[case] u: &str, #[case] label: &str) {
        assert!(validate_url(u).is_err(), "must reject {label}: {u:?}");
    }

    // ---- prefix -------------------------------------------------------

    #[rstest]
    #[case("/opt/gha")]
    #[case("/opt/my_runner")]
    #[case("/var/lib/gha")]
    #[case("/srv/runners")]
    fn prefix_accepts(#[case] p: &str) {
        validate_prefix(p).expect("must accept");
    }

    #[rstest]
    #[case("")]
    #[case("opt/gha")]
    #[case("/")]
    #[case("/etc")]
    #[case("/var")]
    #[case("/opt gha")]
    #[case("/opt/gha\nhack")]
    #[case("/opt/gha$bad")]
    #[case("/opt/..gha")]
    #[case("/opt/../etc")]
    fn prefix_rejects(#[case] p: &str) {
        assert!(validate_prefix(p).is_err(), "must reject {p:?}");
    }

    /// Every entry of `TOP_LEVEL_RESERVED` must be rejected by
    /// `validate_prefix`. Iterating the slice (rather than enumerating
    /// each path as a separate `#[case]`) guarantees the test stays in
    /// sync if entries are added or removed.
    #[test]
    fn prefix_rejects_every_top_level_reserved_entry() {
        for entry in TOP_LEVEL_RESERVED {
            let err = validate_prefix(entry).expect_err(&format!(
                "TOP_LEVEL_RESERVED entry {entry:?} must be rejected"
            ));
            // Whatever the error, it must mention the rejected path so
            // operators see which prefix collided with the host layout.
            let msg = err.to_string();
            assert!(
                msg.contains(entry),
                "rejection message for {entry:?} should reference the path; got: {msg}"
            );
        }
    }

    #[test]
    fn prefix_rejects_symlink() {
        let dir = TempDir::new().unwrap();
        let target = dir.path().join("target");
        std::fs::create_dir(&target).unwrap();
        let link = dir.path().join("link");
        std::os::unix::fs::symlink(&target, &link).unwrap();
        let link_str = link.to_str().unwrap();
        // Path may contain underscores so it must pass PREFIX_RE first.
        // tempfile uses random hex chars + dashes; both allowed by PREFIX_RE.
        let err = validate_prefix(link_str).expect_err("must reject symlink");
        let msg = format!("{err}");
        assert!(
            msg.contains("symlink"),
            "expected symlink error, got: {msg}"
        );
    }

    #[test]
    fn normalize_prefix_strips_trailing_slash() {
        assert_eq!(normalize_prefix("/opt/gha/"), "/opt/gha");
        assert_eq!(normalize_prefix("/opt/gha"), "/opt/gha");
        assert_eq!(normalize_prefix("/"), "/");
    }

    // ---- user ---------------------------------------------------------

    #[rstest]
    #[case("gha")]
    #[case("gha-runner")]
    #[case("_sys")]
    #[case("x")]
    fn user_accepts(#[case] u: &str) {
        validate_user(u).expect("must accept");
    }

    #[rstest]
    #[case("")]
    #[case("GHA")]
    #[case("1gha")]
    #[case("gha!")]
    #[case("gha x")]
    #[case("gha\n")]
    fn user_rejects(#[case] u: &str) {
        assert!(validate_user(u).is_err(), "must reject {u:?}");
    }

    /// Coarse rejection of clearly-oversize input. The authoritative
    /// boundary is pinned by `user_accepts_at_max_len` /
    /// `user_rejects_one_past_max_len` (USER_MAX_LEN = 31 vs 32). This
    /// test stays as a cheap regression smoke: a far-above-cap length
    /// must still reject. `33` is not the authoritative boundary — it
    /// is just a value comfortably past either cap if the constants
    /// ever drift, catching a bulk regression that disabled the length
    /// gate entirely without depending on the precise threshold.
    #[test]
    fn user_rejects_well_above_max() {
        let s = "a".repeat(33);
        assert!(validate_user(&s).is_err());
    }

    /// Boundary pair: at `USER_MAX_LEN` (= 31) `validate_user` accepts;
    /// at `USER_MAX_LEN + 1` (= 32) it rejects via the explicit length
    /// gate. The 32-char rejection is required because the regex alone
    /// (formerly `{0,31}`) accepted 32-char names but systemd's
    /// strict-mode `valid_user_group_name` would refuse them at
    /// unit-load time. Pinning both endpoints catches an off-by-one
    /// drift in either USER_RE or USER_MAX_LEN.
    #[test]
    fn user_accepts_at_max_len() {
        let s = "a".repeat(USER_MAX_LEN);
        validate_user(&s).expect("must accept exactly USER_MAX_LEN chars");
    }

    /// Companion to `user_accepts_at_max_len`: one char past the cap
    /// must reject with a length-scoped error (not the regex-shape
    /// error). The error must mention USER_MAX_LEN and the systemd
    /// strict-mode source so an operator can act without guessing.
    #[test]
    fn user_rejects_one_past_max_len() {
        let s = "a".repeat(USER_MAX_LEN + 1);
        let err = validate_user(&s).expect_err("must reject one past USER_MAX_LEN");
        match err {
            GharsError::Validation(msg, hint) => {
                assert!(
                    msg.contains("too long") && msg.contains(&USER_MAX_LEN.to_string()),
                    "msg must name the cap; got: {msg}"
                );
                assert!(
                    msg.contains(&SYSTEMD_GROUP_NAME_MAX.to_string()),
                    "msg must explain systemd cap; got: {msg}"
                );
                assert!(
                    hint.contains(&USER_MAX_LEN.to_string()),
                    "hint must restate the cap; got: {hint}"
                );
            }
            other => panic!("expected Validation, got {other:?}"),
        }
    }

    // ---- memory_max ---------------------------------------------------

    #[rstest]
    #[case("")]
    #[case("110G")]
    #[case("4M")]
    #[case("512K")]
    #[case("1024")]
    #[case("50%")]
    #[case("1%")]
    #[case("100%")]
    #[case("infinity")]
    fn memory_max_accepts(#[case] m: &str) {
        validate_memory_max(m).expect("must accept");
    }

    #[rstest]
    #[case("1.5G")]
    #[case("100 GB")]
    #[case("100gb")]
    #[case("0%")]
    #[case("101%")]
    #[case("INFINITY")]
    #[case("5P")]
    #[case("abc")]
    fn memory_max_rejects(#[case] m: &str) {
        assert!(validate_memory_max(m).is_err(), "must reject {m:?}");
    }

    // ---- labels -------------------------------------------------------

    #[rstest]
    #[case("")]
    #[case("label1")]
    #[case("a,b,c")]
    #[case("linux,x64,self-hosted")]
    #[case("with.dot_and-dash")]
    fn labels_accepts(#[case] csv: &str) {
        validate_labels(csv).expect("must accept");
    }

    #[rstest]
    #[case("a,,b")]
    #[case(",leading")]
    #[case("trailing,")]
    #[case("spaces not allowed")]
    #[case("invalid$char")]
    #[case("one/two")]
    fn labels_rejects(#[case] csv: &str) {
        assert!(validate_labels(csv).is_err(), "must reject {csv:?}");
    }

    // ---- sha256 -------------------------------------------------------

    #[test]
    fn sha256_accepts() {
        validate_sha256(&"0".repeat(64)).expect("zeros");
        validate_sha256(&"0123456789abcdef".repeat(4)).expect("lowercase hex");
        validate_sha256(&"ABCDEF0123456789".repeat(4)).expect("mixed-case hex");
    }

    #[rstest]
    #[case("")]
    #[case("not-a-valid-sha256")]
    fn sha256_rejects_misc(#[case] h: &str) {
        assert!(validate_sha256(h).is_err(), "must reject {h:?}");
    }

    #[test]
    fn sha256_rejects_short_long_and_nonhex() {
        assert!(validate_sha256(&"0".repeat(63)).is_err(), "63 chars");
        assert!(validate_sha256(&"0".repeat(65)).is_err(), "65 chars");
        assert!(validate_sha256(&"g".repeat(64)).is_err(), "non-hex");
        assert!(validate_sha256(&"0".repeat(32)).is_err(), "32 chars");
    }

    // ---- version ------------------------------------------------------

    #[test]
    fn version_accepts() {
        validate_version("2.321.0").unwrap();
        validate_version("1.0.0").unwrap();
        validate_version("10.20.30").unwrap();
    }

    #[rstest]
    #[case("")]
    #[case("v2.321.0")]
    #[case("2.321")]
    #[case("2.321.0-rc1")]
    #[case("latest")]
    #[case("2.321.0.1")]
    fn version_rejects(#[case] v: &str) {
        assert!(validate_version(v).is_err(), "must reject {v:?}");
    }

    // ---- runner_tarball -----------------------------------------------

    /// Minimal byte sequence that satisfies the gzip magic check
    /// (`1f 8b`). Real tarballs continue with deflate compression
    /// method + flags + timestamp; the validator only inspects the
    /// first two bytes, so any continuation suffices for tests of
    /// the validator itself. Tests that exercise actual extraction
    /// must build a real archive via `flate2` / `tar` (see
    /// `extract::tests::*build_tar_gz*`).
    const GZIP_MAGIC_PREFIX: &[u8] = &[0x1f, 0x8b, b'f', b'a', b'k', b'e'];

    #[test]
    fn runner_tarball_accepts_regular_file() {
        let dir = TempDir::new().unwrap();
        let p = dir.path().join("t.tar.gz");
        std::fs::write(&p, GZIP_MAGIC_PREFIX).unwrap();
        validate_runner_tarball(p.to_str().unwrap()).unwrap();
    }

    #[test]
    fn runner_tarball_rejects_missing() {
        let dir = TempDir::new().unwrap();
        let p = dir.path().join("missing.tar.gz");
        let err = validate_runner_tarball(p.to_str().unwrap()).expect_err("must error");
        assert!(format!("{err}").contains("does not exist"));
    }

    #[test]
    fn runner_tarball_rejects_symlink() {
        let dir = TempDir::new().unwrap();
        let target = dir.path().join("target");
        std::fs::write(&target, GZIP_MAGIC_PREFIX).unwrap();
        let link = dir.path().join("link");
        std::os::unix::fs::symlink(&target, &link).unwrap();
        let err = validate_runner_tarball(link.to_str().unwrap()).expect_err("must error");
        assert!(format!("{err}").contains("symlink"));
    }

    #[test]
    fn runner_tarball_rejects_directory() {
        let dir = TempDir::new().unwrap();
        let d = dir.path().join("dir");
        std::fs::create_dir(&d).unwrap();
        let err = validate_runner_tarball(d.to_str().unwrap()).expect_err("must error");
        assert!(format!("{err}").contains("regular file"));
    }

    /// A regular file whose first bytes are not the gzip magic
    /// (`1f 8b`) MUST reject. Operators occasionally point
    /// `--runner-tarball` at a saved HTML error page or a JPEG; the
    /// validator surfaces an actionable error at config-load time so
    /// they don't get a cryptic `extract_tarball` failure deep
    /// inside `apply`.
    ///
    /// Format pin: the rejection MUST embed the actual bytes seen
    /// as `got: XX YY`. Operators can attribute the file format
    /// from the error message alone (no `xxd` trip required) — the
    /// HTML fixture starts with `<!` which is `0x3c 0x21`.
    #[test]
    fn runner_tarball_rejects_wrong_magic_bytes() {
        let dir = TempDir::new().unwrap();
        // HTML error page header — a realistic operator footgun. The
        // first two bytes are `<!` = `0x3c 0x21`.
        let p = dir.path().join("notice.tar.gz");
        std::fs::write(&p, b"<!DOCTYPE html>\n<html>\n").unwrap();
        let err = validate_runner_tarball(p.to_str().unwrap()).expect_err("must error");
        let msg = format!("{err}");
        assert!(
            msg.contains("gzip"),
            "rejection must name 'gzip' so the operator knows which format \
             is expected; got: {msg}"
        );
        assert!(
            msg.contains("1f 8b"),
            "rejection must cite the EXPECTED magic bytes so an operator \
             can verify via `xxd | head`; got: {msg}"
        );
        assert!(
            msg.contains("got: 3c 21"),
            "rejection must embed the ACTUAL bytes seen so the operator \
             can attribute the file format from the error alone; got: {msg}"
        );
    }

    /// A file shorter than 2 bytes (cannot contain a valid gzip
    /// header) MUST reject. Pins the partial-read branch.
    ///
    /// Format pin: 1-byte read MUST surface as `got: XX (1 byte)`
    /// so the operator sees both the byte they have AND the
    /// short-read class.
    #[test]
    fn runner_tarball_rejects_under_two_bytes() {
        let dir = TempDir::new().unwrap();
        let p = dir.path().join("tiny.tar.gz");
        std::fs::write(&p, b"\x1f").unwrap(); // 1 byte: half the magic
        let err = validate_runner_tarball(p.to_str().unwrap()).expect_err("must error");
        let msg = format!("{err}");
        assert!(msg.contains("gzip"));
        assert!(
            msg.contains("1 byte"),
            "1-byte short-read must be classed in the message; got: {msg}"
        );
        assert!(
            msg.contains("1f"),
            "the byte that WAS present (0x1f, the legitimate first \
             gzip magic byte) must appear so an operator sees they had \
             a partial download rather than a wrong-format file; got: {msg}"
        );
    }

    /// Empty file MUST surface as `got: <empty file>`. Pins the
    /// `n == 0` branch of the format helper. Without this, a
    /// regression that dropped the empty-file branch would silently
    /// emit `got: 00 00` (zero-init `magic`) and confuse operators
    /// into thinking the file contains zero bytes when it actually
    /// has none readable.
    #[test]
    fn runner_tarball_rejects_empty_file_with_explicit_message() {
        let dir = TempDir::new().unwrap();
        let p = dir.path().join("empty.tar.gz");
        std::fs::write(&p, b"").unwrap();
        let err = validate_runner_tarball(p.to_str().unwrap()).expect_err("must error");
        let msg = format!("{err}");
        assert!(msg.contains("gzip"));
        assert!(
            msg.contains("<empty file>"),
            "empty-file rejection must be explicit (not '00 00'); got: {msg}"
        );
    }

    /// A relative path MUST reject — relative paths resolve
    /// against process CWD which varies between invocations
    /// (operator shell vs. root-via-sudo apply).
    #[test]
    fn runner_tarball_rejects_relative_path() {
        let err =
            validate_runner_tarball("relative/path.tar.gz").expect_err("relative path must reject");
        let msg = format!("{err}");
        assert!(
            msg.contains("absolute"),
            "rejection must name the 'absolute' requirement; got: {msg}"
        );
        assert!(
            msg.contains("relative"),
            "rejection must explicitly call out that the operator passed \
             a relative path; got: {msg}"
        );
    }

    /// Positive pin: an absolute path with valid gzip magic MUST
    /// accept. Pins both gates passing in lockstep.
    #[test]
    fn runner_tarball_accepts_absolute_path_with_gzip_magic() {
        let dir = TempDir::new().unwrap();
        let p = dir.path().join("real.tar.gz");
        std::fs::write(&p, GZIP_MAGIC_PREFIX).unwrap();
        // tempfile gives an absolute path on every platform we
        // support — pin the assertion so a future tempfile change
        // doesn't silently invalidate this test.
        assert!(
            p.is_absolute(),
            "fixture invariant: tempfile path must be absolute"
        );
        validate_runner_tarball(p.to_str().unwrap()).unwrap();
    }

    // ---- identifier ---------------------------------------------------

    #[rstest]
    #[case("a")]
    #[case("ab")]
    #[case("auth-prod")]
    #[case("ccache-pool-1")]
    fn identifier_accepts(#[case] s: &str) {
        validate_identifier(s).expect("must accept");
    }

    #[rstest]
    #[case("")]
    #[case("Auth")]
    #[case("1auth")]
    #[case("auth_prod")]
    #[case("auth.prod")]
    #[case("-auth")]
    #[case("auth-")]
    fn identifier_rejects(#[case] s: &str) {
        assert!(validate_identifier(s).is_err(), "must reject {s:?}");
    }

    // ---- cidr ---------------------------------------------------------

    #[rstest]
    #[case("0.0.0.0/0")]
    #[case("10.0.0.0/8")]
    #[case("192.168.1.0/24")]
    #[case("203.0.113.42/32")]
    #[case("::/0")]
    #[case("fd00::/64")]
    #[case("2001:db8::/32")]
    fn cidr_accepts(#[case] s: &str) {
        validate_cidr(s).expect("must accept");
    }

    #[rstest]
    #[case("")]
    #[case("not-an-ip")]
    #[case("192.168.1.0")]
    #[case("192.168.1.0/")]
    #[case("192.168.1.0/33")]
    #[case("192.168.1.0/-1")]
    #[case("256.0.0.0/8")]
    #[case("10.0.0.0/8 ")]
    #[case(" 10.0.0.0/8")]
    #[case("fd00::/129")]
    fn cidr_rejects(#[case] s: &str) {
        assert!(validate_cidr(s).is_err(), "must reject {s:?}");
    }

    // ---- port ---------------------------------------------------------

    #[test]
    fn port_zero_rejected() {
        assert!(validate_port(0).is_err());
    }

    #[rstest]
    #[case(1)]
    #[case(53)]
    #[case(443)]
    #[case(3128)]
    #[case(50051)]
    #[case(65535)]
    fn port_accepted(#[case] p: u16) {
        validate_port(p).unwrap();
    }

    // ---- egress_rule --------------------------------------------------

    fn egress(addr: &str, port: crate::config::PortSpec) -> crate::config::EgressRule {
        crate::config::EgressRule {
            addr: addr.into(),
            port,
            proto: crate::config::Proto::default(),
            comment: None,
        }
    }

    #[test]
    fn egress_rule_accepts_single_host() {
        validate_egress_rule(&egress(
            "192.168.2.84",
            crate::config::PortSpec::Single(3128),
        ))
        .unwrap();
    }

    #[test]
    fn egress_rule_accepts_cidr() {
        validate_egress_rule(&egress(
            "192.168.2.0/24",
            crate::config::PortSpec::Single(443),
        ))
        .unwrap();
    }

    #[test]
    fn egress_rule_rejects_bad_addr() {
        let err = validate_egress_rule(&egress("not-an-ip", crate::config::PortSpec::Single(80)))
            .expect_err("must reject");
        assert!(format!("{err}").contains("egress addr invalid"));
    }

    #[test]
    fn egress_rule_rejects_port_zero() {
        let err = validate_egress_rule(&egress("10.0.0.1", crate::config::PortSpec::Single(0)))
            .expect_err("must reject port=0");
        assert!(format!("{err}").contains("port 0"));
    }

    #[test]
    fn egress_rule_rejects_empty_port_set() {
        let err = validate_egress_rule(&egress("10.0.0.1", crate::config::PortSpec::Set(vec![])))
            .expect_err("must reject empty set");
        assert!(format!("{err}").contains("port set is empty"));
    }

    #[test]
    fn egress_rule_rejects_zero_in_port_set() {
        let err = validate_egress_rule(&egress(
            "10.0.0.1",
            crate::config::PortSpec::Set(vec![80, 0, 443]),
        ))
        .expect_err("must reject zero in set");
        assert!(format!("{err}").contains("port 0"));
    }

    #[test]
    fn egress_rule_accepts_port_range() {
        validate_egress_rule(&egress(
            "10.0.0.1",
            crate::config::PortSpec::Range {
                start: 1024,
                end: 2048,
            },
        ))
        .unwrap();
    }

    #[test]
    fn egress_rule_rejects_inverted_range() {
        let err = validate_egress_rule(&egress(
            "10.0.0.1",
            crate::config::PortSpec::Range {
                start: 2048,
                end: 1024,
            },
        ))
        .expect_err("must reject inverted range");
        assert!(format!("{err}").contains("range start > end"));
    }

    #[test]
    fn egress_rule_rejects_port_zero_in_range() {
        let err = validate_egress_rule(&egress(
            "10.0.0.1",
            crate::config::PortSpec::Range { start: 0, end: 100 },
        ))
        .expect_err("must reject zero in range");
        assert!(format!("{err}").contains("port 0"));
    }

    // ---- egress_comment (SEC-30) -------------------------------------

    #[test]
    fn egress_comment_accepts_full_safe_set() {
        // Every char in [A-Za-z0-9 _.,:/+-] must pass. Construct one
        // string that contains them all so a regression that drops
        // any single class is caught here.
        let safe = "abcXYZ012 _.,:/+-";
        validate_egress_comment(safe).unwrap();
    }

    #[test]
    fn egress_comment_accepts_empty() {
        // Empty string has no chars and trivially satisfies the
        // allowlist. Mirrors `Option<String>::Some("")` reaching the
        // validator from a sloppy operator config — better to accept
        // empty and emit a no-op `comment ""` than to reject a TOML
        // form that's already syntactically valid.
        validate_egress_comment("").unwrap();
    }

    #[test]
    fn egress_comment_rejects_double_quote() {
        // The renderer wraps the comment in `"..."`. A literal `"`
        // would close the string and let everything after it parse
        // as nft tokens — the canonical SEC-30 attack.
        let err = validate_egress_comment("bad\"quote").expect_err("must reject");
        let msg = format!("{err}");
        assert!(msg.contains("disallowed character"), "got: {msg}");
        // char debug-format of `"` is `'"'`. Match the literal to pin
        // that the offender is named — a future change that drops the
        // `{ch:?}` formatter (e.g. switches to a numeric codepoint)
        // breaks this assertion.
        assert!(msg.contains("'\"'"), "must name the offender: {msg}");
        assert!(msg.contains("position 3"), "must give position: {msg}");
    }

    #[test]
    fn egress_comment_rejects_backslash() {
        // `\` inside an nft string literal is a quoting prefix; even
        // when balanced, it would smuggle escape sequences past the
        // operator's intent.
        let err = validate_egress_comment("escape\\here").expect_err("must reject");
        assert!(format!("{err}").contains("disallowed character"));
    }

    #[test]
    fn egress_comment_rejects_shell_meta() {
        // nft files are loaded by `nft -f`, never by a shell — but
        // copy-pasted comments can end up in shell scripts the
        // operator wraps around ghars. Reject `$ ( ) ;` so a comment
        // that would survive the nft parser still can't smuggle a
        // command if grep'd into a shell context downstream.
        for c in ['$', '(', ')', ';', '`', '|', '&', '\n'] {
            let s = format!("hello{c}world");
            validate_egress_comment(&s)
                .err()
                .unwrap_or_else(|| panic!("must reject char {c:?}"));
        }
    }

    #[test]
    fn egress_comment_accepts_plus_sign() {
        // `+` is in the allowlist alongside `-`; useful for human
        // comments like "8.8.8.8 + 8.8.4.4" or "primary+secondary".
        // It's harmless inside an nft string literal — the nft parser
        // treats `+` as a literal char in `comment "..."`. Pin
        // acceptance so a future tighten doesn't drop it without a
        // visible test failure.
        validate_egress_comment("a+b").unwrap();
        validate_egress_comment("primary+secondary").unwrap();
    }

    #[test]
    fn egress_comment_rejects_non_ascii() {
        // `c.is_ascii_alphanumeric()` is the only `true` branch; any
        // non-ASCII letter (latin-1, accented, or multi-byte UTF-8)
        // is rejected. Pin one representative each: a multi-byte
        // codepoint and a 4-byte codepoint.
        validate_egress_comment("café").expect_err("multi-byte rejected");
        validate_egress_comment("🦀").expect_err("4-byte rejected");
    }

    #[test]
    fn egress_comment_reports_first_offender() {
        // Multiple bad chars: the validator names the FIRST one and
        // its position. Don't silently coalesce — operator should fix
        // the leftmost offender first, then re-run.
        let err = validate_egress_comment("ok\"first;second").expect_err("must reject");
        let msg = format!("{err}");
        assert!(msg.contains("position 2"), "leftmost first: {msg}");
        assert!(msg.contains("'\"'"), "name `\"` not `;`: {msg}");
    }

    #[test]
    fn egress_rule_rejects_unsafe_comment() {
        // SEC-30: validate_egress_rule plumbs the comment through
        // validate_egress_comment. End-to-end so a future refactor
        // that decouples them fails this test.
        let mut rule = egress("10.0.0.1", crate::config::PortSpec::Single(80));
        rule.comment = Some("bad\"quote".into());
        let err = validate_egress_rule(&rule).expect_err("must reject");
        assert!(format!("{err}").contains("disallowed character"));
    }

    #[test]
    fn egress_rule_accepts_safe_comment() {
        // Positive path: a comment in the safe set passes through.
        let mut rule = egress("10.0.0.1", crate::config::PortSpec::Single(80));
        rule.comment = Some("squid proxy 8.8.8.8/32".into());
        validate_egress_rule(&rule).unwrap();
    }

    // ---- dns_mode -----------------------------------------------------

    #[test]
    fn dns_forward_accepted() {
        validate_dns_mode(&crate::config::DnsMode::Forward).unwrap();
    }

    #[test]
    fn dns_static_accepts_one_server() {
        let dns = crate::config::DnsMode::Static {
            servers: vec!["1.1.1.1".parse().unwrap()],
        };
        validate_dns_mode(&dns).unwrap();
    }

    #[test]
    fn dns_static_rejects_empty_servers() {
        let dns = crate::config::DnsMode::Static { servers: vec![] };
        let err = validate_dns_mode(&dns).expect_err("must reject empty");
        assert!(format!("{err}").contains("requires at least one server"));
    }

    // ---- network_spec -------------------------------------------------

    fn netns_spec_with(
        allowed_egress: Vec<crate::config::EgressRule>,
        ip_allow: Vec<IpNet>,
    ) -> crate::config::NetworkSpec {
        crate::config::NetworkSpec {
            mode: crate::config::NetworkMode::Netns,
            allowed_egress,
            ip_allow,
            ip_deny: vec![],
            address_families: vec![],
            dns: crate::config::DnsMode::default(),
            ipv6: crate::config::Ipv6Mode::default(),
        }
    }

    #[test]
    fn network_spec_netns_requires_egress_or_ip_allow() {
        let spec = netns_spec_with(vec![], vec![]);
        let err = validate_network_spec(&spec).expect_err("must reject empty");
        assert!(format!("{err}").contains("no allowed_egress and no ip_allow"));
    }

    #[test]
    fn network_spec_netns_accepts_with_egress() {
        let spec = netns_spec_with(
            vec![egress(
                "192.168.2.84",
                crate::config::PortSpec::Single(3128),
            )],
            vec![],
        );
        validate_network_spec(&spec).unwrap();
    }

    #[test]
    fn network_spec_netns_accepts_with_ip_allow() {
        let spec = netns_spec_with(vec![], vec!["192.168.2.84/32".parse::<IpNet>().unwrap()]);
        validate_network_spec(&spec).unwrap();
    }

    #[test]
    fn network_spec_propagates_egress_rule_failures() {
        let spec = netns_spec_with(
            vec![egress("10.0.0.1", crate::config::PortSpec::Single(0))],
            vec![],
        );
        let err = validate_network_spec(&spec).expect_err("must reject port 0");
        assert!(format!("{err}").contains("port 0"));
    }

    #[test]
    fn network_spec_propagates_dns_failures() {
        let mut spec = netns_spec_with(
            vec![egress("10.0.0.1", crate::config::PortSpec::Single(3128))],
            vec![],
        );
        spec.dns = crate::config::DnsMode::Static { servers: vec![] };
        let err = validate_network_spec(&spec).expect_err("must reject empty dns");
        assert!(format!("{err}").contains("requires at least one server"));
    }

    #[test]
    fn network_spec_open_does_not_require_egress() {
        let spec = crate::config::NetworkSpec {
            mode: crate::config::NetworkMode::Open,
            allowed_egress: vec![],
            ip_allow: vec![],
            ip_deny: vec![],
            address_families: vec![],
            dns: crate::config::DnsMode::default(),
            ipv6: crate::config::Ipv6Mode::default(),
        };
        validate_network_spec(&spec).unwrap();
    }

    // ---- extra_capabilities (SEC-01) ---------------------------------

    #[rstest]
    #[case::admin("CAP_SYS_ADMIN")]
    #[case::ptrace("CAP_SYS_PTRACE")]
    #[case::module("CAP_SYS_MODULE")]
    #[case::rawio("CAP_SYS_RAWIO")]
    #[case::netraw("CAP_NET_RAW")]
    fn extra_capabilities_rejects_denied(#[case] cap: &str) {
        let err = validate_extra_capabilities(&[cap.to_string()])
            .expect_err("must reject denied capability");
        let msg = format!("{err}");
        assert!(msg.contains("denied"), "{msg}");
        assert!(msg.contains(cap), "{msg}");
    }

    #[rstest]
    #[case("cap_sys_admin")]
    #[case("Cap_Sys_Admin")]
    #[case(" CAP_SYS_ADMIN ")]
    fn extra_capabilities_case_and_whitespace_insensitive(#[case] cap: &str) {
        let err = validate_extra_capabilities(&[cap.to_string()])
            .expect_err("must reject regardless of case/whitespace");
        let msg = format!("{err}");
        assert!(
            msg.contains("CAP_SYS_ADMIN") && msg.contains("denied"),
            "{msg}"
        );
    }

    #[rstest]
    #[case("CAP_NET_BIND_SERVICE")]
    #[case("CAP_CHOWN")]
    #[case("CAP_DAC_OVERRIDE")]
    #[case("CAP_AUDIT_WRITE")]
    fn extra_capabilities_accepts_safe(#[case] cap: &str) {
        validate_extra_capabilities(&[cap.to_string()]).expect("must accept benign cap");
    }

    #[test]
    fn extra_capabilities_accepts_empty_list() {
        validate_extra_capabilities(&[]).unwrap();
    }

    #[test]
    fn extra_capabilities_rejects_empty_entry() {
        let err =
            validate_extra_capabilities(&[String::new()]).expect_err("must reject empty token");
        assert!(format!("{err}").contains("empty"));
    }

    #[rstest]
    #[case("not_a_cap")]
    #[case("CAP-SYS-ADMIN")]
    #[case("CAP_!@#")]
    #[case("SYS_ADMIN")]
    fn extra_capabilities_rejects_malformed(#[case] cap: &str) {
        let err = validate_extra_capabilities(&[cap.to_string()])
            .expect_err("must reject malformed cap token");
        assert!(format!("{err}").contains("not a CAP_*"));
    }

    #[test]
    fn extra_capabilities_first_failure_short_circuits() {
        // First entry is benign, second is denied — ensure the function
        // does NOT silently accept the second by stopping at the first.
        let caps = vec!["CAP_CHOWN".into(), "CAP_SYS_ADMIN".into()];
        let err = validate_extra_capabilities(&caps).expect_err("must reject");
        assert!(format!("{err}").contains("CAP_SYS_ADMIN"));
    }

    // ---- extra_bind_paths (SEC-01) -----------------------------------

    #[rstest]
    #[case("/proc/sys")]
    #[case("/proc/sys/")]
    #[case("/proc/sys/net/ipv4")]
    #[case("/sys/kernel/security")]
    #[case("/sys/kernel/security/apparmor")]
    #[case("/proc/sysrq-trigger")]
    #[case("/dev/kmem")]
    #[case("/dev/mem")]
    fn extra_bind_paths_rejects_denied(#[case] p: &str) {
        let paths = vec![camino::Utf8PathBuf::from(p)];
        let err = validate_extra_bind_paths(&paths).expect_err("must reject denied path");
        let msg = format!("{err}");
        assert!(msg.contains("denied") && msg.contains("SEC-01"), "{msg}");
    }

    #[rstest]
    #[case("/etc/pki/ca-trust/source/anchors/ca.pem")]
    #[case("/opt/gha/extra")]
    #[case("/var/cache/sccache")]
    #[case("/srv/share/ro")]
    fn extra_bind_paths_accepts_safe(#[case] p: &str) {
        let paths = vec![camino::Utf8PathBuf::from(p)];
        validate_extra_bind_paths(&paths).expect("must accept benign path");
    }

    #[test]
    fn extra_bind_paths_does_not_substring_match() {
        // `/dev/memfoo` should NOT match `/dev/mem` — component-prefix only.
        let paths = vec![camino::Utf8PathBuf::from("/dev/memfoo")];
        validate_extra_bind_paths(&paths).expect("must not substring-match");
    }

    #[test]
    fn extra_bind_paths_rejects_relative() {
        let paths = vec![camino::Utf8PathBuf::from("etc/foo")];
        let err = validate_extra_bind_paths(&paths).expect_err("must reject relative path");
        assert!(format!("{err}").contains("absolute"));
    }

    #[test]
    fn extra_bind_paths_rejects_empty_entry() {
        let paths = vec![camino::Utf8PathBuf::from("")];
        let err = validate_extra_bind_paths(&paths).expect_err("must reject empty path");
        assert!(format!("{err}").contains("empty"));
    }

    #[test]
    fn extra_bind_paths_accepts_empty_list() {
        validate_extra_bind_paths(&[]).unwrap();
    }

    // ---- hook_script (SEC-12) ----------------------------------------

    /// Detect whether the test process is root WITHOUT calling unsafe.
    /// `unsafe_code = "forbid"` overrides any `#[allow(unsafe_code)]`
    /// (the lint level can only widen). `/proc/self` is owned by the
    /// task's real UID on Linux.
    fn running_as_root() -> bool {
        std::fs::metadata("/proc/self")
            .map(|m| m.uid() == 0)
            .unwrap_or(false)
    }

    fn mk_hook(dir: &TempDir, name: &str, content: &[u8], mode: u32) -> camino::Utf8PathBuf {
        use std::io::Write;
        use std::os::unix::fs::PermissionsExt;
        let path = dir.path().join(name);
        let mut f = std::fs::File::create(&path).unwrap();
        f.write_all(content).unwrap();
        let mut perms = f.metadata().unwrap().permissions();
        perms.set_mode(mode);
        f.set_permissions(perms).unwrap();
        camino::Utf8PathBuf::from_path_buf(path).unwrap()
    }

    #[test]
    fn hook_script_rejects_missing() {
        let p = camino::Utf8PathBuf::from("/nonexistent/ghars/test/hook.sh");
        let err = validate_hook_script(&p).expect_err("must reject missing");
        // open(2) fails with ENOENT — the new error path goes through
        // open_no_follow_with_meta, which surfaces "open failed".
        let msg = format!("{err}");
        assert!(
            msg.contains("open failed") && msg.contains("SEC-12"),
            "{msg}"
        );
    }

    #[test]
    fn hook_script_rejects_symlink() {
        let dir = TempDir::new().unwrap();
        let target = mk_hook(&dir, "real.sh", b"#!/bin/sh\nexit 0\n", 0o755);
        let link_path = dir.path().join("link.sh");
        std::os::unix::fs::symlink(target.as_std_path(), &link_path).unwrap();
        let link = camino::Utf8PathBuf::from_path_buf(link_path).unwrap();
        let err = validate_hook_script(&link).expect_err("must reject symlink");
        // The new O_NOFOLLOW path returns ELOOP from open(2). The
        // hint string in the Validation error mentions "symlink"; the
        // message contains "open failed". Either match confirms the
        // SEC-12 rejection is on the symlink path.
        let msg = format!("{err}");
        assert!(msg.contains("symlink") && msg.contains("SEC-12"), "{msg}");
    }

    #[test]
    fn hook_script_rejects_directory() {
        let dir = TempDir::new().unwrap();
        let sub = dir.path().join("subdir");
        std::fs::create_dir(&sub).unwrap();
        let p = camino::Utf8PathBuf::from_path_buf(sub).unwrap();
        let err = validate_hook_script(&p).expect_err("must reject directory");
        // Directories ARE openable for read on Linux (the resulting fd
        // can be fstat'd, getdents'd, etc.). open() succeeds; the
        // "not a regular file" check fires on the metadata.
        assert!(format!("{err}").contains("regular file"));
    }

    #[test]
    fn hook_script_rejects_relative_path() {
        let p = camino::Utf8PathBuf::from("etc/hooks/pre.sh");
        let err = validate_hook_script(&p).expect_err("must reject relative");
        let msg = format!("{err}");
        assert!(
            msg.contains("not absolute") && msg.contains("SEC-12"),
            "{msg}"
        );
    }

    #[test]
    fn hook_script_rejects_no_owner_exec_bit() {
        let dir = TempDir::new().unwrap();
        // 0o644: rw-r--r--, no owner-exec.
        let p = mk_hook(&dir, "noexec.sh", b"#!/bin/sh\nexit 0\n", 0o644);
        let err = validate_hook_script(&p).expect_err("must reject without owner-exec");
        let msg = format!("{err}");
        // Either the missing-x check fires (when running as root, so
        // owner=0 is satisfied) or the uid check (when not running as
        // root). Both are valid SEC-12 rejections — the field-name in
        // the message ("owner-execute" vs "uid") confirms which.
        assert!(
            msg.contains("owner-execute") || msg.contains("uid"),
            "{msg}",
        );
    }

    #[test]
    fn hook_script_rejects_non_root_owner_when_executable() {
        if running_as_root() {
            // Test irrelevant when running as root — the file we create
            // would be owned by uid 0 and pass.
            return;
        }
        let dir = TempDir::new().unwrap();
        // Owner-exec is set, but the test process is not root, so the
        // UID check fires.
        let p = mk_hook(&dir, "owned.sh", b"#!/bin/sh\nexit 0\n", 0o755);
        let err = validate_hook_script(&p).expect_err("must reject non-root owned");
        let msg = format!("{err}");
        assert!(msg.contains("uid") && msg.contains("SEC-12"), "{msg}");
    }

    #[test]
    fn hook_script_accepts_when_root_owned_and_executable() {
        if !running_as_root() {
            // Cannot create a uid=0 file as a non-root user.
            return;
        }
        let dir = TempDir::new().unwrap();
        let p = mk_hook(&dir, "good.sh", b"#!/bin/sh\nexit 0\n", 0o700);
        validate_hook_script(&p).expect("root + 0700 + non-symlink must pass");
    }

    #[test]
    fn hook_script_rejects_world_writable() {
        // SEC-12 hardening: a world-writable hook script (mode &
        // 0o002 != 0) lets any local user rewrite the script body.
        // The root-owned-script check above is moot if the runner
        // user can chmod its content. We must reject before the
        // unit's hook ExecStart= reads the file.
        if !running_as_root() {
            // The function rejects on uid != 0 first; we'd never
            // reach the mode check.
            return;
        }
        let dir = TempDir::new().unwrap();
        let p = mk_hook(&dir, "ww.sh", b"#!/bin/sh\nexit 0\n", 0o707);
        let err = validate_hook_script(&p)
            .expect_err("world-writable hook script must be rejected");
        let msg = format!("{err}");
        assert!(
            msg.contains("group/world-writable") && msg.contains("SEC-12"),
            "expected world-writable rejection message; got {msg}"
        );
    }

    #[test]
    fn hook_script_rejects_group_writable() {
        // Group-writable (0o020) is the same trust break as
        // world-writable: any member of the file's group can
        // rewrite the body. SEC-12 demands owner-only mutation.
        if !running_as_root() {
            return;
        }
        let dir = TempDir::new().unwrap();
        let p = mk_hook(&dir, "gw.sh", b"#!/bin/sh\nexit 0\n", 0o770);
        let err = validate_hook_script(&p)
            .expect_err("group-writable hook script must be rejected");
        let msg = format!("{err}");
        assert!(
            msg.contains("group/world-writable"),
            "expected group-writable rejection message; got {msg}"
        );
    }

    #[test]
    fn hook_script_rejects_mode_0777_explicitly() {
        // The audit finding cites "mode 0777 passes" as the
        // regression baseline. Pin: 0777 must NOT pass under the
        // new rule.
        if !running_as_root() {
            return;
        }
        let dir = TempDir::new().unwrap();
        let p = mk_hook(&dir, "777.sh", b"#!/bin/sh\nexit 0\n", 0o777);
        let err = validate_hook_script(&p)
            .expect_err("mode 0777 hook script must be rejected");
        let msg = format!("{err}");
        assert!(msg.contains("group/world-writable"), "{msg}");
    }

    #[test]
    fn hook_script_accepts_owner_writable_only() {
        // 0700 passes the root-owned check above and the new
        // group/world-write check (the bits below 0o100 are zero).
        // 0o755 (group/world readable, NOT writable) also passes —
        // owner-write is fine; only group/world-WRITE is forbidden.
        if !running_as_root() {
            return;
        }
        let dir = TempDir::new().unwrap();
        let p = mk_hook(&dir, "ok.sh", b"#!/bin/sh\nexit 0\n", 0o755);
        validate_hook_script(&p)
            .expect("0755 (g/w readable + executable, NOT writable) must pass");
    }

    #[test]
    fn hook_script_rejects_root_parented_absolute_path() {
        // SEC-12 hardening: a hook at `/foo.sh` would have parent
        // `/`, and the renderer's `BindReadOnlyPaths=<parent>`
        // line would mount the entire host into the runner
        // sandbox. Reject pre-render so the operator gets a clear
        // remediation hint pointing at "use a subdirectory".
        // Construct a concrete path under /tmp first to verify the
        // file-existence checks don't reject it before we get to
        // the parent-check, then re-route via a /-parent string.
        let path = camino::Utf8PathBuf::from("/foo.sh");
        let err = validate_hook_script(&path)
            .expect_err("hook with parent=`/` must be rejected");
        let msg = format!("{err}");
        assert!(
            msg.contains("parent directory is `/`") && msg.contains("SEC-12"),
            "expected root-parent rejection; got {msg}"
        );
    }

    #[test]
    fn hook_script_accepts_subdir_parented_path() {
        // Positive control: the same script body under a real
        // subdirectory passes the new parent check (assuming root
        // ownership + correct mode). When not running as root, the
        // validator rejects on uid != 0 first; we just verify the
        // root-parent check is NOT what fires.
        let dir = TempDir::new().unwrap();
        let p = mk_hook(&dir, "ok.sh", b"#!/bin/sh\nexit 0\n", 0o700);
        // The temp dir parent path is `/tmp/...` (not `/`), so
        // the parent check passes. Subsequent checks may reject
        // (uid != 0 when not root), but that's fine — we just
        // assert the root-parent message does NOT appear.
        let result = validate_hook_script(&p);
        if let Err(err) = &result {
            let msg = format!("{err}");
            assert!(
                !msg.contains("parent directory is `/`"),
                "subdir-parented path must NOT trigger root-parent rejection; got {msg}"
            );
        }
    }

    // ---- expanded SEC-01 path denylist -------------------------------

    #[rstest]
    #[case::kmsg("/dev/kmsg")]
    #[case::kallsyms("/dev/kallsyms")]
    #[case::kcore("/proc/kcore")]
    fn extra_bind_paths_rejects_new_denied_static(#[case] p: &str) {
        let paths = vec![camino::Utf8PathBuf::from(p)];
        let err = validate_extra_bind_paths(&paths).expect_err("must reject expanded deny entry");
        let msg = format!("{err}");
        assert!(msg.contains("denied") && msg.contains("SEC-01"), "{msg}");
        assert!(msg.contains(p), "error must name the offending path: {msg}");
    }

    #[rstest]
    #[case::pid_exact("/proc/1")]
    #[case::pid_trailing_slash("/proc/1/")]
    #[case::pid_subdir("/proc/1/cmdline")]
    #[case::pid_long("/proc/123456")]
    #[case::pid_subdir_long("/proc/4242/maps")]
    fn extra_bind_paths_rejects_per_pid_procfs(#[case] p: &str) {
        let paths = vec![camino::Utf8PathBuf::from(p)];
        let err = validate_extra_bind_paths(&paths).expect_err("must reject /proc/<pid>");
        let msg = format!("{err}");
        assert!(
            msg.contains("per-PID procfs") && msg.contains("SEC-01"),
            "{msg}"
        );
    }

    #[rstest]
    #[case::sys_below_proc("/proc/sys/net/ipv4/ip_forward")]
    #[case::nondigit_after_proc("/proc/self/maps")]
    #[case::nondigit_at_proc_root("/proc/cpuinfo")]
    #[case::not_proc_at_all("/procmon/data")]
    #[case::pid_with_trailing_alpha("/proc/12abc")]
    fn extra_bind_paths_per_pid_regex_does_not_overmatch(#[case] p: &str) {
        // None of these is a per-PID match. /proc/sys/... fires the
        // static deny entry; /proc/self, /proc/cpuinfo, /procmon, and
        // /proc/12abc must NOT trip the per-PID regex.
        let paths = vec![camino::Utf8PathBuf::from(p)];
        let result = validate_extra_bind_paths(&paths);
        if let Err(e) = &result {
            let msg = format!("{e}");
            assert!(
                !msg.contains("per-PID procfs"),
                "per-PID regex over-matched {p:?}: {msg}",
            );
        }
    }

    #[test]
    fn open_no_follow_with_meta_rejects_symlink_with_eloop() {
        let dir = TempDir::new().unwrap();
        let target = dir.path().join("real");
        std::fs::write(&target, b"x").unwrap();
        let link = dir.path().join("link");
        std::os::unix::fs::symlink(&target, &link).unwrap();
        let err = open_no_follow_with_meta(&link).expect_err("must reject symlink");
        // ELOOP is the documented kernel return for O_NOFOLLOW + symlink.
        // Confirm the helper surfaces it as raw_os_error so callers can
        // branch (e.g. auth's symlink-specific hint).
        assert_eq!(err.raw_os_error(), Some(libc::ELOOP));
    }

    #[test]
    fn open_no_follow_with_meta_returns_metadata_for_real_file() {
        let dir = TempDir::new().unwrap();
        let path = dir.path().join("real");
        std::fs::write(&path, b"hello").unwrap();
        let (file, meta) = open_no_follow_with_meta(&path).expect("real file opens");
        assert!(meta.file_type().is_file());
        assert_eq!(meta.len(), 5);
        // File handle is usable: read it back.
        use std::io::Read as _;
        let mut buf = String::new();
        let mut f = file;
        f.read_to_string(&mut buf).unwrap();
        assert_eq!(buf, "hello");
    }
}
