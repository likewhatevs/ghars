//! Pure validators for individual fields: identifier regex, GitHub URL
//! shape, sha256 64-hex, runner version `X.Y.Z`, label charset, memory
//! grammar, CIDR.
//!
//! Behavior ported field-for-field from the legacy Python install
//! tool. Every regex and rejection case is preserved verbatim so the
//! parity tests reuse the Python suite directly.

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

use crate::config::{EnvironmentSpec, IDENTIFIER_MAX_LEN, IDENTIFIER_REGEX};
use crate::{GharsError, Result};

/// Path-component prefix used in `<state_dir>/<trust_zone>/ghars-<name>/`,
/// `LogNamespace=ghars-<name>`, and (in netns mode) the host-side veth
/// name `ghars-<name>-h`. Centralized so [`VETH_NAME_OVERHEAD`] derives
/// from `prefix.len()` rather than a hand-counted constant.
pub(crate) const RUNNER_USER_PREFIX: &str = "ghars-";

/// systemd's strict-mode `valid_user_group_name` ceiling: the
/// largest user / group name systemd will accept on `User=` /
/// `Group=` directives. Verified at systemd
/// `src/basic/user-util.c::valid_user_group_name`, which caps every
/// User=/Group= name at `sizeof_field(struct utmpx, ut_user) - 1 = 31`
/// (per `glibc bits/utmpx.h`: `__UT_NAMESIZE = 32` includes the NUL
/// terminator).
pub(crate) const SYSTEMD_USER_GROUP_NAME_MAX: usize = 31;

/// Prefix that systemd's `User=` directive carries for every ghars
/// runner / cache-server unit under the `DynamicUser` model:
/// `User=ghars-tz-<TRUST_ZONE>`. Centralized so [`TRUST_ZONE_MAX_LEN`]
/// derives from `prefix.len()` rather than a hand-counted constant.
pub(crate) const TRUST_ZONE_USER_PREFIX: &str = "ghars-tz-";

/// Largest `trust_zone` whose rendered `DynamicUser` identity
/// `ghars-tz-<TRUST_ZONE>` still fits
/// [`SYSTEMD_USER_GROUP_NAME_MAX`].
///
/// Concretely: `31 - 9 = 22` chars. Catching this at config-load
/// surfaces a scoped error (`runner "NAME":` / `cache_pool "NAME":`)
/// before any unit starts, instead of an opaque systemd
/// `valid_user_group_name` failure during apply.
pub const TRUST_ZONE_MAX_LEN: usize = SYSTEMD_USER_GROUP_NAME_MAX - TRUST_ZONE_USER_PREFIX.len();

// Compile-time underflow guard: if a future edit ever made
// `TRUST_ZONE_USER_PREFIX.len() >= SYSTEMD_USER_GROUP_NAME_MAX`, the
// const subtraction above would underflow at compile time; the
// explicit assert names the invariant ("the rendered DynamicUser name
// shape requires at least one operator-controlled char to remain
// after the prefix").
const _: () = assert!(SYSTEMD_USER_GROUP_NAME_MAX > TRUST_ZONE_USER_PREFIX.len());

/// Linux interface-name buffer size from `<linux/if.h>`. The kernel
/// stores network device names in a fixed-width array of this size,
/// where the last byte is reserved for the trailing NUL — so a NAME's
/// usable byte length is `IFNAMSIZ - 1` (15 chars). `dev_valid_name`
/// in `net/core/dev.c` enforces this on every netlink `RTM_NEWLINK`.
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
/// inherit only the identifier-shape cap [`IDENTIFIER_MAX_LEN`].
pub const NETNS_RUNNER_NAME_MAX_LEN: usize = IFNAMSIZ - 1 - VETH_NAME_OVERHEAD;

// Compile-time underflow guard for the netns runner-name derivation.
// If a future edit ever made `VETH_NAME_OVERHEAD + 1 >= IFNAMSIZ`,
// the const subtraction above would underflow at compile time; the
// explicit assert names the invariant ("the rendered veth name shape
// requires at least one operator-controlled char to remain after the
// prefix + suffix").
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

// systemd `RestrictAddressFamilies=` token shape: `AF_` prefix, then
// `[A-Z0-9_]+`. Anchored on both ends. Validates entries flowing into
// either `Hardening.restrict_address_families` (drops into
// `20-hardening.conf` `RestrictAddressFamilies=` line) or
// `NetworkSpec.restrict_address_families` (drops into `40-network.conf`
// `RestrictAddressFamilies=` line). systemd refuses any token outside
// the AF_* family, but its rejection happens at unit-load time with an
// opaque message; gating at config load surfaces the typo against the
// offending operator field with the offending token quoted verbatim.
static AF_FAMILY_RE: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r"^AF_[A-Z0-9_]+$").expect("AF_FAMILY_REGEX is a compile-time constant")
});

/// Hard cap on the byte length of an `AF_*` token. systemd's
/// `RestrictAddressFamilies=` parser accepts arbitrary identifier
/// shapes but the kernel's `<bits/socket.h>` family names top out
/// well under this. Catching at config load surfaces a structured
/// reject before the unit fails at load time.
const AF_FAMILY_MAX_LEN: usize = 32;

/// `AF_*` aliases that systemd EXCLUDES from
/// `RestrictAddressFamilies=` lookup — operators who write these
/// see opaque "unknown family" errors at unit-load time. Each
/// alias maps to its canonical Linux `<bits/socket.h>` form via
/// `<bits/socket-types.h>` `#define`s; the validator rejects with
/// a "use the canonical X instead" hint so operators converge on
/// the form systemd's parser actually accepts.
///
/// Mirrors `DENY_EXTRA_CAPABILITIES` shape (a static slice of
/// (offending, replacement) pairs); the slice is small enough that
/// linear lookup is cheaper than a `HashMap` and keeps the error path
/// allocation-free.
const AF_FAMILY_ALIASES: &[(&str, &str)] = &[
    ("AF_FILE", "AF_UNIX"),
    ("AF_LOCAL", "AF_UNIX"),
    ("AF_ROUTE", "AF_NETLINK"),
];

/// Bare syscall identifier shape for `Hardening.extra_syscalls`
/// tokens. Lowercase ASCII letter or underscore as the lead char,
/// then alphanumeric + underscore (matches libseccomp's syscall
/// registry naming convention — e.g. `clone3`, `pidfd_open`,
/// `_llseek`, `io_uring_setup`).
///
/// Deliberately REJECTS systemd's other accepted `SystemCallFilter`=
/// shapes:
/// - `@group` syntax (e.g. `@basic-io`, `@privileged`): groups grant
///   bulk syscall surface and `@privileged` carries the `CAP_SYS_ADMIN`-
///   equivalent set, which would bypass the SEC-01 deny-list applied
///   to `extra_capabilities`.
/// - `name:errno` action annotations (e.g. `mount:EPERM`): systemd's
///   `config_parse_syscall_filter` at `systemd/src/core/load-fragment.c`
///   line 3287-3291 silently drops these in allow-list mode (which is
///   the only mode ghars emits), so they would never take effect.
/// - `~`-prefix tokens: see `validate_extra_syscalls` below.
///
/// Operators needing groups or action annotations should file an
/// issue with the concrete use case (mirrors the `extra_capabilities`
/// pattern).
static SYSCALL_NAME_RE: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r"^[a-z_][a-z0-9_]*$").expect("SYSCALL_NAME_REGEX is a compile-time constant")
});

/// Hard cap on the byte length of an `extra_syscalls` token. The
/// longest current Linux syscall name is `landlock_restrict_self`
/// at 22 bytes; 64 leaves substantial headroom for future syscall
/// + architecture-suffix combinations while catching operator-pasted
/// nonsense before it reaches systemd's parser.
const SYSCALL_NAME_MAX_LEN: usize = 64;

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
            format!(
                "identifier {s:?} too long: {} > {IDENTIFIER_MAX_LEN}",
                s.len()
            ),
            format!("shorten the identifier to ≤{IDENTIFIER_MAX_LEN} characters"),
        ));
    }
    if !IDENTIFIER_RE.is_match(s) {
        return Err(validation(
            format!("identifier invalid: {s:?} must match {IDENTIFIER_REGEX}"),
            "use lowercase letters, digits, and dashes; start with a letter; end with a letter or digit",
        ));
    }
    Ok(())
}

/// Validate a runner name (`[[runner]] name`).
///
/// Wrapper over [`validate_identifier`]. The pre-DynamicUser-era
/// tighter cap that used to layer on top of the identifier check has
/// been retired: under the current `DynamicUser` model the per-runner
/// User= is `ghars-tz-<TRUST_ZONE>` (bounded by `trust_zone` length, not
/// runner name) and the synthesized identifiers that DO embed the
/// runner name (`LogNamespace`, `StateDirectory`, `WorkingDirectory`) are
/// each bounded well above `IDENTIFIER_MAX_LEN`. Netns-mode runners
/// face a tighter cap [`NETNS_RUNNER_NAME_MAX_LEN`] enforced separately
/// by `cli::validate_netns_runner_name_lengths`.
///
/// # Errors
///
/// `GharsError::Validation` for any identifier-shape failure.
pub fn validate_runner_name(name: &str) -> Result<()> {
    validate_identifier(name)
}

/// Validate a `[cache_pools.NAME]` key.
///
/// Wrapper over [`validate_identifier`]. The pre-DynamicUser-era
/// tighter cap that used to layer on top of the identifier check has
/// been retired: no per-pool group is created under `DynamicUser` (see
/// `apply.rs::execute_create_cache_pool` "No groupadd" comment), and
/// the surfaces where the pool name appears (the systemd unit instance
/// `ghars-cache@<pool>.service`, the UDS path
/// `/run/ghars/cache-<pool>.sock`, and the drop-in directory) are each
/// bounded well above `IDENTIFIER_MAX_LEN`.
///
/// # Errors
///
/// `GharsError::Validation` for any identifier-shape failure.
pub fn validate_cache_pool_name(name: &str) -> Result<()> {
    validate_identifier(name)
}

/// Validate a `trust_zone` value's shape and length.
///
/// The rendered `DynamicUser` identity for every ghars runner /
/// cache-server unit is `User=ghars-tz-<TRUST_ZONE>`. systemd's
/// strict-mode `valid_user_group_name` rejects any User= name longer
/// than [`SYSTEMD_USER_GROUP_NAME_MAX`] (31 chars) AND any name
/// outside the `[A-Za-z0-9_.-]` charset (no whitespace, no
/// punctuation, no control chars). ghars's identifier shape
/// `^[a-z]([a-z0-9-]*[a-z0-9])?$` is a strict subset of what systemd
/// accepts, so passing the identifier gate guarantees the rendered
/// `ghars-tz-<TRUST_ZONE>` will satisfy `valid_user_group_name`.
///
/// Two-layer gate:
///   1. [`validate_identifier`] — charset + identifier-shape +
///      [`IDENTIFIER_MAX_LEN`] (= 64) length cap. Rejects uppercase,
///      underscores, dots, spaces, hyphens-at-edges, etc.
///   2. [`TRUST_ZONE_MAX_LEN`] (= 22) length cap on top of the
///      64-char identifier cap, derived from the
///      [`SYSTEMD_USER_GROUP_NAME_MAX`] (31) ceiling minus the
///      `ghars-tz-` prefix.
///
/// Catching at config-load surfaces a structured error before any
/// unit starts, instead of an opaque systemd
/// `valid_user_group_name` failure during apply. Control-char
/// rejection in the `trust_zone` string proper is also covered here
/// (via the identifier shape gate); `check_identity_field` /
/// `validate_identity_fields` still runs as defense-in-depth at
/// render time so any future operator-controlled field that flows
/// into `render_identity` without passing through this gate stays
/// covered.
///
/// # Errors
///
/// Returns `GharsError::Validation` when `tz` fails the identifier
/// shape OR `tz.len() > TRUST_ZONE_MAX_LEN`. The "too long" message
/// echoes the offending value, names the cap, and cites the systemd
/// ceiling so the operator understands the constraint.
pub fn validate_trust_zone(tz: &str) -> Result<()> {
    validate_identifier(tz)?;
    if tz.len() > TRUST_ZONE_MAX_LEN {
        return Err(validation(
            format!(
                "trust_zone {tz:?} too long: {} > {TRUST_ZONE_MAX_LEN} \
                 (User=ghars-tz-<TRUST_ZONE> must fit systemd's \
                 {SYSTEMD_USER_GROUP_NAME_MAX}-char user-name ceiling)",
                tz.len(),
            ),
            format!("shorten the trust_zone to ≤{TRUST_ZONE_MAX_LEN} characters",),
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
/// reserved directories (`/`, `/etc`, `/var`, ...), symlinks, any
/// existing inode at the prefix path that is not a directory (regular
/// files, FIFOs, sockets, character/block devices), and prefix paths
/// whose walk traverses a non-directory at an intermediate path
/// component (`ENOTDIR` from open(2)). The symlink check opens the
/// path with `O_NOFOLLOW`; the kernel rejects a final-path-component
/// symlink at open(2) time with `ELOOP`. The final-component file-
/// type check inspects fstat metadata of the opened inode (TOCTOU-
/// safe against the open). When the path does not yet exist, the
/// open returns `ENOENT` and the validator accepts silently — apply
/// creates the prefix on first install.
///
/// Pattern-aligns with [`validate_hook_script`]. The two existence-
/// time gates serve different purposes:
///
/// * **`O_NOFOLLOW` symlink rejection**: codebase consistency. This
///   validator has no production caller chain that would expose a
///   TOCTOU, so the lstat→`O_NOFOLLOW` migration was not driven by
///   a closeable security gap.
/// * **`is_dir()` file-type gate**: operationally load-bearing.
///   Apply mkdir-and-chowns under the prefix, so a non-directory
///   inode (regular file, FIFO, socket, char/block device) at the
///   prefix path would either silently corrupt unrelated state or
///   hang on a FIFO open without this gate. Reject at config-load
///   time so the operator sees an actionable error attached to the
///   prefix field rather than an opaque mkdir/chown failure deep
///   inside apply.
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
    // Open via the shared O_NOFOLLOW helper. ELOOP rejects a final-
    // component symlink; ENOTDIR rejects an intermediate non-directory
    // blocking the walk; ENOENT and other errors pass silently
    // because the prefix may legitimately not exist at validate time
    // (apply creates it). When the open succeeds the prefix already
    // exists, and we assert it is a directory — apply will mkdir-
    // and-chown under it, which would silently corrupt a regular
    // file or hang forever on a FIFO without this gate. The fstat-
    // based file_type check reads metadata of the opened inode, not
    // a re-walked path, so the type assertion is TOCTOU-safe against
    // the open.
    match open_no_follow_with_meta(Path::new(p)) {
        Ok((_file, meta)) => {
            if !meta.file_type().is_dir() {
                return Err(validation(
                    format!(
                        "prefix is not a directory: {p} (file type: {:?})",
                        meta.file_type()
                    ),
                    "use a path that is either an existing directory or \
                     a path that does not yet exist",
                ));
            }
        }
        Err(e) if e.raw_os_error() == Some(libc::ELOOP) => {
            return Err(validation(
                format!("prefix is a symlink; resolve and pass the real path: {p}"),
                "run `readlink -f` and pass the resolved path",
            ));
        }
        Err(e) if e.raw_os_error() == Some(libc::ENOTDIR) => {
            // `ENOTDIR` from open(2) means an intermediate path
            // component is not a directory (a regular file, FIFO,
            // socket, or device blocks the walk). The is_dir() check
            // above only fires when the open SUCCEEDS — so a
            // FIFO/regular-file at, say, `/opt/blocker/gha` would
            // otherwise fall through the catch-all and apply would
            // fail later with the same opaque error this gate is
            // meant to surface earlier.
            return Err(validation(
                format!("prefix path traverses a non-directory: {p}"),
                "an intermediate path component is not a directory; \
                 check for obstructions (a regular file, FIFO, or \
                 device blocking the parent walk)",
            ));
        }
        Err(_) => {}
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
/// Gates applied (in order):
/// 1. Path is absolute. Relative paths resolve against `process CWD`,
///    which varies between `ghars validate` (operator's shell), `ghars
///    apply` (root via sudo), and a future systemd-driven invocation
///    (no CWD guarantee). Pinning to absolute eliminates that footgun.
/// 2. Path opens with `O_NOFOLLOW` — kernel returns `ELOOP` for a
///    symlink in the final component, `ENOENT` for missing, surfaced as
///    distinct validation messages.
/// 3. fstat on the open fd shows a regular file. fstat-on-fd
///    (`File::metadata`) reads the metadata of the inode we hold open,
///    not whatever lives at the path now — closes the lstat-then-open
///    TOCTOU window the previous `symlink_metadata` + `File::open(p)`
///    sequence left open.
/// 4. File begins with the gzip magic bytes `1f 8b`. Operators
///    occasionally point `[[runner]].runner_tarball` at a freshly-
///    downloaded HTML error page, a JPEG, or a partial download. The read happens
///    on the same fd we opened with `O_NOFOLLOW` so the magic bytes are
///    sourced from the same inode whose type we just verified — no
///    re-walk of the path between the type check and the magic-byte
///    read. Catching the format mismatch here surfaces an actionable
///    "not a gzip archive" error at config-load time instead of an
///    opaque `extract_tarball` failure deep inside `apply` (after
///    partial state mutations).
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
    // Open with O_NOFOLLOW first: a symlink in the final component
    // returns ELOOP at open(2) time, and the resulting fd is the
    // single source of truth for both the fstat-based regular-file
    // check and the magic-byte read below. Without this, a
    // symlink_metadata→File::open sequence leaves a TOCTOU window
    // where an attacker swaps a regular file for a symlink between
    // the lstat and the open. The shared helper [`open_no_follow_with_meta`]
    // produces (file, fstat-on-fd metadata); we map its bare
    // io::Error to per-class validation messages so operators see
    // ELOOP, ENOENT, and other failures as distinct errors.
    let (mut f, meta) = open_no_follow_with_meta(p).map_err(|e| match e.raw_os_error() {
        Some(code) if code == libc::ELOOP => validation(
            format!("runner-tarball must be a regular file, not a symlink: {path}"),
            "resolve the link and pass the real path",
        ),
        Some(code) if code == libc::ENOENT => validation(
            format!("runner-tarball file does not exist: {path}"),
            "download the tarball locally and pass the resolved path",
        ),
        _ => validation(
            format!("runner-tarball cannot be opened: {path}: {e}"),
            "verify the file is readable by the user invoking ghars",
        ),
    })?;
    if !meta.file_type().is_file() {
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

/// Validate every field of a `NetworkSpec`. Order is load-bearing:
/// the mode-scoped gate runs FIRST so an operator who put a
/// netns-only field on an Open-mode block sees the structured
/// "this field requires mode = netns" error before any per-rule
/// validation surfaces. Per-rule validation
/// (`validate_egress_rule` over each entry, `validate_dns_mode` on
/// the resolved policy) runs AFTER, so a misconfiguration like
/// "Open mode + bad egress port" surfaces the mode-scope error
/// (which the operator must address first) instead of a per-rule
/// error against rules that wouldn't be applied anyway.
///
/// Mode-scoped invariants (the first-class fail-fast gate):
///
/// - `mode = "netns"` requires at least one of `allowed_egress` /
///   `ip_allow` (a fully-isolated netns runner is almost certainly
///   a misconfiguration — design Part 9c "validation").
/// - `mode = "open"` rejects `allowed_egress` (no namespace, no nft —
///   the rules would be silently ignored and the operator would
///   discover the gap by observing unfiltered egress).
/// - `mode = "open"` rejects non-default `dns` (the DNS resolution
///   policy applies inside the netns; Open-mode runners inherit
///   the host's `/etc/resolv.conf` and the field would be silently
///   ignored).
/// - `mode = "open"` rejects `ipv6 = Enabled` (IPv6 ULA allocation is
///   a Netns-mode artifact; Open-mode runners share the host's
///   IPv6 stack).
///
/// `ip_allow`, `ip_deny`, and `restrict_address_families` are honored
/// in BOTH modes (cgroup-BPF and `RestrictAddressFamilies=` apply at
/// the cgroup layer regardless of namespace), so neither mode rejects
/// them.
///
/// # Errors
///
/// Returns `GharsError::Validation` on the first failing rule.
pub fn validate_network_spec(spec: &crate::config::NetworkSpec) -> Result<()> {
    // Stage 1: mode-scoped gate. Runs before per-rule validation so
    // an Open-mode block carrying netns-only fields produces the
    // mode-scope error rather than per-rule errors against fields
    // that wouldn't be applied. Netns mode's "requires egress or
    // ip_allow" check stays here too — it's a mode-shape invariant,
    // not a per-rule check.
    match spec.mode {
        crate::config::NetworkMode::Netns => {
            if spec.allowed_egress.is_empty() && spec.ip_allow.is_empty() {
                return Err(validation(
                    "netns network has no allowed_egress and no ip_allow",
                    "a fully-isolated netns runner can't reach the network at all; \
                    list at least one allowed_egress entry or ip_allow CIDR",
                ));
            }
        }
        crate::config::NetworkMode::Open => {
            if !spec.allowed_egress.is_empty() {
                return Err(validation(
                    "allowed_egress requires mode = netns; nft rules are not generated for open mode",
                    "remove the allowed_egress entries, or change mode to \"netns\" \
                     (Open-mode runners share the host netns; egress filtering at \
                     the netfilter layer is a netns artifact). Cgroup-BPF gating \
                     via ip_allow / ip_deny works in either mode.",
                ));
            }
            if !matches!(spec.dns, crate::config::DnsMode::Forward) {
                return Err(validation(
                    "dns requires mode = netns; open-mode runners inherit the host's /etc/resolv.conf",
                    "remove the dns block (it defaults to Forward, the only sensible \
                     setting for open mode), or change mode to \"netns\" so the per-\
                     runner resolver policy actually applies",
                ));
            }
            if matches!(spec.ipv6, crate::config::Ipv6Mode::Enabled) {
                return Err(validation(
                    "ipv6 = enabled requires mode = netns; open-mode runners share the host's IPv6 stack",
                    "remove the ipv6 setting (defaults to disabled, which means \"do \
                     nothing extra in the netns\" and is consistent with sharing the \
                     host stack), or change mode to \"netns\" so the per-runner ULA \
                     allocation actually happens",
                ));
            }
        }
    }
    // Stage 2: per-rule validation. Reached only when the mode-
    // scoped invariants pass. Egress rules are guaranteed to apply
    // (Netns mode) — Open mode short-circuited above with
    // allowed_egress non-empty, so the loop below runs only for
    // Netns. DNS mode validation runs in both modes (Open's
    // restriction to Forward was checked above; this validates
    // Static's servers list non-empty for Netns).
    // restrict_address_families validation runs in both modes —
    // the directive applies at the cgroup layer regardless of
    // namespace, so the AF_* token shape gate is mode-independent.
    for rule in &spec.allowed_egress {
        validate_egress_rule(rule)?;
    }
    validate_dns_mode(&spec.dns)?;
    validate_restrict_address_families(
        "restrict_address_families",
        &spec.restrict_address_families,
    )?;
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
///   `pivot_root`, ptrace any task, ioctl on block devices, set hostname,
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

/// Filesystem paths ghars refuses to add to `BindReadOnlyPaths=`
/// via `Hardening.extra_bind_paths`. Mounting any of these into
/// the runner namespace re-exposes a host-control surface the
/// systemd profile takes care to hide:
/// - `/proc/sys` — kernel sysctls. Read-only is enough for
///   fingerprinting.
/// - `/sys/kernel/security` — securityfs (`SELinux`, `AppArmor`, `IMA`).
/// - `/proc/sysrq-trigger` — even read-only mount makes the file
///   path present, re-exposing a host-control surface.
/// - `/dev/kmem`, `/dev/mem` — raw kernel/physical memory.
/// - `/dev/kmsg` — kernel ring buffer. Read-only is still an
///   info-leak (the runner can read all dmesg output, including
///   driver / module / hardware fingerprints).
/// - `/dev/kallsyms` — kernel symbol-to-address map. Even read-only
///   defeats `KASLR`.
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
    Regex::new(r"^/proc/[0-9]+($|/)").expect("PROC_PID_RE is a compile-time constant")
});

/// Validate every entry in a `restrict_address_families` list
/// (used by both `Hardening.restrict_address_families` and
/// `NetworkSpec.restrict_address_families`). Each token must:
///
/// 1. Be non-empty (a stray comma in TOML produces an empty string
///    between commas).
/// 2. Be at most [`AF_FAMILY_MAX_LEN`] = 32 bytes (defense-in-depth
///    against operator-pasted nonsense; real AF_* tokens are well
///    under this).
/// 3. Match the systemd `RestrictAddressFamilies=` shape
///    `AF_[A-Z0-9_]+`. Case-sensitive: `af_unix` is not equivalent
///    to `AF_UNIX` for systemd, and accepting the lowercase form
///    would let an operator's silent-failure-shape typo slip
///    through (the operator wrote `af_unix`, the unit loaded with
///    nothing matching, and the workload exhibited unexpected
///    egress failures at runtime).
/// 4. Not appear in [`AF_FAMILY_ALIASES`] — systemd EXCLUDES
///    `AF_FILE`/`AF_LOCAL`/`AF_ROUTE` from its parser; operators
///    who write these see opaque "unknown family" errors at
///    unit-load time. The validator rejects with a "use the
///    canonical X instead" hint so operators converge on the form
///    systemd's parser actually accepts.
///
/// systemd itself refuses any non-`AF_*` token at unit-load time
/// with an opaque error; gating at config load surfaces the typo
/// against the offending operator field with the offending token
/// quoted verbatim.
///
/// `field_label` is interpolated into the error message so the
/// operator sees which field carried the bad token (e.g.
/// `"hardening.restrict_address_families"` for the hardening site,
/// or just `"restrict_address_families"` for the per-network site
/// where the `[network.NAME]:` block scope is prepended by
/// `validate_networks` upstream).
///
/// # Errors
///
/// Returns `GharsError::Validation` on the first entry that fails
/// any of the gates above.
pub fn validate_restrict_address_families(field_label: &str, families: &[String]) -> Result<()> {
    for entry in families {
        if entry.is_empty() {
            return Err(validation(
                format!("{field_label} entry is empty"),
                "remove the empty token; a stray comma in TOML can produce \
                 an empty string between commas in the resulting Vec",
            ));
        }
        if entry.len() > AF_FAMILY_MAX_LEN {
            return Err(validation(
                format!(
                    "{field_label} entry {entry:?} is {} bytes; \
                     real AF_* tokens are well under {AF_FAMILY_MAX_LEN}",
                    entry.len(),
                ),
                "shorten or replace the token; if the value really is a \
                 systemd address-family name longer than 32 bytes, file an \
                 issue with the systemd reference",
            ));
        }
        if !AF_FAMILY_RE.is_match(entry) {
            return Err(validation(
                format!(
                    "{field_label} entry {entry:?} is not a valid AF_* token; \
                     systemd RestrictAddressFamilies= rejects any non-AF_* \
                     family at unit-load time",
                ),
                "use systemd address-family tokens like AF_UNIX, AF_INET, \
                 AF_INET6, AF_NETLINK; see systemd.exec(5) RestrictAddressFamilies= \
                 for the supported list. Tokens are case-sensitive; lowercase \
                 forms (e.g. \"af_unix\") are not accepted",
            ));
        }
        for (alias, canonical) in AF_FAMILY_ALIASES {
            if entry == alias {
                return Err(validation(
                    format!(
                        "{field_label} entry {entry:?} is excluded by systemd's \
                         RestrictAddressFamilies= parser; use the canonical \
                         {canonical:?} instead",
                    ),
                    format!(
                        "replace {alias} with {canonical}; \
                         systemd's <bits/socket-types.h> defines {alias} as an \
                         alias for {canonical}, but its parser only accepts the \
                         canonical name",
                    ),
                ));
            }
        }
    }
    Ok(())
}

/// Validate `Hardening.extra_capabilities` (SEC-01).
///
/// Each entry must satisfy:
/// - Equal to its own trimmed form (no surrounding whitespace). The
///   renderer at `units::render_hardening` emits tokens via
///   `Vec::join(" ")` verbatim, so a whitespace-padded token would
///   produce different on-disk bytes (and a different `spec_hash`)
///   from the equivalent unpadded form, triggering a spurious in-place
///   `UpdateRunner` cascade across cosmetically-equivalent TOML —
///   mirroring the byte-equality contract `merge_hardening` enforces
///   via sort+dedup for the Vec ordering.
/// - Non-empty.
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
        if raw.as_str() != trimmed {
            return Err(validation(
                format!(
                    "extra_capabilities entry {raw:?} has surrounding whitespace; \
                     ghars's renderer emits the raw token verbatim into the \
                     CapabilityBoundingSet= line, so a whitespace-padded token \
                     would produce different on-disk bytes (and a different \
                     spec_hash) from the equivalent unpadded form, triggering \
                     a spurious in-place UpdateRunner cascade across \
                     cosmetically-equivalent TOML (the next `ghars apply` \
                     would restart your runners even though systemd's \
                     runtime effect is identical to the unpadded form)"
                ),
                "remove the leading/trailing whitespace from the token",
            ));
        }
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

/// Validate `Hardening.extra_syscalls` (SEC-01).
///
/// Each entry must satisfy:
/// - Equal to its own trimmed form (no surrounding whitespace). The
///   renderer at `units::render_hardening` emits tokens via
///   `Vec::join(" ")` verbatim, so a whitespace-padded token would
///   produce different on-disk bytes (and a different `spec_hash`)
///   from the equivalent unpadded form, triggering a spurious in-place
///   `UpdateRunner` cascade across cosmetically-equivalent TOML —
///   mirroring the byte-equality contract `merge_hardening` enforces
///   via sort+dedup for the Vec ordering.
/// - Non-empty.
/// - Not start with `~`. systemd's `SystemCallFilter=` parser at
///   `systemd/src/core/load-fragment.c` line 3238-3241 checks
///   `rvalue[0] == '~'` on the WHOLE directive value and, if set,
///   flips the directive from allow-list to deny-list semantics for
///   ALL subsequent tokens. A single `~`-prefix token in an
///   otherwise-empty Vec joins to `"~foo"` (`rvalue[0] == '~'`) and
///   flips the polarity; in a mixed Vec, `~` (ASCII 0x7E) sorts AFTER
///   all alphanumerics so the `~`-prefix token lands at the END of
///   the joined directive and is silently dropped by libseccomp as
///   an unknown syscall name. Both outcomes contradict the operator's
///   stated intent of "extend the allowlist"; rejecting at config-
///   load shape-check eliminates both — mirrors how `AF_FAMILY_RE`
///   intrinsically rejects `~`-prefix for `validate_restrict_address_families`.
/// - Not start with `@`. systemd treats `@group` (e.g. `@basic-io`,
///   `@privileged`) as a syscall-group reference. Granting groups
///   bypasses the SEC-01 deny-list applied to `extra_capabilities`
///   (e.g. `@privileged` carries CAP_SYS_ADMIN-equivalent syscalls).
/// - Not contain `:`. systemd parses `name:errno` as an action
///   annotation, but the parser silently drops these in allow-list
///   mode (`load-fragment.c:3287-3291`: `if (!invert && num >= 0) ...
///   log_syntax ... continue`). ghars emits `SystemCallFilter`= in
///   allow-list mode only, so `:errno` tokens have no effect.
/// - Match [`SYSCALL_NAME_RE`] (`^[a-z_][a-z0-9_]*$`). Catches
///   embedded whitespace, control characters, uppercase, leading
///   digits, hyphens, and Unicode that libseccomp's
///   `sym_seccomp_syscall_resolve_name` would warning-log and silently
///   drop.
/// - Length ≤ [`SYSCALL_NAME_MAX_LEN`] (64 bytes).
///
/// # Errors
///
/// Returns `GharsError::Validation` on the first offending token. The
/// message names `extra_syscalls`, quotes the rejected token verbatim,
/// and provides a remediation hint pointing at systemd.exec(5)
/// `SystemCallFilter=` for the supported allow-list-style bare-name
/// form.
pub fn validate_extra_syscalls(syscalls: &[String]) -> Result<()> {
    for raw in syscalls {
        let trimmed = raw.trim();
        if raw.as_str() != trimmed {
            return Err(validation(
                format!(
                    "extra_syscalls entry {raw:?} has surrounding whitespace; \
                     ghars's renderer emits the raw token verbatim into the \
                     SystemCallFilter= line, so a whitespace-padded token \
                     would produce different on-disk bytes (and a different \
                     spec_hash) from the equivalent unpadded form, \
                     triggering a spurious in-place UpdateRunner cascade \
                     across cosmetically-equivalent TOML (the next \
                     `ghars apply` would restart your runners even though \
                     systemd's runtime effect is identical to the unpadded \
                     form)"
                ),
                "remove the leading/trailing whitespace from the token",
            ));
        }
        if trimmed.is_empty() {
            return Err(validation(
                "extra_syscalls entry is empty",
                "remove the empty token from [hardening.extra_syscalls]",
            ));
        }
        if trimmed.starts_with('~') {
            return Err(validation(
                format!(
                    "extra_syscalls entry {trimmed:?} starts with `~`; \
                     systemd treats a leading `~` on the SystemCallFilter= \
                     directive as a deny-list polarity flip. A single \
                     `~`-prefix token in the Vec joins to a directive value \
                     whose first byte is `~` and flips systemd's polarity; \
                     even in a mixed Vec where the `~` token sorts to the \
                     end (ASCII 0x7E > alphanumerics) and is silently \
                     dropped by libseccomp, the operator's intent is \
                     subverted"
                ),
                "drop the `~` prefix; ghars emits SystemCallFilter= in \
                 allow-list mode only. If you need to remove a syscall \
                 the template grants, file an issue with the use case",
            ));
        }
        if trimmed.starts_with('@') {
            return Err(validation(
                format!(
                    "extra_syscalls entry {trimmed:?} starts with `@`; \
                     systemd treats `@`-prefixed tokens as syscall groups, \
                     but ghars rejects them at config-load because groups \
                     like `@privileged` grant CAP_SYS_ADMIN-equivalent \
                     syscall surface, bypassing the SEC-01 deny-list \
                     applied to extra_capabilities"
                ),
                "use bare syscall names (e.g. `clone3`, `rseq`, \
                 `pidfd_open`); see systemd.exec(5) SystemCallFilter= \
                 for the bare-name form. If you need a specific group, \
                 file an issue with the use case",
            ));
        }
        if trimmed.contains(':') {
            return Err(validation(
                format!(
                    "extra_syscalls entry {trimmed:?} contains `:`; \
                     systemd treats `name:errno` as an action annotation \
                     valid only in deny-list mode, but ghars emits \
                     SystemCallFilter= in allow-list mode where such \
                     tokens are silently dropped"
                ),
                "drop the `:errno` suffix; ghars's allow-list mode does \
                 not support action annotations",
            ));
        }
        if trimmed.len() > SYSCALL_NAME_MAX_LEN {
            return Err(validation(
                format!(
                    "extra_syscalls entry {trimmed:?} is {} bytes; real \
                     syscall names top out under {SYSCALL_NAME_MAX_LEN}",
                    trimmed.len(),
                ),
                "shorten the token; if it really is a systemd-supported \
                 syscall name longer than 64 bytes, file an issue with \
                 the systemd reference",
            ));
        }
        if !SYSCALL_NAME_RE.is_match(trimmed) {
            return Err(validation(
                format!(
                    "extra_syscalls entry {trimmed:?} is not a valid \
                     syscall name; ghars accepts only bare lowercase \
                     ASCII syscall identifiers (e.g. `clone3`, `rseq`, \
                     `pidfd_open`)"
                ),
                "use systemd syscall tokens like `clone3`, `rseq`, \
                 `pidfd_open`, `io_uring_setup`; see systemd.exec(5) \
                 SystemCallFilter= for the supported list. Tokens are \
                 case-sensitive lowercase",
            ));
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
/// `O_NONBLOCK` is set alongside `O_NOFOLLOW` so that opening a fifo
/// returns immediately rather than blocking on a writer. Every caller
/// inspects `file_type()` on the returned metadata to reject
/// unexpected inode types before consuming the fd:
/// `validate_runner_tarball`, `validate_hook_script`,
/// `verify_local_tarball_open`, and `read_root_owned_0600` require
/// regular files; `validate_prefix` requires a directory. A fifo at
/// the final path component would hang the open syscall until a
/// writer arrived if `O_NONBLOCK` were absent — only the final inode
/// is opened, so FIFOs at intermediate path components would yield
/// `ENOTDIR` regardless of `O_NONBLOCK`.
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
        .custom_flags(libc::O_NOFOLLOW | libc::O_NONBLOCK)
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
    // SEC-12 hardening: reject hook scripts whose parent resolves to
    // the filesystem root after component-walk normalization. Covers
    // literal `/`, `//`, `/.`, `/foo/..` and other root-equivalent
    // textual forms — all would emit `BindReadOnlyPaths=/<parent>`
    // lines that systemd resolves to `/` at unit-load, exposing the
    // entire host filesystem to the runner.
    if let Some(parent) = path.parent()
        && (parent.as_str().is_empty()
            || crate::path_util::binds_filesystem_root(parent))
    {
        return Err(validation(
            format!(
                "hook script {path}: parent directory `{parent}` resolves \
                 to filesystem root (SEC-12); BindReadOnlyPaths=/ would \
                 expose the entire host to the runner"
            ),
            "place the hook under a dedicated subdirectory \
                 (e.g. /usr/local/lib/ghars-hooks/<name>.sh) so the \
                 BindReadOnlyPaths bind targets a narrow tree",
        ));
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
            format!("hook script {path}: mode {mode:o} has group/world-writable bits set (SEC-12)",),
            "chmod go-w <path> so only root can modify the script",
        ));
    }
    Ok(())
}

/// Tier 1 env var names: shared-library injection class. Operators
/// setting `LD_PRELOAD` etc. would let arbitrary `.so` files load into
/// every workflow step.
const RESERVED_LD_FAMILY: &[&str] = &[
    "LD_PRELOAD",
    "LD_LIBRARY_PATH",
    "LD_AUDIT",
    "LD_DEBUG",
    "LD_DEBUG_OUTPUT",
    "LD_BIND_NOW",
    "LD_BIND_NOT",
    "LD_PROFILE",
    "LD_TRACE_LOADED_OBJECTS",
    "GLIBC_TUNABLES",
    "MALLOC_TRACE",
];

/// Tier 2 env var names: shell-execution hijacking. `BASH_ENV` /
/// `ENV` source a script at non-interactive bash/sh start; `IFS`
/// hijacks word splitting; `PS4` / `PROMPT_COMMAND` execute on prompt.
const RESERVED_SHELL_HIJACK: &[&str] = &[
    "IFS",
    "BASH_ENV",
    "ENV",
    "BASHOPTS",
    "SHELLOPTS",
    "PS4",
    "PROMPT_COMMAND",
];

/// Tier 3 env var names: ghars-owned. The renderer emits these from
/// `trust_zone` / `name` / cache bindings / proxy / hooks; operator
/// override would shadow framework-emitted values and silently break
/// the layered configuration. Use the dedicated config surfaces
/// instead (`[defaults] trust_zone`, `[[cache_pools.NAME]]`,
/// `[proxy]`, `[[runner.hooks]]`).
const RESERVED_GHARS_OWNED: &[&str] = &[
    "PATH",
    "HOME",
    "USER",
    "LOGNAME",
    "SHELL",
    "TMPDIR",
    "LANG",
    "CCACHE_DIR",
    "CCACHE_MAXSIZE",
    "KTSTR_LOCK_DIR",
    "KTSTR_CACHE_DIR",
    "SCCACHE_SERVER_UDS",
    "SCCACHE_DIR",
    "SCCACHE_NO_DAEMON",
    "SCCACHE_CACHE_SIZE",
    "HTTP_PROXY",
    "http_proxy",
    "HTTPS_PROXY",
    "https_proxy",
    "NO_PROXY",
    "no_proxy",
    "ACTIONS_RUNNER_INPUT_TOKEN",
    "ACTIONS_RUNNER_HOOK_JOB_STARTED",
    "ACTIONS_RUNNER_HOOK_JOB_COMPLETED",
    "RUNNER_ALLOW_RUNASROOT",
];

/// POSIX env-var-name shape regex: leading letter or underscore, then
/// uppercase letters / digits / underscores. `systemd.exec(5)`'s
/// `Environment=` parser accepts a broader set, but `Runner.Listener`'s
/// `.env` consumer and most workflow shell scripts treat lowercase /
/// punctuated names as suspicious. Strict-uppercase is the principled
/// shape for operator-declared env vars.
static ENV_VAR_NAME_REGEX: LazyLock<Regex> =
    LazyLock::new(|| Regex::new(r"^[A-Z_][A-Z0-9_]*$").expect("env var name regex compiles"));

/// Validate operator-declared `[defaults.environment]` /
/// `[runner.environment]` block at config-load. Iterates over `vars`,
/// `path_prepend`, `path_append` calling the per-field helpers.
///
/// # Errors
///
/// Returns `GharsError::Validation` on the first failing key / value /
/// path entry. Each error names the offending input and the rationale
/// (security-tier, ghars-owned, POSIX-shape, or path-syntax) so the
/// operator learns the security model from the rejection.
pub fn validate_environment_spec(spec: &EnvironmentSpec) -> Result<()> {
    for (key, value) in &spec.vars {
        validate_env_var_name(key)?;
        validate_env_var_value(key, value)?;
    }
    for p in &spec.path_prepend {
        validate_path_segment("path_prepend", p)?;
    }
    for p in &spec.path_append {
        validate_path_segment("path_append", p)?;
    }
    Ok(())
}

/// Reject empty / non-POSIX / deny-listed env-var names with per-tier
/// rationale.
fn validate_env_var_name(name: &str) -> Result<()> {
    if name.is_empty() {
        return Err(validation(
            "operator-declared env var name is empty".to_string(),
            "every entry in [defaults.environment].vars / [runner.environment].vars must have a non-empty key",
        ));
    }
    if RESERVED_LD_FAMILY.contains(&name) {
        return Err(validation(
            format!("env var name `{name}` is rejected (LD_* env vars enable shared-library injection — dynamic-loader attack surface)"),
            "pick a different name; if you need to override loader behavior for a specific workflow, do it inside a wrapper script the step invokes",
        ));
    }
    if RESERVED_SHELL_HIJACK.contains(&name) {
        return Err(validation(
            format!("env var name `{name}` is rejected (BASH_ENV / IFS / etc. enable shell-execution hijacking before workflow steps see env)"),
            "pick a different name; shell behavior should be configured inside the step's script, not via cross-step env",
        ));
    }
    if RESERVED_GHARS_OWNED.contains(&name) {
        let dedicated = match name {
            "PATH" => "use environment.path_prepend / environment.path_append",
            "HOME" | "USER" | "LOGNAME" | "SHELL" | "TMPDIR" => "set by the runner unit per trust_zone — not operator-configurable",
            "LANG" => "fixed to C.UTF-8 by ghars",
            "CCACHE_DIR" | "CCACHE_MAXSIZE" => "set via [[cache_pools.NAME]] kinds = [\"ccache\"]",
            "KTSTR_LOCK_DIR" | "KTSTR_CACHE_DIR" => "set per trust_zone by ghars",
            n if n.starts_with("SCCACHE_") => "set via [[cache_pools.NAME]] kinds = [\"sccache\"]",
            "HTTP_PROXY" | "http_proxy" | "HTTPS_PROXY" | "https_proxy" | "NO_PROXY" | "no_proxy" => "set via [proxy] / [[runner.proxy]]",
            "ACTIONS_RUNNER_INPUT_TOKEN" => "set by the runner-registration flow; operator override would corrupt registration",
            "ACTIONS_RUNNER_HOOK_JOB_STARTED" | "ACTIONS_RUNNER_HOOK_JOB_COMPLETED" => "set via [[runner.hooks]]",
            "RUNNER_ALLOW_RUNASROOT" => "ghars never runs the runner as root; operator override would not change that",
            _ => "use the dedicated config surface for this key",
        };
        return Err(validation(
            format!("env var name `{name}` is rejected (rendered into Environment= and .env from ghars internal state — use a different key)"),
            dedicated,
        ));
    }
    if !ENV_VAR_NAME_REGEX.is_match(name) {
        return Err(validation(
            format!("env var name `{name}` does not match POSIX env-var-name shape `^[A-Z_][A-Z0-9_]*$`"),
            "operator-declared env var names must use uppercase letters, digits, and underscores only, with a leading letter or underscore",
        ));
    }
    Ok(())
}

/// Reject env-var values containing control characters (`\n` / `\r` /
/// `\0` would inject a second `Environment=` directive line in
/// 00-ghars.conf or a second `KEY=VALUE` line in .env, allowing
/// operator-supplied data to escape its value position and forge a
/// new env var).
fn validate_env_var_value(key: &str, value: &str) -> Result<()> {
    for c in value.chars() {
        if c == '\n' || c == '\r' || c == '\0' || c.is_control() {
            return Err(validation(
                format!("env var `{key}` value contains a control character (newline / carriage return / NUL / other control char)"),
                "values must be single-line printable text; multi-line values would inject a second Environment= directive into 00-ghars.conf and a second KEY=VALUE line into .env",
            ));
        }
    }
    Ok(())
}

/// Reject empty / non-absolute / `:`-containing / control-char-
/// containing path segments. The `:` character is the PATH separator;
/// embedding it in a single segment would silently split the entry.
fn validate_path_segment(field: &str, p: &camino::Utf8PathBuf) -> Result<()> {
    let s = p.as_str();
    if s.is_empty() {
        return Err(validation(
            format!("{field} entry is empty"),
            "every entry must be a non-empty absolute path",
        ));
    }
    if !p.is_absolute() {
        return Err(validation(
            format!("{field} entry `{s}` is not an absolute path"),
            "PATH segments must be absolute (relative paths are workflow-step CWD-dependent and would silently resolve unpredictably)",
        ));
    }
    for c in s.chars() {
        if c == ':' {
            return Err(validation(
                format!("{field} entry `{s}` contains `:`"),
                "`:` is the PATH separator; embed it in a single segment and the entry silently splits — use multiple entries instead",
            ));
        }
        if c == '\n' || c == '\r' || c == '\0' || c.is_control() {
            return Err(validation(
                format!("{field} entry `{s}` contains a control character"),
                "PATH segments must be single-line printable text — multi-line entries would corrupt the rendered .path file and 00-ghars.conf Environment=PATH= line",
            ));
        }
    }
    Ok(())
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used)]
#[path = "validators_tests_a.rs"]
mod tests_a;

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used)]
#[path = "validators_tests_b.rs"]
mod tests_b;
