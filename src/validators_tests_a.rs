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

/// Past `IDENTIFIER_MAX_LEN` always rejects (the identifier layer
/// is the binding cap for runner names — no separate runner-name
/// cap layers on top). Pinned here so a future loosening of the
/// identifier layer doesn't silently re-introduce 65+ char names.
#[test]
fn runner_name_rejects_one_past_identifier_max_len() {
    let s = "a".repeat(IDENTIFIER_MAX_LEN + 1);
    let err = validate_runner_name(&s).expect_err("must reject one past IDENTIFIER_MAX_LEN");
    match err {
        GharsError::Validation(msg, _) => {
            assert!(
                msg.contains("identifier")
                    && msg.contains("too long")
                    && msg.contains(&IDENTIFIER_MAX_LEN.to_string()),
                "msg must come from validate_identifier; got: {msg}"
            );
            assert!(
                msg.contains(&s),
                "msg must echo the offending name; got: {msg}"
            );
        }
        other => panic!("expected Validation, got {other:?}"),
    }
}

/// `validate_runner_name` accepts a name at exactly
/// `IDENTIFIER_MAX_LEN`. Pins that the validator inherits the
/// identifier cap and does not layer a tighter one on top.
#[test]
fn runner_name_accepts_identifier_max_len() {
    let s = "a".repeat(IDENTIFIER_MAX_LEN);
    validate_runner_name(&s).expect("must accept exactly IDENTIFIER_MAX_LEN");
}

/// Pre-WO-S25N, `validate_runner_name` rejected names longer than
/// the legacy 25-char `RUNNER_NAME_MAX_LEN` holdover cap. The cap
/// was retired because no synthesized identifier embedding the
/// runner name is bounded by it under the current `DynamicUser`
/// model. This test pins that names in the newly-accepted range
/// (26..=63 chars) PASS — a regression that re-introduced the
/// 25-char cap (or any sub-IDENTIFIER_MAX_LEN cap) would surface
/// here. 30 chars is comfortably above the legacy cap and
/// comfortably below `IDENTIFIER_MAX_LEN`.
#[test]
fn runner_name_accepts_above_legacy_cap() {
    let s = "a".repeat(30);
    validate_runner_name(&s).expect("30-char runner name must accept (above legacy 25-char cap)");
}

// ---- cache_pool_name ---------------------------------------------

/// `validate_cache_pool_name` accepts a pool name at exactly
/// `IDENTIFIER_MAX_LEN`. Pins that the validator inherits the
/// identifier cap and does not layer a tighter one on top.
#[test]
fn cache_pool_name_accepts_identifier_max_len() {
    let s = "a".repeat(IDENTIFIER_MAX_LEN);
    validate_cache_pool_name(&s).expect("must accept exactly IDENTIFIER_MAX_LEN");
}

/// `validate_cache_pool_name` rejects one char past
/// `IDENTIFIER_MAX_LEN`. Rejection comes from `validate_identifier`
/// since the cache-pool wrapper does not layer a tighter cap.
#[test]
fn cache_pool_name_rejects_one_past_identifier_max_len() {
    let s = "a".repeat(IDENTIFIER_MAX_LEN + 1);
    let err = validate_cache_pool_name(&s).expect_err("must reject one past IDENTIFIER_MAX_LEN");
    match err {
        GharsError::Validation(msg, _) => {
            assert!(
                msg.contains("identifier")
                    && msg.contains("too long")
                    && msg.contains(&IDENTIFIER_MAX_LEN.to_string()),
                "msg must come from validate_identifier; got: {msg}"
            );
            assert!(
                msg.contains(&s),
                "msg must echo the offending name; got: {msg}"
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

/// Pre-WO-S25N, `validate_cache_pool_name` rejected pool names
/// longer than the legacy 19-char `CACHE_POOL_NAME_MAX_LEN`
/// holdover cap. The cap was retired because no per-pool group is
/// created under `DynamicUser` and the surfaces where the pool name
/// appears (systemd unit instance, UDS path, drop-in dir) are each
/// bounded well above `IDENTIFIER_MAX_LEN`. This test pins that
/// pool names in the newly-accepted range (20..=63 chars) PASS — a
/// regression that re-introduced the 19-char cap (or any
/// sub-IDENTIFIER_MAX_LEN cap) would surface here. 30 chars is
/// comfortably above the legacy cap and comfortably below
/// `IDENTIFIER_MAX_LEN`.
#[test]
fn cache_pool_name_accepts_above_legacy_cap() {
    let s = "a".repeat(30);
    validate_cache_pool_name(&s).expect("30-char pool name must accept (above legacy 19-char cap)");
}

// ---- trust_zone --------------------------------------------------

/// Single-char `trust_zone` must pass — exercises the lower
/// boundary. The validator caps length only (control-char
/// rejection lives in `check_identity_field`), so any 1-char
/// string is accepted.
#[test]
fn trust_zone_accepts_one_char() {
    validate_trust_zone("a").expect("single-char trust_zone must pass");
}

/// A `trust_zone` of exactly `TRUST_ZONE_MAX_LEN` chars MUST pass —
/// the cap is inclusive (the longest accepted, not exclusive).
/// Pins `>` not `>=` at the comparison site.
#[test]
fn trust_zone_accepts_trust_zone_max_len() {
    let s = "a".repeat(TRUST_ZONE_MAX_LEN);
    validate_trust_zone(&s).expect("must accept exactly TRUST_ZONE_MAX_LEN");
}

/// A `trust_zone` one char past `TRUST_ZONE_MAX_LEN` MUST reject.
/// Error message must (a) echo the offending value, (b) contain
/// "too long" and the cap class, (c) cite `SYSTEMD_USER_GROUP_NAME_MAX`
/// or the User=ghars-tz- prefix so the operator understands the
/// derivation, and (d) the hint must restate the cap.
#[test]
fn trust_zone_rejects_one_past_trust_zone_max_len() {
    let s = "a".repeat(TRUST_ZONE_MAX_LEN + 1);
    let err = validate_trust_zone(&s).expect_err("must reject one past TRUST_ZONE_MAX_LEN");
    match err {
        GharsError::Validation(msg, hint) => {
            assert!(
                msg.contains(&s),
                "msg must echo the offending trust_zone; got: {msg}"
            );
            assert!(
                msg.contains("too long") && msg.contains(&TRUST_ZONE_MAX_LEN.to_string()),
                "msg must name the cap class and value; got: {msg}"
            );
            assert!(
                msg.contains(&SYSTEMD_USER_GROUP_NAME_MAX.to_string()) || msg.contains("ghars-tz-"),
                "msg must cite SYSTEMD_USER_GROUP_NAME_MAX or the \
                 User=ghars-tz- prefix; got: {msg}"
            );
            assert!(
                hint.contains(&TRUST_ZONE_MAX_LEN.to_string()),
                "hint must restate the cap; got: {hint}"
            );
        }
        other => panic!("expected Validation, got {other:?}"),
    }
}

/// Uppercase chars MUST reject through the identifier-shape gate
/// BEFORE the `trust_zone` length check. The rejection message
/// must come from `validate_identifier` ("identifier invalid")
/// rather than the length-cap "too long" arm.
#[test]
fn trust_zone_rejects_uppercase() {
    let err = validate_trust_zone("Audited").expect_err("uppercase trust_zone must reject");
    match err {
        GharsError::Validation(msg, _) => {
            assert!(
                msg.contains("identifier invalid"),
                "msg must come from the identifier-shape gate, \
                 not the length cap; got: {msg}"
            );
        }
        other => panic!("expected Validation, got {other:?}"),
    }
}

/// Underscores MUST reject — the identifier shape allows only
/// `[a-z0-9-]`. systemd's `valid_user_group_name` would accept
/// underscores, but ghars's identifier subset is strictly
/// narrower.
#[test]
fn trust_zone_rejects_underscore() {
    let err = validate_trust_zone("audited_zone").expect_err("underscore trust_zone must reject");
    match err {
        GharsError::Validation(msg, _) => {
            assert!(
                msg.contains("identifier invalid"),
                "msg must come from the identifier-shape gate; \
                 got: {msg}"
            );
        }
        other => panic!("expected Validation, got {other:?}"),
    }
}

/// Whitespace MUST reject. Spaces are not in the identifier
/// charset and would also break systemd's user-name parser.
#[test]
fn trust_zone_rejects_space() {
    let err =
        validate_trust_zone("audited zone").expect_err("space-bearing trust_zone must reject");
    match err {
        GharsError::Validation(msg, _) => {
            assert!(
                msg.contains("identifier invalid"),
                "msg must come from the identifier-shape gate; \
                 got: {msg}"
            );
        }
        other => panic!("expected Validation, got {other:?}"),
    }
}

/// Dots MUST reject. systemd's `valid_user_group_name` accepts
/// dots, but ghars's identifier subset uses kebab-case only.
/// Catching here gives operators a single canonical shape across
/// every identifier surface (auth keys, runner names, cache
/// pool names, trust zones).
#[test]
fn trust_zone_rejects_dot() {
    let err = validate_trust_zone("audited.zone").expect_err("dot-bearing trust_zone must reject");
    match err {
        GharsError::Validation(msg, _) => {
            assert!(
                msg.contains("identifier invalid"),
                "msg must come from the identifier-shape gate; \
                 got: {msg}"
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

/// Plant real directories under a `TempDir` so each case opens
/// a real inode and traverses the `Ok((_file, meta))` arm —
/// proving that `validate_prefix` accepts existing directories,
/// not merely missing paths. The varied child names (`gha`,
/// `my_runner`, `runners-1`, `nested/leaf`) cover the
/// underscore-bearing, hyphen-bearing, and deep-nested shapes
/// that all match `PREFIX_RE`. Using static literal paths
/// (`/opt/gha` etc.) would fall through the `ENOENT` catch-all
/// on a typical CI host and never exercise the `is_dir()` gate.
#[test]
fn prefix_accepts_existing_directories() {
    let dir = TempDir::new().unwrap();
    let cases = ["gha", "my_runner", "runners-1", "nested/leaf"];
    for name in cases {
        let p = dir.path().join(name);
        std::fs::create_dir_all(&p).unwrap();
        assert!(p.is_dir(), "fixture invariant: {p:?} must exist as a dir");
        validate_prefix(p.to_str().unwrap())
            .unwrap_or_else(|e| panic!("validate_prefix({p:?}) must accept; got {e}"));
    }
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

/// FIFO at the prefix path. The shared `open_no_follow_with_meta`
/// helper sets `O_NONBLOCK`, so opening the FIFO returns an fd
/// without blocking on a writer; the fstat-based `file_type` gate
/// then rejects it as a non-directory. Without the directory
/// gate, apply would proceed to mkdir-and-chown under the FIFO
/// path and either silently corrupt unrelated state or fail with
/// a deep, unactionable error far from the config-load site.
#[test]
fn prefix_rejects_fifo() {
    use nix::sys::stat::Mode;
    use nix::unistd::mkfifo;
    let dir = TempDir::new().unwrap();
    let fifo_path = dir.path().join("fifo-prefix");
    mkfifo(&fifo_path, Mode::S_IRUSR | Mode::S_IWUSR).unwrap();
    let err = validate_prefix(fifo_path.to_str().unwrap()).expect_err("FIFO must reject");
    let msg = format!("{err}");
    assert!(
        msg.contains("is not a directory"),
        "FIFO rejection must surface via the not-a-directory branch \
         so the operator knows the file type is wrong; got: {msg}"
    );
    // Pin against the ELOOP arm wording specifically. Plain
    // `symlink` appears in the std Debug-formatted FileType field
    // names (`is_symlink: false`), so we match the unique
    // ELOOP-branch phrase rather than the bare token.
    assert!(
        !msg.contains("is a symlink"),
        "FIFO rejection must NOT collapse into the ELOOP branch — \
         the operator would otherwise resolve a non-existent link; \
         got: {msg}"
    );
}

/// Regular file at the prefix path. Catches the same class of
/// operator error that `prefix_rejects_fifo` does (config names
/// an inode of the wrong type) but exercises the most common
/// non-directory case — a stale config pointing at a leftover
/// regular file at the intended prefix path. Pins the error
/// message wording so a future format change doesn't silently
/// degrade the operator-facing diagnostic.
#[test]
fn prefix_rejects_regular_file() {
    let dir = TempDir::new().unwrap();
    let file_path = dir.path().join("regular-prefix");
    std::fs::write(&file_path, b"").unwrap();
    let err = validate_prefix(file_path.to_str().unwrap()).expect_err("regular file must reject");
    let msg = format!("{err}");
    assert!(
        msg.contains("is not a directory"),
        "regular-file rejection must surface via the not-a-directory \
         branch; got: {msg}"
    );
}

/// `ENOTDIR` arm: a prefix path whose walk traverses a regular
/// file (or any non-directory) at an intermediate component
/// must be rejected with "traverses a non-directory" — not
/// silently accepted via the catch-all (which is reserved for
/// `ENOENT` first-install). Without this gate, apply would
/// proceed to `mkdir(prefix)` and fail with the same `ENOTDIR`
/// far from the config-load site, leaving the operator to
/// chase the obstruction from the apply-side error rather than
/// the validate-side one. The fixture plants a regular file at
/// `<tempdir>/blocker` and asserts that
/// `<tempdir>/blocker/leaf` rejects via the new arm.
#[test]
fn prefix_rejects_intermediate_non_directory() {
    let dir = TempDir::new().unwrap();
    let blocker = dir.path().join("blocker");
    std::fs::write(&blocker, b"").unwrap();
    let through = blocker.join("leaf");
    let err = validate_prefix(through.to_str().unwrap())
        .expect_err("path traversing a regular file must reject");
    let msg = format!("{err}");
    assert!(
        msg.contains("traverses"),
        "intermediate-non-directory rejection must surface via the \
         ENOTDIR branch (`traverses a non-directory`); got: {msg}"
    );
    // Pin against the ENOENT catch-all silent acceptance: if the
    // ENOTDIR arm is dropped, the open's ENOTDIR would fall
    // through `Err(_) => {}` and the validator would return Ok.
    // The expect_err above already guards against that, but the
    // additional negative assertion documents intent.
    assert!(
        !msg.contains("symlink"),
        "ENOTDIR rejection must NOT collapse into the ELOOP arm; \
         got: {msg}"
    );
}

/// First-time-install workflow: operator runs `ghars validate` on a
/// brand-new prefix path that does not exist yet (apply will create
/// it). The `O_NOFOLLOW` open returns ENOENT, which `validate_prefix`
/// must tolerate silently and return Ok. Without this pin, a future
/// regression that surfaced ENOENT as a validation error would
/// break the very-first-apply flow without breaking any other test.
#[test]
fn prefix_accepts_nonexistent_path() {
    let dir = TempDir::new().unwrap();
    // Tempdir itself exists; child path does not.
    let nonexistent = dir.path().join("does-not-exist-yet");
    assert!(
        !nonexistent.exists(),
        "fixture invariant: path must not exist"
    );
    validate_prefix(nonexistent.to_str().unwrap())
        .expect("missing path must pass — apply creates the prefix");
}

#[test]
fn normalize_prefix_strips_trailing_slash() {
    assert_eq!(normalize_prefix("/opt/gha/"), "/opt/gha");
    assert_eq!(normalize_prefix("/opt/gha"), "/opt/gha");
    assert_eq!(normalize_prefix("/"), "/");
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

/// Dangling symlink — link exists, target does not. With
/// `O_NOFOLLOW` the kernel returns `ELOOP` (not `ENOENT`) at
/// open(2) time on the link itself, before resolving the missing
/// target. The validator MUST classify this as the "symlink"
/// rejection branch, not "does not exist". Without this pin, a
/// future regression that swapped the ELOOP and ENOENT arms would
/// silently mislabel dangling symlinks as missing files,
/// confusing operators who would fix the wrong problem.
#[test]
fn runner_tarball_rejects_dangling_symlink() {
    let dir = TempDir::new().unwrap();
    let missing_target = dir.path().join("nope.tar.gz");
    let link = dir.path().join("dangling.tar.gz");
    std::os::unix::fs::symlink(&missing_target, &link).unwrap();
    assert!(
        !missing_target.exists(),
        "fixture invariant: target must not exist"
    );
    let err =
        validate_runner_tarball(link.to_str().unwrap()).expect_err("dangling symlink must error");
    let msg = format!("{err}");
    assert!(
        msg.contains("symlink"),
        "ELOOP-from-O_NOFOLLOW on dangling link must surface as the \
         symlink rejection, NOT 'does not exist'; got: {msg}"
    );
    assert!(
        !msg.contains("does not exist"),
        "dangling-symlink rejection must NOT contain 'does not exist' — \
         that wording belongs to the ENOENT arm; got: {msg}"
    );
}

/// Catch-all arm pin: a regular file with mode 0o000 fails
/// `open(O_RDONLY|O_NOFOLLOW)` with `EACCES` (not ELOOP, not
/// ENOENT). The validator must classify this through the catch-
/// all arm at validators.rs (the third match branch in the
/// `open_no_follow_with_meta` `map_err`) rather than misreporting
/// it as missing or as a symlink. Without this pin, a future
/// regression that collapsed the catch-all into the ENOENT arm
/// would tell an operator their readable-but-mode-zero file is
/// "missing" — leading them to recreate the file instead of
/// fixing permissions.
///
/// Skipped when the caller has root DAC bypass: under EUID 0,
/// `open(0o000)` succeeds, the file is empty, and the gate falls
/// through to the magic-byte check. The test body detects the
/// bypass empirically (a successful read of the 0o000 file) and
/// returns early; the production code path is the same in both
/// regimes, only the privilege check differs.
#[test]
fn runner_tarball_rejects_unreadable_file() {
    use std::os::unix::fs::PermissionsExt;
    let dir = TempDir::new().unwrap();
    let p = dir.path().join("unreadable.tar.gz");
    std::fs::write(&p, GZIP_MAGIC_PREFIX).unwrap();
    std::fs::set_permissions(&p, std::fs::Permissions::from_mode(0o000)).unwrap();
    // Detect root DAC bypass empirically. If we (the test) can
    // still read the 0o000 file, the production validator can
    // too, and the EACCES branch we want to exercise is
    // unreachable. Restore mode and skip silently.
    if std::fs::read(&p).is_ok() {
        std::fs::set_permissions(&p, std::fs::Permissions::from_mode(0o644)).unwrap();
        return;
    }
    let err = validate_runner_tarball(p.to_str().unwrap()).expect_err("unreadable file must error");
    let msg = format!("{err}");
    // Restore readable permissions BEFORE assertions so a panic
    // still allows TempDir's Drop to clean up the tree.
    std::fs::set_permissions(&p, std::fs::Permissions::from_mode(0o644)).unwrap();
    assert!(
        !msg.contains("does not exist"),
        "EACCES rejection must NOT collapse into the ENOENT branch \
         — operator would otherwise fix the wrong problem; got: {msg}"
    );
    assert!(
        !msg.contains("not a symlink"),
        "EACCES rejection must NOT collapse into the ELOOP branch; \
         got: {msg}"
    );
    assert!(
        msg.contains("cannot be opened"),
        "EACCES must surface via the catch-all arm wording \
         ('cannot be opened'); got: {msg}"
    );
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
/// `[[runner]].runner_tarball` at a saved HTML error page or a
/// JPEG; the validator surfaces an actionable error at
/// config-load time so they don't get a cryptic
/// `extract_tarball` failure deep inside `apply`.
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

/// Empty path string MUST reject — `Path::new("").is_absolute()`
/// is false, so the validator hits the same "must be absolute"
/// branch as relative paths with segments. Pins the assumption
/// that `merge_defaults` relies on: operator TOML cannot reach
/// the merge-time `.filter(|p| !p.as_str().is_empty())` chain
/// because `validate_runner_tarballs` (cli/load.rs) rejects empty
/// paths first. Without this pin, a stdlib change to
/// `Path::new("").is_absolute()` semantics would silently
/// invalidate the `merge.rs` defense-in-depth-only framing.
#[test]
fn runner_tarball_rejects_empty_path() {
    let err = validate_runner_tarball("").expect_err("empty path must reject");
    let msg = format!("{err}");
    assert!(
        msg.contains("absolute"),
        "empty-path rejection must surface via the 'must be \
         absolute' branch so operator gets the same diagnostic \
         as other non-absolute paths; got: {msg}"
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

/// FIFO regression pin. `open_no_follow_with_meta` sets
/// `O_NONBLOCK` alongside `O_NOFOLLOW` so that opening a FIFO
/// returns immediately rather than blocking until a writer
/// arrives. The validator's fstat-based regular-file gate then
/// rejects the FIFO. Without `O_NONBLOCK` the open(2) call
/// would hang and the test would deadlock; with it, the validator
/// surfaces the rejection through the regular-file branch.
#[test]
fn runner_tarball_rejects_fifo() {
    use nix::sys::stat::Mode;
    use nix::unistd::mkfifo;
    let dir = TempDir::new().unwrap();
    let fifo_path = dir.path().join("pipe.tar.gz");
    mkfifo(&fifo_path, Mode::S_IRUSR | Mode::S_IWUSR).unwrap();
    let err = validate_runner_tarball(fifo_path.to_str().unwrap()).expect_err("FIFO must reject");
    let msg = format!("{err}");
    assert!(
        msg.contains("regular file"),
        "FIFO rejection must surface via the regular-file branch \
         so the operator knows the file type is wrong; got: {msg}"
    );
    assert!(
        !msg.contains("symlink"),
        "FIFO rejection must NOT surface as the symlink branch \
         — operator would otherwise resolve a non-existent link; \
         got: {msg}"
    );
    assert!(
        !msg.contains("does not exist"),
        "FIFO rejection must NOT surface as the ENOENT branch \
         — the FIFO exists, only its file type is wrong; got: {msg}"
    );
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

pub(super) fn egress(addr: &str, port: crate::config::PortSpec) -> crate::config::EgressRule {
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
