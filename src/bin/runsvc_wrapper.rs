//! Verify-only runsvc trampoline.
//!
//! Invoked from the runner unit as:
//!
//! ```text
//! ExecStart=/usr/lib/ghars/runsvc-wrapper %i
//! ```
//!
//! No prefix. The trampoline runs at the unit's
//! DynamicUser-allocated identity (`User=ghars-tz-<TRUST_ZONE>` set
//! by the per-runner 00-ghars.conf drop-in). The unit's full sandbox
//! stays applied — filesystem-namespacing, system-call filter,
//! network namespace, capability bounding set, and other directives
//! all remain in force because no `!` or `+` prefix is present
//! (verified against systemd's `src/core/exec-invoke.c::needs_sandboxing`,
//! which is gated on `EXEC_COMMAND_FULLY_PRIVILEGED` — set ONLY by
//! `+`).
//!
//! What the binary does, in order:
//! 1. Validate `argv[1]` (the systemd `%i` instance name) against the
//!    runner-name regex so a malformed unit cannot pass shell-special
//!    characters into our path construction.
//! 2. Open
//!    `/etc/systemd/system/ghars-runner@<INSTANCE>.service.d/00-ghars.conf`
//!    with `O_NOFOLLOW`, parse it, extract the
//!    `X-Ghars-Runsvc-Sha256` value from the `[Service]` section.
//!    Reading the file directly is required because systemd's
//!    `conf-parser.c:160` silently drops `X-*` keys on parse — they
//!    are never exposed via D-Bus properties.
//! 3. Open `/var/lib/ghars/<TRUST_ZONE>/ghars-<INSTANCE>/runsvc.sh`
//!    with `O_NOFOLLOW | O_RDONLY`. Verify `fstat()` reports a regular
//!    file with at least owner-execute (`S_IXUSR`).
//! 4. Compute SHA256 of the opened fd's full contents. Compare to the
//!    annotation. On mismatch refuse to exec — the on-disk
//!    runsvc.sh has changed since `ghars apply` recorded its hash,
//!    and exec'ing it would persist arbitrary code across restarts.
//! 5. Clear `FD_CLOEXEC` on the script fd. The kernel's
//!    `binfmt_script` handler (`fs/binfmt_script.c:93` checking
//!    `BINPRM_FLAGS_PATH_INACCESSIBLE`) refuses to interpret a script
//!    when the source fd is close-on-exec, because the interpreter
//!    needs to re-open `/proc/self/fd/N` post-exec.
//! 6. `fexecve(fd, argv, envp)` on the verified fd. The kernel
//!    re-resolves the binary via `/proc/self/fd/N`, runs the
//!    shebang's interpreter, and never refers back to the path we
//!    opened — closing the open-then-rename TOCTOU window the
//!    runner could otherwise exploit. NO setuid/setgid/setgroups —
//!    DynamicUser= already established the runner identity before
//!    this binary ever started.
//!
//! On any failure the binary writes a single actionable line to
//! stderr (which systemd captures into the journal under the unit's
//! `LogNamespace=`) and exits non-zero. The exit codes are stable so
//! the journal grep target stays consistent across releases — see
//! the [`exit_code`] module.

#![forbid(unsafe_code)]

use std::ffi::{CString, OsString};
use std::fs::File;
use std::io::{Read, Write};
use std::os::fd::AsRawFd;
use std::os::unix::ffi::OsStringExt;
use std::os::unix::fs::{MetadataExt, OpenOptionsExt};
use std::path::PathBuf;
use std::process::ExitCode;

use nix::fcntl::{FcntlArg, FdFlag, fcntl};
use sha2::{Digest, Sha256};

/// Stable exit codes. Operators / journal queries rely on these to
/// distinguish "argv malformed" from "integrity check failed" from
/// "exec failed at the kernel boundary" — a single non-zero would
/// leave incident response guessing.
mod exit_code {
    pub const ARGV_INVALID: u8 = 2;
    pub const ANNOTATION_MISSING: u8 = 3;
    pub const SCRIPT_OPEN_FAILED: u8 = 4;
    pub const SCRIPT_NOT_REGULAR_OR_NOT_EXEC: u8 = 5;
    pub const SHA256_MISMATCH: u8 = 6;
    pub const FD_CLOEXEC_CLEAR_FAILED: u8 = 7;
    pub const FEXECVE_FAILED: u8 = 8;
    pub const INTERNAL_ERROR: u8 = 9;
}

/// Runner instance regex: matches the `IDENTIFIER_REGEX` from
/// `config.rs:24` (and the upstream Python tool). systemd is supposed
/// to keep `%i` template values in this shape but a misconfigured
/// drop-in could pass anything; defending here costs nothing.
fn instance_name_is_valid(name: &str) -> bool {
    let bytes = name.as_bytes();
    if bytes.is_empty() {
        return false;
    }
    if !bytes[0].is_ascii_lowercase() {
        return false;
    }
    if bytes.len() == 1 {
        return true;
    }
    let last = bytes[bytes.len() - 1];
    if !(last.is_ascii_lowercase() || last.is_ascii_digit()) {
        return false;
    }
    for b in &bytes[1..bytes.len() - 1] {
        if !(b.is_ascii_lowercase() || b.is_ascii_digit() || *b == b'-') {
            return false;
        }
    }
    true
}

/// Find the value of a key in a specific section of a systemd-style
/// unit/drop-in body. Mirrors `state.rs::ParsedUnit` for the subset
/// the wrapper needs — section headers `[NAME]`, `KEY=VALUE` lines,
/// `#` / `;` comments. Continuation lines (trailing `\`) are not
/// supported because `render_identity` never emits one for X-Ghars-
/// annotations; a continuation in 00-ghars.conf would indicate
/// tampering and we'd rather fail than try to follow it.
fn find_section_key<'a>(body: &'a str, section: &str, key: &str) -> Option<&'a str> {
    let mut current_section: Option<&str> = None;
    for raw in body.lines() {
        let line = raw.trim();
        if line.is_empty() {
            continue;
        }
        if let Some(c) = line.chars().next() {
            if c == '#' || c == ';' {
                continue;
            }
        }
        if let Some(stripped) = line.strip_prefix('[').and_then(|s| s.strip_suffix(']')) {
            current_section = Some(stripped);
            continue;
        }
        let Some(sec) = current_section else {
            continue;
        };
        if sec != section {
            continue;
        }
        let Some((k, v)) = line.split_once('=') else {
            continue;
        };
        if k.trim() == key {
            return Some(v.trim());
        }
    }
    None
}

/// `sha256:HEX` annotation form. Lowercase hex, exactly 64 chars.
fn annotation_well_formed(value: &str) -> bool {
    let Some(hex) = value.strip_prefix("sha256:") else {
        return false;
    };
    hex.len() == 64 && hex.bytes().all(|b| matches!(b, b'0'..=b'9' | b'a'..=b'f'))
}

/// Hash a fully-buffered fd via `Read` into an owned `sha256:HEX`
/// string. The fd must already be at offset 0; on return the caller
/// should NOT depend on the position.
fn sha256_of_reader<R: Read>(mut r: R) -> std::io::Result<String> {
    let mut hasher = Sha256::new();
    let mut buf = [0u8; 64 * 1024];
    loop {
        let n = r.read(&mut buf)?;
        if n == 0 {
            break;
        }
        hasher.update(&buf[..n]);
    }
    Ok(format!("sha256:{}", hex::encode(hasher.finalize())))
}

fn drop_in_path(instance: &str) -> PathBuf {
    PathBuf::from(format!(
        "/etc/systemd/system/ghars-runner@{instance}.service.d/00-ghars.conf"
    ))
}

fn runsvc_path(trust_zone: &str, instance: &str) -> PathBuf {
    PathBuf::from(format!(
        "/var/lib/ghars/{trust_zone}/ghars-{instance}/runsvc.sh"
    ))
}

/// Single failure-path helper. systemd's journal already prefixes
/// every line with the unit name; we just emit the actionable detail.
fn die(code: u8, msg: impl AsRef<str>) -> ExitCode {
    let mut stderr = std::io::stderr().lock();
    let _ = writeln!(stderr, "ghars-runsvc-wrapper: {}", msg.as_ref());
    ExitCode::from(code)
}

fn main() -> ExitCode {
    let mut args = std::env::args_os();
    let _self = args.next();
    let Some(instance_os) = args.next() else {
        return die(
            exit_code::ARGV_INVALID,
            "missing INSTANCE argv[1] — invoke as `runsvc-wrapper <instance>` from the runner unit's ExecStart",
        );
    };
    let Some(instance) = instance_os.to_str() else {
        return die(
            exit_code::ARGV_INVALID,
            "INSTANCE argv[1] is not valid UTF-8",
        );
    };
    if !instance_name_is_valid(instance) {
        return die(
            exit_code::ARGV_INVALID,
            format!(
                "INSTANCE argv[1] {instance:?} fails the runner-name regex \
                 ^[a-z]([a-z0-9-]*[a-z0-9])?$ — refusing to construct paths \
                 from a non-canonical name"
            ),
        );
    }

    // --- Step 1: read the integrity annotation from 00-ghars.conf ----
    let drop_in = drop_in_path(instance);
    let drop_in_body = match read_file_no_follow(&drop_in) {
        Ok(b) => b,
        Err(e) => {
            return die(
                exit_code::ANNOTATION_MISSING,
                format!(
                    "open drop-in {}: {e} — has `ghars apply` finished writing \
                     this runner's unit + drop-ins?",
                    drop_in.display()
                ),
            );
        }
    };
    let drop_in_text = match std::str::from_utf8(&drop_in_body) {
        Ok(s) => s,
        Err(_) => {
            return die(
                exit_code::ANNOTATION_MISSING,
                format!(
                    "drop-in {} is not valid UTF-8 — re-run `ghars apply` to \
                     regenerate the file",
                    drop_in.display()
                ),
            );
        }
    };
    let Some(expected) = find_section_key(drop_in_text, "Service", "X-Ghars-Runsvc-Sha256") else {
        return die(
            exit_code::ANNOTATION_MISSING,
            format!(
                "drop-in {} is missing [Service] X-Ghars-Runsvc-Sha256 — re-run \
                 `ghars apply` to record the runsvc.sh hash",
                drop_in.display()
            ),
        );
    };
    if !annotation_well_formed(expected) {
        return die(
            exit_code::ANNOTATION_MISSING,
            format!(
                "X-Ghars-Runsvc-Sha256={expected:?} in {} is not in `sha256:HEX` \
                 form (64 lowercase hex chars after `sha256:`) — drop-in \
                 corruption, re-run `ghars apply`",
                drop_in.display()
            ),
        );
    }
    let expected_owned = expected.to_owned();

    // Trust-zone resolution: read X-Ghars-Trust-Zone from the [Unit]
    // section of the same drop-in. Defaults to "default" when the
    // annotation is absent or empty (matches plan::reconstruct_identity).
    let trust_zone = find_section_key(drop_in_text, "Unit", "X-Ghars-Trust-Zone")
        .filter(|t| !t.is_empty())
        .unwrap_or("default")
        .to_owned();

    // --- Step 2: open + integrity-check runsvc.sh -------------------
    let script_path = runsvc_path(&trust_zone, instance);
    let script_file = match open_no_follow_rdonly(&script_path) {
        Ok(f) => f,
        Err(e) => {
            return die(
                exit_code::SCRIPT_OPEN_FAILED,
                format!(
                    "open runsvc.sh {} with O_NOFOLLOW failed: {e} — if the \
                     path was replaced by a symlink an attacker may be \
                     attempting persistent RCE; do not start the unit until \
                     `ghars apply` is rerun",
                    script_path.display()
                ),
            );
        }
    };
    let meta = match script_file.metadata() {
        Ok(m) => m,
        Err(e) => {
            return die(
                exit_code::SCRIPT_OPEN_FAILED,
                format!("fstat runsvc.sh {}: {e}", script_path.display()),
            );
        }
    };
    if !meta.file_type().is_file() {
        return die(
            exit_code::SCRIPT_NOT_REGULAR_OR_NOT_EXEC,
            format!(
                "runsvc.sh {} is not a regular file — refusing to exec",
                script_path.display()
            ),
        );
    }
    // Owner-execute bit is the minimum for fexecve to succeed; the
    // tarball install (`extract::install_runner_binary`) lays
    // runsvc.sh down as 0755, so any other mode means tampering or
    // operator interference.
    if meta.mode() & 0o100 == 0 {
        return die(
            exit_code::SCRIPT_NOT_REGULAR_OR_NOT_EXEC,
            format!(
                "runsvc.sh {} mode {:o} lacks owner-execute — refusing to exec",
                script_path.display(),
                meta.mode() & 0o7777
            ),
        );
    }

    let actual = match sha256_of_reader(&script_file) {
        Ok(s) => s,
        Err(e) => {
            return die(
                exit_code::SCRIPT_OPEN_FAILED,
                format!("read runsvc.sh {}: {e}", script_path.display()),
            );
        }
    };
    if actual != expected_owned {
        return die(
            exit_code::SHA256_MISMATCH,
            format!(
                "runsvc.sh integrity check failed for runner {instance} \
                 (expected {expected_owned}, got {actual}) — runsvc.sh has \
                 changed since `ghars apply`; run `ghars apply` to restore \
                 or investigate tampering"
            ),
        );
    }

    // --- Step 3: clear FD_CLOEXEC on the script fd -------------------
    // binfmt_script.c:93 refuses to interpret a script when the source
    // fd is FD_CLOEXEC because the kernel constructs `/proc/self/fd/N`
    // as the effective path and the script interpreter needs that
    // path to be readable post-exec. Rust's std opens with O_CLOEXEC
    // by default; clear it just before fexecve.
    let script_fd = script_file.as_raw_fd();
    if let Err(e) = fcntl(script_fd, FcntlArg::F_SETFD(FdFlag::empty())) {
        return die(
            exit_code::FD_CLOEXEC_CLEAR_FAILED,
            format!("clear FD_CLOEXEC on runsvc.sh fd: {e}"),
        );
    }

    // --- Step 4: fexecve the verified fd ----------------------------
    let argv0 = match CString::new(script_path.as_os_str().as_encoded_bytes()) {
        Ok(c) => c,
        Err(_) => {
            return die(
                exit_code::INTERNAL_ERROR,
                format!(
                    "runsvc.sh path {} contains a NUL byte",
                    script_path.display()
                ),
            );
        }
    };
    // Inherit the unit's full Environment= via std::env. With no
    // ExecStart= prefix the unit's Environment= directives are applied
    // verbatim before the trampoline starts, so each `KEY=VALUE` in
    // std::env is already what the unit configured.
    let env_strs: Vec<OsString> = std::env::vars_os()
        .map(|(k, v)| {
            let mut combined = OsString::with_capacity(k.len() + 1 + v.len());
            combined.push(&k);
            combined.push("=");
            combined.push(&v);
            combined
        })
        .collect();
    let mut envp: Vec<CString> = Vec::with_capacity(env_strs.len());
    for s in env_strs {
        match CString::new(s.into_vec()) {
            Ok(c) => envp.push(c),
            Err(_) => {
                return die(
                    exit_code::INTERNAL_ERROR,
                    "an environment variable contains a NUL byte — refusing to exec",
                );
            }
        }
    }
    let argv: [CString; 1] = [argv0];

    // On success fexecve does not return; the only path back is an
    // error.
    let err = nix::unistd::fexecve(script_fd, &argv, &envp).err();
    let errno = err.map_or_else(
        || "fexecve returned without error but did not replace the process".to_string(),
        |e| format!("fexecve failed: {e}"),
    );
    die(
        exit_code::FEXECVE_FAILED,
        format!(
            "{errno} — runsvc.sh integrity verified, but the kernel could not \
             exec it (interpreter missing? /proc not mounted? sandbox \
             restrictions?)"
        ),
    )
}

/// Open `path` for read with `O_NOFOLLOW`, mirroring
/// `auth.rs::read_root_owned_0600`'s style. `O_NOFOLLOW` makes
/// `open(2)` itself fail with `ELOOP` when the target is a symlink,
/// closing the lstat-then-open TOCTOU.
fn open_no_follow_rdonly(path: &std::path::Path) -> std::io::Result<File> {
    std::fs::OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_NOFOLLOW)
        .open(path)
}

fn read_file_no_follow(path: &std::path::Path) -> std::io::Result<Vec<u8>> {
    let mut f = open_no_follow_rdonly(path)?;
    let mut buf = Vec::new();
    f.read_to_end(&mut buf)?;
    Ok(buf)
}

#[cfg(test)]
#[allow(clippy::unwrap_used)]
mod tests {
    use super::*;

    #[test]
    fn instance_name_accepts_canonical_runner_names() {
        assert!(instance_name_is_valid("buckos"));
        assert!(instance_name_is_valid("ci-1"));
        assert!(instance_name_is_valid("a"));
        assert!(instance_name_is_valid("a0"));
        assert!(instance_name_is_valid("ktstr-1"));
        assert!(instance_name_is_valid("rust-build-1"));
    }

    #[test]
    fn instance_name_rejects_anything_else() {
        // Empty — nothing to construct paths from.
        assert!(!instance_name_is_valid(""));
        // Leading digit.
        assert!(!instance_name_is_valid("1ci"));
        // Trailing dash.
        assert!(!instance_name_is_valid("ci-"));
        // Uppercase.
        assert!(!instance_name_is_valid("Buckos"));
        // Path separator — would let an attacker traverse out of
        // /var/lib/ghars/<TRUST_ZONE>/ghars-<INSTANCE>/.
        assert!(!instance_name_is_valid("ci/foo"));
        // Shell metacharacter — defense in depth even though we never
        // pass INSTANCE to a shell.
        assert!(!instance_name_is_valid("ci$x"));
        // NUL.
        assert!(!instance_name_is_valid("ci\0x"));
        // Whitespace.
        assert!(!instance_name_is_valid("ci x"));
        // `..` — fails the runner-name regex
        // `^[a-z]([a-z0-9-]*[a-z0-9])?$`. Defense-in-depth against
        // hypothetical path-traversal even though the
        // format!("ghars-{instance}") interpolation would produce
        // a literal `ghars-..` directory component (not a
        // parent-reference) under the
        // `/var/lib/ghars/<TRUST_ZONE>/ghars-<INSTANCE>/` path
        // shape.
        assert!(!instance_name_is_valid(".."));
    }

    #[test]
    fn find_section_key_extracts_value_from_named_section() {
        let body = "[Unit]\nX-Ghars-Spec-Hash=sha256:abc\n\n[Service]\n\
                    X-Ghars-Runsvc-Sha256=sha256:def\n";
        assert_eq!(
            find_section_key(body, "Service", "X-Ghars-Runsvc-Sha256"),
            Some("sha256:def")
        );
    }

    #[test]
    fn find_section_key_distinguishes_sections_with_same_key() {
        // If a malformed drop-in put X-Ghars-Runsvc-Sha256 under
        // [Unit] (the wrong section), the wrapper must NOT pick it up.
        // The annotation table places it in [Service]; mismatch =
        // tampering or a bug.
        let body = "[Unit]\nX-Ghars-Runsvc-Sha256=sha256:wrong\n[Service]\n\
                    Description=foo\n";
        assert_eq!(
            find_section_key(body, "Service", "X-Ghars-Runsvc-Sha256"),
            None
        );
    }

    #[test]
    fn find_section_key_skips_comments_and_blank_lines() {
        let body = "# top comment\n\n; semicolon comment\n[Service]\n\
                    # inside section\nX-Ghars-Runsvc-Sha256=sha256:abc\n";
        assert_eq!(
            find_section_key(body, "Service", "X-Ghars-Runsvc-Sha256"),
            Some("sha256:abc")
        );
    }

    #[test]
    fn find_section_key_returns_first_match_in_order() {
        // systemd treats consecutive scalar `Key=` assignments as
        // last-wins, but for our annotation we emit it once. Document
        // current behavior: first-match in source order. If the
        // renderer ever emits two we'd want last-match — change here
        // and add a regression test then.
        let body = "[Service]\nX-Ghars-Runsvc-Sha256=sha256:first\n\
                    X-Ghars-Runsvc-Sha256=sha256:second\n";
        assert_eq!(
            find_section_key(body, "Service", "X-Ghars-Runsvc-Sha256"),
            Some("sha256:first")
        );
    }

    // -- parser divergence vs state.rs (anti-tampering posture) ----------

    #[test]
    fn find_section_key_does_not_follow_continuation_lines() {
        // state.rs::ParsedUnit joins trailing `\` continuations into a
        // single logical line. The wrapper deliberately does NOT (per
        // doc-comment lines 121-124): a continuation in 00-ghars.conf
        // would indicate tampering. Test that the trailing `\` is
        // preserved verbatim in the captured value, so
        // annotation_well_formed will reject it (not 64 hex chars).
        let body = "[Service]\nX-Ghars-Runsvc-Sha256=sha256:abc\\\n  def\n";
        let value = find_section_key(body, "Service", "X-Ghars-Runsvc-Sha256")
            .expect("find_section_key returns Some");
        // Trailing `\` is part of the value, not a continuation marker.
        assert!(
            value.ends_with('\\'),
            "expected trailing backslash in raw value, got {value:?}"
        );
        // The well-formedness check rejects it: not 64 lowercase hex
        // chars, so main() would surface ANNOTATION_MISSING.
        assert!(
            !annotation_well_formed(value),
            "annotation_well_formed must reject continuation form"
        );
    }

    #[test]
    fn find_section_key_preserves_inline_equals_sign_in_value() {
        // line.split_once('=') splits on the FIRST `=` only, so a value
        // containing additional `=` characters is preserved verbatim.
        // Verify the captured value matches the part after the first
        // `=` even when it itself contains `=`.
        let body = "[Service]\nKey=val=ue=more\n";
        assert_eq!(
            find_section_key(body, "Service", "Key"),
            Some("val=ue=more")
        );
    }

    #[test]
    fn find_section_key_silently_drops_assignment_with_empty_key() {
        // `=value` splits to ("", "value") — k.trim() is empty. The
        // current code's `if k.trim() == key` only matches when key is
        // also empty (which never happens for our annotations), so the
        // bad assignment is silently skipped. Verify a real key still
        // resolves correctly even when an empty-key line precedes it.
        let body = "[Service]\n=stale\nX-Ghars-Runsvc-Sha256=sha256:good\n";
        assert_eq!(
            find_section_key(body, "Service", "X-Ghars-Runsvc-Sha256"),
            Some("sha256:good")
        );
        // An asked-for empty key would resolve to the dropped value
        // (theoretical — main() never calls with an empty key).
        assert_eq!(find_section_key(body, "Service", ""), Some("stale"));
    }

    #[test]
    fn find_section_key_first_wins_diverges_from_systemd_last_wins() {
        // Pin the wrapper's first-match semantics. systemd's
        // conf-parser.c uses last-wins; the wrapper's parser uses
        // first-wins. Today render_identity emits the annotation once,
        // so this never matters in production. If a future change
        // emits two assignments (or an attacker injects a second), the
        // wrapper would validate the FIRST value while systemd reads
        // the LAST — a parser-divergence attack surface.
        //
        // This test pins the divergence so any future change to the
        // wrapper that flips it to last-wins fires a regression and
        // forces explicit review.
        let body = "[Service]\nX-Ghars-Runsvc-Sha256=sha256:first\n\
                    X-Ghars-Runsvc-Sha256=sha256:second\n\
                    X-Ghars-Runsvc-Sha256=sha256:third\n";
        assert_eq!(
            find_section_key(body, "Service", "X-Ghars-Runsvc-Sha256"),
            Some("sha256:first"),
            "wrapper uses first-match semantics; if this fails the wrapper now matches systemd's last-wins, which means the annotation table contract changed",
        );
    }

    #[test]
    fn annotation_well_formed_accepts_canonical_form() {
        // 64 lowercase hex chars after the `sha256:` prefix — what
        // sha256_of_reader emits.
        let s = format!("sha256:{}", "a".repeat(64));
        assert!(annotation_well_formed(&s));
        let s = format!("sha256:{}", "0123456789abcdef".repeat(4));
        assert!(annotation_well_formed(&s));
    }

    #[test]
    fn annotation_well_formed_rejects_malformed_inputs() {
        assert!(!annotation_well_formed(""));
        assert!(!annotation_well_formed("sha256:"));
        // 63 chars.
        assert!(!annotation_well_formed(&format!(
            "sha256:{}",
            "a".repeat(63)
        )));
        // 65 chars.
        assert!(!annotation_well_formed(&format!(
            "sha256:{}",
            "a".repeat(65)
        )));
        // Uppercase hex — sha256_of_reader emits lowercase only.
        assert!(!annotation_well_formed(&format!(
            "sha256:{}",
            "A".repeat(64)
        )));
        // Non-hex.
        assert!(!annotation_well_formed(&format!(
            "sha256:{}",
            "g".repeat(64)
        )));
        // Wrong prefix.
        assert!(!annotation_well_formed(&format!("md5:{}", "a".repeat(64))));
        // No prefix at all.
        assert!(!annotation_well_formed(&"a".repeat(64)));
    }

    #[test]
    fn sha256_of_reader_matches_known_vector() {
        // Empty input → known SHA-256 digest.
        let s = sha256_of_reader(std::io::empty()).unwrap();
        assert_eq!(
            s,
            "sha256:e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
        );
        // "abc" → known SHA-256 digest.
        let s = sha256_of_reader(&b"abc"[..]).unwrap();
        assert_eq!(
            s,
            "sha256:ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad"
        );
    }

    #[test]
    fn sha256_of_reader_handles_data_larger_than_buffer() {
        // Pumping more than 64 KiB through the hasher exercises the
        // multi-read path of sha256_of_reader (the inline buffer is
        // 64 KiB).
        let big = vec![0xa5u8; 200 * 1024];
        let s = sha256_of_reader(&big[..]).unwrap();
        let mut h = Sha256::new();
        h.update(&big);
        let direct = format!("sha256:{}", hex::encode(h.finalize()));
        assert_eq!(s, direct);
    }

    #[test]
    fn drop_in_path_constructs_per_instance_path() {
        assert_eq!(
            drop_in_path("buckos"),
            std::path::PathBuf::from(
                "/etc/systemd/system/ghars-runner@buckos.service.d/00-ghars.conf"
            )
        );
    }

    #[test]
    fn runsvc_path_constructs_per_trust_zone_path() {
        assert_eq!(
            runsvc_path("default", "buckos"),
            std::path::PathBuf::from("/var/lib/ghars/default/ghars-buckos/runsvc.sh")
        );
        assert_eq!(
            runsvc_path("ci", "ktstr-1"),
            std::path::PathBuf::from("/var/lib/ghars/ci/ghars-ktstr-1/runsvc.sh")
        );
    }

    #[test]
    fn open_no_follow_rdonly_rejects_symlink() {
        // SEC-02 anti-TOCTOU primitive: O_NOFOLLOW must make open(2)
        // fail when the path is a symlink so the kernel never resolves
        // through to a runner-controlled target.
        let tmp = tempfile::tempdir().unwrap();
        let target = tmp.path().join("target");
        std::fs::write(&target, b"#!/bin/sh\n").unwrap();
        let link = tmp.path().join("link");
        std::os::unix::fs::symlink(&target, &link).unwrap();

        let err = open_no_follow_rdonly(&link).expect_err("symlink must be rejected");
        // ELOOP (40) is the kernel's signal that O_NOFOLLOW refused
        // to traverse the symlink. Some libcs surface ENOTDIR/ENOENT
        // for related cases but a regular-file symlink is ELOOP.
        assert_eq!(err.raw_os_error(), Some(libc::ELOOP));

        // Direct open on the regular file must succeed — we're only
        // closing the symlink path.
        let f = open_no_follow_rdonly(&target).unwrap();
        let s = sha256_of_reader(&f).unwrap();
        assert!(s.starts_with("sha256:"));
    }

    #[test]
    fn end_to_end_annotation_match_against_real_file() {
        // Verify the round-trip the wrapper relies on: the annotation
        // value emitted by render_identity at apply time MUST equal
        // sha256_of_reader's output on the same script bytes when read
        // back through O_NOFOLLOW. Without this guarantee every start
        // would fail the integrity check.
        let tmp = tempfile::tempdir().unwrap();
        let path = tmp.path().join("runsvc.sh");
        let body = b"#!/bin/sh\necho hello\n";
        std::fs::write(&path, body).unwrap();

        let f = open_no_follow_rdonly(&path).unwrap();
        let computed = sha256_of_reader(&f).unwrap();

        let mut h = Sha256::new();
        h.update(body);
        let expected = format!("sha256:{}", hex::encode(h.finalize()));

        assert_eq!(computed, expected);
        assert!(annotation_well_formed(&computed));
    }
}
