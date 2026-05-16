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
/// from within a runtime" (verified empirically below). This pin
/// guards the contract: production code in `auth.rs` MUST NOT call
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
/// reactor thread (`current_thread` runtime), and its inner
/// `block_on` hits the same already-entered guard. The panic
/// surfaces when the outer `block_on` awaits the `JoinHandle`. This
/// pins the contract so a future caller who refactors auth.rs to
/// use spawn + `block_on` doesn't silently introduce a deadlock.
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
/// future body. We can't statically verify "passed to `block_on`"
/// from a unit test, but the next-best check is that auth.rs
/// keeps its 4 call sites top-level — this fails fast if a
/// teammate refactors auth.rs into a nested `block_on` shape and
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
                 within the preceding 50 lines — violation of the \
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
    // SEC-08: a CA cert file with no PEM CERTIFICATE blocks
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
    // SEC-08: a file that contains PEM blocks but NO
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
    // forms must reject.
    assert!(parse_url("https://GITHUB.com/example/repo").is_err());
    assert!(parse_url("https://Github.com/example/repo").is_err());
    assert!(parse_url("https://GITHUB.COM/example/repo").is_err());
}

#[test]
fn user_agent_is_versioned() {
    // github.rs USER_AGENT must be `ghars/<version>` to match
    // extract.rs. The crate version comes from CARGO_PKG_VERSION at
    // build time, so the prefix is the stable assertion target.
    assert!(USER_AGENT.starts_with("ghars/"));
    assert!(USER_AGENT.len() > "ghars/".len());
}

// ---- parse_url Python-parity rejection cases ----------------------
//
// validators.rs::tests::url_rejects already enumerates the full
// Python `test_url_rejects` set against `validate_url`. These cases
// pin the same coverage at the `parse_url` entry point so any
// regression in the validate_url -> parse_url chain (e.g. the
// `validate_url` pre-check getting accidentally removed) surfaces
// here. The list mirrors the legacy Python install tool's URL
// rejection cases plus an explicit-port case.

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

// ---- extract_sha256 body-format edge cases ------------------------

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

// ---- fetch_latest_release / fetch_release end-to-end --------------

/// Build the JSON body mockito serves for a mocked GitHub release.
/// Captures the contract ghars depends on:
/// - `tag_name` is `vX.Y.Z`
/// - `assets[]` carries `name` + `digest = "sha256:HEX"`
/// - `body` carries a redundant `<hex>  <filename>` line so tests
///   can assert the asset-digest path is preferred.
pub(super) fn release_json(tag: &str, sha_x64: &str, sha_arm: &str) -> String {
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
            assert!(
                msg.contains("404"),
                "msg must include status code; got: {msg}"
            );
            assert!(
                hint.contains("runner version") && hint.contains("owner/repo"),
                "404 hint must surface runner-version + owner/repo guidance; got: {hint}"
            );
        }
        other => panic!("expected GharsError::GitHub, got {other:?}"),
    }
    mock.assert();
}

/// 429 rate-limit responses must surface the operator-actionable
/// Retry-After hint, mirroring the
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
            assert!(
                msg.contains("429"),
                "msg must include status code; got: {msg}"
            );
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
            assert!(
                msg.contains("401"),
                "msg must include status code; got: {msg}"
            );
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
            assert!(
                msg.contains("403"),
                "msg must include status code; got: {msg}"
            );
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

/// 5xx responses surface the upstream-degraded hint with
/// status.github.com pointer. Mirrors
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
            assert!(
                msg.contains("503"),
                "msg must include status code; got: {msg}"
            );
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

/// A status code outside the named arms (e.g. 418 I'm a teapot)
/// takes the catch-all generic hint —
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
            assert!(
                msg.contains("418"),
                "msg must include status code; got: {msg}"
            );
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
