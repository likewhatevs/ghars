use super::*;
use crate::error::FORMAT_ERROR_CHAIN_MAX_DEPTH;

use super::tests_a::release_json;

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

// ---- response body size cap ---------------------------------------

/// Normal-size body acceptance pin: a typical releases JSON
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

/// Oversize body rejection pin: when the body exceeds
/// `MAX_RELEASES_BODY_BYTES`, `http_get_payload` rejects the
/// response. Mockito sets Content-Length automatically from the
/// served body, so this single test exercises the Layer-1
/// pre-read rejection path (the CL header reflects the real
/// oversize body length, the pre-check fires before any read).
/// The Layer-2 streaming defense — the `reader.take(cap + 1).read_to_end()`
/// code at `github.rs::read_body_capped` — is exercised separately
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

// ---- read_body_capped + http_get_payload_with_cap unit tests --------

/// `read_body_capped` returns Ok with the full buffer when the
/// reader has exactly `cap` bytes (the boundary case). Pinned
/// to defend against an off-by-one regression that uses `>=` in
/// place of `>` on the buf-len check.
#[test]
fn read_body_capped_accepts_exactly_at_cap() {
    let cap: u64 = 64;
    let body = vec![b'x'; cap as usize];
    let buf = read_body_capped(std::io::Cursor::new(body.clone()), cap).unwrap();
    assert_eq!(buf, body);
}

/// `read_body_capped` returns Ok with the buffer when the
/// reader has fewer than `cap` bytes (the under-cap case).
#[test]
fn read_body_capped_accepts_under_cap() {
    let cap: u64 = 64;
    let body = vec![b'y'; 32];
    let buf = read_body_capped(std::io::Cursor::new(body.clone()), cap).unwrap();
    assert_eq!(buf, body);
}

/// `read_body_capped` returns `BodyCapError::CapExceeded`
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
        BodyCapError::Io(other) => {
            panic!("expected BodyCapError::CapExceeded, got Io({other:?})")
        }
    }
}

/// `http_get_payload_with_cap` end-to-end pin against
/// mockito with a small cap (64 bytes). Body is 128 bytes, larger
/// than the cap; production code path goes through Layer 1 (CL
/// header check) and rejects with "Content-Length ... exceeds 64
/// bytes". This exercises the cap-injection seam without
/// requiring a 4 MiB body. Also pins Layer 1 hint differentiation
/// (on-wire / pre-decompression framing distinct from Layer 2's
/// post-decompression / bomb-signature framing) and the
/// `MAX_RELEASES_BODY_BYTES` escape-hatch breadcrumb.
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
            // Layer 1 differentiation: on-wire/pre-decompression framing distinct from Layer 2's post-decompression framing.
            assert!(
                hint.contains("on-wire") && hint.contains("pre-decompression"),
                "Layer 1 hint must surface on-wire/pre-decompression framing; got: {hint}"
            );
            assert!(
                !hint.contains("post-decompression"),
                "Layer 1 hint must NOT surface post-decompression framing (Layer 2 territory); got: {hint}"
            );
            assert!(
                hint.contains("MAX_RELEASES_BODY_BYTES"),
                "Layer 1 hint must surface MAX_RELEASES_BODY_BYTES escape hatch; got: {hint}"
            );
            // Human-readable size labels alongside raw byte counts so an operator can read "128 B (128 bytes)" without mental conversion.
            assert!(
                msg.contains("128 B") && msg.contains("64 B"),
                "Layer 1 msg must include human-readable byte sizes (e.g. '128 B', '64 B'); got: {msg}"
            );
            // Cap-hint suffix removed: the `(current limit: ...)`
            // trailing parenthetical is dropped. The cap value
            // already appears in the body (`exceeds 64 B (64
            // bytes)`), and re-stating it in the hint added no
            // operator-actionable information. The load-bearing
            // breadcrumb is the symbol-name reference
            // (`MAX_RELEASES_BODY_BYTES`), pinned above. Negative
            // pin guards against a regression that re-introduces
            // the duplicated suffix.
            assert!(
                !hint.contains("current limit:"),
                "Layer 1 hint MUST NOT surface 'current limit:' suffix (cap-hint suffix removed); got: {hint}"
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
/// `content-length` (the chunked-body path skips the CL header
/// that the bytes-body path adds). This forces Layer 1 to skip and
/// Layer 2 (the streaming `read_body_capped` post-decompression
/// gate) to fire — the actual gzip-bomb defense surface.
///
/// Asserts the wrapped error format: starts with "GitHub API
/// response", contains "body exceeds" + cap value, surfaces
/// "post-decompression" framing distinct from Layer 1's "on-wire
/// / pre-decompression" framing, and crucially does NOT contain
/// the doubled-noun "response response" (regression pin for the
/// cleaner pass). Pins that the hint text uses neutral
/// "larger than expected" framing (naming both the deliberately-
/// crafted and legitimately-large possibilities) and avoids the
/// alarming "compression-bomb signature" framing.
#[test]
fn http_get_payload_with_cap_rejects_via_layer_2_streaming_when_no_content_length() {
    let mut server = mockito::Server::new();
    let mock = server
        .mock("GET", "/repos/actions/runner/releases/latest")
        .with_status(200)
        .with_header("content-type", "application/json")
        .with_chunked_body(|w| w.write_all(&[b'q'; 128]))
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
            // Layer 2 hint uses neutral "larger than expected"
            // wording that names both threat-model and legitimate-
            // payload possibilities, and avoids alarming
            // "compression-bomb signature" framing. Pin both so
            // a regression toward the alarming form surfaces here.
            assert!(
                hint.contains("larger than expected"),
                "Layer 2 hint must surface neutral 'larger than expected' framing; got: {hint}"
            );
            assert!(
                hint.contains("deliberately-crafted") && hint.contains("legitimately large"),
                "Layer 2 hint must name both threat-model + legitimate-payload possibilities; got: {hint}"
            );
            assert!(
                !hint.contains("compression-bomb signature"),
                "Layer 2 hint MUST NOT surface alarming 'compression-bomb signature' framing; got: {hint}"
            );
            assert!(
                hint.contains("status.github.com"),
                "Layer 2 hint must surface status.github.com triage breadcrumb; got: {hint}"
            );
            assert!(
                hint.contains("MAX_RELEASES_BODY_BYTES"),
                "hint must surface MAX_RELEASES_BODY_BYTES escape hatch; got: {hint}"
            );
            // Layer 2 msg must include human-readable size
            // label (e.g. "64 B") alongside raw "64 bytes" so an
            // operator reads them without mental conversion. The
            // small-cap test uses a 64-byte cap which renders as
            // "64 B" in human_bytes (sub-KiB integer-byte path).
            assert!(
                msg.contains("64 B (64 bytes)"),
                "Layer 2 msg must include human-readable byte size '64 B (64 bytes)'; got: {msg}"
            );
            // Cap-hint suffix removed: the `(current limit: ...)`
            // trailing parenthetical is dropped (parity with Layer
            // 1). The cap value already appears in the body
            // (`exceeds 64 B (64 bytes) post-decompression`); the
            // load-bearing breadcrumb is the symbol-name reference
            // (`MAX_RELEASES_BODY_BYTES`, pinned above). Negative
            // pin guards against regression.
            assert!(
                !hint.contains("current limit:"),
                "Layer 2 hint MUST NOT surface 'current limit:' suffix (cap-hint suffix removed); got: {hint}"
            );
        }
        other => panic!("expected GharsError::GitHub, got {other:?}"),
    }
    mock.assert();
}

/// Pin: reqwest's gzip auto-decompress is load-bearing for the
/// Layer 2 cap defense. Cargo.toml configures reqwest with the
/// `gzip` feature; `build_blocking_client` builds the Client
/// without an explicit `.gzip(...)` call, relying on the feature
/// flag to enable transparent decoding when the upstream sets
/// `Content-Encoding: gzip`.
///
/// **Cap-defense layers** (matching the `http_get_payload_with_cap`
/// implementation): Layer 1 = Content-Length pre-check (rejects
/// before reading any body bytes); Layer 2 = streaming
/// `read_body_capped` post-decompression (the actual gzip-bomb
/// defense — bytes counted are downstream of reqwest's gzip
/// decoder, so a small compressed payload that decompresses to
/// gigabytes still fires the cap).
///
/// This test serves a gzip-compressed body whose plaintext is 128
/// bytes (over the 64-byte cap). With gzip auto-decompress active,
/// reqwest's `Response: Read` decoder yields 128 plaintext bytes
/// downstream of the decoder, so `read_body_capped` sees 128 bytes
/// and the cap fires post-decompression.
///
/// Layer 1 skip is over-determined here: reqwest's gzip-decompress
/// codepath strips the `Content-Length` response header (the
/// header reflects the compressed wire size, which is meaningless
/// once the body is decoded), so `resp.headers().get(CONTENT_LENGTH)`
/// returns `None` regardless of whether the compressed body is
/// under or over the cap. The fixture also pins `compressed_size`
/// under cap as belt-and-suspenders insurance against a future
/// reqwest version that propagates the on-wire length.
///
/// Compression: `flate2` is a production dependency at Cargo.toml
/// (production code uses `flate2::read::GzDecoder` at
/// `extract.rs::extract_tarball` for tarball decompression), so
/// this test reuses the in-tree dependency without adding a
/// dev-dep. Plaintext is 128 zero-bytes — highly compressible, so
/// the gzip output stays under 64 bytes; this is the same
/// compression-ratio pattern a real gzip-bomb would exploit
/// (small compressed wire size, large decompressed size), and the
/// cap defense at Layer 2 is what blocks it.
///
/// Asserts:
/// 1. err is `GharsError::GitHub(msg`, hint) — Layer 2 cap-firing branch.
/// 2. msg contains "post-decompression" — Layer 2 framing, distinct
///    from Layer 1's "on-wire" framing.
/// 3. msg contains "body exceeds" + "64 B" — pins the cap-firing format.
/// 4. msg does NOT contain "Content-Length" — Layer 1 must NOT have fired.
/// 5. msg ends with the URL — log-parser stable-suffix parity with
///    Layer 1 / Layer 2 sibling tests.
/// 6. msg does NOT contain "not valid JSON" — counterfactual:
///    a regression that disables the reqwest gzip feature would
///    route through the JSON-decode arm (raw gzip bytes fail to
///    parse) instead of the cap-fire arm; this assertion fails in
///    that case rather than the test silently passing on a
///    different error path.
/// 7. hint mentions `MAX_RELEASES_BODY_BYTES` — operator escape
///    hatch breadcrumb the cap-fire hint surfaces.
/// 8. `mock.assert()` — confirms the request reached the server.
#[test]
fn read_body_capped_post_decompression_via_gzip_response_pins_layer_2_decoder_path() {
    use flate2::Compression;
    use flate2::write::GzEncoder;
    use std::io::Write;

    // 128-byte plaintext exceeds the 64-byte cap post-decompression.
    // Zero-bytes are highly compressible: gzip output for 128 zero
    // bytes is well under 64 bytes (typically ~30). The compressed
    // < cap pin defends against a future reqwest version that
    // forwards the on-wire Content-Length on gzip responses (today
    // it strips the header — the cap defense at Layer 2 is what
    // blocks gzip-bomb payloads regardless).
    let plaintext = vec![0u8; 128];
    assert!(
        plaintext.len() as u64 > 64,
        "fixture invariant: plaintext must exceed cap so Layer 2 fires \
         post-decompression"
    );
    let mut encoder = GzEncoder::new(Vec::new(), Compression::default());
    encoder.write_all(&plaintext).unwrap();
    let compressed = encoder.finish().unwrap();
    assert!(
        (compressed.len() as u64) < 64,
        "fixture invariant: compressed length must be < cap=64 to model a \
         gzip-bomb payload (small wire size, large decompressed size); \
         with this shape Layer 2 (post-decompression) is the layer that \
         must fire — Layer 1 cannot see the decompressed size. got {} bytes",
        compressed.len()
    );

    let mut server = mockito::Server::new();
    let mock = server
        .mock("GET", "/repos/actions/runner/releases/latest")
        .with_status(200)
        .with_header("content-type", "application/json")
        .with_header("content-encoding", "gzip")
        .with_body(compressed)
        .expect(1)
        .create();
    let url = format!("{}/repos/actions/runner/releases/latest", server.url());
    let client = build_blocking_client(None).unwrap();
    let err = http_get_payload_with_cap(&client, &url, 64).unwrap_err();
    match err {
        GharsError::GitHub(msg, hint) => {
            assert!(
                msg.contains("post-decompression"),
                "gzip auto-decompress must route to Layer 2 cap (post-\
                 decompression framing); a regression that drops the \
                 reqwest gzip feature would surface here as a different \
                 error path. got: {msg}"
            );
            assert!(
                msg.contains("body exceeds") && msg.contains("64 B"),
                "Layer 2 msg must surface 'body exceeds' + cap value 64 B; got: {msg}"
            );
            assert!(
                !msg.contains("Content-Length"),
                "Layer 1 (Content-Length pre-check) must NOT fire on \
                 gzip-encoded responses (reqwest strips the header on \
                 auto-decompress paths); if this assertion fails, the \
                 cap defense path has shifted away from Layer 2. \
                 got: {msg}"
            );
            assert!(
                msg.ends_with(&url),
                "URL trailing-position parity with Layer 2 siblings; \
                 log parsers grep the stable ': {{url}}' suffix. got: {msg}"
            );
            assert!(
                !msg.contains("not valid JSON"),
                "counterfactual: a regression that disables the reqwest \
                 gzip feature would deliver raw compressed bytes and \
                 route through the JSON-decode arm (which surfaces \
                 'not valid JSON'). The cap-fire arm must not produce \
                 that text; if it does, the gzip auto-decompress path \
                 is broken and the cap defense weakened. got: {msg}"
            );
            assert!(
                hint.contains("MAX_RELEASES_BODY_BYTES"),
                "Layer 2 cap-fire hint must surface the \
                 MAX_RELEASES_BODY_BYTES escape-hatch breadcrumb so \
                 operators can locate the constant if the upstream \
                 payload is legitimately large. got: {hint}"
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
/// underlying `io::Error` is preserved so the wrapper can surface
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
        BodyCapError::CapExceeded { cap: reported } => panic!(
            "I/O failure must produce BodyCapError::Io — that variant is the wrapper's I/O-error discriminant; got: CapExceeded {{ cap: {reported} }}"
        ),
    }
}

/// `format_error_chain` walks an `io::Error`'s `.source()` chain so
/// nested causes (e.g. `reqwest::Error` wrapping `hyper::Error`
/// wrapping rustls) survive into the operator-visible message.
/// Synthesize: outer `io::Error` wraps a custom mid error that
/// wraps an inner error via `source()`. `io::Error` Custom Display
/// delegates to the wrapped error, so `outer.to_string()` emits
/// mid's text; `format_error_chain` walks source chain to append
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
        "chain must add inner-layer text beyond the outer Display; chain={chain}, outer={outer}"
    );
}

/// `format_error_chain` on an `io::Error` with no source returns just
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

/// E2E pin: a 2-level `io::Error` source chain must survive
/// `read_body_capped` → `BodyCapError::Io` → wrapper at
/// `http_get_payload_with_cap`'s I/O-error arm → final
/// `GharsError::GitHub` message. Both the outer (mid-layer) and
/// inner Display strings must appear in the operator-visible
/// message, joined by the wrapper's "response read failed:" prefix
/// + `format_error_chain`'s ": " separator. Defends against a
/// regression that switches the wrapper from `format_error_chain`
/// back to `{io_err}` (which would drop the inner Display).
///
/// Synthesizes the full path: a `FailingReader` that returns an
/// `io::Error::Other` whose payload is a custom `Mid` error whose
/// `.source()` points at an `Inner` error. `read_body_capped`
/// preserves the `io::Error` in `BodyCapError::Io(io_err)`. The
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
            Err(io::Error::other(mid))
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
        BodyCapError::CapExceeded { cap: reported } => panic!(
            "expected BodyCapError::Io with chain payload, got CapExceeded {{ cap: {reported} }}"
        ),
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

/// Anti-doubling pin against the hypothetical double-Display
/// cascade. The concern: if std's `io::Error::Display` (or any
/// outer error type) already includes its source's Display text in
/// its own Display, then `format_error_chain` would emit that text
/// twice — once from `err.to_string()` and again from the
/// `.source()` walk. The cleanest empirical defense is to
/// construct an outer error whose Display intentionally spells out
/// a unique sentinel string that the inner error does NOT contain,
/// then assert that the outermost layer's Display contribution to
/// `format_error_chain` output appears exactly once. If the
/// outer were leaking inner text, the inner Display would also
/// appear once via the source walk — but the outer's would not
/// double.
///
/// The complementary disconfirmation: construct an outer that DOES
/// embed inner text in its own Display (using
/// `io::Error::other(inner)` which delegates Display to the
/// wrapped error per `std::io::Error::fmt` at io/error.rs:1140-1147).
/// In that case the inner text legitimately appears twice (once
/// from `outer.to_string()` because outer Display delegates, once
/// from the source walk). This is by design — `format_error_chain`
/// cannot peek into outer Display formatters to deduplicate. The
/// test pins the `io::Error::other` behavior as a known acceptable
/// repetition so a future maintainer reading the test sees what
/// IS guaranteed (no fabrication of doubled text by the helper)
/// vs. what is NOT guaranteed (no double when outer Display
/// already embeds inner via delegation).
///
/// Source-of-truth read: io/error.rs Display impl for the
/// inner-Custom variant calls `fmt::Display::fmt(&c.error, fmt)`
/// which delegates outright. `reqwest::Error` Display writes ONLY
/// its own kind-specific text and the URL — it does NOT walk
/// into the source chain. So `format_error_chain` over a
/// `reqwest::Error` produces `<outer-kind-text>: <source-text>`
/// with no doubling.
#[test]
fn format_error_chain_no_doubling_on_distinct_outer_display() {
    use std::error::Error;
    use std::fmt;

    const OUTER_SENTINEL: &str = "OUTER-ZK7-UNIQUE";
    const INNER_SENTINEL: &str = "INNER-Q3M-UNIQUE";

    #[derive(Debug)]
    struct DistinctInner;
    impl fmt::Display for DistinctInner {
        fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
            f.write_str(INNER_SENTINEL)
        }
    }
    impl Error for DistinctInner {}

    #[derive(Debug)]
    struct DistinctOuter {
        cause: DistinctInner,
    }
    impl fmt::Display for DistinctOuter {
        fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
            // Outer Display intentionally does NOT include inner's
            // text — exactly the reqwest::Error pattern.
            f.write_str(OUTER_SENTINEL)
        }
    }
    impl Error for DistinctOuter {
        fn source(&self) -> Option<&(dyn Error + 'static)> {
            Some(&self.cause)
        }
    }

    let err = DistinctOuter {
        cause: DistinctInner,
    };
    let chain = format_error_chain(&err);
    // Each sentinel must appear exactly once: the outer once
    // from `err.to_string()`, the inner once from the source
    // walk. No doubling in either direction.
    assert_eq!(
        chain.matches(OUTER_SENTINEL).count(),
        1,
        "outer sentinel must appear exactly once when outer Display does not embed source; got: {chain}"
    );
    assert_eq!(
        chain.matches(INNER_SENTINEL).count(),
        1,
        "inner sentinel must appear exactly once via source-walk; got: {chain}"
    );
    // Pin the order: outer first, then ": ", then inner.
    let expected = format!("{OUTER_SENTINEL}: {INNER_SENTINEL}");
    assert_eq!(
        chain, expected,
        "chain must concatenate outer + ': ' + inner with no extra framing; got: {chain}"
    );
}

/// `io::Error::new(kind, inner)` "transparent wrap" pin.
///
/// The hypothetical doubling concern: if std's `io::Error` Display
/// embedded the wrapped error's text AND `source()` returned the
/// wrapped error, then `format_error_chain` would surface the
/// wrapped error's text twice (once from outer Display delegation,
/// once from the source walk).
///
/// Verified against std at io/error.rs (stable toolchain
/// 1.94.x):
///   - Display impl (Custom variant) at io/error.rs:1046-1058
///     calls `c.error.fmt(fmt)` — delegates to wrapped Display
///     verbatim (so `outer.to_string()` emits inner text).
///   - `source()` impl (Custom variant) at io/error.rs:1072-1079
///     returns `c.error.source()` — NOT `Some(&*c.error)`. The
///     wrapped error itself is SKIPPED in the source walk; the
///     walk goes directly to whatever the wrapped error's own
///     `source()` returns.
///
/// Net behavior: `io::Error::new(kind, inner)` produces a
/// "transparent wrap" — the wrapped error's identity is consumed
/// into the outer (Display delegation + source-skip). For an
/// inner error whose own `source()` is `None`,
/// `format_error_chain` emits the inner Display exactly ONCE.
///
/// Production impact: none. Production code calls
/// `format_error_chain(&reqwest_err)` and
/// `format_error_chain(&io_err)` directly on the outermost
/// type, never wrapping `reqwest::Error` in `io::Error::other`.
/// `Reqwest::Error` Display writes ONLY its own kind-specific
/// text and URL, never embedding the source — so the production
/// no-doubling regime is pinned by
/// `format_error_chain_no_doubling_on_distinct_outer_display`.
///
/// This pin defends against a regression that "fixes" the
/// nonexistent doubling by adding a substring deduplicator,
/// which would corrupt the genuine no-doubling case where inner
/// text is meaningfully distinct from anything embedded by outer.
#[test]
fn format_error_chain_io_error_wrap_is_transparent_no_doubling() {
    use std::error::Error;
    use std::fmt;
    use std::io;

    const INNER_SENTINEL: &str = "INNER-DEL-SENTINEL";

    #[derive(Debug)]
    struct DistinctInner;
    impl fmt::Display for DistinctInner {
        fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
            f.write_str(INNER_SENTINEL)
        }
    }
    impl Error for DistinctInner {}

    // io::Error::new wraps the inner error such that:
    //   - outer Display delegates to inner (1 emission of sentinel)
    //   - outer.source() returns inner.source() (not the wrapped
    //     inner itself), and DistinctInner has no source override
    //     so the source walk yields None.
    // Net: chain emits sentinel exactly once.
    let outer = io::Error::other(DistinctInner);
    let chain = format_error_chain(&outer);
    assert_eq!(
        chain.matches(INNER_SENTINEL).count(),
        1,
        "io::Error wrap is transparent — outer Display delegates to inner (1 emit) and source walk skips wrapped inner via inner.source()=None; chain must emit sentinel exactly once; got: {chain}"
    );
    // Anti-fabrication pin: chain equals exactly the inner Display
    // text. Defense against a regression that prepends/appends
    // framing in the depth-0 (no-source) path, or that adds a
    // pseudo-layer for the wrapped inner.
    assert_eq!(
        chain, INNER_SENTINEL,
        "io::Error wrap is transparent — chain must equal the inner Display verbatim with no framing; got: {chain}"
    );
}

/// `format_error_chain` depth cap pin. Construct a 17-level Error
/// chain where each level's `.source()` returns the next level;
/// after `format_error_chain`, the output must contain exactly 16
/// ": " separators (= 17 layers of Display joined by 16 separators
/// would be the unbounded case, but the cap stops the walk at
/// `FORMAT_ERROR_CHAIN_MAX_DEPTH` = 16 source-chain hops, producing
/// outermost + 16 hops = 17 emitted layers separated by 16 ": ").
/// The cap fires *before* the 17th hop, so the 18th-and-beyond
/// layers are dropped. This defends against regressions that
/// remove the depth cap (would cycle/explode on cyclic chains) or
/// off-by-one regressions that set the cap to 15 or 17.
///
/// Note on counting: `format_error_chain` emits the outermost layer's
/// Display first (no leading ": "), then walks `.source()` up to
/// `FORMAT_ERROR_CHAIN_MAX_DEPTH` (16) more levels, prepending ": "
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
        separator_count, FORMAT_ERROR_CHAIN_MAX_DEPTH,
        "depth cap must stop walk at FORMAT_ERROR_CHAIN_MAX_DEPTH (= 16) hops, producing exactly 16 ': ' separators; got {separator_count} in chain: {chain}"
    );
    assert!(
        chain.contains("layer-0"),
        "chain must include outermost layer; got: {chain}"
    );
    assert!(
        chain.contains(&format!("layer-{FORMAT_ERROR_CHAIN_MAX_DEPTH}")),
        "chain must include the last layer reached by the cap (layer-{FORMAT_ERROR_CHAIN_MAX_DEPTH}); got: {chain}"
    );
    assert!(
        !chain.contains(&format!("layer-{}", FORMAT_ERROR_CHAIN_MAX_DEPTH + 1)),
        "chain must NOT include layers beyond the cap (layer-{}); got: {chain}",
        FORMAT_ERROR_CHAIN_MAX_DEPTH + 1
    );
}

/// Pin: `cap == u64::MAX` trips the debug-build assertion in
/// `read_body_capped`. Documents the silent-disable footgun:
/// `cap.saturating_add(1)` saturates at `u64::MAX`, so
/// `Read::take(u64::MAX)` never short-circuits, and the
/// post-read check `buf.len() as u64 > cap` requires
/// `buf.len() > u64::MAX` (impossible on 64-bit `usize`). The
/// `debug_assert!` is the development-time tripwire; in release
/// builds the cap is silently a no-op. Production callers fix
/// `cap = MAX_RELEASES_BODY_BYTES` (4 MiB) so this edge has no
/// production exposure today.
#[test]
#[cfg(debug_assertions)]
#[should_panic(expected = "u64::MAX silently disables the cap")]
fn read_body_capped_panics_on_u64_max_cap_in_debug_builds() {
    let _ = read_body_capped(std::io::Cursor::new(vec![b'x'; 8]), u64::MAX);
}

/// Pin: `http_get_payload_with_cap` rejects an HTTP 204 No
/// Content response (success status, empty body) with a
/// targeted error before `serde_json::from_slice` would emit
/// the unhelpful "EOF while parsing a value at line 1 column 0".
/// 204/205 are valid HTTP success codes; the releases-API
/// contract requires a JSON body on success, so an empty body
/// indicates either a method-rewriting proxy, a captive portal
/// stripping the payload, or an upstream contract change.
#[test]
fn http_get_payload_with_cap_rejects_204_no_content_with_empty_body_hint() {
    let mut server = mockito::Server::new();
    let mock = server
        .mock("GET", "/repos/actions/runner/releases/latest")
        .with_status(204)
        .with_body("")
        .expect(1)
        .create();
    let url = format!("{}/repos/actions/runner/releases/latest", server.url());
    let client = build_blocking_client(None).unwrap();
    let err = http_get_payload_with_cap(&client, &url, MAX_RELEASES_BODY_BYTES).unwrap_err();
    match err {
        GharsError::GitHub(msg, hint) => {
            assert!(
                msg.contains("empty body"),
                "msg must surface 'empty body' framing; got: {msg}"
            );
            assert!(
                msg.contains("204"),
                "msg must include the offending status code; got: {msg}"
            );
            // URL trailing-position pin: matches Layer 1 / Layer 2
            // / HTTP-status arms so log parsers grep all four
            // error classes with the same suffix shape.
            assert!(
                msg.ends_with(&format!(": {url}")),
                "empty-body msg must end with ': {{url}}'; got: {msg}"
            );
            assert!(
                hint.contains("204") && hint.contains("No Content"),
                "hint must name 204 No Content; got: {hint}"
            );
            assert!(
                hint.contains("proxy") || hint.contains("captive portal"),
                "hint must surface proxy / captive-portal triage breadcrumb; got: {hint}"
            );
            // Anti-confusion pin: this error class must NOT
            // delegate to the JSON-decode arm's wording, which
            // would mislead the operator into looking for
            // malformed JSON when the body is actually empty.
            assert!(
                !msg.contains("not valid JSON"),
                "empty-body msg must NOT route through the JSON-decode arm; got: {msg}"
            );
            assert!(
                !msg.contains("EOF while parsing"),
                "empty-body msg must NOT surface the cryptic serde EOF error; got: {msg}"
            );
        }
        other => panic!("expected GharsError::GitHub, got {other:?}"),
    }
    mock.assert();
}

/// Pin: a successful 200 response with a zero-byte body (e.g. a
/// proxy stripping the payload while preserving the status code)
/// hits the same empty-body branch as 204. Pinning the 200 case
/// alongside 204 defends against a regression that scopes the
/// check to the 204-status arm specifically — the gate is on the
/// post-cap buffer length, not the status code, so any
/// success-status zero-byte body must trip the same diagnostic.
#[test]
fn http_get_payload_with_cap_rejects_200_with_empty_body_via_proxy_strip() {
    let mut server = mockito::Server::new();
    let mock = server
        .mock("GET", "/repos/actions/runner/releases/latest")
        .with_status(200)
        .with_header("content-type", "application/json")
        .with_body("")
        .expect(1)
        .create();
    let url = format!("{}/repos/actions/runner/releases/latest", server.url());
    let client = build_blocking_client(None).unwrap();
    let err = http_get_payload_with_cap(&client, &url, MAX_RELEASES_BODY_BYTES).unwrap_err();
    match err {
        GharsError::GitHub(msg, _hint) => {
            assert!(
                msg.contains("empty body"),
                "200 + zero-byte body must hit the empty-body arm; got: {msg}"
            );
            assert!(
                msg.contains("200"),
                "msg must include the 200 status; got: {msg}"
            );
            assert!(
                !msg.contains("not valid JSON"),
                "200 + empty body must NOT route through the JSON-decode arm; got: {msg}"
            );
        }
        other => panic!("expected GharsError::GitHub, got {other:?}"),
    }
    mock.assert();
}
