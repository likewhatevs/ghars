use super::super::*;
use super::*;

#[test]
fn template_starts_with_unit_section() {
    let t = runner_template_text();
    assert!(t.starts_with("[Unit]\n"));
    // ConditionPathExists / WorkingDirectory / StateDirectory /
    // HOME live in the per-runner drop-in (path components depend
    // on trust_zone, which `%i` cannot express).
    assert!(!t.contains("ConditionPathExists=/var/lib/ghars/%i/runsvc.sh"));
    assert!(!t.contains("WorkingDirectory=/var/lib/ghars/%i"));
    assert!(!t.contains("\nStateDirectory=ghars/%i\n"));
    // ExecStart= lives only in the per-runner drop-in because the
    // path includes the resolved runner version (bin.X.Y.Z) which
    // the template-level `%i` specifier cannot express.
    assert!(!t.contains("\nExecStart="));
    // DynamicUser=yes replaces the static `User=ghars-%i` /
    // `Group=ghars-%i` from the prior model; the User= name itself
    // is set by the per-runner 00-ghars.conf drop-in to
    // `ghars-tz-<TRUST_ZONE>` so trust-zone-shared runners receive
    // the same transient UID.
    assert!(t.contains("\nDynamicUser=yes\n"));
    assert!(!t.contains("\nUser=ghars-%i\n"));
    assert!(!t.contains("\nGroup=ghars-%i\n"));
    // Capability bounding set is empty: ExecStart does not
    // setuid/setgid (DynamicUser= handles the identity), so no
    // CAP_SETUID/CAP_SETGID are required.
    assert!(t.contains("\nCapabilityBoundingSet=\n"));
    assert!(!t.contains("CapabilityBoundingSet=CAP_SETUID"));
    assert!(t.contains("Slice=system.slice"));
}

#[test]
fn render_identity_emits_exec_start_with_reset_and_versioned_path() {
    // The drop-in provides ExecStart= because the path depends on
    // trust_zone + resolved runner version. The empty `ExecStart=`
    // resets any inherited value (defense against 99-*.conf
    // ExecStart= overrides) and the second line names the
    // tarball's runsvc.sh under the versioned bin dir.
    let spec = minimal_spec();
    let r = render_runner_unit(&spec).unwrap();
    let id = r.drop_ins.get("00-ghars.conf").unwrap();
    assert!(id.contains("\nExecStart=\n"));
    assert!(id.contains(
        "\nExecStart=/bin/bash /var/lib/ghars/default/ghars-buckos/bin.2.334.0/bin/runsvc.sh\n"
    ));
    // Both lines are inside [Service].
    let service_idx = id.find("[Service]").unwrap();
    let reset_idx = id.find("\nExecStart=\n").unwrap();
    let path_idx = id.find("ExecStart=/bin/bash").unwrap();
    assert!(service_idx < reset_idx);
    assert!(reset_idx < path_idx);
}

#[test]
fn render_identity_does_not_emit_x_ghars_runsvc_sha256() {
    // The X-Ghars-Runsvc-Sha256 annotation was the runsvc-wrapper
    // trampoline's integrity-check input — both the wrapper and
    // the annotation have been removed. Pin that no future renderer
    // change resurrects the annotation.
    let spec = minimal_spec();
    let r = render_runner_unit(&spec).unwrap();
    let id = r.drop_ins.get("00-ghars.conf").unwrap();
    assert!(!id.contains("X-Ghars-Runsvc-Sha256"));
}

/// Renderer-side defense-in-depth pin for the
/// `runner_tarball = Some(Utf8PathBuf::from(""))` direct-construct
/// dark input. The merge-layer filter at `merge_defaults` collapses
/// `Some("")` → `None` before lowering, but a direct-construct
/// caller (test fixture, future programmatic spec builder) can
/// still produce an `EffectiveRunnerSpec` with `runner_tarball =
/// Some(Utf8PathBuf::from(""))` that bypasses merge. The renderer's
/// own empty-string gate must short-circuit before hashing so the
/// `X-Ghars-Runner-Tarball-Hash=sha256:e3b0c44...` (sha256 of empty
/// input) line is NOT emitted — empty must render identically to
/// `None` (no line at all) so direct-construct callers cannot flip
/// `spec_hash`. Sister to the merge-side pin
/// `merge_defaults_collapses_some_empty_runner_tarball_to_none` in
/// `plan/tests/part2.rs`.
#[test]
fn render_identity_treats_some_empty_runner_tarball_as_none_at_renderer() {
    let mut spec = minimal_spec();
    spec.runner_tarball = Some(Utf8PathBuf::from(""));
    let r = render_runner_unit(&spec).unwrap();
    let id = r.drop_ins.get("00-ghars.conf").unwrap();
    assert!(
        !id.contains("X-Ghars-Runner-Tarball-Hash"),
        "Some(empty) runner_tarball must NOT emit \
         X-Ghars-Runner-Tarball-Hash; got drop-in:\n{id}"
    );
}

#[test]
fn render_runner_env_file_emits_unconditional_keys_for_empty_caches() {
    // LANG + KTSTR_LOCK_DIR + KTSTR_CACHE_DIR always emitted.
    // CCACHE_DIR is GATED on having at least one ccache-kind
    // binding (the `has_ccache` binding gate in
    // `execute_create_runner` — symmetric with apply-layer
    // .ccache dir creation gating). Empty caches = no ccache
    // binding = no CCACHE_DIR emission. Pin byte-exact output
    // so any drift
    // (extra blank line, key reorder, missing newline, or a
    // regression to unconditional CCACHE_DIR emission) is caught.
    let spec = minimal_spec(); // caches = vec![]
    let env = render_runner_env_file(&spec).unwrap();
    assert_eq!(
        env,
        "LANG=C.UTF-8\n\
         KTSTR_LOCK_DIR=/var/lib/ghars/default/.ktstr\n\
         KTSTR_CACHE_DIR=/var/lib/ghars/default/.ktstr\n",
        "byte-exact empty-caches output drift detected",
    );
}

/// Pin that `render_runner_env_file` emits `CCACHE_DIR=` ONLY
/// when the spec has at least one ccache-kind binding. Without a
/// ccache binding the env var must be absent so the unconditional
/// ccache wrappers in PATH (units.rs `render_runner_path_file`)
/// don't intercept `gcc`/`cc` calls and try to write to the
/// trust-zone `.ccache` dir that wasn't created by apply.
///
/// Symmetric with `execute_create_runner`'s `.ccache` dir
/// creation gate (`has_ccache` check in apply/runners.rs).
/// The two are load-bearing for the `has_ccache` binding gate
/// invariant: dir presence ⇔ env var presence ⇔
/// at-least-one-ccache-binding.
#[test]
fn render_runner_env_file_gates_ccache_dir_on_ccache_binding() {
    // Use line-start match (CCACHE_DIR=... is a full env-file
    // line) so the assertion doesn't falsely match the
    // `SCCACHE_DIR=` line which contains `CCACHE_DIR=` as a
    // substring starting at index 1.
    let has_ccache_dir_line =
        |env: &str| -> bool { env.lines().any(|l| l.starts_with("CCACHE_DIR=")) };

    // No binding → no CCACHE_DIR.
    let spec = minimal_spec();
    let env = render_runner_env_file(&spec).unwrap();
    assert!(
        !has_ccache_dir_line(&env),
        "no-binding spec must NOT emit CCACHE_DIR line: {env}"
    );

    // Ccache-only binding → CCACHE_DIR present.
    let mut spec_c = minimal_spec();
    spec_c.caches.push(crate::config::EffectiveCacheBinding {
        name: "obj".into(),
        kinds: vec![CacheKind::Ccache],
        size: "10G".into(),
        mode: CacheMode::Shared,
        trust_zone: "default".into(),
        sccache_path: None,
        sleep_path: Some("/usr/bin/sleep".into()),
        server_mode: crate::config::SccacheServerMode::Pooled,
        renderer_schema: crate::systemd::RENDERER_SCHEMA,
    });
    let env_c = render_runner_env_file(&spec_c).unwrap();
    assert!(
        env_c.contains("CCACHE_DIR=/var/lib/ghars/default/.ccache\n"),
        "ccache-binding spec must emit trust-zone-interpolated CCACHE_DIR: {env_c}"
    );

    // Sccache-only binding → no CCACHE_DIR line (kind-blind
    // regression guard — the gate must check the Ccache kind
    // specifically, not just "any binding").
    let mut spec_s = minimal_spec();
    spec_s.caches.push(crate::config::EffectiveCacheBinding {
        name: "build".into(),
        kinds: vec![CacheKind::Sccache],
        size: "10G".into(),
        mode: CacheMode::Shared,
        trust_zone: "default".into(),
        sccache_path: Some("/usr/bin/sccache".into()),
        sleep_path: None,
        server_mode: crate::config::SccacheServerMode::Pooled,
        renderer_schema: crate::systemd::RENDERER_SCHEMA,
    });
    let env_s = render_runner_env_file(&spec_s).unwrap();
    assert!(
        !has_ccache_dir_line(&env_s),
        "sccache-only-binding spec must NOT emit CCACHE_DIR line (note: \
         SCCACHE_DIR is fine — only the bare CCACHE_DIR= line is gated): {env_s}"
    );

    // Combined-kind binding → CCACHE_DIR present (binding has
    // Ccache + Sccache, so the contains-Ccache predicate fires).
    let mut spec_combined = minimal_spec();
    spec_combined
        .caches
        .push(crate::config::EffectiveCacheBinding {
            name: "combined".into(),
            kinds: vec![CacheKind::Ccache, CacheKind::Sccache],
            size: "10G".into(),
            mode: CacheMode::Shared,
            trust_zone: "default".into(),
            sccache_path: Some("/usr/bin/sccache".into()),
            sleep_path: Some("/usr/bin/sleep".into()),
            server_mode: crate::config::SccacheServerMode::Pooled,
            renderer_schema: crate::systemd::RENDERER_SCHEMA,
        });
    let env_combined = render_runner_env_file(&spec_combined).unwrap();
    assert!(
        env_combined.contains("CCACHE_DIR=/var/lib/ghars/default/.ccache\n"),
        "combined-kind-binding spec must emit CCACHE_DIR: {env_combined}"
    );
}

#[test]
fn render_runner_env_file_emits_per_binding_lines_by_kind() {
    // Ccache-only binding: CCACHE_MAXSIZE only, no SCCACHE_*.
    let mut spec = minimal_spec();
    spec.caches.push(crate::config::EffectiveCacheBinding {
        name: "build".into(),
        kinds: vec![CacheKind::Ccache],
        size: "50G".into(),
        mode: CacheMode::Shared,
        trust_zone: "default".into(),
        sccache_path: None,
        sleep_path: Some("/usr/bin/sleep".into()),
        server_mode: crate::config::SccacheServerMode::Pooled,
        renderer_schema: crate::systemd::RENDERER_SCHEMA,
    });
    let env = render_runner_env_file(&spec).unwrap();
    assert!(
        env.contains("CCACHE_MAXSIZE=50G\n"),
        "missing CCACHE_MAXSIZE: {env}"
    );
    assert!(
        !env.contains("SCCACHE_"),
        "ccache-only must not emit SCCACHE_*: {env}"
    );

    // Sccache-only binding: SCCACHE_* yes, no CCACHE_MAXSIZE.
    let mut spec2 = minimal_spec();
    spec2.caches.push(crate::config::EffectiveCacheBinding {
        name: "build".into(),
        kinds: vec![CacheKind::Sccache],
        size: "200G".into(),
        mode: CacheMode::Shared,
        trust_zone: "default".into(),
        sccache_path: Some("/usr/bin/sccache".into()),
        sleep_path: None,
        server_mode: crate::config::SccacheServerMode::Pooled,
        renderer_schema: crate::systemd::RENDERER_SCHEMA,
    });
    let env2 = render_runner_env_file(&spec2).unwrap();
    assert!(
        !env2.contains("CCACHE_MAXSIZE"),
        "sccache-only must not emit CCACHE_MAXSIZE: {env2}"
    );
    assert!(
        env2.contains("SCCACHE_SERVER_UDS=/run/ghars/cache-build.sock\n"),
        "missing SCCACHE_SERVER_UDS: {env2}"
    );
    assert!(
        env2.contains("SCCACHE_NO_DAEMON=1\n"),
        "missing SCCACHE_NO_DAEMON: {env2}"
    );
    assert!(
        env2.contains("SCCACHE_CACHE_SIZE=200G\n"),
        "missing SCCACHE_CACHE_SIZE: {env2}"
    );
    assert!(
        env2.contains("SCCACHE_DIR=/var/cache/ghars/pools/build/sccache\n"),
        "missing SCCACHE_DIR: {env2}"
    );
}

/// Renderer contract test: with two ccache bindings in
/// `spec.caches`, `render_runner_env_file` emits a per-binding
/// `CCACHE_MAXSIZE=` line for EACH binding in `spec.caches` source
/// order. The downstream `.env` loader semantic
/// (`Runner.Listener::LoadAndSetEnv` calls
/// `Environment.SetEnvironmentVariable` per line, later call
/// overwrites earlier) is the CONSEQUENCE that motivated the
/// `validate_no_duplicate_cache_kinds` gate — but this test does
/// not exercise that consumer. It pins the upstream renderer
/// contract: both lines present, deterministic source order.
///
/// The config-load gate
/// `crate::cli::load::validate_no_duplicate_cache_kinds` REJECTS
/// multi-ccache configs before render — operators cannot trigger
/// this path through normal `ghars apply`. This test pins the
/// renderer's contract for direct-construct code paths (test
/// fixtures, future programmatic users) so the per-binding
/// emission stays deterministic if it's ever reachable.
///
/// The `lower_to_effective` pipeline sorts `caches` alphabetically
/// by `name` (src/plan/compute.rs `caches.sort_by`) before reaching
/// this renderer — but that pipeline is upstream; this test
/// constructs `spec.caches` directly so it pins the renderer
/// contract, not the full pipeline.
#[test]
fn render_runner_env_file_emits_one_ccache_maxsize_per_binding_in_source_order() {
    let mut spec = minimal_spec();
    spec.caches.push(crate::config::EffectiveCacheBinding {
        name: "build".into(),
        kinds: vec![CacheKind::Ccache],
        size: "50G".into(),
        mode: CacheMode::Shared,
        trust_zone: "default".into(),
        sccache_path: None,
        sleep_path: Some("/usr/bin/sleep".into()),
        server_mode: crate::config::SccacheServerMode::Pooled,
        renderer_schema: crate::systemd::RENDERER_SCHEMA,
    });
    spec.caches.push(crate::config::EffectiveCacheBinding {
        name: "test".into(),
        kinds: vec![CacheKind::Ccache],
        size: "100G".into(),
        mode: CacheMode::Shared,
        trust_zone: "default".into(),
        sccache_path: None,
        sleep_path: Some("/usr/bin/sleep".into()),
        server_mode: crate::config::SccacheServerMode::Pooled,
        renderer_schema: crate::systemd::RENDERER_SCHEMA,
    });
    let env = render_runner_env_file(&spec).unwrap();
    assert!(
        env.contains("CCACHE_MAXSIZE=50G\n"),
        "missing first binding's CCACHE_MAXSIZE: {env}"
    );
    assert!(
        env.contains("CCACHE_MAXSIZE=100G\n"),
        "missing second binding's CCACHE_MAXSIZE: {env}"
    );
    let p50 = env.find("CCACHE_MAXSIZE=50G").unwrap();
    let p100 = env.find("CCACHE_MAXSIZE=100G").unwrap();
    assert!(
        p50 < p100,
        "spec.caches order must drive emission order (50G before 100G): {env}"
    );
    // CCACHE_DIR is trust-zone-fixed, not per-binding. Pin that
    // multi-ccache bindings do NOT introduce per-pool CCACHE_DIR
    // emissions — that property is load-bearing for the
    // singleton-per-kind validator's rationale.
    let ccache_dir_count = env.matches("CCACHE_DIR=").count();
    assert_eq!(
        ccache_dir_count, 1,
        "CCACHE_DIR must be emitted exactly once (trust-zone-fixed, not per-binding): {env}"
    );
    // Pin the trust_zone-interpolated VALUE so a regression that
    // swapped the trust_zone variable for a literal "default"
    // doesn't break operators on non-default trust zones while
    // still passing the count check above.
    assert!(
        env.contains("CCACHE_DIR=/var/lib/ghars/default/.ccache\n"),
        "CCACHE_DIR must include the trust-zone-interpolated path: {env}"
    );
}

#[test]
fn render_runner_path_file_contains_ccache_wrappers_and_cargo_bin() {
    // Single line, newline-terminated. ccache wrappers FIRST so
    // bare `gcc`/`cc` resolve to wrappers (otherwise 100% ccache
    // misses). Per-runner .cargo/bin segment included. System path
    // tail in sbin-before-bin order.
    let spec = minimal_spec(); // trust_zone=default, name=buckos
    let p = render_runner_path_file(&spec).unwrap();
    assert!(p.ends_with('\n'), "path_file must end with newline: {p:?}");
    assert_eq!(
        p.matches('\n').count(),
        1,
        "path_file must be exactly one line: {p:?}"
    );
    assert!(
        p.starts_with("/usr/lib64/ccache:/usr/lib/ccache:"),
        "ccache wrappers must come first: {p}"
    );
    assert!(
        p.contains("/var/lib/ghars/default/ghars-buckos/.cargo/bin"),
        "missing per-runner .cargo/bin: {p}"
    );
    assert!(
        p.ends_with(":/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin\n"),
        "system path tail wrong: {p}"
    );
}

// ---- render_identity defense-in-depth rejection tests ------------
//
// Each test mutates ONE interpolated field in `minimal_spec()`,
// calls `render_runner_unit`, and asserts:
//   - render returns Err(GharsError::Validation),
//   - the error message names the offending field and the
//     character class label,
//   - the offending byte itself never appears in the message
//     (defense-in-depth: validation errors should not leak the
//     value being validated).
//
// Coverage targets `check_identity_field`'s four labels (newline,
// carriage return, NUL byte, control character) crossed against
// multiple interpolated fields (name, url, auth_name, user,
// labels[], caches[].name).

/// Helper: assert `render_runner_unit(spec)` errors with the
/// expected field name + class label, and that the offending
/// `bad` byte does NOT appear in the message segment of the
/// rendered Display.
///
/// `GharsError::Validation` Display is
/// `"validation: <msg>\n  hint: <hint>"` (see error.rs's
/// `Validation` variant `#[error(...)]` thiserror attribute),
/// so the message segment is everything before `"\n  hint:"`.
/// Checking only that segment avoids a false positive when the
/// bad byte is itself `\n` (which the Display formatter always
/// embeds between message and hint).
fn assert_render_identity_rejects(spec: &EffectiveRunnerSpec, field: &str, class: &str, bad: char) {
    let err = render_runner_unit(spec).unwrap_err();
    assert!(
        matches!(err, GharsError::Validation(_, _)),
        "expected Validation, got {err:?}"
    );
    let msg = format!("{err}");
    assert!(
        msg.contains("render_identity"),
        "error must name the rejecting function: {msg}"
    );
    assert!(
        msg.contains(field),
        "error must name the offending field {field:?}: {msg}"
    );
    assert!(
        msg.contains(class),
        "error must name the character class {class:?}: {msg}"
    );
    // Defense-in-depth: the offending byte must not appear in the
    // message segment (everything before the Display formatter's
    // hint delimiter `\n  hint:`).
    let message_segment = msg.split("\n  hint:").next().unwrap_or(&msg);
    assert!(
        !message_segment.contains(bad),
        "error message must not leak the offending byte {bad:?} \
         (segment before hint delimiter): {message_segment:?}"
    );
}

#[test]
fn render_identity_rejects_newline_in_name() {
    let mut spec = minimal_spec();
    spec.name = "buckos\nINJECTED=1".into();
    assert_render_identity_rejects(&spec, "name", "newline", '\n');
}

#[test]
fn render_identity_rejects_carriage_return_in_url() {
    let mut spec = minimal_spec();
    spec.url = "https://github.com/example/buckos\rPOLLUTE=1".into();
    assert_render_identity_rejects(&spec, "url", "carriage return", '\r');
}

#[test]
fn render_identity_rejects_nul_in_auth_name() {
    let mut spec = minimal_spec();
    spec.auth_name = "pat\0attacker".into();
    assert_render_identity_rejects(&spec, "auth_name", "NUL byte", '\0');
}

#[test]
fn render_identity_rejects_newline_in_label() {
    let mut spec = minimal_spec();
    spec.labels = vec!["self-hosted".into(), "linux\nbad".into()];
    assert_render_identity_rejects(&spec, "labels[]", "newline", '\n');
}

#[test]
fn render_identity_rejects_newline_in_cache_name() {
    let mut spec = minimal_spec();
    spec.caches.push(EffectiveCacheBinding {
        name: "build\npool".into(),
        kinds: vec![CacheKind::Ccache],
        size: "10G".into(),
        mode: CacheMode::Shared,
        trust_zone: "default".into(),
        sccache_path: None,
        sleep_path: Some("/usr/bin/sleep".into()),
        server_mode: crate::config::SccacheServerMode::Pooled,
        renderer_schema: crate::systemd::RENDERER_SCHEMA,
    });
    assert_render_identity_rejects(&spec, "caches[].name", "newline", '\n');
}

/// Positive path: a clean `minimal_spec` MUST render without error.
/// Without this pin, a buggy `check_identity_field` that rejects
/// every input (e.g. inverted condition) would only show up on
/// the rejection tests — and they'd all pass, masking the bug.
#[test]
fn render_identity_accepts_clean_spec() {
    let spec = minimal_spec();
    let r = render_runner_unit(&spec).expect("clean spec must render");
    // Sanity: the rendered drop-in actually contains a key from
    // every check_identity_field call site (proving we hit the
    // success branch end-to-end, not just a short-circuit).
    let id = r.drop_ins.get("00-ghars.conf").unwrap();
    assert!(id.contains("X-Ghars-Runner-Name=buckos"));
    assert!(id.contains("X-Ghars-Auth-Name=pat"));
    assert!(id.contains("X-Ghars-Trust-Zone=default"));
}

/// Empty `caches` MUST emit `X-Ghars-Caches=` with
/// an empty value, NOT skip the line. The classifier
/// distinguishes `Some(vec![])` (line present, empty value) from
/// `None` (line absent) — see `DiscoveredAnnotations` docstring.
/// Without an unconditional emit, a runner whose caches list
/// shrinks from `["pool-a"]` → `[]` would have no on-disk record
/// of the prior membership, so `apply.rs` could not compute a
/// caches-list diff for the drop-in body rewrite.
#[test]
fn render_identity_emits_x_ghars_caches_with_empty_value_when_caches_empty() {
    let spec = minimal_spec();
    // minimal_spec already has caches=vec![] — pin that here
    // explicitly so a future minimal_spec mutation doesn't silently
    // weaken the test.
    assert!(
        spec.caches.is_empty(),
        "test relies on minimal_spec having empty caches"
    );
    let r = render_runner_unit(&spec).expect("clean spec must render");
    let id = r.drop_ins.get("00-ghars.conf").unwrap();
    // Anchor on `\nX-Ghars-Caches=\n` (line break before, line break
    // immediately after the `=`). This catches both "missing line"
    // (substring absent) and "line with non-empty value"
    // (`X-Ghars-Caches=pool-a\n` would not contain `=\n`).
    // `writeln!` emits `\n` after every line, so `=\n` is the
    // unambiguous empty-value signature.
    assert!(
        id.contains("\nX-Ghars-Caches=\n"),
        "00-ghars.conf must contain `X-Ghars-Caches=` with empty value when \
         spec.caches is empty; got drop-in:\n{id}"
    );
}

/// `render_identity` sorts `spec.labels` alphabetically before
/// emitting the `X-Ghars-Labels=` annotation, regardless of the
/// order they arrive in. `plan::merge_defaults` already sorts
/// labels via `labels.sort_unstable()`; this test pins the
/// defense-in-depth re-sort inside `render_identity` (where the
/// `X-Ghars-Labels=` line is emitted) so a direct
/// `EffectiveRunnerSpec` constructor that bypasses
/// `merge_defaults` still produces a canonical on-disk
/// annotation. A regression dropping the sort
/// at the emission site would surface here as the line carrying
/// the unsorted construction order.
#[test]
fn render_identity_emits_labels_sorted() {
    // Build the spec DIRECTLY (no merge_defaults) so the test
    // proves the emission-site sort is load-bearing.
    let mut spec = minimal_spec();
    spec.labels = vec!["zebra".into(), "alpha".into(), "middle".into()];
    let r = render_runner_unit(&spec).expect("clean spec must render");
    let id = r.drop_ins.get("00-ghars.conf").unwrap();
    // Exact-line pin: `X-Ghars-Labels=alpha,middle,zebra` followed
    // by `\n`. Any other order (insertion: zebra,alpha,middle;
    // reverse: zebra,middle,alpha) would not contain this exact
    // substring.
    assert!(
        id.contains("\nX-Ghars-Labels=alpha,middle,zebra\n"),
        "X-Ghars-Labels= must emit values in alphabetical order; got drop-in:\n{id}"
    );
}

/// `render_identity` emits `X-Ghars-Dns` + `X-Ghars-Ipv6`
/// annotations when `spec.network` is `Some`. Without these the
/// classifier sees a `spec_hash` flip on dns/ipv6 edit but no
/// Stage 1 `FieldChange` — falls through to the uncovered arm.
/// Both annotations use the plain-string convention shared with
/// every other `X-Ghars-*` line: dns via
/// `crate::config::dns_to_annotation` (`forward` / `static:<csv>`)
/// and ipv6 via `crate::config::ipv6_to_annotation` (`disabled`
/// / `enabled`). Both must be parseable by
/// `DiscoveredAnnotations::from_drop_in_body`.
#[test]
fn render_identity_emits_x_ghars_dns_and_ipv6_for_netns_runner() {
    use crate::config::{DnsMode, EffectiveNetworkBinding, Ipv6Mode, NetworkMode, NetworkSpec};
    let mut spec = minimal_spec();
    spec.network = Some(EffectiveNetworkBinding {
        name: "isolated".into(),
        spec: NetworkSpec {
            mode: NetworkMode::Netns,
            allowed_egress: vec![],
            ip_allow: vec![],
            ip_deny: vec![],
            restrict_address_families: vec![],
            dns: DnsMode::Forward,
            ipv6: Ipv6Mode::Disabled,
        },
        subnet: None,
    });
    let r = render_runner_unit(&spec).expect("clean spec must render");
    let id = r.drop_ins.get("00-ghars.conf").unwrap();
    // Dns renders via `dns_to_annotation` — plain-string form
    // matching the convention of other X-Ghars-* annotations
    // (X-Ghars-Network-Mode=netns, X-Ghars-Labels=...). Forward
    // emits the literal `forward`.
    assert!(
        id.contains("\nX-Ghars-Dns=forward\n"),
        "00-ghars.conf must contain X-Ghars-Dns=forward when spec.network is Some + dns=Forward; got drop-in:\n{id}"
    );
    assert!(
        id.contains("\nX-Ghars-Ipv6=disabled\n"),
        "00-ghars.conf must contain X-Ghars-Ipv6=disabled for default Ipv6Mode; got drop-in:\n{id}"
    );
}

/// Inverse: when `spec.network` is `None` (operator did not
/// reference any `[network.NAME]` block — implicit host-netns),
/// the dns/ipv6 annotations MUST NOT be emitted; they're
/// `NetworkSpec` sub-fields and have no meaning without a network
/// binding. Open-mode bindings WITH cgroup-BPF policies still
/// materialize `spec.network = Some(...)` and DO emit per the
/// sibling test
/// `render_identity_emits_x_ghars_dns_and_ipv6_for_open_mode_runner`.
#[test]
fn render_identity_omits_x_ghars_dns_and_ipv6_when_no_network() {
    let spec = minimal_spec();
    assert!(spec.network.is_none(), "minimal_spec must have no network");
    let r = render_runner_unit(&spec).expect("clean spec must render");
    let id = r.drop_ins.get("00-ghars.conf").unwrap();
    assert!(
        !id.contains("X-Ghars-Dns="),
        "00-ghars.conf must NOT contain X-Ghars-Dns= when spec.network is None; got drop-in:\n{id}"
    );
    assert!(
        !id.contains("X-Ghars-Ipv6="),
        "00-ghars.conf must NOT contain X-Ghars-Ipv6= when spec.network is None; got drop-in:\n{id}"
    );
}

/// Pins the Open-mode emission decision: X-Ghars-Dns +
/// X-Ghars-Ipv6 ARE emitted for Open-mode network bindings (gate
/// is `spec.network.is_some()`, NOT `mode == Netns`). Open-mode
/// values are validator-constrained to `forward` + `disabled`
/// today (per `validators::validate_network_spec`), so this test
/// pins the trivially-valued emission as an intentional contract.
/// A future regression that added `if matches!(net.spec.mode,
/// NetworkMode::Netns)` gating would silently drop the
/// annotations from Open-mode drop-ins — this test would fail.
#[test]
fn render_identity_emits_x_ghars_dns_and_ipv6_for_open_mode_runner() {
    use crate::config::{DnsMode, EffectiveNetworkBinding, Ipv6Mode, NetworkMode, NetworkSpec};
    let mut spec = minimal_spec();
    spec.network = Some(EffectiveNetworkBinding {
        name: "host-policy".into(),
        spec: NetworkSpec {
            mode: NetworkMode::Open,
            allowed_egress: vec![],
            ip_allow: vec!["10.0.0.0/8".parse().unwrap()],
            ip_deny: vec![],
            restrict_address_families: vec![],
            dns: DnsMode::Forward,
            ipv6: Ipv6Mode::Disabled,
        },
        subnet: None,
    });
    let r = render_runner_unit(&spec).expect("clean spec must render");
    let id = r.drop_ins.get("00-ghars.conf").unwrap();
    assert!(
        id.contains("\nX-Ghars-Dns=forward\n"),
        "00-ghars.conf must contain X-Ghars-Dns=forward for Open-mode binding (validator-fixed value); got drop-in:\n{id}"
    );
    assert!(
        id.contains("\nX-Ghars-Ipv6=disabled\n"),
        "00-ghars.conf must contain X-Ghars-Ipv6=disabled for Open-mode binding (validator-fixed value); got drop-in:\n{id}"
    );
}

/// Propagation: `render_runner_unit` must surface the
/// `check_identity_field` error verbatim (it's not swallowed
/// or wrapped with a layer that obscures the offending field).
/// The error must still name "`render_identity`" so an operator
/// reading stderr can pinpoint the rejecting function.
#[test]
fn render_runner_unit_propagates_check_identity_field_error() {
    let mut spec = minimal_spec();
    spec.name = "buckos\nbad".into();
    let err = render_runner_unit(&spec).unwrap_err();
    let msg = format!("{err}");
    assert!(
        msg.contains("render_identity"),
        "render_runner_unit must propagate the check_identity_field \
         error verbatim: {msg}"
    );
}

/// Fail-fast ordering: when MULTIPLE fields are bad, the
/// FIRST validated field surfaces — `render_identity` validates
/// in order (`spec_hash`, name, url, `auth_name`, ...) and the `?`
/// short-circuits on the first failure. Pin that order: a bad
/// `url` AND bad `name` MUST report `url` (validated earlier),
/// not `name`.
#[test]
fn render_identity_validation_runs_before_any_write() {
    let mut spec = minimal_spec();
    spec.url = "https://github.com/example/buckos\nbad".into();
    let err = render_runner_unit(&spec).unwrap_err();
    let msg = format!("{err}");
    assert!(
        msg.contains("\"url\""),
        "first-validated field (url) must surface, not a later \
         field (prefix): {msg}"
    );
    assert!(
        !msg.contains("\"prefix\""),
        "later-validated field (prefix) must NOT surface — fail-fast \
         on first error: {msg}"
    );
}

// ---- defense-in-depth across render_hardening / render_proxy / render_numa
//
// Each test mutates ONE operator-controllable string in
// `minimal_spec()`, calls `render_runner_unit`, and asserts:
//   - render returns Err(GharsError::Validation),
//   - the error message names the offending field and the
//     character class label (newline).
// The pattern matches the render_identity tests above and pins
// that the corresponding render_* function gates the value
// BEFORE any bytes hit the drop-in body.

#[test]
fn render_hardening_rejects_newline_in_extra_capabilities_entry() {
    let mut spec = minimal_spec();
    spec.hardening.extra_capabilities = vec!["CAP_NET_BIND_SERVICE\nINJECTED=1".into()];
    let err = render_runner_unit(&spec).unwrap_err();
    assert!(
        matches!(err, GharsError::Validation(_, _)),
        "expected Validation, got {err:?}"
    );
    let msg = format!("{err}");
    assert!(
        msg.contains("extra_capabilities[]"),
        "msg must name field: {msg}"
    );
    assert!(msg.contains("newline"), "msg must name class: {msg}");
}

// ---- check_no_whitespace_padding renderer-side gate
//
// Direct-construct exercise of `check_no_whitespace_padding`
// across all 5 Hardening list-typed fields (see the helper's
// doc-comment for per-field coverage role — defense-in-depth
// for extra_syscalls/extra_capabilities, safety net for
// restrict_address_families, primary defense for
// bind_readonly_paths, trailing-whitespace closer for
// extra_bind_paths). Each test mutates ONE operator-controllable
// list entry in `minimal_spec()` to add surrounding whitespace,
// calls `render_runner_unit`, and asserts the error names the
// offending field + says "whitespace".

#[test]
fn render_hardening_rejects_whitespace_padding_in_extra_capabilities_entry() {
    let mut spec = minimal_spec();
    spec.hardening.extra_capabilities = vec!["  CAP_NET_BIND_SERVICE  ".into()];
    let err = render_runner_unit(&spec).unwrap_err();
    assert!(
        matches!(err, GharsError::Validation(_, _)),
        "expected Validation, got {err:?}"
    );
    let msg = format!("{err}");
    assert!(
        msg.contains("extra_capabilities[]"),
        "msg must name field: {msg}"
    );
    assert!(msg.contains("whitespace"), "msg must name class: {msg}");
}

#[test]
fn render_hardening_rejects_whitespace_padding_in_extra_syscalls_entry() {
    let mut spec = minimal_spec();
    spec.hardening.extra_syscalls = vec!["  read  ".into()];
    let err = render_runner_unit(&spec).unwrap_err();
    assert!(
        matches!(err, GharsError::Validation(_, _)),
        "expected Validation, got {err:?}"
    );
    let msg = format!("{err}");
    assert!(
        msg.contains("extra_syscalls[]"),
        "msg must name field: {msg}"
    );
    assert!(msg.contains("whitespace"), "msg must name class: {msg}");
}

#[test]
fn render_hardening_rejects_whitespace_padding_in_restrict_address_families_entry() {
    let mut spec = minimal_spec();
    spec.hardening.restrict_address_families = vec!["  AF_UNIX  ".into()];
    let err = render_runner_unit(&spec).unwrap_err();
    assert!(
        matches!(err, GharsError::Validation(_, _)),
        "expected Validation, got {err:?}"
    );
    let msg = format!("{err}");
    assert!(
        msg.contains("restrict_address_families[]"),
        "msg must name field: {msg}"
    );
    assert!(msg.contains("whitespace"), "msg must name class: {msg}");
}

#[test]
fn render_hardening_rejects_whitespace_padding_in_bind_readonly_paths_entry() {
    let mut spec = minimal_spec();
    spec.hardening.bind_readonly_paths = Some(vec![Utf8PathBuf::from("  /etc/example  ")]);
    let err = render_runner_unit(&spec).unwrap_err();
    assert!(
        matches!(err, GharsError::Validation(_, _)),
        "expected Validation, got {err:?}"
    );
    let msg = format!("{err}");
    assert!(
        msg.contains("bind_readonly_paths[]"),
        "msg must name field: {msg}"
    );
    assert!(msg.contains("whitespace"), "msg must name class: {msg}");
}

#[test]
fn render_hardening_rejects_whitespace_padding_in_extra_bind_paths_entry() {
    let mut spec = minimal_spec();
    spec.hardening.extra_bind_paths = vec![Utf8PathBuf::from("  /var/log/example  ")];
    let err = render_runner_unit(&spec).unwrap_err();
    assert!(
        matches!(err, GharsError::Validation(_, _)),
        "expected Validation, got {err:?}"
    );
    let msg = format!("{err}");
    assert!(
        msg.contains("extra_bind_paths[]"),
        "msg must name field: {msg}"
    );
    assert!(msg.contains("whitespace"), "msg must name class: {msg}");
}

/// Per-side trim coverage: a regression that swapped `value.trim()`
/// for `value.trim_end()` would skip leading-whitespace detection.
/// The 5 both-end-padded tests above don't catch that regression
/// because their fixtures have whitespace at both ends (`trim_end`
/// would still reject them via the trailing whitespace). This test
/// uses leading-only padding to pin the leading-trim half of
/// `str::trim`'s contract.
#[test]
fn render_hardening_rejects_leading_only_whitespace_in_extra_capabilities_entry() {
    let mut spec = minimal_spec();
    spec.hardening.extra_capabilities = vec![" CAP_NET_BIND_SERVICE".into()];
    let err = render_runner_unit(&spec).unwrap_err();
    assert!(
        matches!(err, GharsError::Validation(_, _)),
        "expected Validation, got {err:?}"
    );
    let msg = format!("{err}");
    assert!(
        msg.contains("extra_capabilities[]"),
        "msg must name field: {msg}"
    );
    assert!(msg.contains("whitespace"), "msg must name class: {msg}");
}

/// Symmetric inverse of the test above: a regression that swapped
/// `value.trim()` for `value.trim_start()` would skip trailing-
/// whitespace detection. Trailing-only fixture pins the trailing-
/// trim half of `str::trim`'s contract.
#[test]
fn render_hardening_rejects_trailing_only_whitespace_in_extra_capabilities_entry() {
    let mut spec = minimal_spec();
    spec.hardening.extra_capabilities = vec!["CAP_NET_BIND_SERVICE ".into()];
    let err = render_runner_unit(&spec).unwrap_err();
    assert!(
        matches!(err, GharsError::Validation(_, _)),
        "expected Validation, got {err:?}"
    );
    let msg = format!("{err}");
    assert!(
        msg.contains("extra_capabilities[]"),
        "msg must name field: {msg}"
    );
    assert!(msg.contains("whitespace"), "msg must name class: {msg}");
}

#[test]
fn render_proxy_rejects_newline_in_https_url() {
    let mut spec = minimal_spec();
    spec.proxy = Some(ProxySpec {
        http: None,
        https: Some("http://192.168.2.84:3128\nINJECTED=1".into()),
        no_proxy: vec![],
        ca_certs: vec![],
    });
    let err = render_runner_unit(&spec).unwrap_err();
    assert!(
        matches!(err, GharsError::Validation(_, _)),
        "expected Validation, got {err:?}"
    );
    let msg = format!("{err}");
    assert!(msg.contains("proxy.https"), "msg must name field: {msg}");
    assert!(msg.contains("newline"), "msg must name class: {msg}");
}

#[test]
fn render_numa_rejects_newline_in_allowed_cpus() {
    let mut spec = minimal_spec();
    spec.allowed_cpus = Some("0-31\nINJECTED=1".into());
    let err = render_runner_unit(&spec).unwrap_err();
    assert!(
        matches!(err, GharsError::Validation(_, _)),
        "expected Validation, got {err:?}"
    );
    let msg = format!("{err}");
    assert!(msg.contains("allowed_cpus"), "msg must name field: {msg}");
    assert!(msg.contains("newline"), "msg must name class: {msg}");
}

/// Direct-construct defense-in-depth pin: a hand-built
/// `EffectiveRunnerSpec` with `Some("")` for `allowed_cpus` or
/// `allowed_memory_nodes` bypasses `merge_defaults`' normalization.
/// `render_numa` must STILL emit no 50-numa.conf for the
/// empty-string case (renderer-side filter mirrors
/// `render_memory`'s empty-string short-circuit).
#[test]
fn render_numa_treats_some_empty_as_none_at_renderer() {
    let mut spec = minimal_spec();
    spec.allowed_cpus = Some(String::new());
    spec.allowed_memory_nodes = Some(String::new());
    let r = render_runner_unit(&spec).unwrap();
    assert!(
        !r.drop_ins.contains_key("50-numa.conf"),
        "render_numa must not emit 50-numa.conf when both fields are \
         Some(empty); got drop-ins: {:?}",
        r.drop_ins.keys().collect::<Vec<_>>()
    );
}

/// Per-field independence pin: when ONLY `allowed_cpus` is
/// `Some(empty)`, the renderer must skip the `AllowedCPUs=` line
/// while still emitting `AllowedMemoryNodes=` for the non-empty
/// sister field. Pins that the per-field `.filter()` at
/// `render_numa` operates field-by-field — surviving non-empty
/// values still render, and the eliminated empty-string value
/// does NOT leak a bare `AllowedCPUs=` reset directive into the
/// body.
#[test]
fn render_numa_treats_some_empty_allowed_cpus_alone_as_none_for_that_field() {
    let mut spec = minimal_spec();
    spec.allowed_cpus = Some(String::new());
    spec.allowed_memory_nodes = Some("0".into());
    let r = render_runner_unit(&spec).unwrap();
    let body = r
        .drop_ins
        .get("50-numa.conf")
        .expect("50-numa.conf must still emit when one field is non-empty");
    assert!(
        body.contains("AllowedMemoryNodes=0"),
        "AllowedMemoryNodes=0 must appear in 50-numa.conf body; got:\n{body}"
    );
    assert!(
        !body.contains("AllowedCPUs="),
        "Some(empty) allowed_cpus must NOT emit AllowedCPUs= reset directive; got:\n{body}"
    );
}

/// Symmetric inverse of the test above: when ONLY
/// `allowed_memory_nodes` is `Some(empty)`, the renderer must
/// skip the `AllowedMemoryNodes=` line while still emitting
/// `AllowedCPUs=` for the non-empty sister field, and the
/// eliminated empty-string value does NOT leak a bare
/// `AllowedMemoryNodes=` reset directive into the body.
#[test]
fn render_numa_treats_some_empty_allowed_memory_nodes_alone_as_none_for_that_field() {
    let mut spec = minimal_spec();
    spec.allowed_cpus = Some("0-31".into());
    spec.allowed_memory_nodes = Some(String::new());
    let r = render_runner_unit(&spec).unwrap();
    let body = r
        .drop_ins
        .get("50-numa.conf")
        .expect("50-numa.conf must still emit when one field is non-empty");
    assert!(
        body.contains("AllowedCPUs=0-31"),
        "AllowedCPUs=0-31 must appear in 50-numa.conf body; got:\n{body}"
    );
    assert!(
        !body.contains("AllowedMemoryNodes="),
        "Some(empty) allowed_memory_nodes must NOT emit AllowedMemoryNodes= reset directive; got:\n{body}"
    );
}

// ---- defense-in-depth across the remaining render_*
// functions that interpolate operator-controllable strings into
// drop-in bodies. Same pattern as the render_hardening / render_proxy
// / render_numa tests above: mutate ONE field, call
// `render_runner_unit` (or `render_cache_drop_in`), assert the error
// surfaces with the field name + char-class label.

/// `render_memory`: `memory_max` is an operator-supplied free-form
/// String interpolated into `MemoryMax=`. A newline would inject a
/// new directive line. The field is gated by the defense-in-depth
/// `check_identity_field` call inside `render_memory`.
#[test]
fn render_memory_rejects_newline_in_memory_max() {
    let mut spec = minimal_spec();
    spec.memory_max = Some("110G\nINJECTED=1".into());
    let err = render_runner_unit(&spec).unwrap_err();
    assert!(
        matches!(err, GharsError::Validation(_, _)),
        "expected Validation, got {err:?}"
    );
    let msg = format!("{err}");
    assert!(msg.contains("memory_max"), "msg must name field: {msg}");
    assert!(msg.contains("newline"), "msg must name class: {msg}");
}

/// `render_cache_pool`: `caches[].size` is an operator-supplied
/// free-form String interpolated into `Environment=CCACHE_MAXSIZE=`
/// and `Environment=SCCACHE_CACHE_SIZE=` lines. A newline would
/// terminate the env value and inject another directive.
#[test]
fn render_cache_pool_rejects_newline_in_caches_size() {
    let mut spec = minimal_spec();
    spec.caches = vec![EffectiveCacheBinding {
        name: "build".into(),
        kinds: vec![CacheKind::Sccache],
        size: "200G\nINJECTED=1".into(),
        mode: CacheMode::Shared,
        trust_zone: "default".into(),
        sccache_path: Some("/usr/bin/sccache".into()),
        sleep_path: None,
        server_mode: crate::config::SccacheServerMode::Pooled,
        renderer_schema: crate::systemd::RENDERER_SCHEMA,
    }];
    let err = render_runner_unit(&spec).unwrap_err();
    assert!(
        matches!(err, GharsError::Validation(_, _)),
        "expected Validation, got {err:?}"
    );
    let msg = format!("{err}");
    assert!(msg.contains("caches[].size"), "msg must name field: {msg}");
    assert!(msg.contains("newline"), "msg must name class: {msg}");
}

/// `render_network`: `network.restrict_address_families[]` is an
/// operator-supplied free-form String entry joined with `" "` and
/// emitted on a `RestrictAddressFamilies=` line. A newline
/// anywhere in an entry would inject a new directive line.
#[test]
fn render_network_rejects_newline_in_restrict_address_families_entry() {
    let mut spec = minimal_spec();
    spec.network = Some(EffectiveNetworkBinding {
        name: "buck2-isolated".into(),
        spec: NetworkSpec {
            mode: NetworkMode::Netns,
            allowed_egress: vec![],
            ip_allow: vec![],
            ip_deny: vec![],
            restrict_address_families: vec!["AF_UNIX\nINJECTED=1".into()],
            dns: DnsMode::default(),
            ipv6: Ipv6Mode::default(),
        },
        subnet: Some("10.200.0.0/30".parse::<IpNet>().unwrap()),
    });
    let err = render_runner_unit(&spec).unwrap_err();
    assert!(
        matches!(err, GharsError::Validation(_, _)),
        "expected Validation, got {err:?}"
    );
    let msg = format!("{err}");
    assert!(
        msg.contains("network.restrict_address_families[]"),
        "msg must name field: {msg}"
    );
    assert!(msg.contains("newline"), "msg must name class: {msg}");
}

/// Sister to the `render_hardening` whitespace-padding rejection
/// tests above. `network.restrict_address_families[]` is the only
/// operator-supplied String surface in `render_network`'s body and
/// is joined with `" "` verbatim, so a whitespace-padded token
/// produces different on-disk bytes (and a different `spec_hash`)
/// from the equivalent unpadded form. Pin the renderer-side
/// `check_no_whitespace_padding` mirror that complements
/// `render_hardening`'s same-field gate. The canonical config-load
/// gate at `validators::validate_restrict_address_families` uses
/// the anchored `AF_FAMILY_RE` regex which implicitly rejects
/// padding via shape; this renderer-side check is the explicit
/// safety net for direct-construct callers that bypass
/// `cli::load`.
#[test]
fn render_network_rejects_whitespace_padding_in_restrict_address_families_entry() {
    let mut spec = minimal_spec();
    spec.network = Some(EffectiveNetworkBinding {
        name: "buck2-isolated".into(),
        spec: NetworkSpec {
            mode: NetworkMode::Netns,
            allowed_egress: vec![],
            ip_allow: vec![],
            ip_deny: vec![],
            restrict_address_families: vec!["  AF_UNIX  ".into()],
            dns: DnsMode::default(),
            ipv6: Ipv6Mode::default(),
        },
        subnet: Some("10.200.0.0/30".parse::<IpNet>().unwrap()),
    });
    let err = render_runner_unit(&spec).unwrap_err();
    assert!(
        matches!(err, GharsError::Validation(_, _)),
        "expected Validation, got {err:?}"
    );
    let msg = format!("{err}");
    assert!(
        msg.contains("network.restrict_address_families[]"),
        "msg must name field: {msg}"
    );
    assert!(msg.contains("whitespace"), "msg must name class: {msg}");
}

/// Open-mode sister to the Netns test above — pins that the
/// `check_no_whitespace_padding` gate fires INDEPENDENTLY of the
/// `if netns_mode` branch. A future regression that scoped the
/// check to only Netns mode would still pass the Netns test but
/// silently lose Open-mode coverage. Mirrors the existing
/// `render_network_open_rejects_newline_in_restrict_address_families_entry`
/// Netns-vs-Open pair pattern for the newline gate.
#[test]
fn render_network_open_rejects_whitespace_padding_in_restrict_address_families_entry() {
    let mut spec = minimal_spec();
    spec.network = Some(EffectiveNetworkBinding {
        name: "buck2-isolated".into(),
        spec: NetworkSpec {
            mode: NetworkMode::Open,
            allowed_egress: vec![],
            ip_allow: vec![],
            ip_deny: vec![],
            restrict_address_families: vec!["  AF_UNIX  ".into()],
            dns: DnsMode::default(),
            ipv6: Ipv6Mode::default(),
        },
        subnet: None,
    });
    let err = render_runner_unit(&spec).unwrap_err();
    assert!(
        matches!(err, GharsError::Validation(_, _)),
        "expected Validation, got {err:?}"
    );
    let msg = format!("{err}");
    assert!(
        msg.contains("network.restrict_address_families[]"),
        "msg must name field: {msg}"
    );
    assert!(msg.contains("whitespace"), "msg must name class: {msg}");
}

/// Defense-in-depth parity: `restrict_address_families[]` newline
/// rejection MUST fire under Open mode too. The renderer body
/// runs the same `check_identity_field` loop in both modes — the
/// gate is mode-independent because the directive lives at the
/// cgroup layer regardless of whether a netns is allocated.
/// Pin Open mode separately so a future regression that scopes
/// the check to only `if netns_mode { ... }` surfaces here.
#[test]
fn render_network_open_rejects_newline_in_restrict_address_families_entry() {
    let mut spec = minimal_spec();
    spec.network = Some(EffectiveNetworkBinding {
        name: "hostnet".into(),
        spec: NetworkSpec {
            mode: NetworkMode::Open,
            allowed_egress: vec![],
            ip_allow: vec![],
            ip_deny: vec![],
            restrict_address_families: vec!["AF_UNIX\nINJECTED=1".into()],
            dns: DnsMode::default(),
            ipv6: Ipv6Mode::default(),
        },
        subnet: None,
    });
    let err = render_runner_unit(&spec).unwrap_err();
    assert!(
        matches!(err, GharsError::Validation(_, _)),
        "expected Validation, got {err:?}"
    );
    let msg = format!("{err}");
    assert!(
        msg.contains("network.restrict_address_families[]"),
        "msg must name field: {msg}"
    );
    assert!(msg.contains("newline"), "msg must name class: {msg}");
}

/// `render_hooks`: SEC-12 defense-in-depth. The validator
/// (`validators::validate_hook_script`) rejects root-parent
/// hook paths at config load time, but the renderer is the
/// last gate before `BindReadOnlyPaths=<parent>` lands on
/// disk. A hook at `/foo.sh` whose parent is `/` would emit
/// `BindReadOnlyPaths=/`, mounting the entire host into the
/// runner sandbox. The render-time check refuses to emit such
/// a directive even if the validator was bypassed
/// (programmatic spec construction, future test surfaces).
#[test]
fn render_hooks_rejects_root_parent_pre_job_path() {
    let mut spec = minimal_spec();
    spec.hooks = Some(crate::config::HooksSpec {
        pre_job: Some(camino::Utf8PathBuf::from("/foo.sh")),
        post_job: None,
    });
    let err = render_runner_unit(&spec).unwrap_err();
    assert!(
        matches!(err, GharsError::Validation(_, _)),
        "expected Validation, got {err:?}"
    );
    let msg = format!("{err}");
    assert!(msg.contains("hooks.pre_job parent directory"), "msg: {msg}");
    assert!(msg.contains("/foo.sh"), "msg: {msg}");
    assert!(msg.contains("SEC-12"), "msg must label SEC-12: {msg}");
    assert!(msg.contains("filesystem root"), "msg: {msg}");
    // The shared `check_no_root_bind` helper emits a generic
    // remediation pointing operators at a narrower path or a
    // 99-*.conf operator drop-in. The hooks-specific subdirectory
    // hint lives at `validators::validate_hook_script` which fires
    // at config-load before the renderer.
    assert!(
        msg.contains("narrower path") || msg.contains("99-*.conf"),
        "remediation hint must point at narrower-path / drop-in: {msg}"
    );
}

/// Path-normalization tightening: `/foo/..` resolves to root via
/// `ParentDir` saturation in `binds_filesystem_root`. The previous
/// renderer-side check used `parent_str == "/"` string-equality and
/// ACCEPTED `/foo/..` (literal string is `/foo/..`, not `/`), so
/// the rendered drop-in carried `BindReadOnlyPaths=/foo/..` which
/// systemd's mount-path normalization resolves to `/` at unit-load
/// time — full host exposure. The post-refactor `check_no_root_bind`
/// component-walk catches this class. Regression-pin so a revert to
/// the weaker check surfaces here.
#[test]
fn render_hooks_rejects_parent_dir_climb_root_pre_job_path() {
    let mut spec = minimal_spec();
    spec.hooks = Some(crate::config::HooksSpec {
        pre_job: Some(camino::Utf8PathBuf::from("/foo/../bar.sh")),
        post_job: None,
    });
    let err = render_runner_unit(&spec).unwrap_err();
    assert!(matches!(err, GharsError::Validation(_, _)));
    let msg = format!("{err}");
    assert!(msg.contains("SEC-12"), "msg: {msg}");
    assert!(msg.contains("filesystem root"), "msg: {msg}");
    // Pin the full label format including the hook path. Mirrors
    // the label-format pin pattern from the render_hardening
    // SEC-12 tests — catches a regression where a future call site
    // drops the `hooks.<field>` scope prefix or the `for `{p}``
    // context suffix.
    assert!(msg.contains("hooks.pre_job parent directory"), "msg: {msg}");
    assert!(msg.contains("/foo/../bar.sh"), "msg: {msg}");
}

/// `render_hooks`: `hooks.pre_job` is an operator-supplied path
/// (`Utf8PathBuf` is a UTF-8 wrapper, not a control-char filter)
/// interpolated into `Environment=ACTIONS_RUNNER_HOOK_JOB_STARTED=`
/// and `BindReadOnlyPaths=` lines. A newline would split the env
/// value or escape into a separate `BindReadOnlyPaths` directive.
#[test]
fn render_hooks_rejects_newline_in_pre_job_path() {
    let mut spec = minimal_spec();
    spec.hooks = Some(crate::config::HooksSpec {
        pre_job: Some(camino::Utf8PathBuf::from(
            "/etc/ghars/hooks/pre.sh\nINJECTED=1",
        )),
        post_job: None,
    });
    let err = render_runner_unit(&spec).unwrap_err();
    assert!(
        matches!(err, GharsError::Validation(_, _)),
        "expected Validation, got {err:?}"
    );
    let msg = format!("{err}");
    assert!(msg.contains("hooks.pre_job"), "msg must name field: {msg}");
    assert!(msg.contains("newline"), "msg must name class: {msg}");
}

/// `render_cache_drop_in`: `binding.size` is an operator-supplied
/// String emitted via `Environment=SCCACHE_CACHE_SIZE=` /
/// `Environment=CCACHE_MAXSIZE=`. Direct call (not via
/// `render_runner_unit`) because cache drop-ins are rendered at a
/// separate call site (`plan.rs::into_cache_pool_plan`).
#[test]
fn render_cache_drop_in_rejects_newline_in_binding_size() {
    let binding = EffectiveCacheBinding {
        name: "build".into(),
        kinds: vec![CacheKind::Sccache],
        size: "200G\nINJECTED=1".into(),
        mode: CacheMode::Shared,
        trust_zone: "default".into(),
        sccache_path: Some("/usr/bin/sccache".into()),
        sleep_path: None,
        server_mode: crate::config::SccacheServerMode::Pooled,
        renderer_schema: crate::systemd::RENDERER_SCHEMA,
    };
    let err = render_cache_drop_in(&binding, "/etc/ghars/ghars.toml", "sha256:abcd")
        .expect_err("must reject newline");
    assert!(
        matches!(err, GharsError::Validation(_, _)),
        "expected Validation, got {err:?}"
    );
    let msg = format!("{err}");
    assert!(msg.contains("caches[].size"), "msg must name field: {msg}");
    assert!(msg.contains("newline"), "msg must name class: {msg}");
}

/// `render_cache_drop_in`: `binding.sccache_path` is interpolated
/// into the `ExecStart=` line for sccache-serving pools. A newline
/// in the path would split the `ExecStart=` directive and inject a
/// follow-up directive at unit-load time. The renderer's
/// `check_identity_field("caches[].sccache_path", ...)` gate must
/// reject newline before any bytes hit the drop-in body. Mirrors
/// `render_cache_drop_in_rejects_newline_in_binding_size`.
#[test]
fn render_cache_drop_in_rejects_newline_in_sccache_path() {
    let binding = EffectiveCacheBinding {
        name: "build".into(),
        kinds: vec![CacheKind::Sccache],
        size: "200G".into(),
        mode: CacheMode::Shared,
        trust_zone: "default".into(),
        sccache_path: Some("/usr/bin/sccache\nINJECTED=1".into()),
        sleep_path: None,
        server_mode: crate::config::SccacheServerMode::Pooled,
        renderer_schema: crate::systemd::RENDERER_SCHEMA,
    };
    let err = render_cache_drop_in(&binding, "/etc/ghars/ghars.toml", "sha256:abcd")
        .expect_err("must reject newline in sccache_path");
    assert!(
        matches!(err, GharsError::Validation(_, _)),
        "expected Validation, got {err:?}"
    );
    let msg = format!("{err}");
    assert!(
        msg.contains("caches[].sccache_path"),
        "msg must name field: {msg}"
    );
    assert!(msg.contains("newline"), "msg must name class: {msg}");
}

/// `render_cache_drop_in`: `binding.sleep_path` is interpolated
/// into the `ExecStart=` line for ccache-only pools. A newline in
/// the path would split the `ExecStart=` directive and inject a
/// follow-up directive at unit-load time. Mirrors the
/// `_in_sccache_path` test above; the gate is symmetric.
#[test]
fn render_cache_drop_in_rejects_newline_in_sleep_path() {
    let binding = EffectiveCacheBinding {
        name: "build".into(),
        kinds: vec![CacheKind::Ccache],
        size: "200G".into(),
        mode: CacheMode::Shared,
        trust_zone: "default".into(),
        sccache_path: None,
        sleep_path: Some("/usr/bin/sleep\nINJECTED=1".into()),
        server_mode: crate::config::SccacheServerMode::Pooled,
        renderer_schema: crate::systemd::RENDERER_SCHEMA,
    };
    let err = render_cache_drop_in(&binding, "/etc/ghars/ghars.toml", "sha256:abcd")
        .expect_err("must reject newline in sleep_path");
    assert!(
        matches!(err, GharsError::Validation(_, _)),
        "expected Validation, got {err:?}"
    );
    let msg = format!("{err}");
    assert!(
        msg.contains("caches[].sleep_path"),
        "msg must name field: {msg}"
    );
    assert!(msg.contains("newline"), "msg must name class: {msg}");
}

/// `render_cache_drop_in`: NUL bytes in `sccache_path` would
/// truncate the path at the parser's C-string boundary
/// (systemd's conf-parser treats every value as a C-string at
/// the libc layer). The renderer's
/// `check_identity_field("caches[].sccache_path", ...)` gate
/// must reject NUL bytes alongside newlines / carriage returns.
/// Mirrors the newline test above; the gate's NUL branch is the
/// "NUL byte" class label from `check_identity_field` and tests
/// elsewhere pin the same label
/// (`render_identity_rejects_nul_in_auth_name`).
#[test]
fn render_cache_drop_in_rejects_nul_in_sccache_path() {
    let binding = EffectiveCacheBinding {
        name: "build".into(),
        kinds: vec![CacheKind::Sccache],
        size: "200G".into(),
        mode: CacheMode::Shared,
        trust_zone: "default".into(),
        sccache_path: Some("/usr/bin/sccache\0attacker".into()),
        sleep_path: None,
        server_mode: crate::config::SccacheServerMode::Pooled,
        renderer_schema: crate::systemd::RENDERER_SCHEMA,
    };
    let err = render_cache_drop_in(&binding, "/etc/ghars/ghars.toml", "sha256:abcd")
        .expect_err("must reject NUL byte in sccache_path");
    assert!(
        matches!(err, GharsError::Validation(_, _)),
        "expected Validation, got {err:?}"
    );
    let msg = format!("{err}");
    assert!(
        msg.contains("caches[].sccache_path"),
        "msg must name field: {msg}"
    );
    assert!(msg.contains("NUL"), "msg must name class: {msg}");
}
