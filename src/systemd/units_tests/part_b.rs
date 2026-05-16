//! Units tests part b: networks, cgroup-bpf, proxy/hooks/numa,
//! cache drop-ins, cross-cutting integration. See `part_a.rs` for
//! template + identity + `runner_env_file` + `render_hardening` tests.

#![allow(clippy::unwrap_used, clippy::expect_used)]

use super::super::*;
use super::*;
use crate::systemd::{cache_template_text, netns_template_text};

#[test]
fn netns_template_has_load_bearing_execstop() {
    // ExecStop= is mandatory on RemainAfterExit=yes oneshot
    // units to prevent systemd from destroying runtime data.
    let t = netns_template_text();
    assert!(t.contains("RemainAfterExit=yes"));
    assert!(t.contains("ExecStop=+"));
}

#[test]
fn cache_template_has_protect_system_strict() {
    let t = cache_template_text();
    assert!(t.contains("ProtectSystem=strict"));
    assert!(t.contains("StopWhenUnneeded=yes"));
}

#[test]
fn render_minimal_spec_emits_identity_and_lognamespace() {
    let spec = minimal_spec();
    let r = render_runner_unit(&spec).unwrap();
    assert!(r.template.contains("[Unit]"));
    let id = r.drop_ins.get("00-ghars.conf").unwrap();
    assert!(id.contains("X-Ghars-Spec-Hash=sha256:dead"));
    assert!(id.contains("X-Ghars-Runner-Name=buckos"));
    assert!(id.contains("X-Ghars-Auth-Name=pat"));
    let log = r.drop_ins.get("80-lognamespace.conf").unwrap();
    assert!(log.contains("LogNamespace=ghars-buckos"));
}

#[test]
fn render_skips_optional_drop_ins_when_absent() {
    let spec = minimal_spec();
    let r = render_runner_unit(&spec).unwrap();
    assert!(!r.drop_ins.contains_key("10-memory.conf"));
    assert!(!r.drop_ins.contains_key("20-hardening.conf"));
    assert!(!r.drop_ins.contains_key("30-cache-pool.conf"));
    assert!(!r.drop_ins.contains_key("40-network.conf"));
    assert!(!r.drop_ins.contains_key("50-numa.conf"));
    assert!(!r.drop_ins.contains_key("60-proxy.conf"));
    assert!(!r.drop_ins.contains_key("70-hooks.conf"));
    // 15-resolv.conf IS always present; verified separately.
}

#[test]
fn render_resolv_bind_open_mode_binds_host_resolv_conf() {
    // No spec.network ⇒ Open mode ⇒ runner binds host's
    // /etc/resolv.conf (same source/destination).
    let spec = minimal_spec();
    let r = render_runner_unit(&spec).unwrap();
    let body = r
        .drop_ins
        .get("15-resolv.conf")
        .expect("15-resolv.conf must be present for every runner");
    assert!(body.contains("BindReadOnlyPaths=/etc/resolv.conf"));
    // Source != netns path.
    assert!(!body.contains("/run/ghars/netns-resolv/"));
}

#[test]
fn render_resolv_bind_netns_mode_binds_netns_source() {
    // Netns mode ⇒ runner binds the per-runner file written by
    // `_netns-setup` to /etc/resolv.conf (source:dest form).
    let mut spec = minimal_spec();
    spec.network = Some(EffectiveNetworkBinding {
        name: "buck2-isolated".into(),
        spec: NetworkSpec {
            mode: NetworkMode::Netns,
            allowed_egress: vec![EgressRule {
                addr: "192.168.2.84".into(),
                port: PortSpec::Single(3128),
                proto: Proto::Tcp,
                comment: None,
            }],
            ip_allow: vec![],
            ip_deny: vec![],
            restrict_address_families: vec![],
            dns: DnsMode::default(),
            ipv6: Ipv6Mode::default(),
        },
        subnet: Some("10.200.0.0/30".parse::<IpNet>().unwrap()),
    });
    let r = render_runner_unit(&spec).unwrap();
    let body = r.drop_ins.get("15-resolv.conf").unwrap();
    assert!(body.contains("BindReadOnlyPaths=/run/ghars/netns-resolv/buckos:/etc/resolv.conf",));
    // The bare host path must NOT be present.
    assert!(
        !body
            .lines()
            .any(|l| l.trim() == "BindReadOnlyPaths=/etc/resolv.conf")
    );
}

#[test]
fn template_omits_etc_resolv_conf_to_avoid_dedup_conflict() {
    // systemd's mount-list dedup keeps the FIRST same-destination
    // entry (src/core/namespace.c:drop_duplicates). To swap the
    // /etc/resolv.conf source per-runner the template must not bind
    // it; the 15-resolv.conf drop-in is the sole source.
    let body = runner_template_text();
    // The template's `BindReadOnlyPaths=/etc/hosts /etc/nsswitch.conf`
    // line must NOT include /etc/resolv.conf as a token.
    let resolv_line = body
        .lines()
        .find(|l| l.starts_with("BindReadOnlyPaths=") && l.contains("/etc/hosts"));
    let line = resolv_line.expect("etc/hosts bind line missing");
    assert!(
        !line.split_whitespace().any(|tok| tok == "/etc/resolv.conf"),
        "template line {line:?} must omit /etc/resolv.conf"
    );
}

#[test]
fn render_emits_memory_when_set() {
    let mut spec = minimal_spec();
    spec.memory_max = Some("110G".into());
    let r = render_runner_unit(&spec).unwrap();
    let m = r.drop_ins.get("10-memory.conf").unwrap();
    assert!(m.contains("MemoryMax=110G"));
}

#[test]
fn render_emits_hardening_when_overridden() {
    let mut spec = minimal_spec();
    spec.hardening.protect_control_groups = Some(true);
    spec.hardening.restrict_realtime = Some(true);
    spec.hardening.extra_syscalls = vec!["clone3".into(), "rseq".into()];
    spec.hardening.etc_bind_style = EtcBindStyle::Broad;
    let r = render_runner_unit(&spec).unwrap();
    let h = r.drop_ins.get("20-hardening.conf").unwrap();
    assert!(h.contains("ProtectControlGroups=yes"));
    assert!(h.contains("RestrictRealtime=yes"));
    assert!(h.contains("SystemCallFilter=clone3 rseq"));
    assert!(h.contains("BindReadOnlyPaths=/etc"));
    // Broad APPENDS to the template's curated /etc set rather
    // than replacing it. systemd unions list-typed directives
    // across template + drop-in unless an empty-RHS reset
    // (`BindReadOnlyPaths=` with nothing after `=`) clears the
    // prior list — the drop-in must not emit such a reset.
    assert!(
        !h.lines().any(|l| l.trim() == "BindReadOnlyPaths="),
        "Broad must not emit a BindReadOnlyPaths= reset directive: {h}"
    );
    // Sanity: no kvm-related lines or warnings when kvm wasn't
    // touched in the override.
    assert!(!h.lines().any(|l| l.starts_with("DeviceAllow")));
    assert!(r.warnings.is_empty());
}

// ---- single-token positive-render pins for the 4 Hardening
// list-typed fields not directly covered by
// `render_emits_hardening_when_overridden` above (which exercises
// extra_syscalls). `extra_capabilities` had no prior positive-render
// coverage; `restrict_address_families`, `bind_readonly_paths`, and
// `extra_bind_paths` are already exercised by composition fixtures
// elsewhere in this test file (the `*_composes_across_*` and
// `*_render_preserves_operator_order_for_colliding_paths` families)
// — these 4 tests add leaner single-token sibling pins so a
// regression that breaks the simple render path is caught at a
// narrow fixture before being masked by the broader composition
// fixtures. Pin that clean tokens pass BOTH `check_identity_field`
// AND `check_no_whitespace_padding` and render to the expected
// directive in the 20-hardening.conf drop-in body. Catches the
// regression where the whitespace gate becomes overly aggressive
// (e.g. swapped to `value != "FIXED"` by mistake) — would pass the
// negative tests above but break the simple positive render path.

#[test]
fn render_hardening_emits_extra_capabilities_for_clean_token() {
    let mut spec = minimal_spec();
    spec.hardening.extra_capabilities = vec!["CAP_NET_BIND_SERVICE".into()];
    let r = render_runner_unit(&spec).expect("clean token must render");
    let body = r
        .drop_ins
        .get("20-hardening.conf")
        .expect("20-hardening.conf expected when extra_capabilities is non-empty");
    assert!(
        body.contains("CapabilityBoundingSet=CAP_NET_BIND_SERVICE"),
        "expected CapabilityBoundingSet=CAP_NET_BIND_SERVICE in body; got:\n{body}"
    );
}

#[test]
fn render_hardening_emits_restrict_address_families_for_clean_token() {
    let mut spec = minimal_spec();
    spec.hardening.restrict_address_families = vec!["AF_UNIX".into()];
    let r = render_runner_unit(&spec).expect("clean token must render");
    let body = r
        .drop_ins
        .get("20-hardening.conf")
        .expect("20-hardening.conf expected when restrict_address_families is non-empty");
    assert!(
        body.contains("RestrictAddressFamilies=AF_UNIX"),
        "expected RestrictAddressFamilies=AF_UNIX in body; got:\n{body}"
    );
}

#[test]
fn render_hardening_emits_bind_readonly_paths_for_clean_path() {
    let mut spec = minimal_spec();
    spec.hardening.bind_readonly_paths = Some(vec![Utf8PathBuf::from("/etc/example")]);
    let r = render_runner_unit(&spec).expect("clean path must render");
    let body = r
        .drop_ins
        .get("20-hardening.conf")
        .expect("20-hardening.conf expected when bind_readonly_paths is non-empty");
    assert!(
        body.contains("BindReadOnlyPaths=/etc/example"),
        "expected BindReadOnlyPaths=/etc/example in body; got:\n{body}"
    );
}

/// Note: `extra_bind_paths` emits via the `BindReadOnlyPaths=`
/// directive (not `BindPaths=`) — systemd treats `BindReadOnlyPaths`
/// as list-typed, so both `bind_readonly_paths` and
/// `extra_bind_paths` append to the cumulative list (per
/// `render_hardening`'s call site above and the field doc-comment
/// on `Hardening::extra_bind_paths` at `config.rs`). The assertion
/// therefore checks for `BindReadOnlyPaths=/var/log/example`, not
/// `BindPaths=`.
#[test]
fn render_hardening_emits_extra_bind_paths_for_clean_path() {
    let mut spec = minimal_spec();
    spec.hardening.extra_bind_paths = vec![Utf8PathBuf::from("/var/log/example")];
    let r = render_runner_unit(&spec).expect("clean path must render");
    let body = r
        .drop_ins
        .get("20-hardening.conf")
        .expect("20-hardening.conf expected when extra_bind_paths is non-empty");
    assert!(
        body.contains("BindReadOnlyPaths=/var/log/example"),
        "expected BindReadOnlyPaths=/var/log/example in body; got:\n{body}"
    );
}

/// SEC-12 root-bind rejection: literal `/` in
/// `bind_readonly_paths`. `bind_readonly_paths` has no config-load
/// validator at all, so the renderer is the FIRST/ONLY gate. A
/// `BindReadOnlyPaths=/` emission would overlay-bind the host root
/// into the runner namespace, defeating every other Hardening
/// protection. Mirrors the existing `render_hooks` SEC-12 pattern.
#[test]
fn render_hardening_rejects_root_bind_readonly_paths() {
    let mut spec = minimal_spec();
    spec.hardening.bind_readonly_paths = Some(vec![Utf8PathBuf::from("/")]);
    let err = render_runner_unit(&spec).unwrap_err();
    assert!(
        matches!(err, GharsError::Validation(_, _)),
        "expected Validation, got {err:?}"
    );
    let msg = format!("{err}");
    assert!(msg.contains("bind_readonly_paths"), "msg: {msg}");
    assert!(msg.contains("SEC-12"), "msg: {msg}");
    assert!(msg.contains("filesystem root"), "msg: {msg}");
    // Pin the full label format. Without this, a future caller
    // dropping the `hardening.` prefix or the `[]` suffix would
    // still satisfy the `bind_readonly_paths` substring assertion
    // above. The label is the call site's contract with operators.
    assert!(
        msg.contains("hardening.bind_readonly_paths[]"),
        "msg: {msg}"
    );
}

/// Sister to `render_hardening_rejects_root_bind_readonly_paths`.
/// `extra_bind_paths` passes the config-load
/// `validate_extra_bind_paths` check today for bare `/` (the
/// `DENY_EXTRA_BIND_PATHS` list does not include `/`), so the
/// renderer is the only gate.
#[test]
fn render_hardening_rejects_root_extra_bind_paths() {
    let mut spec = minimal_spec();
    spec.hardening.extra_bind_paths = vec![Utf8PathBuf::from("/")];
    let err = render_runner_unit(&spec).unwrap_err();
    assert!(
        matches!(err, GharsError::Validation(_, _)),
        "expected Validation, got {err:?}"
    );
    let msg = format!("{err}");
    assert!(msg.contains("extra_bind_paths"), "msg: {msg}");
    assert!(msg.contains("SEC-12"), "msg: {msg}");
    assert!(msg.contains("filesystem root"), "msg: {msg}");
    // Pin the full label format. Sister to the bind_readonly_paths
    // assertion above — catches a regression where a future caller
    // drops the `hardening.` prefix or the `[]` suffix.
    assert!(msg.contains("hardening.extra_bind_paths[]"), "msg: {msg}");
}

/// Path-normalization variant: `//` collapses to `/` at
/// `mount(2)` time, so the SEC-12 gate must reject it even
/// though `path.as_str() == "/"` is false.
/// `binds_filesystem_root`'s component-walk handles this by
/// treating consecutive separators as a single `RootDir`
/// component.
#[test]
fn render_hardening_rejects_double_slash_root_bind_readonly_paths() {
    let mut spec = minimal_spec();
    spec.hardening.bind_readonly_paths = Some(vec![Utf8PathBuf::from("//")]);
    let err = render_runner_unit(&spec).unwrap_err();
    assert!(matches!(err, GharsError::Validation(_, _)));
    let msg = format!("{err}");
    assert!(msg.contains("SEC-12"), "msg: {msg}");
}

/// Path-normalization variant: `/.` is `RootDir + CurDir` which
/// resolves to root. The component-walk treats `CurDir` as a
/// no-op, leaving depth=0 → reject.
#[test]
fn render_hardening_rejects_dot_root_extra_bind_paths() {
    let mut spec = minimal_spec();
    spec.hardening.extra_bind_paths = vec![Utf8PathBuf::from("/.")];
    let err = render_runner_unit(&spec).unwrap_err();
    assert!(matches!(err, GharsError::Validation(_, _)));
    let msg = format!("{err}");
    assert!(msg.contains("SEC-12"), "msg: {msg}");
}

/// Path-normalization variant: `/foo/..` climbs to root via
/// `ParentDir`. The component-walk increments depth for `foo`
/// and decrements for `..`, leaving depth=0 → reject.
#[test]
fn render_hardening_rejects_parent_dir_climb_root_extra_bind_paths() {
    let mut spec = minimal_spec();
    spec.hardening.extra_bind_paths = vec![Utf8PathBuf::from("/foo/..")];
    let err = render_runner_unit(&spec).unwrap_err();
    assert!(matches!(err, GharsError::Validation(_, _)));
    let msg = format!("{err}");
    assert!(msg.contains("SEC-12"), "msg: {msg}");
}

/// Mid-list rejection: `/` in the middle of a list of valid
/// paths. The per-entry loop must iterate every entry; a
/// regression that only checked the first entry would miss
/// this case.
#[test]
fn render_hardening_rejects_root_mid_list_bind_readonly_paths() {
    let mut spec = minimal_spec();
    spec.hardening.bind_readonly_paths = Some(vec![
        Utf8PathBuf::from("/etc/example"),
        Utf8PathBuf::from("/"),
        Utf8PathBuf::from("/var/log/example"),
    ]);
    let err = render_runner_unit(&spec).unwrap_err();
    assert!(matches!(err, GharsError::Validation(_, _)));
    let msg = format!("{err}");
    assert!(msg.contains("SEC-12"), "msg: {msg}");
}

/// Empty entry must be rejected with the correct "entry is
/// empty" error class — NOT misclassified as "filesystem root"
/// (which would happen without the empty pre-check, since
/// `Path::components()` on `""` yields `[]` and the
/// component-walk returns depth=0).
/// `bind_readonly_paths` has no config-load validator so this
/// renderer-side check is the only gate.
#[test]
fn render_hardening_rejects_empty_bind_readonly_paths_entry() {
    let mut spec = minimal_spec();
    spec.hardening.bind_readonly_paths = Some(vec![Utf8PathBuf::from("")]);
    let err = render_runner_unit(&spec).unwrap_err();
    assert!(matches!(err, GharsError::Validation(_, _)));
    let msg = format!("{err}");
    assert!(msg.contains("bind_readonly_paths"), "msg: {msg}");
    assert!(msg.contains("empty"), "msg: {msg}");
    assert!(
        !msg.contains("filesystem root"),
        "empty entry must not be misclassified as filesystem root: {msg}"
    );
}

/// Sister to `render_hardening_rejects_empty_bind_readonly_paths_entry`
/// for `extra_bind_paths`. The config-load validator
/// `validate_extra_bind_paths` already rejects empty entries,
/// but this renderer-side check is defense-in-depth for
/// direct-construct callers that bypass cli/load.rs.
#[test]
fn render_hardening_rejects_empty_extra_bind_paths_entry() {
    let mut spec = minimal_spec();
    spec.hardening.extra_bind_paths = vec![Utf8PathBuf::from("")];
    let err = render_runner_unit(&spec).unwrap_err();
    assert!(matches!(err, GharsError::Validation(_, _)));
    let msg = format!("{err}");
    assert!(msg.contains("extra_bind_paths"), "msg: {msg}");
    assert!(msg.contains("empty"), "msg: {msg}");
    assert!(
        !msg.contains("filesystem root"),
        "empty entry must not be misclassified as filesystem root: {msg}"
    );
}

/// Negative regression: `/foo/../bar` resolves to `/bar` (a
/// non-root path) — must NOT be rejected. Catches a regression
/// that broadens the gate to reject any path containing `..`.
#[test]
fn render_hardening_accepts_parent_dir_normalized_to_non_root_extra_bind_paths() {
    let mut spec = minimal_spec();
    spec.hardening.extra_bind_paths = vec![Utf8PathBuf::from("/foo/../bar")];
    let r = render_runner_unit(&spec).expect("non-root path must render");
    let body = r
        .drop_ins
        .get("20-hardening.conf")
        .expect("20-hardening.conf expected when extra_bind_paths is non-empty");
    // The renderer emits the operator's textual path verbatim;
    // systemd resolves `..` at mount(2) time.
    assert!(
        body.contains("BindReadOnlyPaths=/foo/../bar"),
        "expected BindReadOnlyPaths=/foo/../bar; got:\n{body}"
    );
}

#[test]
fn render_hardening_rejects_colon_in_extra_bind_paths() {
    let mut spec = minimal_spec();
    spec.hardening.extra_bind_paths = vec![Utf8PathBuf::from("/etc:/")];
    let err = render_runner_unit(&spec).unwrap_err();
    assert!(matches!(err, GharsError::Validation(_, _)));
    let msg = format!("{err}");
    assert!(msg.contains("extra_bind_paths"), "msg: {msg}");
    assert!(msg.contains("SOURCE:DESTINATION"), "msg: {msg}");
}

#[test]
fn render_hardening_rejects_colon_in_bind_readonly_paths() {
    let mut spec = minimal_spec();
    spec.hardening.bind_readonly_paths = Some(vec![Utf8PathBuf::from("/etc:/shadow")]);
    let err = render_runner_unit(&spec).unwrap_err();
    assert!(matches!(err, GharsError::Validation(_, _)));
    let msg = format!("{err}");
    assert!(msg.contains("bind_readonly_paths"), "msg: {msg}");
    assert!(msg.contains("SOURCE:DESTINATION"), "msg: {msg}");
}

#[test]
fn render_hardening_rejects_whitespace_in_extra_bind_paths() {
    let mut spec = minimal_spec();
    spec.hardening.extra_bind_paths = vec![Utf8PathBuf::from("/etc/foo /etc/passwd")];
    let err = render_runner_unit(&spec).unwrap_err();
    assert!(matches!(err, GharsError::Validation(_, _)));
    let msg = format!("{err}");
    assert!(msg.contains("extra_bind_paths"), "msg: {msg}");
    assert!(msg.contains("whitespace"), "msg: {msg}");
}

#[test]
fn render_hardening_rejects_relative_extra_bind_paths() {
    let mut spec = minimal_spec();
    spec.hardening.extra_bind_paths = vec![Utf8PathBuf::from("foo")];
    let err = render_runner_unit(&spec).unwrap_err();
    assert!(matches!(err, GharsError::Validation(_, _)));
    let msg = format!("{err}");
    assert!(msg.contains("extra_bind_paths"), "msg: {msg}");
    assert!(msg.contains("not an absolute path"), "msg: {msg}");
}

#[test]
fn render_hardening_kvm_true_emits_device_allow() {
    // Explicit kvm=true is an override (the template default agrees,
    // but the operator's intent is recorded). The drop-in re-emits
    // `DeviceAllow=/dev/kvm rw` rather than relying on the template
    // alone; this also exercises the reset-on-empty validator
    // pass-through (a non-empty DeviceAllow line never triggers the
    // empty-reset rule).
    let mut spec = minimal_spec();
    spec.hardening.kvm = Some(true);
    let r = render_runner_unit(&spec).unwrap();
    let h = r.drop_ins.get("20-hardening.conf").unwrap();
    assert!(h.contains("DeviceAllow=/dev/kvm rw"));
    // Importantly: no bare `DeviceAllow=` reset present.
    assert!(
        !h.lines()
            .any(|l| l == "DeviceAllow=" || l == "DeviceAllow= ")
    );
    assert!(r.warnings.is_empty());
}

#[test]
fn render_hardening_kvm_false_resets_device_allow_and_warns() {
    // kvm=false must emit `DeviceAllow=` (empty
    // reset) so the template's `DeviceAllow=/dev/kvm rw` is
    // revoked. Combined with the template's `DevicePolicy=closed`,
    // this denies all device access. The renderer surfaces a
    // warning so apply prints "kvm=false drops /dev/kvm rw" to the
    // operator before executing.
    let mut spec = minimal_spec();
    spec.hardening.kvm = Some(false);
    let r = render_runner_unit(&spec).unwrap();
    let h = r.drop_ins.get("20-hardening.conf").unwrap();
    assert!(
        h.lines().any(|l| l == "DeviceAllow="),
        "expected bare `DeviceAllow=` reset line in:\n{h}"
    );
    assert!(!h.contains("/dev/kvm rw"));
    // The warning carries the runner name and explains the
    // consequence to the operator.
    assert_eq!(r.warnings.len(), 1);
    let w = &r.warnings[0];
    assert!(w.contains("buckos"));
    assert!(w.contains("kvm=false"));
    assert!(w.contains("DeviceAllow=/dev/kvm rw"));
}

#[test]
fn render_omits_30_cache_pool_for_ccache_filesystem_only() {
    let mut spec = minimal_spec();
    spec.caches.push(EffectiveCacheBinding {
        name: "build".into(),
        kinds: vec![CacheKind::Ccache],
        size: "200G".into(),
        mode: CacheMode::Shared,
        trust_zone: "default".into(),
        sccache_path: None,
        sleep_path: Some("/usr/bin/sleep".into()),
        renderer_schema: crate::systemd::RENDERER_SCHEMA,
    });
    let r = render_runner_unit(&spec).unwrap();
    // ccache-only pools use the filesystem-mode mechanism — no
    // ghars-cache@ unit dependency, no BindPaths to a pool dir,
    // no sccache server, no LAYER 1 Environment= directives. With
    // nothing structurally meaningful to emit, render_cache_pool
    // returns None and the 30-cache-pool.conf drop-in is absent
    // from RenderedUnit.drop_ins entirely — the apply layer's
    // DropInChangeKind::Removed branch will delete any stub left
    // over on disk from before this gate landed.
    assert!(
        !r.drop_ins.contains_key("30-cache-pool.conf"),
        "ccache-only pools must omit 30-cache-pool.conf (no LAYER 1 \
         directives to carry; CCACHE_DIR/CCACHE_MAXSIZE live in \
         LAYER 2 .env): got drop_ins {:?}",
        r.drop_ins.keys().collect::<Vec<_>>()
    );
}

/// Last-line-of-defense regression pin for a multi-ccache spec
/// reaching the renderer via direct `EffectiveRunnerSpec`
/// construction (bypassing `validate_no_duplicate_cache_kinds` at
/// config-load and the parallel `lower_to_effective` gate).
///
/// Multi-ccache bindings produce no structurally-meaningful drop-in
/// content — the ccache branch in `render_cache_pool` is empty by
/// design (`CCACHE_DIR` / `CCACHE_MAXSIZE` live in LAYER 2 .env, owned
/// by `render_runner_env_file`; the trust-zone-shared `CCACHE_DIR`
/// plus last-writer-wins `CCACHE_MAXSIZE` in .env is what ccache
/// actually consumes). With nothing to emit, the renderer returns
/// None and the 30-cache-pool.conf drop-in is absent from
/// `RenderedUnit.drop_ins` entirely.
///
/// Pins the renderer-side absence so a future regression that
/// re-introduces per-binding LAYER 1 emission (and thereby a
/// misleading `systemctl cat` view) fails this test immediately.
#[test]
fn render_omits_30_cache_pool_for_multi_ccache_only_spec() {
    let mut spec = minimal_spec();
    spec.caches.push(EffectiveCacheBinding {
        name: "obj-a".into(),
        kinds: vec![CacheKind::Ccache],
        size: "50G".into(),
        mode: CacheMode::Shared,
        trust_zone: "default".into(),
        sccache_path: None,
        sleep_path: Some("/usr/bin/sleep".into()),
        renderer_schema: crate::systemd::RENDERER_SCHEMA,
    });
    spec.caches.push(EffectiveCacheBinding {
        name: "obj-b".into(),
        kinds: vec![CacheKind::Ccache],
        size: "100G".into(),
        mode: CacheMode::Shared,
        trust_zone: "default".into(),
        sccache_path: None,
        sleep_path: Some("/usr/bin/sleep".into()),
        renderer_schema: crate::systemd::RENDERER_SCHEMA,
    });
    let r = render_runner_unit(&spec).unwrap();
    assert!(
        !r.drop_ins.contains_key("30-cache-pool.conf"),
        "multi-ccache spec must omit 30-cache-pool.conf (no LAYER 1 \
         directives produced — all CCACHE_* live in LAYER 2 .env): \
         got drop_ins {:?}",
        r.drop_ins.keys().collect::<Vec<_>>()
    );
}

#[test]
fn render_emits_cache_pool_for_sccache() {
    let mut spec = minimal_spec();
    spec.caches.push(EffectiveCacheBinding {
        name: "build".into(),
        kinds: vec![CacheKind::Sccache],
        size: "200G".into(),
        mode: CacheMode::Shared,
        trust_zone: "default".into(),
        sccache_path: Some("/usr/bin/sccache".into()),
        sleep_path: None,
        renderer_schema: crate::systemd::RENDERER_SCHEMA,
    });
    let r = render_runner_unit(&spec).unwrap();
    let c = r.drop_ins.get("30-cache-pool.conf").unwrap();
    assert!(c.contains("SCCACHE_SERVER_UDS=/run/ghars/cache-build.sock"));
    assert!(c.contains("SCCACHE_NO_DAEMON=1"));
    assert!(c.contains("BindPaths="));
    assert!(c.contains("/run/ghars"));
}

#[test]
fn render_emits_network_for_netns() {
    let mut spec = minimal_spec();
    let net_spec = NetworkSpec {
        mode: NetworkMode::Netns,
        allowed_egress: vec![],
        ip_allow: vec!["192.168.2.84/32".parse::<IpNet>().unwrap()],
        ip_deny: vec!["0.0.0.0/0".parse::<IpNet>().unwrap()],
        restrict_address_families: vec!["AF_UNIX".into(), "AF_INET".into()],
        dns: DnsMode::default(),
        ipv6: Ipv6Mode::default(),
    };
    spec.network = Some(EffectiveNetworkBinding {
        name: "buck2-isolated".into(),
        spec: net_spec,
        subnet: Some("10.200.0.0/30".parse::<IpNet>().unwrap()),
    });
    let r = render_runner_unit(&spec).unwrap();
    let n = r.drop_ins.get("40-network.conf").unwrap();
    assert!(n.contains("Requires=ghars-net@buckos.service"));
    assert!(n.contains("BindsTo=ghars-net@buckos.service"));
    assert!(n.contains("NetworkNamespacePath=/var/run/netns/ghars-buckos"));
    assert!(n.contains("IPAddressAllow=192.168.2.84/32"));
    assert!(n.contains("IPAddressDeny=0.0.0.0/0"));
    // Renderer-site canonical-lex-order sort: operator fixture
    // [AF_UNIX, AF_INET] emits `AF_INET AF_UNIX`. Exact-line
    // match resists false-positive on substring extension
    // (e.g. a future regression emitting trailing tokens).
    assert!(
        n.lines()
            .any(|l| l == "RestrictAddressFamilies=AF_INET AF_UNIX"),
        "network drop-in missing canonical RestrictAddressFamilies, got:\n{n}"
    );
    // Identity drop-in must record the netns subnet.
    let id = r.drop_ins.get("00-ghars.conf").unwrap();
    assert!(id.contains("X-Ghars-Netns-Subnet=10.200.0.0/30"));
}

/// Defense-in-depth pin for the renderer-site
/// canonical-lex-order sort in `render_network`. The production
/// path canonicalizes `NetworkSpec.restrict_address_families`
/// upstream at `canonicalize_network_spec` in
/// `lower_to_effective`; the renderer-site sort is defense-in-
/// depth for direct-construct callers (test fixtures). Sister
/// of `render_identity_emits_labels_sorted` and the post-
/// X-Ghars-Pool-Kinds sort pin in `render_cache_drop_in`.
///
/// Three `NetworkSpec` fixtures with the SAME family set in
/// opposing orders must produce byte-identical `40-network.conf`
/// bodies. A regression that replaced `sort_unstable()` with a
/// partial canonicalization (dedup-only, or a comparator that
/// is lex-stable for [INET, UNIX] but unstable across NETLINK)
/// would survive the four existing assertions (all of which
/// use only the [`AF_UNIX`, `AF_INET`] fixture) but flunk here.
#[test]
fn render_network_emits_canonical_address_families_regardless_of_input_order() {
    let mk_spec = |families: Vec<String>| {
        let mut s = minimal_spec();
        s.network = Some(EffectiveNetworkBinding {
            name: "buck2-isolated".into(),
            spec: NetworkSpec {
                mode: NetworkMode::Netns,
                allowed_egress: vec![],
                ip_allow: vec![],
                ip_deny: vec![],
                restrict_address_families: families,
                dns: DnsMode::default(),
                ipv6: Ipv6Mode::default(),
            },
            subnet: Some("10.200.0.0/30".parse::<IpNet>().unwrap()),
        });
        s
    };

    // Three permutations of {AF_INET, AF_NETLINK, AF_UNIX}.
    // Lex-ascending canonical: AF_INET AF_NETLINK AF_UNIX
    // (I=0x49 < N=0x4E < U=0x55).
    let body_a = render_runner_unit(&mk_spec(vec![
        "AF_UNIX".into(),
        "AF_INET".into(),
        "AF_NETLINK".into(),
    ]))
    .unwrap()
    .drop_ins
    .get("40-network.conf")
    .unwrap()
    .clone();
    let body_b = render_runner_unit(&mk_spec(vec![
        "AF_NETLINK".into(),
        "AF_INET".into(),
        "AF_UNIX".into(),
    ]))
    .unwrap()
    .drop_ins
    .get("40-network.conf")
    .unwrap()
    .clone();
    let body_c = render_runner_unit(&mk_spec(vec![
        "AF_INET".into(),
        "AF_NETLINK".into(),
        "AF_UNIX".into(),
    ]))
    .unwrap()
    .drop_ins
    .get("40-network.conf")
    .unwrap()
    .clone();

    // Positive: all three emit the exact canonical line.
    for (label, body) in [("a", &body_a), ("b", &body_b), ("c", &body_c)] {
        assert!(
            body.lines()
                .any(|l| l == "RestrictAddressFamilies=AF_INET AF_NETLINK AF_UNIX"),
            "{label} must emit canonical RestrictAddressFamilies (renderer-site sort regressed); got:\n{body}"
        );
    }

    // Strong invariance: same set in opposing orders renders
    // byte-identical bodies. A partial-canonicalization
    // regression survives the positive assertions but flunks
    // here.
    assert_eq!(
        body_a, body_b,
        "permutation invariance regressed (a vs b); left:\n{body_a}\nright:\n{body_b}"
    );
    assert_eq!(
        body_a, body_c,
        "permutation invariance regressed (a vs c); left:\n{body_a}\nright:\n{body_c}"
    );
}

/// Defense-in-depth gate: an Open-mode binding with no
/// cgroup-BPF policy fields reaching `render_network` is a
/// bug-shape input (the production lowering path collapses such
/// bindings to `spec.network = None` before the renderer runs).
/// The renderer returns `Ok(None)` rather than emitting an
/// empty `[Service]` section, so test fixtures that bypass
/// `lower_to_effective` (this one) still produce no drop-in.
#[test]
fn render_skips_network_for_open_mode_with_empty_cgroup_bpf() {
    let mut spec = minimal_spec();
    let net_spec = NetworkSpec {
        mode: NetworkMode::Open,
        allowed_egress: vec![],
        ip_allow: vec![],
        ip_deny: vec![],
        restrict_address_families: vec![],
        dns: DnsMode::default(),
        ipv6: Ipv6Mode::default(),
    };
    spec.network = Some(EffectiveNetworkBinding {
        name: "open".into(),
        spec: net_spec,
        subnet: None,
    });
    let r = render_runner_unit(&spec).unwrap();
    assert!(!r.drop_ins.contains_key("40-network.conf"));
}

/// Open-mode binding carrying ALL THREE of `ip_deny` / `ip_allow`
/// / `restrict_address_families` MUST emit a `40-network.conf`
/// with the cgroup-BPF directives but WITHOUT the
/// namespace-bound scaffolding
/// (`Requires=`/`BindsTo=`/`After=ghars-net@…`,
/// `NetworkNamespacePath=`). Open mode has no per-runner netns,
/// so the side-unit dependencies and the bind-mount path do not
/// apply; emitting them would force the unit to fail-closed
/// against a non-existent ghars-net@ side-unit.
#[test]
fn render_emits_cgroup_bpf_only_for_open_mode_with_all_fields() {
    let mut spec = minimal_spec();
    let net_spec = NetworkSpec {
        mode: NetworkMode::Open,
        allowed_egress: vec![],
        ip_allow: vec!["10.0.0.0/8".parse::<IpNet>().unwrap()],
        ip_deny: vec!["0.0.0.0/0".parse::<IpNet>().unwrap()],
        restrict_address_families: vec!["AF_UNIX".into(), "AF_INET".into()],
        dns: DnsMode::default(),
        ipv6: Ipv6Mode::default(),
    };
    spec.network = Some(EffectiveNetworkBinding {
        name: "hostnet".into(),
        spec: net_spec,
        subnet: None,
    });
    let r = render_runner_unit(&spec).unwrap();
    let n = r
        .drop_ins
        .get("40-network.conf")
        .expect("open mode with cgroup-BPF directives must emit 40-network.conf");
    // Cgroup-BPF directives present.
    assert!(n.contains("IPAddressAllow=10.0.0.0/8"));
    assert!(n.contains("IPAddressDeny=0.0.0.0/0"));
    // Renderer-site canonical-lex-order sort: operator
    // [AF_UNIX, AF_INET] renders as `AF_INET AF_UNIX`.
    // Exact-line match (resists substring-extension regressions).
    assert!(
        n.lines()
            .any(|l| l == "RestrictAddressFamilies=AF_INET AF_UNIX"),
        "open-mode network drop-in missing canonical RestrictAddressFamilies, got:\n{n}"
    );
    // Namespace-scoped scaffolding absent.
    assert!(
        !n.contains("Requires=ghars-net@"),
        "open mode must not Require ghars-net@: {n}"
    );
    assert!(
        !n.contains("BindsTo=ghars-net@"),
        "open mode must not BindsTo ghars-net@: {n}"
    );
    assert!(
        !n.contains("After=ghars-net@"),
        "open mode must not order After= ghars-net@: {n}"
    );
    assert!(
        !n.contains("NetworkNamespacePath="),
        "open mode must not bind a netns path: {n}"
    );
    // No [Unit] section header at all (the netns scaffolding is
    // the only [Unit] contributor in this drop-in).
    assert!(
        !n.contains("[Unit]"),
        "open mode 40-network.conf must not carry a [Unit] section: {n}"
    );
}

/// Open-mode runs with ONLY `ip_deny` set MUST still emit the
/// drop-in. Mirrors the `ip_allow_only` and
/// `restrict_address_families_only` shape tests: each cgroup-BPF
/// field on its own must trigger emission. Together with the
/// other two single-field tests, this pins each field as an
/// independent emission trigger so a future regression that
/// gates emission on (e.g.) "`ip_allow` OR
/// `restrict_address_families`" (omitting `ip_deny`) surfaces
/// here.
#[test]
fn render_emits_cgroup_bpf_for_open_mode_with_ip_deny_only() {
    let mut spec = minimal_spec();
    spec.network = Some(EffectiveNetworkBinding {
        name: "hostnet".into(),
        spec: NetworkSpec {
            mode: NetworkMode::Open,
            allowed_egress: vec![],
            ip_allow: vec![],
            ip_deny: vec!["0.0.0.0/0".parse::<IpNet>().unwrap()],
            restrict_address_families: vec![],
            dns: DnsMode::default(),
            ipv6: Ipv6Mode::default(),
        },
        subnet: None,
    });
    let r = render_runner_unit(&spec).unwrap();
    let n = r
        .drop_ins
        .get("40-network.conf")
        .expect("ip_deny alone in open mode must emit 40-network.conf");
    assert!(n.contains("IPAddressDeny=0.0.0.0/0"));
    assert!(!n.contains("IPAddressAllow="));
    assert!(!n.contains("RestrictAddressFamilies="));
    assert!(!n.contains("NetworkNamespacePath="));
}

/// Open-mode runs with only one of the cgroup-BPF fields set
/// MUST still emit the drop-in. Pin every single-field shape so a
/// future regression that gates emission on (e.g.) `ip_deny`
/// alone surfaces here.
#[test]
fn render_emits_cgroup_bpf_for_open_mode_with_ip_allow_only() {
    let mut spec = minimal_spec();
    spec.network = Some(EffectiveNetworkBinding {
        name: "hostnet".into(),
        spec: NetworkSpec {
            mode: NetworkMode::Open,
            allowed_egress: vec![],
            ip_allow: vec!["192.0.2.0/24".parse::<IpNet>().unwrap()],
            ip_deny: vec![],
            restrict_address_families: vec![],
            dns: DnsMode::default(),
            ipv6: Ipv6Mode::default(),
        },
        subnet: None,
    });
    let r = render_runner_unit(&spec).unwrap();
    let n = r
        .drop_ins
        .get("40-network.conf")
        .expect("ip_allow alone in open mode must emit 40-network.conf");
    assert!(n.contains("IPAddressAllow=192.0.2.0/24"));
    assert!(!n.contains("IPAddressDeny="));
    assert!(!n.contains("RestrictAddressFamilies="));
    assert!(!n.contains("NetworkNamespacePath="));
}

#[test]
fn render_emits_cgroup_bpf_for_open_mode_with_restrict_address_families_only() {
    let mut spec = minimal_spec();
    spec.network = Some(EffectiveNetworkBinding {
        name: "hostnet".into(),
        spec: NetworkSpec {
            mode: NetworkMode::Open,
            allowed_egress: vec![],
            ip_allow: vec![],
            ip_deny: vec![],
            restrict_address_families: vec!["AF_INET".into()],
            dns: DnsMode::default(),
            ipv6: Ipv6Mode::default(),
        },
        subnet: None,
    });
    let r = render_runner_unit(&spec).unwrap();
    let n = r
        .drop_ins
        .get("40-network.conf")
        .expect("restrict_address_families alone in open mode must emit 40-network.conf");
    assert!(n.contains("RestrictAddressFamilies=AF_INET"));
    assert!(!n.contains("IPAddressAllow="));
    assert!(!n.contains("IPAddressDeny="));
    assert!(!n.contains("NetworkNamespacePath="));
}

/// `X-Ghars-Netns-Subnet=` is Netns-scoped per the
/// `filesystem-layout` annotation table. An Open-mode binding
/// has `subnet = None` (no /30 allocated), so the renderer's
/// `if let Some(subnet) = net.subnet` gate suppresses the
/// annotation; otherwise an operator reading `00-ghars.conf`
/// would conclude a netns had been allocated.
#[test]
fn render_identity_omits_netns_subnet_annotation_for_open_mode() {
    let mut spec = minimal_spec();
    spec.network = Some(EffectiveNetworkBinding {
        name: "hostnet".into(),
        spec: NetworkSpec {
            mode: NetworkMode::Open,
            allowed_egress: vec![],
            ip_allow: vec!["10.0.0.0/8".parse::<IpNet>().unwrap()],
            ip_deny: vec![],
            restrict_address_families: vec![],
            dns: DnsMode::default(),
            ipv6: Ipv6Mode::default(),
        },
        subnet: None,
    });
    let r = render_runner_unit(&spec).unwrap();
    let id = r.drop_ins.get("00-ghars.conf").unwrap();
    // Network mode is still annotated as "open" so the plan
    // classifier's Open↔Netns transition detector still works.
    assert!(id.contains("X-Ghars-Network-Mode=open"));
    // No subnet line — Open-mode bindings have subnet = None so
    // the renderer's presence-gate suppresses the annotation.
    assert!(
        !id.contains("X-Ghars-Netns-Subnet="),
        "open-mode binding must not emit X-Ghars-Netns-Subnet, got:\n{id}"
    );
}

#[test]
fn render_emits_proxy() {
    let mut spec = minimal_spec();
    spec.proxy = Some(ProxySpec {
        http: Some("http://192.168.2.84:3128".into()),
        https: Some("http://192.168.2.84:3128".into()),
        no_proxy: vec!["192.168.2.84".into()],
        ca_certs: vec![CaCertBinding {
            env: "REQUESTS_CA_BUNDLE".into(),
            path: Utf8PathBuf::from("/etc/pki/tls/certs/ca-bundle.crt"),
        }],
    });
    let r = render_runner_unit(&spec).unwrap();
    let p = r.drop_ins.get("60-proxy.conf").unwrap();
    assert!(p.contains("Environment=HTTP_PROXY=http://192.168.2.84:3128"));
    assert!(p.contains("Environment=http_proxy=http://192.168.2.84:3128"));
    assert!(p.contains("Environment=NO_PROXY=192.168.2.84"));
    assert!(p.contains("Environment=REQUESTS_CA_BUNDLE=/etc/pki/tls/certs/ca-bundle.crt"));
    // SEC-08: no `-` prefix on proxy CA cert paths — missing CA
    // must fail the unit start, not silently fall back to system roots.
    assert!(p.contains("BindReadOnlyPaths=/etc/pki/tls/certs/ca-bundle.crt"));
    assert!(!p.contains("BindReadOnlyPaths=-/etc/pki/tls/certs/ca-bundle.crt"));
}

#[test]
fn render_proxy_rejects_root_ca_cert_path() {
    let mut spec = minimal_spec();
    spec.proxy = Some(ProxySpec {
        http: None,
        https: None,
        no_proxy: vec![],
        ca_certs: vec![CaCertBinding {
            env: "CERT".into(),
            path: Utf8PathBuf::from("/"),
        }],
    });
    let err = render_runner_unit(&spec).unwrap_err();
    assert!(matches!(err, GharsError::Validation(_, _)));
    let msg = format!("{err}");
    assert!(msg.contains("proxy.ca_certs[].path"), "msg: {msg}");
    assert!(msg.contains("SEC-12"), "msg: {msg}");
    assert!(msg.contains("filesystem root"), "msg: {msg}");
}

#[test]
fn render_proxy_rejects_parent_dir_climb_root_ca_cert_path() {
    let mut spec = minimal_spec();
    spec.proxy = Some(ProxySpec {
        http: None,
        https: None,
        no_proxy: vec![],
        ca_certs: vec![CaCertBinding {
            env: "CERT".into(),
            path: Utf8PathBuf::from("/foo/.."),
        }],
    });
    let err = render_runner_unit(&spec).unwrap_err();
    assert!(matches!(err, GharsError::Validation(_, _)));
    let msg = format!("{err}");
    assert!(msg.contains("proxy.ca_certs[].path"), "msg: {msg}");
    assert!(msg.contains("SEC-12"), "msg: {msg}");
    assert!(msg.contains("filesystem root"), "msg: {msg}");
}

#[test]
fn render_proxy_rejects_empty_ca_cert_path() {
    let mut spec = minimal_spec();
    spec.proxy = Some(ProxySpec {
        http: None,
        https: None,
        no_proxy: vec![],
        ca_certs: vec![CaCertBinding {
            env: "CERT".into(),
            path: Utf8PathBuf::from(""),
        }],
    });
    let err = render_runner_unit(&spec).unwrap_err();
    assert!(matches!(err, GharsError::Validation(_, _)));
    let msg = format!("{err}");
    assert!(msg.contains("proxy.ca_certs[].path"), "msg: {msg}");
    assert!(msg.contains("empty"), "msg: {msg}");
    assert!(
        !msg.contains("filesystem root"),
        "empty entry must not be misclassified as filesystem root: {msg}"
    );
}

#[test]
fn render_proxy_rejects_colon_in_ca_cert_path() {
    let mut spec = minimal_spec();
    spec.proxy = Some(ProxySpec {
        http: None,
        https: None,
        no_proxy: vec![],
        ca_certs: vec![CaCertBinding {
            env: "CERT".into(),
            path: Utf8PathBuf::from("/etc:/"),
        }],
    });
    let err = render_runner_unit(&spec).unwrap_err();
    assert!(matches!(err, GharsError::Validation(_, _)));
    let msg = format!("{err}");
    assert!(msg.contains("proxy.ca_certs[].path"), "msg: {msg}");
    assert!(msg.contains(':'), "msg: {msg}");
    assert!(msg.contains("SOURCE:DESTINATION"), "msg: {msg}");
}

#[test]
fn render_proxy_accepts_non_root_ca_cert_path() {
    let mut spec = minimal_spec();
    spec.proxy = Some(ProxySpec {
        http: None,
        https: None,
        no_proxy: vec![],
        ca_certs: vec![CaCertBinding {
            env: "REQUESTS_CA_BUNDLE".into(),
            path: Utf8PathBuf::from("/foo/../bar.pem"),
        }],
    });
    let r = render_runner_unit(&spec).expect("non-root path must render");
    let p = r.drop_ins.get("60-proxy.conf").unwrap();
    assert!(
        p.contains("BindReadOnlyPaths=/foo/../bar.pem"),
        "expected BindReadOnlyPaths=/foo/../bar.pem; got:\n{p}"
    );
}

#[test]
fn render_emits_hooks() {
    let mut spec = minimal_spec();
    spec.hooks = Some(HooksSpec {
        pre_job: Some(Utf8PathBuf::from("/opt/gha/pre-job.sh")),
        post_job: Some(Utf8PathBuf::from("/opt/gha/post-job.sh")),
    });
    let r = render_runner_unit(&spec).unwrap();
    let h = r.drop_ins.get("70-hooks.conf").unwrap();
    assert!(h.contains("Environment=ACTIONS_RUNNER_HOOK_JOB_STARTED=/opt/gha/pre-job.sh"));
    assert!(h.contains("Environment=ACTIONS_RUNNER_HOOK_JOB_COMPLETED=/opt/gha/post-job.sh"));
    // Parent dir deduped.
    assert!(h.contains("BindReadOnlyPaths=/opt/gha"));
}

// Drop-in interaction tests. systemd treats list-typed
// directives (RestrictAddressFamilies, BindReadOnlyPaths,
// SystemCallFilter, ...) as APPEND across drop-ins — every line
// contributes to the union, the LAST one does not "win". The
// tests below pin that contract for the directive pairs that the
// ghars renderer can emit from MULTIPLE drop-ins simultaneously,
// so a future edit that accidentally rewrites one of these to
// "scalar override" semantics fails immediately.
//
// What "compose" means here in test terms: render_runner_unit
// produces text bytes; both contributing drop-ins MUST be present
// in the output map AND each MUST contain the directive line we
// expect. systemd's load-time merge then unions them. We do NOT
// re-implement systemd's parser; we verify the inputs to the
// parser (the bytes ghars writes) so a regression to "only emit
// one drop-in" is caught.

#[test]
fn restrict_address_families_composes_across_hardening_and_network() {
    // 20-hardening.conf and 40-network.conf both emit
    // `RestrictAddressFamilies=`. The union {AF_UNIX, AF_INET,
    // AF_NETLINK} is the operator's intent — hardening scopes the
    // global policy, network adds netns-specific families.
    let mut spec = minimal_spec();
    spec.hardening.restrict_address_families = vec!["AF_UNIX".into(), "AF_NETLINK".into()];
    spec.network = Some(EffectiveNetworkBinding {
        name: "buck2-isolated".into(),
        spec: NetworkSpec {
            mode: NetworkMode::Netns,
            allowed_egress: vec![EgressRule {
                addr: "192.168.2.84".into(),
                port: PortSpec::Single(3128),
                proto: Proto::Tcp,
                comment: None,
            }],
            ip_allow: vec![],
            ip_deny: vec![],
            restrict_address_families: vec!["AF_UNIX".into(), "AF_INET".into()],
            dns: DnsMode::default(),
            ipv6: Ipv6Mode::default(),
        },
        subnet: Some("10.200.0.0/30".parse::<IpNet>().unwrap()),
    });
    let r = render_runner_unit(&spec).unwrap();
    let h = r
        .drop_ins
        .get("20-hardening.conf")
        .expect("hardening drop-in present");
    let n = r
        .drop_ins
        .get("40-network.conf")
        .expect("network drop-in present");
    // Each drop-in carries its OWN RestrictAddressFamilies= line —
    // systemd will union them at load time. Pin both lines.
    //
    // Both Hardening and NetworkSpec emissions now canonical-
    // lex-sort at the renderer site (`render_hardening` for the
    // hardening drop-in, `render_network` for the network drop-
    // in), so operator-supplied `[AF_UNIX, AF_NETLINK]` and
    // `[AF_UNIX, AF_INET]` emit alpha-sorted on disk regardless
    // of input order. The defensive sort mirrors the upstream
    // `plan::merge_hardening` + `canonicalize_network_spec`
    // sorts; direct-construct callers (this test) bypass those,
    // so the renderer-side sort is the load-bearing
    // canonicalization gate.
    assert!(
        h.lines()
            .any(|l| l == "RestrictAddressFamilies=AF_NETLINK AF_UNIX"),
        "hardening drop-in missing RestrictAddressFamilies, got:\n{h}"
    );
    assert!(
        n.lines()
            .any(|l| l == "RestrictAddressFamilies=AF_INET AF_UNIX"),
        "network drop-in missing RestrictAddressFamilies, got:\n{n}"
    );
    // Neither drop-in emits a bare `RestrictAddressFamilies=` reset
    // (that would erase the union per systemd.exec(5)
    // RestrictAddressFamilies — bare `=` resets the allowlist).
    for body in [h, n] {
        assert!(
            !body.lines().any(|l| l.trim() == "RestrictAddressFamilies="),
            "drop-in must not reset the allowlist, got:\n{body}"
        );
    }
}

/// Same composition contract under Open mode. The Open
/// `40-network.conf` drop-in carries cgroup-BPF directives
/// only (no namespace bind), but `RestrictAddressFamilies=` is
/// one of those directives — it lives at the cgroup layer, not
/// the namespace layer, so it composes across drop-ins
/// identically in either mode. Pinning Open-mode composition
/// here mirrors the existing Netns test so a future regression
/// that gates `RestrictAddressFamilies=` emission on Netns mode
/// (instead of on the field being non-empty) surfaces.
#[test]
fn restrict_address_families_composes_across_hardening_and_open_network() {
    let mut spec = minimal_spec();
    spec.hardening.restrict_address_families = vec!["AF_UNIX".into(), "AF_NETLINK".into()];
    spec.network = Some(EffectiveNetworkBinding {
        name: "hostnet".into(),
        spec: NetworkSpec {
            mode: NetworkMode::Open,
            allowed_egress: vec![],
            ip_allow: vec![],
            ip_deny: vec![],
            restrict_address_families: vec!["AF_UNIX".into(), "AF_INET".into()],
            dns: DnsMode::default(),
            ipv6: Ipv6Mode::default(),
        },
        subnet: None,
    });
    let r = render_runner_unit(&spec).unwrap();
    let h = r
        .drop_ins
        .get("20-hardening.conf")
        .expect("hardening drop-in present");
    let n = r
        .drop_ins
        .get("40-network.conf")
        .expect("open-mode network drop-in present (cgroup-BPF directives non-empty)");
    // Each drop-in carries its OWN RestrictAddressFamilies= line.
    // Both Hardening (`render_hardening`) and NetworkSpec
    // (`render_network`) emissions canonical-lex-sort at the
    // renderer site, so operator-supplied Vec order is irrelevant
    // for on-disk bytes (mirror of the netns sister test above).
    assert!(
        h.lines()
            .any(|l| l == "RestrictAddressFamilies=AF_NETLINK AF_UNIX"),
        "hardening drop-in missing RestrictAddressFamilies, got:\n{h}"
    );
    assert!(
        n.lines()
            .any(|l| l == "RestrictAddressFamilies=AF_INET AF_UNIX"),
        "open network drop-in missing RestrictAddressFamilies, got:\n{n}"
    );
    // Neither drop-in emits a bare reset.
    for body in [h, n] {
        assert!(
            !body.lines().any(|l| l.trim() == "RestrictAddressFamilies="),
            "drop-in must not reset the allowlist, got:\n{body}"
        );
    }
    // Open-mode-specific anti-properties: the network drop-in
    // must NOT carry the namespace scaffolding even though it
    // emits `RestrictAddressFamilies=`.
    assert!(
        !n.contains("[Unit]"),
        "open-mode 40-network.conf must not carry [Unit] section, got:\n{n}"
    );
    assert!(
        !n.contains("NetworkNamespacePath="),
        "open-mode 40-network.conf must not bind a netns path, got:\n{n}"
    );
}

#[test]
fn restrict_address_families_drop_ins_load_in_numeric_order() {
    // BTreeMap iteration is alphabetic by key, which for the
    // numeric-prefix drop-in basenames (`20-hardening.conf` <
    // `40-network.conf`) is the same as systemd's load order
    // (lower numbers load first per Part 9). Pin that the
    // map's keys come out in the right order so plan output and
    // any future "concatenate drop-ins for systemd-analyze
    // verify" code observes the same order systemd will use.
    let mut spec = minimal_spec();
    spec.hardening.restrict_address_families = vec!["AF_UNIX".into()];
    spec.network = Some(EffectiveNetworkBinding {
        name: "ci-net".into(),
        spec: NetworkSpec {
            mode: NetworkMode::Netns,
            allowed_egress: vec![EgressRule {
                addr: "10.0.0.1".into(),
                port: PortSpec::Single(443),
                proto: Proto::Tcp,
                comment: None,
            }],
            ip_allow: vec![],
            ip_deny: vec![],
            restrict_address_families: vec!["AF_INET".into()],
            dns: DnsMode::default(),
            ipv6: Ipv6Mode::default(),
        },
        subnet: Some("10.200.0.0/30".parse::<IpNet>().unwrap()),
    });
    let r = render_runner_unit(&spec).unwrap();
    let keys: Vec<&str> = r.drop_ins.keys().map(String::as_str).collect();
    let h_idx = keys.iter().position(|k| *k == "20-hardening.conf").unwrap();
    let n_idx = keys.iter().position(|k| *k == "40-network.conf").unwrap();
    assert!(
        h_idx < n_idx,
        "hardening (20) must precede network (40); got keys {keys:?}"
    );
}

#[test]
fn bind_readonly_paths_composes_across_hardening_proxy_hooks() {
    // BindReadOnlyPaths is emitted from up to THREE drop-ins:
    // - 20-hardening (extra_bind_paths + etc_bind_style=Broad)
    // - 60-proxy (CA cert paths)
    // - 70-hooks (parent dirs of pre/post-job scripts)
    // systemd unions all of them. Pin that each drop-in carries
    // its own bytes and that none of them emit a bare reset.
    let mut spec = minimal_spec();
    spec.hardening.extra_bind_paths = vec![Utf8PathBuf::from("/opt/internal-tools")];
    spec.proxy = Some(ProxySpec {
        http: Some("http://10.0.0.1:3128".into()),
        https: Some("http://10.0.0.1:3128".into()),
        no_proxy: vec![],
        ca_certs: vec![CaCertBinding {
            env: "REQUESTS_CA_BUNDLE".into(),
            path: Utf8PathBuf::from("/etc/pki/tls/certs/ca-bundle.crt"),
        }],
    });
    spec.hooks = Some(HooksSpec {
        pre_job: Some(Utf8PathBuf::from("/opt/gha-hooks/pre-job.sh")),
        post_job: Some(Utf8PathBuf::from("/opt/gha-hooks/post-job.sh")),
    });
    let r = render_runner_unit(&spec).unwrap();
    let h = r
        .drop_ins
        .get("20-hardening.conf")
        .expect("hardening present");
    let p = r.drop_ins.get("60-proxy.conf").expect("proxy present");
    let k = r.drop_ins.get("70-hooks.conf").expect("hooks present");

    assert!(
        h.lines()
            .any(|l| l == "BindReadOnlyPaths=/opt/internal-tools"),
        "hardening drop-in missing extra_bind_paths line, got:\n{h}"
    );
    assert!(
        p.lines()
            .any(|l| l == "BindReadOnlyPaths=/etc/pki/tls/certs/ca-bundle.crt"),
        "proxy drop-in missing CA cert bind line, got:\n{p}"
    );
    assert!(
        k.lines().any(|l| l == "BindReadOnlyPaths=/opt/gha-hooks"),
        "hooks drop-in missing parent-dir bind line, got:\n{k}"
    );

    // None of these drop-ins emit a bare BindReadOnlyPaths=
    // reset — that would silently erase the template's curated
    // /etc list and the union of every other contributor.
    for (name, body) in [("hardening", h), ("proxy", p), ("hooks", k)] {
        assert!(
            !body.lines().any(|l| l.trim() == "BindReadOnlyPaths="),
            "{name} drop-in emitted reset BindReadOnlyPaths=, got:\n{body}"
        );
    }
}

/// Byte-equality regression pin for `bind_readonly_paths`.
///
/// `bind_readonly_paths` is intentionally NOT sorted at
/// either the upstream `merge_hardening` boundary or the
/// renderer (see `merge.rs` for the canonical rationale).
/// systemd's PID 1 user-space sorts mount entries parent-
/// first via `mount_path_compare`
/// (`systemd/src/core/namespace.c:1003`) BEFORE issuing any
/// `mount(2)` syscall, so operator-declared order is
/// discarded in user-space and never reaches the kernel's
/// mount-overlay state. The sort abstention is
/// for byte-equality between the operator's TOML and the
/// rendered `BindReadOnlyPaths=` drop-in line: a sort-
/// induced reorder would (a) flip `spec_hash` (different
/// JSON → different SHA256 → spurious in-place
/// `UpdateRunner` cascade per `RENDERER_SCHEMA` semantics) and
/// (b) make the operator's TOML order non-canonical (re-
/// deploy with the original ordering would not produce a
/// `NoOp`).
///
/// Fixture uses child-before-parent path ordering
/// (`/etc/ssl/certs/custom.pem` before `/etc/ssl`)
/// specifically because alphabetical sort would reverse it
/// (parent < child lex), producing a concrete byte-shift
/// the assertion catches.
#[test]
fn bind_readonly_paths_render_preserves_operator_order_for_colliding_paths() {
    let mut spec = minimal_spec();
    spec.hardening.bind_readonly_paths = Some(vec![
        Utf8PathBuf::from("/etc/ssl/certs/custom.pem"),
        Utf8PathBuf::from("/etc/ssl"),
    ]);
    let r = render_runner_unit(&spec).unwrap();
    let h = r
        .drop_ins
        .get("20-hardening.conf")
        .expect("hardening drop-in present");
    // Operator order preserved verbatim: child first, parent
    // second. Alphabetical sort would emit "/etc/ssl
    // /etc/ssl/certs/custom.pem" instead (parent first).
    assert!(
        h.lines()
            .any(|l| l == "BindReadOnlyPaths=/etc/ssl/certs/custom.pem /etc/ssl"),
        "bind_readonly_paths render did not preserve operator order \
         — a sort-induced reorder would flip `spec_hash` and trigger \
         spurious in-place UpdateRunner cascades, and would make the \
         operator's TOML order non-canonical. The renderer must emit \
         the operator's path order verbatim. Got:\n{h}"
    );
}

/// Sister to `bind_readonly_paths_render_preserves_operator_order_for_colliding_paths`.
/// `extra_bind_paths` shares the same byte-equality
/// invariant — both fields emit to `BindReadOnlyPaths=` and
/// both are intentionally NOT sorted at any layer. See the
/// sister test above + `merge.rs` for the full byte-equality
/// rationale (`spec_hash` stability + canonical TOML
/// ordering).
#[test]
fn extra_bind_paths_render_preserves_operator_order_for_colliding_paths() {
    let mut spec = minimal_spec();
    spec.hardening.extra_bind_paths = vec![
        Utf8PathBuf::from("/opt/runner/cache"),
        Utf8PathBuf::from("/opt/runner"),
    ];
    let r = render_runner_unit(&spec).unwrap();
    let h = r
        .drop_ins
        .get("20-hardening.conf")
        .expect("hardening drop-in present");
    // Operator order preserved verbatim: child cache dir
    // first, then parent. Alphabetical sort would emit
    // "/opt/runner /opt/runner/cache" instead (parent first).
    assert!(
        h.lines()
            .any(|l| l == "BindReadOnlyPaths=/opt/runner/cache /opt/runner"),
        "extra_bind_paths render did not preserve operator order \
         — a sort-induced reorder would flip `spec_hash` and trigger \
         spurious in-place UpdateRunner cascades, and would make the \
         operator's TOML order non-canonical. The renderer must emit \
         the operator's path order verbatim. Got:\n{h}"
    );
}

#[test]
fn system_call_filter_composes_across_template_and_hardening() {
    // SystemCallFilter is emitted by:
    // - the runner template (baseline `@system-service ...` +
    //   the inverse `~@mount @clock ...` denylist)
    // - 20-hardening when `extra_syscalls` is non-empty
    // The union is what systemd enforces. Pin that the hardening
    // line is present alongside the template's two lines.
    let mut spec = minimal_spec();
    spec.hardening.extra_syscalls = vec!["clone3".into(), "rseq".into()];
    let r = render_runner_unit(&spec).unwrap();
    let template = &r.template;
    let h = r
        .drop_ins
        .get("20-hardening.conf")
        .expect("hardening present");

    // Template baseline (allowlist) + denylist must both be
    // present — same line count regardless of drop-in additions.
    assert!(
        template
            .lines()
            .any(|l| l.starts_with("SystemCallFilter=@system-service")),
        "template missing baseline allowlist"
    );
    assert!(
        template
            .lines()
            .any(|l| l.starts_with("SystemCallFilter=~@mount")),
        "template missing denylist"
    );
    // Hardening drop-in adds union members — operator can grow the
    // allowlist without rewriting the template.
    assert!(
        h.lines().any(|l| l == "SystemCallFilter=clone3 rseq"),
        "hardening drop-in missing extra syscalls, got:\n{h}"
    );

    // Hardening must not emit a bare SystemCallFilter=
    // reset (would erase BOTH template lines).
    assert!(
        !h.lines().any(|l| l.trim() == "SystemCallFilter="),
        "hardening drop-in emitted reset SystemCallFilter=, got:\n{h}"
    );
}

#[test]
fn render_emits_numa_drop_in() {
    let mut spec = minimal_spec();
    spec.allowed_cpus = Some("0-31".into());
    spec.allowed_memory_nodes = Some("0".into());
    let r = render_runner_unit(&spec).unwrap();
    let n = r.drop_ins.get("50-numa.conf").unwrap();
    assert!(n.contains("AllowedCPUs=0-31"));
    assert!(n.contains("AllowedMemoryNodes=0"));
}

#[test]
fn render_cache_drop_in_for_sccache_only() {
    let binding = EffectiveCacheBinding {
        name: "build".into(),
        kinds: vec![CacheKind::Sccache],
        size: "200G".into(),
        mode: CacheMode::Shared,
        trust_zone: "default".into(),
        // Pin sccache to /usr/local/bin to verify the renderer
        // emits the binding's path verbatim (not a hardcoded
        // /usr/bin/ prefix). The two-path probe in
        // resolve_cache_pool_paths covers cargo-install layouts;
        // this assertion guards that the renderer respects the
        // resolved value rather than re-hardcoding.
        sccache_path: Some("/usr/local/bin/sccache".into()),
        sleep_path: None,
        renderer_schema: crate::systemd::RENDERER_SCHEMA,
    };
    let body = render_cache_drop_in(&binding, "/etc/ghars/ghars.toml", "sha256:abcd").unwrap();
    assert!(body.contains("X-Ghars-Pool-Kinds=sccache"));
    assert!(body.contains("\nExecStart=/usr/local/bin/sccache --start-server\n"));
    // Sanity: the prior hardcoded /usr/bin/sccache path is no
    // longer emitted when the binding pins a different location.
    assert!(!body.contains("/usr/bin/sccache"));
    assert!(body.contains("SCCACHE_NO_DAEMON=1"));
    assert!(body.contains("SCCACHE_IDLE_TIMEOUT=0"));
    // ccache-specific env entries are absent. Anchor at line start
    // so we don't match the `CCACHE_DIR=` substring inside
    // `SCCACHE_DIR=` / `Environment=SCCACHE_DIR=`.
    assert!(
        !body
            .lines()
            .any(|l| l.starts_with("Environment=CCACHE_DIR=")
                || l.starts_with("Environment=CCACHE_MAXSIZE="))
    );
}

#[test]
fn render_cache_drop_in_for_ccache_only_uses_sleep_infinity() {
    let binding = EffectiveCacheBinding {
        name: "build".into(),
        kinds: vec![CacheKind::Ccache],
        size: "200G".into(),
        mode: CacheMode::Shared,
        trust_zone: "default".into(),
        // ccache-only pool: sccache_path stays None, sleep_path
        // pinned to /bin/sleep (the legacy non-merged-usr fallback)
        // to verify the renderer emits the resolved path verbatim
        // rather than the previous hardcoded /usr/bin/sleep.
        sccache_path: None,
        sleep_path: Some("/bin/sleep".into()),
        renderer_schema: crate::systemd::RENDERER_SCHEMA,
    };
    let body = render_cache_drop_in(&binding, "/etc/ghars/ghars.toml", "sha256:abcd").unwrap();
    assert!(body.contains("X-Ghars-Pool-Kinds=ccache"));
    assert!(body.contains("\nExecStart=/bin/sleep infinity\n"));
    // Sanity: the prior hardcoded /usr/bin/sleep is no longer
    // emitted when the binding pins a different location.
    assert!(!body.contains("/usr/bin/sleep"));
    // Per the per-binding CCACHE_DIR audit removal: CCACHE_DIR
    // is NO LONGER emitted on the cache pool unit drop-in for
    // ccache-only pools. The cache pool unit's ExecStart is
    // `sleep infinity` (the stub) — it never reads CCACHE_DIR.
    // The prior emission was dead code that misled
    // `systemctl cat` readers.
    assert!(
        !body
            .lines()
            .any(|l| l.starts_with("Environment=CCACHE_DIR=")),
        "no `Environment=CCACHE_DIR=` expected on ccache-only cache pool unit (dead-code removal): {body}"
    );
    assert!(!body.contains("--start-server"));
}

#[test]
fn render_cache_drop_in_for_both_kinds_emits_unified_unit() {
    let binding = EffectiveCacheBinding {
        name: "build".into(),
        kinds: vec![CacheKind::Sccache, CacheKind::Ccache],
        size: "200G".into(),
        mode: CacheMode::Shared,
        trust_zone: "default".into(),
        // Pool serves both kinds — the sccache server takes
        // ExecStart and sleep_path is None (the renderer never
        // reads sleep for sccache-serving pools).
        sccache_path: Some("/usr/bin/sccache".into()),
        sleep_path: None,
        renderer_schema: crate::systemd::RENDERER_SCHEMA,
    };
    let body = render_cache_drop_in(&binding, "/etc/ghars/ghars.toml", "sha256:abcd").unwrap();
    // Both env sets emit; the sccache server is the ExecStart.
    assert!(body.contains("CCACHE_DIR"));
    assert!(body.contains("SCCACHE_DIR"));
    assert!(body.contains("\nExecStart=/usr/bin/sccache --start-server\n"));
}

#[test]
fn cache_template_sets_umask_0077_for_uds_mode() {
    // sccache UDS mode is kernel-enforced at vfs_mknod time (Linux
    // net/unix/af_unix.c:unix_bind_bsd:1349 —
    // `umode_t mode = S_IFSOCK | (SOCK_INODE(...)->i_mode & ~current_umask())`).
    // sccache's UnixListener::bind (sccache server.rs:511,
    // commands.rs:104) performs no chmod after bind, so the
    // kernel-applied mode is final. UMask=0077 in the template
    // makes the resulting socket mode 0600 (owner rw, group/others
    // denied) atomically — no TOCTOU window between bind() and a
    // chmod shim. Reach is owner-DAC: the cache server and the
    // runners in its trust_zone share the same DynamicUser-allocated
    // UID (User=ghars-tz-<TRUST_ZONE> in both unit drop-ins);
    // runners in other trust_zones get EACCES at connect(). This
    // test pins the template directive so a future cleanup pass
    // can't drop it without surfacing the regression.
    let body = cache_template_text();
    assert!(
        body.contains("\nUMask=0077\n"),
        "cache template must set UMask=0077 for sccache UDS mode 0600; got body:\n{body}"
    );
}

/// Defense-in-depth pin for the `X-Ghars-Pool-Kinds=` CSV
/// canonical sort in `render_cache_drop_in`. Operator-supplied
/// `[cache_pools.NAME].kinds` Vec is preserved verbatim into
/// `EffectiveCacheBinding.kinds`; the renderer must sort the
/// CSV emission so `systemctl cat ghars-cache@POOL.service`
/// shows byte-identical Pool-Kinds output regardless of
/// operator TOML order. Sister of the X-Ghars-Labels= /
/// X-Ghars-Caches= defensive sorts at `render_identity`.
///
/// Two direct-construct fixtures with the SAME kind set in
/// opposing orders ([Sccache, Ccache] vs [Ccache, Sccache])
/// must produce the same X-Ghars-Pool-Kinds=ccache,sccache
/// emission. A regression that dropped the renderer-site
/// `.sort_unstable()` would emit the operator-supplied order
/// — the `\n...\n`-bracketed positive assertions print the
/// full body on mismatch so the regression surfaces with the
/// concrete miss-rendered line.
#[test]
fn render_cache_drop_in_emits_canonical_pool_kinds_csv() {
    let mk_binding = |kinds: Vec<CacheKind>| EffectiveCacheBinding {
        name: "build".into(),
        kinds,
        size: "200G".into(),
        mode: CacheMode::Shared,
        trust_zone: "default".into(),
        sccache_path: Some("/usr/bin/sccache".into()),
        sleep_path: None,
        renderer_schema: crate::systemd::RENDERER_SCHEMA,
    };

    let body_sccache_first = render_cache_drop_in(
        &mk_binding(vec![CacheKind::Sccache, CacheKind::Ccache]),
        "/etc/ghars/ghars.toml",
        "sha256:abcd",
    )
    .unwrap();
    let body_ccache_first = render_cache_drop_in(
        &mk_binding(vec![CacheKind::Ccache, CacheKind::Sccache]),
        "/etc/ghars/ghars.toml",
        "sha256:abcd",
    )
    .unwrap();

    // Both must emit canonical (lex-ascending) CSV. The
    // `\n...\n` bracketing pins the exact line — render_cache_drop_in
    // emits X-Ghars-Pool-Kinds= exactly once per body, so a
    // failed positive assertion is sufficient evidence of a
    // sort regression (no separate negative assertion needed).
    assert!(
        body_sccache_first.contains("\nX-Ghars-Pool-Kinds=ccache,sccache\n"),
        "operator [Sccache, Ccache] order must emit canonical \
         ccache,sccache CSV (renderer-site sort regressed); got:\n{body_sccache_first}"
    );
    assert!(
        body_ccache_first.contains("\nX-Ghars-Pool-Kinds=ccache,sccache\n"),
        "operator [Ccache, Sccache] order must emit canonical \
         ccache,sccache CSV; got:\n{body_ccache_first}"
    );

    // Strong invariance: same kind set in opposing orders must
    // render byte-identical bodies. Both calls pass the same
    // literal "sha256:abcd" so the X-Ghars-Spec-Hash line stays
    // equal (production-path spec_hash desync from kinds Vec
    // order is tracked by the upstream-sort task at
    // `into_cache_pool_plan`); under that pin, the renderer-site
    // sort makes the rendered body byte-identical for any
    // permutation of the same kind set.
    assert_eq!(
        body_sccache_first, body_ccache_first,
        "permutation invariance: same kinds set in opposing orders \
         must render byte-identical bodies (renderer-site sort regressed); \
         left:\n{body_sccache_first}\nright:\n{body_ccache_first}"
    );
}

#[test]
fn render_cache_drop_in_relies_on_template_umask_no_exec_start_post_shim() {
    // sccache UDS mode enforcement lives in the cache template
    // (UMask=0077), not the per-pool drop-in. The drop-in must
    // NOT emit a chmod ExecStartPost — the chmod-after-bind shim
    // is rejected because of the TOCTOU window between bind()
    // returning and chmod() landing during which a non-owner
    // could connect. UMask= closes the window at vfs_mknod time.
    // This test pins both pool kinds (sccache and ccache-only)
    // to confirm neither emits ExecStartPost.
    for kinds in [
        vec![CacheKind::Sccache],
        vec![CacheKind::Ccache],
        vec![CacheKind::Sccache, CacheKind::Ccache],
    ] {
        let serves_sccache = kinds.contains(&CacheKind::Sccache);
        let binding = EffectiveCacheBinding {
            name: "build".into(),
            kinds,
            size: "200G".into(),
            mode: CacheMode::Shared,
            trust_zone: "default".into(),
            sccache_path: serves_sccache.then(|| "/usr/bin/sccache".into()),
            sleep_path: (!serves_sccache).then(|| "/usr/bin/sleep".into()),
            renderer_schema: crate::systemd::RENDERER_SCHEMA,
        };
        let body = render_cache_drop_in(&binding, "/etc/ghars/ghars.toml", "sha256:abcd").unwrap();
        assert!(
            !body.contains("ExecStartPost"),
            "cache drop-in must NOT emit ExecStartPost — \
             mode enforcement is solved at the template level via UMask=0077. \
             got body:\n{body}"
        );
    }
}
