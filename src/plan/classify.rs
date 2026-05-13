//! Stage 1 of `plan_from`'s intersection-branch reconciliation: parse
//! the on-disk `X-Ghars-*` annotation set out of a discovered runner's
//! `00-ghars.conf` drop-in, and classify which of the recreate-class
//! identity fields differ from the desired effective spec. In-place-
//! only fields (`auth_name`, `trust_zone`, `caches`) are recorded as
//! [`super::types::FieldChange`]s without contributing a recreate
//! reason so the operator-visible diff still shows the change.

use crate::config::EffectiveRunnerSpec;
use crate::state::{DiscoveredRunner, extract_x_ghars};

use super::types::{FieldChange, FieldValue};

/// Annotation values pulled out of the `[Unit]` section of a
/// discovered runner's `00-ghars.conf` drop-in body — the subset
/// that drives `requires_recreate` decisions and the field-level
/// diff payload on `RunnerDelta`. NOT the runner template body
/// (`ghars-runner@.service`); that file carries only the
/// non-per-runner `X-Ghars-Managed=true` and
/// `X-Ghars-Schema-Version=1` lines. Per-runner identity
/// annotations live entirely in the drop-in.
///
/// State discovery doesn't carry the full `EffectiveRunnerSpec` of
/// the discovered unit (only the `spec_hash` + raw text), so the plan
/// engine reconstructs the comparable subset from the X-Ghars-*
/// annotations the unit-text generator emits in `00-ghars.conf`.
///
/// Annotations covered: `X-Ghars-Runner-Url`,
/// `X-Ghars-Auth-Name`, `X-Ghars-Effective-Version`,
/// `X-Ghars-Labels`, `X-Ghars-Arch`, `X-Ghars-Runner-Sha256`
/// (when set), `X-Ghars-Runner-Tarball-Hash` (when set; sha256 of
/// operator path string, NOT the path), `X-Ghars-Trust-Zone`,
/// `X-Ghars-Network-Mode`, `X-Ghars-Caches` (comma-joined cache
/// pool names, sorted by `lower_to_effective`; empty value parses
/// as `Some(vec![])` to distinguish from missing annotation).
/// Fields still NOT annotated
/// (`memory_max`, hardening, `allowed_cpus`, proxy, hooks) live in
/// their own drop-ins; the in-place classification (Stage 2 in
/// `classify_recreate_reasons_from_annotations`) detects them by
/// comparing rendered drop-in bodies against the discovered drop-
/// ins, which avoids the need to round-trip those values through
/// annotations.
///
/// Missing-annotation handling: when a field's annotation is `None`
/// (older ghars-applied unit predating the per-field annotation set,
/// or operator-edited unit with the line stripped), the corresponding
/// Stage 1 check is skipped rather than treated as
/// "annotation==empty != desired".
/// Without this, every existing runner would falsely recreate on the
/// first apply post-upgrade because their on-disk units lack the new
/// keys. The spec-hash mismatch path picks up the change once and
/// the freshly-applied unit then carries the new annotations for
/// subsequent runs.
#[derive(Debug, Default)]
pub(super) struct DiscoveredAnnotations {
    pub(super) url: Option<String>,
    pub(super) auth_name: Option<String>,
    pub(super) runner_version: Option<String>,
    pub(super) labels: Option<Vec<String>>,
    pub(super) arch: Option<String>,
    pub(super) runner_sha256: Option<String>,
    pub(super) runner_tarball_hash: Option<String>,
    pub(super) trust_zone: Option<String>,
    pub(super) network_mode: Option<String>,
    /// `X-Ghars-Caches` value. Comma-split list of cache pool
    /// names the runner was registered against. Drives in-place
    /// drop-in reconciliation: apply diffs this against
    /// `delta.after.spec.caches` to surface added / removed pool
    /// names in the per-action detail string, and the rendered
    /// 30-cache-pool.conf drop-in body reflects the post-update
    /// pool list verbatim. Cache reach is materialized by the
    /// `BindPaths=` entries in that drop-in.
    pub(super) caches: Option<Vec<String>>,
    /// `X-Ghars-Dns` value — plain-string `DnsMode` via
    /// [`crate::config::dns_to_annotation`] / `dns_from_annotation`
    /// (`forward` for Forward, `static:<csv>` for Static). Routes
    /// as in-place FieldChange (no recreate): a dns mode change
    /// re-runs `ghars _netns-setup` on the next netns side-unit
    /// restart that the in-place rewrite triggers; no GitHub
    /// registration impact, no provision/teardown asymmetry. Pre-
    /// fix runners (annotation absent) skip the comparison.
    pub(super) dns: Option<crate::config::DnsMode>,
    /// `X-Ghars-Ipv6` value — simple snake_case enum string
    /// (`disabled` / `enabled`). v0.1 only `Disabled` is reachable
    /// (Enabled hard-errors at apply per `Ipv6Mode::Enabled` doc),
    /// so the annotation is defensive forward-compat. Routes as
    /// in-place FieldChange when the day comes that Enabled is
    /// supported. Reconsider recreate-vs-in-place when v0.2 lands
    /// ipv6=Enabled (subnet provisioning may need recreate).
    pub(super) ipv6: Option<crate::config::Ipv6Mode>,
}

impl DiscoveredAnnotations {
    /// Extract annotations from a discovered runner. Reads the
    /// `00-ghars.conf` drop-in body — that's where
    /// `crate::systemd::render_identity` writes every X-Ghars-* line
    /// (the `[Unit]` section of the drop-in). The runner template
    /// `ghars-runner@.service` itself carries only `X-Ghars-Managed=true`
    /// + `X-Ghars-Schema-Version=1`, NOT the per-runner identity
    /// annotations.
    ///
    /// `state::discover` populates `discovered.on_disk_unit_text`
    /// from the per-instance unit file path
    /// (`<unit_dir>/ghars-runner@<INSTANCE>.service`) via
    /// `fs::read_to_string` inside `discover`'s per-runner loop —
    /// `apply::execute_create_runner` writes the canonical template
    /// body to that path verbatim, so the bytes the planner sees are
    /// the runner template even though the path is per-instance.
    /// `discovered.drop_ins["00-ghars.conf"]` is populated from the
    /// per-runner drop-in dir via the `read_drop_ins` call in the
    /// same loop.
    /// Reading the unit text would
    /// therefore find nothing — Stage 1 annotation classification
    /// would silently break in production while passing under any
    /// fixture that happens to put the lines in the unit text.
    ///
    /// Missing drop-in handling: a runner whose `00-ghars.conf` is
    /// absent (older apply, operator-stripped) yields a default
    /// `DiscoveredAnnotations` with every field `None`. The classifier
    /// treats `None` as "skip this field" (avoiding spurious recreates
    /// on first apply post-upgrade), so no annotations + a hash
    /// mismatch falls through to the `uncovered` in-place arm in
    /// `plan_from` — the in-place rewrite re-establishes
    /// `00-ghars.conf` (including all `X-Ghars-*` annotations) so the
    /// next plan can classify cleanly.
    pub(super) fn from_discovered(discovered: &DiscoveredRunner) -> Self {
        let body = match discovered.drop_ins.get("00-ghars.conf") {
            Some(b) => b.as_str(),
            None => return Self::default(),
        };
        Self::from_drop_in_body(body)
    }

    pub(super) fn from_drop_in_body(body: &str) -> Self {
        let mut out = DiscoveredAnnotations::default();
        for (k, v) in extract_x_ghars(body) {
            match k.as_str() {
                "X-Ghars-Runner-Url" => out.url = Some(v),
                "X-Ghars-Auth-Name" => out.auth_name = Some(v),
                "X-Ghars-Effective-Version" => out.runner_version = Some(v),
                "X-Ghars-Labels" => {
                    // Empty annotation value ⇒ empty label vec
                    // (consistent with the renderer emitting
                    // `X-Ghars-Labels=` for spec.labels.is_empty()).
                    //
                    // Centralize set-semantic canonicalization at the
                    // parse boundary: labels are byte-sorted on emission
                    // (render_identity defense-in-depth at systemd.rs)
                    // and on classifier comparison (sorted_set_field_diff
                    // upstream). Sorting here makes those downstream
                    // sorts true defense-in-depth — every caller that
                    // reads `out.labels` sees canonical order, so a
                    // future caller that skips its own sort still gets
                    // the right answer.
                    let mut parsed: Vec<String> = if v.is_empty() {
                        Vec::new()
                    } else {
                        v.split(',').map(str::to_owned).collect()
                    };
                    parsed.sort_unstable();
                    out.labels = Some(parsed);
                }
                "X-Ghars-Arch" => out.arch = Some(v),
                "X-Ghars-Runner-Sha256" => out.runner_sha256 = Some(v),
                // Persist HASH of tarball path, not the path
                // itself. The on-disk operator path can leak
                // environment fingerprints (mount points, usernames,
                // kernel-private dirs); the hash is sufficient for
                // change detection without persisting the original
                // path string.
                "X-Ghars-Runner-Tarball-Hash" => out.runner_tarball_hash = Some(v),
                "X-Ghars-Trust-Zone" => out.trust_zone = Some(v),
                "X-Ghars-Network-Mode" => out.network_mode = Some(v),
                "X-Ghars-Caches" => {
                    // Distinguish "key present with empty value"
                    // (X-Ghars-Caches=) from "key absent" (line not
                    // emitted at all):
                    // - Present here ⇒ this arm runs ⇒ Some(parsed),
                    //   where empty value parses to Some(vec![])
                    //   (matches labels handling above; the runner
                    //   was registered with no cache pools).
                    // - Absent ⇒ this arm never runs ⇒ out.caches
                    //   stays at its default None ⇒ "unknown" ⇒ the
                    //   classifier skips the cache-pool diff
                    //   rendering at apply time. render_identity
                    //   emits the line unconditionally, so None
                    //   means the runner predates that
                    //   unconditional-emit change.
                    //
                    // Sort at parse time (matches labels above):
                    // caches are set-semantic and the renderer +
                    // classifier both sort. Canonicalizing here keeps
                    // those downstream sorts true defense-in-depth so
                    // any future caller of `out.caches` sees stable
                    // order without an extra sort.
                    let mut parsed: Vec<String> = if v.is_empty() {
                        Vec::new()
                    } else {
                        v.split(',').map(str::to_owned).collect()
                    };
                    parsed.sort_unstable();
                    out.caches = Some(parsed);
                }
                "X-Ghars-Dns" => {
                    // Round-trip via `dns_from_annotation` — the
                    // emission site uses `dns_to_annotation`
                    // (plain-string form, not JSON). Malformed
                    // values (e.g. older ghars wrote a different
                    // shape, or operator-edited drop-in) parse to
                    // None and the classifier skips the comparison
                    // (same as the absent-annotation case).
                    out.dns = crate::config::dns_from_annotation(&v);
                }
                "X-Ghars-Ipv6" => {
                    out.ipv6 = crate::config::ipv6_from_annotation(&v);
                }
                _ => {}
            }
        }
        out
    }
}

/// Classify recreate-bound field changes between an annotation-
/// reconstructed view of the discovered runner and the desired
/// effective spec.
///
/// Returns the list of recreate-bound fields that differ. A non-empty
/// list ⇒ `requires_recreate = true`.
///
/// Fields covered (Part 3 `requires_recreate` table — annotation-
/// derived subset):
/// - `url` — recreate (config.sh registration is URL-bound).
/// - `runner_version` — recreate (re-extract tarball).
/// - `labels` — recreate (registration is labels-bound).
/// - `arch` — recreate (binary architecture differs).
/// - `runner_sha256` — recreate (re-extract tarball under new digest).
/// - `runner_tarball` — recreate (operator-supplied binary swap;
///   detected via SHA256 of the path string, not the path itself,
///   to avoid persisting operator environment fingerprints in the
///   on-disk unit).
/// - `network` — recreate (Open↔Netns toggle requires
///   `provision_netns_artifacts` / `teardown_netns_artifacts`, which
///   only `execute_create_runner` / `execute_remove_runner` call; the
///   in-place rewrite path leaves orphan netns side-units or
///   unprovisioned netns paths). Within-mode config edits (egress
///   rules, DNS mode) stay in-place via the 40-network.conf body
///   diff at Stage 2.
///
/// In-place-only detection (`FieldChange` recorded, no recreate
/// reason):
/// - `auth_name` — auth-ref change is in-place per design Part 3.
///   The underlying secret is rotated out-of-band and apply
///   rebuilds the auth registry every run.
/// - `trust_zone` — once cache-pool cross-references validate at
///   `lower_to_effective` time, the runner unit body has no
///   `trust_zone` dependency. The annotation lets the operator-
///   visible diff surface `trust_zone: a → b` while keeping the
///   apply path in-place (no host-state migration).
/// - `caches` — pool-list change is in-place per design Part 3.
///   `apply::execute_update_runner`'s in-place path rewrites the
///   30-cache-pool.conf drop-in with the new pool list, diffs
///   `delta.before_caches` against the desired list to produce
///   the `(added: …; removed: …)` detail string, and cycles the
///   unit so the post-update `BindPaths` take effect — no recreate
///   needed.
///
/// All three of these record `FieldChanges` WITHOUT pushing a
/// recreate reason; the `uncovered` warn-log gate at the call site
/// checks `field_changes.is_empty()` so any one signal alone
/// prevents the spurious coverage-gap warn from firing.
///
/// Missing-annotation handling: a field whose discovered annotation
/// is `None` (older ghars-applied unit, or operator-stripped) is
/// SKIPPED here — comparing `None` against any desired
/// value would falsely fire on first apply post-upgrade. The spec-
/// hash mismatch propagates the change once; subsequent applies see
/// the freshly-emitted annotations and Stage 1 covers the field.
///
/// # Field-level diff payload
///
/// For each detected change, the function ALSO emits a `FieldChange`
/// into `out_changes` with the before/after values rendered as
/// strings. CLI consumers display this as `field: before → after`.

/// Compare two set-semantic string fields and return a `FieldChange`
/// when the sets differ. Used by both the labels and caches branches
/// of `classify_recreate_reasons_from_annotations` — both fields are
/// set-semantic (GitHub Actions matches labels order-independently;
/// cache-pool bindings are unordered — the rendered drop-in body
/// sorts pool names alphabetically) and must use the same
/// sort-then-compare contract that apply enforces.
///
/// `before`: the discovered annotation Vec, or `None` for the
/// post-upgrade fixture (skips the comparison entirely).
/// `after`: an iterator over the desired set's string values. Caller
/// extracts `.name` for caches or hands `String::as_str` for labels.
///
/// Both sides are sorted via `sort_unstable` (byte-wise Ord; matches
/// the validator-enforced ASCII charset). When the sets differ, the
/// returned `FieldChange.before/after` carry the SORTED Vecs so
/// operator-facing surfaces (plan JSON, --diff) see the canonical
/// ordering GitHub / apply will use.
///
/// Returns `None` when discovered is `None` (skip) or the sorted sets
/// match (no-op). The caller decides whether to push a recreate
/// reason — labels does, caches does not (in-place per design Part 3).
fn sorted_set_field_diff<'a>(
    path: &'static str,
    before: Option<&'a [String]>,
    after: impl Iterator<Item = &'a str>,
) -> Option<FieldChange> {
    let before = before?;
    let mut before_sorted: Vec<&str> = before.iter().map(String::as_str).collect();
    before_sorted.sort_unstable();
    let mut after_sorted: Vec<&str> = after.collect();
    after_sorted.sort_unstable();
    if before_sorted == after_sorted {
        return None;
    }
    Some(FieldChange {
        path,
        before: FieldValue::List(before_sorted.iter().map(|s| (*s).to_owned()).collect()),
        after: FieldValue::List(after_sorted.iter().map(|s| (*s).to_owned()).collect()),
    })
}

/// **AUTHORITATIVE SOURCE** for the recreate-bound field token
/// vocabulary. Every operator-facing doc reference to recreate
/// reasons (`docs/src/architecture.md` Plan disruption taxonomy +
/// `docs/src/operations.md` "Plan shows recreate, operator wants
/// in-place") MUST mirror the `reasons.push("...")` calls below.
///
/// Adding a new recreate-class field family requires THREE edits in
/// lockstep:
///   1. New `reasons.push("FIELD_NAME")` here.
///   2. Add the same `FIELD_NAME` to the bullet list at
///      `RunnerDelta::recreate_reasons` doc-comment (`plan/types.rs`).
///   3. Add the same `FIELD_NAME` to the vocabulary line at
///      `docs/src/operations.md` ("Vocabulary: url, runner_version,
///      ...") and the trailing-examples line at
///      `docs/src/architecture.md` Plan disruption section.
///
/// A token here without matching doc lines (or vice versa) means
/// operator-facing docs lie about which changes are recreate-class —
/// the alerting and runbook patterns operators build on top of plan
/// output depend on exact-match grepping of the documented vocabulary.
pub(super) fn classify_recreate_reasons_from_annotations(
    discovered: &DiscoveredAnnotations,
    desired: &EffectiveRunnerSpec,
    out_changes: &mut Vec<FieldChange>,
) -> Vec<&'static str> {
    let mut reasons: Vec<&'static str> = Vec::new();

    if let Some(url) = discovered.url.as_deref()
        && url != desired.url
    {
        reasons.push("url");
        out_changes.push(FieldChange {
            path: "url",
            before: FieldValue::String(url.to_owned()),
            after: FieldValue::String(desired.url.clone()),
        });
    }
    if let Some(version) = discovered.runner_version.as_deref() {
        let desired_version = desired.runner_version.as_deref().unwrap_or("");
        if version != desired_version {
            reasons.push("runner_version");
            out_changes.push(FieldChange {
                path: "runner_version",
                before: FieldValue::String(version.to_owned()),
                after: FieldValue::String(desired_version.to_owned()),
            });
        }
    }
    // Labels are set-semantic for GitHub Actions matching, mirror the
    // caches treatment below. Sort BOTH sides before equality so a
    // pure reorder (older ghars-applied unit wrote
    // `X-Ghars-Labels=beta,alpha` then operator reorders TOML to
    // `[alpha, beta]`) does not record a misleading `labels` recreate
    // reason / FieldChange even though GitHub's view of the
    // registration is identical. Recreate-class: a labels diff must
    // re-register the runner with GitHub.
    if let Some(change) = sorted_set_field_diff(
        "labels",
        discovered.labels.as_deref(),
        desired.labels.iter().map(String::as_str),
    ) {
        reasons.push("labels");
        out_changes.push(change);
    }
    if let Some(arch) = discovered.arch.as_deref() {
        let desired_arch = match desired.arch {
            crate::config::Arch::X86_64 => "x86_64",
            crate::config::Arch::Aarch64 => "aarch64",
        };
        if arch != desired_arch {
            reasons.push("arch");
            out_changes.push(FieldChange {
                path: "arch",
                before: FieldValue::String(arch.to_owned()),
                after: FieldValue::String(desired_arch.to_owned()),
            });
        }
    }
    // runner_sha256 change is recreate-class. Annotation is
    // emitted only when non-empty (systemd.rs::render_identity), so
    // a `None` here means either (a) the operator never pinned a
    // digest or (b) the runner predates the annotation. Either way
    // we skip — comparing None against any desired value would
    // falsely fire on the first apply post-upgrade. The classifier
    // sees the change once via spec_hash mismatch; the next apply
    // carries the freshly-emitted annotation and Stage 1 covers it.
    if let Some(sha) = discovered.runner_sha256.as_deref() {
        let desired_sha = desired.runner_sha256.as_deref().unwrap_or("");
        if sha != desired_sha {
            reasons.push("runner_sha256");
            out_changes.push(FieldChange {
                path: "runner_sha256",
                before: FieldValue::String(sha.to_owned()),
                after: FieldValue::String(desired_sha.to_owned()),
            });
        }
    }
    // runner_tarball change is recreate-class (operator-
    // supplied binary swap). The on-disk annotation is the SHA256
    // of the tarball PATH STRING, not the path itself, to avoid
    // leaking operator environment fingerprints into the persisted
    // unit. The before-value here is therefore the discovered
    // hash; the after-value is the recomputed hash of the desired
    // path. FieldChange records both hashes so operators can grep
    // for the typed reason without ever seeing the path.
    if let Some(disc_hash) = discovered.runner_tarball_hash.as_deref() {
        let desired_hash = desired
            .runner_tarball
            .as_deref()
            .map(|p| {
                use sha2::{Digest, Sha256};
                let mut h = Sha256::new();
                h.update(p.as_str().as_bytes());
                format!("sha256:{}", hex::encode(h.finalize()))
            })
            .unwrap_or_default();
        if disc_hash != desired_hash {
            reasons.push("runner_tarball");
            out_changes.push(FieldChange {
                path: "runner_tarball",
                before: FieldValue::String(disc_hash.to_owned()),
                after: FieldValue::String(desired_hash),
            });
        }
    }
    // Network mode change MUST recreate. The in-place rewrite
    // path (apply.rs::execute_update_runner non-recreate branch)
    // does not call provision_netns_artifacts /
    // teardown_netns_artifacts. An Open→Netns transition routed
    // in-place would write 40-network.conf + 15-resolv.conf with
    // NetworkNamespacePath= but leave the netns missing — the
    // unit's fail-closed `Requires=ghars-net@%i.service` would then
    // fail at restart. A Netns→Open transition routed in-place
    // would orphan ghars-net@INSTANCE + nft rule files + the
    // /var/run/netns/ghars-INSTANCE iface. Stage 1 detection here
    // forces the recreate path, which DOES run both lifecycle
    // helpers via execute_remove_runner + execute_create_runner.
    //
    // Within-mode config changes (egress rule edits, DNS mode
    // toggles inside Netns; ip_allow / ip_deny /
    // restrict_address_families edits inside Open mode) do NOT
    // recreate — the 40-network.conf body diff is in-place safe
    // and Stage 2 picks it up via the managed-drop-in body diff
    // in plan_from's intersection branch (the
    // `any_drop_in_modified` check that filters
    // MANAGED_DROP_IN_BASENAMES against Created|Modified|Removed).
    //
    // Open-mode policy edits land cleanly in Stage 2 because the
    // cgroup-BPF directives are emitted in the 40-network.conf
    // body itself (no nft side-files to miss). Toggling
    // `ip_allow` / `ip_deny` / `restrict_address_families` flips
    // the rendered drop-in body and Stage 2's body diff records
    // the in-place change.
    //
    // Caveat: within-Netns egress rule changes are NOT yet
    // detected by Stage 2 — `render_network` (systemd.rs) emits a
    // 40-network.conf that does NOT carry allowed_egress; the rules
    // flow into nft.d/ files written by apply, which Stage 2 doesn't
    // diff. A pure egress edit therefore presents as a spec-hash
    // mismatch with no Stage 1 reason and no Stage 2 evidence, and
    // falls through to the `uncovered` in-place arm in `plan_from`.
    // The in-place apply rewrites 00-ghars.conf (X-Ghars-Spec-Hash
    // annotation flips) and restarts the unit; the nft.d/ rules
    // are re-applied at the netns side-unit's next restart cycle.
    if let Some(mode) = discovered.network_mode.as_deref() {
        let desired_mode = match desired.network.as_ref().map(|n| &n.spec.mode) {
            Some(crate::config::NetworkMode::Netns) => "netns",
            Some(crate::config::NetworkMode::Open) | None => "open",
        };
        if mode != desired_mode {
            reasons.push("network");
            out_changes.push(FieldChange {
                path: "network",
                before: FieldValue::String(mode.to_owned()),
                after: FieldValue::String(desired_mode.to_owned()),
            });
        }
    }
    // auth_name change is in-place per design Part 3 — apply
    // rebuilds the auth registry every run and re-mints tokens
    // against whatever PAT/App/file source the spec currently
    // references, so there is no host-state migration to do.
    // Without this branch an auth-name-only change has no Stage 1
    // reason and no Stage 2
    // managed-drop-in-body delta (since `00-ghars.conf` carries the
    // X-Ghars-Auth-Name annotation but is excluded from the in-
    // place filter), falling through to the `uncovered` in-place
    // arm at the spec_hash mismatch check below. Recording a
    // FieldChange (without pushing to `reasons`) keeps the
    // operator-visible diff payload (the rendered text/JSON shows
    // `auth_name: before → after`) AND surfaces the change in
    // Stage 1 with a typed field rather than the opaque
    // hash-only signal. The uncovered guard below also gates on
    // `out_changes.is_empty()` so this FieldChange suppresses
    // the warn log when auth_name is the lone cause.
    if let Some(auth_name) = discovered.auth_name.as_deref()
        && auth_name != desired.auth_name
    {
        out_changes.push(FieldChange {
            path: "auth_name",
            before: FieldValue::String(auth_name.to_owned()),
            after: FieldValue::String(desired.auth_name.clone()),
        });
    }
    // trust_zone change is in-place per design Part 3. Once
    // cache-pool cross-reference validation passes at
    // `lower_to_effective` time, the runner unit body has no
    // `trust_zone` dependency — the field exists only to enforce
    // SEC-03 (cache-pool isolation) at config-load time. trust_zone
    // is in EffectiveRunnerSpec spec_hash so any change does
    // surface as a hash mismatch; without this branch, that
    // mismatch would fall through to the `uncovered` in-place arm
    // (post-fix) and surface as a warn log without a typed
    // FieldChange. Recording the FieldChange surfaces the change
    // as a typed field in plan output instead of the opaque
    // hash-only signal.
    if let Some(zone) = discovered.trust_zone.as_deref()
        && zone != desired.trust_zone
    {
        out_changes.push(FieldChange {
            path: "trust_zone",
            before: FieldValue::String(zone.to_owned()),
            after: FieldValue::String(desired.trust_zone.clone()),
        });
    }
    // caches change is in-place per design Part 3 — apply.rs's
    // execute_update_runner in-place path rewrites the
    // 30-cache-pool.conf drop-in with the new pool list and diffs
    // `delta.before_caches` against the desired list to produce
    // the `(added: …; removed: …)` per-action detail string.
    // Recording a FieldChange here (without pushing a recreate
    // reason) makes the change visible in plan output and gates
    // the `uncovered` warn log the same way auth_name / trust_zone
    // do (post-fix the uncovered arm logs a warn but no longer
    // recreates).
    //
    // Cache pool membership is set-semantics (the rendered drop-in
    // body sorts pool names alphabetically; execute_update_runner's
    // BTreeSet difference block in apply.rs computes the diff for
    // the detail string). The plan classifier MUST mirror that
    // contract or a pure reorder ["a","b"] → ["b","a"] would record
    // a misleading FieldChange in plan output even though apply
    // does no body change.
    //
    // In-place class: emit the FieldChange but DO NOT push a
    // recreate reason. Apply rewrites the per-runner drop-in body
    // in place; the runner identity is unchanged.
    if let Some(change) = sorted_set_field_diff(
        "caches",
        discovered.caches.as_deref(),
        desired.caches.iter().map(|c| c.name.as_str()),
    ) {
        out_changes.push(change);
    }
    // dns change is in-place: the dns mode drives
    // `/run/ghars/netns-resolv/<name>` written by `ghars _netns-setup`
    // at the ghars-net@ side-unit's ExecStart. A dns mode change
    // re-runs _netns-setup on the next netns side-unit restart that
    // the in-place rewrite triggers; no GitHub registration impact,
    // no provision/teardown asymmetry. Recording a FieldChange
    // (without pushing to `reasons`) keeps the change visible in
    // plan output AND prevents the uncovered warn-log from firing
    // on a dns-only edit.
    //
    // Operator-facing format mirrors X-Ghars-Network-Mode's plain
    // enum-string convention: `forward` for Forward, `static:<csv>`
    // for Static{servers}. Both the on-disk X-Ghars-Dns annotation
    // and the FieldChange render share `dns_to_annotation` so the
    // diff strings match what `systemctl cat` shows verbatim.
    //
    // Both dns and ipv6 arms only emit when desired ALSO has a
    // network binding (`desired.network.is_some()`). dns and ipv6
    // are NetworkSpec sub-fields — they don't exist without a
    // network. A transition from `Some(NetworkSpec)` → `None`
    // (operator removed the network ref) is a network-mode change
    // that the network classifier already surfaces; this arm would
    // otherwise emit asymmetric ghost-FieldChanges (dns: forward →
    // `""`; ipv6: enabled → `disabled`) where one shows the absent
    // network as empty-string and the other as the Disabled
    // default. Skip both when desired.network is None.
    if let (Some(dns), Some(desired_net)) =
        (discovered.dns.as_ref(), desired.network.as_ref())
    {
        let desired_dns = &desired_net.spec.dns;
        if dns != desired_dns {
            out_changes.push(FieldChange {
                path: "dns",
                before: FieldValue::String(crate::config::dns_to_annotation(dns)),
                after: FieldValue::String(crate::config::dns_to_annotation(desired_dns)),
            });
        }
    }
    // ipv6 change is in-place (defensive forward-compat — v0.1 only
    // Disabled is reachable; Enabled hard-errors at apply per
    // `Ipv6Mode::Enabled` doc-comment). Recording a FieldChange
    // suppresses the uncovered warn on ipv6-only edits (rare in
    // v0.1) and surfaces the change in plan output if it ever
    // happens. Same `desired.network.is_some()` guard as dns above.
    if let (Some(ipv6), Some(desired_net)) =
        (discovered.ipv6, desired.network.as_ref())
    {
        let desired_ipv6 = desired_net.spec.ipv6;
        if ipv6 != desired_ipv6 {
            out_changes.push(FieldChange {
                path: "ipv6",
                before: FieldValue::String(crate::config::ipv6_to_annotation(ipv6).to_owned()),
                after: FieldValue::String(
                    crate::config::ipv6_to_annotation(desired_ipv6).to_owned(),
                ),
            });
        }
    }

    reasons
}
