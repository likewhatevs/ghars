//! Filesystem paths used by ghars on the host.
//!
//! All paths flow from a single [`Paths`] value so tests can redirect them
//! into a tempdir without per-call plumbing. Defaults follow FHS conventions
//! and the design spec (Part 3 — Paths).

use camino::Utf8PathBuf;

/// Filesystem paths consumed by ghars during plan/apply.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Paths {
    /// `/var/lib/ghars` — per-runner state (config.sh output, runsvc.sh,
    /// versioned bin/ directories).
    pub state_dir: Utf8PathBuf,
    /// `/var/cache/ghars` — shared cache pool storage.
    pub cache_dir: Utf8PathBuf,
    /// `/var/log/ghars` — persistent log storage outside journald.
    pub logs_dir: Utf8PathBuf,
    /// `/etc/systemd/system` — unit + drop-in installation root.
    pub unit_dir: Utf8PathBuf,
    /// `/etc/credstore.encrypted/ghars` — auth credential storage.
    pub credentials_dir: Utf8PathBuf,
    /// `/run/ghars` — runtime data (apply lock, sccache UDS, token drops,
    /// netns resolv.conf bind-mount sources).
    pub runtime_dir: Utf8PathBuf,
    /// `/etc/ghars` — config + nft rule directory (`nft.d/` lives here).
    pub config_dir: Utf8PathBuf,
    /// `/etc/systemd/resolved.conf.d` — host-wide systemd-resolved
    /// drop-in directory. Used by `resolved_drop_in()` to publish the
    /// per-runner DNS-forward configuration. Field exists so tests
    /// (and operators with custom systemd installations) can redirect
    /// the path under an alternate root rather than hitting the live
    /// host `/etc`.
    pub resolved_conf_d: Utf8PathBuf,
}

impl Default for Paths {
    fn default() -> Self {
        Self {
            state_dir: Utf8PathBuf::from("/var/lib/ghars"),
            cache_dir: Utf8PathBuf::from("/var/cache/ghars"),
            logs_dir: Utf8PathBuf::from("/var/log/ghars"),
            unit_dir: Utf8PathBuf::from("/etc/systemd/system"),
            credentials_dir: Utf8PathBuf::from("/etc/credstore.encrypted/ghars"),
            runtime_dir: Utf8PathBuf::from("/run/ghars"),
            config_dir: Utf8PathBuf::from("/etc/ghars"),
            resolved_conf_d: Utf8PathBuf::from("/etc/systemd/resolved.conf.d"),
        }
    }
}

impl Paths {
    /// `<logs_dir>/apply.log` — append-only structured audit log of
    /// every apply action (SEC-36). One JSON object per line with
    /// fields: `timestamp`, `action`, `target`, `outcome`. Written
    /// at mode 0600 (root:root); operators tail/rotate via
    /// logrotate (recommended config in
    /// `apply::write_audit_log_entry`'s doc-comment).
    #[must_use]
    pub fn apply_log(&self) -> Utf8PathBuf {
        self.logs_dir.join("apply.log")
    }

    /// `<state_dir>/<trust_zone>/ghars-<name>` — runner state directory
    /// (e.g. `/var/lib/ghars/default/ghars-buckos`). Per design Part 3 +
    /// the DynamicUser pivot: runners that share a `trust_zone` share
    /// the parent dir (and thus the trust_zone's transient UID), so
    /// they can read/write each other's state through DAC.
    #[must_use]
    pub fn runner_home(&self, trust_zone: &str, name: &str) -> Utf8PathBuf {
        self.state_dir
            .join(trust_zone)
            .join(format!("ghars-{name}"))
    }

    /// `<state_dir>/<trust_zone>` — shared HOME root for every runner
    /// in `trust_zone`.
    #[must_use]
    pub fn trust_zone_home(&self, trust_zone: &str) -> Utf8PathBuf {
        self.state_dir.join(trust_zone)
    }

    /// `<unit_dir>/ghars-runner@<name>.service` — runner unit file.
    #[must_use]
    pub fn unit_file(&self, name: &str) -> Utf8PathBuf {
        self.unit_dir.join(format!("ghars-runner@{name}.service"))
    }

    /// `<unit_dir>/ghars-runner@<name>.service.d` — drop-in directory for
    /// per-runner overrides on the runner template unit.
    #[must_use]
    pub fn drop_in_dir(&self, name: &str) -> Utf8PathBuf {
        self.unit_dir.join(format!("ghars-runner@{name}.service.d"))
    }

    /// `<unit_dir>/ghars-cache@.service` — canonical cache template unit
    /// file (Part 9b). Written once and shared across all pool instances.
    #[must_use]
    pub fn cache_template_unit_file(&self) -> Utf8PathBuf {
        self.unit_dir.join("ghars-cache@.service")
    }

    /// `<unit_dir>/ghars-net@.service` — canonical netns template unit
    /// file (Part 9c). Written once by the first netns CreateRunner and
    /// shared by every per-runner instance `ghars-net@INSTANCE.service`.
    #[must_use]
    pub fn netns_template_unit_file(&self) -> Utf8PathBuf {
        self.unit_dir.join("ghars-net@.service")
    }

    /// `<unit_dir>/ghars-net@<name>.service` — per-runner netns unit
    /// path (template instance). systemd creates this implicitly via the
    /// template; ghars references it by name when calling
    /// `EnableUnitFiles` / `Start` / `Stop`.
    #[must_use]
    pub fn netns_unit_file(&self, name: &str) -> Utf8PathBuf {
        self.unit_dir.join(format!("ghars-net@{name}.service"))
    }

    /// `<unit_dir>/ghars-cache@<pool>.service` — per-pool cache unit
    /// path (template instance). systemd creates this implicitly via the
    /// template; ghars references it by name when calling
    /// `EnableUnitFiles` / `Start` / `Stop`.
    #[must_use]
    pub fn cache_unit_file(&self, pool: &str) -> Utf8PathBuf {
        self.unit_dir.join(format!("ghars-cache@{pool}.service"))
    }

    /// `<unit_dir>/ghars-cache@<pool>.service.d` — drop-in directory for
    /// per-pool overrides on the cache template unit.
    #[must_use]
    pub fn cache_drop_in_dir(&self, pool: &str) -> Utf8PathBuf {
        self.unit_dir.join(format!("ghars-cache@{pool}.service.d"))
    }

    /// `<cache_dir>/pools/<pool>` — per-pool cache storage directory
    /// (Part 9b: `CacheDirectory=ghars/pools/%i`). systemd creates and
    /// owns this at runtime; ghars removes it on `RemoveCachePool` so
    /// stale pool state does not survive a config drop.
    #[must_use]
    pub fn cache_pool_dir(&self, pool: &str) -> Utf8PathBuf {
        self.cache_pool_root().join(pool)
    }

    /// `<cache_dir>/pools` — the directory under which every
    /// per-pool subdir lives. Exposed separately so
    /// `apply::execute_remove_cache_pool` can hand it to
    /// `guard_home_dir_rmrf` as the prefix the per-pool dir must be
    /// a child of (defense in depth against path-separator or `..`
    /// regressions in pool name validation).
    #[must_use]
    pub fn cache_pool_root(&self) -> Utf8PathBuf {
        self.cache_dir.join("pools")
    }

    /// `<runtime_dir>/apply.lock` — POSIX advisory file lock for `apply`.
    #[must_use]
    pub fn apply_lock(&self) -> Utf8PathBuf {
        self.runtime_dir.join("apply.lock")
    }

    /// `<runtime_dir>/<name>.token` — token-drop path consumed by config.sh.
    #[must_use]
    pub fn token_drop(&self, name: &str) -> Utf8PathBuf {
        self.runtime_dir.join(format!("{name}.token"))
    }

    /// `<config_dir>/nft.d/<name>-host.nft` — host-side nft rules loaded into
    /// the host network namespace by `ghars-net@<name>.service`.
    #[must_use]
    pub fn nft_host_rule(&self, name: &str) -> Utf8PathBuf {
        self.config_dir
            .join("nft.d")
            .join(format!("{name}-host.nft"))
    }

    /// `<config_dir>/nft.d/<name>-ns.nft` — inside-namespace nft rules loaded
    /// inside `ghars-<name>` by `ghars-net@<name>.service`.
    #[must_use]
    pub fn nft_ns_rule(&self, name: &str) -> Utf8PathBuf {
        self.config_dir.join("nft.d").join(format!("{name}-ns.nft"))
    }

    /// `<resolved_conf_d>/ghars-<name>.conf` — systemd-resolved drop-in for
    /// netns DNS forwarding (`dns = "forward"` mode). Path resolves under the
    /// configurable `resolved_conf_d` root so tests can redirect away from the
    /// live host `/etc`.
    #[must_use]
    pub fn resolved_drop_in(&self, name: &str) -> Utf8PathBuf {
        self.resolved_conf_d.join(format!("ghars-{name}.conf"))
    }

    /// `<runtime_dir>/netns-resolv/<name>` — generated `resolv.conf` bind-mount
    /// source for the runner's netns.
    #[must_use]
    pub fn netns_resolv_conf(&self, name: &str) -> Utf8PathBuf {
        self.runtime_dir.join("netns-resolv").join(name)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn defaults_match_design_spec() {
        let p = Paths::default();
        assert_eq!(p.state_dir, "/var/lib/ghars");
        assert_eq!(p.cache_dir, "/var/cache/ghars");
        assert_eq!(p.logs_dir, "/var/log/ghars");
        assert_eq!(p.unit_dir, "/etc/systemd/system");
        assert_eq!(p.credentials_dir, "/etc/credstore.encrypted/ghars");
        assert_eq!(p.runtime_dir, "/run/ghars");
        assert_eq!(p.config_dir, "/etc/ghars");
        assert_eq!(p.resolved_conf_d, "/etc/systemd/resolved.conf.d");
    }

    #[test]
    fn runner_home_joins_trust_zone_and_runner_name() {
        let p = Paths::default();
        assert_eq!(
            p.runner_home("default", "buckos"),
            "/var/lib/ghars/default/ghars-buckos"
        );
        assert_eq!(
            p.runner_home("ci", "ktstr-1"),
            "/var/lib/ghars/ci/ghars-ktstr-1"
        );
    }

    #[test]
    fn trust_zone_home_returns_shared_root() {
        let p = Paths::default();
        assert_eq!(p.trust_zone_home("default"), "/var/lib/ghars/default");
        assert_eq!(p.trust_zone_home("audited"), "/var/lib/ghars/audited");
    }

    #[test]
    fn unit_file_uses_ghars_runner_template_prefix() {
        let p = Paths::default();
        assert_eq!(
            p.unit_file("buckos"),
            "/etc/systemd/system/ghars-runner@buckos.service"
        );
    }

    #[test]
    fn drop_in_dir_appends_d_suffix_to_unit_path() {
        let p = Paths::default();
        assert_eq!(
            p.drop_in_dir("buckos"),
            "/etc/systemd/system/ghars-runner@buckos.service.d"
        );
    }

    #[test]
    fn apply_lock_under_runtime_dir() {
        let p = Paths::default();
        assert_eq!(p.apply_lock(), "/run/ghars/apply.lock");
    }

    #[test]
    fn token_drop_under_runtime_dir() {
        let p = Paths::default();
        assert_eq!(p.token_drop("buckos"), "/run/ghars/buckos.token");
    }

    #[test]
    fn nft_rule_paths_under_config_nft_d() {
        let p = Paths::default();
        assert_eq!(
            p.nft_host_rule("buckos"),
            "/etc/ghars/nft.d/buckos-host.nft"
        );
        assert_eq!(p.nft_ns_rule("buckos"), "/etc/ghars/nft.d/buckos-ns.nft");
    }

    #[test]
    fn resolved_drop_in_under_systemd_resolved_conf_d() {
        let p = Paths::default();
        assert_eq!(
            p.resolved_drop_in("buckos"),
            "/etc/systemd/resolved.conf.d/ghars-buckos.conf"
        );
    }

    #[test]
    fn netns_resolv_conf_under_runtime_netns_resolv() {
        let p = Paths::default();
        assert_eq!(
            p.netns_resolv_conf("buckos"),
            "/run/ghars/netns-resolv/buckos"
        );
    }

    #[test]
    fn cache_template_unit_file_under_unit_dir() {
        let p = Paths::default();
        assert_eq!(
            p.cache_template_unit_file(),
            "/etc/systemd/system/ghars-cache@.service"
        );
    }

    #[test]
    fn cache_unit_file_uses_pool_name_in_template_instance() {
        let p = Paths::default();
        assert_eq!(
            p.cache_unit_file("build"),
            "/etc/systemd/system/ghars-cache@build.service"
        );
    }

    #[test]
    fn cache_drop_in_dir_appends_d_suffix_to_pool_unit() {
        let p = Paths::default();
        assert_eq!(
            p.cache_drop_in_dir("build"),
            "/etc/systemd/system/ghars-cache@build.service.d"
        );
    }

    #[test]
    fn cache_pool_dir_under_cache_dir_pools_subtree() {
        let p = Paths::default();
        assert_eq!(p.cache_pool_dir("build"), "/var/cache/ghars/pools/build");
    }

    #[test]
    fn netns_template_unit_file_under_unit_dir() {
        let p = Paths::default();
        assert_eq!(
            p.netns_template_unit_file(),
            "/etc/systemd/system/ghars-net@.service"
        );
    }

    #[test]
    fn netns_unit_file_uses_runner_name_in_template_instance() {
        let p = Paths::default();
        assert_eq!(
            p.netns_unit_file("buckos"),
            "/etc/systemd/system/ghars-net@buckos.service"
        );
    }

    #[test]
    fn paths_redirect_under_alternate_roots() {
        let p = Paths {
            state_dir: Utf8PathBuf::from("/tmp/ghars-test/lib"),
            cache_dir: Utf8PathBuf::from("/tmp/ghars-test/cache"),
            logs_dir: Utf8PathBuf::from("/tmp/ghars-test/log"),
            unit_dir: Utf8PathBuf::from("/tmp/ghars-test/units"),
            credentials_dir: Utf8PathBuf::from("/tmp/ghars-test/creds"),
            runtime_dir: Utf8PathBuf::from("/tmp/ghars-test/run"),
            config_dir: Utf8PathBuf::from("/tmp/ghars-test/etc"),
            resolved_conf_d: Utf8PathBuf::from("/tmp/ghars-test/resolved.conf.d"),
        };
        assert_eq!(
            p.runner_home("default", "r"),
            "/tmp/ghars-test/lib/default/ghars-r"
        );
        assert_eq!(
            p.unit_file("r"),
            "/tmp/ghars-test/units/ghars-runner@r.service"
        );
        assert_eq!(
            p.drop_in_dir("r"),
            "/tmp/ghars-test/units/ghars-runner@r.service.d"
        );
        assert_eq!(p.apply_lock(), "/tmp/ghars-test/run/apply.lock");
        assert_eq!(p.token_drop("r"), "/tmp/ghars-test/run/r.token");
        assert_eq!(p.nft_host_rule("r"), "/tmp/ghars-test/etc/nft.d/r-host.nft");
        assert_eq!(p.nft_ns_rule("r"), "/tmp/ghars-test/etc/nft.d/r-ns.nft");
        assert_eq!(
            p.netns_resolv_conf("r"),
            "/tmp/ghars-test/run/netns-resolv/r"
        );
        assert_eq!(
            p.cache_template_unit_file(),
            "/tmp/ghars-test/units/ghars-cache@.service"
        );
        assert_eq!(
            p.cache_unit_file("build"),
            "/tmp/ghars-test/units/ghars-cache@build.service"
        );
        assert_eq!(
            p.cache_drop_in_dir("build"),
            "/tmp/ghars-test/units/ghars-cache@build.service.d"
        );
        assert_eq!(
            p.cache_pool_dir("build"),
            "/tmp/ghars-test/cache/pools/build"
        );
        assert_eq!(
            p.netns_template_unit_file(),
            "/tmp/ghars-test/units/ghars-net@.service"
        );
        assert_eq!(
            p.netns_unit_file("r"),
            "/tmp/ghars-test/units/ghars-net@r.service"
        );
        assert_eq!(
            p.resolved_drop_in("r"),
            "/tmp/ghars-test/resolved.conf.d/ghars-r.conf"
        );
    }
}
