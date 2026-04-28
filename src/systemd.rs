//! Systemd adapter: D-Bus trait + `zbus` blocking-API implementation,
//! plus unit-text and drop-in generation.
//!
//! Design spec: Part 3 (`systemd.rs`) + Part 9 (template + drop-ins) +
//! Part 9b (unified per-pool cache service) + Part 9c (netns +
//! ghars-net@.service template + nft rule generation) + Part 9d
//! (proxy drop-in) + Part 9e (hooks drop-in).
//!
//! Boundaries:
//! - The `Systemd` trait is the mock seam for tests.
//! - `DbusSystemd` calls the `org.freedesktop.systemd1.Manager`
//!   interface over the system bus via `zbus::blocking`.
//! - Unit-text + drop-in + nft rule rendering are pure functions; no
//!   D-Bus, no filesystem.
//! - `validate_drop_in` enforces the F48 reset-on-empty rule on every
//!   generated drop-in body before it leaves the renderer.
//!
//! `ghars-net@.service` and `ghars-cache@.service` template bodies are
//! emitted as static helpers because they don't vary per-runner; only
//! their per-instance drop-ins do.

use std::collections::BTreeMap;
use std::fmt::Write;
use std::sync::LazyLock;

use regex::Regex;
use zbus::blocking::{Connection, Proxy};
pub use zbus::zvariant::OwnedObjectPath;
use zbus::zvariant::OwnedValue;

use crate::apply::cache_pool_group;
use crate::config::{
    CacheKind, EffectiveCacheBinding, EffectiveNetworkBinding, EffectiveRunnerSpec, EtcBindStyle,
    Hardening, NetworkMode, PortSpec, Proto,
};
use crate::{GharsError, Result};

// --- Systemd trait -------------------------------------------------------

/// Systemd D-Bus adapter. Production uses `DbusSystemd`; tests inject
/// an in-memory mock that records calls.
pub trait Systemd {
    /// `Manager.Reload()`. Reload unit files after a write or unlink.
    ///
    /// # Errors
    ///
    /// Returns `GharsError::Systemd` if the D-Bus call fails.
    fn daemon_reload(&self) -> Result<()>;

    /// `Manager.StartUnit(name, mode)` with `mode = "replace"`. Returns
    /// the job object path on success.
    ///
    /// # Errors
    ///
    /// Returns `GharsError::Systemd` if the call fails or the unit
    /// refuses to start.
    fn start_unit(&self, unit: &str) -> Result<()>;

    /// `Manager.StopUnit(name, mode)` with `mode = "replace"`. Returns
    /// the job object path on success.
    ///
    /// # Errors
    ///
    /// Returns `GharsError::Systemd` if the call fails.
    fn stop_unit(&self, unit: &str) -> Result<()>;

    /// `Manager.EnableUnitFiles(files, runtime=false, force=false)`.
    /// Links the unit into the appropriate `*.target.wants/` directory.
    ///
    /// # Errors
    ///
    /// Returns `GharsError::Systemd` on D-Bus failure.
    fn enable_unit(&self, unit: &str) -> Result<()>;

    /// `Manager.DisableUnitFiles(files, runtime=false)`. Removes the
    /// `*.target.wants/` symlink.
    ///
    /// # Errors
    ///
    /// Returns `GharsError::Systemd` on D-Bus failure.
    fn disable_unit(&self, unit: &str) -> Result<()>;

    /// `Manager.ListUnitsFiltered(states)`. Returns `(name,
    /// description, load_state, active_state, sub_state, follower,
    /// object_path, job_id, job_type, job_object_path)` tuples.
    ///
    /// Used by state discovery to enumerate live `ghars-runner@*`
    /// instances and `ghars-cache@*` services without `daemon-reload`-
    /// triggering enumeration over the full unit set.
    ///
    /// # Errors
    ///
    /// Returns `GharsError::Systemd` on D-Bus failure.
    fn list_units_filtered(&self, states: &[&str]) -> Result<Vec<UnitListEntry>>;

    /// Read a string-typed property from a named interface.
    ///
    /// Wire signature MUST be `s`. Numeric / object-path / array
    /// values are rejected with a typed error — there is NO
    /// `format!("{value:?}")` Debug fallback. Callers that ask for a
    /// non-string property get a clear "wrong typed accessor"
    /// diagnostic instead of an inspectable-but-unparseable Debug
    /// string.
    ///
    /// Common (unit, iface, property) tuples:
    /// - `(unit, "org.freedesktop.systemd1.Unit",   "ActiveState")`
    /// - `(unit, "org.freedesktop.systemd1.Unit",   "LoadState")`
    /// - `(unit, "org.freedesktop.systemd1.Unit",   "SubState")`
    /// - `(unit, "org.freedesktop.systemd1.Unit",   "UnitFileState")`
    /// - `(unit, "org.freedesktop.systemd1.Service","Type")`
    /// - `(unit, "org.freedesktop.systemd1.Service","Result")`
    ///
    /// # Errors
    ///
    /// Returns `GharsError::Systemd` on D-Bus failure, unknown
    /// property, or wire-signature mismatch.
    fn get_unit_property(&self, unit: &str, iface: &str, property: &str) -> Result<String>;

    /// Read an unsigned-integer property from a named interface.
    ///
    /// Wire signature may be `y`/`q`/`u`/`t` — every unsigned int
    /// shape widens losslessly to u64. The accessor accepts each
    /// shape because systemd encodes scalar numerics inconsistently:
    /// `MemoryCurrent`/`CPUUsageNSec`/`IOReadBytes`/`IOWriteBytes`/
    /// `TasksCurrent` use `t`, `MainPID` uses `u`, and a future
    /// systemd revision could repick. One accessor covers them all.
    ///
    /// Common (unit, iface, property) tuples:
    /// - `(unit, "org.freedesktop.systemd1.Service","MainPID")` — `u`
    /// - `(unit, "org.freedesktop.systemd1.Service","MemoryCurrent")` — `t`
    /// - `(unit, "org.freedesktop.systemd1.Service","CPUUsageNSec")` — `t`
    /// - `(unit, "org.freedesktop.systemd1.Service","IOReadBytes")` — `t`
    /// - `(unit, "org.freedesktop.systemd1.Service","IOWriteBytes")` — `t`
    /// - `(unit, "org.freedesktop.systemd1.Service","TasksCurrent")` — `t`
    ///
    /// systemd reports `MemoryCurrent = u64::MAX` when accounting is
    /// disabled; this method passes that sentinel through verbatim —
    /// callers that care must compare against `u64::MAX` themselves.
    ///
    /// # Errors
    ///
    /// Returns `GharsError::Systemd` if the property is missing, has
    /// a non-numeric type (`s`/`o`/`a`/struct), or D-Bus is
    /// unreachable.
    fn get_unit_property_u64(&self, unit: &str, iface: &str, property: &str) -> Result<u64>;

    /// Read an object-path property from a named interface. Wire
    /// signature MUST be `o`.
    ///
    /// Common tuple: `(unit, "org.freedesktop.systemd1.Unit",
    /// "FragmentPath")`.
    ///
    /// # Errors
    ///
    /// Returns `GharsError::Systemd` on D-Bus failure, unknown
    /// property, or wire-signature mismatch.
    fn get_unit_property_object_path(
        &self,
        unit: &str,
        iface: &str,
        property: &str,
    ) -> Result<OwnedObjectPath>;

    /// Read a string-typed property from
    /// `org.freedesktop.systemd1.Service`.
    ///
    /// Convenience over `get_unit_property` that hardcodes the Service
    /// interface — call sites that want
    /// `Service.Result`/`Service.Type`/etc. avoid spelling the
    /// interface name on every line. Wire signature MUST be `s`;
    /// numeric / object-path / array values are rejected with a typed
    /// error.
    ///
    /// Common properties: `Type`, `Result`,
    /// `ExecMainStartTimestamp` (formatted-string variant).
    ///
    /// # Errors
    ///
    /// Returns `GharsError::Systemd` on D-Bus failure, unknown
    /// property, or wire-signature mismatch.
    fn get_service_property_string(&self, unit: &str, property: &str) -> Result<String>;

    /// Read an unsigned-integer property from
    /// `org.freedesktop.systemd1.Service`.
    ///
    /// Convenience over `get_unit_property_u64` that hardcodes the
    /// Service interface. Accepts any unsigned int wire shape
    /// (`y`/`q`/`u`/`t`) and widens losslessly to u64 — every numeric
    /// Service property goes through this single accessor regardless
    /// of which width systemd used.
    ///
    /// Common properties: `MainPID` (`u`), `MemoryCurrent` (`t`),
    /// `CPUUsageNSec` (`t`), `IOReadBytes` / `IOWriteBytes` (`t`),
    /// `TasksCurrent` (`t`).
    ///
    /// systemd reports `MemoryCurrent = u64::MAX` when accounting is
    /// disabled; the value is passed through verbatim — callers that
    /// care must compare against `u64::MAX` themselves.
    ///
    /// # Errors
    ///
    /// Returns `GharsError::Systemd` if the property is missing, has
    /// a non-numeric type (`s`/`o`/`a`/struct), or D-Bus is
    /// unreachable.
    fn get_service_property_u64(&self, unit: &str, property: &str) -> Result<u64>;
}

/// Raw tuple shape of one entry in `Manager.ListUnitsFiltered`'s reply
/// (D-Bus signature `(ssssssouso)`). Decoded into `UnitListEntry` by
/// the adapter; kept here as a type alias to make the deserialization
/// site readable.
type UnitListReplyTuple = (
    String,
    String,
    String,
    String,
    String,
    String,
    OwnedObjectPath,
    u32,
    String,
    OwnedObjectPath,
);

/// One row of `Manager.ListUnitsFiltered`'s reply tuple. Field order
/// matches the D-Bus signature `a(ssssssouso)` documented at
/// `org.freedesktop.systemd1`'s introspection XML.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct UnitListEntry {
    /// Primary unit name (e.g. `ghars-runner@buckos.service`).
    pub name: String,
    /// `Description=` text.
    pub description: String,
    /// `LoadState` (`loaded`, `error`, `masked`, `not-found`).
    pub load_state: String,
    /// `ActiveState` (`active`, `inactive`, `failed`, etc.).
    pub active_state: String,
    /// `SubState` (`running`, `dead`, `start-pre`, etc.).
    pub sub_state: String,
    /// Follower unit (empty when this unit is canonical).
    pub follower: String,
    /// Unit object path on the D-Bus.
    pub object_path: String,
    /// Job ID (0 when no job is queued).
    pub job_id: u32,
    /// Job type (`start`, `stop`, ...; empty when no job).
    pub job_type: String,
    /// Job object path (`/` when no job).
    pub job_object_path: String,
}

// --- DbusSystemd ---------------------------------------------------------

/// `org.freedesktop.systemd1` well-known service.
const SD_SERVICE: &str = "org.freedesktop.systemd1";
/// `Manager` object path on the systemd bus name.
const SD_MANAGER_PATH: &str = "/org/freedesktop/systemd1";
/// `Manager` interface name.
const SD_MANAGER_IFACE: &str = "org.freedesktop.systemd1.Manager";
/// Standard `Properties` interface — used for `Get` and `Set`.
const PROPS_IFACE: &str = "org.freedesktop.DBus.Properties";
/// `Service` interface — hardcoded by `get_service_property_*` so
/// Service-specific accessors do not spell the interface on every
/// call site.
const SD_SERVICE_IFACE: &str = "org.freedesktop.systemd1.Service";
/// Per-systemd convention, the "replace" job mode is the safe default
/// for `Start`/`Stop` from automation: queues the job, replacing any
/// pending one for the same unit.
const JOB_MODE: &str = "replace";

/// Production `Systemd` impl backed by the system D-Bus and `zbus`'s
/// blocking-API. See Part 3 (`systemd.rs`).
pub struct DbusSystemd {
    connection: Connection,
}

impl std::fmt::Debug for DbusSystemd {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("DbusSystemd").finish_non_exhaustive()
    }
}

impl DbusSystemd {
    /// Open a blocking connection to the system D-Bus.
    ///
    /// # Errors
    ///
    /// Returns `GharsError::Systemd` if the system bus is unreachable.
    pub fn new() -> Result<Self> {
        let connection = Connection::system().map_err(|e| {
            GharsError::Systemd(
                format!("system D-Bus connect failed: {e}"),
                "verify dbus is running and the caller has access to the system bus".into(),
            )
        })?;
        Ok(Self { connection })
    }

    fn manager_proxy(&self) -> Result<Proxy<'_>> {
        Proxy::new(
            &self.connection,
            SD_SERVICE,
            SD_MANAGER_PATH,
            SD_MANAGER_IFACE,
        )
        .map_err(|e| {
            GharsError::Systemd(
                format!("construct Manager proxy: {e}"),
                "verify systemd D-Bus interface is reachable".into(),
            )
        })
    }

    fn unit_path(&self, unit: &str) -> Result<OwnedObjectPath> {
        let proxy = self.manager_proxy()?;
        proxy
            .call::<_, _, OwnedObjectPath>("GetUnit", &(unit,))
            .map_err(|e| {
                GharsError::Systemd(
                    format!("Manager.GetUnit({unit}): {e}"),
                    "verify the unit is loaded — `systemctl status UNIT` and `daemon-reload`"
                        .into(),
                )
            })
    }
}

impl Systemd for DbusSystemd {
    fn daemon_reload(&self) -> Result<()> {
        let proxy = self.manager_proxy()?;
        // Reload returns no body; () matches the empty signature.
        proxy.call::<_, _, ()>("Reload", &()).map_err(|e| {
            GharsError::Systemd(
                format!("Manager.Reload: {e}"),
                "check journalctl for systemd errors and verify root or polkit auth".into(),
            )
        })
    }

    fn start_unit(&self, unit: &str) -> Result<()> {
        let proxy = self.manager_proxy()?;
        // Reply is the job object path; we don't need to track it.
        proxy
            .call::<_, _, OwnedObjectPath>("StartUnit", &(unit, JOB_MODE))
            .map_err(|e| {
                GharsError::Systemd(
                    format!("Manager.StartUnit({unit}, {JOB_MODE}): {e}"),
                    "inspect `systemctl status UNIT` and the unit's journal".into(),
                )
            })?;
        Ok(())
    }

    fn stop_unit(&self, unit: &str) -> Result<()> {
        let proxy = self.manager_proxy()?;
        proxy
            .call::<_, _, OwnedObjectPath>("StopUnit", &(unit, JOB_MODE))
            .map_err(|e| {
                GharsError::Systemd(
                    format!("Manager.StopUnit({unit}, {JOB_MODE}): {e}"),
                    "inspect `systemctl status UNIT` and the unit's journal".into(),
                )
            })?;
        Ok(())
    }

    fn enable_unit(&self, unit: &str) -> Result<()> {
        let proxy = self.manager_proxy()?;
        // EnableUnitFiles(files: as, runtime: b, force: b) -> (carries_install_info: b, changes: a(sss))
        // We discard both return components; ghars relies on a follow-up
        // daemon_reload() call which is the operator's contract.
        let files: Vec<&str> = vec![unit];
        proxy
            .call::<_, _, (bool, Vec<(String, String, String)>)>(
                "EnableUnitFiles",
                &(files, false, false),
            )
            .map_err(|e| {
                GharsError::Systemd(
                    format!("Manager.EnableUnitFiles({unit}): {e}"),
                    "verify the unit file is present in /etc/systemd/system or /usr/lib/systemd/system"
                        .into(),
                )
            })?;
        Ok(())
    }

    fn disable_unit(&self, unit: &str) -> Result<()> {
        let proxy = self.manager_proxy()?;
        // DisableUnitFiles(files: as, runtime: b) -> (changes: a(sss))
        let files: Vec<&str> = vec![unit];
        proxy
            .call::<_, _, Vec<(String, String, String)>>("DisableUnitFiles", &(files, false))
            .map_err(|e| {
                GharsError::Systemd(
                    format!("Manager.DisableUnitFiles({unit}): {e}"),
                    "the unit may already be disabled or not installed".into(),
                )
            })?;
        Ok(())
    }

    fn list_units_filtered(&self, states: &[&str]) -> Result<Vec<UnitListEntry>> {
        let proxy = self.manager_proxy()?;
        // ListUnitsFiltered(states: as) -> a(ssssssouso)
        // The reply tuple (per systemd D-Bus introspection) carries:
        //   (name, description, load_state, active_state, sub_state,
        //    follower, object_path, job_id, job_type, job_object_path)
        let states_vec: Vec<&str> = states.to_vec();
        let raw: Vec<UnitListReplyTuple> = proxy
            .call("ListUnitsFiltered", &(states_vec,))
            .map_err(|e| {
                GharsError::Systemd(
                    format!("Manager.ListUnitsFiltered({states:?}): {e}"),
                    "check that the system bus is reachable".into(),
                )
            })?;
        Ok(raw
            .into_iter()
            .map(
                |(
                    name,
                    description,
                    load_state,
                    active_state,
                    sub_state,
                    follower,
                    object_path,
                    job_id,
                    job_type,
                    job_object_path,
                )| UnitListEntry {
                    name,
                    description,
                    load_state,
                    active_state,
                    sub_state,
                    follower,
                    object_path: object_path.as_str().to_owned(),
                    job_id,
                    job_type,
                    job_object_path: job_object_path.as_str().to_owned(),
                },
            )
            .collect())
    }

    fn get_unit_property(&self, unit: &str, iface: &str, property: &str) -> Result<String> {
        let value = self.fetch_property(unit, iface, property)?;
        decode_string_value(unit, iface, property, &value)
    }

    fn get_unit_property_u64(&self, unit: &str, iface: &str, property: &str) -> Result<u64> {
        let value = self.fetch_property(unit, iface, property)?;
        decode_u64_value(unit, iface, property, &value)
    }

    fn get_unit_property_object_path(
        &self,
        unit: &str,
        iface: &str,
        property: &str,
    ) -> Result<OwnedObjectPath> {
        let value = self.fetch_property(unit, iface, property)?;
        decode_object_path_value(unit, iface, property, &value)
    }

    fn get_service_property_string(&self, unit: &str, property: &str) -> Result<String> {
        self.get_unit_property(unit, SD_SERVICE_IFACE, property)
    }

    fn get_service_property_u64(&self, unit: &str, property: &str) -> Result<u64> {
        self.get_unit_property_u64(unit, SD_SERVICE_IFACE, property)
    }
}

impl DbusSystemd {
    /// Construct the Properties proxy for `unit`'s object path and
    /// call `Properties.Get(interface, property)`. Used by every typed
    /// accessor so the D-Bus boilerplate (path resolution +
    /// proxy construction + InvalidArgs error formatting) stays in
    /// one place.
    fn fetch_property(&self, unit: &str, interface: &str, property: &str) -> Result<OwnedValue> {
        let path = self.unit_path(unit)?;
        let path_str = path.as_str().to_owned();
        let proxy =
            Proxy::new(&self.connection, SD_SERVICE, path_str, PROPS_IFACE).map_err(|e| {
                GharsError::Systemd(
                    format!("construct Properties proxy for {unit}: {e}"),
                    "verify systemd D-Bus is reachable".into(),
                )
            })?;
        proxy.call("Get", &(interface, property)).map_err(|e| {
            GharsError::Systemd(
                format!("Properties.Get({unit}, {interface}.{property}): {e}"),
                format!(
                    "verify the property exists on {interface}; \
                    Service-only properties (MainPID, MemoryCurrent, ...) \
                    fail when queried on Unit, and vice-versa"
                ),
            )
        })
    }
}

/// Decode a `Properties.Get` reply into a Rust `String`. Wire
/// signature MUST be `s`; any other shape is rejected with a typed
/// error. There is NO `format!("{value:?}")` Debug fallback — that
/// would have produced strings like `"U32(1234)"` for u32 properties
/// and silently broken every parse-from-string caller (notably
/// MainPID at apply.rs::verify_runner_netns).
fn decode_string_value(
    unit: &str,
    iface: &str,
    property: &str,
    value: &OwnedValue,
) -> Result<String> {
    let cloned = value.try_clone().map_err(|e| {
        GharsError::Systemd(
            format!("Properties.Get({unit}, {iface}.{property}) clone: {e}"),
            "report this as a ghars bug".into(),
        )
    })?;
    String::try_from(cloned).map_err(|_| {
        GharsError::Systemd(
            format!(
                "Properties.Get({unit}, {iface}.{property}) wire signature mismatch: \
                expected s, got non-string value"
            ),
            "use get_unit_property_u64 for numeric properties or \
            get_unit_property_object_path for object-path properties"
                .into(),
        )
    })
}

/// Decode a `Properties.Get` reply into a Rust `u64`. Accepts any
/// unsigned-int wire shape (`y`/`q`/`u`/`t`) and widens losslessly
/// to u64. systemd encodes numeric properties inconsistently —
/// `MainPID` is `u`, `MemoryCurrent`/`CPUUsageNSec`/etc. are `t`,
/// and a future revision could repick — so one accessor that covers
/// every unsigned int is the only correctness-preserving shape.
/// Strings, object paths, signed ints, arrays, and structs are
/// rejected with a typed error.
fn decode_u64_value(unit: &str, iface: &str, property: &str, value: &OwnedValue) -> Result<u64> {
    // u64 first — covers `t` directly and is the most common shape.
    let cloned = value.try_clone().map_err(|e| {
        GharsError::Systemd(
            format!("Properties.Get({unit}, {iface}.{property}) clone: {e}"),
            "report this as a ghars bug".into(),
        )
    })?;
    if let Ok(v) = u64::try_from(cloned) {
        return Ok(v);
    }
    // Then u32 (`u`, e.g. MainPID).
    let cloned = value.try_clone().map_err(|e| {
        GharsError::Systemd(
            format!("Properties.Get({unit}, {iface}.{property}) clone: {e}"),
            "report this as a ghars bug".into(),
        )
    })?;
    if let Ok(v) = u32::try_from(cloned) {
        return Ok(u64::from(v));
    }
    // Then u16 (`q`).
    let cloned = value.try_clone().map_err(|e| {
        GharsError::Systemd(
            format!("Properties.Get({unit}, {iface}.{property}) clone: {e}"),
            "report this as a ghars bug".into(),
        )
    })?;
    if let Ok(v) = u16::try_from(cloned) {
        return Ok(u64::from(v));
    }
    // Finally u8 (`y`).
    let cloned = value.try_clone().map_err(|e| {
        GharsError::Systemd(
            format!("Properties.Get({unit}, {iface}.{property}) clone: {e}"),
            "report this as a ghars bug".into(),
        )
    })?;
    if let Ok(v) = u8::try_from(cloned) {
        return Ok(u64::from(v));
    }
    Err(GharsError::Systemd(
        format!(
            "Properties.Get({unit}, {iface}.{property}) wire signature mismatch: \
            expected an unsigned int (y/q/u/t), got non-numeric value"
        ),
        "use get_unit_property for string-typed values or \
        get_unit_property_object_path for object-path properties"
            .into(),
    ))
}

/// Decode a `Properties.Get` reply into an `OwnedObjectPath`. Wire
/// signature MUST be `o`; any other shape is rejected.
fn decode_object_path_value(
    unit: &str,
    iface: &str,
    property: &str,
    value: &OwnedValue,
) -> Result<OwnedObjectPath> {
    let cloned = value.try_clone().map_err(|e| {
        GharsError::Systemd(
            format!("Properties.Get({unit}, {iface}.{property}) clone: {e}"),
            "report this as a ghars bug".into(),
        )
    })?;
    OwnedObjectPath::try_from(cloned).map_err(|_| {
        GharsError::Systemd(
            format!(
                "Properties.Get({unit}, {iface}.{property}) wire signature mismatch: \
                expected o, got non-object-path value"
            ),
            "use get_unit_property for string-typed values or \
            get_unit_property_u64 for numeric properties"
                .into(),
        )
    })
}

// --- Reset-on-empty validator (F48) -------------------------------------

/// List-typed directives that systemd treats as RESET on empty
/// assignment (per `systemd.exec.xml:2912-2920` for `SystemCallFilter`,
/// the same rule applies to the rest). A managed drop-in (00-09 ..
/// 50-59 ranges) MUST NOT emit any of these with a bare `=` —
/// otherwise the entire allowlist / denylist defined by the template
/// silently disappears.
//
// `DeviceAllow` is INTENTIONALLY ABSENT from this list. The runner
// template grants exactly one device — `DeviceAllow=/dev/kvm rw` — and
// the operator's `hardening.kvm = false` override has to revoke that
// grant somehow. systemd's only mechanism for revoking a list-typed
// allowance is the empty-reset (`DeviceAllow=`); a drop-in cannot
// "subtract" a specific entry. So `render_hardening` emits
// `DeviceAllow=` followed by nothing when the operator drops kvm,
// producing the desired empty allowlist alongside the template's
// `DevicePolicy=closed` (which already denies-by-default once the
// allowlist is empty). The other ten directives in this list have
// multi-entry templates where an accidental empty-reset would silently
// disable security hardening; F48's protection is preserved for them.
const RESET_ON_EMPTY_DIRECTIVES: &[&str] = &[
    "SystemCallFilter",
    "CapabilityBoundingSet",
    "BindReadOnlyPaths",
    "BindPaths",
    "ReadWritePaths",
    "IPAddressDeny",
    "IPAddressAllow",
    "RestrictAddressFamilies",
    "AmbientCapabilities",
    "SystemCallLog",
];

// The pattern joins a constant slice of static strings — Regex::new
// failure is impossible by inspection. `expect` makes the panic site
// concrete; the surrounding `#[allow]` matches the validators module's
// pattern for compile-time-constant regexes.
//
// Pattern shape: `(?m)^[ \t]*(?:DIRECTIVE)=[ \t]*$`.
// - `(?m)` — `^` / `$` match per-line (multiline anchors), so the
//   regex finds resets anywhere in the body.
// - `^[ \t]*` — leading horizontal whitespace is allowed because
//   `man systemd.syntax` says "leading whitespace is ignored". A
//   line `   DeviceAllow=` is parsed by systemd as a reset, so the
//   validator MUST flag it. We use `[ \t]*` (NOT `\s*`) so the regex
//   doesn't slurp newlines into "leading whitespace" and confuse
//   per-line matching.
// - `(?:DIRECTIVE)` — exact match against the protected name set.
//   `(?:...)` groups without capturing.
// - `=[ \t]*$` — bare `=` followed by horizontal whitespace only,
//   then end-of-line. Same `[ \t]` reasoning. Trailing newlines are
//   not consumed by `\s` here, so per-line semantics are preserved.
//
// Cases the pattern HANDLES correctly:
// - `DeviceAllow=`                      → match (reset)
// - `DeviceAllow=  ` (trailing spaces)  → match (still reset)
// - `   DeviceAllow=` (leading spaces)  → match (systemd ignores LWS)
// - `DeviceAllow=/dev/kvm rw`           → no match (has a value)
// - `# DeviceAllow=`                    → no match (comment)
// - `; DeviceAllow=`                    → no match (comment)
// - `DeviceAllow=\\` (continuation)     → no match (`\` is not in
//   `[ \t]`; the next line carries the value, so this is NOT a reset)
//
// Cases NOT handled (out of scope; documented for future work):
// - section-name boundaries — the regex doesn't care which `[Service]`
//   block a line is in. A bare `DeviceAllow=` under `[X-Ghars-Notes]`
//   would still trip the regex even though systemd would never read
//   it. This is conservatively safe (false positives only).
// - quoted reset values — `DeviceAllow=""` is treated as a non-empty
//   value `""` by systemd-analyze, so it's NOT a reset. The current
//   pattern correctly does NOT match this (the `=` is followed by a
//   non-whitespace `"`).
#[allow(clippy::expect_used)]
static RESET_ON_EMPTY_RE: LazyLock<Regex> = LazyLock::new(|| {
    let alts = RESET_ON_EMPTY_DIRECTIVES.join("|");
    let pattern = format!(r"(?m)^[ \t]*(?:{alts})=[ \t]*$");
    Regex::new(&pattern).expect("RESET_ON_EMPTY_RE pattern is constant")
});

/// Reject a generated drop-in body that contains any reset-on-empty
/// assignment. Operator-managed `99-*.conf` files are NOT validated —
/// the operator owns those.
///
/// # Errors
///
/// Returns `GharsError::Validation` with the offending directive name
/// and a hint pointing at the F48 spec section.
pub fn validate_drop_in(name: &str, body: &str) -> Result<()> {
    if let Some(m) = RESET_ON_EMPTY_RE.find(body) {
        let line = m.as_str().trim_end();
        // Extract the directive name (everything before the `=`).
        let directive = line.split('=').next().unwrap_or("").trim();
        return Err(GharsError::Validation(
            format!(
                "drop-in {name} emits an empty reset for {directive:?}; \
                this would silently erase the template's allowlist"
            ),
            "drop-ins must never emit list-typed directives with a bare `=`; \
            see Part 9 reset-on-empty validator (F48)"
                .into(),
        ));
    }
    Ok(())
}

// --- Hardening profile ---------------------------------------------------

/// Hardening defaults — match the Python tool's profile (see Part 9,
/// the doc-comments on `Hardening` in `config.rs`). `None` on a
/// `Hardening` field means "inherit"; the renderer translates each
/// option to a concrete bool / list at render time.
//
// One bool per systemd directive is the natural shape — bitflags would
// obscure the per-directive label. Pedantic clippy suggests refactoring
// >3 bools; here the labels are load-bearing for readability.
#[allow(clippy::struct_excessive_bools)]
struct HardeningProfile {
    kvm: bool,
    restrict_realtime: bool,
    protect_control_groups: bool,
    restrict_suid_sgid: bool,
    private_devices: bool,
    private_ipc: bool,
}

impl HardeningProfile {
    fn from(h: &Hardening) -> Self {
        Self {
            kvm: h.kvm.unwrap_or(true),
            restrict_realtime: h.restrict_realtime.unwrap_or(false),
            protect_control_groups: h.protect_control_groups.unwrap_or(false),
            restrict_suid_sgid: h.restrict_suid_sgid.unwrap_or(true),
            private_devices: h.private_devices.unwrap_or(true),
            private_ipc: h.private_ipc.unwrap_or(true),
        }
    }
}

fn yes_no(b: bool) -> &'static str {
    if b { "yes" } else { "no" }
}

// --- Rendered output ----------------------------------------------------

/// Result of `render_runner_unit`: the canonical template body plus
/// the per-instance drop-ins keyed by basename (e.g.
/// `00-ghars.conf`), plus any warnings the renderer wants to surface
/// to the operator (rendered into plan output).
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct RenderedUnit {
    /// Canonical template body — installed once at
    /// `/etc/systemd/system/ghars-runner@.service`.
    pub template: String,
    /// Drop-in basename → contents. Installed under the per-instance
    /// drop-in directory (`ghars-runner@NAME.service.d/`).
    pub drop_ins: BTreeMap<String, String>,
    /// Render-time advisories surfaced to the plan engine. The plan
    /// engine concatenates these into `Plan.warnings` so apply prints
    /// them before executing. Examples: "kvm=false drops /dev/kvm rw
    /// — workflows that need KVM will fail".
    pub warnings: Vec<String>,
}

// --- Runner template body (Part 9) ---------------------------------------

/// Canonical `ghars-runner@.service` template body. Pure function:
/// returns the same bytes every time. The body is verbatim from Part 9.
#[must_use]
pub fn runner_template_text() -> String {
    // The template is intentionally large + comment-heavy per Part 9;
    // we emit it as a raw string so the bytes round-trip exactly.
    RUNNER_TEMPLATE.to_string()
}

const RUNNER_TEMPLATE: &str = r"[Unit]
Description=GitHub Actions Runner (%i)
After=network-online.target
Wants=network-online.target
ConditionPathExists=/var/lib/ghars/%i/runsvc.sh
StartLimitIntervalSec=300
StartLimitBurst=5
X-Ghars-Managed=true
X-Ghars-Schema-Version=1

[Service]
Type=simple
# SEC-02: ExecStart=! runs the runsvc trampoline as root (User=/Group=
# bypassed) WHILE the unit's full sandbox stays applied — including
# TemporaryFileSystem=/:ro, BindReadOnlyPaths, PrivateDevices, the
# SystemCallFilter allowlist, NetworkNamespacePath, etc. (Per
# systemd.service(5) the `!` prefix alters only User=/Group=/
# SupplementaryGroups=; in contrast `+` would also bypass
# CapabilityBoundingSet AND every filesystem-namespacing directive,
# which would silently leave the runner unsandboxed.)
#
# The trampoline integrity-checks /var/lib/ghars/%i/runsvc.sh against
# the recorded X-Ghars-Runsvc-Sha256 annotation in
# /etc/systemd/system/ghars-runner@%i.service.d/00-ghars.conf, then
# setgid()/setuid()s to ghars-%i and fexecve()s the verified file
# descriptor (closing the open-then-rename TOCTOU window the runner
# user could otherwise exploit on a runner-owned runsvc.sh).
#
# The trampoline is a separately-packaged compiled binary at
# /usr/lib/ghars/runsvc-wrapper (root:root mode 0755) — NOT a shell
# script. CapabilityBoundingSet below is overridden to grant just the
# CAP_SETUID/CAP_SETGID needed by the privilege drop; runsvc.sh has no
# file capabilities, so per capabilities(7) its post-exec permitted
# set is empty regardless of the bounding set.
ExecStart=!/usr/lib/ghars/runsvc-wrapper %i
User=ghars-%i
Group=ghars-%i
WorkingDirectory=/var/lib/ghars/%i
# F72: Slice=system.slice unconditional. No operator opt-in.
Slice=system.slice

# StateDirectory implies BindPaths under TemporaryFileSystem=/:ro and
# survives across restarts.
StateDirectory=ghars/%i
StateDirectoryMode=0700
CacheDirectory=ghars/%i
CacheDirectoryMode=0700
LogsDirectory=ghars/%i
LogsDirectoryMode=0700
RuntimeDirectory=ghars/%i
RuntimeDirectoryMode=0700

# PATH set explicitly. systemd's compile-time DEFAULT_PATH varies and
# may omit sbin. ccache wrapper dirs come first to shadow real
# compilers.
Environment=PATH=/usr/lib64/ccache:/usr/lib/ccache:/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin
Environment=LANG=C.UTF-8
Environment=HOME=/var/lib/ghars/%i

# Per-runner cache env. Shared cache pools override these via
# 30-cache-pool.conf drop-in.
Environment=CCACHE_DIR=%C/ghars/%i/ccache
Environment=SCCACHE_DIR=%C/ghars/%i/sccache
Environment=CCACHE_MAXSIZE=200G
Environment=SCCACHE_CACHE_SIZE=200G
# SCCACHE_SERVER_UDS lives on tmpfs (RuntimeDirectory) — no stale
# sockets after crash. (F32)
Environment=SCCACHE_SERVER_UDS=%t/ghars/%i/sccache.sock

KillMode=control-group
KillSignal=SIGTERM
TimeoutStopSec=5min

# Privilege isolation. CapabilityBoundingSet is the smallest set the
# SEC-02 wrapper needs to drop privileges (CAP_SETUID + CAP_SETGID for
# the setuid/setgid syscalls — kernel/sys.c:669 enforces CAP_SETUID).
# After the wrapper fexecve()s into runsvc.sh the kernel computes the
# new permitted set as `(P_inheritable & F_inheritable) | (F_permitted
# & P_bounding)`. Inheritable is empty, runsvc.sh is a script with no
# file capabilities, so the post-exec permitted set is empty regardless
# of the bounding set. AmbientCapabilities stays empty so the kernel
# does not raise any cap into permitted at exec time.
NoNewPrivileges=yes
CapabilityBoundingSet=CAP_SETUID CAP_SETGID
AmbientCapabilities=

# Filesystem allowlist. Optional paths use `-` prefix for merged-usr
# compat. (F35)
TemporaryFileSystem=/:ro
BindReadOnlyPaths=/usr -/lib -/lib64 -/bin -/sbin
BindReadOnlyPaths=/etc/hosts /etc/nsswitch.conf
BindReadOnlyPaths=/etc/passwd /etc/group
BindReadOnlyPaths=/etc/ssl /etc/ca-certificates -/etc/pki
BindReadOnlyPaths=-/etc/locale.conf /etc/localtime
BindReadOnlyPaths=/etc/ld.so.cache -/etc/ld.so.conf.d
BindReadOnlyPaths=-/etc/protocols -/etc/services
BindReadOnlyPaths=-/etc/alternatives
BindReadOnlyPaths=-/etc/os-release
BindReadOnlyPaths=-/etc/gitconfig
PrivateTmp=yes
UMask=0077

# Device access. PrivateDevices=yes constructs a clean /dev;
# DevicePolicy=closed denies everything; DeviceAllow re-adds /dev/kvm
# for KVM-backed workloads.
PrivateDevices=yes
DevicePolicy=closed
DeviceAllow=/dev/kvm rw

ProtectProc=invisible

# Kernel hardening.
ProtectKernelTunables=yes
ProtectKernelModules=yes
ProtectKernelLogs=yes
# ProtectControlGroups=no is INTENTIONAL: workflows create
# cpuset/memory cgroups on the host (buck2 nested virt, VM test
# harnesses). yes here would make /sys/fs/cgroup read-only and break
# those flows. (F33)
ProtectControlGroups=no
ProtectClock=yes
ProtectHostname=yes
LockPersonality=yes

# Syscall filtering. @system-service is the baseline allowlist; pkey_*
# and perf_event_open are extras needed by Node, .NET, and KVM
# workloads.
SystemCallArchitectures=native
SystemCallFilter=@system-service pkey_alloc pkey_mprotect pkey_free perf_event_open
SystemCallErrorNumber=EPERM
SystemCallFilter=~@mount @clock @keyring @module @raw-io @reboot @swap @obsolete
SystemCallLog=~@system-service pkey_alloc pkey_mprotect pkey_free perf_event_open

RestrictNamespaces=yes
PrivateIPC=yes

ProtectHome=yes
RemoveIPC=yes
# RestrictRealtime=no is INTENTIONAL: KVM vCPU/watchdog threads need
# SCHED_FIFO for stable guest latency. LimitRTPRIO=2 caps the
# priority they can request. (F33)
RestrictRealtime=no
RestrictSUIDSGID=yes

# LimitMEMLOCK=infinity required for KVM/buck2 mlock on large guest
# pages.
LimitMEMLOCK=infinity
LimitRTPRIO=2

LogRateLimitIntervalSec=30s
LogRateLimitBurst=10000

Restart=always
RestartSec=10

[Install]
WantedBy=multi-user.target
";

// --- ghars-net@.service template (Part 9c) -------------------------------

/// Canonical `ghars-net@.service` template body (oneshot, persistent
/// netns, fail-closed via `NetworkNamespacePath=` on the runner side).
#[must_use]
pub fn netns_template_text() -> String {
    NETNS_TEMPLATE.to_string()
}

const NETNS_TEMPLATE: &str = r#"[Unit]
Description=ghars netns + veth + nft for runner %i
X-Ghars-Managed=true
X-Ghars-Schema-Version=1
# F79: StopWhenUnneeded=NO. The named netns at /var/run/netns/ghars-%i
# is bind-mounted (persistent across unit deactivation). ghars-net@
# stays in active state to symbolize "netns exists"; only torn down by
# explicit `ghars apply` removal of the runner. Runner restarts do NOT
# recreate the netns — the bind-mount survives.
StopWhenUnneeded=no
After=network.target

[Service]
Type=oneshot
RemainAfterExit=yes

# `+` prefix runs as root regardless of User= (per systemd.exec.xml).
# Required for: ip netns add, ip link, sysctl writes, nft -f.
ExecStart=+/usr/bin/ghars _netns-setup %i
ExecStart=+/usr/sbin/nft -f /etc/ghars/nft.d/%i-host.nft
ExecStart=+/usr/bin/ghars _netns-veth %i /usr/sbin/nft -f /etc/ghars/nft.d/%i-ns.nft

# LOAD-BEARING: ExecStop= MUST be present. systemd's
# service.c:1364-1383 destroys runtime data on SERVICE_EXITED when no
# ExecStop=, ExecReload=, or ExecStopPost= is defined — even with
# RemainAfterExit=yes. The named netns is its own bind-mount so we
# don't rely on systemd's runtime data, but having ExecStop= ensures
# cleanup helpers run on unit deactivation. (F49)
ExecStop=+/usr/sbin/nft destroy table inet ghars_%i
ExecStop=+/usr/bin/ghars _netns-veth %i /usr/sbin/nft destroy table inet ghars_%i_ns
ExecStop=+/usr/bin/ghars _netns-teardown %i

User=root
Slice=system.slice
KillMode=control-group
TimeoutSec=30s

[Install]
# Pulled in by runner units' Requires=; never enabled standalone.
"#;

// --- ghars-cache@.service template (Part 9b) -----------------------------

/// Canonical `ghars-cache@.service` template body. Per-pool drop-ins
/// (rendered separately via `render_cache_drop_in`) provide
/// `ExecStart=` + cache-specific `Environment=` entries.
#[must_use]
pub fn cache_template_text() -> String {
    CACHE_TEMPLATE.to_string()
}

const CACHE_TEMPLATE: &str = r"[Unit]
Description=ghars cache service for pool %i (ccache + sccache)
After=network.target
X-Ghars-Managed=true
X-Ghars-Schema-Version=1
# StopWhenUnneeded keeps the unit alive only when at least one runner
# unit Requires= it (per-runner 30-cache-pool.conf adds Requires=).
StopWhenUnneeded=yes

[Service]
Type=simple
# `Group=` is INTENTIONALLY omitted from the template — the per-pool
# 00-ghars.conf drop-in sets `Group=ghars-cache-<pool>` so each pool's
# UDS at `/run/ghars/cache-<pool>.sock` is owned by a per-pool group.
# Runners join only the `ghars-cache-<pool>` groups they're allowed to
# reach (apply.rs::execute_create_runner adds membership), so a
# compromised runner cannot connect to ANOTHER pool's UDS even if it
# can resolve the path. Hardcoding `Group=gha` here would defeat the
# per-pool ACL because every cache server would run with the same
# primary group, and the UDS would be world-reachable for every
# `gha`-group runner. (#200 / SEC-04 mitigation step 1.)
#
# `User=gha` stays in the template — every cache service runs as the
# same uid so the cache directory's contents have a single owner; the
# DAC boundary between pools is the `Group=` membership set by the
# drop-in plus the UDS file mode (0660) the cache server writes.
User=gha
Slice=system.slice

# UMask=0007 is the kernel-enforced sccache UDS permission gate.
# AF_UNIX bind() masks the socket inode mode by current_umask() at
# vfs_mknod time (Linux net/unix/af_unix.c:unix_bind_bsd:1349 —
# `umode_t mode = S_IFSOCK | (SOCK_INODE(sk->sk_socket)->i_mode & ~current_umask())`).
# sccache's UnixListener::bind (sccache server.rs:511 +
# commands.rs:104) performs no chmod after bind, so the kernel-applied
# mode is final. With UMask=0007, the resulting UDS inode mode is
# 0660 — owner=User= rw, group=Group= rw, others denied. Combined
# with the per-pool drop-in's `Group=ghars-cache-<pool>` (the cache
# server's primary gid is inherited by mknod), this gives the
# UDS owner=gha:ghars-cache-<pool> mode=0660. Runners that joined the
# `ghars-cache-<pool>` supplementary group (via apply.rs::execute_create_runner)
# can connect; non-members get EACCES. UMask= closes the mode at
# bind() time atomically — unlike a chmod-after-bind shim, there is
# no TOCTOU window between bind() returning and the chmod landing
# during which a same-group attacker could connect. (#199 SEC-04
# step 2.)
UMask=0007

# CacheDirectory creates /var/cache/ghars/pools/%i with mode 0755
# (group-traversable; runners run as the same User=gha and connect
# via UDS or share files within the pool dir).
CacheDirectory=ghars/pools/%i
CacheDirectoryMode=0755
RuntimeDirectory=ghars
RuntimeDirectoryMode=0755

# Per-kinds env + ExecStart land in the per-pool 00-ghars.conf drop-in
# (sccache server launches there when kinds includes sccache;
# ccache-only pools render ExecStart=/usr/bin/sleep infinity to keep
# the unit active so its CacheDirectory stays mounted).

KillMode=control-group
KillSignal=SIGTERM
TimeoutStopSec=30s

# Hardening — narrower than runner. No /dev/kvm, no realtime, no exec.
NoNewPrivileges=yes
CapabilityBoundingSet=
AmbientCapabilities=
PrivateDevices=yes
PrivateTmp=yes
ProtectKernelTunables=yes
ProtectKernelModules=yes
ProtectKernelLogs=yes
ProtectClock=yes
ProtectHostname=yes
ProtectControlGroups=yes
LockPersonality=yes
RestrictNamespaces=yes
RestrictRealtime=yes
RestrictSUIDSGID=yes
ProtectHome=yes
ProtectSystem=strict
RemoveIPC=yes
RestrictAddressFamilies=AF_UNIX
SystemCallArchitectures=native
SystemCallFilter=@system-service
SystemCallErrorNumber=EPERM
SystemCallFilter=~@mount @clock @keyring @module @raw-io @reboot @swap @obsolete

# Restart on crash (sccache server crashes are recoverable; clients
# reconnect).
Restart=on-failure
RestartSec=2

[Install]
WantedBy=multi-user.target
";

// --- Runner unit + drop-ins renderer (Part 9 / 9d / 9e) ------------------

/// Render the canonical runner unit template + all applicable
/// drop-ins for an effective runner spec.
///
/// Drop-ins emitted (ranges per Part 9 / F30):
/// - `00-ghars.conf` — identity annotations (always)
/// - `10-memory.conf` — `MemoryMax=` (when set)
/// - `15-resolv.conf` — `/etc/resolv.conf` bind source (always; switches
///   between host's resolv.conf and the netns-private file in
///   `/run/ghars/netns-resolv/<name>` based on the runner's network mode)
/// - `20-hardening.conf` — per-field hardening overrides
/// - `30-cache-pool.conf` — ccache/sccache pool bindings (when caches non-empty)
/// - `40-network.conf` — netns binding (Netns mode only)
/// - `50-numa.conf` — `AllowedCPUs=` / `AllowedMemoryNodes=` (when set)
/// - `60-proxy.conf` — proxy env + CA-trust env (when proxy resolved)
/// - `70-hooks.conf` — pre/post-job hook env + `BindReadOnlyPaths` (when hooks resolved)
/// - `80-lognamespace.conf` — `LogNamespace=ghars-NAME` (always; F78 confirmed)
///
/// # Errors
///
/// Returns `GharsError::Validation` when:
/// - `render_identity` (via [`check_identity_field`]) finds a `\n`,
///   `\r`, `\0`, or other control character in any interpolated
///   X-Ghars-* field — defense-in-depth against unit-text injection
///   (#286). The error message names the offending field and the
///   character class.
/// - The F48 reset-on-empty validator finds any generated drop-in
///   body about to emit a list-typed directive with a bare `=`.
///   Such an output is a generator bug; the validator is a safety
///   net.
pub fn render_runner_unit(spec: &EffectiveRunnerSpec) -> Result<RenderedUnit> {
    let mut drop_ins: BTreeMap<String, String> = BTreeMap::new();
    let mut warnings: Vec<String> = Vec::new();

    drop_ins.insert("00-ghars.conf".into(), render_identity(spec)?);

    if let Some(body) = render_memory(spec)? {
        drop_ins.insert("10-memory.conf".into(), body);
    }

    // 15-resolv.conf — always present. Binds /etc/resolv.conf into the
    // runner's mount namespace from the right source for the runner's
    // network mode. Open mode binds the host's /etc/resolv.conf; Netns
    // mode binds /run/ghars/netns-resolv/<name> (written by
    // `_netns-setup` from the operator's DnsMode). The template's
    // BindReadOnlyPaths intentionally OMITS /etc/resolv.conf because
    // systemd's mount-list dedup keeps the FIRST same-destination entry
    // (per src/core/namespace.c:drop_duplicates), so a drop-in cannot
    // override the template's source. Splitting it out into its own
    // drop-in is the only correct way to swap sources per runner.
    drop_ins.insert("15-resolv.conf".into(), render_resolv_bind(spec));

    if let Some(body) = render_hardening(spec, &mut warnings)? {
        drop_ins.insert("20-hardening.conf".into(), body);
    }

    if let Some(body) = render_cache_pool(spec)? {
        drop_ins.insert("30-cache-pool.conf".into(), body);
    }

    if let Some(body) = render_network(spec)? {
        drop_ins.insert("40-network.conf".into(), body);
    }

    if let Some(body) = render_numa(spec)? {
        drop_ins.insert("50-numa.conf".into(), body);
    }

    if let Some(body) = render_proxy(spec)? {
        drop_ins.insert("60-proxy.conf".into(), body);
    }

    if let Some(body) = render_hooks(spec)? {
        drop_ins.insert("70-hooks.conf".into(), body);
    }

    drop_ins.insert("80-lognamespace.conf".into(), render_lognamespace(spec));

    // F48 reset-on-empty validator — applied to EVERY generated drop-in.
    for (name, body) in &drop_ins {
        validate_drop_in(name, body)?;
    }

    Ok(RenderedUnit {
        template: runner_template_text(),
        drop_ins,
        warnings,
    })
}

/// Defense-in-depth (#286): reject any value about to be interpolated
/// into a `00-ghars.conf` line that contains characters which would
/// break out of the `Key=Value` boundary or corrupt the systemd unit
/// parser. `\n` / `\r` would inject a new directive line; `\0` is a
/// shell / parser hazard; other control chars produce undefined
/// behavior in the X-Ghars-* annotation parser at
/// `state::extract_x_ghars`.
///
/// Called from three sites, none privileged:
/// - `render_identity` (this file) — the LAST gate before bytes hit
///   disk during plan render. Wraps the result with `render_identity:`
///   so the message in stderr names the rejecting function (#286).
/// - `cli::validate_identity_fields` — config-load gate so the
///   operator sees the offending block name (`runner "NAME"` /
///   `cache_pool "NAME"`) before the planner runs (#344/#346).
/// - `plan::plan_from` — defense-in-depth on the synthesized
///   `config_source` value (#345/#346).
///
/// The error message itself is bare (no caller-site prefix). The
/// render_identity caller (this file, just below) wraps with
/// `"render_identity:"` so plan-time render errors name the
/// rejecting function. The cli.rs caller wraps with the offending
/// block name (`runner "NAME":` / `cache_pool "NAME":`); the
/// plan.rs caller propagates the bare error (config_source is
/// composed from paths.config_dir, no operator-meaningful scope to
/// prepend). Hardcoding `"render_identity:"` here would mislead
/// operators when the rejection actually fires at config-load time
/// (#380).
pub(crate) fn check_identity_field(field: &str, value: &str) -> Result<()> {
    if let Some(bad) = value
        .chars()
        .find(|c| *c == '\n' || *c == '\r' || *c == '\0' || c.is_control())
    {
        let class = if bad == '\n' {
            "newline"
        } else if bad == '\r' {
            "carriage return"
        } else if bad == '\0' {
            "NUL byte"
        } else {
            "control character"
        };
        return Err(GharsError::Validation(
            format!(
                "field {field:?} contains forbidden {class}; \
                 X-Ghars-* annotations must be single-line, control-free"
            ),
            "fix the offending value upstream (likely a config edit added \
             a stray newline or terminal escape)"
                .into(),
        ));
    }
    Ok(())
}

fn render_identity(spec: &EffectiveRunnerSpec) -> Result<String> {
    // Validate every interpolated field BEFORE writing — fail-fast
    // before the bytes touch the BTreeMap so an upstream caller's
    // re-render yields the same error each time and never produces
    // a partially-written buffer.
    //
    // `check` wraps `check_identity_field` so the resulting Validation
    // error names "render_identity" as the rejecting site (#286).
    // `cli::validate_identity_fields` adds its own block-scoped
    // prepend (`runner "NAME":` / `cache_pool "NAME":`); `plan::plan_from`
    // propagates the bare error. By emitting the bare form from
    // `check_identity_field` itself, stderr only says "render_identity"
    // when the rejection actually fires here at plan-render time
    // (#380).
    let check = |field: &str, value: &str| -> Result<()> {
        check_identity_field(field, value)
            .map_err(|e| crate::error::prepend_validation_scope("render_identity", e))
    };
    check("spec_hash", &spec.spec_hash)?;
    check("name", &spec.name)?;
    check("url", &spec.url)?;
    check("auth_name", &spec.auth_name)?;
    for label in &spec.labels {
        check("labels[]", label)?;
    }
    check("user", &spec.user)?;
    check("prefix", spec.prefix.as_str())?;
    for binding in &spec.caches {
        check("caches[].name", &binding.name)?;
    }
    check("config_source", &spec.config_source)?;
    if let Some(v) = spec.runner_version.as_deref() {
        check("runner_version", v)?;
    }
    if let Some(sha) = spec.runner_sha256.as_deref() {
        check("runner_sha256", sha)?;
    }
    // runner_tarball is hashed (sha256 of the path string) before
    // emission, so the rendered value cannot contain control chars.
    // The path string itself never appears in the unit. No check
    // needed here.
    check("trust_zone", &spec.trust_zone)?;
    if !spec.runsvc_sha256.is_empty() {
        check("runsvc_sha256", &spec.runsvc_sha256)?;
    }

    let mut s = String::new();
    s.push_str("[Unit]\n");
    let _ = writeln!(s, "X-Ghars-Spec-Hash={}", spec.spec_hash);
    let _ = writeln!(s, "X-Ghars-Runner-Name={}", spec.name);
    let _ = writeln!(s, "X-Ghars-Runner-Url={}", spec.url);
    let _ = writeln!(s, "X-Ghars-Auth-Name={}", spec.auth_name);
    // BATCH C / #11 + #12: emit Labels and Arch as annotations so the
    // plan engine can reconstruct the recreate-bound subset of an
    // already-applied EffectiveRunnerSpec from the on-disk unit text.
    // Without these, a labels-only or arch-only edit fell through to
    // the conservative `spec_hash_mismatch` recreate fallback, even
    // though both fields are knowable at config-load time. Comma-
    // joined labels mirrors the existing X-Ghars-Caches format.
    //
    // Labels arrive pre-sorted by `merge_defaults` (set semantics —
    // GitHub matches workflow `runs-on:` against the registered label
    // set order-independently). The defensive sort here mirrors the
    // caches comment below: any future caller that builds an
    // `EffectiveRunnerSpec` directly bypasses `merge_defaults`'s
    // sort, so re-sorting at the emission site keeps the on-disk
    // `X-Ghars-Labels=` annotation canonical regardless. Without
    // this, an unsorted-Vec direct-construct caller would emit a
    // non-canonical annotation and the plan classifier's sorted
    // comparison would silently mask the divergence.
    let mut label_names: Vec<&str> = spec.labels.iter().map(String::as_str).collect();
    label_names.sort_unstable();
    let _ = writeln!(s, "X-Ghars-Labels={}", label_names.join(","));
    let arch_str = match spec.arch {
        crate::config::Arch::X86_64 => "x86_64",
        crate::config::Arch::Aarch64 => "aarch64",
    };
    let _ = writeln!(s, "X-Ghars-Arch={arch_str}");
    // BATCH C / #11 + #12: emit User and Prefix so the plan engine can
    // surface the operator's intent on update-runner (e.g. show a
    // "user: gha → ghars-buckos" line in the diff). Both are
    // identity-bound (changing either forces a recreate) but having
    // the before-value lets the renderer say what changed instead of
    // emitting an opaque "spec_hash_mismatch" reason.
    let _ = writeln!(s, "X-Ghars-User={}", spec.user);
    let _ = writeln!(s, "X-Ghars-Prefix={}", spec.prefix);
    // emit X-Ghars-Caches unconditionally (matches the X-Ghars-Labels
    // pattern at render_identity above) so the planner can detect
    // caches-list shrinks. Without an unconditional emit, a runner
    // whose caches list goes from `["a"]` → `[]` would have no
    // on-disk record of the prior membership, so the in-place path
    // could not compute a set diff to drive
    // `users.remove_user_from_group`. Empty value is parsed as
    // `Some(vec![])` by the classifier (see DiscoveredAnnotations
    // labels handling).
    //
    // caches arrive pre-sorted by lower_to_effective. The defensive
    // sort here mirrors the labels emission above: any future caller
    // that builds an `EffectiveRunnerSpec` directly bypasses
    // `lower_to_effective`'s sort, so re-sorting at the emission site
    // keeps the on-disk `X-Ghars-Caches=` annotation canonical
    // regardless. Without this, an unsorted-Vec direct-construct
    // caller would emit a non-canonical annotation and the plan
    // classifier's sorted comparison would silently mask the
    // divergence.
    let mut cache_names: Vec<&str> = spec.caches.iter().map(|c| c.name.as_str()).collect();
    cache_names.sort_unstable();
    let _ = writeln!(s, "X-Ghars-Caches={}", cache_names.join(","));
    let _ = writeln!(s, "X-Ghars-Config-Source={}", spec.config_source);
    let _ = writeln!(
        s,
        "X-Ghars-Effective-Version={}",
        spec.runner_version.as_deref().unwrap_or("")
    );
    // #296: runner_sha256 is operator-supplied SHA256 of the runner
    // tarball — recreate-class. Emitted only when set so a missing
    // line means "operator did not pin a digest" (resolves through
    // the releases API). An empty `=` would conflate "operator
    // explicitly cleared the pin" with "field never set" at parse
    // time. Emit nothing when None; the classifier treats absence as
    // "skip this field" not "differs from empty".
    if let Some(sha) = spec.runner_sha256.as_deref()
        && !sha.is_empty()
    {
        let _ = writeln!(s, "X-Ghars-Runner-Sha256={sha}");
    }
    // #296: runner_tarball is an operator-supplied local path to a
    // pre-downloaded tarball. The PATH itself leaks operator
    // environment (mount points, usernames, kernel-private dirs) so
    // we emit a SHA256 of the path string instead. The hash is
    // sufficient for change detection — a change to the tarball
    // path produces a new hash, even though the operator's path is
    // never persisted in the on-disk artifact. No emission when
    // None (same rationale as runner_sha256 above).
    if let Some(tarball) = spec.runner_tarball.as_deref() {
        use sha2::{Digest, Sha256};
        let mut h = Sha256::new();
        h.update(tarball.as_str().as_bytes());
        let _ = writeln!(
            s,
            "X-Ghars-Runner-Tarball-Hash=sha256:{}",
            hex::encode(h.finalize())
        );
    }
    // #290: trust_zone is in EffectiveRunnerSpec spec_hash but has
    // no runner-unit body dependency once cache-pool cross-references
    // validate. Annotated so the classifier can detect an isolated
    // trust_zone change as in-place (FieldChange but no recreate
    // reason — see plan.rs::classify_recreate_reasons_from_annotations).
    let _ = writeln!(s, "X-Ghars-Trust-Zone={}", spec.trust_zone);
    // #308 / #311: network mode (open|netns). Recreate-class — see
    // classifier. Emitted unconditionally; "open" is the canonical
    // string for "no [network] block referenced or NetworkMode::Open".
    let net_mode = match spec.network.as_ref().map(|n| &n.spec.mode) {
        Some(crate::config::NetworkMode::Netns) => "netns",
        Some(crate::config::NetworkMode::Open) | None => "open",
    };
    let _ = writeln!(s, "X-Ghars-Network-Mode={net_mode}");
    if let Some(net) = &spec.network {
        let _ = writeln!(s, "X-Ghars-Netns-Subnet={}", net.subnet);
    }
    // X-Ghars-Runsvc-Sha256 lives in [Service] per Part 17's
    // authoritative annotation table. Emitted only when populated;
    // before the install phase records the digest the field is empty
    // and we omit the line so the wrapper's own
    // "annotation missing" error path stays the single signal that
    // apply hasn't completed yet (rather than a confusing
    // "annotation present but empty" half-state). The wrapper reads
    // this key out of /etc/systemd/system/ghars-runner@INSTANCE
    // .service.d/00-ghars.conf, since systemd's conf-parser silently
    // drops X-* keys (`shared/conf-parser.c:160`) and never exposes
    // them as D-Bus properties.
    if !spec.runsvc_sha256.is_empty() {
        s.push('\n');
        s.push_str("[Service]\n");
        let _ = writeln!(s, "X-Ghars-Runsvc-Sha256={}", spec.runsvc_sha256);
    }
    Ok(s)
}

fn render_memory(spec: &EffectiveRunnerSpec) -> Result<Option<String>> {
    let Some(m) = spec.memory_max.as_deref() else {
        return Ok(None);
    };
    if m.is_empty() {
        return Ok(None);
    }
    // Defense-in-depth (#348): `memory_max` is an operator-supplied free-
    // form String (config.rs `EffectiveRunnerSpec.memory_max:
    // Option<String>`) interpolated directly into `MemoryMax=`. A
    // newline would inject a new directive line; NUL/control chars would
    // corrupt the systemd unit parser the same way the
    // `check_identity_field` gate already prevents in `render_identity`.
    check_identity_field("memory_max", m)?;
    let mut s = String::new();
    s.push_str("[Service]\n");
    let _ = writeln!(s, "MemoryMax={m}");
    Ok(Some(s))
}

fn render_hardening(
    spec: &EffectiveRunnerSpec,
    warnings: &mut Vec<String>,
) -> Result<Option<String>> {
    let h = &spec.hardening;
    let profile = HardeningProfile::from(h);

    // Defense-in-depth (#348): every operator-supplied string about to
    // be interpolated into a 20-hardening.conf body must clear
    // check_identity_field BEFORE any bytes are written. The
    // hardening profile lets the operator append entries to systemd
    // list-typed directives (RestrictAddressFamilies, SystemCallFilter
    // → extra_syscalls, CapabilityBoundingSet → extra_capabilities,
    // BindReadOnlyPaths → bind_readonly_paths + extra_bind_paths); a
    // newline anywhere in those values would inject a new directive
    // line at unit-load time. Validating at the top of the renderer
    // means a malformed entry produces an Err instead of bytes.
    for entry in &h.restrict_address_families {
        check_identity_field("restrict_address_families[]", entry)?;
    }
    for entry in &h.extra_syscalls {
        check_identity_field("extra_syscalls[]", entry)?;
    }
    for entry in &h.extra_capabilities {
        check_identity_field("extra_capabilities[]", entry)?;
    }
    if let Some(paths) = &h.bind_readonly_paths {
        for p in paths {
            check_identity_field("bind_readonly_paths[]", p.as_str())?;
        }
    }
    for p in &h.extra_bind_paths {
        check_identity_field("extra_bind_paths[]", p.as_str())?;
    }

    // Determine if any directive needs to be emitted. The template
    // already contains the canonical defaults; we only emit a drop-in
    // when at least one overridable field is touched OR the operator
    // bumped extra_syscalls / extra_capabilities / extra_bind_paths /
    // bind_readonly_paths / restrict_address_families.
    let touches_scalar = h.kvm.is_some()
        || h.restrict_realtime.is_some()
        || h.protect_control_groups.is_some()
        || h.restrict_suid_sgid.is_some()
        || h.private_devices.is_some()
        || h.private_ipc.is_some();
    let has_lists = !h.restrict_address_families.is_empty()
        || !h.extra_syscalls.is_empty()
        || !h.extra_capabilities.is_empty()
        || !h.extra_bind_paths.is_empty()
        || h.bind_readonly_paths.is_some();
    let has_etc_override = h.etc_bind_style != EtcBindStyle::default();
    if !touches_scalar && !has_lists && !has_etc_override {
        return Ok(None);
    }

    let mut s = String::new();
    s.push_str("[Service]\n");

    if h.kvm.is_some() {
        // The runner template grants `DeviceAllow=/dev/kvm rw`. systemd
        // treats `DeviceAllow` as list-typed and the only way to revoke
        // a template-level grant from a drop-in is the empty-reset
        // pattern (a drop-in cannot subtract a specific entry). When
        // the operator opts out of KVM via `hardening.kvm = false` we
        // emit `DeviceAllow=` and follow it with no further entries —
        // the resulting set is empty, combined with the template's
        // `DevicePolicy=closed` this denies all device access.
        //
        // The F48 reset-on-empty validator treats `DeviceAllow`
        // INTENTIONALLY as not-protected (see RESET_ON_EMPTY_DIRECTIVES
        // doc-comment) precisely so this branch can land. The other
        // directives in that list have multi-entry templates where an
        // empty reset would silently disable hardening; `DeviceAllow`
        // has a single template entry and revoking it is the operator's
        // documented intent.
        if profile.kvm {
            s.push_str("DeviceAllow=/dev/kvm rw\n");
        } else {
            s.push_str("DeviceAllow=\n");
            warnings.push(format!(
                "runner {name}: hardening.kvm=false drops DeviceAllow=/dev/kvm rw; \
                workflows that need KVM access (nested virtualization, KVM-based \
                test harnesses) will fail",
                name = spec.name
            ));
        }
    }
    if h.restrict_realtime.is_some() {
        let _ = writeln!(s, "RestrictRealtime={}", yes_no(profile.restrict_realtime));
    }
    if h.protect_control_groups.is_some() {
        let _ = writeln!(
            s,
            "ProtectControlGroups={}",
            yes_no(profile.protect_control_groups)
        );
    }
    if h.restrict_suid_sgid.is_some() {
        let _ = writeln!(s, "RestrictSUIDSGID={}", yes_no(profile.restrict_suid_sgid));
    }
    if h.private_devices.is_some() {
        let _ = writeln!(s, "PrivateDevices={}", yes_no(profile.private_devices));
    }
    if h.private_ipc.is_some() {
        let _ = writeln!(s, "PrivateIPC={}", yes_no(profile.private_ipc));
    }

    if !h.restrict_address_families.is_empty() {
        let _ = writeln!(
            s,
            "RestrictAddressFamilies={}",
            h.restrict_address_families.join(" ")
        );
    }

    if !h.extra_syscalls.is_empty() {
        // Append-style — systemd treats consecutive SystemCallFilter=
        // lines as union, so adding new tokens through a drop-in
        // grows the allowlist instead of replacing it.
        let _ = writeln!(s, "SystemCallFilter={}", h.extra_syscalls.join(" "));
    }

    if !h.extra_capabilities.is_empty() {
        // Same union semantics for CapabilityBoundingSet=. The runner
        // template grants CAP_SETUID + CAP_SETGID (the runsvc.sh
        // privilege-drop set, line 887); appending caps here UNIONS
        // with that base — the operator's tokens are added, not
        // substituted. Operators who want to revoke the base set must
        // use a 99-*.conf operator drop-in with the empty-reset form
        // (`CapabilityBoundingSet=` followed by the desired set), which
        // the F48 validator does NOT police.
        //
        // Canonicalization is upstream: this renderer emits whatever
        // is in `h.extra_capabilities` verbatim, including duplicates
        // and operator-supplied order. `plan::merge_hardening` is
        // responsible for sorting AND deduping the merged Vec before
        // the renderer sees it (#384) so a pure reorder or accidental
        // dup in TOML does not perturb the rendered drop-in body or
        // the spec_hash. The same upstream contract applies to
        // `extra_syscalls` (SystemCallFilter= line above) and
        // `restrict_address_families` (RestrictAddressFamilies=).
        let _ = writeln!(
            s,
            "CapabilityBoundingSet={}",
            h.extra_capabilities.join(" ")
        );
    }

    // BindReadOnlyPaths handling per Part 3 (R4). systemd.exec(5)
    // documents BindReadOnlyPaths as a list-typed directive: each
    // assignment APPENDS to the cumulative list, and only the
    // empty-reset form (`BindReadOnlyPaths=`) clears it. Both
    // bind_readonly_paths and extra_bind_paths therefore APPEND to the
    // template's accumulated list — neither replaces it. The F48
    // validator (RESET_ON_EMPTY_DIRECTIVES at systemd.rs:649-660)
    // forbids a managed drop-in from emitting the bare-`=` reset
    // form, so this generator only ever appends. Operators who want
    // to *narrow* the bind-readonly set must use a 99-*.conf
    // operator drop-in (which the F48 validator does NOT police).
    if let Some(paths) = &h.bind_readonly_paths {
        if !paths.is_empty() {
            // Emit the operator's chosen entries on one
            // BindReadOnlyPaths= line. Multiple assignments would
            // also append; one line is the deterministic form. The
            // generator's branch above filters out the empty case,
            // so the F48 reset-on-empty rule is never violated here.
            let joined = paths
                .iter()
                .map(|p| p.as_str())
                .collect::<Vec<_>>()
                .join(" ");
            let _ = writeln!(s, "BindReadOnlyPaths={joined}");
        }
    }
    if !h.extra_bind_paths.is_empty() {
        let joined = h
            .extra_bind_paths
            .iter()
            .map(|p| p.as_str())
            .collect::<Vec<_>>()
            .join(" ");
        let _ = writeln!(s, "BindReadOnlyPaths={joined}");
    }

    if h.etc_bind_style == EtcBindStyle::Broad {
        // Broad: bind whole /etc. Append; the template's curated /etc
        // entries remain (BindReadOnlyPaths is list-typed; appending
        // /etc widens coverage without resetting).
        s.push_str("BindReadOnlyPaths=/etc\n");
    }

    Ok(Some(s))
}

fn render_cache_pool(spec: &EffectiveRunnerSpec) -> Result<Option<String>> {
    if spec.caches.is_empty() {
        return Ok(None);
    }
    // Defense-in-depth (#348): `binding.size` is an operator-supplied
    // free-form String (config.rs `EffectiveCacheBinding.size: String`)
    // interpolated into `Environment=CCACHE_MAXSIZE=` and
    // `Environment=SCCACHE_CACHE_SIZE=` lines. A newline would terminate
    // the env value and inject another directive. `binding.name` is
    // already validated by `validate_cache_pool_name` at config load, so
    // it does not need a separate gate here.
    for c in &spec.caches {
        check_identity_field("caches[].size", &c.size)?;
    }
    let mut s = String::new();
    s.push_str("[Unit]\n");
    for c in &spec.caches {
        let _ = writeln!(s, "Requires=ghars-cache@{}.service", c.name);
        let _ = writeln!(s, "After=ghars-cache@{}.service", c.name);
    }
    s.push('\n');
    s.push_str("[Service]\n");
    let mut bind_paths: Vec<String> = Vec::new();
    let mut needs_run_ghars = false;
    for c in &spec.caches {
        let pool_dir = format!("/var/cache/ghars/pools/{}", c.name);
        if c.kinds.contains(&CacheKind::Ccache) {
            let _ = writeln!(s, "Environment=CCACHE_DIR={pool_dir}/ccache");
            // Pool-size override; the template defaults to 200G but the
            // pool's configured size wins.
            let _ = writeln!(s, "Environment=CCACHE_MAXSIZE={}", c.size);
            bind_paths.push(pool_dir.clone());
        }
        if c.kinds.contains(&CacheKind::Sccache) {
            let _ = writeln!(
                s,
                "Environment=SCCACHE_SERVER_UDS=/run/ghars/cache-{}.sock",
                c.name
            );
            // Pool-side server is the sole owner; runners are clients.
            // SCCACHE_NO_DAEMON=1 prevents auto-spawn (#32).
            s.push_str("Environment=SCCACHE_NO_DAEMON=1\n");
            let _ = writeln!(s, "Environment=SCCACHE_CACHE_SIZE={}", c.size);
            needs_run_ghars = true;
            // Pool dir is also bound so sccache disk reads succeed even
            // when the runner needs to inspect cache shape locally.
            if !bind_paths.contains(&pool_dir) {
                bind_paths.push(pool_dir);
            }
        }
    }
    if needs_run_ghars {
        bind_paths.push("/run/ghars".into());
    }
    if !bind_paths.is_empty() {
        // BindPaths is list-typed; emitting a non-empty value APPENDS
        // to the template's set (the template has no BindPaths line —
        // it relies on TemporaryFileSystem=/:ro + selective rebinds).
        // F48 validator passes because we only get here with at least
        // one entry.
        let _ = writeln!(s, "BindPaths={}", bind_paths.join(" "));
    }
    Ok(Some(s))
}

/// `15-resolv.conf` — always emitted. Binds /etc/resolv.conf in the
/// runner's mount namespace from the source appropriate for the
/// runner's network mode:
/// - Open / no-network: host's `/etc/resolv.conf` (same path → same
///   path; runner inherits the host resolver).
/// - Netns: `/run/ghars/netns-resolv/<name>` (written by
///   `ghars _netns-setup` from the operator's `DnsMode`).
///
/// Always-emitted so the template can omit the path entirely; see
/// `render_runner_unit` for why the override-via-drop-in pattern fails
/// (systemd's mount-list dedup keeps the FIRST entry per destination).
fn render_resolv_bind(spec: &EffectiveRunnerSpec) -> String {
    let mut s = String::new();
    s.push_str("[Service]\n");
    let netns_mode = matches!(
        spec.network.as_ref().map(|n| &n.spec.mode),
        Some(NetworkMode::Netns),
    );
    if netns_mode {
        // The netns helper writes the source file at unit start; if
        // the file is missing the bind fails — fail-closed. No `-`
        // prefix.
        let _ = writeln!(
            s,
            "BindReadOnlyPaths=/run/ghars/netns-resolv/{}:/etc/resolv.conf",
            spec.name
        );
    } else {
        s.push_str("BindReadOnlyPaths=/etc/resolv.conf\n");
    }
    s
}

fn render_network(spec: &EffectiveRunnerSpec) -> Result<Option<String>> {
    let Some(net) = spec.network.as_ref() else {
        return Ok(None);
    };
    if !matches!(net.spec.mode, NetworkMode::Netns) {
        return Ok(None);
    }
    // Defense-in-depth (#348): `address_families[]` is the only operator-
    // supplied free-form String surface in this renderer's body. It is
    // joined with `" "` and emitted on a `RestrictAddressFamilies=` line,
    // so a newline anywhere in an entry would inject a new directive.
    // `ip_allow` / `ip_deny` are typed (`Vec<IpNet>`) so they cannot
    // carry control chars; `spec.name` is gated by `validate_runner_name`
    // upstream.
    for entry in &net.spec.address_families {
        check_identity_field("network.address_families[]", entry)?;
    }
    let mut s = String::new();
    s.push_str("[Unit]\n");
    let _ = writeln!(s, "Requires=ghars-net@{}.service", spec.name);
    let _ = writeln!(s, "BindsTo=ghars-net@{}.service", spec.name);
    let _ = writeln!(s, "After=ghars-net@{}.service", spec.name);
    s.push('\n');
    s.push_str("[Service]\n");

    // F79 fail-closed: NetworkNamespacePath= refuses to start when the
    // bind-mount path is missing or unjoinable (exec-invoke.c:4760-4761).
    let _ = writeln!(s, "NetworkNamespacePath=/var/run/netns/ghars-{}", spec.name);

    // Defense in depth at the cgroup-BPF layer.
    for cidr in &net.spec.ip_allow {
        let _ = writeln!(s, "IPAddressAllow={cidr}");
    }
    for cidr in &net.spec.ip_deny {
        let _ = writeln!(s, "IPAddressDeny={cidr}");
    }
    if !net.spec.address_families.is_empty() {
        let _ = writeln!(
            s,
            "RestrictAddressFamilies={}",
            net.spec.address_families.join(" ")
        );
    }

    Ok(Some(s))
}

fn render_numa(spec: &EffectiveRunnerSpec) -> Result<Option<String>> {
    let cpus = spec.allowed_cpus.as_deref();
    let mems = spec.allowed_memory_nodes.as_deref();
    if cpus.is_none() && mems.is_none() {
        return Ok(None);
    }
    // Defense-in-depth (#348): both fields are operator-supplied
    // strings interpolated into AllowedCPUs= / AllowedMemoryNodes=.
    // A newline anywhere would inject a new directive line.
    if let Some(c) = cpus {
        check_identity_field("allowed_cpus", c)?;
    }
    if let Some(m) = mems {
        check_identity_field("allowed_memory_nodes", m)?;
    }
    let mut s = String::new();
    s.push_str("[Service]\n");
    if let Some(c) = cpus {
        let _ = writeln!(s, "AllowedCPUs={c}");
    }
    if let Some(m) = mems {
        let _ = writeln!(s, "AllowedMemoryNodes={m}");
    }
    Ok(Some(s))
}

fn render_proxy(spec: &EffectiveRunnerSpec) -> Result<Option<String>> {
    let Some(proxy) = spec.proxy.as_ref() else {
        return Ok(None);
    };
    if proxy.http.is_none()
        && proxy.https.is_none()
        && proxy.no_proxy.is_empty()
        && proxy.ca_certs.is_empty()
    {
        return Ok(None);
    }
    // Defense-in-depth (#348): every operator-supplied string about to
    // be interpolated into a 60-proxy.conf body must clear
    // check_identity_field BEFORE bytes are written. The proxy fields
    // appear in `Environment=...` directives — a newline would
    // terminate the env var and inject a new directive (or, for
    // path bindings below, escape into BindReadOnlyPaths).
    if let Some(http) = &proxy.http {
        check_identity_field("proxy.http", http)?;
    }
    if let Some(https) = &proxy.https {
        check_identity_field("proxy.https", https)?;
    }
    for entry in &proxy.no_proxy {
        check_identity_field("proxy.no_proxy[]", entry)?;
    }
    for binding in &proxy.ca_certs {
        check_identity_field("proxy.ca_certs[].env", &binding.env)?;
        check_identity_field("proxy.ca_certs[].path", binding.path.as_str())?;
    }
    let mut s = String::new();
    s.push_str("[Service]\n");
    if let Some(http) = &proxy.http {
        // Both upper- and lower-case env vars so apps that read either
        // find a value (R2 / #38).
        let _ = writeln!(s, "Environment=HTTP_PROXY={http}");
        let _ = writeln!(s, "Environment=http_proxy={http}");
    }
    if let Some(https) = &proxy.https {
        let _ = writeln!(s, "Environment=HTTPS_PROXY={https}");
        let _ = writeln!(s, "Environment=https_proxy={https}");
    }
    if !proxy.no_proxy.is_empty() {
        let joined = proxy.no_proxy.join(",");
        let _ = writeln!(s, "Environment=NO_PROXY={joined}");
        let _ = writeln!(s, "Environment=no_proxy={joined}");
    }
    let mut bind_paths: Vec<String> = Vec::new();
    for binding in &proxy.ca_certs {
        let _ = writeln!(s, "Environment={}={}", binding.env, binding.path);
        // No `-` prefix: a missing CA cert must FAIL the unit, not silently
        // tolerate absence. Tolerating absence here lets the runner connect
        // through the proxy with the system trust store as a fallback —
        // that's MITM if the proxy is untrusted (SEC-08 / B2 review #173).
        bind_paths.push(binding.path.to_string());
    }
    if !bind_paths.is_empty() {
        let _ = writeln!(s, "BindReadOnlyPaths={}", bind_paths.join(" "));
    }
    Ok(Some(s))
}

fn render_hooks(spec: &EffectiveRunnerSpec) -> Result<Option<String>> {
    let Some(h) = spec.hooks.as_ref() else {
        return Ok(None);
    };
    if h.pre_job.is_none() && h.post_job.is_none() {
        return Ok(None);
    }
    // Defense-in-depth (#348): `pre_job` / `post_job` are operator-supplied
    // host paths (config.rs `HooksSpec` fields are `Option<Utf8PathBuf>`)
    // interpolated into `Environment=ACTIONS_RUNNER_HOOK_JOB_*` and
    // `BindReadOnlyPaths=` lines. A newline embedded in the Utf8 path
    // string (Utf8PathBuf is a UTF-8 wrapper, not a control-char filter)
    // would split the env value or escape into a separate
    // BindReadOnlyPaths directive. Validate both bytes-on-disk surfaces
    // before any are written.
    if let Some(p) = &h.pre_job {
        check_identity_field("hooks.pre_job", p.as_str())?;
    }
    if let Some(p) = &h.post_job {
        check_identity_field("hooks.post_job", p.as_str())?;
    }
    let mut s = String::new();
    s.push_str("[Service]\n");
    if let Some(p) = &h.pre_job {
        let _ = writeln!(s, "Environment=ACTIONS_RUNNER_HOOK_JOB_STARTED={p}");
    }
    if let Some(p) = &h.post_job {
        let _ = writeln!(s, "Environment=ACTIONS_RUNNER_HOOK_JOB_COMPLETED={p}");
    }
    // Bind the parent directory of each hook script (deduped if pre and
    // post share the parent). Hook scripts must be reachable through
    // the runner's mount namespace.
    let mut parents: Vec<String> = Vec::new();
    for p in [&h.pre_job, &h.post_job].into_iter().flatten() {
        if let Some(parent) = p.parent() {
            let parent_str = parent.to_string();
            if !parent_str.is_empty() && !parents.contains(&parent_str) {
                parents.push(parent_str);
            }
        }
    }
    if !parents.is_empty() {
        let _ = writeln!(s, "BindReadOnlyPaths={}", parents.join(" "));
    }
    Ok(Some(s))
}

fn render_lognamespace(spec: &EffectiveRunnerSpec) -> String {
    // F78 confirmed: unconditional. systemd 254+ floor enforced at
    // preflight.
    let mut s = String::new();
    s.push_str("[Service]\n");
    let _ = writeln!(s, "LogNamespace=ghars-{}", spec.name);
    s
}

// --- Cache service drop-in (Part 9b) ------------------------------------

/// Render the per-pool drop-in `00-ghars.conf` for
/// `ghars-cache@NAME.service`. Shape varies by `kinds` (ccache only,
/// sccache only, both).
///
/// # Errors
///
/// Returns `GharsError::Validation` from the F48 reset-on-empty
/// validator.
// Pedantic clippy flags ccache/sccache local bindings as confusable;
// the variant names are load-bearing (they ARE the schema's
// CacheKind values) and renaming would obscure the mapping.
#[allow(clippy::similar_names)]
pub fn render_cache_drop_in(
    binding: &EffectiveCacheBinding,
    config_source: &str,
    spec_hash: &str,
) -> Result<String> {
    // Defense-in-depth (#348): three operator/composer-supplied
    // strings interpolate into this drop-in body —
    //   * `binding.size` (operator-supplied, free-form String) →
    //     `Environment=SCCACHE_CACHE_SIZE=` / `Environment=CCACHE_MAXSIZE=`
    //   * `config_source` (composed at plan time from
    //     `paths.config_dir`; already gated by `plan_from`'s
    //     identity-field check, but a future caller that bypasses
    //     `plan_from` would still skip it without this gate) →
    //     `X-Ghars-Config-Source=`
    //   * `spec_hash` (deterministically derived from canonicalized
    //     config; in production cannot contain control chars but the
    //     gate is cheap defense-in-depth in case a future hash format
    //     adds free-form metadata) → `X-Ghars-Spec-Hash=`
    // `binding.name` is gated upstream by `validate_cache_pool_name`
    // (USER_RE charset only) at config load. `binding.kinds` is a
    // typed enum so it cannot carry control chars.
    check_identity_field("caches[].size", &binding.size)?;
    check_identity_field("config_source", config_source)?;
    check_identity_field("spec_hash", spec_hash)?;
    let serves_ccache = binding.kinds.contains(&CacheKind::Ccache);
    let serves_sccache = binding.kinds.contains(&CacheKind::Sccache);

    let mut s = String::new();
    s.push_str("[Unit]\n");
    let _ = writeln!(s, "X-Ghars-Spec-Hash={spec_hash}");
    let _ = writeln!(s, "X-Ghars-Pool-Name={}", binding.name);
    let kinds_csv = binding
        .kinds
        .iter()
        .map(|k| match k {
            CacheKind::Ccache => "ccache",
            CacheKind::Sccache => "sccache",
        })
        .collect::<Vec<_>>()
        .join(",");
    let _ = writeln!(s, "X-Ghars-Pool-Kinds={kinds_csv}");
    let _ = writeln!(s, "X-Ghars-Config-Source={config_source}");
    s.push('\n');

    s.push_str("[Service]\n");
    // #200 / SEC-04: per-pool group. The cache template intentionally
    // does NOT set `Group=`; the drop-in stamps it here so each pool's
    // sccache UDS belongs to the `ghars-cache-<pool>` primary group.
    // Runners join only the groups they reference in `caches = [...]`
    // (apply.rs::execute_create_runner adds membership), so a runner
    // that doesn't list `pool` in its caches array cannot connect to
    // `pool`'s UDS at all — even if it can name the path. Without this
    // line the cache server would run with `Group=gha` (the user's
    // default group via `User=gha`), and the UDS would be world-
    // reachable for every gha-group runner.
    let _ = writeln!(s, "Group={}", cache_pool_group(&binding.name));
    if serves_sccache {
        let _ = writeln!(
            s,
            "Environment=SCCACHE_DIR=%C/ghars/pools/{}/sccache",
            binding.name
        );
        let _ = writeln!(s, "Environment=SCCACHE_CACHE_SIZE={}", binding.size);
        let _ = writeln!(
            s,
            "Environment=SCCACHE_SERVER_UDS=%t/ghars/cache-{}.sock",
            binding.name
        );
        s.push_str("Environment=SCCACHE_NO_DAEMON=1\n");
        // SCCACHE_IDLE_TIMEOUT=0 prevents the server from exiting
        // mid-shift. Mismatch between server idle timeout and runner
        // restart cycles would force re-init of the on-disk cache (F33
        // / #33).
        s.push_str("Environment=SCCACHE_IDLE_TIMEOUT=0\n");
    }
    if serves_ccache {
        let _ = writeln!(
            s,
            "Environment=CCACHE_DIR=%C/ghars/pools/{}/ccache",
            binding.name
        );
        let _ = writeln!(s, "Environment=CCACHE_MAXSIZE={}", binding.size);
    }

    if serves_sccache {
        s.push_str("ExecStart=/usr/bin/sccache --start-server\n");
        // #199 mode enforcement is in the cache template via UMask=0007,
        // not a per-pool ExecStartPost. Kernel-enforced at vfs_mknod
        // time (Linux net/unix/af_unix.c:unix_bind_bsd:1349) so there
        // is no TOCTOU window between bind() and a chmod shim. See the
        // UMask= comment in cache_template_text() for the full
        // mechanism + citations.
        let _ = writeln!(s, "ReadWritePaths=%C/ghars/pools/{} %t/ghars", binding.name);
    } else {
        // ccache-only pool — the unit exists to own the CacheDirectory
        // and act as a Requires= anchor (StopWhenUnneeded handles
        // lifecycle). sleep infinity is the simplest way to keep
        // Type=simple alive without consuming resources.
        s.push_str("ExecStart=/usr/bin/sleep infinity\n");
        let _ = writeln!(s, "ReadWritePaths=%C/ghars/pools/{}", binding.name);
    }

    validate_drop_in(&format!("ghars-cache@{}/00-ghars.conf", binding.name), &s)?;
    Ok(s)
}

// --- nft rule generator (Part 9c) ----------------------------------------

/// Pair of nft rule files for one Netns runner. Generated from the
/// resolved network binding (`allowed_egress` + `ip_allow` + `ip_deny`
/// + the allocated /30 subnet).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct NftRules {
    /// Host-side rules. Loaded by `ghars-net@%i.service`'s `nft -f
    /// /etc/ghars/nft.d/%i-host.nft` `ExecStart` line. Filters traffic
    /// arriving on the runner's veth, before forwarding.
    pub host_rules: String,
    /// Inside-namespace rules. Loaded inside the runner's netns via
    /// `ghars _netns-veth %i nft -f /etc/ghars/nft.d/%i-ns.nft`.
    /// Defense in depth: drops misbehaving outbound traffic before it
    /// reaches the veth.
    pub ns_rules: String,
}

/// Render the host-side + ns-side nft rule files for one runner.
///
/// `runner_name` is the systemd instance name (e.g. `"buckos"`). The
/// table names follow the `ghars_RUNNER` (host) and `ghars_RUNNER_ns`
/// (inside) convention used by the `ghars-net@.service` `ExecStop=`.
///
/// **Caller invariant (SEC-35):** `runner_name` MUST already match
/// `crate::config::IDENTIFIER_REGEX` (`^[a-z]([a-z0-9-]*[a-z0-9])?$`,
/// ≤ 64 chars). The full `IDENTIFIER_REGEX` charset (`a-z 0-9 -`) is a
/// subset of nft's identifier alphabet for table/chain names and
/// interface-glob patterns, so a runner name that passes
/// `validators::validate_runner_name` interpolates safely into every
/// `ghars_RUNNER`, `ghars-RUNNER-h`, `ghars-RUNNER-r`, `ghars-RUNNER-*`,
/// and log-prefix string this generator emits. We re-validate at the
/// entry of this function as a defense-in-depth check; an invalid
/// runner name reaching this point is a programming error elsewhere
/// (config loader / count expander), but we'd rather refuse than emit
/// a malformed nft file that risks injecting attacker-controlled
/// nft syntax.
///
/// The generator masquerades `subnet` only — per Challenge 7
/// scoping. Comments inside `EgressRule`s must already have passed
/// `crate::validators::validate_egress_comment` (which rejects any
/// character outside `[A-Za-z0-9 _.,:/+-]`) before reaching the
/// generator; the renderer interpolates them verbatim and an
/// `assert!` (live in release) panics on programming errors that
/// bypass the validator (SEC-30).
///
/// # Errors
///
/// Returns `GharsError::Validation` if `runner_name` fails the
/// identifier regex (SEC-35 defense-in-depth gate). Other future
/// validation hooks (CIDR ranges, port-range sanity beyond the
/// config-time validator) hang off this same Result.
pub fn render_nft_rules(runner_name: &str, binding: &EffectiveNetworkBinding) -> Result<NftRules> {
    crate::validators::validate_runner_name(runner_name).map_err(|e| match e {
        GharsError::Validation(msg, _) => GharsError::Validation(
            format!("nft rule generator refused runner name: {msg}"),
            "runner names must match ^[a-z]([a-z0-9-]*[a-z0-9])?$ (SEC-35)".into(),
        ),
        other => other,
    })?;
    // #432 defense-in-depth: this generator emits `iifname
    // "ghars-{runner_name}-h"` and `oifname "ghars-{runner_name}-h"`
    // matchers that the kernel will refuse if the rendered interface
    // name exceeds IFNAMSIZ - 1. `cli::validate_netns_runner_name_lengths`
    // (load_config validator #9) gates this at config-load, but
    // direct callers of `render_nft_rules` (snapshot tests,
    // hypothetical future code paths) bypass that gate. Re-check the
    // cap alongside the existing IDENTIFIER_REGEX gate so a programming
    // error here surfaces a structured Validation instead of leaking
    // an oversize string into the generated nft file.
    if runner_name.len() > crate::validators::NETNS_RUNNER_NAME_MAX_LEN {
        return Err(GharsError::Validation(
            format!(
                "nft rule generator refused runner name: {runner_name:?} is {got} chars; \
                 derived veth 'ghars-{runner_name}-h' would exceed kernel IFNAMSIZ ({ifn})",
                got = runner_name.len(),
                ifn = crate::validators::IFNAMSIZ,
            ),
            format!(
                "shorten the runner name to <={} chars or switch to network mode 'open'",
                crate::validators::NETNS_RUNNER_NAME_MAX_LEN,
            ),
        ));
    }
    let host = render_nft_host(runner_name, binding);
    let ns = render_nft_ns(runner_name, binding);
    Ok(NftRules {
        host_rules: host,
        ns_rules: ns,
    })
}

fn render_nft_host(runner_name: &str, binding: &EffectiveNetworkBinding) -> String {
    let mut s = String::new();
    let _ = writeln!(s, "# generated by ghars apply — DO NOT EDIT");
    let _ = writeln!(
        s,
        "# runner={runner_name} netns=ghars-{runner_name} veth=ghars-{runner_name}-h"
    );
    let _ = writeln!(s, "# subnet={}", binding.subnet);
    s.push('\n');

    let _ = writeln!(s, "table inet ghars_{runner_name} {{");
    s.push_str("    chain output_filter {\n");
    s.push_str("        ct state established,related accept\n");
    // ICMP frag-needed: Part 9c Challenge 5 — never drop. PMTU
    // discovery requires this.
    s.push_str(
        "        meta l4proto icmp icmp type destination-unreachable icmp code frag-needed accept\n",
    );
    for rule in &binding.spec.allowed_egress {
        for (proto_token, _) in proto_tokens(rule.proto) {
            for line in
                egress_rule_lines(&rule.addr, &rule.port, proto_token, rule.comment.as_deref())
            {
                let _ = writeln!(s, "        {line}");
            }
        }
    }
    let _ = writeln!(
        s,
        "        log prefix \"ghars-{runner_name} drop: \" level info"
    );
    s.push_str("        drop\n");
    s.push_str("    }\n");

    s.push_str("    chain forward {\n");
    s.push_str("        type filter hook forward priority filter\n");
    let _ = writeln!(
        s,
        "        iifname \"ghars-{runner_name}-h\" jump output_filter"
    );
    // MSS clamping for TCP — Part 9c Challenge 5. Both directions on
    // the veth.
    let _ = writeln!(
        s,
        "        oifname \"ghars-{runner_name}-h\" tcp flags syn / syn,rst tcp option maxseg size set rt mtu"
    );
    let _ = writeln!(
        s,
        "        iifname \"ghars-{runner_name}-h\" tcp flags syn / syn,rst tcp option maxseg size set rt mtu"
    );
    s.push_str("    }\n");

    s.push_str("    chain postroute {\n");
    s.push_str("        type nat hook postrouting priority srcnat\n");
    // Per-runner masquerade scope (SEC-07 / Challenge 7). Source is
    // THIS runner's /30 only; if the runner's table is destroyed by
    // ExecStop, the masquerade rule vanishes with it.
    let _ = writeln!(
        s,
        "        ip saddr {} oifname != \"ghars-{runner_name}-*\" masquerade",
        binding.subnet
    );
    s.push_str("    }\n");
    s.push_str("}\n");
    s
}

fn render_nft_ns(runner_name: &str, binding: &EffectiveNetworkBinding) -> String {
    let mut s = String::new();
    let _ = writeln!(s, "# generated by ghars apply — DO NOT EDIT");
    let _ = writeln!(s, "# runner={runner_name} namespace=ghars-{runner_name}");
    s.push('\n');

    let _ = writeln!(s, "table inet ghars_{runner_name}_ns {{");
    s.push_str("    chain output_filter {\n");
    s.push_str("        ct state established,related accept\n");
    s.push_str("        oifname \"lo\" accept\n");
    s.push_str(
        "        meta l4proto icmp icmp type destination-unreachable icmp code frag-needed accept\n",
    );
    for rule in &binding.spec.allowed_egress {
        for (proto_token, _) in proto_tokens(rule.proto) {
            for line in
                egress_rule_lines(&rule.addr, &rule.port, proto_token, rule.comment.as_deref())
            {
                let _ = writeln!(s, "        {line}");
            }
        }
    }
    let _ = writeln!(
        s,
        "        log prefix \"ghars-{runner_name} ns-drop: \" level info"
    );
    s.push_str("        drop\n");
    s.push_str("    }\n");

    s.push_str("    chain output {\n");
    s.push_str("        type filter hook output priority filter\n");
    s.push_str("        jump output_filter\n");
    s.push_str("    }\n");

    s.push_str("    chain input {\n");
    s.push_str("        type filter hook input priority filter\n");
    s.push_str("        ct state established,related accept\n");
    s.push_str("        iifname \"lo\" accept\n");
    let _ = writeln!(s, "        iifname \"ghars-{runner_name}-r\" accept");
    let _ = writeln!(
        s,
        "        log prefix \"ghars-{runner_name} ns-in-drop: \" level info"
    );
    s.push_str("        drop\n");
    s.push_str("    }\n");
    s.push_str("}\n");
    s
}

fn proto_tokens(proto: Proto) -> Vec<(&'static str, &'static str)> {
    // Returns (nft proto token, comment-friendly label) pairs. `Both`
    // expands to two passes so the generator emits one rule per L4
    // protocol — nft has no `proto in {tcp, udp}` shorthand for dport
    // matching that mixes both cleanly.
    match proto {
        Proto::Tcp => vec![("tcp", "tcp")],
        Proto::Udp => vec![("udp", "udp")],
        Proto::Both => vec![("tcp", "tcp"), ("udp", "udp")],
    }
}

fn egress_rule_lines(
    addr: &str,
    port: &PortSpec,
    proto: &'static str,
    comment: Option<&str>,
) -> Vec<String> {
    // EgressRule.addr is parsed by the config-time validator as IpAddr
    // or IpNet; we pass it through verbatim. nft accepts both `ip
    // daddr 1.2.3.4` and `ip daddr 1.2.3.0/24`.
    //
    // SEC-30: comment is interpolated unsanitized between `"` chars.
    // The validator (validate_egress_comment) rejects any character
    // that could break the string literal at config-load time, so the
    // only path here is via inputs that already passed that gate. The
    // assert! below is a defense-in-depth gate against any future
    // call site that constructs an EgressRule programmatically and
    // skips validation: panic-on-violation is preferred over silently
    // emitting a malformed nft rule, and assert! (not debug_assert!)
    // keeps the gate live in release builds where the SEC-30 attack
    // would otherwise hit production.
    if let Some(c) = comment {
        assert!(
            c.chars().all(|ch| ch.is_ascii_alphanumeric()
                || matches!(ch, ' ' | '_' | '.' | ',' | ':' | '/' | '+' | '-')),
            "EgressRule.comment {c:?} contains chars outside [A-Za-z0-9 _.,:/+-]; \
             validate_egress_comment must run before render_nft_rules"
        );
    }
    match port {
        PortSpec::Single(p) => {
            let mut line = format!("ip daddr {addr} {proto} dport {p} accept");
            if let Some(c) = comment {
                let _ = write!(line, " comment \"{c}\"");
            }
            vec![line]
        }
        PortSpec::Set(ports) => {
            // nft `dport { p1, p2, ... }` set syntax.
            let set = ports
                .iter()
                .map(u16::to_string)
                .collect::<Vec<_>>()
                .join(", ");
            let mut line = format!("ip daddr {addr} {proto} dport {{ {set} }} accept");
            if let Some(c) = comment {
                let _ = write!(line, " comment \"{c}\"");
            }
            vec![line]
        }
        PortSpec::Range { start, end } => {
            // nft range syntax: `dport START-END`.
            let mut line = format!("ip daddr {addr} {proto} dport {start}-{end} accept");
            if let Some(c) = comment {
                let _ = write!(line, " comment \"{c}\"");
            }
            vec![line]
        }
    }
}

// --- Test surface --------------------------------------------------------

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used)]
mod tests {
    use super::*;
    use camino::Utf8PathBuf;
    use ipnet::IpNet;

    use crate::config::{
        Arch, CaCertBinding, CacheMode, DnsMode, EgressRule, HooksSpec, Ipv6Mode, NetworkSpec,
        ProxySpec,
    };

    fn minimal_spec() -> EffectiveRunnerSpec {
        EffectiveRunnerSpec {
            name: "buckos".into(),
            url: "https://github.com/example/buckos".into(),
            arch: Arch::X86_64,
            user: "ghars-buckos".into(),
            prefix: Utf8PathBuf::from("/var/lib/ghars"),
            labels: vec!["self-hosted".into(), "linux".into()],
            memory_max: None,
            runner_version: Some("2.334.0".into()),
            runner_sha256: None,
            runner_tarball: None,
            auth_name: "pat".into(),
            caches: vec![],
            trust_zone: "default".into(),
            network: None,
            proxy: None,
            hooks: None,
            hardening: Hardening::default(),
            allowed_cpus: None,
            allowed_memory_nodes: None,
            spec_hash: "sha256:dead".into(),
            runsvc_sha256: String::new(),
            config_source: "/etc/ghars/ghars.toml".into(),
        }
    }

    #[test]
    fn template_starts_with_unit_section() {
        let t = runner_template_text();
        assert!(t.starts_with("[Unit]\n"));
        assert!(t.contains("ConditionPathExists=/var/lib/ghars/%i/runsvc.sh"));
        // SEC-02: `!` prefix (NOT `+`) on the wrapper. `+` would
        // bypass User/Group AND the entire sandbox; `!` keeps the
        // sandbox applied while still letting the wrapper run as root
        // so it can drop privileges itself.
        assert!(t.contains("ExecStart=!/usr/lib/ghars/runsvc-wrapper %i"));
        assert!(!t.contains("ExecStart=+/usr/lib/ghars/runsvc-wrapper"));
        // Capability bounding set must include exactly the caps the
        // wrapper needs to drop privileges. Empty bounding set would
        // make setuid(2) return EPERM (kernel/sys.c:669 requires
        // CAP_SETUID).
        assert!(t.contains("CapabilityBoundingSet=CAP_SETUID CAP_SETGID"));
        assert!(t.contains("Slice=system.slice"));
    }

    #[test]
    fn render_identity_emits_runsvc_sha_in_service_section_when_set() {
        // SEC-02 trampoline reads the X-Ghars-Runsvc-Sha256 annotation
        // from /etc/systemd/system/ghars-runner@INSTANCE.service.d/
        // 00-ghars.conf. The annotation table in Part 17 places it
        // under [Service]; the renderer must emit a [Service] section
        // header before the line so the trampoline's section-aware
        // parser finds it.
        let mut spec = minimal_spec();
        spec.runsvc_sha256 = "sha256:abcdef".into();
        let r = render_runner_unit(&spec).unwrap();
        let id = r.drop_ins.get("00-ghars.conf").unwrap();
        assert!(id.contains("[Service]\nX-Ghars-Runsvc-Sha256=sha256:abcdef"));
        // The [Unit] annotations still come first.
        let service_idx = id.find("[Service]").unwrap();
        let unit_idx = id.find("[Unit]").unwrap();
        assert!(unit_idx < service_idx);
    }

    #[test]
    fn render_identity_omits_runsvc_sha_when_empty() {
        // Pre-install: spec carries the empty string and the renderer
        // must drop the line entirely so the wrapper sees a single
        // failure mode ("annotation missing") rather than the
        // confusing "annotation present but empty" half-state.
        let spec = minimal_spec();
        assert!(spec.runsvc_sha256.is_empty());
        let r = render_runner_unit(&spec).unwrap();
        let id = r.drop_ins.get("00-ghars.conf").unwrap();
        assert!(!id.contains("X-Ghars-Runsvc-Sha256"));
    }

    // ---- #286: render_identity defense-in-depth rejection tests ------
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
    /// `"validation: <msg>\n  hint: <hint>"` (see error.rs:55-58),
    /// so the message segment is everything before `"\n  hint:"`.
    /// Checking only that segment avoids a false positive when the
    /// bad byte is itself `\n` (which the Display formatter always
    /// embeds between message and hint).
    fn assert_render_identity_rejects(
        spec: &EffectiveRunnerSpec,
        field: &str,
        class: &str,
        bad: char,
    ) {
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
    fn render_identity_rejects_control_char_in_user() {
        let mut spec = minimal_spec();
        // \x07 (BEL) is a control character that is not NUL, newline,
        // or carriage return — falls through to the generic class.
        spec.user = "ghars-buckos\x07".into();
        assert_render_identity_rejects(&spec, "user", "control character", '\x07');
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
        });
        assert_render_identity_rejects(&spec, "caches[].name", "newline", '\n');
    }

    /// Positive path: a clean minimal_spec MUST render without error.
    /// Without this pin, a buggy check_identity_field that rejects
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

    /// #271 / #371: empty `caches` MUST emit `X-Ghars-Caches=` with
    /// an empty value, NOT skip the line. The classifier
    /// distinguishes `Some(vec![])` (line present, empty value) from
    /// `None` (line absent) — see DiscoveredAnnotations docstring.
    /// Without an unconditional emit, a runner whose caches list
    /// shrinks from `["pool-a"]` → `[]` would have no on-disk record
    /// of the prior membership, so `apply.rs` could not compute a
    /// supplementary-group set diff to drive `gpasswd -d`.
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
    /// order they arrive in. `merge_defaults` already sorts (plan.rs
    /// line 924); this test pins the defense-in-depth re-sort at the
    /// emission site (line 1334) so a direct EffectiveRunnerSpec
    /// constructor that bypasses `merge_defaults` still produces a
    /// canonical on-disk annotation. A regression dropping the sort
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

    /// #286 propagation: render_runner_unit must surface the
    /// `check_identity_field` error verbatim (it's not swallowed
    /// or wrapped with a layer that obscures the offending field).
    /// The error must still name "render_identity" so an operator
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

    /// #286 fail-fast ordering: when MULTIPLE fields are bad, the
    /// FIRST validated field surfaces — render_identity validates
    /// in order (spec_hash, name, url, auth_name, ...) and the `?`
    /// short-circuits on the first failure. Pin that order: a bad
    /// `url` AND bad `prefix` MUST report `url` (validated earlier),
    /// not `prefix`.
    #[test]
    fn render_identity_validation_runs_before_any_write() {
        let mut spec = minimal_spec();
        spec.url = "https://github.com/example/buckos\nbad".into();
        spec.prefix = camino::Utf8PathBuf::from("/var/lib/ghars\nbad");
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

    // ---- #348: defense-in-depth across render_hardening / render_proxy / render_numa
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

    // ---- #348 (FIX 2): defense-in-depth across the remaining render_*
    // functions that interpolate operator-controllable strings into
    // drop-in bodies. Same pattern as the render_hardening / render_proxy
    // / render_numa tests above: mutate ONE field, call
    // `render_runner_unit` (or `render_cache_drop_in`), assert the error
    // surfaces with the field name + char-class label.

    /// `render_memory`: `memory_max` is an operator-supplied free-form
    /// String interpolated into `MemoryMax=`. A newline would inject a
    /// new directive line. Pinned because the field skipped #286/#348
    /// gates pre-fix.
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

    /// `render_network`: `network.address_families[]` is an operator-
    /// supplied free-form String entry joined with `" "` and emitted on
    /// a `RestrictAddressFamilies=` line. A newline anywhere in an
    /// entry would inject a new directive line.
    #[test]
    fn render_network_rejects_newline_in_address_families_entry() {
        let mut spec = minimal_spec();
        spec.network = Some(EffectiveNetworkBinding {
            name: "buck2-isolated".into(),
            spec: NetworkSpec {
                mode: NetworkMode::Netns,
                allowed_egress: vec![],
                ip_allow: vec![],
                ip_deny: vec![],
                address_families: vec!["AF_UNIX\nINJECTED=1".into()],
                dns: DnsMode::default(),
                ipv6: Ipv6Mode::default(),
            },
            subnet: "10.200.0.0/30".parse::<IpNet>().unwrap(),
        });
        let err = render_runner_unit(&spec).unwrap_err();
        assert!(
            matches!(err, GharsError::Validation(_, _)),
            "expected Validation, got {err:?}"
        );
        let msg = format!("{err}");
        assert!(
            msg.contains("network.address_families[]"),
            "msg must name field: {msg}"
        );
        assert!(msg.contains("newline"), "msg must name class: {msg}");
    }

    /// `render_hooks`: `hooks.pre_job` is an operator-supplied path
    /// (`Utf8PathBuf` is a UTF-8 wrapper, not a control-char filter)
    /// interpolated into `Environment=ACTIONS_RUNNER_HOOK_JOB_STARTED=`
    /// and `BindReadOnlyPaths=` lines. A newline would split the env
    /// value or escape into a separate BindReadOnlyPaths directive.
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

    #[test]
    fn netns_template_has_load_bearing_execstop() {
        // F49: ExecStop= is mandatory on RemainAfterExit=yes oneshot
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
                address_families: vec![],
                dns: DnsMode::default(),
                ipv6: Ipv6Mode::default(),
            },
            subnet: "10.200.0.0/30".parse::<IpNet>().unwrap(),
        });
        let r = render_runner_unit(&spec).unwrap();
        let body = r.drop_ins.get("15-resolv.conf").unwrap();
        assert!(
            body.contains("BindReadOnlyPaths=/run/ghars/netns-resolv/buckos:/etc/resolv.conf",)
        );
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
        // Sanity: no kvm-related lines or warnings when kvm wasn't
        // touched in the override.
        assert!(!h.lines().any(|l| l.starts_with("DeviceAllow")));
        assert!(r.warnings.is_empty());
    }

    #[test]
    fn render_hardening_kvm_true_emits_device_allow() {
        // Explicit kvm=true is an override (the template default agrees,
        // but the operator's intent is recorded). The drop-in re-emits
        // `DeviceAllow=/dev/kvm rw` rather than relying on the template
        // alone; this also exercises the F48 reset-on-empty validator
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
        // The fix for #177: kvm=false must emit `DeviceAllow=` (empty
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
    fn validate_drop_in_now_allows_device_allow_reset() {
        // F48 was loosened for DeviceAllow specifically (see the
        // RESET_ON_EMPTY_DIRECTIVES doc-comment for rationale). Verify
        // the validator does NOT reject a bare `DeviceAllow=` line.
        // Other directives still trigger F48 — the validator's
        // protection on SystemCallFilter, BindReadOnlyPaths, etc. is
        // unchanged (covered by validate_drop_in_rejects_each_directive
        // below).
        let body = "[Service]\nDeviceAllow=\n";
        validate_drop_in("20-hardening.conf", body).unwrap();
    }

    #[test]
    fn render_emits_cache_pool_for_ccache() {
        let mut spec = minimal_spec();
        spec.caches.push(EffectiveCacheBinding {
            name: "build".into(),
            kinds: vec![CacheKind::Ccache],
            size: "200G".into(),
            mode: CacheMode::Shared,
            trust_zone: "default".into(),
        });
        let r = render_runner_unit(&spec).unwrap();
        let c = r.drop_ins.get("30-cache-pool.conf").unwrap();
        assert!(c.contains("Requires=ghars-cache@build.service"));
        assert!(c.contains("Environment=CCACHE_DIR=/var/cache/ghars/pools/build/ccache"));
        assert!(c.contains("Environment=CCACHE_MAXSIZE=200G"));
        assert!(c.contains("BindPaths="));
        assert!(!c.contains("SCCACHE_NO_DAEMON"));
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
            address_families: vec!["AF_UNIX".into(), "AF_INET".into()],
            dns: DnsMode::default(),
            ipv6: Ipv6Mode::default(),
        };
        spec.network = Some(EffectiveNetworkBinding {
            name: "buck2-isolated".into(),
            spec: net_spec,
            subnet: "10.200.0.0/30".parse::<IpNet>().unwrap(),
        });
        let r = render_runner_unit(&spec).unwrap();
        let n = r.drop_ins.get("40-network.conf").unwrap();
        assert!(n.contains("Requires=ghars-net@buckos.service"));
        assert!(n.contains("BindsTo=ghars-net@buckos.service"));
        assert!(n.contains("NetworkNamespacePath=/var/run/netns/ghars-buckos"));
        assert!(n.contains("IPAddressAllow=192.168.2.84/32"));
        assert!(n.contains("IPAddressDeny=0.0.0.0/0"));
        assert!(n.contains("RestrictAddressFamilies=AF_UNIX AF_INET"));
        // Identity drop-in must record the netns subnet.
        let id = r.drop_ins.get("00-ghars.conf").unwrap();
        assert!(id.contains("X-Ghars-Netns-Subnet=10.200.0.0/30"));
    }

    #[test]
    fn render_skips_network_for_open_mode() {
        let mut spec = minimal_spec();
        let net_spec = NetworkSpec {
            mode: NetworkMode::Open,
            allowed_egress: vec![],
            ip_allow: vec![],
            ip_deny: vec![],
            address_families: vec![],
            dns: DnsMode::default(),
            ipv6: Ipv6Mode::default(),
        };
        spec.network = Some(EffectiveNetworkBinding {
            name: "open".into(),
            spec: net_spec,
            subnet: "0.0.0.0/32".parse::<IpNet>().unwrap(),
        });
        let r = render_runner_unit(&spec).unwrap();
        assert!(!r.drop_ins.contains_key("40-network.conf"));
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
        // SEC-08 / #173: no `-` prefix on proxy CA cert paths — missing CA
        // must fail the unit start, not silently fall back to system roots.
        assert!(p.contains("BindReadOnlyPaths=/etc/pki/tls/certs/ca-bundle.crt"));
        assert!(!p.contains("BindReadOnlyPaths=-/etc/pki/tls/certs/ca-bundle.crt"));
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

    // #149: drop-in interaction tests. systemd treats list-typed
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
                address_families: vec!["AF_UNIX".into(), "AF_INET".into()],
                dns: DnsMode::default(),
                ipv6: Ipv6Mode::default(),
            },
            subnet: "10.200.0.0/30".parse::<IpNet>().unwrap(),
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
        assert!(
            h.lines()
                .any(|l| l == "RestrictAddressFamilies=AF_UNIX AF_NETLINK"),
            "hardening drop-in missing RestrictAddressFamilies, got:\n{h}"
        );
        assert!(
            n.lines()
                .any(|l| l == "RestrictAddressFamilies=AF_UNIX AF_INET"),
            "network drop-in missing RestrictAddressFamilies, got:\n{n}"
        );
        // Neither drop-in emits a bare `RestrictAddressFamilies=` reset
        // (that would erase the union per systemd.exec.xml:2912-2920).
        for body in [h, n] {
            assert!(
                !body.lines().any(|l| l.trim() == "RestrictAddressFamilies="),
                "drop-in must not reset the allowlist, got:\n{body}"
            );
        }
    }

    #[test]
    fn restrict_address_families_drop_ins_load_in_numeric_order() {
        // BTreeMap iteration is alphabetic by key, which for the
        // numeric-prefix drop-in basenames (`20-hardening.conf` <
        // `40-network.conf`) is the same as systemd's load order
        // (lower numbers load first per Part 9 / F30). Pin that the
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
                address_families: vec!["AF_INET".into()],
                dns: DnsMode::default(),
                ipv6: Ipv6Mode::default(),
            },
            subnet: "10.200.0.0/30".parse::<IpNet>().unwrap(),
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

        // F48: none of these drop-ins emit a bare BindReadOnlyPaths=
        // reset — that would silently erase the template's curated
        // /etc list and the union of every other contributor.
        for (name, body) in [("hardening", h), ("proxy", p), ("hooks", k)] {
            assert!(
                !body.lines().any(|l| l.trim() == "BindReadOnlyPaths="),
                "{name} drop-in emitted reset BindReadOnlyPaths=, got:\n{body}"
            );
        }
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

        // F48: hardening must not emit a bare SystemCallFilter=
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
    fn validate_drop_in_rejects_empty_systemcallfilter() {
        let body = "[Service]\nSystemCallFilter=\n";
        let err = validate_drop_in("test.conf", body).expect_err("must reject");
        assert!(format!("{err}").contains("SystemCallFilter"));
    }

    #[test]
    fn validate_drop_in_rejects_empty_capabilityboundingset() {
        let body = "[Service]\nCapabilityBoundingSet=  \n";
        assert!(validate_drop_in("x", body).is_err());
    }

    #[test]
    fn validate_drop_in_rejects_each_directive() {
        // F48 covers ALL of these directives — the test exercises every
        // one so a future edit that drops one from the list is caught
        // immediately.
        for d in RESET_ON_EMPTY_DIRECTIVES {
            let body = format!("[Service]\n{d}=\n");
            assert!(
                validate_drop_in("x", &body).is_err(),
                "must reject empty {d}"
            );
        }
    }

    #[test]
    fn validate_drop_in_accepts_non_empty_assignments() {
        let body = "[Service]\nSystemCallFilter=@system-service\nBindReadOnlyPaths=/etc\n";
        validate_drop_in("x", body).unwrap();
    }

    #[test]
    fn validate_drop_in_accepts_template_unrelated_keys() {
        let body = "[Service]\nMemoryMax=110G\nEnvironment=FOO=\n";
        // Environment= with bare Key= IS valid (it unsets an env var);
        // RESET_ON_EMPTY_DIRECTIVES doesn't include Environment.
        validate_drop_in("x", body).unwrap();
    }

    // #185 — multi-line edge cases for the F48 reset-on-empty regex.
    // These pin the regex against systemd.syntax(7) parsing semantics:
    // leading whitespace is ignored, comments are skipped, multi-line
    // bodies must be scanned per-line, and continuation lines (trailing
    // `\`) are NOT empty resets.

    #[test]
    fn validate_drop_in_skips_comment_lines() {
        // `#` and `;` start comment lines per systemd.syntax(7).
        // Even though the body contains the literal text
        // `SystemCallFilter=`, the line begins with `#` (or `;`) so
        // systemd discards the whole line. The validator MUST also
        // skip — false positives here would flag operator-supplied
        // 99-*.conf comments that document directives.
        let hash_comment = "[Service]\n# SystemCallFilter=\n";
        validate_drop_in("ok-hash.conf", hash_comment).unwrap();
        let semi_comment = "[Service]\n; CapabilityBoundingSet=\n";
        validate_drop_in("ok-semi.conf", semi_comment).unwrap();
        // A `#` mid-line is NOT a comment per systemd.syntax — the
        // line `SystemCallFilter= # not-a-comment` parses as setting
        // SystemCallFilter to `# not-a-comment`. Bare `=` with
        // trailing non-whitespace is correctly NOT flagged.
        let inline_hash = "[Service]\nSystemCallFilter= # ignored\n";
        validate_drop_in("inline-hash.conf", inline_hash).unwrap();
    }

    #[test]
    fn validate_drop_in_rejects_indented_bare_assignment() {
        // systemd.syntax(7): "leading whitespace is ignored". A line
        // `    SystemCallFilter=` is parsed by systemd as a reset
        // identical to `SystemCallFilter=` flush left. The regex
        // pattern accommodates `^[ \t]*` so the validator catches
        // BOTH forms.
        let four_spaces = "[Service]\n    SystemCallFilter=\n";
        let err = validate_drop_in("indent.conf", four_spaces).expect_err("indented reset");
        assert!(format!("{err}").contains("SystemCallFilter"));
        let tab = "[Service]\n\tBindReadOnlyPaths=\n";
        let err = validate_drop_in("tab.conf", tab).expect_err("tab-indented reset");
        assert!(format!("{err}").contains("BindReadOnlyPaths"));
        // Mixed leading whitespace.
        let mixed = "[Service]\n \t \tIPAddressAllow=\n";
        let err = validate_drop_in("mixed.conf", mixed).expect_err("mixed-LWS reset");
        assert!(format!("{err}").contains("IPAddressAllow"));
    }

    #[test]
    fn validate_drop_in_accepts_bare_eq_with_trailing_value() {
        // `SystemCallFilter= some content` parses as setting the value
        // to `some content` (with the leading space the systemd
        // tokenizer trims). NOT a reset. The regex's `=[ \t]*$`
        // anchor requires only horizontal whitespace before EOL.
        let with_value = "[Service]\nSystemCallFilter=@system-service\n";
        validate_drop_in("with-value.conf", with_value).unwrap();
        let with_space_value = "[Service]\nBindReadOnlyPaths=  /etc\n";
        validate_drop_in("space-value.conf", with_space_value).unwrap();
        // Quoted empty string is a value, not a reset.
        let quoted_empty = "[Service]\nDeviceAllow=\"\"\n";
        validate_drop_in("quoted-empty.conf", quoted_empty).unwrap();
    }

    #[test]
    fn validate_drop_in_rejects_first_of_multiple_bare_lines() {
        // Multiple resets in one body: the validator only needs to
        // surface ONE failure (Regex::find returns the first match),
        // and the error must name a directive that's actually in the
        // body. Pin both halves so a regression to "find_iter +
        // dedup" doesn't accidentally suppress findings.
        let body = "[Service]\nSystemCallFilter=\nBindReadOnlyPaths=\n";
        let err = validate_drop_in("multi.conf", body).expect_err("first reset matches");
        let msg = format!("{err}");
        assert!(
            msg.contains("SystemCallFilter") || msg.contains("BindReadOnlyPaths"),
            "expected a directive in the error, got: {msg}"
        );
    }

    #[test]
    fn validate_drop_in_handles_continuation_lines_correctly() {
        // systemd supports backslash line continuation per
        // systemd.syntax(7): "if a line ends with a backslash followed
        // by a newline, the line is joined with the next line". A
        // bare `=` followed by `\` is NOT a reset — the actual value
        // arrives on the joined line.
        //
        // The `\` character is NOT in the regex's `[ \t]*` class, so
        // the pattern correctly does NOT match `SystemCallFilter=\`.
        let continued = "[Service]\nSystemCallFilter=\\\n  @system-service\n";
        validate_drop_in("continuation.conf", continued).unwrap();
    }

    #[test]
    fn validate_drop_in_per_line_anchors_dont_cross_lines() {
        // The `(?m)` mode makes `^` / `$` per-line, so a directive
        // line that DOES have a value but is followed by another line
        // starting with `[` (section) or whitespace must not be
        // misinterpreted as a reset. Pin the per-line semantics so a
        // future edit that drops `(?m)` is caught here.
        let body = "[Service]\nSystemCallFilter=@system-service\n[X-Ghars-Notes]\nbar=baz\n";
        validate_drop_in("ok-section.conf", body).unwrap();
        // Multiple legitimate value lines stacked back-to-back — `$`
        // must match BEFORE the newline, not after, so each line is
        // independently checked.
        let body2 = "[Service]\nSystemCallFilter=@system-service\nIPAddressAllow=192.168.0.0/16\n";
        validate_drop_in("ok-multi-value.conf", body2).unwrap();
    }

    #[test]
    fn validate_drop_in_handles_crlf_line_endings() {
        // operators editing 99-*.conf on Windows / via tools that
        // emit CRLF would land `DeviceAllow=\r\n` in the body — `\r`
        // is NOT in `[ \t]*`. The current regex treats `=\r` as
        // "value `\r`", i.e. NOT a reset. Document this edge case so
        // a regression that flips to `\s*` (consuming `\r`) trips
        // here. systemd reads `\r` as a literal byte in the value
        // (per src/basic/extract-word.c: only `\n` / `\0` terminate);
        // so `key=\r\n` on systemd is "key set to `\r`" which is
        // functionally a near-empty list but NOT a true reset.
        // We only emit LF-terminated drop-ins ourselves; this case
        // can only arise from operator-edited 99-*.conf which the
        // validator does not gate.
        let crlf = "[Service]\nDeviceAllow=\r\n";
        // DeviceAllow is in the F48 EXEMPT set anyway (single-entry
        // template), so `validate_drop_in` accepts a bare reset
        // regardless. Use a different protected directive to test
        // the CRLF behavior on the regex itself.
        validate_drop_in("device-crlf.conf", crlf).unwrap();
        let crlf_protected = "[Service]\nSystemCallFilter=\r\n";
        validate_drop_in("syscall-crlf.conf", crlf_protected).unwrap();
    }

    #[test]
    fn validate_drop_in_doesnt_match_substring_directives() {
        // The pattern uses `^[ \t]*(?:DIRECTIVE)=` where DIRECTIVE is
        // the exact directive name. A different directive that ENDS
        // with a protected name (hypothetically `MySystemCallFilter=`)
        // must NOT match — the line-start anchor (modulo leading
        // whitespace) keeps the directive name from drifting into the
        // middle of another identifier. Pin the anchoring semantics
        // even though no real systemd directive currently shares a
        // suffix with our protected set.
        let body = "[Service]\nMySystemCallFilter=\n";
        validate_drop_in("substring.conf", body).unwrap();
    }

    #[test]
    fn validate_drop_in_finds_directive_anywhere_in_body() {
        // The body might be hundreds of lines (full template + many
        // overrides). The regex MUST scan the whole body, not just
        // the first few lines. Plant a reset deep in a body that
        // looks otherwise valid.
        let mut body = String::from("[Service]\n");
        for i in 0..50 {
            body.push_str(&format!("Environment=KEY{i}=value{i}\n"));
        }
        body.push_str("BindReadOnlyPaths=\n");
        body.push_str("MemoryMax=110G\n");
        let err = validate_drop_in("deep.conf", &body).expect_err("must find deep reset");
        assert!(format!("{err}").contains("BindReadOnlyPaths"));
    }

    #[test]
    fn render_cache_drop_in_for_sccache_only() {
        let binding = EffectiveCacheBinding {
            name: "build".into(),
            kinds: vec![CacheKind::Sccache],
            size: "200G".into(),
            mode: CacheMode::Shared,
            trust_zone: "default".into(),
        };
        let body = render_cache_drop_in(&binding, "/etc/ghars/ghars.toml", "sha256:abcd").unwrap();
        assert!(body.contains("X-Ghars-Pool-Kinds=sccache"));
        assert!(body.contains("ExecStart=/usr/bin/sccache --start-server"));
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
        };
        let body = render_cache_drop_in(&binding, "/etc/ghars/ghars.toml", "sha256:abcd").unwrap();
        assert!(body.contains("X-Ghars-Pool-Kinds=ccache"));
        assert!(body.contains("ExecStart=/usr/bin/sleep infinity"));
        assert!(body.contains("CCACHE_DIR=%C/ghars/pools/build/ccache"));
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
        };
        let body = render_cache_drop_in(&binding, "/etc/ghars/ghars.toml", "sha256:abcd").unwrap();
        // Both env sets emit; the sccache server is the ExecStart.
        assert!(body.contains("CCACHE_DIR"));
        assert!(body.contains("SCCACHE_DIR"));
        assert!(body.contains("ExecStart=/usr/bin/sccache --start-server"));
    }

    #[test]
    fn cache_template_sets_umask_0007_for_uds_mode() {
        // #199 (resolved via UMask=0007): the sccache UDS mode is
        // kernel-enforced at vfs_mknod time (Linux
        // net/unix/af_unix.c:unix_bind_bsd:1349 —
        // `umode_t mode = S_IFSOCK | (SOCK_INODE(...)->i_mode & ~current_umask())`).
        // sccache's UnixListener::bind (sccache server.rs:511,
        // commands.rs:104) performs no chmod after bind, so the
        // kernel-applied mode is final. UMask=0007 in the template
        // makes the resulting socket mode 0660 (owner+group rw, others
        // denied) atomically — no TOCTOU window between bind() and a
        // chmod shim. This test pins the template directive so a
        // future cleanup pass can't drop it without surfacing the
        // SEC-04 regression.
        let body = cache_template_text();
        assert!(
            body.contains("\nUMask=0007\n"),
            "cache template must set UMask=0007 for sccache UDS mode 0660; got body:\n{body}"
        );
    }

    #[test]
    fn render_cache_drop_in_relies_on_template_umask_no_exec_start_post_shim() {
        // #199 mode enforcement lives in the cache template (UMask=0007),
        // not the per-pool drop-in. The drop-in must NOT emit a chmod
        // ExecStartPost — that approach was the chmod-after-bind shim
        // ruled out at design time because of the TOCTOU window
        // between bind() returning and chmod() landing during which a
        // same-group attacker could connect. UMask= closes the window
        // at vfs_mknod time. This test pins both pool kinds (sccache
        // and ccache-only) to confirm neither emits ExecStartPost.
        for kinds in [
            vec![CacheKind::Sccache],
            vec![CacheKind::Ccache],
            vec![CacheKind::Sccache, CacheKind::Ccache],
        ] {
            let binding = EffectiveCacheBinding {
                name: "build".into(),
                kinds,
                size: "200G".into(),
                mode: CacheMode::Shared,
                trust_zone: "default".into(),
            };
            let body =
                render_cache_drop_in(&binding, "/etc/ghars/ghars.toml", "sha256:abcd").unwrap();
            assert!(
                !body.contains("ExecStartPost"),
                "cache drop-in must NOT emit ExecStartPost — \
                 #199 is solved at the template level via UMask=0007. \
                 got body:\n{body}"
            );
        }
    }

    fn netns_binding(subnet: &str, allowed: Vec<EgressRule>) -> EffectiveNetworkBinding {
        EffectiveNetworkBinding {
            name: "buck2-isolated".into(),
            spec: NetworkSpec {
                mode: NetworkMode::Netns,
                allowed_egress: allowed,
                ip_allow: vec![],
                ip_deny: vec![],
                address_families: vec![],
                dns: DnsMode::default(),
                ipv6: Ipv6Mode::default(),
            },
            subnet: subnet.parse::<IpNet>().unwrap(),
        }
    }

    #[test]
    fn render_nft_emits_per_runner_table_and_masquerade() {
        let binding = netns_binding(
            "10.200.0.0/30",
            vec![EgressRule {
                addr: "192.168.2.84".into(),
                port: PortSpec::Single(3128),
                proto: Proto::Tcp,
                comment: Some("squid proxy".into()),
            }],
        );
        let rules = render_nft_rules("buckos", &binding).unwrap();
        assert!(rules.host_rules.contains("table inet ghars_buckos"));
        assert!(
            rules
                .host_rules
                .contains("ip daddr 192.168.2.84 tcp dport 3128 accept")
        );
        assert!(rules.host_rules.contains("comment \"squid proxy\""));
        assert!(
            rules
                .host_rules
                .contains("ip saddr 10.200.0.0/30 oifname != \"ghars-buckos-*\" masquerade")
        );
        // Per-runner ns table.
        assert!(rules.ns_rules.contains("table inet ghars_buckos_ns"));
    }

    #[test]
    fn render_nft_includes_icmp_frag_needed_in_both_tables() {
        // Challenge 5: PMTU discovery requires accepting ICMP type 3
        // code 4 in BOTH the host forward path and the netns input.
        let binding = netns_binding("10.200.0.0/30", vec![]);
        let rules = render_nft_rules("buckos", &binding).unwrap();
        assert!(
            rules
                .host_rules
                .contains("icmp type destination-unreachable icmp code frag-needed accept")
        );
        assert!(
            rules
                .ns_rules
                .contains("icmp type destination-unreachable icmp code frag-needed accept")
        );
    }

    #[test]
    fn render_nft_includes_mss_clamp_on_both_directions() {
        let binding = netns_binding("10.200.0.0/30", vec![]);
        let rules = render_nft_rules("buckos", &binding).unwrap();
        assert!(rules.host_rules.contains(
            "oifname \"ghars-buckos-h\" tcp flags syn / syn,rst tcp option maxseg size set rt mtu"
        ));
        assert!(rules.host_rules.contains(
            "iifname \"ghars-buckos-h\" tcp flags syn / syn,rst tcp option maxseg size set rt mtu"
        ));
    }

    #[test]
    fn render_nft_handles_proto_both() {
        let binding = netns_binding(
            "10.200.0.0/30",
            vec![EgressRule {
                addr: "1.2.3.4".into(),
                port: PortSpec::Single(53),
                proto: Proto::Both,
                comment: None,
            }],
        );
        let rules = render_nft_rules("r", &binding).unwrap();
        // Both tcp + udp lines emitted.
        assert!(
            rules
                .host_rules
                .contains("ip daddr 1.2.3.4 tcp dport 53 accept")
        );
        assert!(
            rules
                .host_rules
                .contains("ip daddr 1.2.3.4 udp dport 53 accept")
        );
    }

    #[test]
    fn render_nft_handles_port_set_and_range() {
        let binding = netns_binding(
            "10.200.0.0/30",
            vec![
                EgressRule {
                    addr: "10.0.0.1".into(),
                    port: PortSpec::Set(vec![80, 443]),
                    proto: Proto::Tcp,
                    comment: None,
                },
                EgressRule {
                    addr: "10.0.0.2".into(),
                    port: PortSpec::Range {
                        start: 1024,
                        end: 2048,
                    },
                    proto: Proto::Tcp,
                    comment: None,
                },
            ],
        );
        let rules = render_nft_rules("r", &binding).unwrap();
        assert!(rules.host_rules.contains("dport { 80, 443 }"));
        assert!(rules.host_rules.contains("dport 1024-2048"));
    }

    #[test]
    fn render_nft_passes_safe_comment_unchanged() {
        // SEC-30: validate_egress_comment is the single gate; the
        // renderer interpolates a comment that's already in the safe
        // set verbatim. No `?` substitution, no escaping. Any byte
        // that survives this assertion is a byte that was in the
        // operator's TOML.
        let binding = netns_binding(
            "10.200.0.0/30",
            vec![EgressRule {
                addr: "1.2.3.4".into(),
                port: PortSpec::Single(80),
                proto: Proto::Tcp,
                comment: Some("squid proxy 8.8.8.8/32".into()),
            }],
        );
        let rules = render_nft_rules("r", &binding).unwrap();
        assert!(
            rules
                .host_rules
                .contains("comment \"squid proxy 8.8.8.8/32\""),
            "expected comment to pass through verbatim; got: {}",
            rules.host_rules
        );
    }

    // SEC-35: instance-name escaping in nft commands and helper
    // scripts. The nft generator interpolates `runner_name` directly
    // into table/chain names, interface names, and log-prefix strings;
    // we depend on the IDENTIFIER_REGEX-validated runner name being a
    // safe subset of nft's identifier alphabet. The next four tests
    // pin both halves of that contract.

    #[test]
    fn render_nft_rejects_runner_name_with_uppercase() {
        let binding = netns_binding("10.200.0.0/30", vec![]);
        let err = render_nft_rules("Buckos", &binding).expect_err("must reject");
        assert!(format!("{err}").contains("nft rule generator refused"));
    }

    #[test]
    fn render_nft_rejects_runner_name_with_underscore() {
        // Underscore is allowed in nft identifiers but NOT in
        // IDENTIFIER_REGEX. The generator gates on the regex so an
        // underscore in the runner name is a programming error from
        // the loader (which should have rejected it already); the
        // generator's defense-in-depth check refuses anyway.
        let binding = netns_binding("10.200.0.0/30", vec![]);
        let err = render_nft_rules("buck_os", &binding).expect_err("must reject");
        assert!(format!("{err}").contains("nft rule generator refused"));
    }

    #[test]
    fn render_nft_rejects_runner_name_with_shell_metachar() {
        let binding = netns_binding("10.200.0.0/30", vec![]);
        // Backtick + `;` + space — every common shell metachar must
        // bounce off the IDENTIFIER_REGEX gate.
        for bad in [
            "bad`name",
            "bad;rm -rf /",
            "bad name",
            "bad/name",
            "bad$name",
        ] {
            let err = render_nft_rules(bad, &binding).expect_err(&format!("must reject {bad:?}"));
            assert!(format!("{err}").contains("nft rule generator refused"));
        }
    }

    #[test]
    fn render_nft_accepts_full_identifier_charset() {
        // The full IDENTIFIER_REGEX charset is `^[a-z]([a-z0-9-]*[a-z0-9])?$`.
        // Use a name that exercises all of `[a-z]` + `[0-9]` + `-`
        // while staying within `NETNS_RUNNER_NAME_MAX_LEN` (#432: the
        // generator now enforces the IFNAMSIZ-derived cap as
        // defense-in-depth, so this test feeds a name that fits the
        // tighter netns cap rather than the looser
        // `RUNNER_NAME_MAX_LEN`). 7 chars covers `[a-z]` + `[0-9]` +
        // `-` and exercises all three character classes the regex
        // permits. Mirrors SEC-35's "verify the full regex charset
        // produces valid nft syntax".
        let name = "a1-b2-c";
        let binding = netns_binding(
            "10.200.0.0/30",
            vec![EgressRule {
                addr: "1.2.3.4".into(),
                port: PortSpec::Single(443),
                proto: Proto::Tcp,
                comment: None,
            }],
        );
        let rules = render_nft_rules(name, &binding).unwrap();

        // Table name follows ghars_RUNNER convention with underscores
        // separating ghars and the verbatim runner name. nft accepts
        // `-` and digits inside table identifiers (kernel tablename
        // grammar permits the full a-z 0-9 _ - set).
        assert!(
            rules
                .host_rules
                .contains(&format!("table inet ghars_{name}"))
        );
        assert!(
            rules
                .ns_rules
                .contains(&format!("table inet ghars_{name}_ns"))
        );

        // Interface globs `ghars-RUNNER-h`, `ghars-RUNNER-r`,
        // `ghars-RUNNER-*` are all quoted in the rule output. None of
        // them can contain unbalanced quotes — the runner name doesn't
        // include `"`.
        assert!(rules.host_rules.contains(&format!("\"ghars-{name}-h\"")));
        assert!(rules.host_rules.contains(&format!("\"ghars-{name}-*\"")));
        assert!(rules.ns_rules.contains(&format!("\"ghars-{name}-r\"")));

        // Log-prefix string literals are also balanced and contain the
        // verbatim runner name without escape sequences.
        assert!(
            rules
                .host_rules
                .contains(&format!("\"ghars-{name} drop: \""))
        );
        assert!(
            rules
                .ns_rules
                .contains(&format!("\"ghars-{name} ns-drop: \""))
        );

        // Sanity: every double-quote in the output is paired (no
        // dangling `"`s that would cause nft to swallow following
        // tokens). Counting is sufficient because every rendered
        // string literal closes with a matching `"`.
        let dq_count = rules.host_rules.chars().filter(|&c| c == '"').count();
        assert!(
            dq_count.is_multiple_of(2),
            "host rules have unbalanced quotes"
        );
        let dq_count = rules.ns_rules.chars().filter(|&c| c == '"').count();
        assert!(
            dq_count.is_multiple_of(2),
            "ns rules have unbalanced quotes"
        );
    }

    // --- #147: Service-interface typed accessors --------------------
    //
    // The trait's `get_service_property_*` methods delegate to
    // `get_unit_property*` with a hardcoded `org.freedesktop.systemd1
    // .Service` interface argument. Tests below pin both halves of
    // that contract via a recording mock: (a) the Service interface
    // string is the one the production accessor passes through, and
    // (b) the typed widening done by `get_unit_property_u64` is
    // preserved through the convenience wrapper. A regression that
    // hardcodes the Unit interface (or drops the interface
    // altogether) trips here.

    /// Recording mock that captures every (unit, iface, property)
    /// tuple seen by the trait methods so the test can assert the
    /// Service-interface convenience wrapper forwards the right
    /// interface string. Only u64 / string accessors are exercised;
    /// the object-path accessor is unreachable in this test surface.
    #[derive(Default)]
    struct RecordingSystemd {
        // (unit, iface, property) -> response value (string-typed)
        // for `get_unit_property` and the integer parse for u64.
        responses: std::cell::RefCell<std::collections::HashMap<(String, String, String), String>>,
        // Recorded calls in insertion order.
        calls: std::cell::RefCell<Vec<(String, String, String)>>,
    }

    impl RecordingSystemd {
        fn set(&self, unit: &str, iface: &str, prop: &str, value: &str) {
            self.responses
                .borrow_mut()
                .insert((unit.into(), iface.into(), prop.into()), value.into());
        }
        fn calls(&self) -> Vec<(String, String, String)> {
            self.calls.borrow().clone()
        }
    }

    impl Systemd for RecordingSystemd {
        fn daemon_reload(&self) -> Result<()> {
            Ok(())
        }
        fn start_unit(&self, _: &str) -> Result<()> {
            Ok(())
        }
        fn stop_unit(&self, _: &str) -> Result<()> {
            Ok(())
        }
        fn enable_unit(&self, _: &str) -> Result<()> {
            Ok(())
        }
        fn disable_unit(&self, _: &str) -> Result<()> {
            Ok(())
        }
        fn list_units_filtered(&self, _: &[&str]) -> Result<Vec<UnitListEntry>> {
            Ok(vec![])
        }
        fn get_unit_property(&self, unit: &str, iface: &str, property: &str) -> Result<String> {
            self.calls
                .borrow_mut()
                .push((unit.into(), iface.into(), property.into()));
            self.responses
                .borrow()
                .get(&(unit.into(), iface.into(), property.into()))
                .cloned()
                .ok_or_else(|| {
                    GharsError::Systemd(
                        format!("RecordingSystemd: no value for {unit} {iface} {property}"),
                        "test fixture missing".into(),
                    )
                })
        }
        fn get_unit_property_u64(&self, unit: &str, iface: &str, property: &str) -> Result<u64> {
            let s = self.get_unit_property(unit, iface, property)?;
            s.trim().parse::<u64>().map_err(|e| {
                GharsError::Systemd(
                    format!("RecordingSystemd: {property} on {unit} not u64: {e}"),
                    "test fixture stored a non-numeric string".into(),
                )
            })
        }
        fn get_unit_property_object_path(
            &self,
            _: &str,
            _: &str,
            _: &str,
        ) -> Result<OwnedObjectPath> {
            unreachable!("RecordingSystemd does not exercise object-path properties")
        }
        fn get_service_property_string(&self, unit: &str, property: &str) -> Result<String> {
            self.get_unit_property(unit, SD_SERVICE_IFACE, property)
        }
        fn get_service_property_u64(&self, unit: &str, property: &str) -> Result<u64> {
            self.get_unit_property_u64(unit, SD_SERVICE_IFACE, property)
        }
    }

    #[test]
    fn get_service_property_string_targets_service_interface() {
        // The Service-interface convenience wrapper MUST forward the
        // Service interface string verbatim; a regression that drops
        // the interface (or uses Unit) will cause systemd's
        // Properties.Get to return a different property (or fail) at
        // runtime. Pin the forwarded interface here.
        let s = RecordingSystemd::default();
        s.set(
            "ghars-runner@buckos.service",
            SD_SERVICE_IFACE,
            "Result",
            "success",
        );
        let v = s
            .get_service_property_string("ghars-runner@buckos.service", "Result")
            .unwrap();
        assert_eq!(v, "success");
        let calls = s.calls();
        assert_eq!(calls.len(), 1);
        assert_eq!(calls[0].1, "org.freedesktop.systemd1.Service");
        assert_eq!(calls[0].2, "Result");
    }

    #[test]
    fn get_service_property_u64_targets_service_interface() {
        // MainPID is the canonical Service.u64 property — plumb it
        // through the wrapper and assert the recorded interface is
        // Service. A future "let me just use Unit" regression breaks
        // this assertion immediately.
        let s = RecordingSystemd::default();
        s.set(
            "ghars-runner@buckos.service",
            SD_SERVICE_IFACE,
            "MainPID",
            "12345",
        );
        let pid = s
            .get_service_property_u64("ghars-runner@buckos.service", "MainPID")
            .unwrap();
        assert_eq!(pid, 12345);
        let calls = s.calls();
        assert_eq!(calls.len(), 1);
        assert_eq!(calls[0].1, "org.freedesktop.systemd1.Service");
        assert_eq!(calls[0].2, "MainPID");
    }

    #[test]
    fn get_service_property_string_propagates_missing_property_error() {
        // The wrapper must surface the underlying Properties.Get
        // error verbatim — operators rely on the systemd-level
        // diagnostic to identify mistyped property names.
        let s = RecordingSystemd::default();
        let err = s
            .get_service_property_string("ghars-runner@buckos.service", "NotAProperty")
            .unwrap_err();
        let msg = format!("{err}");
        assert!(msg.contains("NotAProperty"), "{msg}");
        let calls = s.calls();
        assert_eq!(calls[0].1, "org.freedesktop.systemd1.Service");
    }

    #[test]
    fn get_service_property_u64_propagates_typed_error_on_non_numeric() {
        // Non-numeric reply must surface the wire-signature mismatch
        // diagnostic rather than silently returning 0 / unwrapping —
        // that hint is what the operator uses to pick the right
        // accessor (string vs u64) on the next call.
        let s = RecordingSystemd::default();
        s.set(
            "ghars-runner@buckos.service",
            SD_SERVICE_IFACE,
            "Type",
            "simple",
        );
        let err = s
            .get_service_property_u64("ghars-runner@buckos.service", "Type")
            .unwrap_err();
        let msg = format!("{err}");
        assert!(
            msg.contains("not u64") || msg.contains("non-numeric"),
            "{msg}"
        );
    }
}
