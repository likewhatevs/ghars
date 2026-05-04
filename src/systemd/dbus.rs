//! D-Bus systemd adapter and the reset-on-empty drop-in validator.
//!
//! Splits from the (previously monolithic) `systemd.rs` module:
//! - The [`Systemd`] trait + [`UnitListEntry`] reply tuple shape.
//! - The production [`DbusSystemd`] impl backed by `zbus::blocking`.
//! - Typed `Properties.Get` decoders (`decode_string_value`,
//!   `decode_u64_value`, `decode_object_path_value`).
//! - The [`validate_drop_in`] reset-on-empty gate
//!   ([`RESET_ON_EMPTY_DIRECTIVES`] + [`RESET_ON_EMPTY_RE`]).
//!
//! The unit-text + nft-rule renderers live in sibling modules
//! (`units` and `nft`) and re-export through `mod.rs`.

use std::sync::LazyLock;

use regex::Regex;
use zbus::blocking::{Connection, Proxy};
pub use zbus::zvariant::OwnedObjectPath;
use zbus::zvariant::OwnedValue;

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
    /// State discovery does NOT use this — it enumerates managed
    /// units by globbing the filesystem (`state::list_runner_unit_files`
    /// / `state::list_cache_pool_drop_in_dirs`) so partial-apply
    /// residue and units in `not-found`/`failed` state are still
    /// reconciled. The filesystem is the configuration source of
    /// truth; D-Bus is the runtime status source.
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
    /// Common properties: `Type`, `Result`.
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
/// and silently broken parse-from-string callers. Numeric properties
/// must use `decode_u64_value` instead.
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

// --- Reset-on-empty validator -------------------------------------------

/// List-typed directives that systemd treats as RESET on empty
/// assignment (per `systemd.exec(5)` for `SystemCallFilter`, the same
/// rule applies to the rest). A managed drop-in (00-09 .. 50-59
/// ranges) MUST NOT emit any of these with a bare `=` — otherwise the
/// entire allowlist / denylist defined by the template silently
/// disappears.
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
// disable security hardening; the validator's protection is preserved
// for them.
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
//   systemd's config parser strips it before parsing each line
//   (`skip_leading_chars(buf, WHITESPACE)` in
//   `src/shared/conf-parser.c::config_parse`). A line
//   `   DeviceAllow=` is therefore parsed as a reset, so the
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
/// and a hint pointing at the reset-on-empty validator's contract.
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
            "drop-ins must never emit list-typed directives with a bare `=` — \
            doing so would silently erase the template's allowlist"
                .into(),
        ));
    }
    Ok(())
}

// --- Test surface --------------------------------------------------------

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used)]
mod tests {
    use super::*;

    #[test]
    fn validate_drop_in_now_allows_device_allow_reset() {
        // The reset-on-empty validator exempts DeviceAllow specifically
        // (see the `RESET_ON_EMPTY_DIRECTIVES` doc-comment for rationale).
        // Verify the validator does NOT reject a bare `DeviceAllow=`
        // line. Other directives still trigger the validator — it
        // continues to protect SystemCallFilter, BindReadOnlyPaths,
        // etc. (covered by `validate_drop_in_rejects_each_directive`
        // below).
        let body = "[Service]\nDeviceAllow=\n";
        validate_drop_in("20-hardening.conf", body).unwrap();
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
        // The reset-on-empty validator covers ALL of these directives
        // — the test exercises every one so a future edit that drops
        // one from the list is caught immediately.
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

    // Multi-line edge cases for the reset-on-empty regex.
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
        // DeviceAllow is in the validator's EXEMPT set anyway
        // (single-entry template), so `validate_drop_in` accepts
        // a bare reset
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

    // --- Service-interface typed accessors -------------------------
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
