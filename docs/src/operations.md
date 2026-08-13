# Operations

Day-2 operational reference: validate, plan, apply, status, logs,
metrics, upgrades, troubleshooting.

## validate

```sh
sudo ghars validate
sudo ghars validate --deep
```

Parses `--config` (default `/etc/ghars/ghars.toml`), runs the full
validator chain, and exits 0 on success or 6 on a config-class
rejection (`GharsError::Config` for parse failures /
`GharsError::Validation` for shape failures).

`--deep` additionally builds the auth registry
(`build_auth_registry`) and round-trips each `[auth.NAME]` against
GitHub. Without `--deep`, validation is shape-only and never
touches the network.

Use cases:

- **Pre-commit gate.** Run `ghars validate` in CI before merging
  config changes. Exit 6 means "config is broken; do not merge".
- **Pre-apply gate.** Run `ghars validate --deep` before `ghars
  apply` to surface unreachable GitHub auth before the apply loop
  starts touching state.

## plan

```sh
sudo ghars plan
sudo ghars plan --only build-1,ci-3
sudo ghars plan --json
sudo ghars plan --diff
sudo ghars plan --detailed-exitcode
sudo ghars plan --detailed-exitcode-recreate
```

`plan` reads the config, discovers actual state from systemd +
disk, and prints an ordered, terraform-style action list. No
system changes.

Output shape (text mode, no `--diff`):

```text
+ runner build-1 (create) [recreate]
~ runner ci-3 (spec_changed; update: in-place) [restart]
    labels: self-hosted,linux → self-hosted,linux,x64
+ cache_pool build (create) [recreate]
  noop (build-2: in sync) [none]
Plan: 4 actions (1 restart, 2 recreate, 1 none). any_recreate: true
```

Action sigils: `+` create, `-` remove, `~` in-place update, `!`
recreate-class `UpdateRunner` (the surprising case where what
looks like an update tears down + reregisters), space NoOp. The
`[restart]` / `[recreate]` / `[none]` bracket tag is
`Action::disruption().label()` (see
[Architecture](./architecture.md#4-plan-disruption-taxonomy-plandisruption)).
The summary line at the end (`Plan: N actions (R restart, K
recreate, N none). any_recreate: bool`) is emitted by
`render_plan_summary_line`.

Flags:

- `--only NAMES` — comma-separated runner names; substring match.
- `--json` — emit JSON instead of text. Schema is documented in
  the source under `cli::plan_to_json_value` (current
  `schema_version` is 2). Secrets are redacted in BOTH formats.
- `--diff` — show full drop-in body content. Default off because
  drop-in bodies can carry credential-bearing `Environment=`
  lines (see [the diff caveat](#diff-and-credential-leakage)).
- `--detailed-exitcode` — exit 2 when the plan diff is
  non-empty. Without this flag, `plan` always exits 0
  regardless of whether the plan diff is empty.
- `--detailed-exitcode-recreate` — exit 8 when the plan
  contains any recreate-class action. Independent of
  `--detailed-exitcode`. When both are set, recreate (8) trumps
  detailed-changes (2).

`plan` does NOT expose `--refresh-releases` or `--output-dir` —
those were placeholders for v0.2 capabilities; surfacing them
without the underlying behavior would silently no-op. v0.1
queries the release API on-demand and writes generated artifacts
to the host paths in `Paths`.

## apply

```sh
sudo ghars apply
sudo ghars apply --auto-approve
sudo ghars apply --fail-fast
sudo ghars apply --rollback-on-failure
sudo ghars apply --dry-run
sudo ghars apply --only build-1
sudo ghars apply --no-restart
```

`apply` runs the plan again (since state may have moved between
`plan` and `apply` on a busy host), prints it, prompts `y/N`,
and on confirmation dispatches each action through its
`execute_*` handler.

Output during the apply loop is one row per action:

```text
ok: CreateRunner(build-1) [recreate] (created)
ok: UpdateRunner(ci-3) [restart] (in-place: 1 file(s) changed)
fail: CreateRunner(build-2) [recreate] (github: 401 unauthorized)
noop: build-3: in sync [none]
```

The `ok:` rows go to stdout; `fail:` rows go to stderr (so
`ghars apply | grep ok` gives a clean success roll-up). `noop:`
rows go to stdout — note the `NoOp(...)` wrapper is label-stripped,
so the bare reason text appears between `noop:` and the
`[none]` bracket. `[recreate]` / `[restart]` / `[none]` is the
apply-time actual `Disruption` for success/skip outcomes (e.g. an
in-place `UpdateRunner` that short-circuits to byte-equality NoOp
reports `[none]`); for `Failed` rows it falls back to the
plan-time worst-case (apply-time disruption is unknown when the
handler returns Err mid-execution).

Flags:

- `--auto-approve` — skip the y/N prompt.
- `--fail-fast` — stop on first action failure. Without it,
  failures accumulate and apply continues; final exit code
  reflects the worst-case (4 partial, 5 auth, 1 generic).
- `--rollback-on-failure` — best-effort: walk this action's
  recorded `Vec<UndoStep>` in reverse and reverse each step
  (file unlinks, unit stop/disable, GitHub deregister via fresh
  removal token). Per-action scope only; earlier successful
  actions are not touched. Default off; partial state is left
  for the next apply to idempotently complete.
- `--dry-run` — render artifacts but do not write them. The
  lock is still acquired (so concurrent `--dry-run` runs
  serialize) but no D-Bus calls or filesystem writes occur.
  Equivalent to `ghars plan` in semantics; exposed on apply
  so CI scripts can pipe `apply --dry-run --detailed-exitcode`
  into a single command.
- `--only NAMES` — filter actions to a subset of runners.
- `--detailed-exitcode` / `--detailed-exitcode-recreate` —
  same semantics as on `plan`. Fire on `apply --dry-run`,
  pre-confirm, the cancel path, and post-apply when
  `result.failed.is_empty()`.
- `--no-restart` — write all files (drop-ins, .env, .path,
  per-pool 00-ghars.conf) but skip the in-place restart cycle
  (`daemon_reload + stop_unit + start_unit`) for `UpdateRunner`
  and `UpdateCachePool` actions. The running unit keeps its
  pre-rewrite loaded config until the operator explicitly runs
  `systemctl restart ghars-runner@NAME.service` (or
  `ghars-cache@POOL.service` for the cache side). Use for
  maintenance-window deployments where config lands now but the
  disruption is scheduled for off-hours. Recreate-class actions
  (full enumeration: `url` / `runner_version` / `labels` /
  `arch` / `runner_sha256` / `runner_tarball` / `network` for
  runners; `CreateCachePool` + `RemoveCachePool` for pools)
  proceed regardless of this flag — they are structurally
  undeferrable (`CreateRunner` / `RemoveRunner` / `Recreated
  UpdateRunner` / `CreateCachePool` / `RemoveCachePool` all tear
  down or bring up the unit by design). `UpdateCachePool` (pool
  drop-in rewrite from operator edits of `[cache_pools]`
  settings, including `kinds` changes) IS deferred by this flag
  — pool kinds changes flow through `UpdateCachePool` in-place,
  not through recreate. Per-action rows in the apply output
  carry the deferred-restart context in the detail string
  itself (e.g. `ok: UpdateRunner(build-1) [none] (in-place: 1
  file(s) changed, 0 group op(s), restart deferred
  (--no-restart): run `systemctl restart
  ghars-runner@build-1.service` to complete the rollout)`).
  The `[disruption]` bracket tag shows `[none]` because
  apply-time blast-radius is zero — no unit was actually
  touched. A final-line summary tallies the deferred-restart
  count and prints the canonical remediation command. SOC/SRE
  audit-log readers can grep on `outcome: deferred-restart` to
  enumerate affected runners and pools (the
  `ApplyOutcome::audit_summary` token is distinct from
  `"success"` / `"in-sync"`). CAVEAT: re-running `ghars apply`
  WITHOUT `--no-restart` will see byte-matched on-disk files
  (this apply wrote them) and take the byte-equality
  short-circuit at `execute_update_runner` /
  `execute_update_cache_pool` — it does NOT issue the deferred
  restart. Operators MUST run `systemctl restart` to clear
  pending state; re-apply is not a remediation path.
  Verification caveat: `systemctl show ghars-runner@NAME` after
  `--no-restart` reflects the NEW drop-in bytes from disk
  (because the end-of-apply `daemon_reload` refreshed systemd's
  unit-file index), but the running runner process keeps its
  OLD in-memory `ExecContext` until restart. Use `cat
  /proc/$(systemctl show -P MainPID
  ghars-runner@NAME.service)/environ | tr '\0' '\n'` to inspect
  what the running runner actually has.

### Concurrency

`apply` acquires `<runtime_dir>/apply.lock` (default
`/run/ghars/apply.lock`) via `fs4::FileExt::try_lock` (POSIX
advisory exclusive lock through `flock(2)`, non-blocking). The file is mode
0600; the body holds the holder's PID. On contention the call
returns `GharsError::ApplyLocked { pid, path, stale }`; see
[Troubleshooting → "another apply is running"](#another-apply-is-running)
for the `stale` semantics and the manual remediation.

### Audit log

Every action taken (success, failure, no-op, dry-run) appends one
JSON line to `<logs_dir>/apply.log` (default
`/var/log/ghars/apply.log`):

```json
{
  "timestamp": "2026-04-29T12:34:56.789Z",
  "action":    "CreateRunner",
  "target":    "build-1",
  "outcome":   "success"
}
```

Suggested logrotate config (operators install separately — not
bundled in v0.1):

```text
/var/log/ghars/apply.log {
    weekly
    rotate 12
    compress
    missingok
    notifempty
    create 0600 root root
    postrotate
        # No service reload — apply/audit.rs reopens via append-mode each time.
    endscript
}
```

## status

```sh
sudo ghars status
sudo ghars status --json
sudo ghars status --metrics
sudo ghars status --health-only
sudo ghars status --runners-only
sudo ghars status --score
sudo ghars status build-1 ci-3
```

Two sections (plus optional METRICS / SECURITY):

1. **SYSTEM HEALTH** — preflight check rollup.
2. **RUNNERS** — managed-unit table with drift annotations.

Flags:

- `--json` — emit JSON. Schema documented in the source.
- `--metrics` — append a metrics section (per-runner memory /
  CPU / IO / tasks). Conflicts with `--health-only`.
- `--health-only` — skip the RUNNERS section. Conflicts with
  `--runners-only` and `--metrics`.
- `--runners-only` — skip the SYSTEM HEALTH section. Conflicts
  with `--health-only`.
- `--score` — append a SECURITY section listing the
  `systemd-analyze security` exposure score and label
  (`SAFE`, `OK`, `MEDIUM`, `EXPOSED`, `UNSAFE`) for every
  managed `ghars-runner@*` and `ghars-cache@*` unit. Per-unit
  lookup failures (e.g. unit not loaded after a missed
  `daemon-reload`) surface as inline `error: ...` rows so one
  missing unit does not erase the report. Informational only —
  no pass/fail gate. The `just sd-analyze` recipe is a
  convenience wrapper.
- `--github` — query GitHub's runner-list API for each declared
  URL and add a `github` column to the RUNNERS table showing
  each runner's GitHub-side status (`online`, `offline`, or
  `unknown`). Uses the per-runner PAT from `[auth.NAME]`. Helps
  triage the "systemd says active, GitHub says offline" drift
  case before invoking `ghars apply` (which would otherwise
  reconcile silently via the registration-check loop).
- Positional `NAMES` — filter to specific runner names.

### Preflight

The SYSTEM HEALTH section runs the preflight checks defined in
`preflight.rs`:

| check          | what it does                                                              |
|----------------|---------------------------------------------------------------------------|
| `OS`           | parse `/etc/os-release`; accept Ubuntu 24+, Fedora 40+, RHEL/CentOS/Rocky/AlmaLinux 10+ |
| `systemd`      | `Manager.Version` over D-Bus; reject below `MIN_SYSTEMD_VERSION = 254` (`LogNamespace=` requires it) |
| `kvm`          | `/dev/kvm` exists + `kvm` group provisioned on host                      |
| `tools`        | `install`, `chmod`, `chown`, `getent`, `runuser`, `nft`, `ip`, `sysctl`, `systemd-analyze`, `unshare` |
| `kernel`       | cgroup v2 + Seccomp + `CONFIG_NET_NS` (`unshare -n` empirical) + `CAP_NET_ADMIN` (`CapEff` parse) |
| `root`         | apply mode requires uid 0                                                |
| `ptrace_scope` | Yama LSM `kernel.yama.ptrace_scope`; warn at < 2 (SEC-28; advisory)      |

Each check returns `Pass`, `Fail`, `Warn`, or `Skip`. `Fail` blocks
apply (apply exits 3); `Warn` is advisory. The exit-code-3 path
also fires when `cmd_status` rolls up a `Fail`.

## logs

```sh
sudo ghars logs                       # all managed runners
sudo ghars logs build-1               # one runner
sudo ghars logs build-1,ci-3 -n 500
sudo ghars logs build-1 --follow
sudo ghars logs build-1 --since "1 hour ago"
```

Wraps `journalctl -u ghars-runner@NAME.service` for each named
runner. Empty NAMES = all managed runners discovered by
`fs::read_dir` on `<unit_dir>` (the on-disk scan that
`state::discover` performs).

Flags:

- `--follow` / `-f` — pass through to journalctl.
- `-n LINES` / `--lines LINES` — last N entries (default 100).
- `--since SPEC` — systemd journal time spec
  (`"2 hours ago"`, `"yesterday"`, etc.).

`LogNamespace=ghars-NAME` (set by the `80-lognamespace.conf`
drop-in) gives each runner its own journal namespace; cross-runner
log mixing on busy hosts is impossible at the journald layer.

## metrics

```sh
sudo ghars metrics
sudo ghars metrics build-1 ci-3
sudo ghars metrics --json
sudo ghars metrics --no-total
```

Per-runner + total memory / CPU / IO / tasks via systemd D-Bus
property reads (`MemoryCurrent`, `CPUUsageNSec`, `IOReadBytes`,
`IOWriteBytes`, `TasksCurrent`) on the per-unit
`org.freedesktop.systemd1.Service` interface.

Flags:

- `NAMES` — positional, comma-separated. Empty = all managed
  runners.
- `--json` — JSON instead of table.
- `--no-total` — suppress the total row in table output.

`MemoryCurrent = u64::MAX` is systemd's sentinel for "accounting
disabled"; `metrics` passes it through verbatim (callers that
care can compare against `u64::MAX`).

## cleanup

```sh
sudo ghars cleanup
```

Removes all ghars-managed state from the host:

- Stops + disables every managed runner / cache-pool / netns unit.
- Removes unit files (`/etc/systemd/system/ghars-*@*.service`) and
  drop-in directories.
- Removes runner homes (`/var/lib/ghars/`), cache pools
  (`/var/cache/ghars/`), runtime files (`/run/ghars/`), and
  nft / resolved-conf-d artifacts.
- Removes netns bind-mounts under `/var/run/netns/ghars-*`.
- Runs `daemon-reload` so systemd forgets the removed units.

`/etc/ghars/ghars.toml` is left intact — re-running `ghars apply`
reconverges to the declared spec from scratch.

Requires root and an available systemd D-Bus connection. Fails fast
with `GharsError::Systemd` if D-Bus is unreachable rather than
leaving the host half-cleaned.

## Upgrades

With `runner_version` unset (the default), no manual rolling is
needed: every `plan` / `apply` resolves the latest actions/runner
release and recreates any runner installed at an older version.
Run `ghars apply` on whatever cadence you already use; the fleet
follows the release stream. This matters because ghars registers
runners with `--disableupdate` — a fleet that never upgrades
eventually crosses GitHub's runner-version deprecation floor, at
which point every listener exits at startup with "Runner version
vX.Y.Z is deprecated and cannot receive messages", the service
flaps into `start-limit-hit`, and jobs queue forever. Track-latest
turns that cliff into an ordinary recreate.

Rolling a *pinned* runner version:

1. Edit `defaults.runner_version` (or per-runner
   `runner_version`) in `ghars.toml`.
2. Optionally update `runner_sha256`. If unset, ghars resolves
   the digest from the GitHub release at plan time.
3. Run `ghars plan` to confirm the diff. Version changes are
   recreate-class — every affected runner shows
   `[recreate]`.
4. Run `ghars apply`. The recreate path: deregister + stop +
   teardown + extract new tarball + register + start.

Tarball download:

- Streams via `reqwest blocking` in 64 KiB chunks.
- Two-layer cap on the download size:
  - Layer 1: `Content-Length` header pre-check (rejects before
    streaming starts; nothing written to disk).
  - Layer 2: cumulative-byte counter inside the chunk loop
    (catches gzipped responses where `Content-Length` is the
    on-wire size and the post-decompression size is larger).
  - Cap is `MAX_TARBALL_DOWNLOAD_BYTES = 512 MiB` — ~2x
    headroom over the legitimate maximum (the
    actions/runner Linux tarball is observed at ~245 MB x64 /
    ~210 MB arm64 at v2.334.0).
  - On overflow: drop the file handle, unlink `dest`, return
    `GharsError::Tarball` so a half-written file cannot be
    promoted by a later SHA-256 check.
- Verifies SHA-256 case-insensitively (both sides lowercased).
- On mismatch: unlinks the file before returning
  `GharsError::Sha256Mismatch`.

Versioned `bin.X.Y.Z/` directories under each runner home preserve
rollback targets. `Defaults.keep_versions` (default 2) drives the
pruner: after a successful install, the N most recent by mtime are
kept; the rest are removed. `1` = no rollback retention; values
above 5 keep more rollback targets.

## Troubleshooting

### "another apply is running"

```text
GharsError::ApplyLocked { pid: 12345, path: "/run/ghars/apply.lock", stale: false }
```

Another apply has the lock. Default behavior: fail with the
holding PID. If the holder is genuinely hung (process exists but
is stuck), `kill 12345` releases the lock (the kernel
auto-releases the flock on process exit; the lock file body may
linger, but the next apply will succeed).

If the error reports `stale: true`, the lock file exists on disk
but no process with that PID is running. The held lock is NOT
auto-reclaimed — the operator must `rm /run/ghars/apply.lock`
and retry. The stale flag is the green light for safe manual
removal.

### "preflight failed"

```text
exit code 3
```

A preflight `Fail` blocked apply. Run `ghars status --health-only`
for the rollup. Each `Fail` row carries a `hint` string with the
remediation.

### "config is broken"

```text
exit code 6
```

`GharsError::Config` (parse) or `GharsError::Validation` (shape).
The error message names the offending block. Run `ghars
validate` for the same gate without doing anything else.

### "apply needs --auto-approve"

```text
exit code 7
```

`cmd_apply` reached the y/N prompt with non-TTY stdin and
`--auto-approve` was not passed. Either run interactively or pass
`--auto-approve` (e.g. in a CI driver).

### "github 401 / 403"

Auth-resolve failure (build_auth_registry or per-action). Check
that the env var `token_env` references is set, or the
`token_file` is mode 0600 owned by root, or the GitHub App
`private_key_path` is readable and not a symlink. `ghars
validate --deep` round-trips tokens against GitHub before any
apply runs.

### Runner unit fails to start in netns mode

`apply::verify_runner_netns` post-start check failed: `readlink
/proc/PID/ns/net` matched `/proc/1/ns/net`, meaning the runner
fell back to the host netns. Confirm:

- `CONFIG_NET_NS` is enabled in the kernel (`ghars status
  --health-only` checks this).
- `CAP_NET_ADMIN` is in the caller's effective set (preflight
  checks this).
- `ghars-net@NAME.service` is in `active` state — the namespace
  bind-mount at `/var/run/netns/ghars-NAME` survives across the
  runner restart only if the netns unit is active.

### Plan shows recreate, operator wants in-place

A field listed in `RunnerDelta::recreate_reasons` triggered the
recreate decision. Vocabulary: `url`, `runner_version`, `labels`,
`arch`, `runner_sha256`, `runner_tarball`, `network`. None of
these are operator-configurable to in-place-only — the recreate
is structural. To proceed, accept the disruption (or move the
change behind a maintenance window).

The authoritative source for this vocabulary lives at
`src/plan/classify.rs::classify_recreate_reasons_from_annotations`;
any token added there must be reflected in this vocabulary line
and in `architecture.md`'s Plan disruption section.

A spec-hash mismatch with no field-level explanation no longer
triggers recreate; the `uncovered` arm in `plan_from` falls
through to in-place (rewrites the X-Ghars-Spec-Hash annotation
in 00-ghars.conf and restarts the unit, leaving GitHub
registration intact). If you previously alerted on
`recreate (uncovered)` in plan output that signal moves to the
warn-level log line in the planner — switch alerts to grep for
"uncovered" in `ghars plan` stderr (the warn log) rather than
stdout.

### Why did my fleet restart on a ghars binary upgrade?

A ghars binary upgrade that bumps the internal
`crate::systemd::RENDERER_SCHEMA` constant flips every managed
runner's and cache pool's `spec_hash`. On the next `ghars apply`,
every managed unit falls through the in-place arm — apply rewrites
`X-Ghars-Spec-Hash` in `00-ghars.conf` and restarts the unit to
pick up any byte-changed drop-ins. This is the intended fleet
auto-convergence cascade.

What does NOT happen:
- GitHub registration stays intact — no token re-mint, no
  `config.sh` re-run, no runner re-registration.
- Runner identity (UID, runner-home, network namespace) is
  preserved.

In-flight workload impact:
- Currently-running workflows on a restarted runner are sent
  SIGTERM at unit-stop time. systemd waits `TimeoutStopSec=5min`
  before SIGKILL. Workflows that drain cleanly in under 5 min
  finish; longer-running ones get killed.
- Restarts are sequential across the fleet on the host the apply
  ran on (no parallelism today).
- Operator opt-out for protected-workload windows is `apply
  --no-restart`: writes the new drop-ins / `.env` / `.path` to
  disk but skips the per-action `daemon_reload + stop + start`
  cycle. The running unit keeps its pre-rewrite loaded config
  until the operator runs `systemctl restart
  ghars-runner@NAME.service`. See `apply` Flags above for the
  full caveat — re-apply WITHOUT `--no-restart` sees byte-matched
  on-disk files and takes the byte-equality short-circuit, so
  re-apply is NOT a remediation path; operators MUST run
  `systemctl restart` to clear pending state. Recreate-class
  changes (`url` / `runner_version` / `labels` / `arch` /
  `runner_sha256` / `runner_tarball` / `network`) are
  structurally undeferrable even with the flag and still tear
  down the unit.

Cross-host invariant:
- Each host independently computes its own local hash against its
  own discovered annotation. Heterogeneous fleets (some hosts on
  the new binary, some on the old) apply cleanly without
  interfering — each host converges to the binary it's running.

When to bump `RENDERER_SCHEMA`:
- Any byte change to the rendered template, drop-ins, env_file,
  or path_file for the same `EffectiveRunnerSpec` input — the
  reviewer checklist requires the bump in the same commit as the
  renderer change. Cosmetic refactors (comment edits, formatting)
  do NOT bump; only behavior changes that alter what systemd /
  `runsvc.sh` / `Runner.Listener` reads from the rendered files
  do.

### "Implicit-latest" runners track the latest release

A runner deployed without a pinned `runner_version` (on the
runner or in `[defaults]`) tracks the latest actions/runner
release: every `plan` / `apply` resolves the current latest and
classifies a runner installed at anything older as a
recreate-class `runner_version` change. The installed version is
read from the on-disk `X-Ghars-Effective-Version` annotation in
`00-ghars.conf`.

When the releases API is unreachable at plan time, the plan
carries a warning and unpinned runners are classified against
their installed (annotation) versions — the pre-track-latest
behavior — so offline plans neither error nor recreate blind.
Do not leave the fleet in that degraded mode indefinitely:
runners register with `--disableupdate`, and a version left
frozen eventually crosses GitHub's deprecation floor ("Runner
version vX.Y.Z is deprecated and cannot receive messages" on
every listener start, service flaps to `start-limit-hit`, jobs
queue forever).

Tarball-pinned runners (`runner_tarball` set) MUST pin
`runner_version` — `ghars plan` rejects them at validation time
otherwise, because the tarball install needs a version string
to name the on-disk `bin.X.Y.Z` directory and ghars cannot
infer the version from the tarball filename.

If you see `UpdateRunner(NAME): rewrite .env/.path → in-place
delta missing runner_version` at apply time, the runner's
`00-ghars.conf` is missing the `X-Ghars-Effective-Version`
annotation. This happens for runners deployed by a ghars
version that predates the annotation, runners whose
`00-ghars.conf` was operator-stripped, or runners whose
annotation was manually edited to an invalid value (anything
that doesn't match `X.Y.Z`). Remediation:

- Pin `runner_version = "X.Y.Z"` in `ghars.toml` to match the
  installed version (`ls /var/lib/ghars/<TRUST_ZONE>/ghars-<NAME>/bin.*`
  shows the installed `bin.X.Y.Z/` directory).
- Or remove the runner from `ghars.toml` and re-add it so a
  fresh `CreateRunner` re-fetches the latest version from the
  GitHub API.

## --diff and credential leakage

Both `ghars plan --diff` and `ghars apply --diff` render full
drop-in body content. The `60-proxy.conf` drop-in carries
dual-case `Environment=HTTP_PROXY=...` / `http_proxy=...` and
`Environment=HTTPS_PROXY=...` / `https_proxy=...` lines (apps that
read either spelling find a value), and an authenticated proxy
URL embeds credentials in the userinfo component
(`https://USER:PASS@host`). With `--diff` set, those credentials
appear in stdout (and any captured CI artifact, build log upload,
terminal scrollback, or shared paste) in cleartext on every line.

Operators piping `--diff` output to artifacts that survive past
the invoking shell session must treat the output as a
credential-bearing file: do not commit, do not upload to shared
logs, do not paste to chat. Other drop-ins may likewise embed
sensitive `Environment=` values; proxy auth is the canonical case
but not the only one.

Default off precisely so the secret-bearing body never reaches
stdout unless the operator opts in.

## Setting environment variables for workflow steps

Use `[defaults.environment]` / `[[runner]].environment` in
`ghars.toml` to declare env vars and PATH additions that
workflow steps see. **Do not edit `bin.X.Y.Z/.env` directly** —
ghars overwrites it on every apply (the file is ghars-owned).

```toml
[defaults.environment]
vars = { MY_TEAM_VAR = "production" }
path_prepend = ["/opt/company-tools/bin"]

[[runner]]
name = "buckos"
[runner.environment]
vars = { DEPLOY_TARGET = "buckos-ci" }
path_append = ["/opt/buckos-specific/bin"]
```

Operator vars land in BOTH `bin.X.Y.Z/.env` (consumed by
`Runner.Listener::LoadAndSetEnv` for workflow steps) AND
`00-ghars.conf` (`Environment=` directives, consumed by systemd
for the runner unit process). Both layers carry the same merged
keys — operator's `MY_TEAM_VAR` is visible to the runner daemon
AND to every workflow step.

Field-by-field validation rejects security-critical names
(`LD_PRELOAD` and the LD\_\* family, shell-hijack vars like
`BASH_ENV` / `IFS` / `PS4`), ghars-owned names (`PATH`, `HOME`,
`CCACHE_DIR`, `KTSTR_*`, `SCCACHE_*`, `HTTP_PROXY` family,
`ACTIONS_RUNNER_*`), and any name that does not match the
POSIX env-var-name regex `^[A-Z_][A-Z0-9_]*$`. See
`configuration.md` → `EnvironmentSpec` → Validation for the
full deny-list and rationale per tier.

PATH entries must be absolute paths. `path_prepend` lands
BETWEEN the framework ccache wrappers and the per-runner
`.cargo/bin` segment (so operator paths cannot shadow `gcc` /
`cc` and break compile-cache hits). `path_append` lands AFTER
the system tail.

## Why can't I declare two ccache (or sccache) pools per runner?

`ghars validate` and `ghars apply` reject any runner whose
`[[runner]].caches` list contains two pool refs that share a
single `kind` (two ccache pools, two sccache pools, or a
combined-kind pool plus a same-kind-only pool). The error scopes
to the offending runner + names both conflicting pools + offers
two remediations (drop one pool, or merge kinds into one pool
entry).

The constraint is structural, not arbitrary:

- **ccache** is single-`CCACHE_DIR`-per-process by upstream
  design. `ccache/src/ccache/config.cpp` picks ONE `cache_dir`
  from a strict resolution chain with no loop or list. Multi-
  pool ghars binding cannot deliver distinct cache dirs to the
  workflow step. When a runner is bound to at least one ccache
  pool, the renderer emits `CCACHE_DIR=/var/lib/ghars/<TRUST_ZONE>/
  .ccache` in the runner's `.env` (so trust-zone-shared cache
  hits across runners survive recreates) and one `CCACHE_MAXSIZE`
  per binding — `Runner.Listener::LoadAndSetEnv` calls
  `Environment.SetEnvironmentVariable` per line and the LAST
  `CCACHE_MAXSIZE` wins. Two pools collapse to one effective
  cache with whichever pool's size cap was emitted last.
  Runners with NO ccache binding don't get `CCACHE_DIR=` in
  their `.env` and don't have the trust-zone `.ccache` dir
  created on disk; the unconditional ccache wrappers in PATH
  fall back to ccache's XDG default (`$HOME/.ccache` under
  `runner_home`), giving the runner a per-runner ephemeral
  cache instead of the trust-zone-shared one.
- **sccache** reads a single `SCCACHE_SERVER_UDS`. Two sccache
  bindings emit two `Environment=SCCACHE_SERVER_UDS=` directives
  in the runner's 30-cache-pool.conf; systemd's last-writer-wins
  `Environment=` semantics route every sccache call to one pool,
  silently shadowing the other.

If your goal is shared cache across multiple runners, that's the
default — every runner in the same `trust_zone` shares the
trust-zone-derived `CCACHE_DIR` and can reference the same
`[cache_pools.NAME]` entry. The `mode = "shared"` default on
`[cache_pools.NAME]` permits cross-runner referencing without
extra config.

If your goal is multi-backend ccache storage (e.g. local +
remote), use ccache's own `remote_storage` feature
(`CCACHE_REMOTE_STORAGE` env var, configured via the operator
`environment.vars` field on the runner) — a single primary
local `CCACHE_DIR` with a secondary HTTP / Redis / file backend
on top. ghars's `[[cache_pools]]` machinery is for primary local
caches.

## Customizing runner unit directives: use `99-*.conf`, never edit ghars-managed drop-ins

ghars renders every per-runner drop-in basename in the
`MANAGED_DROP_IN_BASENAMES` set (the `00-ghars.conf`,
`10-memory.conf`, `15-resolv.conf`, `20-hardening.conf`,
`30-cache-pool.conf`, `40-network.conf`, `50-numa.conf`,
`60-proxy.conf`, `70-hooks.conf`, `80-lognamespace.conf` family).
ghars OWNS these files: every `ghars apply` rewrites them from
the rendered output, and any operator hand-edit is silently
overwritten the next time the runner's spec_hash flips or a
managed body diff is detected.

**Only `99-*.conf` drop-ins survive across applies.** The
in-place update loop guards the `99-*.conf` namespace (any
basename NOT in `MANAGED_DROP_IN_BASENAMES`) so operator-added
directives via `systemctl edit ghars-runner@NAME.service` (which
writes `/etc/systemd/system/ghars-runner@NAME.service.d/override.conf`,
typically renamed to `99-operator.conf` for ghars compatibility)
are preserved indefinitely.

### When you hand-edit a ghars-managed drop-in anyway

The `X-Ghars-Spec-Hash` annotation in `00-ghars.conf` lives
inside the file ghars rewrites. If you hand-edit `00-ghars.conf`
to add an extra `Environment=` line and leave the annotation
intact, ghars's plan layer still considers the spec_hash equal
to the desired hash (the annotation line didn't change) — so
the in-place arm classifies the runner as in-sync and emits
NoOp. Your edit persists, but only because plan happened to
short-circuit. Any subsequent change to the desired spec
(memory_max bump, cache binding edit, RENDERER_SCHEMA bump on
ghars upgrade) flips spec_hash, triggers the in-place rewrite,
and your hand-edit is silently lost.

**Don't rely on hand-edits to ghars-managed drop-ins surviving.**
The supported override mechanism is `99-*.conf`. Any directive
you would have added to `00-ghars.conf` belongs in a 99-prefixed
file the in-place update loop's `MANAGED_DROP_IN_BASENAMES`
guard preserves.

### Workflow steps see empty / minimal env after a failed apply

A `ghars apply` that failed PARTWAY through a `CreateRunner`
action triggers rollback. The rollback path for `bin.X.Y.Z/.env`
and `bin.X.Y.Z/.path` is unlink-on-undo (the `WriteFile` undo
step records `prior_content: None` for fresh files, so rollback
removes the file rather than restoring it). Subsequent
`actions/runner` startup writes a minimal default `.env` /
`.path` of its own — no ccache wrappers, no `KTSTR_*` env, no
operator-declared `environment.vars`. Workflow steps relying on
those framework env vars run in degraded mode.

Remediation: re-run `ghars apply` to restore the ghars-emitted
`.env` / `.path` content. The successful re-apply overwrites
the minimal upstream-written files with the full framework +
operator-declared composition.
