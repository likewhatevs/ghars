# Getting Started

This chapter walks from a clean install to a registered, running
runner. Everything below assumes a supported host (see
[preflight](./operations.md#preflight)) and root or equivalent
privilege.

## Install

The crate is not yet published to crates.io. Build from source:

```sh
git clone https://github.com/likewhatevs/ghars
cd ghars
cargo install --path .
sudo install -Dm755 ~/.cargo/bin/runsvc-wrapper \
    /usr/lib/ghars/runsvc-wrapper
```

The crate ships two `[[bin]]` targets: the `ghars` CLI (placed on
`PATH` by `cargo install`) and the `runsvc-wrapper` trampoline,
which MUST be copied to `/usr/lib/ghars/runsvc-wrapper` (root:root
mode 0755) — the unit template's `ExecStart=` points at that exact
path. Unit start fails when the binary is missing.

## Scaffold the config

```sh
sudo ghars init
```

`init` writes a starter `ghars.toml` to the path resolved from
`--config` / `GHARS_CONFIG` / the default `/etc/ghars/ghars.toml`.
Override with `--output PATH` to write somewhere else.

Per-runner systemd identities are NOT created by `init`. Each runner
runs under a transient UID allocated by `DynamicUser=yes` at unit
start; the `User=` is set to a `ghars-tz-<TRUST_ZONE>` name that
maps to a UID systemd allocates on its own. Nothing is written to
`/etc/passwd` or `/etc/group`.

## Authenticate

`[auth.NAME]` blocks are the only place credentials are declared.
Runners reference an auth block by name. `kind` discriminates the
mechanism:

```toml
# Personal Access Token, env-sourced.
[auth.pat]
kind = "pat"
token_env = "GHARS_PAT"

# GitHub App.
[auth.gh-app-prod]
kind = "github_app"
app_id = 12345
installation_id = 67890
private_key_path = "/etc/ghars/keys/app.pem"
```

`AuthSpec` has four variants: `pat`, `github_app`, `interactive`
(prompts on a TTY for a registration token at apply time), and
`token_file` (reads a pre-minted registration token from disk).

For `pat`, exactly one of `token_env` or `token_file` MUST be set;
the validator enforces this XOR at config load. The PAT scopes
required depend on the runner's URL shape:

- **Repo-level runner** (`url = "https://github.com/OWNER/REPO"`)
  — classic PAT needs the `repo` scope; fine-grained PAT needs
  the `Administration: write` permission on the repo.
- **Org-level runner** (`url = "https://github.com/OWNER"`) —
  classic PAT needs the `admin:org` scope; fine-grained PAT needs
  the `Administration: write` permission scoped at the org.

Mint tokens at `https://github.com/settings/tokens` (classic) or
`https://github.com/settings/personal-access-tokens/new`
(fine-grained). `ghars` is token-type-agnostic — both kinds
forward to `octocrab` as Bearer credentials, and GitHub validates
server-side.

If you put the PAT in `token_env`, remember that `sudo` defaults
to `env_reset` (see `/etc/sudoers`), which scrubs the caller's
environment. Run `sudo -E ghars …` to preserve `GHARS_PAT`, or
use `token_file` to put the credential at a root-readable
path instead.

For `token_file`, the file MUST be mode 0600 owned by root; checked
at apply time by `PatToken::new` in `auth.rs`.

## Add a runner

Two ways:

**Edit the TOML directly.** Append a `[[runner]]` block:

```toml
[[runner]]
name = "build-1"
url = "https://github.com/example/build"
auth = "pat"
labels = ["x64"]
```

Then run `sudo ghars apply`.

**Use the `add` subcommand.** Non-interactive when the auth block
exists and the env var is set:

```sh
sudo ghars add --repo OWNER/REPO
```

`ghars add` appends a `[[runner]]` block, then runs `apply` unless
`--no-apply` is passed. Flags: `--name`, `--labels`,
`--auth`, `--no-apply`. The default name is
`OWNER-REPO-N` where `N` picks the next free index.

## First plan

```sh
sudo ghars plan
```

`plan` prints an ordered, terraform-style list of actions:
`CreateRunner`, `UpdateRunner`, `RemoveRunner`, `CreateCachePool`,
`UpdateCachePool`, `RemoveCachePool`, `NoOp`. Each action carries a
`[restart]` / `[recreate]` / `[none]` bracket tag indicating the
plan-time worst-case disruption. See
[Architecture](./architecture.md) for the full vocabulary.

`plan` makes no system changes. Useful flags:

- `--only NAMES` — filter to a comma-separated subset of runners
  (substring match).
- `--json` — emit JSON instead of text. Secrets are redacted in
  both formats.
- `--diff` — show full drop-in body content. Default off because
  drop-in bodies can carry credential-bearing `Environment=` lines
  (see the `--diff` notes in [Operations](./operations.md)).
- `--detailed-exitcode` — exit 2 when the plan diff is non-empty
  (terraform parity).
- `--detailed-exitcode-recreate` — exit 8 when the plan contains
  any recreate-class action.

## First apply

```sh
sudo ghars apply
```

Apply prints the same plan, prompts `y/N`, and on confirmation
dispatches each action. The apply loop:

1. Acquires `<runtime_dir>/apply.lock` (POSIX advisory exclusive
   lock via `fs2::FileExt`).
2. GCs stale `.NAME.tmp.PID.COUNTER` temp files and stale
   `<state_dir>/.staging/<name>-<version>-<pid>/` staging dirs left
   behind by previous applies that crashed mid-write.
3. Sorts actions into the canonical phase order:
   `CreateCachePool` → `UpdateCachePool` → `RemoveRunner` →
   `UpdateRunner` (in-place subset first, recreate subset second)
   → `CreateRunner` → `RemoveCachePool`. Within each phase,
   actions sort by their identifier for determinism.
4. Dispatches each action through its `execute_*` handler.
5. Issues a single `Manager.Reload` (`daemon-reload`) at the end.
6. Releases the lock on Drop.

Useful flags:

- `--auto-approve` — skip the y/N prompt.
- `--fail-fast` — stop on first action failure.
- `--rollback-on-failure` — best-effort: when an action's handler
  fails, walk that action's recorded `Vec<UndoStep>` in reverse and
  reverse each step. Per-action scope only — earlier successful
  actions are not touched.
- `--dry-run` — render artifacts but do not write them. The lock
  is still acquired (so concurrent dry-runs serialize) but no
  D-Bus calls or filesystem writes occur.
- `--detailed-exitcode` and `--detailed-exitcode-recreate` —
  same semantics as on `plan`.

## Verify

```sh
sudo ghars status
```

`status` prints two sections: SYSTEM HEALTH (preflight checks) and
RUNNERS (managed-unit table with drift annotations). Filters:
`--health-only`, `--runners-only`, `--metrics`, `--json`, plus
positional names.

Tail the runner's journal:

```sh
sudo ghars logs build-1 --follow
```

`logs` wraps `journalctl -u ghars-runner@NAME.service`. Empty NAMES
list = all managed runners. Flags: `--follow`, `-n LINES`,
`--since SPEC`.

## What you got

After a successful apply for a single-runner config:

- `/etc/systemd/system/ghars-runner@.service` — canonical template,
  shared.
- `/etc/systemd/system/ghars-runner@build-1.service.d/` —
  per-runner drop-ins (`00-ghars.conf` identity annotations,
  `15-resolv.conf`, `80-lognamespace.conf`, plus optional ones
  depending on config).
- `/var/lib/ghars/<TRUST_ZONE>/ghars-build-1/` — runner state dir
  (config.sh output, the regular-file `runsvc.sh` written by
  config.sh, and one `bin.X.Y.Z/` directory per installed
  version with the current install published atomically via
  `renameat2(RENAME_EXCHANGE)`).
- `/var/log/ghars/apply.log` — append-only structured audit log,
  one JSON object per line per action.

The full filesystem layout is in
[Filesystem Layout](./filesystem-layout.md).

## Quickstart, condensed

```sh
cargo install --path .                                  # crate not on crates.io yet
sudo install -Dm755 ~/.cargo/bin/runsvc-wrapper /usr/lib/ghars/runsvc-wrapper
sudo ghars init                                         # write /etc/ghars/ghars.toml (mode 0640)
sudoedit /etc/ghars/ghars.toml                          # add [auth.pat] + GHARS_PAT
export GHARS_PAT=ghp_...
sudo -E ghars add --repo OWNER/REPO                     # appends [[runner]] + applies
sudo -E ghars status                                    # confirm
```

`ghars add` prompts only for what's not on the command line; with
`--auth pat` and `GHARS_PAT` set, it is non-interactive end-to-end.
The `-E` is required for `sudo` to preserve `GHARS_PAT` past the
default `env_reset` policy.
