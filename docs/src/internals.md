# Internals

This chapter documents the load-bearing low-level mechanisms:
TOCTOU-safe file operations, atomic publish via `renameat2`,
fsync durability, the apply lock, the GC passes, and the
reset-on-empty validator.

Reviewers and contributors are the audience; operators rarely
need this material.

## TOCTOU-safe file operations

ghars never trusts that a path resolves to the same inode between
operations. Every operator-supplied path that reaches a privileged
operation goes through one of these gates.

### `O_NOFOLLOW` at open

Symlinks are rejected at the kernel `open(2)` boundary, not at
lstat-then-open. Used for:

- `runner_tarball` paths (operator-supplied; passed to
  `verify_local_tarball` then `install_runner_binary`).
- Hook scripts (`HooksSpec.pre_job` / `post_job`); the validator
  opens with `O_NOFOLLOW` and checks regular-file + executable +
  root-owned.
- The GitHub App `private_key_path` PEM.
- `runsvc.sh` integrity checks at runtime by the trampoline.

The canonical helper `validators::open_no_follow_with_meta`
takes a `&std::path::Path`, opens it with the relevant flags,
and returns the open `File` plus its `Metadata`:

```rust
pub(crate) fn open_no_follow_with_meta(
    path: &Path,
) -> std::io::Result<(File, Metadata)> {
    let file = OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_NOFOLLOW | libc::O_NONBLOCK)
        .open(path)?;
    let meta = file.metadata()?;
    Ok((file, meta))
}
```

Callers holding a `Utf8Path` adapt with `.as_std_path()`:
`validate_hook_script(path: &Utf8Path)` passes
`path.as_std_path()` to the helper. `O_NOFOLLOW` is the
symlink defense; `O_NONBLOCK` prevents `open(2)` from hanging
on a fifo. Both flags are required to close the relevant
attack surfaces.

### renameat2 atomicity

When ghars needs to swap a directory in place (e.g. publishing a
freshly-extracted `bin.X.Y.Z/` over an existing one during an
upgrade), it uses `renameat2` with the `RENAME_EXCHANGE` flag
instead of a 2-step `remove + rename`. RENAME_EXCHANGE atomically
swaps two paths; an observer (the runsvc-wrapper re-running, a
concurrent apply reading state) never sees a window where the
path is missing or partially written.

Used by `extract_and_swap_from_file` to swap the staging dir
with the live `bin.X.Y.Z/` (after which the old tree, now sitting
at the staging path, is removed). The `nix` crate's safe wrapper
around `renameat2` is the implementation seam (the workspace
forbids `unsafe_code`).

### `fexecve` instead of `execve`

The runsvc-wrapper execs the integrity-checked fd (not the path),
closing the open-then-rename TOCTOU window. The `nix` crate
provides `fexecve` in `nix::unistd` (gated by the `process`
feature in `Cargo.toml`). Full integrity protocol (open, SHA-256,
annotation compare, fexecve, refusal on mismatch) is documented in
[Security](./security.md#runtime-integrity-runsvc-wrapper).

## fsync durability

A `rename` from a temp path to the final path is atomic against
crashes only if both the rename AND the parent directory entry
are persisted. POSIX makes neither guarantee implicit;
`apply.rs::write_root_owned` and the extract paths explicitly
`fsync` the parent directory after every rename.

`extract.rs` does the same for the staging tree post-unpack
(`extract_tarball_from_file` batches dir fsyncs of the staging
subtree before the final atomic swap), and for the `bin.<VERSION>/`
directory swap (`extract_and_swap_from_file` fsyncs both
`runner_home` and `staging.parent()` after the renameat2
RENAME_EXCHANGE).

## Apply lock

`<runtime_dir>/apply.lock` (default `/run/ghars/apply.lock`)
serializes every `apply` invocation against the host. The file is
opened at mode 0600 (or chmodded down if a wider-mode pre-existing
file is found, with diagnostic), and acquired via
`fs2::FileExt::try_lock_exclusive` (POSIX advisory exclusive lock,
non-blocking).

```rust
let file = OpenOptions::new()
    .read(true).write(true).create(true)
    .mode(0o600)
    .open(lock_path.as_std_path())?;
FileExt::try_lock_exclusive(&file).map_err(|e| {
    // On contention: read the lock body for the holding PID, probe
    // /proc/<pid>/status for liveness, return ApplyLocked { pid, path, stale }.
})?;
```

`fs2` calls `flock(2)`; the lock auto-releases when the file
handle drops (process exit, explicit `Drop`).

The lock body holds the holding apply's PID. On contention,
`acquire_lock` reads the file body, probes `/proc/<pid>/status`
to determine liveness, and returns
`GharsError::ApplyLocked { pid, path, stale }`. The `stale`
field is `true` when the recorded PID is no longer alive (e.g.
`kill -9` of the apply process leaves the lock file on disk
because the kernel auto-released the flock but the file body
persists). SEC-19: the stale flag is a DIAGNOSTIC signal — the
held lock is NOT auto-reclaimed. The operator must `rm
<runtime_dir>/apply.lock` manually and retry; `stale: true`
tells them removing the file is safe.

## GC passes

`apply` runs two best-effort GC passes after lock acquisition and
before the per-action loop, both skipped under `--dry-run`:

### `gc_stale_temp_files`

Targets `.NAME.tmp.PID.COUNTER`-shaped files under `unit_dir`,
per-runner drop-in dirs (`ghars-runner@*.service.d/`), per-pool
drop-in dirs (`ghars-cache@*.service.d/`), `config_dir/nft.d/`,
and `config_dir/netns.d/`. These are
leftovers from `write_root_owned` calls that crashed between
`create_new` (which uses `O_CREAT | O_EXCL` to claim the temp
name atomically) and the final rename.

Filtering rules (the conservative gate):

- The basename must parse as `.{final_name}.tmp.{pid}.{counter}`
  with both `pid` and `counter` decimal integers and the basename
  starting with `.` (hidden).
- The embedded PID must not match the current process (defensive
  — apply.lock blocks concurrent applies, but the gate is
  redundant).
- The mtime must be older than `STALE_TEMP_AGE_SECS` (the
  apply.lock makes this gate sufficient — other applies are
  blocked by the lock, so any stale temp older than the threshold
  has no claim).

Anything that fails to parse is left alone.

### `gc_stale_staging_dirs`

Targets `<state_dir>/.staging/<name>-<version>-<pid>/` directories
left by `extract::install_runner_binary` calls that crashed past
their own cleanup branch. Filesystem subtree is disjoint from
`gc_stale_temp_files`'s targets, so the two passes are
independent.

Same own-PID + age gates. No PID-liveness probe — under
apply.lock the only stagedirs that exist are either ours
(in-flight; we wouldn't GC our own) or stale beyond the age
threshold.

## Reset-on-empty validator

systemd treats certain list-typed directives as RESET on empty
assignment (per `systemd.exec(5)`):

```
SystemCallFilter=
```

without a value clears the entire allowlist established by an
earlier line. A managed drop-in that emits this would silently
erase the template's hardening. The `validate_drop_in` function
(`systemd.rs`) refuses any generated drop-in body that contains a
bare `=` for any of:

```
SystemCallFilter
CapabilityBoundingSet
BindReadOnlyPaths
BindPaths
ReadWritePaths
IPAddressDeny
IPAddressAllow
RestrictAddressFamilies
AmbientCapabilities
SystemCallLog
```

(`DeviceAllow` is INTENTIONALLY ABSENT — `hardening.kvm = false`
must revoke `DeviceAllow=/dev/kvm rw` somehow, and the only
mechanism systemd offers to revoke a list-typed allowance is the
empty-reset. The runner template has `DevicePolicy=closed`, so
the empty allowlist is fail-closed regardless.)

The regex `RESET_ON_EMPTY_RE` is `(?m)^[ \t]*(?:DIRECTIVES_OR)=[
\t]*$`, where:

- `(?m)` makes `^` / `$` match per-line.
- `[ \t]*` (not `\s*`) — leading horizontal whitespace is
  allowed because `man systemd.syntax` says leading whitespace is
  ignored. `\s` would slurp newlines into "leading whitespace"
  and break per-line matching.
- The `=[ \t]*$` tail catches `DIRECTIVE=`, `DIRECTIVE=  ` (with
  trailing spaces), but not `DIRECTIVE=value` (has a value).

Operator-managed `99-*.conf` files are NOT validated — the
operator owns those.

## Identity field validation

Every value interpolated into a `00-ghars.conf` `X-Ghars-*`
annotation passes through `check_identity_field`:

- Reject `\n` / `\r` — would inject a new directive line into
  the unit file and break the parser's `Key=Value` boundary.
- Reject `\0` — shell / parser hazard.
- Reject any `is_control()` char — undefined behavior in the
  X-Ghars-* annotation parser at `state::extract_x_ghars`.

Three call sites, all defense-in-depth:

- `render_identity` (in `systemd.rs`) — the LAST gate before
  bytes hit disk. Wraps the result with `render_identity:` so
  plan-time render errors name the rejecting function.
- `cli::validate_identity_fields` — config-load gate, scoped by
  `runner "NAME":` / `cache_pool "NAME":` so the operator sees
  the offending block.
- `plan::plan_from` — defense-in-depth on the synthesized
  `config_source` value composed from `paths.config_dir`.

## Control-character escaping

`crate::escape_control_chars` (in `lib.rs`) escapes ASCII control
characters (C0 + DEL) before terminal emission. Identifies escape
candidates via `char::is_ascii_control()` (true for `0x00..=0x1f`
and `0x7f`); each control char rewrites via
`char::escape_default()` (`\n`/`\r`/`\t` for the named ones,
`\u{NN}` for the rest). Bytes ≥ 0x80 (every multibyte UTF-8
sequence) pass through unchanged — preserves i18n filenames at
the cost of leaving the C1 control range
(`U+0080..=U+009F`) unescaped (those codepoints are valid UTF-8
continuation bytes inside multibyte sequences; aggressive
escaping would mangle non-ASCII strings).

Returns `Cow::Borrowed` on the fast path (clean ASCII / clean
UTF-8 input scans bytes once and returns); the allocating path
fires only when at least one control char is present. The
function is idempotent under its own escape vocabulary — a
second pass on already-escaped output returns `Cow::Borrowed`
with byte-equal output, so layered defense at multiple call
sites costs only a byte-scan per re-pass.

Used at:

- `apply::ApplyOutcome::Failed.error_summary` — defends
  downstream stderr emission against ANSI-escape-laden
  `GharsError::to_string()` output.
- `apply::UndoStep::describe` — every per-variant
  path/name/url field is escaped.
- `cli::render_rollback_advisory` — interpolates two operator-
  supplied fields per failure entry; both escape before stderr
  emission.
- `cli::render_action_line` and `cli::plan_to_json_value` — drop-
  in basenames (defends against on-disk filesystem entries that
  bypassed config-load validation).
- `cli::push_indented_body` and `cli::push_indented_unified_diff`
  — drop-in body content under `--diff`. Hostile body bytes
  replace with the printable `\u{NN}` form; the 12-space indent
  prefix and the intentional `\x1b[32m` / `\x1b[31m` / `\x1b[0m`
  ANSI wraps survive structurally.

## Tarball download caps

Two-layer cap in `extract.rs::http_download_with_cap`:

**Layer 1: `Content-Length` header pre-check.** Before opening
`dest`, parse the `Content-Length` header. If it exceeds
`max_bytes` (production: `MAX_TARBALL_DOWNLOAD_BYTES = 512 MiB`),
reject with `GharsError::Tarball` — nothing is written to disk.
Required because `resp.content_length()` returns `None` for
gzipped responses (reqwest's `gzip` feature decompresses
transparently and zeros the size hint). Reading the raw
`Content-Length` header bypasses the gzip transparency.

**Layer 2: cumulative-byte counter.** Inside the chunk loop,
`saturating_add` the read count onto a `u64` total. Once `total >
max_bytes`, drop the file handle, unlink `dest`, return
`GharsError::Tarball`. Required because Layer 1 sees the on-wire
(pre-decompression) size; an attacker who can inject HTTP
responses can compress a small payload to terabytes
post-decompression.

The chunk size is 64 KiB (`CHUNK_SIZE`); the cap is 512 MiB
(`MAX_TARBALL_DOWNLOAD_BYTES`) — ~2x headroom over the legitimate
maximum (the actions/runner Linux tarball weighs in at ~245 MB
x64 / ~210 MB arm64 at v2.334.0).

On overflow, the partial dest file is unlinked. If the unlink
fails (ENOSPC / EACCES / EROFS), the error is logged via
`tracing::warn!` and the cap-fire error propagates — the
operator must see WHY the download was rejected.

## Safe tar member filter

`extract.rs::safe_member_filter` rejects every tar entry that
would write outside the staging dir or steal privilege:

- Path traversal (`..`, absolute paths in the entry name).
- Symlink / hardlink escape (link target outside the staging
  root).
- Device / fifo / char / block entries.

Mode bits are masked: the `Archive` is constructed with
`preserve_permissions = false` (the default), so the tar crate
writes `mode & 0o777` to the file. The setuid / setgid / sticky
bits (`0o7000`) lie entirely outside `0o777` and are stripped by
construction (SEC-10). uid/gid are forced to the extracting
process's identity (so a tar built with embedded uid/gid
annotations cannot smuggle a privileged owner).

The staging dir itself is built root-owned under
`<state_dir>/.staging/<name>-<version>-<pid>/` (SEC-09 / SEC-33);
the final atomic rename hands the freshly-extracted bin tree to
the runner home in one step.

## Error rendering and chains

`crate::error::format_error_chain` walks the source chain on every
`io::Error` / `reqwest::Error` and emits the inner cause inline so
operators triaging a TLS / DNS / transport failure see (e.g.) the
rustls reason code or the hyper transport reason — not just the
outer Display layer.

Bare `?` on `io::Error` invokes the `From<io::Error> for
GharsError` impl which uses the default Display — that drops
nested causes. Every I/O site in `extract.rs::http_download_with_cap`
wraps explicitly via `format_error_chain` to preserve the chain.

## Async runtime surface

The crate uses `tokio` with `default-features = false, features =
["rt"]` — only the runtime, no `macros`, no `time`, no
file IO. A single `OnceLock<Runtime>` provides `block_on(...)`
for `octocrab` calls (which need an async executor); octocrab
0.42 with the `rustls` + `default-client` features uses
`hyper-rustls` directly (not `reqwest`), so we do not pass it a
custom HTTP client. zbus runs its own executor via
`zbus::blocking` (zbus's `blocking-api` feature wraps the async
executor; the default `async-io` backend is the implementation,
NOT tokio).

`#[tokio::main]` is not used. `fn main()` is sync. The two
runtimes (tokio-rt for octocrab, async-io for zbus) coexist
without sharing — they do not see each other's tasks.

## Workspace lints

`Cargo.toml` sets:

```toml
[lints.rust]
unsafe_code = "forbid"
missing_docs = "warn"

[lints.clippy]
pedantic = { level = "warn", priority = -1 }
unwrap_used = "warn"
expect_used = "warn"
```

Effects:

- `unsafe_code = "forbid"` — every place that needs a syscall
  goes through a safe wrapper crate (`nix` for `fexecve` and
  `renameat2`; `libc` for `O_NOFOLLOW` / `O_NONBLOCK` constants
  threaded through `OpenOptionsExt::custom_flags`; `fs2` for
  `flock`).
- `missing_docs = "warn"` — every public item has a doc comment.
- `pedantic` clippy is warn-level; `unwrap_used` and
  `expect_used` are warn-level so production code paths cannot
  panic on `Option::None` or `Result::Err` without the warning
  surfacing in CI.

## Where to find the source

Each section above maps to a specific module:

| topic                          | source                                  |
|--------------------------------|-----------------------------------------|
| `O_NOFOLLOW` open patterns     | `validators.rs`, `extract.rs`           |
| `renameat2` exchange           | `extract.rs`                            |
| `fexecve` trampoline           | `src/bin/runsvc_wrapper.rs`             |
| fsync durability               | `apply.rs::write_root_owned`, `extract.rs` |
| apply lock                     | `apply.rs::acquire_lock`                |
| GC passes                      | `apply.rs::gc_stale_temp_files`, `apply.rs::gc_stale_staging_dirs` |
| reset-on-empty validator       | `systemd.rs::validate_drop_in`          |
| identity field validator       | `systemd.rs::check_identity_field`      |
| control-char escape            | `lib.rs::escape_control_chars`          |
| tarball cap                    | `extract.rs::http_download_with_cap`    |
| safe tar member filter         | `extract.rs::safe_member_filter`        |
| error chain rendering          | `error.rs::format_error_chain`          |
