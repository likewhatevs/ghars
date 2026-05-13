# ghars development recipes

mod scripts

# List recipes (default when running bare `just`)
default:
    @just --list

# Run all tests
test:
    cargo nextest run

# Format the workspace
fmt:
    cargo fmt --all

# Run tests with coverage (70% line gate)
coverage: ci-coverage

# Run mutation testing and print score
mutants:
    cargo mutants --test-tool nextest --json --output mutants.out
    @just scripts::mutants-score

# Lint (same checks as CI)
lint: ci-fmt ci-clippy

# Build mdbook
book: ci-docs

# Serve mdbook locally
book-serve:
    mdbook serve docs --open

# Install development tools and wire up the local pre-commit hook
setup:
    cargo install cargo-nextest --locked
    cargo install cargo-llvm-cov --locked
    cargo install cargo-mutants --locked
    cargo install mdbook --locked
    cargo install mdbook-linkcheck2 --locked
    cargo install rust-script --locked
    cargo install cargo-deny --locked
    git config core.hooksPath .githooks

# Run `systemd-analyze security` against every managed runner +
# cache-pool unit and print per-unit exposure scores. Wraps
# `ghars status --score`. Informational only — no pass/fail gate.
sd-analyze:
    cargo run -- status --score

# --- CI recipes (called by .github/workflows/ci.yml) ---

# Format check
ci-fmt:
    cargo fmt --all -- --check

# Clippy
ci-clippy:
    cargo clippy --workspace --all-targets -- -D warnings

# Test + coverage with 70% line gate (lcov output gitignored)
ci-coverage:
    cargo llvm-cov nextest \
        --workspace \
        --lcov \
        --output-path lcov.info \
        --fail-under-lines 70

# Musl static build + link assertion for the ghars binary
ci-musl:
    #!/usr/bin/env bash
    set -euo pipefail
    rustup target add x86_64-unknown-linux-musl
    cargo build --release --target x86_64-unknown-linux-musl
    P="target/x86_64-unknown-linux-musl/release/ghars"
    file "$P"
    file "$P" | grep -qE "statically linked|static-pie linked"

# cargo deny check (advisories, bans, sources, licenses)
ci-audit:
    cargo deny check advisories bans sources licenses

# mdbook build + test
ci-docs:
    mdbook build docs
    mdbook test docs
