# ghars development recipes

mod scripts

# Run all tests
test:
    cargo nextest run

# Run tests with coverage
coverage:
    cargo llvm-cov nextest --lcov --output-path lcov.info --fail-under-lines 70
    @echo "Coverage report: lcov.info"

# Run mutation testing and print score
mutants:
    cargo mutants --test-tool nextest --json --output mutants.out
    @just scripts::mutants-score

# Lint (same checks as CI)
lint:
    cargo fmt --all -- --check
    cargo clippy --workspace --all-targets -- -D warnings

# Build mdbook
book:
    mdbook build docs

# Serve mdbook locally
book-serve:
    mdbook serve docs --open
