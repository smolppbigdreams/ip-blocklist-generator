#!/usr/bin/env bash
#MISE description="Run all Rust tests (unit + integration + doc-tests) in release mode."
set -eo pipefail

# ==========================================
# Run Tests
# ==========================================
gum spin --spinner pulse --title " [🦀] Compiling and running tests..." -- \
    cargo test --release --workspace --all-features

gum log --level info "[✅] All tests passed."
