#!/usr/bin/env bash
# Workspace test and release build. GitHub Actions and Origin CI both call this.
set -euo pipefail
cd "$(dirname "$0")/.."
cargo test --workspace --locked
cargo build --workspace --release --locked
