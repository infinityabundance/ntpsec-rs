#!/bin/sh
# Build the entire ntpsec-rs workspace
set -e

cd "$(dirname "$0")/.."

echo "=== Building ntpsec-rs workspace ==="
cargo build --workspace
echo "Build complete."

echo ""
echo "=== Running tests ==="
cargo test --workspace
echo "Tests complete."

echo ""
echo "=== Generating docs ==="
cargo xtask gen
echo "Doc generation complete."
