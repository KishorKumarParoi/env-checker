#!/usr/bin/env bash
set -euo pipefail

echo "▶ Cleaning local Rust build artifacts..."
cargo clean || true

echo "▶ Removing Vercel project deployment (if requested)..."
cd web
vercel remove env-checker --yes || true
echo "✅ Teardown complete ($0.00 cost)."
