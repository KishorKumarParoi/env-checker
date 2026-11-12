#!/usr/bin/env bash
set -euo pipefail

echo "▶ Running Rust unit tests & release build..."
cargo test --workspace
cargo build --release

echo "▶ Deploying env-checker Control Plane (env.kishor.tech) to Vercel..."
cd web
DEPLOY_URL=$(vercel --prod --yes)
echo "✓ Deployed to: $DEPLOY_URL"

echo "▶ Binding custom subdomain env.kishor.tech..."
vercel alias set "$DEPLOY_URL" env.kishor.tech || vercel domains add env.kishor.tech || true
echo "✅ Live at https://env.kishor.tech"
