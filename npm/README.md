# env-checker — Rust DevSecOps Secret & `.env` Quality Gate

**Blazing-fast Rust pre-commit & CI/CD secret gate (Nexus / SonarQube style)** with HMAC API-key authentication, npm CLI distribution (`@kishorkumarparoi/env-checker`), auto-purge remediation, and SARIF 2.1.0 reporting.

- **Control Plane & API Key Portal**: [https://env.kishor.tech](https://env.kishor.tech)
- **Author**: [Kishor Kumar Paroi](https://kishor.tech)

## Quick Start

```bash
# 1. Install globally via npm (or run via npx)
npm install -g @kishorkumarparoi/env-checker

# 2. Install git pre-commit & pre-push hooks
env-checker init-hooks

# 3. Scan staged files before committing
env-checker scan --staged --env prod

# 4. Auto-purge leaked .env files, redact source secrets, and harden .gitignore
env-checker purge --staged --delete --redact

# 5. CI/CD Quality Gate (blocks pipeline & uploads audit telemetry)
ENV_CHECKER_API_KEY="ec_live_..." env-checker ci --env prod --auto-purge
```

## Build from Source (Rust)

```bash
cargo test --workspace
cargo build --release
./target/release/env-checker scan .
```
