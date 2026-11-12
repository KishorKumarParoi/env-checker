#!/usr/bin/env node
/**
 * @kishorkumarparoi/env-checker
 * Hybrid launcher: uses the native Rust binary when available for maximum SIMD/parallel speed,
 * with a zero-dependency Node.js fallback for portable npx CI/CD execution.
 */
const { spawnSync, execSync } = require('child_process');
const fs = require('fs');
const path = require('path');

const RUST_BIN_CANDIDATES = [
  path.resolve(__dirname, '../../target/release/env-checker'),
  path.resolve(__dirname, '../native/env-checker'),
  'env-checker-rust'
];

function findRustBinary() {
  for (const candidate of RUST_BIN_CANDIDATES) {
    if (candidate.includes(path.sep) && fs.existsSync(candidate)) {
      return candidate;
    }
  }
  return null;
}

const rustBin = findRustBinary();
const args = process.argv.slice(2);

if (rustBin) {
  const res = spawnSync(rustBin, args, { stdio: 'inherit', env: process.env });
  process.exit(res.status ?? 1);
}

// Portable Node.js fallback (for npx environments without Rust installed)
const RULES = [
  { id: 'EC-001', name: 'OpenAI API Key', re: /\bsk-(?:proj-|svcacct-|admin-)?[A-Za-z0-9_-]{20,}\b/g },
  { id: 'EC-002', name: 'Anthropic API Key', re: /\bsk-ant-(?:api\d{2}-)?[A-Za-z0-9_-]{24,}\b/g },
  { id: 'EC-003', name: 'AWS Access Key ID', re: /\b(?:AKIA|ASIA|AROA|AIDA)[0-9A-Z]{16}\b/g },
  { id: 'EC-005', name: 'GitHub Token', re: /\b(?:ghp|gho|ghu|ghs|ghr)_[A-Za-z0-9]{36,}\b|\bgithub_pat_[A-Za-z0-9_]{22,}\b/g },
  { id: 'EC-006', name: 'Google / Gemini API Key', re: /\bAIza[0-9A-Za-z\-_]{35}\b/g },
  { id: 'EC-007', name: 'Stripe Live Key', re: /\b(?:sk|rk)_live_[0-9a-zA-Z]{24,}\b/g },
  { id: 'EC-009', name: 'HuggingFace Token', re: /\bhf_[A-Za-z0-9]{24,}\b/g },
  { id: 'EC-010', name: 'Groq API Key', re: /\bgsk_[A-Za-z0-9]{40,}\b/g },
  { id: 'EC-011', name: 'Private Key PEM', re: /-----BEGIN (?:RSA |EC |DSA |OPENSSH |PGP )?PRIVATE KEY-----/g },
  { id: 'EC-012', name: 'DB URL w/ Credentials', re: /\b(?:postgres|postgresql|mysql|mongodb(?:\+srv)?|redis|amqp):\/\/[^:\s'"]+:[^@\s'"]{6,}@[^\s'"]+/gi }
];

function isSensitiveEnvFile(filePath) {
  const base = path.basename(filePath).toLowerCase();
  if (base === '.env.example' || base === '.env.sample' || base === '.env.template') return false;
  return base === '.env' || base.startsWith('.env.') || base.endsWith('.pem') || base.endsWith('.key');
}

function walk(dir, out = []) {
  for (const entry of fs.readdirSync(dir, { withFileTypes: true })) {
    if (['.git', 'node_modules', 'target', '.env-checker-quarantine'].includes(entry.name)) continue;
    const full = path.join(dir, entry.name);
    if (entry.isDirectory()) walk(full, out);
    else out.push(full);
  }
  return out;
}

async function verifyKey(endpoint, apiKey, envName) {
  if (!apiKey) return;
  try {
    const res = await fetch(`${endpoint.replace(/\/$/, '')}/api/v1/verify`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json', 'x-api-key': apiKey },
      body: JSON.stringify({ environment: envName })
    });
    if (!res.ok) throw new Error(`HTTP ${res.status}`);
    const data = await res.json();
    if (!data.valid) throw new Error('Invalid API key');
    console.log(`✓ Authenticated (${data.project || 'env.kishor.tech'})`);
  } catch (err) {
    console.error(`✗ API key verification failed: ${err.message}`);
    process.exit(2);
  }
}

async function main() {
  if (args.includes('--help') || args.includes('-h') || args.length === 0) {
    console.log('env-checker v1.0.0 — Rust/Node Secret & .env Security Gate (https://env.kishor.tech)');
    console.log('Usage: env-checker <scan|purge|ci|init-hooks> [path] [--staged] [--env prod] [--api-key KEY] [--auto-purge]');
    process.exit(0);
  }

  const cmd = args[0];
  const targetDir = path.resolve(args[1] && !args[1].startsWith('-') ? args[1] : '.');
  const staged = args.includes('--staged');
  const autoPurge = args.includes('--auto-purge') || cmd === 'purge';
  const envIdx = args.indexOf('--env');
  const envName = envIdx !== -1 ? args[envIdx + 1] : 'prod';
  const keyIdx = args.indexOf('--api-key');
  const apiKey = keyIdx !== -1 ? args[keyIdx + 1] : process.env.ENV_CHECKER_API_KEY;
  const endpoint = process.env.ENV_CHECKER_ENDPOINT || 'https://env.kishor.tech';

  if (cmd === 'ci') {
    if (!apiKey) {
      console.error('✗ Missing --api-key or ENV_CHECKER_API_KEY. Generate one at https://env.kishor.tech');
      process.exit(2);
    }
    await verifyKey(endpoint, apiKey, envName);
  } else if (apiKey) {
    await verifyKey(endpoint, apiKey, envName);
  }

  let files = [];
  if (staged) {
    try {
      const out = execSync('git diff --cached --name-only --diff-filter=ACMR', { cwd: targetDir }).toString();
      files = out.split(/\r?\n/).filter(Boolean).map((f) => path.join(targetDir, f));
    } catch {
      files = [];
    }
  } else {
    files = walk(targetDir);
  }

  const findings = [];
  const envFiles = [];

  for (const file of files) {
    const rel = path.relative(targetDir, file);
    if (isSensitiveEnvFile(file)) envFiles.push(rel);
    let content;
    try {
      content = fs.readFileSync(file, 'utf8');
    } catch {
      continue;
    }
    const lines = content.split(/\r?\n/);
    lines.forEach((line, idx) => {
      for (const rule of RULES) {
        rule.re.lastIndex = 0;
        const m = rule.re.exec(line);
        if (m) {
          findings.push({ rule_id: rule.id, rule_name: rule.name, file: rel, line: idx + 1 });
          break;
        }
      }
    });
  }

  if (autoPurge && (findings.length > 0 || envFiles.length > 0)) {
    for (const rel of envFiles) {
      try { execSync(`git rm --cached --ignore-unmatch -f "${rel}"`, { cwd: targetDir, stdio: 'ignore' }); } catch {}
    }
    console.log(`🧹 Auto-purge unstaged ${envFiles.length} sensitive .env/key file(s).`);
  }

  if (findings.length > 0 || (staged && envFiles.length > 0)) {
    console.error(`QUALITY GATE: BLOCKED (${findings.length} secret findings, ${envFiles.length} .env files)`);
    findings.forEach((f) => console.error(`  [${f.rule_id}] ${f.file}:${f.line} — ${f.rule_name}`));
    process.exit(1);
  }

  console.log(`QUALITY GATE: PASSED (${files.length} files scanned, env=${envName})`);
}

main();
