const RULES = [
  { id: 'EC-001', name: 'OpenAI API Key', severity: 'CRITICAL', re: /\bsk-(?:proj-|svcacct-|admin-)?[A-Za-z0-9_-]{20,}\b/g },
  { id: 'EC-002', name: 'Anthropic API Key', severity: 'CRITICAL', re: /\bsk-ant-(?:api\d{2}-)?[A-Za-z0-9_-]{24,}\b/g },
  { id: 'EC-003', name: 'AWS Access Key ID', severity: 'CRITICAL', re: /\b(?:AKIA|ASIA|AROA|AIDA)[0-9A-Z]{16}\b/g },
  { id: 'EC-005', name: 'GitHub PAT', severity: 'CRITICAL', re: /\b(?:ghp|gho|ghu|ghs|ghr)_[A-Za-z0-9]{36,}\b|\bgithub_pat_[A-Za-z0-9_]{22,}\b/g },
  { id: 'EC-006', name: 'Google / Gemini API Key', severity: 'CRITICAL', re: /\bAIza[0-9A-Za-z\-_]{35}\b/g },
  { id: 'EC-007', name: 'Stripe Live Key', severity: 'CRITICAL', re: /\b(?:sk|rk)_live_[0-9a-zA-Z]{24,}\b/g },
  { id: 'EC-009', name: 'HuggingFace Token', severity: 'HIGH', re: /\bhf_[A-Za-z0-9]{24,}\b/g },
  { id: 'EC-010', name: 'Groq API Key', severity: 'CRITICAL', re: /\bgsk_[A-Za-z0-9]{40,}\b/g },
  { id: 'EC-011', name: 'Private Key PEM', severity: 'CRITICAL', re: /-----BEGIN (?:RSA |EC |DSA |OPENSSH |PGP )?PRIVATE KEY-----/g },
  { id: 'EC-012', name: 'Database URL w/ Credentials', severity: 'CRITICAL', re: /\b(?:postgres|postgresql|mysql|mongodb(?:\+srv)?|redis|amqp):\/\/[^:\s'"]+:[^@\s'"]{6,}@[^\s'"]+/gi },
  { id: 'EC-014', name: 'Generic Secret Assignment', severity: 'HIGH', re: /\b(?:api_key|apikey|secret_key|client_secret|access_token|auth_token|db_password|supabase_service_role_key|vercel_token)\s*[:=]\s*['"]?([A-Za-z0-9_\-./+=]{16,})['"]?/gi }
];

module.exports = (req, res) => {
  if (req.method === 'OPTIONS') return res.status(204).end();
  if (req.method !== 'POST') {
    return res.status(405).json({ error: 'Method not allowed. Use POST.' });
  }
  const { content = '', filename = '.env' } = req.body || {};
  const text = String(content);
  const lines = text.split(/\r?\n/);
  const findings = [];
  const redactedLines = lines.map((line, idx) => {
    let out = line;
    for (const rule of RULES) {
      rule.re.lastIndex = 0;
      const m = rule.re.exec(line);
      if (m) {
        const raw = m[1] || m[0];
        const masked = raw.length > 8 ? `${raw.slice(0, 4)}...${raw.slice(-4)}` : '****';
        findings.push({
          rule_id: rule.id,
          rule_name: rule.name,
          severity: rule.severity,
          file: filename,
          line: idx + 1,
          redacted_match: masked
        });
        out = out.replace(raw, '[REDACTED_BY_ENV_CHECKER]');
        break;
      }
    }
    return out;
  });

  return res.status(200).json({
    gate_status: findings.length > 0 ? 'BLOCKED' : 'PASSED',
    findings,
    redacted_content: redactedLines.join('\n')
  });
};
