const crypto = require('crypto');
const { verifyApiKey, extractApiKey } = require('../_lib/auth');

module.exports = (req, res) => {
  if (req.method === 'OPTIONS') return res.status(204).end();
  if (req.method !== 'POST') {
    return res.status(405).json({ error: 'Method not allowed. Use POST.' });
  }
  const key = extractApiKey(req);
  const auth = verifyApiKey(key);
  if (!auth.valid) {
    return res.status(401).json({ error: auth.reason });
  }
  const report = req.body || {};
  return res.status(200).json({
    accepted: true,
    audit_id: `aud_${crypto.randomBytes(6).toString('hex')}`,
    project: auth.project,
    gate_status: report.gate_status || 'UNKNOWN',
    findings_count: Array.isArray(report.findings) ? report.findings.length : 0,
    recorded_at: new Date().toISOString()
  });
};
