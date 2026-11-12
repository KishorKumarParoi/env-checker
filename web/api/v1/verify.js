const { verifyApiKey, extractApiKey } = require('../_lib/auth');

module.exports = (req, res) => {
  if (req.method === 'OPTIONS') return res.status(204).end();
  if (req.method !== 'POST') {
    return res.status(405).json({ error: 'Method not allowed. Use POST.' });
  }
  const key = extractApiKey(req);
  const result = verifyApiKey(key);
  if (!result.valid) {
    return res.status(401).json({ valid: false, error: result.reason });
  }
  const requestedEnv = (req.body && req.body.environment) || 'prod';
  if (result.environment !== 'all' && result.environment !== requestedEnv) {
    return res.status(403).json({
      valid: false,
      error: `Key scoped to '${result.environment}' cannot authorize '${requestedEnv}'`
    });
  }
  return res.status(200).json({
    valid: true,
    key_id: result.key_id,
    project: result.project,
    environment: result.environment,
    policy: 'STRICT_BLOCK_AND_PURGE'
  });
};
