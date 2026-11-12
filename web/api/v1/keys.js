const { issueApiKey } = require('../_lib/auth');

module.exports = (req, res) => {
  if (req.method === 'OPTIONS') return res.status(204).end();
  if (req.method !== 'POST') {
    return res.status(405).json({ error: 'Method not allowed. Use POST.' });
  }
  const body = req.body || {};
  const issued = issueApiKey({
    project: body.project,
    environment: body.environment,
    owner: body.owner
  });
  return res.status(201).json(issued);
};
