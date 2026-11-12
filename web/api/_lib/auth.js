const crypto = require('crypto');

const SECRET = process.env.ENV_CHECKER_MASTER_SECRET || 'kishor-tech-env-checker-hmac-root-2026';

function signPayload(payloadB64) {
  return crypto.createHmac('sha256', SECRET).update(payloadB64).digest('hex').slice(0, 24);
}

function issueApiKey({ project = 'default-project', environment = 'all', owner = 'developer' } = {}) {
  const cleanProject = String(project).replace(/[^a-zA-Z0-9._-]/g, '').slice(0, 40) || 'default-project';
  const cleanEnv = ['dev', 'test', 'stage', 'prod', 'all'].includes(environment) ? environment : 'all';
  const keyId = crypto.randomBytes(4).toString('hex');
  const payload = JSON.stringify({
    id: keyId,
    p: cleanProject,
    e: cleanEnv,
    o: String(owner).slice(0, 32),
    ts: Date.now()
  });
  const payloadB64 = Buffer.from(payload, 'utf8').toString('base64url');
  const sig = signPayload(payloadB64);
  return {
    api_key: `ec_live_${payloadB64}.${sig}`,
    key_id: keyId,
    project: cleanProject,
    environment: cleanEnv,
    created_at: new Date().toISOString()
  };
}

function verifyApiKey(rawKey) {
  if (!rawKey || typeof rawKey !== 'string' || !rawKey.startsWith('ec_live_')) {
    return { valid: false, reason: 'Missing or malformed ec_live_ API key' };
  }
  const token = rawKey.slice('ec_live_'.length);
  const parts = token.split('.');
  if (parts.length !== 2) {
    return { valid: false, reason: 'Invalid key structure' };
  }
  const [payloadB64, sig] = parts;
  const expected = signPayload(payloadB64);
  const a = Buffer.from(sig, 'utf8');
  const b = Buffer.from(expected, 'utf8');
  if (a.length !== b.length || !crypto.timingSafeEqual(a, b)) {
    return { valid: false, reason: 'Invalid HMAC signature' };
  }
  try {
    const decoded = JSON.parse(Buffer.from(payloadB64, 'base64url').toString('utf8'));
    return {
      valid: true,
      key_id: decoded.id,
      project: decoded.p,
      environment: decoded.e,
      owner: decoded.o
    };
  } catch {
    return { valid: false, reason: 'Corrupted key payload' };
  }
}

function extractApiKey(req) {
  const headerKey = req.headers['x-api-key'];
  if (headerKey) return String(headerKey).trim();
  const auth = req.headers['authorization'];
  if (auth && String(auth).toLowerCase().startsWith('bearer ')) {
    return String(auth).slice(7).trim();
  }
  return '';
}

module.exports = { issueApiKey, verifyApiKey, extractApiKey };
