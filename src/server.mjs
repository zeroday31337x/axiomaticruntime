import http from 'node:http';
import fs from 'node:fs';
import { timingSafeEqual } from 'node:crypto';
import { evaluateAxiomaticBranch } from './runtime.mjs';
import { validateProfile } from './profile.mjs';

const port = Number(process.env.PORT || 8080);
const profilePath = process.env.AXIOMATIC_PROFILE || './profiles/zdx-validated-v1.json';
const token = process.env.AXIOMATIC_RUNTIME_TOKEN;
if (!token || Buffer.byteLength(token) < 32) {
  console.error('AXIOMATIC_RUNTIME_TOKEN must be set to at least 32 bytes');
  process.exit(1);
}

let profile;
try {
  profile = JSON.parse(fs.readFileSync(profilePath, 'utf8'));
  const v = validateProfile(profile);
  if (!v.valid) throw new Error(v.errors.join('; '));
  console.log('profile', v.classification, v.hash);
} catch (e) {
  console.error('profile validation failed:', e.message);
  process.exit(1);
}

function authorized(req) {
  const value = req.headers.authorization || '';
  const prefix = 'Bearer ';
  if (!value.startsWith(prefix)) return false;
  const supplied = Buffer.from(value.slice(prefix.length));
  const expected = Buffer.from(token);
  return supplied.length === expected.length && timingSafeEqual(supplied, expected);
}

http.createServer((req, res) => {
  res.setHeader('content-type', 'application/json');
  if (req.method === 'GET' && req.url === '/health') {
    res.end(JSON.stringify({ ok: true, version: '1.0.0' }));
    return;
  }
  if (req.method !== 'POST' || req.url !== '/v1/evaluate') {
    res.statusCode = 404; res.end(JSON.stringify({ error: 'not_found' })); return;
  }
  if (!authorized(req)) {
    res.statusCode = 401; res.end(JSON.stringify({ error: 'unauthorized' })); return;
  }
  let body = '', size = 0, done = false;
  req.on('data', chunk => {
    size += chunk.length;
    if (size > 1048576) {
      done = true; res.statusCode = 413; res.end(JSON.stringify({ error: 'body_too_large' })); req.destroy();
    } else body += chunk;
  });
  req.on('end', () => {
    if (done) return;
    try {
      const input = JSON.parse(body || '{}');
      res.end(JSON.stringify(evaluateAxiomaticBranch({ proposal: input.proposal, explicitAction: input.explicitAction === true, profile })));
    } catch {
      res.statusCode = 400; res.end(JSON.stringify({ error: 'invalid_json' }));
    }
  });
}).listen(port, '0.0.0.0');
