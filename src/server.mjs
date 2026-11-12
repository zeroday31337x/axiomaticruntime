import http from 'node:http';
import fs from 'node:fs';
import { timingSafeEqual } from 'node:crypto';
import { evaluateAxiomaticBranch } from './runtime.mjs';
import { validateProfile } from './profile.mjs';

const MAX_BODY_BYTES = 1024 * 1024;
const port = Number(process.env.PORT ?? 8080);
const profilePath = process.env.AXIOMATIC_PROFILE || './profiles/zdx-validated-v1.json';
const token = process.env.AXIOMATIC_RUNTIME_TOKEN;
if (!Number.isInteger(port) || port < 1 || port > 65535) {
  console.error('PORT must be a valid TCP port');
  process.exit(1);
}
if (!token || Buffer.byteLength(token) < 32) {
  console.error('AXIOMATIC_RUNTIME_TOKEN must be set to at least 32 bytes');
  process.exit(1);
}
let profile;
try {
  profile = JSON.parse(fs.readFileSync(profilePath, 'utf8'));
  const checked = validateProfile(profile);
  if (!checked.valid) throw new Error(checked.errors.join('; '));
  console.log('profile', checked.classification, checked.hash);
} catch (error) {
  console.error('profile validation failed:', error.message);
  process.exit(1);
}
const expectedToken = Buffer.from(token);
function authorized(req) {
  const header = req.headers.authorization;
  if (typeof header !== 'string' || !header.startsWith('Bearer ')) return false;
  const supplied = Buffer.from(header.slice('Bearer '.length));
  return supplied.length === expectedToken.length && timingSafeEqual(supplied, expectedToken);
}
function send(res, status, payload) {
  if (res.writableEnded) return;
  res.statusCode = status;
  res.end(JSON.stringify(payload));
}
const server = http.createServer((req, res) => {
  res.setHeader('content-type', 'application/json');
  res.setHeader('cache-control', 'no-store');
  if (req.method === 'GET' && req.url === '/health') {
    return send(res, 200, { ok: true, version: '1.0.0' });
  }
  if (req.method !== 'POST' || req.url !== '/v1/evaluate') {
    return send(res, 404, { error: 'not_found' });
  }
  if (!authorized(req)) return send(res, 401, { error: 'unauthorized' });
  let size = 0;
  let tooLarge = false;
  const chunks = [];
  req.on('data', chunk => {
    if (tooLarge) return;
    size += chunk.length;
    if (size > MAX_BODY_BYTES) {
      tooLarge = true;
      res.setHeader('connection', 'close');
      send(res, 413, { error: 'body_too_large' });
      req.resume();
      return;
    }
    chunks.push(chunk);
  });
  req.on('end', () => {
    if (tooLarge) return;
    let input;
    try {
      input = JSON.parse(Buffer.concat(chunks, size).toString('utf8'));
    } catch {
      return send(res, 400, { error: 'invalid_json' });
    }
    if (!input || typeof input !== 'object' || Array.isArray(input))
      return send(res, 400, { error: 'invalid_request' });
    try {
      return send(res, 200, evaluateAxiomaticBranch({
        proposal: input.proposal, explicitAction: input.explicitAction === true, profile,
      }));
    } catch {
      return send(res, 500, { decision: 'PRUNE', reason: 'evaluation_failed' });
    }
  });
  req.on('error', () => {
    if (!tooLarge) send(res, 400, { error: 'invalid_request' });
  });
});
server.headersTimeout = 5000;
server.requestTimeout = 10000;
server.keepAliveTimeout = 5000;
server.maxHeadersCount = 32;
server.maxRequestsPerSocket = 100;
server.listen(port, '0.0.0.0');
