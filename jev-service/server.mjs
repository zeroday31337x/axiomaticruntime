import http from 'node:http';
import { timingSafeEqual } from 'node:crypto';
import { classify } from './classifier.mjs';
import { loadExperimentalModel } from './model-loader.mjs';
const shadow = loadExperimentalModel({ path: process.env.JEV_EXPERIMENTAL_MODEL_PATH, expectedSha256: process.env.JEV_EXPERIMENTAL_MODEL_SHA256, enabled: process.env.JEV_SHADOW_MODE === 'true' });
const token = process.env.JEV_SERVICE_TOKEN;
if (!token || Buffer.byteLength(token) < 32) {
  console.error('JEV_SERVICE_TOKEN must be at least 32 bytes'); process.exit(1);
}
const port = Number(process.env.PORT || 8091);
if (!Number.isInteger(port) || port < 1 || port > 65535) process.exit(1);
const host = process.env.BIND_HOST || '127.0.0.1';
function authorized(req) {
  const header = req.headers.authorization || '';
  if (!header.startsWith('Bearer ')) return false;
  const actual = Buffer.from(header.slice(7));
  const expected = Buffer.from(token);
  return actual.length === expected.length && timingSafeEqual(actual, expected);
}
http.createServer((req, res) => {
  res.setHeader('content-type', 'application/json');
  res.setHeader('cache-control', 'no-store');
  if (req.method === 'GET' && req.url === '/health') {
    res.end(JSON.stringify({ ok: true, modelVersion: 'baseline-rules-0.1', trained: false, shadowLoaded: Boolean(shadow) })); return;
  }
  if (req.method !== 'POST' || req.url !== '/v1/classify') {
    res.writeHead(404).end(JSON.stringify({ error: 'not_found' })); return;
  }
  if (!authorized(req)) {
    res.writeHead(401).end(JSON.stringify({ error: 'unauthorized' })); return;
  }
  let size = 0; const chunks = [];
  req.on('data', chunk => {
    size += chunk.length;
    if (size > 16384) { res.writeHead(413).end(JSON.stringify({ error: 'too_large' })); req.destroy(); }
    else chunks.push(chunk);
  });
  req.on('end', () => {
    if (size > 16384) return;
    try {
      const input = JSON.parse(Buffer.concat(chunks).toString('utf8'));
      const result = classify(input);
      // Shadow results are for controlled offline comparison, never enforcement.
      if (shadow) {
        const candidate = shadow.predict(input?.context);
        result.shadow = { decision: candidate.decision, reason: candidate.reason, modelVersion: shadow.version };
      }
      res.end(JSON.stringify(result));
    } catch { res.writeHead(400).end(JSON.stringify({ error: 'invalid_json' })); }
  });
}).listen(port, host);
