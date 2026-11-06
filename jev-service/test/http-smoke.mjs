import { spawn } from 'node:child_process';
import assert from 'node:assert/strict';
import { setTimeout as sleep } from 'node:timers/promises';

const port = 19091;
const token = 'test-only-jev-service-token-1234567890';
const base = 'http://127.0.0.1:' + port;
const child = spawn(process.execPath, ['server.mjs'], {
  cwd: new URL('../', import.meta.url),
  env: { ...process.env, PORT: String(port), BIND_HOST: '127.0.0.1', JEV_SERVICE_TOKEN: token },
  stdio: 'pipe',
});
try {
  let ready = false;
  for (let i = 0; i < 50; i++) {
    if (child.exitCode !== null) throw new Error('service exited early');
    try {
      const health = await fetch(base + '/health');
      if (health.ok) { ready = true; break; }
    } catch {}
    await sleep(100);
  }
  assert.ok(ready, 'service failed to start');
  const payload = JSON.stringify({ schemaVersion: '1', context: { route: '/health', method: 'GET' } });
  const unauthorized = await fetch(base + '/v1/classify', { method: 'POST', body: payload });
  assert.equal(unauthorized.status, 401);
  const authorized = await fetch(base + '/v1/classify', {
    method: 'POST', headers: { authorization: 'Bearer ' + token, 'content-type': 'application/json' },
    body: payload,
  });
  assert.equal(authorized.status, 200);
  const data = await authorized.json();
  assert.equal(data.decision, 'FLAG');
  assert.equal(data.modelVersion, 'baseline-rules-0.1');
  const malformed = await fetch(base + '/v1/classify', {
    method: 'POST', headers: { authorization: 'Bearer ' + token }, body: '{broken',
  });
  assert.equal(malformed.status, 400);
  console.log('HTTP smoke: health, authentication, classification, malformed JSON passed');
} finally {
  child.kill('SIGTERM');
}
