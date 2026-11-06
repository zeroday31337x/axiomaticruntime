import { spawn } from 'node:child_process';
import { setTimeout as sleep } from 'node:timers/promises';
import assert from 'node:assert/strict';
import { evaluateWithJev } from '../../src/jev-client.mjs';

const port = 19092;
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
    try { if ((await fetch(base + '/health')).ok) { ready = true; break; } } catch {}
    await sleep(100);
  }
  assert.ok(ready);
  const result = await evaluateWithJev({
    hostResult: { decision: 'RETAIN', branchId: 'test' },
    context: { route: '/health', method: 'GET' },
    endpoint: base + '/v1/classify', token, timeoutMs: 1000,
  });
  assert.equal(result.decision, 'GATE');
  assert.equal(result.jev.status, 'ok');
  const badToken = await evaluateWithJev({
    hostResult: { decision: 'RETAIN' }, context: { route: '/health', method: 'GET' },
    endpoint: base + '/v1/classify', token: 'wrong', timeoutMs: 1000,
  });
  assert.equal(badToken.decision, 'GATE');
  assert.equal(badToken.jev.status, 'unavailable');
  console.log('JEV client -> HTTP service smoke passed');
} finally { child.kill('SIGTERM'); }
