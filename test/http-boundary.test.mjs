import test from 'node:test';
import assert from 'node:assert/strict';
import net from 'node:net';
import { spawn } from 'node:child_process';
import { once } from 'node:events';

const token = 'test-only-secret-'.repeat(3);
function reservePort() {
  return new Promise((resolve, reject) => {
    const server = net.createServer();
    server.once('error', reject);
    server.listen(0, '127.0.0.1', () => {
      const { port } = server.address();
      server.close(() => resolve(port));
    });
  });
}
async function ready(url, timeoutMs = 3000) {
  const started = Date.now();
  while (Date.now() - started < timeoutMs) {
    try {
      const r = await fetch(url + '/health');
      if (r.ok) return;
    } catch {}
    await new Promise(resolve => setTimeout(resolve, 40));
  }
  throw new Error('test server did not start');
}
test('HTTP authorization, bounds, fail-closed decisions and health', async () => {
  const port = await reservePort();
  const url = 'http://127.0.0.1:' + port;
  const child = spawn(process.execPath, ['src/server.mjs'], {
    cwd: new URL('..', import.meta.url).pathname,
    env: { ...process.env, PORT: String(port), AXIOMATIC_RUNTIME_TOKEN: token },
    stdio: 'ignore',
  });
  try {
    await ready(url);
    const health = await fetch(url + '/health');
    assert.equal(health.status, 200);
    assert.deepEqual(await health.json(), { ok: true, version: '1.0.0' });

    const noToken = await fetch(url + '/v1/evaluate', {
      method: 'POST', body: JSON.stringify({ proposal: { kind: 'reply', reply: 'ok' } }),
    });
    assert.equal(noToken.status, 401);

    const headers = { authorization: 'Bearer ' + token, 'content-type': 'application/json' };
    const bad = await fetch(url + '/v1/evaluate', {
      method: 'POST', headers, body: JSON.stringify({ proposal: { kind: 'tool', tool: 'not-listed' }, explicitAction: true }),
    });
    assert.equal(bad.status, 200);
    assert.equal((await bad.json()).decision, 'PRUNE');

    const good = await fetch(url + '/v1/evaluate', {
      method: 'POST', headers, body: JSON.stringify({ proposal: { kind: 'command', command: './status' } }),
    });
    assert.equal((await good.json()).decision, 'RETAIN');

    const malformed = await fetch(url + '/v1/evaluate', {
      method: 'POST', headers, body: '{not json}',
    });
    assert.equal(malformed.status, 400);

    const huge = await fetch(url + '/v1/evaluate', {
      method: 'POST', headers, body: JSON.stringify({ proposal: { kind: 'reply', reply: 'A'.repeat(1048576) } }),
    });
    assert.equal(huge.status, 413);
  } finally {
    child.kill('SIGTERM');
    if (child.exitCode === null && child.signalCode === null) await once(child, 'exit');
  }
});

