import test from 'node:test';
import assert from 'node:assert/strict';
import { classifyRoute } from '../src/jev-router.mjs';

const args = { authenticated: true, policyAllows: true, route: '/v1/health', method: 'GET', jev: { endpoint: 'http://localhost/internal/jev', token: 'test' } };
test('host policy denial bypasses JEV', async () => {
  const r = await classifyRoute({ ...args, authenticated: false, fetchImpl: async () => { throw Error('called'); } });
  assert.equal(r.decision, 'DENY');
});
test('JEV ALLOW permits only already-authorized route', async () => {
  const r = await classifyRoute({ ...args, fetchImpl: async () => ({ ok: true, json: async () => ({ decision: 'ALLOW' }) }) });
  assert.equal(r.decision, 'ALLOW');
});
test('JEV outage flags for review', async () => {
  const r = await classifyRoute({ ...args, fetchImpl: async () => { throw Error('offline'); } });
  assert.equal(r.decision, 'FLAG');
});
