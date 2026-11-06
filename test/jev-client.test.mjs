import test from 'node:test';
import assert from 'node:assert/strict';
import { evaluateWithJev } from '../src/jev-client.mjs';

const base = { decision: 'RETAIN', branchId: 'example' };
const params = { hostResult: base, context: { kind: 'tool', tool: 'read' }, endpoint: 'http://localhost/internal/jev', token: 'test-token' };
test('model ALLOW retains host-approved action', async () => {
  const r = await evaluateWithJev({ ...params, fetchImpl: async () => ({ ok: true, json: async () => ({ decision: 'ALLOW', modelVersion: 'test' }) }) });
  assert.equal(r.decision, 'RETAIN');
});
test('model DENY restricts action', async () => {
  const r = await evaluateWithJev({ ...params, fetchImpl: async () => ({ ok: true, json: async () => ({ decision: 'DENY' }) }) });
  assert.equal(r.decision, 'PRUNE');
});
test('invalid model output gates action', async () => {
  const r = await evaluateWithJev({ ...params, fetchImpl: async () => ({ ok: true, json: async () => ({ decision: 'SUPER_ALLOW' }) }) });
  assert.equal(r.decision, 'GATE');
});
test('network error gates action', async () => {
  const r = await evaluateWithJev({ ...params, fetchImpl: async () => { throw Error('offline'); } });
  assert.equal(r.decision, 'GATE');
});
test('host denial never calls model', async () => {
  const r = await evaluateWithJev({ ...params, hostResult: { decision: 'PRUNE' }, fetchImpl: async () => { throw Error('should not call'); } });
  assert.equal(r.decision, 'PRUNE');
});
