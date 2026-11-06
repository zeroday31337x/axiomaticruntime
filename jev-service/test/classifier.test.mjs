import test from 'node:test';
import assert from 'node:assert/strict';
import { classify } from '../classifier.mjs';
test('baseline is never a permissive security authority', () => {
  for (const input of [
    { schemaVersion: '1', context: { route: '/health', method: 'GET' } },
    { schemaVersion: '1', context: { route: '/admin', method: 'POST' } },
    { schemaVersion: '1', context: { route: '/../../etc', method: 'GET' } },
    { schemaVersion: '1', context: { kind: 'tool', tool: 'read' } },
    {},
  ]) assert.notEqual(classify(input).decision, 'ALLOW');
});
test('invalid inputs flag', () => assert.equal(classify(null).decision, 'FLAG'));
