import test from 'node:test';
import assert from 'node:assert/strict';
import { applyJevAdvisory } from '../src/jev-adapter.mjs';

test('JEV cannot override host gates or denials', () => {
  for (const host of ['GATE', 'PRUNE']) {
    for (const model of ['ALLOW', 'DENY', 'FLAG', undefined]) {
      assert.equal(applyJevAdvisory(host, model), host);
    }
  }
});
test('JEV may restrict a host-retained action', () => {
  assert.equal(applyJevAdvisory('RETAIN', 'DENY'), 'PRUNE');
  assert.equal(applyJevAdvisory('RETAIN', 'FLAG'), 'GATE');
  assert.equal(applyJevAdvisory('RETAIN', undefined), 'GATE');
  assert.equal(applyJevAdvisory('RETAIN', 'ALLOW'), 'RETAIN');
});
test('invalid host decision fails closed', () => {
  assert.equal(applyJevAdvisory('UNKNOWN', 'ALLOW'), 'PRUNE');
});
