import test from 'node:test';
import assert from 'node:assert/strict';
import { HOST, JEV, enumerateDecisionPaths, resolveMatrix } from '../decision-matrix.mjs';
import { applyJevAdvisory } from '../../src/jev-adapter.mjs';

test('all 12 finite host/JEV outcomes are defined exactly once', () => {
  const paths = enumerateDecisionPaths();
  assert.equal(paths.length, HOST.length * JEV.length);
  assert.equal(new Set(paths.map(p => p.host + ':' + p.jev)).size, paths.length);
  for (const p of paths) assert.equal(resolveMatrix(p.host, p.jev), p.final);
});
test('GATE and PRUNE cannot be elevated by any JEV decision', () => {
  for (const jev of JEV) {
    assert.equal(resolveMatrix('GATE', jev), 'GATE');
    assert.equal(resolveMatrix('PRUNE', jev), 'PRUNE');
  }
});
test('invalid or missing JEV decision cannot retain', () => {
  for (const value of ['INVALID', 'UNKNOWN', null, undefined]) {
    assert.equal(resolveMatrix('RETAIN', value), 'GATE');
  }
});
test('matrix agrees with existing runtime adapter for valid predictions', () => {
  for (const host of HOST) for (const jev of ['ALLOW', 'DENY', 'FLAG']) {
    const result = applyJevAdvisory({ decision: host }, jev);
    assert.equal(result.decision, resolveMatrix(host, jev), host + '/' + jev);
  }
});
