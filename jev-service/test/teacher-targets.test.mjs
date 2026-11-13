import test from 'node:test';
import assert from 'node:assert/strict';
import { validateTeacherTarget, softTargets } from '../teacher-targets.mjs';
const row = { schemaVersion: '1', task: 'jev_classification', labelSource: 'teacher_candidate',
  approvalStatus: 'unreviewed', reviewed: false, scenarioGroup: 'family-1',
  context: { route: '/health', method: 'GET' },
  teacher: { modelId: 'fixture-teacher', probabilities: { ALLOW: 0.8, DENY: 0.1, FLAG: 0.1 } } };
test('accepts normalized unreviewed teacher distributions', () => {
  assert.equal(validateTeacherTarget(row), true);
  assert.deepEqual(softTargets(row, 1), row.teacher.probabilities);
  const softened = softTargets(row, 2);
  assert.ok(softened.ALLOW < 0.8);
  assert.ok(Math.abs(Object.values(softened).reduce((a,b) => a+b, 0) - 1) < 1e-9);
});
test('rejects invalid, privileged, or non-finite teacher probabilities', () => {
  for (const bad of [
    { ...row, approvalStatus: 'approved' },
    { ...row, reviewed: true },
    { ...row, teacher: { ...row.teacher, probabilities: { ALLOW: 0.9, DENY: 0.9, FLAG: 0.1 } } },
    { ...row, teacher: { ...row.teacher, probabilities: { ALLOW: NaN, DENY: 0, FLAG: 1 } } },
    { ...row, teacher: { ...row.teacher, probabilities: { ALLOW: -0.1, DENY: 0.2, FLAG: 0.9 } } },
  ]) assert.equal(validateTeacherTarget(bad), false);
  assert.throws(() => softTargets(row, 0), /temperature/);
});
