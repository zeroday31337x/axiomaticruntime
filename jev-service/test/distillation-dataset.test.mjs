import test from 'node:test';
import assert from 'node:assert/strict';
import { generatePolicyDataset, validateTeacherExample, exportJsonl } from '../distillation-dataset.mjs';

test('generates 96 deterministic and uniquely identified host-action examples', () => {
  const rows = generatePolicyDataset();
  assert.equal(rows.length, 96);
  assert.equal(new Set(rows.map(r => r.scenarioId)).size, 96);
  assert.ok(rows.every(r => r.task === 'host_action' && r.labelSource === 'deterministic_policy'));
  assert.ok(rows.every(r => ['RETAIN', 'GATE', 'PRUNE'].includes(r.label)));
  assert.ok(rows.some(r => r.split === 'train'));
  assert.ok(rows.some(r => r.split === 'holdout'));
  assert.deepEqual(rows, generatePolicyDataset());
  assert.equal(exportJsonl(rows).trim().split('\n').length, 96);
});
test('teacher candidates are segregated and not promoted to ground truth', () => {
  const candidate = { task: 'jev_classification', labelSource: 'teacher_candidate',
    label: 'FLAG', scenarioGroup: 'attack-family-1',
    context: { route: '/admin', method: 'POST' }, reviewed: false, approvalStatus: 'unreviewed' };
  assert.equal(validateTeacherExample(candidate), true);
  assert.equal(validateTeacherExample({ ...candidate, label: 'RETAIN' }), false);
  assert.equal(validateTeacherExample({ ...candidate, labelSource: 'deterministic_policy' }), false);
  assert.equal(validateTeacherExample({ ...candidate, approvalStatus: 'approved' }), false);
});
