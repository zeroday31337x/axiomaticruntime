import test from 'node:test';
import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import { validateArtifact, predict } from '../linear-model.mjs';
const artifact = JSON.parse(readFileSync(process.env.JEV_TEST_ARTIFACT, 'utf8'));
test('trained artifact matches Node inference schema', () => {
  assert.equal(validateArtifact(artifact), true);
  assert.equal(artifact.approvalStatus, 'experimental');
  const decision = predict({ route: '/health', method: 'GET' }, artifact);
  assert.ok(['ALLOW','DENY','FLAG'].includes(decision.decision));
});
