import test from 'node:test';
import assert from 'node:assert/strict';
import { mkdtempSync, writeFileSync, rmSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { createHash } from 'node:crypto';
import { loadExperimentalModel } from '../model-loader.mjs';
import { featureNames } from '../linear-model.mjs';

test('experimental model is disabled by default', () => {
  assert.equal(loadExperimentalModel({}), null);
});
test('model requires pinned checksum and valid artifact', () => {
  const dir = mkdtempSync(join(tmpdir(), 'jev-test-'));
  try {
    const path = join(dir, 'model.json');
    const artifact = { schemaVersion: '1', classes: ['ALLOW','DENY','FLAG'], featureNames: [...featureNames],
      weights: Array.from({ length: 3 }, () => Array(featureNames.length).fill(0)),
      trained: true, approvalStatus: 'experimental' };
    const bytes = JSON.stringify(artifact);
    writeFileSync(path, bytes);
    const sha = createHash('sha256').update(bytes).digest('hex');
    assert.throws(() => loadExperimentalModel({ path, expectedSha256: '0'.repeat(64), enabled: true }), /checksum/);
    const model = loadExperimentalModel({ path, expectedSha256: sha, enabled: true });
    assert.equal(model.predict({ route: '/health', method: 'GET' }).decision, 'FLAG');
    assert.match(model.version, /^experimental-sha256-/);
  } finally { rmSync(dir, { recursive: true, force: true }); }
});
