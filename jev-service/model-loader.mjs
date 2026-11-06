import { readFileSync } from 'node:fs';
import { createHash } from 'node:crypto';
import { validateArtifact, predict } from './linear-model.mjs';

// Loading is explicit, immutable for process lifetime, and restricted to shadow mode.
// No production enforcement or automatic model approval.
export function loadExperimentalModel({ path, expectedSha256, enabled = false }) {
  if (!enabled) return null;
  if (!path || !/^[a-f0-9]{64}$/i.test(expectedSha256 || '')) {
    throw new Error('experimental model requires path and expected SHA256');
  }
  const bytes = readFileSync(path);
  if (bytes.length > 1048576) throw new Error('artifact too large');
  const actual = createHash('sha256').update(bytes).digest('hex');
  if (actual.toLowerCase() !== expectedSha256.toLowerCase()) throw new Error('artifact checksum mismatch');
  const artifact = JSON.parse(bytes.toString('utf8'));
  if (!validateArtifact(artifact) || artifact.trained !== true || artifact.approvalStatus !== 'experimental') {
    throw new Error('invalid experimental model artifact');
  }
  const frozen = structuredClone(artifact);
  frozen.weights.forEach(Object.freeze);
  Object.freeze(frozen.weights);
  Object.freeze(frozen);
  return Object.freeze({
    version: 'experimental-sha256-' + actual.slice(0, 12),
    predict: context => predict(context, frozen),
  });
}
