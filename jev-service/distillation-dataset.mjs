import { enumeratePaths } from './decision-tree-compiler.mjs';
import { createHash } from 'node:crypto';

// Policy supervision is for final host action, NOT for JEV's three-class labels.
// Teacher-derived model labels must be independently reviewed before use.
const canonical = p => JSON.stringify([p.host, p.jev, p.authenticated, p.routeAllowed, p.rateLimited]);
export function generatePolicyDataset() {
  return enumeratePaths().map(p => {
    const key = canonical(p);
    const digest = createHash('sha256').update(key).digest('hex');
    return Object.freeze({
      schemaVersion: '1',
      task: 'host_action',
      labelSource: 'deterministic_policy',
      policyVersion: 'decision-tree-v1',
      scenarioId: digest.slice(0, 16),
      scenarioGroup: 'matrix-' + digest.slice(0, 16),
      input: { host: p.host, jev: p.jev, authenticated: p.authenticated,
        routeAllowed: p.routeAllowed, rateLimited: p.rateLimited },
      label: p.final,
      split: Number.parseInt(digest.slice(0, 8), 16) % 5 === 0 ? 'holdout' : 'train',
    });
  });
}
export function validateTeacherExample(row) {
  if (!row || row.task !== 'jev_classification' || row.labelSource !== 'teacher_candidate') return false;
  if (!['ALLOW', 'DENY', 'FLAG'].includes(row.label)) return false;
  if (!row.scenarioGroup || typeof row.scenarioGroup !== 'string') return false;
  if (!row.context || typeof row.context.route !== 'string' ||
      typeof row.context.method !== 'string') return false;
  // Teacher suggestions cannot be treated as independent policy ground truth.
  return row.reviewed === false && row.approvalStatus === 'unreviewed';
}
export function exportJsonl(rows) {
  return rows.map(r => JSON.stringify(r)).join('\n') + '\n';
}
