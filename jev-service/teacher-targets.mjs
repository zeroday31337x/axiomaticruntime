// Strict teacher-target contract. Teacher outputs are candidates, never policy truth.
export const CLASSES = Object.freeze(['ALLOW', 'DENY', 'FLAG']);
export function validateTeacherTarget(row) {
  if (!row || row.schemaVersion !== '1' || row.task !== 'jev_classification' ||
      row.labelSource !== 'teacher_candidate' || row.approvalStatus !== 'unreviewed' ||
      row.reviewed !== false || typeof row.scenarioGroup !== 'string' ||
      row.scenarioGroup.length < 1 || row.scenarioGroup.length > 256 ||
      !row.context || typeof row.context.route !== 'string' ||
      !row.context.route.startsWith('/') || row.context.route.length > 2048 ||
      !['GET','POST','PUT','PATCH','DELETE'].includes(row.context.method) ||
      !row.teacher || typeof row.teacher.modelId !== 'string' ||
      row.teacher.modelId.length < 1 || row.teacher.modelId.length > 256 ||
      !row.teacher.probabilities || typeof row.teacher.probabilities !== 'object' ||
      Array.isArray(row.teacher.probabilities) ||
      Object.keys(row.teacher.probabilities).sort().join(',') !== [...CLASSES].sort().join(',')) return false;
  const values = CLASSES.map(c => row.teacher.probabilities[c]);
  return values.every(v => typeof v === 'number' && Number.isFinite(v) && v >= 0 && v <= 1) &&
    Math.abs(values.reduce((a,b) => a + b, 0) - 1) <= 1e-6;
}
export function softTargets(row, temperature = 1) {
  if (!validateTeacherTarget(row)) throw new TypeError('invalid unreviewed teacher target');
  if (!Number.isFinite(temperature) || temperature <= 0 || temperature > 100) throw new RangeError('invalid temperature');
  const weights = CLASSES.map(c => Math.pow(Math.max(row.teacher.probabilities[c], 1e-12), 1 / temperature));
  const total = weights.reduce((a,b) => a + b, 0);
  return Object.fromEntries(CLASSES.map((c,i) => [c, weights[i] / total]));
}
