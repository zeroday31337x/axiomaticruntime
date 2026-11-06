// Compact CPU-only multiclass linear classifier. This is an inference engine,
// not a pre-trained JEV model. Weights must come from an independently validated artifact.
const CLASSES = ['ALLOW', 'DENY', 'FLAG'];
const FEATURES = ['bias', 'method_get', 'method_write', 'route_health', 'route_admin', 'route_auth', 'route_unknown', 'route_suspicious'];
export const featureNames = Object.freeze(FEATURES);
export function features(context) {
  const method = context?.method;
  const route = context?.route;
  if (typeof method !== 'string' || typeof route !== 'string' || !route.startsWith('/') || route.length > 2048) return null;
  const suspicious = /[\\\u0000-\u001f]/.test(route) || route.includes('..') || /%2f|%5c|%00/i.test(route);
  return [
    1, Number(method === 'GET'), Number(['POST','PUT','PATCH','DELETE'].includes(method)),
    Number(route === '/health' || route === '/v1/health'),
    Number(route.startsWith('/admin')), Number(route.startsWith('/auth')),
    Number(!['/health','/v1/health'].includes(route) && !route.startsWith('/admin') && !route.startsWith('/auth')),
    Number(suspicious),
  ];
}
export function validateArtifact(artifact) {
  return artifact?.schemaVersion === '1' && artifact?.classes?.join(',') === CLASSES.join(',') &&
    artifact?.featureNames?.join(',') === FEATURES.join(',') &&
    Array.isArray(artifact.weights) && artifact.weights.length === CLASSES.length &&
    artifact.weights.every(row => Array.isArray(row) && row.length === FEATURES.length && row.every(Number.isFinite));
}
export function predict(context, artifact, minMargin = 1) {
  const vector = features(context);
  if (!vector || !validateArtifact(artifact)) return { decision: 'FLAG', reason: 'invalid_model_or_context' };
  const scores = artifact.weights.map(row => row.reduce((sum, w, i) => sum + w * vector[i], 0));
  const ranking = scores.map((score, i) => ({ score, decision: CLASSES[i] })).sort((a,b) => b.score - a.score);
  if (ranking[0].score - ranking[1].score < minMargin) return { decision: 'FLAG', reason: 'low_margin' };
  return { decision: ranking[0].decision, reason: 'model_classification' };
}
