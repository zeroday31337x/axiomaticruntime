// Authoritative finite host/JEV decision matrix. No learned model may override it.
export const HOST = Object.freeze(['RETAIN', 'GATE', 'PRUNE']);
export const JEV = Object.freeze(['ALLOW', 'DENY', 'FLAG', 'INVALID']);
export const MATRIX = Object.freeze({
  RETAIN: Object.freeze({ ALLOW: 'RETAIN', DENY: 'PRUNE', FLAG: 'GATE', INVALID: 'GATE' }),
  GATE: Object.freeze({ ALLOW: 'GATE', DENY: 'GATE', FLAG: 'GATE', INVALID: 'GATE' }),
  PRUNE: Object.freeze({ ALLOW: 'PRUNE', DENY: 'PRUNE', FLAG: 'PRUNE', INVALID: 'PRUNE' }),
});
export function resolveMatrix(host, jev) {
  if (!HOST.includes(host)) throw new TypeError('unknown host decision');
  return MATRIX[host][JEV.includes(jev) ? jev : 'INVALID'];
}
export function enumerateDecisionPaths() {
  return HOST.flatMap(host => JEV.map(jev => Object.freeze({
    host, jev, final: resolveMatrix(host, jev),
  })));
}
