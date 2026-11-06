export function applyJevAdvisory(hostDecision, modelDecision) {
  if (!['RETAIN', 'GATE', 'PRUNE'].includes(hostDecision)) return 'PRUNE';
  if (hostDecision !== 'RETAIN') return hostDecision;
  if (modelDecision === 'DENY') return 'PRUNE';
  if (modelDecision === 'ALLOW') return 'RETAIN';
  return 'GATE';
}
