import { resolveMatrix } from './decision-matrix.mjs';

// Deterministic finite-domain decision tree compiler. This is a training-data
// generator and verifier, not an authorization endpoint.
export const DOMAIN = Object.freeze({
  host: Object.freeze(['RETAIN', 'GATE', 'PRUNE']),
  jev: Object.freeze(['ALLOW', 'DENY', 'FLAG', 'INVALID']),
  authenticated: Object.freeze([true, false]),
  routeAllowed: Object.freeze([true, false]),
  rateLimited: Object.freeze([true, false]),
});

export function evaluatePath(p) {
  // Security preconditions can only reduce privilege; never elevate a host result.
  if (!p.authenticated || !p.routeAllowed) return 'PRUNE';
  if (p.rateLimited) return p.host === 'PRUNE' ? 'PRUNE' : 'GATE';
  return resolveMatrix(p.host, p.jev);
}
export function enumeratePaths(domain = DOMAIN) {
  const keys = Object.keys(DOMAIN);
  for (const key of keys) {
    if (!Array.isArray(domain[key]) || domain[key].length === 0 ||
      domain[key].some(v => !DOMAIN[key].includes(v))) {
      throw new TypeError('invalid finite domain: ' + key);
    }
  }
  let paths = [{}];
  for (const key of keys) {
    paths = paths.flatMap(p => domain[key].map(v => ({ ...p, [key]: v })));
    if (paths.length > 100000) throw new RangeError('decision space too large');
  }
  return paths.map(p => Object.freeze({ ...p, final: evaluatePath(p) }));
}
export function compileTree(domain = DOMAIN) {
  const paths = enumeratePaths(domain);
  const keys = Object.keys(DOMAIN);
  const build = (rows, depth) => {
    if (rows.every(r => r.final === rows[0].final)) return { decision: rows[0].final };
    if (depth >= keys.length) throw new Error('non-deterministic leaf');
    const key = keys[depth];
    return { test: key, branches: domain[key].map(value => ({
      value, node: build(rows.filter(r => r[key] === value), depth + 1),
    })) };
  };
  return Object.freeze({ schemaVersion: '1', pathCount: paths.length, root: build(paths, 0) });
}
export function traverseTree(tree, input) {
  let node = tree.root;
  while (node.test) {
    const branch = node.branches.find(b => b.value === input[node.test]);
    if (!branch) return 'PRUNE';
    node = branch.node;
  }
  return node.decision;
}
