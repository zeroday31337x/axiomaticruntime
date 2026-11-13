import test from 'node:test';
import assert from 'node:assert/strict';
import { DOMAIN, enumeratePaths, compileTree, traverseTree } from '../decision-tree-compiler.mjs';

test('all 96 bounded decision paths compile and evaluate consistently', () => {
  const paths = enumeratePaths();
  assert.equal(paths.length, 96);
  const tree = compileTree();
  assert.equal(tree.pathCount, paths.length);
  for (const p of paths) assert.equal(traverseTree(tree, p), p.final, JSON.stringify(p));
});
test('authentication and route policy denial always prune', () => {
  for (const p of enumeratePaths()) {
    if (!p.authenticated || !p.routeAllowed) assert.equal(p.final, 'PRUNE');
  }
});
test('rate limiting cannot grant access', () => {
  for (const p of enumeratePaths()) {
    if (p.rateLimited && p.authenticated && p.routeAllowed) assert.notEqual(p.final, 'RETAIN');
  }
});
test('unrecognized values fail closed and invalid domains are rejected', () => {
  const tree = compileTree();
  assert.equal(traverseTree(tree, { host: 'BOGUS' }), 'PRUNE');
  assert.throws(() => enumeratePaths({ ...DOMAIN, host: ['BOGUS'] }), /invalid finite domain/);
});
