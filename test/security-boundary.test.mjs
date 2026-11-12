import test from 'node:test';
import assert from 'node:assert/strict';
import { evaluateAxiomaticBranch as evaluate } from '../src/runtime.mjs';
import { validateProfile } from '../src/profile.mjs';

const valid = {
  schemaVersion: '1.0',
  name: 'Hardened Customer Profile',
  origin: 'customer-modified',
  policy: {
    allowedCommands: ['./status', './deploy'],
    allowedTools: ['read', 'write'],
    mutatingTools: ['write'],
    nonMutatingCommands: ['./status'],
  },
};
const decision = (proposal, explicitAction = false, profile = valid) =>
  evaluate({ proposal, explicitAction, profile }).decision;

test('unknown, missing and malformed proposal kinds PRUNE', () => {
  for (const proposal of [null, {}, [], { kind: 'execute' }, { tool: 'read' }, 'read'])
    assert.equal(decision(proposal), 'PRUNE');
});
test('unvalidated policy objects fail closed when evaluated directly', () => {
  for (const patch of [
    { policy: { ...valid.policy, mutatingTools: ['root'] } },
    { policy: { ...valid.policy, allowedTools: ['read', 42] } },
    { policy: { ...valid.policy, allowedCommands: ['./status', './status'] } },
    { policy: { ...valid.policy, allowedCommands: ['./status', '../sh'] } },
    { policy: { ...valid.policy, nonMutatingCommands: ['./deploy', './status', './unknown'] } },
  ]) {
    const profile = { ...valid, ...patch };
    assert.equal(validateProfile(profile).valid, false);
    assert.equal(decision({ kind: 'tool', tool: 'read' }, true, profile), 'PRUNE');
  }
});
test('invalid command syntax PRUNEs despite explicit approval', () => {
  for (const command of [
    './deploy $(id)', './deploy ' + String.fromCharCode(96) + 'id' + String.fromCharCode(96),
    './deploy $' + '{HOME}', './deploy (id)',
    './deploy *.json', './deploy "release"', './deploy --flag && ./status',
    './deploy\n./status', './deploy \\x', ' ./status', './status ',
  ]) assert.equal(decision({ kind: 'command', command }, true), 'PRUNE');
});
test('host approval is an exact boolean, never a truthy string', () => {
  for (const explicitAction of ['true', 1, {}, [], null])
    assert.equal(decision({ kind: 'tool', tool: 'write' }, explicitAction), 'GATE');
});
test('invalid structured tool identifiers fail closed', () => {
  for (const tool of ['write\n', ' write', 'write ', 'write\x00', ['write']])
    assert.equal(decision({ kind: 'tool', tool }, true), 'PRUNE');
});
test('cyclic and BigInt proposal arguments fail closed', () => {
  const cyclic = {}; cyclic.self = cyclic;
  assert.equal(decision({ kind: 'tool', tool: 'read', args: cyclic }, true), 'PRUNE');
  assert.equal(decision({ kind: 'tool', tool: 'read', args: { amount: 1n } }, true), 'PRUNE');
});
test('unbounded and malformed profile strings reject', () => {
  for (const value of [
    { ...valid, name: ' ' }, { ...valid, name: 'A'.repeat(129) },
    { ...valid, extra: 'ignored?' },
    { ...valid, policy: { ...valid.policy, extra: true } },
    { ...valid, policy: { ...valid.policy, allowedTools: ['read', 'read'] } },
    { ...valid, policy: { ...valid.policy, allowedTools: ['../tool'] } },
  ]) assert.equal(validateProfile(value).valid, false);
});
test('ordinary read calls RETAIN and mutating calls GATE/RETAIN correctly', () => {
  assert.equal(decision({ kind: 'tool', tool: 'read' }), 'RETAIN');
  assert.equal(decision({ kind: 'tool', tool: 'write' }), 'GATE');
  assert.equal(decision({ kind: 'tool', tool: 'write' }, true), 'RETAIN');
  assert.equal(decision({ kind: 'command', command: './status' }), 'RETAIN');
  assert.equal(decision({ kind: 'command', command: './deploy prod' }), 'GATE');
  assert.equal(decision({ kind: 'command', command: './deploy prod' }, true), 'RETAIN');
});

