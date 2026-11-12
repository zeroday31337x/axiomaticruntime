import { createHash } from 'node:crypto';
import { validateProfile } from './profile.mjs';

export const IMMUTABLE_INVARIANTS = Object.freeze({
  onlyRetainExecutes: true, trustedContextIsHostOwned: true, failClosedOnInvalidProfile: true,
});
function reject(branchId, reason) { return { decision: 'PRUNE', branchId, reason }; }
function result(decision, branchId, reason) { return { decision, branchId, reason }; }

export function evaluateAxiomaticBranch({ proposal, profile, explicitAction = false } = {}) {
  // The production host owns the policy and explicitAction. No proposal or model
  // content may alter the policy, approval context, or executor.
  if (!validateProfile(profile).valid) return reject('invalid-profile', 'valid runtime profile required');
  if (!proposal || typeof proposal !== 'object' || Array.isArray(proposal) ||
      !['reply', 'command', 'tool'].includes(proposal.kind))
    return reject('invalid-proposal', 'explicit proposal kind required');

  let normalized;
  try {
    normalized = JSON.stringify({
      kind: proposal.kind, reply: proposal.reply,
      command: proposal.command, tool: proposal.tool, args: proposal.args,
    });
  } catch {
    return reject('invalid-proposal', 'proposal must be serializable');
  }
  if (!normalized || normalized.length > 65536)
    return reject('invalid-proposal', 'proposal exceeds limits');
  const branchId = createHash('sha256').update(normalized).digest('hex').slice(0, 16);
  const policy = profile.policy;
  const approved = explicitAction === true;

  if (proposal.kind === 'reply') {
    return typeof proposal.reply === 'string' && proposal.reply.trim() &&
      proposal.reply.length <= 16384
      ? result('RETAIN', branchId, 'schema-valid reply')
      : reject(branchId, 'empty or oversized reply');
  }
  if (proposal.kind === 'command') {
    const raw = proposal.command;
    if (typeof raw !== 'string' || !raw || raw.length > 1024 || raw !== raw.trim())
      return reject(branchId, 'invalid or non-canonical command');
    // Host implementations must pass validated argument arrays, never execute
    // this as an untrusted shell string. Reject shell metacharacters regardless.
    if (/[\u0000-\u001f\u007f;&|<>\x60$\\(){}\[\]*?!'"]/.test(raw))
      return reject(branchId, 'command contains prohibited shell syntax');
    const base = raw.split(/\s+/)[0].toLowerCase();
    if (!base.startsWith('./') || !policy.allowedCommands.includes(base))
      return reject(branchId, 'command outside allowlist');
    if (!approved && !policy.nonMutatingCommands.includes(base))
      return result('GATE', branchId, 'explicit action required');
    return result('RETAIN', branchId, 'allowed command');
  }
  const tool = proposal.tool;
  if (typeof tool !== 'string' || !tool || tool.length > 128 ||
      tool !== tool.trim() || /[\u0000-\u001f\u007f]/.test(tool) ||
      !policy.allowedTools.includes(tool))
    return reject(branchId, 'tool outside canonical allowlist');
  if (policy.mutatingTools.includes(tool) && !approved)
    return result('GATE', branchId, 'mutating tool requires explicit action');
  // Tool arguments still require schema/authorization checks by the host executor.
  return result('RETAIN', branchId, 'allowed tool call');
}
