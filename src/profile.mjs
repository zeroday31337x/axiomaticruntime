import { createHash } from 'node:crypto';

export const PROFILE_SCHEMA_VERSION = '1.0';
export const ZDX_VALIDATED_BASELINE_HASH = '0cc36375922e4040f1dd3a321d5b18beb67f5e31fe3630363ca94303dd8d9ae6';

export function canonicalProfile(profile) {
  return JSON.stringify({
    schemaVersion: profile.schemaVersion,
    name: profile.name,
    origin: profile.origin,
    policy: profile.policy,
  });
}
export function profileHash(profile) {
  return createHash('sha256').update(canonicalProfile(profile)).digest('hex');
}
const FIELDS = ['allowedCommands', 'allowedTools', 'mutatingTools', 'nonMutatingCommands'];
const PROFILE_KEYS = ['schemaVersion', 'name', 'origin', 'policy'];
function plainObject(value) {
  return value !== null && typeof value === 'object' && !Array.isArray(value) &&
    (Object.getPrototypeOf(value) === Object.prototype || Object.getPrototypeOf(value) === null);
}
function sameKeys(value, keys) {
  return Object.keys(value).every(key => keys.includes(key));
}
function validCommand(value) {
  return typeof value === 'string' && value.length > 2 && value.length <= 128 &&
    /^\.[/][a-z0-9._/-]+$/.test(value) &&
    !value.includes('//') && !value.split('/').includes('..');
}
function validTool(value) {
  return typeof value === 'string' && value.length > 0 && value.length <= 128 &&
    /^[a-zA-Z0-9_.-]+$/.test(value);
}
export function validateProfile(profile) {
  const errors = [];
  if (!plainObject(profile)) return {
    valid: false, errors: ['profile must be an object'],
    hash: null, classification: 'Validation Failed',
  };
  if (!sameKeys(profile, PROFILE_KEYS)) errors.push('unknown profile field');
  if (profile.schemaVersion !== PROFILE_SCHEMA_VERSION) errors.push('unsupported schemaVersion');
  if (typeof profile.name !== 'string' || !profile.name.trim() ||
      profile.name !== profile.name.trim() || profile.name.length > 128)
    errors.push('invalid profile name');
  if (!['zdx-validated', 'customer-modified'].includes(profile.origin))
    errors.push('invalid origin');

  const policy = profile.policy;
  if (!plainObject(policy)) {
    errors.push('policy must be an object');
  } else {
    if (!sameKeys(policy, FIELDS)) errors.push('unknown policy field');
    for (const name of FIELDS) {
      const values = policy[name];
      if (!Array.isArray(values) || values.length > 256) {
        errors.push('policy.' + name + ' must be a bounded array');
        continue;
      }
      const validator = name.endsWith('Commands') ? validCommand : validTool;
      if (!values.every(validator)) errors.push('policy.' + name + ' contains invalid entries');
      if (new Set(values).size !== values.length) errors.push('policy.' + name + ' contains duplicates');
    }
    if (Array.isArray(policy.mutatingTools) && Array.isArray(policy.allowedTools) &&
        policy.mutatingTools.some(v => !policy.allowedTools.includes(v)))
      errors.push('mutatingTools must be a subset of allowedTools');
    if (Array.isArray(policy.nonMutatingCommands) && Array.isArray(policy.allowedCommands) &&
        policy.nonMutatingCommands.some(v => !policy.allowedCommands.includes(v)))
      errors.push('nonMutatingCommands must be a subset of allowedCommands');
  }
  let hash = null;
  if (errors.length === 0) {
    hash = profileHash(profile);
    if (profile.origin === 'zdx-validated' && hash !== ZDX_VALIDATED_BASELINE_HASH)
      errors.push('zdx-validated profile does not match shipped validated baseline');
  }
  const valid = errors.length === 0;
  return {
    valid, errors, hash: valid ? hash : null,
    classification: !valid ? 'Validation Failed'
      : profile.origin === 'zdx-validated' ? 'ZDX Validated' : 'Customer Modified',
  };
}
