import { createHash } from 'node:crypto';
export const PROFILE_SCHEMA_VERSION='1.0';
export function canonicalProfile(profile){return JSON.stringify({schemaVersion:profile.schemaVersion,name:profile.name,origin:profile.origin,policy:profile.policy});}
export function profileHash(profile){return createHash('sha256').update(canonicalProfile(profile)).digest('hex');}
export function validateProfile(p){
 const errors=[]; if(!p||p.schemaVersion!==PROFILE_SCHEMA_VERSION)errors.push('unsupported schemaVersion');
 if(!['zdx-validated','customer-modified'].includes(p?.origin))errors.push('invalid origin');
 const q=p?.policy; for(const k of ['allowedCommands','allowedTools','mutatingTools','nonMutatingCommands'])if(!Array.isArray(q?.[k]))errors.push('policy.'+k+' must be an array');
 if(q?.mutatingTools?.some(x=>!q.allowedTools.includes(x)))errors.push('mutatingTools must be a subset of allowedTools');
 if(q?.nonMutatingCommands?.some(x=>!q.allowedCommands.includes(x)))errors.push('nonMutatingCommands must be a subset of allowedCommands');
 return {valid:errors.length===0,errors,hash:errors.length?null:profileHash(p),classification:p?.origin==='zdx-validated'?'ZDX Validated':'Customer Modified'};
}