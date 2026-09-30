import { createHash } from 'node:crypto';
export const PROFILE_SCHEMA_VERSION='1.0';
export const ZDX_VALIDATED_BASELINE=Object.freeze({schemaVersion:'1.0',name:'ZDX Validated Baseline v1',origin:'zdx-validated',policy:{allowedCommands:['./help','./commands','./status','./get'],allowedTools:[],mutatingTools:[],nonMutatingCommands:['./help','./commands','./status','./get']}});
export function canonicalProfile(profile){return JSON.stringify({schemaVersion:profile.schemaVersion,name:profile.name,origin:profile.origin,policy:profile.policy});}
export function profileHash(profile){return createHash('sha256').update(canonicalProfile(profile)).digest('hex');}
export const ZDX_VALIDATED_BASELINE_HASH=profileHash(ZDX_VALIDATED_BASELINE);
export function validateProfile(p){
 const errors=[]; if(!p||p.schemaVersion!==PROFILE_SCHEMA_VERSION)errors.push('unsupported schemaVersion');
 if(!['zdx-validated','customer-modified'].includes(p?.origin))errors.push('invalid origin');
 const q=p?.policy; for(const k of ['allowedCommands','allowedTools','mutatingTools','nonMutatingCommands'])if(!Array.isArray(q?.[k]))errors.push('policy.'+k+' must be an array');
 if(q?.mutatingTools?.some(x=>!q.allowedTools.includes(x)))errors.push('mutatingTools must be a subset of allowedTools');
 if(q?.nonMutatingCommands?.some(x=>!q.allowedCommands.includes(x)))errors.push('nonMutatingCommands must be a subset of allowedCommands');
 const hash=errors.length?null:profileHash(p),isBaseline=hash===ZDX_VALIDATED_BASELINE_HASH;
 if(!errors.length&&p.origin==='zdx-validated'&&!isBaseline)errors.push('zdx-validated origin requires exact ZDX validated baseline');
 return {valid:errors.length===0,errors,hash:errors.length?null:hash,classification:errors.length?'Validation Failed':isBaseline?'ZDX Validated':'Customer Modified'};
}
