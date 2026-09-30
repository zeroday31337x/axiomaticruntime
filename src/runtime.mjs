import { createHash } from 'node:crypto';
export const IMMUTABLE_INVARIANTS=Object.freeze({onlyRetainExecutes:true,trustedContextIsHostOwned:true,failClosedOnInvalidProfile:true});
export function evaluateAxiomaticBranch({proposal={},profile,explicitAction=false}){
 if(!profile?.policy) return {decision:'PRUNE',branchId:'invalid-profile',reason:'valid runtime profile required'};
 const {allowedCommands=[],allowedTools=[],mutatingTools=[]}=profile.policy;
 const commandSet=new Set(allowedCommands.map(v=>String(v).toLowerCase())), toolSet=new Set(allowedTools.map(String)), mutatingSet=new Set(mutatingTools.map(String));
 const kind=proposal.kind==='reply'||proposal.kind==='command'||proposal.kind==='tool'?proposal.kind:typeof proposal.command==='string'?'command':typeof proposal.tool==='string'?'tool':'reply';
 const normalized=JSON.stringify({kind,command:proposal.command,tool:proposal.tool,args:proposal.args});
 const branchId=createHash('sha256').update(normalized).digest('hex').slice(0,16);
 if(kind==='reply') return typeof proposal.reply==='string'&&proposal.reply.trim()?{decision:'RETAIN',branchId,reason:'schema-valid reply'}:{decision:'PRUNE',branchId,reason:'empty reply'};
 if(kind==='command'){const rawCommand=String(proposal.command||''),command=rawCommand.trim(),base=command.split(/\s+/)[0]?.toLowerCase()||''; if(rawCommand!==command)return{decision:'PRUNE',branchId,reason:'non-canonical command whitespace'}; if(!command.startsWith('./')||!commandSet.has(base))return{decision:'PRUNE',branchId,reason:'command outside allowlist'}; if(!explicitAction&&!profile.policy.nonMutatingCommands.includes(base))return{decision:'GATE',branchId,reason:'explicit action required'}; return{decision:'RETAIN',branchId,reason:'allowed command'};}
 const tool=String(proposal.tool||'').trim(); if(!tool||!toolSet.has(tool))return{decision:'PRUNE',branchId,reason:'tool outside allowlist'}; if(mutatingSet.has(tool)&&!explicitAction)return{decision:'GATE',branchId,reason:'mutating tool requires explicit action'}; return{decision:'RETAIN',branchId,reason:'allowed tool call'};
}