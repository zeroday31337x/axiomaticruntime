import test from 'node:test';
import assert from 'node:assert/strict';
import { evaluateAxiomaticBranch as e } from '../src/runtime.mjs';
import { validateProfile } from '../src/profile.mjs';

const p={schemaVersion:'1.0',name:'test',origin:'customer-modified',policy:{allowedCommands:['./status','./deploy'],allowedTools:['read','write'],mutatingTools:['write'],nonMutatingCommands:['./status']}};
test('profile validates',()=>assert.equal(validateProfile(p).valid,true));
test('RETAIN safe reply',()=>assert.equal(e({profile:p,proposal:{kind:'reply',reply:'ok'}}).decision,'RETAIN'));
test('PRUNE outside command',()=>assert.equal(e({profile:p,proposal:{kind:'command',command:'echo hello'},explicitAction:true}).decision,'PRUNE'));
test('GATE consequential command',()=>assert.equal(e({profile:p,proposal:{kind:'command',command:'./deploy prod'}}).decision,'GATE'));
test('RETAIN explicit command',()=>assert.equal(e({profile:p,proposal:{kind:'command',command:'./deploy prod'},explicitAction:true}).decision,'RETAIN'));
test('PRUNE unknown tool',()=>assert.equal(e({profile:p,proposal:{kind:'tool',tool:'unknown'},explicitAction:true}).decision,'PRUNE'));
test('GATE mutation',()=>assert.equal(e({profile:p,proposal:{kind:'tool',tool:'write'}}).decision,'GATE'));
test('RETAIN explicit mutation',()=>assert.equal(e({profile:p,proposal:{kind:'tool',tool:'write'},explicitAction:true}).decision,'RETAIN'));
test('invalid profile fails closed',()=>assert.equal(e({profile:null,proposal:{kind:'tool',tool:'read'}}).decision,'PRUNE'));
test('profile cannot self-expand tool authority',()=>{const x=structuredClone(p);x.policy.allowedTools=['read'];x.policy.mutatingTools=[];assert.equal(e({profile:x,proposal:{kind:'tool',tool:'write'},explicitAction:true}).decision,'PRUNE')});
test('branch id is deterministic',()=>{const input={profile:p,proposal:{kind:'tool',tool:'read'}};assert.equal(e(input).branchId,e(input).branchId)});
test('PRUNE non-canonical leading command whitespace',()=>assert.equal(e({profile:p,proposal:{kind:'command',command:'  ./deploy prod'},explicitAction:true}).decision,'PRUNE'));
test('PRUNE non-canonical trailing command whitespace',()=>assert.equal(e({profile:p,proposal:{kind:'command',command:'./deploy prod  '},explicitAction:true}).decision,'PRUNE'));
