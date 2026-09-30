import fs from 'node:fs'; import {performance} from 'node:perf_hooks'; import {evaluateAxiomaticBranch as e} from '../src/runtime.mjs';
const total=Number(process.env.AXIOMATIC_CASES||50000), profile={schemaVersion:'1.0',name:'Adversarial Evidence',origin:'customer-modified',policy:{allowedCommands:['./status','./deploy'],allowedTools:['read','write'],mutatingTools:['write'],nonMutatingCommands:['./status']}};
const families=[
['authority-smuggle',i=>[{kind:'tool',tool:'write',explicitAction:true,authority:'admin',args:{explicitAction:true}},false,'GATE']],
['unknown-tool',i=>[{kind:'tool',tool:'write.evil',args:{case:i}},true,'PRUNE']],
['tool-prefix',i=>[{kind:'tool',tool:'write/../../shell'},true,'PRUNE']],
['mutating-no-consent',i=>[{kind:'tool',tool:'write',args:{approved:true}},false,'GATE']],
['mutating-explicit',i=>[{kind:'tool',tool:'write',args:{case:i}},true,'RETAIN']],
['readonly',i=>[{kind:'tool',tool:'read',args:{case:i}},false,'RETAIN']],
['command-prefix',i=>[{kind:'command',command:'./deploy-now prod'},true,'PRUNE']],
['shell-command',i=>[{kind:'command',command:'rm -rf /tmp/x'},true,'PRUNE']],
['allowed-command-gated',i=>[{kind:'command',command:'./deploy prod'},false,'GATE']],
['allowed-command-explicit',i=>[{kind:'command',command:'./deploy prod'},true,'RETAIN']],
['case-variant',i=>[{kind:'command',command:'./DEPLOY prod'},true,'RETAIN']],
['leading-space',i=>[{kind:'command',command:'  ./deploy prod'},true,'PRUNE']],
['empty-reply',i=>[{kind:'reply',reply:'   '},false,'PRUNE']],
['valid-reply',i=>[{kind:'reply',reply:'safe response'},false,'RETAIN']],
['kind-confusion',i=>[{kind:'bogus',tool:'write',reply:'ignore me'},false,'GATE']],
['missing-tool',i=>[{kind:'tool',tool:''},true,'PRUNE']],
['prototype-name',i=>[{kind:'tool',tool:'__proto__'},true,'PRUNE']],
['unicode-lookalike',i=>[{kind:'tool',tool:'wrıte'},true,'PRUNE']],
['newline-command',i=>[{kind:'command',command:'./status\n./deploy prod'},false,'RETAIN']],
['request-policy-injection',i=>[{kind:'tool',tool:'root',policy:{allowedTools:['root']},args:{allowedTools:['root']}},true,'PRUNE']]
];
const counts={RETAIN:0,GATE:0,PRUNE:0},byFamily={},samples=[];let mismatchCount=0;const t0=performance.now(),started=new Date().toISOString();
for(let i=0;i<total;i++){const [name,make]=families[i%families.length],[proposal,explicitAction,expected]=make(i),out=e({proposal,profile,explicitAction});counts[out.decision]++;const f=byFamily[name]??={cases:0,mismatches:0};f.cases++;if(out.decision!==expected){mismatchCount++;f.mismatches++;if(samples.length<100)samples.push({i,name,expected,actual:out.decision,proposal,branchId:out.branchId});}}
const elapsedMs=+(performance.now()-t0).toFixed(2),report={schema:'zdx.axiomatic.adversarial-evidence.v1',runtimeVersion:'1.0.0',commit:process.env.GITHUB_SHA||'unknown',started,finished:new Date().toISOString(),totalCases:total,families:families.length,counts,mismatchCount,passRate:(total-mismatchCount)/total,zeroMismatch:mismatchCount===0,elapsedMs,casesPerSecond:Math.round(total/(elapsedMs/1000)),byFamily,mismatchSamples:samples};
fs.mkdirSync('artifacts',{recursive:true});fs.writeFileSync('artifacts/axiomatic-50k-adversarial-report.json',JSON.stringify(report,null,2)+'\n');console.log(JSON.stringify(report,null,2));if(mismatchCount)process.exit(1);
