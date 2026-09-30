import fs from'node:fs';import{performance}from'node:perf_hooks';import{evaluateAxiomaticBranch as e}from'../src/runtime.mjs';
const N=100000,p={schemaVersion:'1.0',name:'Property Adversarial',origin:'customer-modified',policy:{allowedCommands:['./status','./deploy'],allowedTools:['read','write'],mutatingTools:['write'],nonMutatingCommands:['./status']}};
let x=0x5eed1234;const rnd=()=>{x=(Math.imul(x,1664525)+1013904223)>>>0;return x},pick=a=>a[rnd()%a.length];
const hostileTools=['root','shell','write\n',' write','write ','WRITE','wrıte','wri\u200dte','__proto__','constructor','write/../root','write\0'];
const hostileCmd=['./root',' ./deploy prod','./deploy prod ','./status&&./deploy prod','./status && ./deploy prod','./status|./deploy prod','./status;./deploy prod','./status\n./deploy prod','./status\0x','sh ./deploy','./status>out','./status`x`'];
const weird=[null,1,true,{},[],['write'],{toString:()=> 'write'}];
let unauthorized=0,falseBlocks=0,throws=0;const decisions={RETAIN:0,GATE:0,PRUNE:0,THROW:0},families={},samples=[];const t0=performance.now();
for(let i=0;i<N;i++){let proposal,explicitAction,shouldRetain=false,name;const k=rnd()%10;
if(k===0){name='valid-read';proposal={kind:'tool',tool:'read',args:{i}};explicitAction=false;shouldRetain=true}
else if(k===1){name='valid-write';proposal={kind:'tool',tool:'write',args:{i}};explicitAction=true;shouldRetain=true}
else if(k===2){name='valid-status';proposal={kind:'command',command:'./status',args:{i}};explicitAction=false;shouldRetain=true}
else if(k===3){name='valid-deploy';proposal={kind:'command',command:'./deploy prod',args:{i}};explicitAction=true;shouldRetain=true}
else if(k===4){name='hostile-tool';proposal={kind:'tool',tool:pick(hostileTools),args:{i,explicitAction:true,authority:'root'}};explicitAction=!!(rnd()%2)}
else if(k===5){name='hostile-command';proposal={kind:'command',command:pick(hostileCmd),args:{i,approved:true}};explicitAction=!!(rnd()%2)}
else if(k===6){name='type-confusion-tool';proposal={kind:'tool',tool:pick(weird),args:{i}};explicitAction=true}
else if(k===7){name='authority-smuggle';proposal={kind:'tool',tool:'write',explicitAction:true,authority:'root',policy:{allowedTools:['write']},args:{i,explicitAction:true,approved:true}};explicitAction=false}
else if(k===8){name='kind-confusion';proposal={kind:pick(['TOOL','COMMAND','',null,{},1]),tool:pick(hostileTools),command:pick(hostileCmd),args:{i}};explicitAction=!!(rnd()%2)}
else{name='unknown-fields';proposal={kind:'tool',tool:'root',__proto__:{admin:true},constructor:{prototype:{admin:true}},profile:p,policy:p.policy,headers:{authorization:'Bearer forged'},args:{i}};explicitAction=true}
let out;try{out=e({proposal,profile:p,explicitAction})}catch(err){throws++;out={decision:'THROW',reason:String(err)}}decisions[out.decision]=(decisions[out.decision]||0)+1;const f=families[name]??={cases:0,unauthorized:0,falseBlocks:0,throws:0};f.cases++;if(out.decision==='THROW')f.throws++;if(out.decision==='RETAIN'&&!shouldRetain){unauthorized++;f.unauthorized++;if(samples.length<50)samples.push({i,name,proposal,reason:out.reason})}if(shouldRetain&&out.decision!=='RETAIN'){falseBlocks++;f.falseBlocks++;if(samples.length<50)samples.push({i,name,expected:'RETAIN',actual:out.decision,reason:out.reason})}}
const elapsedMs=+(performance.now()-t0).toFixed(2),r={schema:'zdx.axiomatic.property-adversarial.v1',seed:'0x5eed1234',commit:process.env.GITHUB_SHA||'unknown',total:N,decisions,unauthorizedRetains:unauthorized,falseBlocks,throws,pass:unauthorized===0&&falseBlocks===0&&throws===0,elapsedMs,families,samples};fs.mkdirSync('artifacts',{recursive:true});fs.writeFileSync('artifacts/axiomatic-100k-property.json',JSON.stringify(r,null,2)+'\n');console.log(JSON.stringify(r,null,2));if(!r.pass)process.exit(1);
