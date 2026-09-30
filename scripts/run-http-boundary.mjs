import{spawn}from'node:child_process';import{setTimeout as sleep}from'node:timers/promises';
const token='0123456789abcdef0123456789abcdef0123456789abcdef',port=18765,base='http://127.0.0.1:'+port;const child=spawn(process.execPath,['src/server.mjs'],{env:{...process.env,PORT:String(port),AXIOMATIC_RUNTIME_TOKEN:token},stdio:['ignore','pipe','pipe']});
let failures=[],cases=0;const check=(ok,name,detail)=>{cases++;if(!ok)failures.push({name,detail})};
try{await sleep(500);
let r=await fetch(base+'/health');check(r.status===200,'health',r.status);
r=await fetch(base+'/v1/evaluate',{method:'POST',headers:{'content-type':'application/json'},body:'{}'});check(r.status===401,'unauthenticated',r.status);
for(const auth of ['',token.slice(1),'x'.repeat(token.length),'Bearer '+token+'x']){r=await fetch(base+'/v1/evaluate',{method:'POST',headers:{authorization:auth,'content-type':'application/json'},body:'{}'});check(r.status===401,'bad-token',r.status)}
const H={authorization:'Bearer '+token,'content-type':'application/json'};
const bodies=[
[{proposal:{kind:'tool',tool:'root'},profile:{policy:{allowedTools:['root']}},explicitAction:true},'PRUNE','profile-smuggle'],
[{proposal:{kind:'tool',tool:'write',explicitAction:true,args:{explicitAction:true}},explicitAction:false},'PRUNE','tool-not-default'],
[{proposal:{kind:'command',command:'./status && ./deploy'} ,explicitAction:true},'PRUNE','shell-op'],
[{proposal:{kind:'command',command:' ./status'},explicitAction:true},'PRUNE','space-command'],
[{proposal:{kind:'command',command:'./status'},explicitAction:false},'RETAIN','valid-status']
];
for(const[b,expect,name]of bodies){r=await fetch(base+'/v1/evaluate',{method:'POST',headers:H,body:JSON.stringify(b)});let j=await r.json();check(r.status===200&&j.decision===expect,name,{status:r.status,j})}
r=await fetch(base+'/v1/evaluate',{method:'POST',headers:H,body:'{bad'});check(r.status===400,'bad-json',r.status);
console.log(JSON.stringify({cases,failures,pass:failures.length===0},null,2));if(failures.length)process.exitCode=1;
}finally{child.kill('SIGTERM')}
