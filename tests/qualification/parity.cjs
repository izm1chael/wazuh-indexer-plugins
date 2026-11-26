const {evaluateReplay}=require('./ts-out/tuning-evaluation.js');
const {createHash}=require('node:crypto');
const assert=require('node:assert/strict');
const {spawnSync}=require('node:child_process');
let seed=123456789;
function rnd(n){seed=(Math.imul(1664525,seed)+1013904223)>>>0;return seed%n;}
const fixtures=[];
const ideal=Array.from({length:20},(_,i)=>({id:'sample'+i,label:i<10?'malicious':'benign',baseline:true,candidate:i<10||i<12}));
fixtures.push(ideal,ideal.map((r,i)=>({...r,candidate:i!==0&&r.candidate})),ideal.map((r,i)=>({...r,label:i===19?'unknown':r.label})),ideal.map((r,i)=>({...r,baseline:i!==10&&r.baseline})), [{id:'one',label:'unknown',baseline:true,candidate:false}]);
for(let f=0;f<300;f++){let rows=[];let size=1+rnd(1000);for(let j=0;j<size;j++)rows.push({id:'s'+j,label:['malicious','benign','unknown'][rnd(3)],baseline:rnd(17)<9,candidate:rnd(19)<10});fixtures.push(rows)}
let payload=fixtures.map(rows=>rows.map(r=>[r.id,r.label,r.baseline?1:0,r.candidate?1:0].join('\t')).join('\n')+'\nEND\n').join('');
const output=spawnSync('java',['-cp','java-out','com.wazuh.setup.incident.ReplayHarness'],{input:payload,encoding:'utf8',maxBuffer:4*1024*1024});if(output.status!==0)throw Error(output.stderr);const lines=output.stdout.trim().split('\n');assert.equal(lines.length,fixtures.length);
fixtures.forEach((rows,i)=>{const result=evaluateReplay({baseline_version:'v1',candidate_version:'v2',split:'holdout',rows});const canonical='wazuh-tuning-fixture-v1\n'+[...rows].sort((a,b)=>a.id<b.id?-1:a.id>b.id?1:0).map(r=>[r.id,r.label,r.baseline?1:0,r.candidate?1:0].join('\t')+'\n').join('');const expected=[createHash('sha256').update(canonical).digest('hex'),result.total,result.malicious,result.benign,result.unknown,result.unknownChanged,result.baseline.tp,result.candidate.tp,result.baseline.fp,result.candidate.fp,result.lostMalicious,result.gainedMalicious,result.removedBenign,result.addedBenign,result.gate].join('\t');assert.equal(lines[i],expected,'fixture '+i)});
console.log('PASS: '+fixtures.length+' Java/TypeScript paired fixture comparisons, SHA-256 canonicalization, gates and counts');console.log(output.stderr.trim());
