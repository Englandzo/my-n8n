'use strict';
// Only public vendor image bytes and signature-verified APKs are available here.
const fs=require('node:fs'),path=require('node:path'),crypto=require('node:crypto');
const {execFileSync}=require('node:child_process');
const input=JSON.parse(fs.readFileSync('/tmp/fixture/inputs.json','utf8'));
const skip=new Set(['/proc','/sys','/dev','/tmp']);
const limit=3*1024**3;
function hashFile(p){const h=crypto.createHash('sha256'),buf=Buffer.alloc(1024*1024);const fd=fs.openSync(p,'r');try{let n;while((n=fs.readSync(fd,buf,0,buf.length,null)))h.update(buf.subarray(0,n));}finally{fs.closeSync(fd)}return h.digest('hex')}
function snapshot(){const out={};let bytes=0;function walk(p){if(skip.has(p))return;const s=fs.lstatSync(p);const e={mode:s.mode&0o7777,uid:s.uid,gid:s.gid};if(s.isSymbolicLink()){e.type='link';e.target=fs.readlinkSync(p)}else if(s.isDirectory()){e.type='dir'}else if(s.isFile()){e.type='file';e.size=s.size;bytes+=s.size;if(bytes>limit)throw Error('Snapshot byte ceiling');e.sha256=hashFile(p)}else throw Error('Unexpected special file: '+p);out[p]=e;if(e.type==='dir')for(const n of fs.readdirSync(p).sort())walk(path.join(p,n));}walk('/');return out}
function packages(){const text=fs.readFileSync('/lib/apk/db/installed','utf8'),out={};for(const block of text.split('\n\n')){const lines=block.split('\n');const name=lines.find(x=>x.startsWith('P:'))?.slice(2),version=lines.find(x=>x.startsWith('V:'))?.slice(2);if(name){if(!version||out[name])throw Error('Invalid package database');out[name]=version}}return out}
function changed(a,b){return [...new Set([...Object.keys(a),...Object.keys(b)])].sort().filter(p=>JSON.stringify(a[p])!==JSON.stringify(b[p]))}
function checked(args){return execFileSync('/tmp/tools/apk',args,{encoding:'utf8',timeout:180000,maxBuffer:2*1024*1024,stdio:['ignore','pipe','pipe']})}
const addPrefix=['--no-network','--no-cache','--keys-dir','/tmp/keys','--repositories-file','/dev/null','add','--upgrade'];
function parserProbe(){
 // apk 3.0.9 parses these flags before --print-arch exits, before DB prepare/open.
 const architecture=checked([...addPrefix,'--print-arch']).trim();
 if(architecture!=='x86_64')throw Error('APK parser architecture probe failed');
 const sentinel='n8n-fixture-unknown-option';let rejected=false;
 try{checked([...addPrefix,'--'+sentinel,'--print-arch'])}
 catch(e){
  if(e.status!==1||e.signal||String(e.stdout??'').trim()!==''||!String(e.stderr??'').includes("unrecognized option '"+sentinel+"'"))throw Error('APK parser negative probe failed');
  rejected=true;
 }
 if(!rejected)throw Error('APK parser accepted an unknown option');
 return {architecture,unknown_option_rejected:true,add_prefix:addPrefix};
}
let toolLink=false;
try{
 if(process.getuid()!==0)throw Error('Patch process must be container root');
 const cg='/sys/fs/cgroup/';
 const resource={memory:fs.readFileSync(cg+'memory.max','utf8').trim(),swap:fs.readFileSync(cg+'memory.swap.max','utf8').trim(),cpu:fs.readFileSync(cg+'cpu.max','utf8').trim(),pids:fs.readFileSync(cg+'pids.max','utf8').trim()};
 const cpu=resource.cpu.split(/\s+/).map(Number);
 if(resource.memory!==String(3*1024**3)||resource.swap!=='0'||resource.pids!=='128'||cpu.length!==2||!Number.isFinite(cpu[0])||cpu[0]!==2*cpu[1])throw Error('Effective cgroup v2 resource limits differ from requested limits');

 if(fs.existsSync('/sbin/apk'))throw Error('Unexpected existing package manager');
 const version=checked(['--version']);if(!/apk-tools 3\.0\.9\b/.test(version))throw Error('Static apk version mismatch');
 const parserEvidence=parserProbe();
 const apkFiles=input.allowed_changes.map(x=>'/tmp/apks/'+x.name+'-'+x.to+'.apk');
 checked(['--no-network','--keys-dir','/tmp/keys','verify',...apkFiles]);
 const before=snapshot(),beforePackages=packages();
 for(const x of input.allowed_changes)if(beforePackages[x.name]!==x.from)throw Error('Unexpected installed version: '+x.name);
 fs.symlinkSync('/tmp/tools/apk','/sbin/apk');toolLink=true;
 const transaction=checked([...addPrefix,...apkFiles]);
 fs.unlinkSync('/sbin/apk');toolLink=false;
 const afterPackages=packages();
 const changes=changed(beforePackages,afterPackages);
 const expected=input.allowed_changes.map(x=>x.name).sort();
 if(JSON.stringify(changes)!==JSON.stringify(expected))throw Error('Unexpected package solver delta');
 for(const x of input.allowed_changes)if(afterPackages[x.name]!==x.to)throw Error('Wrong fixed package version: '+x.name);
 const after=snapshot(),delta=changed(before,after);
 const allowed=new Set([...input.new_files,...input.allowed_changes.flatMap(x=>x.installed_files)].map(x=>'/'+x));
 // Bookkeeping only. No passwd/group, unrelated configuration or app changes.
 for(const p of ['/lib/apk/db/installed','/lib/apk/db/scripts.tar','/lib/apk/db/triggers','/lib/apk/db/lock','/etc/apk/world'])allowed.add(p);
 for(const p of delta){
   const a=before[p],b=after[p];
   if(a?.type==='dir'&&b?.type==='dir'&&JSON.stringify(a)===JSON.stringify(b))continue;
   if(!allowed.has(p))throw Error('Unexpected filesystem delta: '+p);
 }
 const appPaths=Object.keys(before).filter(p=>p==='/usr/local/lib/node_modules/n8n'||p.startsWith('/usr/local/lib/node_modules/n8n/'));
 if(appPaths.length<100)throw Error('Application snapshot missing');
 if(appPaths.some(p=>JSON.stringify(before[p])!==JSON.stringify(after[p])))throw Error('Application bytes/metadata changed');
 if(Object.keys(after).some(p=>p.startsWith('/usr/local/lib/node_modules/n8n/')&&!before[p]))throw Error('Application file added');
 const treeHash=crypto.createHash('sha256').update(JSON.stringify(appPaths.sort().map(p=>[p,before[p]]))).digest('hex');
 console.log(JSON.stringify({state:'os_transaction_verified',effective_cgroup:resource,apk_version:version.trim(),parser_probe:parserEvidence,before_packages:beforePackages,after_packages:afterPackages,application_tree_sha256:treeHash,application_entries:appPaths.length,delta:delta.map(p=>({path:p,before:before[p]??null,after:after[p]??null})),transaction_log:transaction},null,2));
}catch(e){console.error('OS transaction failed:',e.message);if(e.stderr)console.error(String(e.stderr).slice(-16384));process.exitCode=20}
finally{if(toolLink){try{fs.unlinkSync('/sbin/apk')}catch{process.exitCode=20}}}
