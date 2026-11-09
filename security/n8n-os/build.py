#!/usr/bin/env python3
"""Public APK-only, offline disposable transaction. Review before remote use."""
import hashlib,http.client,io,json,os,re,selectors,shutil,socket,subprocess,sys,tarfile,tempfile,time,urllib.parse,urllib.request,zlib
from pathlib import Path
MIB=1024**2; GIB=1024**3
HERE=Path(__file__).resolve().parent
INPUT=json.loads((HERE/'inputs.json').read_text())
EVIDENCE=Path('scan-evidence')
REQUIRED_CAPS=['CHOWN','FOWNER','DAC_OVERRIDE','SYS_CHROOT']
CONFIG_KEYS=['User','Entrypoint','Cmd','Env','WorkingDir','ExposedPorts','Volumes','Healthcheck','StopSignal','Labels']

def sha(p):
    h=hashlib.sha256()
    with Path(p).open('rb') as f:
        for b in iter(lambda:f.read(MIB),b''):h.update(b)
    return h.hexdigest()

def bounded(cmd,seconds=30,limit=MIB,watch=None,*,label="command",absolute_deadline=None):
    started=time.monotonic()
    deadline=min(started+seconds,absolute_deadline) if absolute_deadline is not None else started+seconds
    def timeout():return RuntimeError(f"{label}: wall-clock limit exceeded after {time.monotonic()-started:.3f}s")
    if started>=deadline:raise timeout()
    p=subprocess.Popen(cmd,stdout=subprocess.PIPE,stderr=subprocess.PIPE)
    sel=selectors.DefaultSelector();out={1:bytearray(),2:bytearray()};next_watch=0
    for stream,n in [(p.stdout,1),(p.stderr,2)]:os.set_blocking(stream.fileno(),False);sel.register(stream,selectors.EVENT_READ,n)
    try:
        while sel.get_map():
            if time.monotonic()>=deadline:raise timeout()
            if watch and time.monotonic()>=next_watch:watch();next_watch=time.monotonic()+1
            if time.monotonic()>=deadline:raise timeout()
            for key,_ in sel.select(min(.2,max(0,deadline-time.monotonic()))):
                b=os.read(key.fileobj.fileno(),65536)
                if not b:sel.unregister(key.fileobj);continue
                out[key.data].extend(b)
                if len(out[key.data])>limit:raise RuntimeError(label+': captured output limit exceeded')
        if time.monotonic()>=deadline:raise timeout()
        try:code=p.wait(timeout=deadline-time.monotonic())
        except subprocess.TimeoutExpired:raise timeout()
        if code:raise RuntimeError(label+': command failed: '+bytes(out[2][-16384:]).decode(errors='replace'))
        return bytes(out[1])
    finally:
        if p.poll() is None:p.kill();p.wait(timeout=5)
        sel.close()

def inspect(kind,identity):return json.loads(bounded(['docker',kind,'inspect',identity]))[0]
def valid_id(s,image=False):return bool(re.fullmatch(('sha256:' if image else '')+'[0-9a-f]{64}',s))

def verify_config(base,derived):
    # Exact dictionary comparison catches extra env/labels or null/empty Cmd drift.
    if base!=derived:raise RuntimeError('Committed image Config differs from base')

def validate_watch(free,writable):
    if free<8*GIB:raise RuntimeError('Free disk watchdog threshold crossed')
    if writable<0 or writable>256*MIB:raise RuntimeError('Writable layer watchdog threshold crossed')

def remove_owned(ids,kind):
    failed=[]
    for identity in reversed(ids):
        if not valid_id(identity,image=kind=='image'):raise RuntimeError('Invalid owned identity')
        try:bounded(['docker',kind,'rm','-f',identity])
        except Exception:failed.append(identity)
    return failed

def validate_patch_hostconfig(h):
    if h.get('NetworkMode')!='none' or h.get('Privileged') or h.get('PidMode')=='host' or h.get('IpcMode')=='host':raise RuntimeError('Unsafe patch namespaces')
    if h.get('Memory')!=3*GIB or h.get('MemorySwap')!=3*GIB or h.get('NanoCpus')!=2_000_000_000 or h.get('PidsLimit')!=128:raise RuntimeError('Patch resource limits not effective')
    normalize=lambda xs:{x.removeprefix('CAP_').upper() for x in (xs or [])}
    if normalize(h.get('CapAdd'))!=set(REQUIRED_CAPS) or normalize(h.get('CapDrop'))!={'ALL'}:raise RuntimeError('Unexpected patch capabilities')
    if not any(x.startswith('no-new-privileges') for x in h.get('SecurityOpt',[])):raise RuntimeError('Missing no-new-privileges')
    if h.get('PortBindings'):raise RuntimeError('Unexpected published ports')
    for mount in h.get('Mounts',[]):
        if mount.get('Type')!='bind' or not mount.get('ReadOnly') or not mount.get('Target','').startswith('/tmp/'):
            raise RuntimeError('Unexpected writable or non-fixture mount')
    if 'size=256m' not in h.get('Tmpfs',{}).get('/tmp',''):
        raise RuntimeError('Temporary storage cap missing')

class DockerConnection(http.client.HTTPConnection):
    def connect(self):
        self.sock=socket.socket(socket.AF_UNIX,socket.SOCK_STREAM);self.sock.settimeout(self.timeout);self.sock.connect('/var/run/docker.sock')

def commit_exact(cid,config,api):
    if not valid_id(cid) or not re.fullmatch(r'1\.\d+',api):raise RuntimeError('Invalid commit identity/API')
    conn=DockerConnection('localhost',timeout=45)
    try:
        query=urllib.parse.urlencode({'container':cid,'pause':'0','comment':'Isolated public APK security experiment; not a vendor image'})
        conn.request('POST',f'/v{api}/commit?{query}',body=json.dumps(config),headers={'Content-Type':'application/json'})
        resp=conn.getresponse();data=resp.read(MIB+1)
        if len(data)>MIB or resp.status!=201:raise RuntimeError('Commit API rejected or oversized response')
        identity=json.loads(data)['Id']
        if not valid_id(identity,True):raise RuntimeError('Uncertain commit response')
        return identity
    finally:conn.close()

def commit_owned(cid,config,api,protected):
    # Refresh immediately before EACH commit, after all public-image pulls.
    current=set(bounded(['docker','image','ls','--no-trunc','--quiet']).decode().splitlines())
    identity=commit_exact(cid,config,api)
    if identity in current or identity in set(protected):
        raise RuntimeError('Commit returned protected/pre-existing image; refusing ownership')
    return identity

def main():
    os.umask(0o077);run=os.environ.get('GITHUB_RUN_ID','');attempt=os.environ.get('GITHUB_RUN_ATTEMPT','')
    if not re.fullmatch(r'\d+',run) or not re.fullmatch(r'\d+',attempt):raise RuntimeError('Numeric CI identity required')
    if EVIDENCE.exists():raise RuntimeError('Evidence destination already exists')
    EVIDENCE.mkdir();tmp=Path(tempfile.mkdtemp(prefix='n8n-public-os-',dir=os.environ['RUNNER_TEMP']))
    owned=[];images=[];phase='preflight';result={'state':'incomplete','run_id':run,'run_attempt':attempt,'kernel_disk_quota':False,'capabilities':REQUIRED_CAPS,'base':INPUT['base'],'cleanup_ok':False}
    def create(suffix,image,args,mounts=(),user='1000:1000',patch=False,tmpfs=True):
        name=f'n8n-os-{run}-{attempt}-{suffix}'
        names=bounded(['docker','ps','-a','--format','{{.Names}}']).decode().splitlines()
        if name in names:raise RuntimeError('Container name collision')
        command=['docker','create','--name',name,'--platform','linux/amd64','--network','none','--user',user,'--cap-drop','ALL','--security-opt','no-new-privileges','--pids-limit','128','--cpus','2','--memory','3g','--memory-swap','3g','--log-driver','none']
        if tmpfs:command+=['--tmpfs','/tmp:rw,nosuid,nodev,mode=1777,size=256m']
        if patch:
            for cap in REQUIRED_CAPS:command+=['--cap-add',cap]
        else:command+=['--read-only']
        for m in mounts:command+=['--mount',m]
        cid=bounded([*command,'--entrypoint',args[0],image,*args[1:]]).decode().strip()
        if not valid_id(cid):raise RuntimeError('Uncertain container create outcome')
        owned.append(cid);return cid
    try:
        if shutil.disk_usage(tmp).free<16*GIB:raise RuntimeError('Need at least 16 GiB free disk')
        if os.environ.get('DOCKER_HOST','unix:///var/run/docker.sock')!='unix:///var/run/docker.sock':raise RuntimeError('Remote Docker host forbidden')
        endpoint=bounded(['docker','context','inspect','--format','{{.Endpoints.docker.Host}}']).decode().strip()
        if endpoint!='unix:///var/run/docker.sock':raise RuntimeError('Unexpected Docker context endpoint')
        engine=json.loads(bounded(['docker','version','--format','{{json .Server}}']));result['engine']=engine
        api=engine['ApiVersion']
        if not re.fullmatch(r'1\.\d+',api):raise RuntimeError('Unsupported Docker API format')
        phase='pull-public-base-tools'
        for image in [INPUT['base'],INPUT['tools_image']]:bounded(['docker','pull','--platform','linux/amd64',image],300,2*MIB)
        base=inspect('image',INPUT['base']);tools=inspect('image',INPUT['tools_image'])
        if base['Id']!=INPUT['base_config'] or base['Architecture']!='amd64' or base['Os']!='linux':raise RuntimeError('Base identity mismatch')
        if tools['Architecture']!='amd64' or tools['Os']!='linux' or tools['Size']>128*MIB:raise RuntimeError('Unexpected tools image platform/size')
        result['base_config']=base['Config'];result['base_image_id']=base['Id'];result['tool_image_id']=tools['Id']
        phase='commit-config-preflight'
        probe=create('config-probe',INPUT['base'],['/bin/true'],user='0:0')
        bounded(['docker','start','--attach',probe],30)
        if inspect('container',probe)['State']['ExitCode']!=0:raise RuntimeError('Config probe failed')
        result['commit_outcome']='pending'
        probe_image=commit_owned(probe,base['Config'],api,[base['Id'],tools['Id']])
        images.append(probe_image);result['commit_outcome']='confirmed'
        verify_config(base['Config'],inspect('image',probe_image)['Config'])
        if remove_owned([probe_image],'image'):raise RuntimeError('Config probe cleanup failed')
        images.remove(probe_image);result['commit_config_preflight']='passed'
        phase='download-public-apks';apks=tmp/'apks';apks.mkdir();total=0;start=time.monotonic()
        for item in INPUT['packages']:
            name=item['name']+'-'+item['version']+'.apk';dest=apks/name
            with urllib.request.urlopen(item['url'],timeout=30) as response,dest.open('xb') as out:
                while chunk:=response.read(65536):
                    total+=len(chunk)
                    if total>64*MIB or time.monotonic()-start>300:raise RuntimeError('Public bundle limit exceeded')
                    out.write(chunk)
            if dest.stat().st_size!=item['bytes'] or sha(dest)!=item['sha256']:raise RuntimeError('Public APK digest mismatch')
            dest.chmod(0o444)
        apks.chmod(0o755)
        phase='verify-signatures';names=['/input/'+x.name for x in sorted(apks.iterdir())]
        cid=create('verify',INPUT['tools_image'],['/sbin/apk','verify',*names],[f'type=bind,src={apks},dst=/input,readonly'])
        verification=bounded(['docker','start','--attach',cid],60,2*MIB)
        if inspect('container',cid)['State']['ExitCode']!=0:raise RuntimeError('APK signature verification failed')
        result['signature_verification']='all eleven APKs verified by pinned official Alpine image'
        result['signature_stdout_sha256']=hashlib.sha256(verification).hexdigest()
        keyarchive=bounded(['docker','cp',f'{cid}:/etc/apk/keys/{INPUT["signing_key"]}','-'],30,MIB)
        keys=tmp/'keys';keys.mkdir();keys.chmod(0o755)
        with tarfile.open(fileobj=io.BytesIO(keyarchive),mode='r:') as tar:
            entries=tar.getmembers()
            if len(entries)!=1 or not entries[0].isfile() or entries[0].size>65536:raise RuntimeError('Unexpected signing-key archive')
            key=(keys/INPUT['signing_key']);key.write_bytes(tar.extractfile(entries[0]).read());key.chmod(0o444)
        phase='extract-verified-static-tool';data=(apks/'apk-tools-static-3.0.9-r0.apk').read_bytes();static=None
        while data:
            dec=zlib.decompressobj(16+zlib.MAX_WBITS);raw=dec.decompress(data,16*MIB+1)
            if len(raw)>16*MIB or dec.unconsumed_tail:raise RuntimeError('Static APK expansion limit')
            data=dec.unused_data
            with tarfile.open(fileobj=io.BytesIO(raw),mode='r:') as tar:
                for m in tar:
                    if m.name=='sbin/apk.static':
                        if static is not None or not m.isfile() or m.size>8*MIB:raise RuntimeError('Unexpected static binary')
                        static=tar.extractfile(m).read()
        if not static:raise RuntimeError('Verified static tool missing')
        tool=tmp/'apk';tool.write_bytes(static);tool.chmod(0o555)
        # Separate package directory excludes the bootstrap APK from installation.
        install=tmp/'install';install.mkdir();install.chmod(0o755)
        for x in INPUT['allowed_changes']:shutil.copyfile(apks/f'{x["name"]}-{x["to"]}.apk',install/f'{x["name"]}-{x["to"]}.apk')
        for f in install.iterdir():f.chmod(0o444)
        phase='offline-os-transaction'
        cid=create('patch',INPUT['base'],['/usr/bin/node','/tmp/fixture/patch.cjs'],[f'type=bind,src={HERE},dst=/tmp/fixture,readonly',f'type=bind,src={install},dst=/tmp/apks,readonly',f'type=bind,src={tool},dst=/tmp/tools/apk,readonly',f'type=bind,src={keys},dst=/tmp/keys,readonly'],user='0:0',patch=True)
        validate_patch_hostconfig(inspect('container',cid)['HostConfig'])
        result['disk_watch']={'minimum_free_bytes':shutil.disk_usage(tmp).free,'maximum_writable_bytes':None,'kernel_quota':False,'completed_samples':0,'query_timeout_seconds':2,'quiescent_query_timeout_seconds':10,'interval_seconds':1}
        transaction_deadline=time.monotonic()+300
        def watch(quiescent=False):
            record=result['disk_watch'];started=time.monotonic()
            record['last_query_state']='pending'
            try:
                free=shutil.disk_usage(tmp).free
                record['minimum_free_bytes']=min(record['minimum_free_bytes'],free)
                validate_watch(free,0)
                info=json.loads(bounded(['docker','container','inspect','--size',cid],seconds=10 if quiescent else 2,
                    label='quiescent size inspection' if quiescent else 'running size inspection',
                    absolute_deadline=None if quiescent else transaction_deadline))[0]
                if quiescent and (info.get('State',{}).get('Status')!='created' or info['State'].get('Running') is not False):
                    raise RuntimeError('Quiescent size check requires never-started container')
                size=info.get('SizeRw')
                if type(size) is not int:raise RuntimeError('Missing or invalid SizeRw measurement')
                free=shutil.disk_usage(tmp).free
                record['minimum_free_bytes']=min(record['minimum_free_bytes'],free)
                record['maximum_writable_bytes']=max(record['maximum_writable_bytes'] or 0,size)
                record['completed_samples']+=1
                validate_watch(free,size)
                record['last_query_state']='passed'
            except Exception as exc:
                record['last_query_state']='failed';record['last_query_error']=str(exc)
                raise
            finally:record['last_query_seconds']=time.monotonic()-started
        watch(quiescent=True) # Read before start; no guarantee of cache warmth.
        result['disk_watch']['quiescent_query_seconds']=result['disk_watch']['last_query_seconds']
        transaction_deadline=time.monotonic()+300
        patch=bounded(['docker','start','--attach',cid],300,8*MIB,watch,
            label='offline APK transaction',absolute_deadline=transaction_deadline)
        watch() # Require a final valid size observation before accepting the manifest.
        info=inspect('container',cid)
        if info['State']['Running'] or info['State']['ExitCode']!=0:raise RuntimeError('OS transaction failed')
        manifest=json.loads(patch)
        if manifest['state']!='os_transaction_verified':raise RuntimeError('OS delta validation incomplete')
        (EVIDENCE/'os-delta.json').write_bytes(patch)
        result['delta_sha256']=hashlib.sha256(patch).hexdigest();result['application_tree_sha256']=manifest['application_tree_sha256']
        phase='commit-exact-config';result['commit_outcome']='pending'
        identity=commit_owned(cid,base['Config'],api,[base['Id'],tools['Id']])
        images.append(identity);result['commit_outcome']='confirmed';result['image_id']=identity
        derived=inspect('image',identity);verify_config(base['Config'],derived['Config'])
        if derived['RootFS']['Layers'][:-1]!=base['RootFS']['Layers'] or len(derived['RootFS']['Layers'])!=len(base['RootFS']['Layers'])+1:raise RuntimeError('Unexpected derivative rootfs ancestry')
        if derived['Size']>3*GIB:raise RuntimeError('Derivative exceeds image size limit')
        phase='final-tool-absence'
        check=create('absence',identity,['/bin/sh','-ec','test ! -e /sbin/apk; test ! -e /tmp/tools/apk; test ! -e /tmp/apks; test ! -e /tmp/keys; test ! -e /tmp/fixture'],tmpfs=False)
        bounded(['docker','start','--attach',check],30)
        if inspect('container',check)['State']['ExitCode']!=0:raise RuntimeError('Temporary inputs leaked into image')
        result['state']='derivative_verified';result['image_bytes']=derived['Size'];result['derived_config']=derived['Config'];result['rootfs_layers']=derived['RootFS']['Layers']
        result['input_manifest_sha256']=sha(HERE/'inputs.json');result['patch_script_sha256']=sha(HERE/'patch.cjs');result['build_script_sha256']=sha(HERE/'build.py')
        result['owned_image_ids']=images[:]
    except Exception as exc:
        result['error']=str(exc);result['state']='incomplete'
        if result.get('commit_outcome')=='pending':result['commit_outcome']='uncertain; no retry'
    finally:
        failures=remove_owned(owned,'container');result['container_cleanup_failures']=failures
        if failures:result['state']='incomplete'
        if result['state']!='derivative_verified':
            image_failures=remove_owned(images,'image');result['image_cleanup_failures']=image_failures
        result['cleanup_ok']=not failures and not result.get('image_cleanup_failures') and result.get('commit_outcome')!='uncertain; no retry'
        result['phase']=phase
        (EVIDENCE/'derivative.json').write_text(json.dumps(result,indent=2)+'\n')
        shutil.rmtree(tmp)
    return 0 if result['state']=='derivative_verified' and result['cleanup_ok'] else 20

if __name__=='__main__':sys.exit(main())
