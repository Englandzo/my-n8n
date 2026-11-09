#!/usr/bin/env python3
"""One benign, read-only lifecycle gate. No APK execution or image creation."""
import json,os,re,shutil,sys,time
from pathlib import Path
from build import INPUT,HERE,EVIDENCE,GIB,MIB,bounded,inspect,valid_id,remove_owned,sha,frozen_size,resume_verified,validate_watch,record_disk_space

def main():
    os.umask(0o077)
    run=os.environ.get('GITHUB_RUN_ID','');attempt=os.environ.get('GITHUB_RUN_ATTEMPT','')
    if not re.fullmatch(r'\d+',run) or not re.fullmatch(r'\d+',attempt):raise RuntimeError('Numeric CI identity required')
    if EVIDENCE.exists():raise RuntimeError('Preflight evidence destination exists')
    EVIDENCE.mkdir();owned=[]
    result={'state':'incomplete','run_id':run,'run_attempt':attempt,'cleanup_ok':False,'phase':'preflight','kernel_disk_quota':False}
    try:
        record_disk_space(result,'preflight_before_pull',os.environ['RUNNER_TEMP'])
        if os.environ.get('DOCKER_HOST','unix:///var/run/docker.sock')!='unix:///var/run/docker.sock':raise RuntimeError('Remote Docker host forbidden')
        if bounded(['docker','context','inspect','--format','{{.Endpoints.docker.Host}}']).decode().strip()!='unix:///var/run/docker.sock':raise RuntimeError('Unexpected Docker context')
        bounded(['docker','pull','--platform','linux/amd64',INPUT['base']],300,2*MIB)
        record_disk_space(result,'preflight_after_pull',os.environ['RUNNER_TEMP'])
        image=inspect('image',INPUT['base'])
        if image['Id']!=INPUT['base_config'] or image['Architecture']!='amd64' or image['Os']!='linux':raise RuntimeError('Unexpected base image')
        result['base_image_id']=image['Id']
        name=f'n8n-freeze-{run}-{attempt}'
        if name in bounded(['docker','ps','-a','--format','{{.Names}}']).decode().splitlines():raise RuntimeError('Preflight name collision')
        result['container_create_outcome']='pending';result['container_create_name']=name
        cid=bounded(['docker','create','--name',name,'--platform','linux/amd64','--network','none','--user','1000:1000','--read-only','--cap-drop','ALL','--security-opt','no-new-privileges','--pids-limit','128','--cpus','2','--memory','3g','--memory-swap','3g','--log-driver','none','--entrypoint','/usr/bin/node',INPUT['base'],'-e','setInterval(() => {}, 1000)']).decode().strip()
        if not valid_id(cid):raise RuntimeError('Uncertain preflight create identity')
        owned.append(cid);result['owned_container_id']=cid;result['container_create_outcome']='confirmed'
        h=inspect('container',cid)['HostConfig']
        normalize=lambda xs:{x.removeprefix('CAP_').upper() for x in (xs or [])}
        if h.get('NetworkMode')!='none' or h.get('Privileged') or not h.get('ReadonlyRootfs') or h.get('Memory')!=3*GIB or h.get('MemorySwap')!=3*GIB or h.get('NanoCpus')!=2_000_000_000 or h.get('PidsLimit')!=128 or normalize(h.get('CapDrop'))!={'ALL'} or h.get('CapAdd') or h.get('Binds') or h.get('Mounts') or h.get('PortBindings') or h.get('PidMode')=='host' or h.get('IpcMode')=='host':raise RuntimeError('Unexpected preflight isolation')
        if not any(x.startswith('no-new-privileges') for x in h.get('SecurityOpt',[])):raise RuntimeError('Preflight no-new-privileges absent')
        deadline=time.monotonic()+300
        record={'live_window_started':time.monotonic(),'startup_pending':True};result['controller']=record
        result['phase']='start-benign-timer'
        bounded(['docker','start',cid],seconds=2,label='preflight start',absolute_deadline=min(deadline,record['live_window_started']+2))
        result['phase']='first-freeze'
        info,paused=frozen_size(cid,deadline,record)
        if not paused:raise RuntimeError('Benign timer unexpectedly exited')
        size=info.get('SizeRw')
        if type(size) is not int:raise RuntimeError('Invalid preflight writable size')
        validate_watch(shutil.disk_usage(os.environ['RUNNER_TEMP']).free,size)
        result['first_size_bytes']=size
        result['phase']='resume-benign-timer'
        resume_verified(cid,deadline,record)
        # Exercise the same one-second scheduled interval within the shared deadline.
        time.sleep(1)
        result['phase']='second-freeze-for-owned-cleanup'
        info,paused=frozen_size(cid,deadline,record)
        if not paused:raise RuntimeError('Timer exited before paused cleanup')
        size=info.get('SizeRw')
        if type(size) is not int:raise RuntimeError('Invalid second writable size')
        validate_watch(shutil.disk_usage(os.environ['RUNNER_TEMP']).free,size)
        result['second_size_bytes']=size;result['paused_cleanup_requested']=True
        # No unpause here: official force-removal terminates the owned container.
        result['phase']='paused-owned-cleanup'
        failures=remove_owned([cid],'container')
        if failures:raise RuntimeError('Paused owned cleanup failed or uncertain')
        owned.remove(cid);result['removal_request_succeeded']=True
        existing=bounded(['docker','ps','-a','--no-trunc','--format','{{.ID}}']).decode().splitlines()
        if cid in existing:raise RuntimeError('Removed preflight container still exists')
        result['absence_verified']=True
        result['controller_sha256']=sha(HERE/'build.py');result['preflight_sha256']=sha(HERE/'preflight.py')
        result['state']='freeze_preflight_passed'
    except Exception as exc:
        result['error']=str(exc)
        if result.get('container_create_outcome')=='pending':result['container_create_outcome']='uncertain; no retry or guessed deletion'
    finally:
        # Failed/uncertain cleanup is not retried. Other failures receive one owned removal.
        if result.get('phase')=='paused-owned-cleanup' and owned:
            failures=owned[:]
        else:failures=remove_owned(owned,'container')
        absence_uncertain=result.get('removal_request_succeeded') and not result.get('absence_verified')
        result['cleanup_failures']=failures;result['cleanup_ok']=not failures and not absence_uncertain and result.get('container_create_outcome') not in ('pending','uncertain; no retry or guessed deletion')
        if absence_uncertain:result['cleanup_verification_error']='Removal request succeeded; absence verification failed or uncertain'
        if failures:result['state']='incomplete'
        (EVIDENCE/'freeze-preflight.json').write_text(json.dumps(result,indent=2)+'\n')
    return 0 if result['state']=='freeze_preflight_passed' and result['cleanup_ok'] else 20

if __name__=='__main__':sys.exit(main())
