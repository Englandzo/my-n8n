#!/usr/bin/env python3
import json,sys
from pathlib import Path
from build import inspect,remove_owned,valid_id

def cleanup(record):
    identity=record.get('image_id')
    if not identity:
        return {'cleanup_ok':record.get('cleanup_ok',False),'image_removed':False,'note':'No confirmed derivative image ID'}
    if not valid_id(identity,True) or record.get('owned_image_ids')!=[identity]:
        return {'cleanup_ok':False,'error':'Owned derivative identity mismatch; refusing deletion'}
    try:
        image=inspect('image',identity)
        if image['Id']!=identity or image['RootFS']['Layers']!=record['rootfs_layers']:
            raise ValueError('Owned image identity/ancestry changed')
        failures=remove_owned([identity],'image')
        return {'cleanup_ok':not failures,'image_removed':not failures,'image_id':identity,'failures':failures}
    except Exception as exc:return {'cleanup_ok':False,'error':str(exc),'image_id':identity}

def main():
    root=Path('scan-evidence');root.mkdir(exist_ok=True)
    try:r=cleanup(json.loads((root/'derivative.json').read_text()))
    except Exception as exc:r={'cleanup_ok':False,'error':str(exc)}
    (root/'derivative-cleanup.json').write_text(json.dumps(r,indent=2)+'\n')
    return 0 if r['cleanup_ok'] else 20
if __name__=='__main__':sys.exit(main())
