#!/usr/bin/env python3
"""Approved public vendor artifacts only. No private data or Docker socket in containers."""
import datetime as dt
import hashlib
import json
import os
from pathlib import Path
import re
import selectors
import shutil
import subprocess
import sys
import tarfile
import tempfile
import time

MIB = 1024**2
GIB = 1024**3
DB_BUDGET = 3584*MIB
TMP_BUDGET = 1536*MIB
MEMORY_BUDGET = 6*GIB
assert DB_BUDGET + TMP_BUDGET == 5*GIB
assert DB_BUDGET + TMP_BUDGET < MEMORY_BUDGET
SCANNER = 'aquasec/trivy@sha256:8f6bb947dbc528902e11f2f5be52f7b519f6a39d5d148f41166f2040499768fb'
TARGET = 'n8nio/n8n@sha256:5d9f0cc5672b83d438c465f718077af463828c15563a480ef5c7c5fdfa2eae9c'
EXPECTED_CHILD = 'sha256:553e3e97d163e4185792e5ac17da9ac50a90d22f26d7a7404feaf5db81ee1f0f'
OPTIONS = ['image', '--cache-dir', '/cache', '--input', '/input/image.tar',
           '--scanners', 'vuln', '--pkg-types', 'os,library', '--include-dev-deps', '--offline-scan',
           '--skip-db-update', '--skip-java-db-update', '--skip-version-check',
           '--disable-telemetry', '--ignorefile', '', '--ignore-unfixed=false',
           '--severity', 'UNKNOWN,LOW,MEDIUM,HIGH,CRITICAL', '--list-all-pkgs',
           '--parallel', '2', '--format', 'json', '--exit-code', '0',
           '--timeout', '10m', '--no-progress']

def now():
    return dt.datetime.now(dt.timezone.utc).isoformat()

def digest(path):
    h = hashlib.sha256()
    with path.open('rb') as f:
        for b in iter(lambda: f.read(MIB), b''):
            h.update(b)
    return h.hexdigest()

def bounded(cmd, seconds, out, out_limit, err, err_limit=2*MIB):
    """Hard byte ceilings on each captured stream and wall-clock timeout."""
    p = subprocess.Popen(cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
    selector = selectors.DefaultSelector()
    deadline = time.monotonic() + seconds
    sizes = {1: 0, 2: 0}
    with out.open('wb') as of, err.open('wb') as ef:
        for stream, number, output, limit in [(p.stdout, 1, of, out_limit), (p.stderr, 2, ef, err_limit)]:
            os.set_blocking(stream.fileno(), False)
            selector.register(stream, selectors.EVENT_READ, (number, output, limit))
        try:
            while selector.get_map():
                if time.monotonic() > deadline:
                    raise RuntimeError('Command exceeded wall-clock limit')
                for key, _ in selector.select(timeout=min(1, max(0, deadline-time.monotonic()))):
                    chunk = os.read(key.fd, 65536)
                    if not chunk:
                        selector.unregister(key.fileobj)
                        continue
                    number, output, limit = key.data
                    if sizes[number] + len(chunk) > limit:
                        raise RuntimeError('Command exceeded capture byte limit')
                    output.write(chunk)
                    sizes[number] += len(chunk)
            rc = p.wait(timeout=max(.1, deadline-time.monotonic()))
            if rc != 0:
                raise RuntimeError(f'Command failed with exit code {rc}')
        finally:
            selector.close()
            if p.poll() is None:
                p.kill()
            p.wait()
            p.stdout.close()
            p.stderr.close()

def extract_db(archive, dest):
    allowed = {'db/trivy.db', 'db/metadata.json', 'java-db/trivy-java.db', 'java-db/metadata.json'}
    seen = set()
    total = 0
    with tarfile.open(archive, 'r:') as tar:
        for member in tar:
            name = member.name.removeprefix('./').rstrip('/')
            if member.isdir() and name in {'db', 'java-db'}:
                continue
            if name not in allowed or not member.isfile() or name in seen:
                raise RuntimeError('Unexpected or unsafe DB archive member')
            total += member.size
            if total > DB_BUDGET or member.size < 0:
                raise RuntimeError('Expanded DB archive too large')
            if name.endswith('metadata.json') and member.size > MIB:
                raise RuntimeError('DB metadata too large')
            target = dest / name
            target.parent.mkdir(parents=True, exist_ok=True)
            with tar.extractfile(member) as src, target.open('xb') as dst:
                shutil.copyfileobj(src, dst, MIB)
            target.chmod(0o600)
            seen.add(name)
    if seen != allowed:
        raise RuntimeError('Incomplete DB archive')


def main():
    os.umask(0o077)
    run = os.environ.get('GITHUB_RUN_ID', '')
    attempt = os.environ.get('GITHUB_RUN_ATTEMPT', '')
    if not re.fullmatch(r'[0-9]+', run) or not re.fullmatch(r'[0-9]+', attempt):
        raise RuntimeError('Numeric CI run and attempt required')
    uid, gid = os.getuid(), os.getgid()
    if uid == 0:
        raise RuntimeError('Non-root runner UID required')
    evidence = Path('scan-evidence')
    evidence.mkdir(exist_ok=False)
    temp = Path(tempfile.mkdtemp(prefix='public-n8n-scan-', dir=os.environ['RUNNER_TEMP']))
    owned = []
    status = {'state': 'incomplete', 'started_at': now(), 'scanner': SCANNER, 'target': TARGET,
              'platform': 'linux/amd64', 'expected_target_child': EXPECTED_CHILD,
              'options': OPTIONS, 'run_id': run, 'run_attempt': attempt,
              'resource_limits': {'database_bytes': DB_BUDGET, 'tmp_bytes': TMP_BUDGET,
                                  'total_tmpfs_bytes': DB_BUDGET+TMP_BUDGET,
                                  'container_memory_bytes': MEMORY_BUDGET}}
    stage = 'preflight'
    def command(args, seconds=30, name='control', limit=MIB):
        out, err = temp / (name+'.out'), evidence / (name+'.log')
        bounded(args, seconds, out, limit, err)
        return out.read_text()
    common = ['--platform', 'linux/amd64', '--user', f'{uid}:{gid}', '--read-only',
              '--cap-drop', 'ALL', '--security-opt', 'no-new-privileges',
              '--pids-limit', '128', '--memory', '6g', '--cpus', '2',
              '--log-driver', 'none', '-e', 'HOME=/tmp', '--workdir', '/tmp',
              '--tmpfs', f'/cache:rw,nosuid,nodev,noexec,uid={uid},gid={gid},mode=0700,size={DB_BUDGET}',
              '--tmpfs', f'/tmp:rw,nosuid,nodev,noexec,uid={uid},gid={gid},mode=0700,size={TMP_BUDGET}']
    def create(suffix, network, mounts, args, shell=False):
        name = f'n8n-public-scan-{run}-{attempt}-{suffix}'
        # Listing is checked successfully first; missing-name cannot mask daemon failure.
        names = command(['docker', 'ps', '-a', '--format', '{{.Names}}'], name='names').splitlines()
        if name in names:
            raise RuntimeError('Container name collision')
        cmd = ['docker', 'create', '--name', name, *common, '--network', network]
        for mount in mounts:
            cmd += ['--mount', mount]
        if shell:
            cmd += ['--entrypoint', '/bin/sh']
        cid = command([*cmd, SCANNER, *args], name='create').strip()
        if not re.fullmatch(r'[0-9a-f]{64}', cid):
            raise RuntimeError('Uncertain container create result; refusing ID guessing')
        owned.append(cid)
        return cid
    def start(cid, seconds, out, limit, log):
        bounded(['docker', 'start', '--attach', cid], seconds, out, limit, log)
        info = json.loads(command(['docker', 'inspect', cid], name='inspect'))[0]
        if info['State']['Running'] or info['State']['ExitCode'] != 0:
            raise RuntimeError('Container did not complete successfully')
    try:
        if shutil.disk_usage(temp).free < 16*GIB:
            raise RuntimeError('At least 16GiB free runner disk required')
        command(['docker', 'info'], name='docker-info')
        stage = 'pull-public-images'
        command(['docker', 'pull', '--platform', 'linux/amd64', SCANNER], 300, 'scanner-pull')
        command(['docker', 'pull', '--platform', 'linux/amd64', TARGET], 300, 'target-pull')
        inspect = json.loads(command(['docker', 'image', 'inspect', SCANNER, TARGET], name='image-inspect'))
        # Inspect contains public image metadata only. No container or host environment exported.
        status['images'] = [{'id': i['Id'], 'repo_digests': i['RepoDigests'], 'os': i['Os'],
                             'arch': i['Architecture'], 'size_bytes': i['Size']} for i in inspect]
        if any(i['Os'] != 'linux' or i['Architecture'] != 'amd64' or i['Size'] > 3*GIB for i in inspect):
            raise RuntimeError('Unexpected platform or image exceeds budget')
        stage = 'scanner-version'
        cid = create('version', 'none', [], ['--version'])
        start(cid, 30, evidence/'scanner-version.txt', MIB, evidence/'version.log')
        if not re.search(r'^Version: 0\.76\.2$', (evidence/'scanner-version.txt').read_text(), re.M):
            raise RuntimeError('Scanner version mismatch')
        stage = 'public-database-download'
        db_script = '''set -eu
trivy image --cache-dir /cache --download-db-only --db-repository ghcr.io/aquasecurity/trivy-db:2 --disable-telemetry --skip-version-check --no-progress --timeout 5m >&2
trivy image --cache-dir /cache --download-java-db-only --skip-db-update --java-db-repository ghcr.io/aquasecurity/trivy-java-db:1 --disable-telemetry --skip-version-check --no-progress --timeout 5m >&2
tar -C /cache -cf - db/trivy.db db/metadata.json java-db/trivy-java.db java-db/metadata.json
'''
        # Networked downloader sees no host mount, image archive, source or credentials.
        cid = create('db', 'bridge', [], ['-c', db_script], shell=True)
        start(cid, 630, temp/'db.tar', DB_BUDGET, evidence/'db-download.log')
        extract_db(temp/'db.tar', temp/'database')
        (temp/'db.tar').unlink()
        status['databases'] = {}
        for path in sorted((temp/'database').rglob('*')):
            if path.is_file():
                entry = {'sha256': digest(path), 'bytes': path.stat().st_size}
                if path.name == 'metadata.json':
                    entry['metadata'] = json.loads(path.read_text())
                status['databases'][str(path.relative_to(temp/'database'))] = entry
        stage = 'save-public-image-archive'
        bounded(['docker', 'save', TARGET], 180, temp/'image.tar', 3*GIB, evidence/'image-save.log')
        status['archive'] = {'sha256': digest(temp/'image.tar'), 'bytes': (temp/'image.tar').stat().st_size}
        stage = 'offline-image-analysis'
        # Trivy bbolt opens the active DB read/write. Read-only original snapshot is
        # copied to bounded ephemeral /cache; never make a host DB mount writable.
        script = 'set -eu; cp -R /database/db /database/java-db /cache/; exec trivy "$@"'
        cid = create('scan', 'none', [f'type=bind,src={temp}/database,dst=/database,readonly',
                                     f'type=bind,src={temp}/image.tar,dst=/input/image.tar,readonly'],
                     ['-c', script, 'scan', *OPTIONS], shell=True)
        info = json.loads(command(['docker', 'inspect', cid], name='isolation'))[0]
        if info['HostConfig']['NetworkMode'] != 'none' or any(m['RW'] for m in info['Mounts'] if m['Type'] == 'bind'):
            raise RuntimeError('Offline mount/network isolation verification failed')
        start(cid, 630, evidence/'report.json', 16*MIB, evidence/'scan.log')
        # Successful command is NOT a zero-vulnerability verdict. Policy is separate.
        status['state'] = 'scanner_completed'
        stage = 'complete'
    except Exception as exc:
        status['error'] = str(exc)
        print(f'Scanner execution incomplete at {stage}; see bounded evidence.')
    finally:
        status['stage'] = stage
        status['finished_at'] = now()
        cleanup_ok = True
        for cid in reversed(owned):
            try:
                subprocess.run(['docker', 'rm', '-f', cid], timeout=30, check=True,
                               stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
            except Exception:
                cleanup_ok = False
        status['cleanup_ok'] = cleanup_ok
        if not cleanup_ok:
            status['state'] = 'incomplete'
            status['error'] = 'Owned container cleanup failed'
        (evidence/'execution.json').write_text(json.dumps(status, indent=2)+'\n')
        # Inputs are public but not uploaded. Remove only this process's tempfile tree.
        shutil.rmtree(temp)
    return 0 if status['state'] == 'scanner_completed' else 20

if __name__ == '__main__':
    sys.exit(main())
