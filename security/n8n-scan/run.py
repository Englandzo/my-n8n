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
TARGET = 'n8nio/n8n@sha256:8602f5dfacbe2c931eeafd010de0e68182310e9f309921e780ab69182e92b3ae'
EXPECTED_CHILD = 'sha256:256a0fca38c4f0ab02524bcebf77b8ed5acc7aa99a28c4cbca7a4034a76d4b97'
OPTIONS = ['image', '--cache-dir', '/cache', '--input', '/input/image.tar',
           '--scanners', 'vuln', '--pkg-types', 'os,library', '--offline-scan',
           '--skip-db-update', '--skip-java-db-update', '--skip-version-check',
           '--disable-telemetry', '--ignorefile', '', '--ignore-unfixed=false',
           '--severity', 'UNKNOWN,LOW,MEDIUM,HIGH,CRITICAL', '--list-all-pkgs',
           '--parallel', '2', '--format', 'json', '--exit-code', '0',
           '--timeout', '10m', '--no-progress']

def validate_image_flags(help_text):
    # Verify the actual pinned image subcommand, not just generic flag definitions.
    expected = {x.split('=', 1)[0] for x in OPTIONS if x.startswith('--')}
    expected |= {'--download-db-only', '--db-repository', '--download-java-db-only', '--java-db-repository'}
    available = set(re.findall(r'--[a-z][a-z0-9-]*', help_text))
    missing = expected - available
    if missing:
        raise RuntimeError('Unsupported image flags: ' + ', '.join(sorted(missing)))
    return sorted(expected)

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

def extract_db(archive, dest, allowed=None, budget=DB_BUDGET):
    allowed = allowed or {'db/trivy.db', 'db/metadata.json', 'java-db/trivy-java.db', 'java-db/metadata.json'}
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
            if total > budget or member.size < 0:
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
              '--log-driver', 'none', '-e', 'HOME=/tmp', '--workdir', '/tmp']
    def create(suffix, network, mounts, args, shell=False, cache_bytes=DB_BUDGET, tmp_bytes=TMP_BUDGET):
        assert cache_bytes + tmp_bytes <= 5*GIB
        name = f'n8n-public-scan-{run}-{attempt}-{suffix}'
        # Listing is checked successfully first; missing-name cannot mask daemon failure.
        names = command(['docker', 'ps', '-a', '--format', '{{.Names}}'], name='names').splitlines()
        if name in names:
            raise RuntimeError('Container name collision')
        cmd = ['docker', 'create', '--name', name, *common, '--network', network,
               '--tmpfs', f'/cache:rw,nosuid,nodev,noexec,uid={uid},gid={gid},mode=0700,size={cache_bytes}',
               '--tmpfs', f'/tmp:rw,nosuid,nodev,noexec,uid={uid},gid={gid},mode=0700,size={tmp_bytes}']
        for mount in mounts:
            cmd += ['--mount', mount]
        if shell:
            cmd += ['--entrypoint', '/bin/sh']
        cid = command([*cmd, SCANNER, *args], name='create').strip()
        if not re.fullmatch(r'[0-9a-f]{64}', cid):
            raise RuntimeError('Uncertain container create result; refusing ID guessing')
        owned.append(cid)
        return cid
    def start(cid, seconds, out, limit, log, log_limit=2*MIB):
        bounded(['docker', 'start', '--attach', cid], seconds, out, limit, log, log_limit)
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
        stage = 'scanner-image-help'
        cid = create('help', 'none', [], ['image', '--help'])
        start(cid, 30, temp/'image-help.txt', MIB//2, evidence/'version.log')
        help_bytes = (temp/'image-help.txt').read_bytes()
        status['verified_image_flags'] = validate_image_flags(help_bytes.decode())
        status['image_help_sha256'] = hashlib.sha256(help_bytes).hexdigest()
        status['installed_package_scope_source'] = 'https://github.com/aquasecurity/trivy/blob/v0.76.2/pkg/commands/app.go'
        with (evidence/'scanner-version.txt').open('ab') as f:
            f.write(b'\n--- Exact image subcommand help ---\n' + help_bytes)
        stage = 'public-database-download'
        downloads = [
            ('vuln', 'db', 'trivy.db', '--download-db-only --db-repository ghcr.io/aquasecurity/trivy-db:2'),
            ('java', 'java-db', 'trivy-java.db', '--download-java-db-only --java-db-repository ghcr.io/aquasecurity/trivy-java-db:1'),
        ]
        status['resource_limits']['download_cache_bytes'] = 2*GIB
        status['resource_limits']['download_tmp_bytes'] = 2*GIB
        combined_log = evidence/'db-download.log'
        combined_log.write_bytes(b'')
        for kind, folder, filename, flags in downloads:
            stage = 'public-database-download-' + kind
            db_script = (f'set -eu; trivy image --cache-dir /cache {flags} '
                         '--disable-telemetry --skip-version-check --no-progress --timeout 5m >&2; '
                         f'tar -C /cache -cf - {folder}/{filename} {folder}/metadata.json')
            # Each networked downloader sees no mounts or previous DB. Its cache
            # and double-compressed temporary copies fit independent 2GiB bounds.
            cid = create('db-'+kind, 'bridge', [], ['-c', db_script], shell=True,
                         cache_bytes=2*GIB, tmp_bytes=2*GIB)
            part_log = temp/(kind+'.log')
            try:
                start(cid, 330, temp/'db.tar', 2*GIB, part_log, log_limit=MIB)
            finally:
                if part_log.exists():
                    with combined_log.open('ab') as f:
                        f.write(part_log.read_bytes())
            extract_db(temp/'db.tar', temp/'database',
                       allowed={f'{folder}/{filename}', f'{folder}/metadata.json'}, budget=2*GIB)
            (temp/'db.tar').unlink()
            if sum(p.stat().st_size for p in (temp/'database').rglob('*') if p.is_file()) > DB_BUDGET:
                raise RuntimeError('Combined database snapshot exceeds budget')
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
