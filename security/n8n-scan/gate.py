#!/usr/bin/env python3
"""Different outcomes: 20=incomplete, 10=policy findings, 0=no High/Critical found."""
import collections
import hashlib
import json
from pathlib import Path
import sys

MIB = 1024**2
SEVERITIES = ('UNKNOWN', 'LOW', 'MEDIUM', 'HIGH', 'CRITICAL')

def assess(report, execution):
    if execution.get('state') != 'scanner_completed' or not execution.get('cleanup_ok'):
        raise ValueError('Scanner did not complete successfully')
    if report.get('ArtifactType') != 'container_image' or not report.get('Metadata', {}).get('OS', {}).get('Family'):
        raise ValueError('Image/OS identification missing')
    if report['Metadata'].get('ImageID') != execution['images'][1]['id']:
        raise ValueError('Scanned image ID differs from pulled public image')
    results = report.get('Results', [])
    if not isinstance(results, list) or not results:
        raise ValueError('No package results')
    classes = {r.get('Class') for r in results if r.get('Packages')}
    if not {'os-pkgs', 'lang-pkgs'}.issubset(classes):
        raise ValueError('Both OS and library inventories required')
    packages = [p for r in results for p in r.get('Packages', [])]
    if not any(p.get('Name') == 'n8n' and p.get('Version') == '2.46.6' for p in packages):
        raise ValueError('Expected n8n package version absent from inventory')
    counts = {s: {'fix_available': 0, 'no_fix_reported': 0} for s in SEVERITIES}
    affected = set()
    for r in results:
        for v in r.get('Vulnerabilities', []) or []:
            if not v.get('VulnerabilityID') or not v.get('PkgName') or v.get('Severity') not in counts:
                raise ValueError('Malformed finding')
            category = 'fix_available' if v.get('FixedVersion') else 'no_fix_reported'
            counts[v['Severity']][category] += 1
            affected.add(v['VulnerabilityID'])
    high = sum(sum(counts[s].values()) for s in ('HIGH', 'CRITICAL'))
    eol = bool(report['Metadata']['OS'].get('EOSL'))
    return {'state': 'policy_findings' if high or eol else 'no_high_critical_found',
            'counts_by_occurrence': counts, 'unique_advisory_ids': len(affected),
            'package_occurrences': len(packages), 'os': report['Metadata']['OS'],
            'os_end_of_support': eol, 'high_critical_occurrences': high,
            'note': 'All severities and unfixed findings retained in full report; this is not proof of zero vulnerabilities.'}

def main():
    root = Path('scan-evidence')
    root.mkdir(exist_ok=True)
    try:
        report_path = root/'report.json'
        if report_path.stat().st_size > 16*MIB:
            raise ValueError('Full report exceeds read budget')
        report_bytes = report_path.read_bytes()
        result = assess(json.loads(report_bytes), json.loads((root/'execution.json').read_text()))
        result['report_sha256'] = hashlib.sha256(report_bytes).hexdigest()
        code = 10 if result['state'] == 'policy_findings' else 0
    except Exception as exc:
        result = {'state': 'incomplete', 'error': str(exc), 'note': 'No clean security verdict.'}
        code = 20
    (root/'summary.json').write_text(json.dumps(result, indent=2)+'\n')
    # Print only own labels and validated integer totals, never raw artifact strings
    # capable of injecting GitHub workflow commands.
    print('Scan outcome:', result['state'])
    for severity, values in result.get('counts_by_occurrence', {}).items():
        print(severity, 'fix available:', values['fix_available'], 'no fix reported:', values['no_fix_reported'])
    # Strict artifact allowlist, bounded total; no image/DB/archive/source uploads.
    allowed = {'execution.json','report.json','summary.json','scanner-version.txt',
               'docker-info.log','scanner-pull.log','target-pull.log','image-inspect.log',
               'names.log','create.log','version.log','inspect.log','db-download.log',
               'image-save.log','isolation.log','scan.log'}
    files = list(root.iterdir())
    total = sum(p.stat().st_size for p in files)
    if any(p.name not in allowed or not p.is_file() or p.is_symlink() for p in files) or total > 24*MIB:
        print('Evidence upload refused: allowlist or size check failed')
        result['state'] = 'incomplete'
        result['error'] = 'Evidence allowlist or size validation failed'
        (root/'summary.json').write_text(json.dumps(result, indent=2)+'\n')
        code = 20
    else:
        # Workflow uses this marker to avoid uploading arbitrary or oversized data.
        (root/'UPLOAD_READY').write_text('bounded public-image scan evidence only\n')
    return code

if __name__ == '__main__':
    sys.exit(main())
