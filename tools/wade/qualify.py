# SPDX-License-Identifier: AGPL-3.0-or-later
"""WADE reference/build qualification. No installation, cluster requests or credentials."""
import argparse
import hashlib
import json
from pathlib import Path
import subprocess
import tempfile
import zipfile

INDEXER_BASE = 'e2871f7d68ee46fef2b01e21d3261dc6ab411489'
DASHBOARD_BASE = '22901fa354f20616d4bc707003b4b8a115cfb3d9'
EXTERNAL_GATES = [
    'Native plugin compilation and exact RC2 distribution ABI/boot (including uninstall)',
    'Authenticated rule approvals, source scope, canonical agent identity and index UUID authority',
    'Trusted event availability, complete stable multi-index snapshots and watermark qualification',
    'Real secured two-node CAS, immutable delivery, failover and ambiguous acknowledgement tests',
    'Native scheduler, persisted checkpoint, fair late replay, resource limits and recovery',
    'Native Sigma conformance, real historical replay/shadow and protected labelled coverage',
    'Persistent native risk/UEBA, entity graph and telemetry health integration',
    'Dashboard packaging, authenticated live APIs, RBAC, accessibility and browser tests',
    'Analyst disposition provenance, independent approval and AI/ML qualification',
    'Incident finding revision consumer, idempotency, evidence retention and joint rollback',
    'Measured ingest impact, query latency, CPU/RSS, capacity, retention and operational acceptance',
]


def sha(path):
    with path.open('rb') as stream:
        return hashlib.file_digest(stream, 'sha256').hexdigest()


def git(root, *args):
    return subprocess.run(['git', '-C', str(root), *args], check=True, capture_output=True, text=True, timeout=30).stdout.strip()


def checkout(root, base, prefix):
    head = git(root, 'rev-parse', 'HEAD')
    if git(root, 'status', '--porcelain'):
        raise ValueError(f'dirty checkout: {root.name}')
    git(root, 'merge-base', '--is-ancestor', base, head)
    changed = git(root, 'diff', '--name-only', base, head).splitlines()
    if not changed or any(not x.startswith(prefix) for x in changed):
        raise ValueError(f'unexpected WADE branch footprint: {root.name}')
    return {'head': head, 'base': base, 'changed_files': len(changed)}


def step(root, out, name, command, timeout):
    log = out / (name + '.log')
    status, code = 'FAIL', None
    with log.open('wb') as stream:
        try:
            result = subprocess.run(command, cwd=root, stdout=stream, stderr=subprocess.STDOUT, timeout=timeout, check=False)
            code = result.returncode
            status = 'PASS' if code == 0 else 'FAIL'
        except subprocess.TimeoutExpired:
            stream.write(b'\nQUALIFICATION TIMEOUT\n')
        except OSError as error:
            stream.write(('\nEXECUTION UNAVAILABLE: ' + type(error).__name__ + '\n').encode())
    return {'name':name,'status':status,'exit_code':code,'log':log.name,'sha256':sha(log)}


def zip_receipt(path):
    with zipfile.ZipFile(path) as archive:
        members = archive.namelist()
        if members.count('plugin-descriptor.properties') != 1:
            raise ValueError('missing or duplicate plugin descriptor')
        info = archive.getinfo('plugin-descriptor.properties')
        if info.file_size > 65536:
            raise ValueError('descriptor size limit')
        descriptor = archive.read(info).decode('utf-8')
    fields = dict(line.split('=',1) for line in descriptor.splitlines() if '=' in line and not line.startswith('#'))
    if fields.get('name') != 'wazuh-indexer-wade' or fields.get('classname') != 'com.wazuh.wade.plugin.WadePlugin':
        raise ValueError('unexpected plugin descriptor')
    return {'file':path.name,'bytes':path.stat().st_size,'sha256':sha(path),'descriptor':{k:fields.get(k) for k in ('name','version','opensearch.version','java.version','classname')}}


def report_status(steps, native_requested, package):
    reference = [s for s in steps if s['name'] != 'native-build']
    ok = bool(reference) and all(s['status'] == 'PASS' for s in reference)
    native = [s for s in steps if s['name'] == 'native-build']
    built = bool(native) and all(s['status'] == 'PASS' for s in native) and package is not None
    return {'reference':'PASS' if ok else 'FAIL', 'native_package':'PASS' if built else 'FAIL' if native_requested else 'NOT_RUN',
            'production':'BLOCKED', 'exit_code':0 if ok and (not native_requested or built) else 1}


def main():
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--out', required=True, type=Path, help='New private output directory outside both checkouts')
    parser.add_argument('--dashboard-checkout', type=Path)
    parser.add_argument('--native-build', action='store_true')
    parser.add_argument('--opensearch-version', default='3.6.0-SNAPSHOT')
    args=parser.parse_args()
    root=Path(__file__).resolve().parents[2]
    dashboard=args.dashboard_checkout.resolve() if args.dashboard_checkout else None
    out=args.out.resolve()
    if out.is_relative_to(root) or (dashboard and out.is_relative_to(dashboard)):
        parser.error('output must be outside checkouts')
    if not args.opensearch_version or len(args.opensearch_version)>80 or any(c not in 'abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789.-_' for c in args.opensearch_version):
        parser.error('invalid OpenSearch artifact version')
    out.mkdir(mode=0o700,parents=False,exist_ok=False)
    report={'format':'wade-qualification-v1','scope':'reference-and-package-only','steps':[], 'external_gates':EXTERNAL_GATES, 'package':None}
    steps=report['steps']
    try:
        report['indexer']=checkout(root,INDEXER_BASE,'tools/wade/')
        if dashboard:
            report['dashboard']=checkout(dashboard,DASHBOARD_BASE,'tools/wade-review/')
        else:
            report['dashboard']={'status':'NOT_RUN'}
        commands=[('java-reference',['sh','tools/wade/test-analytics.sh'],600),
                  ('python-native',['python3','-B','-m','unittest','discover','-s','tools/wade/native','-v'],600),
                  ('mapping-contracts',['python3','-B','-m','unittest','discover','-s','tools/wade/contracts','-v'],120),
                  ('qualification-selftest',['python3','-B','tools/wade/test_qualify.py'],120)]
        for name,command,timeout in commands: steps.append(step(root,out,name,command,timeout))
        if dashboard:
            import shutil
            with tempfile.TemporaryDirectory() as temp:
                work=Path(temp); source=dashboard/'tools/wade-review'
                shutil.copytree(source/'public',work/'public');shutil.copytree(source/'test',work/'test')
                compiled=step(work,out,'dashboard-typescript',['tsc','--strict','--target','ES2020','--module','commonjs','--lib','ES2020,DOM','--rootDir','public','--outDir','build','public/review.ts','public/application.ts'],120)
                steps.append(compiled)
                if compiled['status']=='PASS': steps.append(step(work,out,'dashboard-review-tests',['node','--test','test/review.test.cjs'],120))
                steps.append(step(root,out,'java-dashboard-contract',['python3','-B','tools/wade/test-replay-contract.py',str(work)],600))
        if args.native_build and all(s['status']=='PASS' for s in steps):
            report['opensearch_artifact_version']=args.opensearch_version
            # Require a fresh build output rather than accepting a stale ZIP. Gradle clean only targets this independent project.
            command=['sh','gradlew','-p','tools/wade/plugin','--no-daemon','-Dopensearch.version='+args.opensearch_version,'clean','bundlePlugin']
            build=step(root,out,'native-build',command,1800);steps.append(build)
            if build['status']=='PASS':
                paths=list((root/'tools/wade/plugin/build/distributions').glob('*.zip'))
                if len(paths)!=1: raise ValueError('expected exactly one plugin ZIP')
                report['package']=zip_receipt(paths[0])
    except (ValueError,OSError,subprocess.SubprocessError,zipfile.BadZipFile) as error:
        report['qualification_error']=str(error)
        steps.append({'name':'qualification-preconditions','status':'FAIL'})
    report.update(report_status(steps,args.native_build,report['package']))
    (out/'report.json').write_text(json.dumps(report,indent=2,sort_keys=True)+'\n',encoding='utf-8')
    print(json.dumps({k:report[k] for k in ('reference','native_package','production','exit_code')},indent=2))
    return report['exit_code']


if __name__=='__main__':
    raise SystemExit(main())
