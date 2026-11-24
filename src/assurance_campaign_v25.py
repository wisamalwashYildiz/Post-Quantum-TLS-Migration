#!/usr/bin/env python3
"""v2.5 repeatable, fail-closed campaign and public evidence archive.

Executes v2.4 root-isolated live TLS in native Linux temporary paths; only
allowlisted, verified verdict data are retained in the Windows-backed project.
The campaign does NOT claim independent receiver-UID separation or TLS exporters.
"""
import argparse
import csv
from datetime import datetime, timezone
import hashlib
import json
import os
from pathlib import Path
import platform
import re
import subprocess
import sys
import uuid

EXPECTED = {'hybrid':'SATISFIED','classical_middle':'VIOLATED',
            'forged_baseline':'SATISFIED','forged_corroborated':'INVALID',
            'missing_witness':'UNRESOLVED','swapped_witness':'INVALID',
            'replayed_transaction':'INVALID'}
FIELD_NAMES=['run_id','status','hybrid','classical_middle','forged_baseline',
             'forged_corroborated','missing_witness','swapped_witness',
             'replayed_transaction','attacker_key_read_denied','transactions_per_connection']


def verdict(value):
    if isinstance(value, str):return value
    if isinstance(value, (list,tuple)) and value and isinstance(value[0],str):return value[0]
    raise ValueError('invalid verdict value')


def sanitized_evidence(raw, expected_count):
    if not isinstance(raw, dict) or raw.get('version')!='2.4':raise ValueError('unexpected evidence version')
    if raw.get('count_per_connection')!=expected_count:raise ValueError('count mismatch')
    if raw.get('attacker_key_read_denied') is not True:raise ValueError('observer key boundary not demonstrated')
    checks=raw.get('checks')
    if not isinstance(checks,dict) or set(checks)!=set(EXPECTED):raise ValueError('missing/unexpected checks')
    outcome={key:verdict(checks[key]) for key in EXPECTED}
    for name,expected in EXPECTED.items():
        if outcome[name]!=expected:raise ValueError(f'condition {name}: {outcome[name]} != {expected}')
    groups=raw.get('groups')
    if not isinstance(groups,dict):raise ValueError('missing groups')
    if groups.get('hybrid')!=['X25519MLKEM768']*3:raise ValueError('hybrid negotiation mismatch')
    if groups.get('classical_middle')!=['X25519MLKEM768','X25519','X25519MLKEM768']:
        raise ValueError('classical negotiation mismatch')
    # Explicit allowlist: never persist extra content such as keys, transactions, or receipts.
    return {'schema':'pqc-v25-sanitized-v1','source_version':'2.4',
            'openssl':str(raw.get('openssl','')),'count_per_connection':expected_count,
            'checks':outcome,'groups':groups,'attacker_key_read_denied':True,
            'limits':raw.get('limits',[]) if isinstance(raw.get('limits'),list) else []}


def write_json(path,obj):
    path.write_text(json.dumps(obj,indent=2,sort_keys=True)+'\n',encoding='utf-8')


def sha256(path):return hashlib.sha256(path.read_bytes()).hexdigest()


def run_capture(command,log,**kw):
    proc=subprocess.run(command,stdout=subprocess.PIPE,stderr=subprocess.STDOUT,text=True,**kw)
    log.write_text(proc.stdout,encoding='utf-8')
    return proc.returncode


def campaign(args):
    if os.geteuid()==0:raise RuntimeError('Campaign must run as normal project user, not root')
    if platform.system()!='Linux':raise RuntimeError('Requires Linux / Ubuntu')
    if not Path(args.runner).is_file():raise FileNotFoundError(args.runner)
    if not Path(args.python).is_file():raise FileNotFoundError(args.python)
    if not Path(args.openssl).is_file():raise FileNotFoundError(args.openssl)
    if args.trials<1 or args.trials>30:raise ValueError('trials must be 1..30')
    if args.count<2 or args.count>100:raise ValueError('count must be 2..100')
    if not re.fullmatch(r'[a-z_][a-z0-9_-]{0,31}',args.attacker_user):raise ValueError('invalid attacker user')
    root=Path(args.archive).resolve();root.mkdir(parents=True,exist_ok=True)
    tag=datetime.now(timezone.utc).strftime('%Y%m%dT%H%M%SZ')+'_'+uuid.uuid4().hex[:8]
    archive=root/('campaign_'+tag)
    archive.mkdir(mode=0o755)
    version=subprocess.run([args.python,'-c','import ssl;print(ssl.OPENSSL_VERSION)'],capture_output=True,text=True)
    manifest={'schema':'pqc-v25-campaign-v1','campaign_id':tag,'created_utc':datetime.now(timezone.utc).isoformat(),
              'mode':'new live TLS per trial; v2.4 root receivers and nobody attacker',
              'trials_requested':args.trials,'transactions_per_connection':args.count,
              'openssl_python':version.stdout.strip(),'platform':platform.platform(),
              'attacker_user':args.attacker_user,
              'security_limits':['receivers share root trust domain','forged relay claims are offline re-signing',
                                 'public handshake correlation labels are not TLS exporters',
                                 'sequential connection reuse, not concurrent multiplexing',
                                 'laboratory TLS certificate validation disabled','not post-quantum X.509 authentication'],
              'run_results':[]}
    write_json(archive/'manifest.json',manifest)
    print('Campaign archive:',archive,flush=True)
    # Authentication before trials, rather than prompting at an arbitrary subprocess stage.
    auth=subprocess.run(['sudo','-v'])
    if auth.returncode:raise RuntimeError('sudo authentication failed')
    rows=[];failures=0
    if not args.skip_tests:
        test_code=run_capture([args.python,'-m','unittest','discover','-s','tests','-p','test_*.py','-v'],
                              archive/'test_results.txt',timeout=90)
        manifest['test_suite_exit_code']=test_code
        write_json(archive/'manifest.json',manifest)
        if test_code:
            print('STOP: regression suite failed; no live trials attempted',flush=True)
            raise SystemExit(2)
    lib=os.environ.get('LD_LIBRARY_PATH','')
    for i in range(args.trials):
        run_id=f'trial_{i+1:03d}'
        trial=archive/run_id;trial.mkdir()
        # Native Ubuntu /var/tmp used ONLY for privileged runtime; no private data copied into archive.
        protected=f'/var/tmp/pqc-v25-{tag}-{i+1:03d}'
        command=['sudo','mkdir','-p',protected]
        try:
            code=run_capture(command,trial/'setup.log',timeout=20)
            if code:raise RuntimeError('protected directory mkdir failed')
            code=run_capture(['sudo','chown','root:root',protected],trial/'ownership.log',timeout=20)
            if code:raise RuntimeError('protected directory ownership failed')
            code=run_capture(['sudo','chmod','700',protected],trial/'permissions.log',timeout=20)
            if code:raise RuntimeError('protected directory permissions failed')
            command=['sudo','env',f'LD_LIBRARY_PATH={lib}',args.python,args.runner,
                     '--openssl',args.openssl,'--output',protected,
                     '--attacker-user',args.attacker_user,'--count',str(args.count)]
            code=run_capture(command,trial/'experiment.log',timeout=args.timeout)
            if code:raise RuntimeError(f'live experiment exit code {code}')
            res=subprocess.run(['sudo','cat',protected+'/protected_path_v24.json'],capture_output=True,text=True,timeout=20)
            if res.returncode:raise RuntimeError('missing protected evidence: '+res.stderr[-300:])
            clean=sanitized_evidence(json.loads(res.stdout),args.count)
            write_json(trial/'evidence.json',clean)
            row={'run_id':run_id,'status':'PASS',**clean['checks'],
                 'attacker_key_read_denied':True,'transactions_per_connection':args.count}
            write_json(trial/'verification.json',{'status':'PASS','expected':EXPECTED,'actual':clean['checks'],
                                                 'method':'independent JSON/schema/verdict checks, not independent cryptographic verifier'})
            print(run_id,'PASS',flush=True)
        except Exception as exc:
            failures+=1
            row={'run_id':run_id,'status':'FAIL','error':str(exc)}
            write_json(trial/'verification.json',{'status':'FAIL','error':str(exc)})
            print(run_id,'FAIL:',exc,flush=True)
        finally:
            # Destroy root-owned protected runtime, including any keys (if present).
            cleanup=subprocess.run(['sudo','rm','-rf','--',protected],capture_output=True,text=True)
            if cleanup.returncode:
                row['cleanup_failed']=True
                failures+=1
                print('WARNING: protected runtime cleanup failed:',protected,flush=True)
            rows.append(row)
            manifest['run_results'].append({'run_id':run_id,'status':row['status'],
                                            'error':row.get('error'), 'cleanup_failed':row.get('cleanup_failed',False)})
            write_json(archive/'manifest.json',manifest)
    with (archive/'summary.csv').open('w',newline='',encoding='utf-8') as stream:
        writer=csv.DictWriter(stream,fieldnames=FIELD_NAMES,extrasaction='ignore');writer.writeheader();writer.writerows(rows)
    summary={'trials':args.trials,'passed':sum(r['status']=='PASS' for r in rows),
             'failed':sum(r['status']!='PASS' for r in rows),'cleanup_errors':sum(bool(r.get('cleanup_failed')) for r in rows),
             'count_per_connection':args.count, 'new_live_tls_connections_expected_per_trial':6,
             'explanation':'Two experimental conditions, each with three real TLS legs; 3*count application forwards per condition.'}
    write_json(archive/'aggregate.json',summary)
    # Hash stable public results, not the checksums file itself.
    with (archive/'checksums.sha256').open('w',encoding='utf-8') as stream:
        for path in sorted(archive.rglob('*')):
            if path.is_file() and path.name!='checksums.sha256':
                stream.write(f'{sha256(path)}  {path.relative_to(archive)}\n')
    print('Summary:',summary,flush=True)
    print('Saved:',archive,flush=True)
    if failures:raise SystemExit(1)


def main():
    p=argparse.ArgumentParser(description=__doc__)
    p.add_argument('--runner',default='src/protected_path_v24.py')
    p.add_argument('--python',required=True,help='absolute path to research Python 3.12')
    p.add_argument('--openssl',required=True,help='absolute path to OpenSSL CLI')
    p.add_argument('--archive',default='results/assurance_campaign_v25')
    p.add_argument('--trials',type=int,default=3);p.add_argument('--count',type=int,default=3)
    p.add_argument('--attacker-user',default='nobody');p.add_argument('--timeout',type=int,default=150)
    p.add_argument('--skip-tests',action='store_true',help='Skip full regression suite (not recommended)')
    campaign(p.parse_args())
if __name__=='__main__':main()
