#!/usr/bin/env python3
"""Instrumented, real-three-hop protected-verification latency experiment.

Executes the UNMODIFIED v32 cryptographic verifier and an instrumented copy of
v32.live_case with ONLY three monotonic timestamp insertions and an extended
return value. Uses real OpenSSL 3.5 TLS 1.3 connections and native Linux UIDs.
Run as root ONLY in the research WSL laboratory, never in production.
"""
import argparse, hashlib, inspect, json, os, pathlib, platform, secrets, sqlite3
import subprocess, sys, tempfile, time, statistics
from datetime import datetime, timezone


def percentile(v, p):
    v=sorted(v)
    if not v:return None
    k=(len(v)-1)*p/100
    lo=int(k); hi=min(lo+1,len(v)-1)
    return v[lo]+(v[hi]-v[lo])*(k-lo)

def summary(v):
    return {'count':len(v),'median_ms':statistics.median(v) if v else None,
            'p95_ms':percentile(v,95),'p99_ms':percentile(v,99),
            'min_ms':min(v) if v else None,'max_ms':max(v) if v else None}

def digest_file(path):return hashlib.sha256(path.read_bytes()).hexdigest()

def build_instrumented_live(v):
    # Copy the EXACT installed function from the repository. Add only markers.
    source=inspect.getsource(v.live_case)
    anchors={
        'def live_case(':'def timed_live_case(',
        '    if len(groups)!=3:': '    t_lab_start_ns=time.perf_counter_ns()\n    if len(groups)!=3:',
        '            for seq in range(count):\n                tx=': '            for seq in range(count):\n                tx=', # a no-op, assert that the source has expected structure elsewhere
        '                transactions.append(tx);send(connection,tx)':
          '                transactions.append(tx)\n                if seq==0:t_first_tx_ns=time.perf_counter_ns()\n                send(connection,tx)',
        "        return {'transactions':transactions,'client':client,'receivers':received,'registered_public_keys':keys},uid_info,access":
          "        t_evidence_ready_ns=time.perf_counter_ns()\n        return ({'transactions':transactions,'client':client,'receivers':received,'registered_public_keys':keys},uid_info,access,{'t_lab_start_ns':t_lab_start_ns,'t_first_tx_ns':t_first_tx_ns,'t_evidence_ready_ns':t_evidence_ready_ns})"
    }
    for old,new in anchors.items():
        if source.count(old)!=1:
            raise RuntimeError('Expected original live_case source anchor not unique or absent: '+repr(old[:65]))
        source=source.replace(old,new,1)
    ns={}
    exec(compile(source,'v32_live_case_instrumented','exec'),vars(v),ns)
    return ns['timed_live_case'],hashlib.sha256(source.encode()).hexdigest()

def main():
    ap=argparse.ArgumentParser(description=__doc__)
    ap.add_argument('--project',default='.')
    ap.add_argument('--openssl',required=True)
    ap.add_argument('--output',default='results/reviewer_c6_live_e2e/c6_live_e2e.json')
    ap.add_argument('--trials',type=int,default=10)
    ap.add_argument('--count',type=int,default=3)
    a=ap.parse_args()
    if not (2<=a.trials<=30 and 2<=a.count<=10):ap.error('--trials 2..30; --count 2..10')
    if os.geteuid()!=0:raise SystemExit('Requires sudo on disposable WSL experiment host for v32 UID separation')
    root=pathlib.Path(a.project).resolve()
    sys.path.insert(0,str(root/'src'))
    import v32_protected_freshness as v
    # The original v32 receiver workers fork and then drop to distinct Linux UIDs.
    # Import the cryptography backend in the trusted parent *before* fork to
    # avoid deferred module discovery from a research venv located under a
    # user-private home directory after the UID change. This does not alter
    # v32, its evidence, or its verification behavior.
    from cryptography.hazmat.backends.openssl.backend import backend as _crypto_backend
    from OpenSSL import SSL
    tls_ver=SSL.SSLeay_version(SSL.SSLEAY_VERSION).decode(errors='replace')
    openssl_ver=subprocess.check_output([a.openssl,'version'],text=True).strip()
    if 'OpenSSL 3.5' not in tls_ver or 'OpenSSL 3.5' not in openssl_ver:
        raise RuntimeError('Live test requires OpenSSL 3.5 both CLI and Python linkage; CLI='+openssl_ver+' Python='+tls_ver)
    instrumented, instrument_hash=build_instrumented_live(v)
    dest=(root/a.output).resolve() if not pathlib.Path(a.output).is_absolute() else pathlib.Path(a.output)
    dest.parent.mkdir(parents=True,exist_ok=True)
    output={'schema':'pqtls-c6-live-e2e-1','scope':('Real localhost 3-hop TLS1.3 handshake and application traffic; '
        'instrumented transaction-to-evidence collection; original v32 protected verifier; '
        'trusted root orchestrator, native Linux UID isolation; not distributed network latency.'),
        'timestamp_utc':datetime.now(timezone.utc).isoformat(),
        'environment':{'platform':platform.platform(),'python':sys.version.split()[0],
            'sqlite':sqlite3.sqlite_version,'ssl_linked':tls_ver,'openssl_cli':openssl_ver,
            'cpu_count':os.cpu_count()},
        'sources':{'v32_sha256':digest_file(root/'src'/'v32_protected_freshness.py'),
            'v30_sha256':digest_file(root/'src'/'v30_session_gate.py'),
            'instrumented_live_case_sha256':instrument_hash,
            'benchmark_sha256':digest_file(pathlib.Path(__file__).resolve())},
        'parameters':{'trials_per_scenario':a.trials,'transactions_per_trial':a.count,
            'scenarios':['hybrid','classical_middle']},'runs':[], 'summary':{}}
    def save():
        temp=dest.with_suffix('.tmp')
        temp.write_text(json.dumps(output,indent=2)+'\n',encoding='utf8')
        os.replace(temp,dest)
    save()
    # Native Linux temp directories are mandatory for UID-separated key files.
    with tempfile.TemporaryDirectory(prefix='pqtls-c6-real-',dir='/var/tmp') as tempdir:
        td=pathlib.Path(tempdir);td.chmod(0o711)
        cert,key=td/'cert.pem',td/'key.pem'
        cmd=[a.openssl,'req','-x509','-newkey','rsa:2048','-keyout',str(key),'-out',str(cert),
             '-days','1','-nodes','-subj','/CN=localhost']
        proc=subprocess.run(cmd,capture_output=True,text=True)
        if proc.returncode:raise RuntimeError('OpenSSL certificate generation failed: '+proc.stderr[-1000:])
        for trial in range(1,a.trials+1):
            for name, groups, expected in [('hybrid',(v.HYBRID,)*3,'SATISFIED'),
                                           ('classical_middle',(v.HYBRID,v.CLASSIC,v.HYBRID),'VIOLATED')]:
                row={'trial':trial,'scenario':name,'expected':expected,'status':'FAIL'}
                try:
                    with tempfile.TemporaryDirectory(prefix='roles-',dir=td) as roles:
                        pathlib.Path(roles).chmod(0o711)
                        ids=v.choose_uids(); challenge=secrets.token_hex(32)
                        # Full experimental cycle includes role setup, TLS handshakes,
                        # actual application traffic, receiver signing and collection,
                        # UID isolation check, and final freshness-protected verdict.
                        t_cycle_start=time.perf_counter_ns()
                        batch,uids,access,marks=instrumented(cert,key,groups,a.count,challenge,
                                         ids[:3],ids[3],roles)
                        t_post_live=time.perf_counter_ns()
                        ledger=pathlib.Path(roles)/'ledger.sqlite3'
                        t_verifier_begin=time.perf_counter_ns()
                        verdict=v.FreshLedger(ledger).check(batch,batch['registered_public_keys'],challenge)
                        t_verifier_end=time.perf_counter_ns()
                        groups_seen=[batch['receivers'][node][0]['record']['inbound_group'] for node in v.NODES]
                        assert verdict==expected,(verdict,expected)
                        assert groups_seen==list(groups),(groups_seen,groups)
                        assert all(access['denied']) and set(uids.values())==set(ids[:3])
                        assert len(batch['transactions'])==a.count
                        assert all(len(batch['receivers'][node])==a.count for node in v.NODES)
                        assert sqlite3.connect(ledger).execute('SELECT COUNT(*) FROM accepted').fetchone()[0]==1
                        row.update(status='PASS',verdict=verdict,negotiated_groups=groups_seen,
                            total_local_cycle_ms=(t_verifier_end-t_cycle_start)/1e6,
                            live_case_ms=(t_post_live-t_cycle_start)/1e6,
                            first_transaction_to_evidence_ms=(marks['t_evidence_ready_ns']-marks['t_first_tx_ns'])/1e6,
                            first_transaction_to_final_verdict_ms=(t_verifier_end-marks['t_first_tx_ns'])/1e6,
                            local_protected_verification_ms=(t_verifier_end-t_verifier_begin)/1e6,
                            evidence_return_to_verdict_ms=(t_verifier_end-marks['t_evidence_ready_ns'])/1e6,
                            verification_includes_ledger_initialization=True,
                            count_transactions=a.count)
                except Exception as exc:
                    row['error']=repr(exc)
                output['runs'].append(row);save()
                print('trial=%d scenario=%s %s'%(trial,name,row['status']),
                      ('cycle=%.3fms tx_to_verdict=%.3fms'%(
                        row['total_local_cycle_ms'],row['first_transaction_to_final_verdict_ms'])) if row['status']=='PASS' else row['error'],flush=True)
    metrics=['total_local_cycle_ms','live_case_ms','first_transaction_to_evidence_ms',
             'first_transaction_to_final_verdict_ms','local_protected_verification_ms',
             'evidence_return_to_verdict_ms']
    for name in ('hybrid','classical_middle'):
        rows=[r for r in output['runs'] if r['scenario']==name and r['status']=='PASS']
        output['summary'][name]={'passed':len(rows),'requested':a.trials,
                                 'metrics':{m:summary([r[m] for r in rows]) for m in metrics}}
    output['all_pass']=all(r['status']=='PASS' for r in output['runs'])
    save()
    print('COMPLETE',str(dest),'all_pass='+str(output['all_pass']),flush=True)
    if not output['all_pass']:raise SystemExit('Some live tests failed; diagnostic JSON retained')

if __name__=='__main__':main()
