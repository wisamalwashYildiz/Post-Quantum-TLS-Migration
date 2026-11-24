#!/usr/bin/env python3
"""Final lab study: genuine 3-hop TLS + signer-compromise boundary + isolated verifier timing.
Root is trusted; compromised signing capability is an explicit laboratory intervention.
"""
import argparse,csv,copy,hashlib,json,os,secrets,statistics,subprocess,tempfile,time,uuid
from pathlib import Path
from datetime import datetime,timezone
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
import v32_protected_freshness as v
from v33_comparative_campaign import report_only

METHODS=('report_only','signed_receiver','protected_fresh')

def compromise_one(batch,private_key_bytes):
    """Simulator controls service receiver signing key; creates a validly signed false group assertion.
    Does NOT simulate obtaining signing key by breaking UID isolation.
    """
    forged=copy.deepcopy(batch)
    name=v.NODES[1]
    signed_rec=forged['receivers'][name][0]
    changed=copy.deepcopy(signed_rec['record'])
    changed['inbound_group']=v.HYBRID if changed['inbound_group']==v.CLASSIC else v.CLASSIC
    sk=Ed25519PrivateKey.from_private_bytes(private_key_bytes)
    forged['receivers'][name][0]=v.signed(sk,changed)
    return forged

def verify_compromise(batch,forged,keys):
    original=v.verify(batch,keys)
    attacker_signature_valid=v.valid(keys[v.NODES[1]],forged['receivers'][v.NODES[1]][0])
    forged_result=v.verify(forged,keys)
    if not attacker_signature_valid:raise AssertionError('controlled compromised-signer signature not authentic')
    if forged_result=='SATISFIED' and original!='SATISFIED':raise AssertionError('unsafe false assurance after one-signer compromise')
    return {'original':original,'compromised_signer_receipt_authenticates':attacker_signature_valid,'compromised_evidence_verdict':forged_result,
            'interpretation':'A valid signature does not prove a truthful statement; cross-hop consistency rejects this unilateral manipulation.'}

def time_methods(batch,keys,challenge,truth,ledger_dir,iterations):
    rows=[]
    # Each timed method gets its own invocation. Never reuse bundle duration for all methods.
    report=[batch['receivers'][n][0]['record']['inbound_group'] for n in v.NODES]
    for repeat in range(iterations):
        # rotate method order to reduce ordering confound
        order=list(METHODS)
        order=order[repeat%3:]+order[:repeat%3]
        for method in order:
            if method=='report_only':
                action=lambda:report_only(batch,report)
            elif method=='signed_receiver':
                action=lambda:v.verify(batch,keys)
            else:
                # DB schema setup outside the timed interval; commit and fsync included in timing.
                ledger=v.FreshLedger(ledger_dir/('fresh_%05d.sqlite3'%repeat))
                action=lambda:v.FreshLedger(ledger.path).check(batch,keys,challenge)
            start=time.perf_counter_ns();verdict=action();duration=time.perf_counter_ns()-start
            if verdict!=truth:raise AssertionError((method,verdict,truth))
            rows.append({'repeat':repeat,'method':method,'verify_ns':duration,'verdict':verdict,
                         'evidence_bytes':len(v.canon(batch)) if method!='report_only' else len(v.canon(report)),
                         'timing_scope':'per-method Python verify; protected includes SQLite access and commit; setup excluded'})
    return rows

def execute(args):
    if os.geteuid()!=0:raise SystemExit('Use the non-root archive launcher; root required only inside protected lab')
    root=Path(args.archive).resolve();target=root/('final_'+datetime.now(timezone.utc).strftime('%Y%m%dT%H%M%SZ')+'_'+uuid.uuid4().hex[:8]);target.mkdir(parents=True)
    durations=[];outcomes=[];errors=[]
    with tempfile.TemporaryDirectory(prefix='pqc-final-',dir='/var/tmp') as td:
        os.chmod(td,0o711)
        cert,key=Path(td)/'cert.pem',Path(td)/'key.pem'
        p=subprocess.run([args.openssl,'req','-x509','-newkey','rsa:2048','-keyout',str(key),'-out',str(cert),'-days','1','-nodes','-subj','/CN=localhost'],text=True,capture_output=True,env=dict(os.environ,OPENSSL_CONF=os.environ.get('OPENSSL_CONF','/etc/ssl/openssl.cnf')))
        if p.returncode:raise RuntimeError('openssl certificate creation: '+p.stderr[-700:])
        for trial in range(1,args.trials+1):
            for scenario,groups in [('hybrid',(v.HYBRID,)*3),('classical_middle',(v.HYBRID,v.CLASSIC,v.HYBRID))]:
                result={'trial':trial,'scenario':scenario,'status':'FAIL'}
                try:
                    with tempfile.TemporaryDirectory(prefix='roles-',dir=td) as role_dir:
                        os.chmod(role_dir,0o711)
                        uids=v.choose_uids();challenge=secrets.token_hex(32)
                        batch,roles,access=v.live_case(cert,key,groups,args.count,challenge,uids[:3],uids[3],role_dir)
                        if access.get('denied')!=[True]*3:raise RuntimeError('UID protection failed')
                        compromised_key=(Path(role_dir)/v.NODES[1]/'signing.key').read_bytes() # privileged operator deliberately simulates stolen key
                        forged=compromise_one(batch,compromised_key)
                        boundary=verify_compromise(batch,forged,batch['registered_public_keys'])
                        truth='SATISFIED' if scenario=='hybrid' else 'VIOLATED'
                        if boundary['original']!=truth or boundary['compromised_evidence_verdict']!='INVALID':raise RuntimeError('unexpected compromise boundary')
                        with tempfile.TemporaryDirectory(prefix='ledger-',dir=td) as led:
                            rows=time_methods(batch,batch['registered_public_keys'],challenge,truth,Path(led),args.iterations)
                        for row in rows:durations.append({'trial':trial,'scenario':scenario,**row})
                        result.update(status='PASS',actual_groups=list(groups),roles=roles,attacker_uid=access['uid'],attacker_key_access_denied=True,**boundary)
                except Exception as exc:
                    result['error']=repr(exc);errors.append(result.copy())
                outcomes.append(result);print('LIVE',trial,scenario,result['status'],result.get('error',''),flush=True)
    with (target/'timings.csv').open('w',newline='') as f:
        fields=['trial','scenario','repeat','method','verify_ns','verdict','evidence_bytes','timing_scope']
        writer=csv.DictWriter(f,fieldnames=fields);writer.writeheader();writer.writerows(durations)
    (target/'compromise_boundary.json').write_text(json.dumps(outcomes,indent=2)+'\n')
    summaries={}
    for method in METHODS:
        a=[row['verify_ns'] for row in durations if row['method']==method]
        summaries[method]={'n':len(a),'median_ns':statistics.median(a) if a else None,'p95_nearest_rank_ns':sorted(a)[max(0,(95*len(a)+99)//100-1)] if a else None,
                           'mean_evidence_bytes':round(statistics.mean(row['evidence_bytes'] for row in durations if row['method']==method),1) if a else None}
    manifest={'schema':'pqc-v35-boundary-performance','created_utc':datetime.now(timezone.utc).isoformat(),'openssl':subprocess.check_output([args.openssl,'version'],text=True).strip(),
              'trials_requested':args.trials,'transactions_per_connection':args.count,'iterations_per_method_per_scenario':args.iterations,
              'successful_live_scenarios':sum(x['status']=='PASS' for x in outcomes),'total_live_scenarios':len(outcomes),'method_summaries':summaries,'errors':errors,
              'limits':['Compromise simulated by privileged laboratory operator reading one valid receiver signing key; NOT actual process exploitation.',
                        'A dishonest legitimate signer can authenticate a false claim; unilateral falsification is rejected here by adjacent honest evidence, NOT a general malicious receiver guarantee.',
                        'Verification timings are separate but Python-level microbenchmarks, not application latency or throughput.',
                        'Protected verifier duration includes fresh SQLite check and commit; database initialization excluded.',
                        'Report-only input is three group strings; full signed methods validate multi-transaction evidence and have different functionality.',
                        'Host root trusted; no TLS peer certificate verification, post-quantum authentication or remote network.',
                        'No private signing keys or TLS exporter material archived.']}
    (target/'manifest.json').write_text(json.dumps(manifest,indent=2)+'\n')
    (target/'checksums.sha256').write_text(''.join(hashlib.sha256(p.read_bytes()).hexdigest()+'  '+p.name+'\n' for p in sorted(target.iterdir()) if p.is_file() and p.name!='checksums.sha256'))
    print('ARCHIVE',target,flush=True);print('METHOD_SUMMARY',json.dumps(summaries),flush=True)
    if errors:raise SystemExit('FAIL: detailed results preserved')
    print('PASS:',len(outcomes),'live scenarios;',len(durations),'individually timed verification calls')

def main():
    ap=argparse.ArgumentParser();ap.add_argument('--openssl',required=True);ap.add_argument('--archive',required=True);ap.add_argument('--trials',type=int,default=3);ap.add_argument('--count',type=int,default=3);ap.add_argument('--iterations',type=int,default=40)
    a=ap.parse_args()
    if not 1<=a.trials<=30 or not 2<=a.count<=30 or not 2<=a.iterations<=1000:ap.error('bounds: trials<=30 count 2..30 iterations 2..1000')
    execute(a)
if __name__=='__main__':main()
