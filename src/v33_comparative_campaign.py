#!/usr/bin/env python3
"""Paired live-TLS evidence comparison; offline attacks are explicitly labeled.
Root trusted; localhost, unvalidated lab cert; no receiver compromise claims.
"""
import argparse, copy, csv, hashlib, json, os, secrets, subprocess, tempfile, time, uuid
from datetime import datetime,timezone
from pathlib import Path
import v32_protected_freshness as v

METHODS=('report_only','signed_receiver','protected_fresh')
SCENARIOS=('unaltered','forwarder_false_hybrid','receiver_edit','missing_receiver','copied_new_challenge')

def report_only(batch,report):
    if len(report)!=3:return 'UNRESOLVED'
    if any(g not in (v.HYBRID,v.CLASSIC) for g in report):return 'UNRESOLVED'
    return 'VIOLATED' if v.CLASSIC in report else 'SATISFIED'

def evaluate(batch,keys,challenge,ledger,intervention):
    original=[batch['receivers'][node][0]['record']['inbound_group'] for node in v.NODES]
    b=copy.deepcopy(batch)
    # Forwarding reports are wholly under the attacker's control in the offline comparator.
    report=list(original)
    if intervention=='forwarder_false_hybrid':report=[v.HYBRID]*3
    if intervention=='receiver_edit':
        b['receivers'][v.NODES[1]][0]['record']['inbound_group']=v.HYBRID if original[1]==v.CLASSIC else v.CLASSIC
        report=[v.HYBRID]*3
    if intervention=='missing_receiver':
        b['receivers'][v.NODES[1]]=[]
        report=[v.HYBRID]*3
    if intervention=='copied_new_challenge':
        # Exact historical signed evidence is submitted for a fresh verifier challenge.
        report=[v.HYBRID]*3
    plain=report_only(b,report)
    signed=v.verify(b,keys)
    required=challenge if intervention!='copied_new_challenge' else secrets.token_hex(32)
    protected=v.FreshLedger(ledger).check(b,keys,required)
    return {'report_only':plain,'signed_receiver':signed,'protected_fresh':protected}

def expected(scenario,attack):
    if scenario=='hybrid':
        truth='SATISFIED'
    else:truth='VIOLATED'
    if attack=='unaltered':return {'report_only':truth,'signed_receiver':truth,'protected_fresh':truth}
    if attack=='forwarder_false_hybrid':return {'report_only':'SATISFIED','signed_receiver':truth,'protected_fresh':truth}
    if attack=='receiver_edit':return {'report_only':'SATISFIED','signed_receiver':'INVALID','protected_fresh':'INVALID'}
    if attack=='missing_receiver':return {'report_only':'SATISFIED','signed_receiver':'UNRESOLVED','protected_fresh':'UNRESOLVED'}
    if attack=='copied_new_challenge':return {'report_only':'SATISFIED','signed_receiver':truth,'protected_fresh':'INVALID'}
    raise KeyError(attack)

def run(args):
    if os.geteuid()!=0:raise SystemExit('Run via sudo launcher only; requires real UID isolation')
    target=Path(args.archive).resolve()/('comparison_'+datetime.now(timezone.utc).strftime('%Y%m%dT%H%M%SZ')+'_'+uuid.uuid4().hex[:8]);target.mkdir(parents=True)
    rows=[];sessions=[];errors=[]
    with tempfile.TemporaryDirectory(prefix='pqc-v33-',dir='/var/tmp') as td:
        os.chmod(td,0o711)
        cert=Path(td)/'cert.pem';key=Path(td)/'key.pem'
        proc=subprocess.run([args.openssl,'req','-x509','-newkey','rsa:2048','-keyout',str(key),'-out',str(cert),'-days','1','-nodes','-subj','/CN=localhost'],capture_output=True,text=True,env=dict(os.environ,OPENSSL_CONF=os.environ.get('OPENSSL_CONF','/etc/ssl/openssl.cnf')))
        if proc.returncode:raise RuntimeError('certificate: '+proc.stderr[-700:])
        for trial in range(1,args.trials+1):
            for scenario,groups in [('hybrid',(v.HYBRID,)*3),('classical_middle',(v.HYBRID,v.CLASSIC,v.HYBRID))]:
                start=time.perf_counter_ns();status='FAIL';reason='';checks={}
                try:
                    with tempfile.TemporaryDirectory(prefix='roles-',dir=td) as role_dir:
                        os.chmod(role_dir,0o711)
                        uid=v.choose_uids();challenge=secrets.token_hex(32)
                        batch,roles,access=v.live_case(cert,key,groups,args.count,challenge,uid[:3],uid[3],role_dir)
                        if access.get('denied')!=[True]*3:raise RuntimeError('key isolation failed')
                        ledger=target/('ledger_%03d_%s.sqlite3'%(trial,scenario))
                        # Each intervention uses an independent ledger so no prior successful
                        # verification can contaminate the paired comparison.
                        for attack in SCENARIOS:
                            att_ledger=target/('ephemeral_%03d_%s_%s.sqlite3'%(trial,scenario,attack))
                            start_verify=time.perf_counter_ns()
                            verdicts=evaluate(batch,batch['registered_public_keys'],challenge,att_ledger,attack)
                            elapsed=time.perf_counter_ns()-start_verify
                            exp=expected(scenario,attack)
                            good=verdicts==exp
                            for method in METHODS:
                                rows.append({'trial':trial,'tls_scenario':scenario,'intervention':attack,'method':method,'verdict':verdicts[method],'expected':exp[method], 'expected_match':good,'verification_bundle_ns':elapsed,'ground_truth': 'HYBRID' if scenario=='hybrid' else 'CLASSICAL_MIDDLE', 'intervention_mode':'offline_after_live_tls'})
                            if not good:raise RuntimeError('unexpected '+attack+': '+str(verdicts)+' expected '+str(exp))
                            att_ledger.unlink(missing_ok=True)
                        checks={'observed_uids':roles,'attacker_uid':access['uid'],'all_keys_denied':True,'actual_groups':[batch['receivers'][n][0]['record']['inbound_group'] for n in v.NODES],'signed_receipt_count':3*args.count}
                        status='PASS'
                except BaseException as e:reason=repr(e);errors.append({'trial':trial,'scenario':scenario,'error':reason})
                sessions.append({'trial':trial,'scenario':scenario,'status':status,'live_setup_and_checks_ns':time.perf_counter_ns()-start,**checks,'error':reason})
                print('LIVE',trial,scenario,status,reason,flush=True)
    with (target/'paired_verdicts.csv').open('w',newline='') as f:
        w=csv.DictWriter(f,fieldnames=['trial','tls_scenario','intervention','method','verdict','expected','expected_match','verification_bundle_ns','ground_truth','intervention_mode']);w.writeheader();w.writerows(rows)
    (target/'live_sessions.json').write_text(json.dumps(sessions,indent=2)+'\n')
    tallies={method:{'n':sum(x['method']==method for x in rows),'false_hybrid_approvals':sum(x['method']==method and x['tls_scenario']=='classical_middle' and x['verdict']=='SATISFIED' for x in rows),'unresolved':sum(x['method']==method and x['verdict']=='UNRESOLVED' for x in rows),'invalid':sum(x['method']==method and x['verdict']=='INVALID' for x in rows)} for method in METHODS}
    manifest={'schema':'pqc-v33-paired-comparison','utc':datetime.now(timezone.utc).isoformat(),'openssl':subprocess.check_output([args.openssl,'version'],text=True).strip(),'trials_requested':args.trials,'transactions_per_tls_connection':args.count,'live_scenario_successes':sum(x['status']=='PASS' for x in sessions),'live_scenario_total':len(sessions),'observations':len(rows),'tallies':tallies,'errors':errors,'limitations':['Report-only comparator uses attacker-controlled claimed groups, not actual receiver evidence','Attacks are OFFLINE mutations after real live TLS; no real forwarder compromise','Signed-only uses the same original authentic receiver signatures but no independent verifier freshness','Per-attack verifier ledgers are independent; shared copied-receipt negative control checks new challenge','Three honest receiver processes with distinct UIDs; trusted root orchestrates; root compromise excluded','Same host localhost; TLS peer certificates unvalidated; no PQ authentication','Verification bundle timing is shared across three methods and not per-method isolated timing','Benchmarked attack cases are deliberately selected, not a statistically representative attack distribution','No raw TLS exporter secrets or signing keys archived']}
    (target/'manifest.json').write_text(json.dumps(manifest,indent=2)+'\n')
    (target/'checksums.sha256').write_text(''.join(hashlib.sha256(p.read_bytes()).hexdigest()+'  '+p.name+'\n' for p in sorted(target.iterdir()) if p.is_file() and p.name!='checksums.sha256'))
    print('ARCHIVE',target,flush=True)
    print('TALLIES',json.dumps(tallies),flush=True)
    if errors:raise SystemExit('FAIL: see preserved archive')
    print('PASS:',len(sessions),'live scenario runs and',len(rows),'paired method decisions')

def main():
    p=argparse.ArgumentParser();p.add_argument('--openssl',required=True);p.add_argument('--archive',required=True);p.add_argument('--trials',type=int,default=3);p.add_argument('--count',type=int,default=3);a=p.parse_args()
    if not 1<=a.trials<=100 or not 2<=a.count<=30:p.error('trials 1..100; count 2..30')
    run(a)
if __name__=='__main__':main()
