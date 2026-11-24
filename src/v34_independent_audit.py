#!/usr/bin/env python3
"""Independent post-hoc audit of v3.3; does not make new TLS security claims."""
import argparse,csv,hashlib,json,collections,datetime,pathlib,sys
METHODS=('report_only','signed_receiver','protected_fresh')
ATTACKS=('unaltered','forwarder_false_hybrid','receiver_edit','missing_receiver','copied_new_challenge')
SCENARIOS=('hybrid','classical_middle')

def audit(folder):
    folder=pathlib.Path(folder); errors=[]
    for line in (folder/'checksums.sha256').read_text().splitlines():
        digest,filename=line.strip().split(maxsplit=1)
        p=folder/filename.strip().lstrip('*')
        if not p.is_file() or hashlib.sha256(p.read_bytes()).hexdigest()!=digest: errors.append('Checksum mismatch '+str(filename))
    with (folder/'paired_verdicts.csv').open(newline='') as f:
        data=list(csv.DictReader(f))
    manifest=json.loads((folder/'manifest.json').read_text())
    sessions=json.loads((folder/'live_sessions.json').read_text())
    n=manifest.get('trials_requested')
    if not isinstance(n,int) or n<1:errors.append('Bad trial count')
    expected={(str(i),sc,att,m) for i in range(1,n+1) for sc in SCENARIOS for att in ATTACKS for m in METHODS} if isinstance(n,int) and n>0 else set()
    keys=[(r['trial'],r['tls_scenario'],r['intervention'],r['method']) for r in data]
    if len(keys)!=len(set(keys)) or set(keys)!=expected:errors.append('Missing, extra, or duplicate paired observations')
    if len(sessions)!=2*n or any(x.get('status')!='PASS' for x in sessions):errors.append('Missing/failed live TLS runs')
    if len(data)!=len(expected):errors.append('Incomplete decision matrix')
    if any(r.get('expected_match')!='True' for r in data):errors.append('Expected-verdict mismatch')
    if any(r.get('intervention_mode')!='offline_after_live_tls' for r in data):errors.append('Unsupported intervention provenance')
    totals={}
    for m in METHODS:
        rr=[r for r in data if r['method']==m]
        totals[m]={'decisions':len(rr),'false_hybrid_approvals':sum(r['tls_scenario']=='classical_middle' and r['verdict']=='SATISFIED' for r in rr),'invalid':sum(r['verdict']=='INVALID' for r in rr),'unresolved':sum(r['verdict']=='UNRESOLVED' for r in rr)}
        if {'n':totals[m]['decisions'],**{k:totals[m][k] for k in ('false_hybrid_approvals','unresolved','invalid')}}!=manifest.get('tallies',{}).get(m):errors.append('Tally mismatch '+m)
    bycase=collections.defaultdict(dict)
    for r in data:bycase[(r['trial'],r['tls_scenario'],r['intervention'])][r['method']]=r
    if any(len(x)!=3 or len({r['verification_bundle_ns'] for r in x.values()})!=1 for x in bycase.values()):errors.append('Timing schema inconsistent: expected shared bundle measurement')
    matched={}
    for att in ATTACKS:
        groups=[b for (t,s,a),b in bycase.items() if a==att and s=='classical_middle']
        matched[att]={'classical_cases':len(groups),'false_approvals_report_only':sum(b.get('report_only',{}).get('verdict')=='SATISFIED' for b in groups),'false_approvals_protected':sum(b.get('protected_fresh',{}).get('verdict')=='SATISFIED' for b in groups)}
    result={'schema':'pqc-v34-independent-audit','generated_utc':datetime.datetime.now(datetime.timezone.utc).isoformat(),'source_schema':manifest.get('schema'),'checksums_checked':len((folder/'checksums.sha256').read_text().splitlines()),'live_scenario_runs':len(sessions),'decision_rows':len(data),'paired_cases':len(bycase),'trial_count':n,'totals':totals,'matched_classical_cases':matched,'integrity':'PASS' if not errors else 'FAIL','errors':errors,'interpretation':['Distinct paired cases are correlated within each trial; counts are not binomial estimates for real deployments.','Attacks were applied offline to evidence after real live TLS, not actual relay process compromises.','verification_bundle_ns is repeated across methods, so per-method verification costs CANNOT be compared.','Report-only accepts attacker-controlled reports in intervention matrix; baseline is intentionally weak.','No malicious legitimate receiver signer test in this dataset.','No TLS peer-certificate authentication; root compromise excluded.']}
    return result

def main():
    p=argparse.ArgumentParser();p.add_argument('--input',required=True);p.add_argument('--output',required=True);a=p.parse_args()
    out=pathlib.Path(a.output);out.mkdir(parents=True,exist_ok=False)
    result=audit(a.input)
    (out/'audit.json').write_text(json.dumps(result,indent=2)+'\n')
    with (out/'findings.csv').open('w',newline='') as f:
        w=csv.writer(f);w.writerow(['method','decisions','false_hybrid_approvals','invalid','unresolved'])
        for m,v in result['totals'].items():w.writerow([m,*[v[k] for k in ['decisions','false_hybrid_approvals','invalid','unresolved']]])
    (out/'audit.sha256').write_text(''.join(hashlib.sha256(q.read_bytes()).hexdigest()+'  '+q.name+'\n' for q in sorted(out.iterdir()) if q.is_file() and q.name!='audit.sha256'))
    print(json.dumps({'integrity':result['integrity'],'live_runs':result['live_scenario_runs'],'rows':result['decision_rows'],'totals':result['totals'],'errors':result['errors']},indent=2))
    if result['errors']:sys.exit(2)
if __name__=='__main__':main()
