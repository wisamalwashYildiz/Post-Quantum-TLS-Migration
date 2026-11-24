#!/usr/bin/env python3
"""v0.8 offline correlation study over *real v0.7 TLS session receipts*.

Only receipt-to-request associations and observation visibility are manipulated.
Actual cryptographic groups are copied unchanged from v0.7 receipts.
The model assumes a complete 2-request/2-receipt collection and exclusive
one-to-one matching *when both middle receipts are present*. These are
explicit assumptions, NOT authenticated correlation or tamper resistance.
"""
import argparse, csv, itertools, json
from pathlib import Path

H='X25519MLKEM768'; C='X25519'


def verdict(groups):
    if C in groups: return 'VIOLATED'
    if None in groups or any(g!=H for g in groups): return 'UNRESOLVED'
    return 'SATISFIED'


def matchings(candidates, n_receipts):
    """Enumerate injective complete assignments; return [] for contradiction."""
    n=len(candidates)
    if n!=n_receipts: raise ValueError('complete bipartite model requires equal counts')
    results=[]
    for assignment in itertools.permutations(range(n_receipts),n):
        if all(assignment[i] in candidates[i] for i in range(n)):
            results.append(assignment)
    return results


def aggregate(values):
    vals=set(values)
    if not vals:return 'INCONSISTENT'
    return next(iter(vals)) if len(vals)==1 else 'UNRESOLVED'


def evaluate(end_groups, middles, candidates):
    n=len(end_groups)
    if middles is None:
        both=[verdict([g[0],None,g[1]]) for g in end_groups]
        return {'joint':both,'local':both,'matchings':None,'consistent':True}
    possibilities=matchings(candidates,len(middles))
    if not possibilities:
        return {'joint':['INCONSISTENT']*n,
                'local':['INCONSISTENT']*n,'matchings':0,'consistent':False}
    joint=[];local=[]
    for i,(g,b) in enumerate(end_groups):
        joint.append(aggregate(verdict([g,middles[a[i]],b]) for a in possibilities))
        # Same evidence; local baseline deliberately ignores exclusive assignment.
        local.append(aggregate(verdict([g,middles[j],b]) for j in candidates[i]))
    return {'joint':joint,'local':local,'matchings':len(possibilities),'consistent':True}


def run_pair(left,right,mode):
    assert left['route']!=right['route']
    records=[left,right]
    end=[(r['actual_groups'][0],r['actual_groups'][2]) for r in records]
    mids=[r['receipts'][1]['incoming_group'] for r in records]
    assert mids==[r['actual_groups'][1] for r in records]
    if mode=='full': candidates=[[0],[1]]
    elif mode=='complementary': candidates=[[0,1],[1]]
    elif mode=='symmetric': candidates=[[0,1],[0,1]]
    elif mode=='inconsistent': candidates=[[0],[0]]
    elif mode=='redacted': candidates=None
    else:raise ValueError(mode)
    result=evaluate(end,None if candidates is None else mids,candidates)
    truths=[r['ground_truth'] for r in records]
    return {'request_ids':[r['request_id'] for r in records],
            'routes':[r['route'] for r in records],
            'ground_truth':truths,'middle_receipt_groups':mids if mode!='redacted' else None,
            'candidate_receipt_indices':candidates,'scenario_mode':mode,
            'joint':result['joint'],'local':result['local'],
            'matchings':result['matchings'],'consistent':result['consistent'],
            'edge_only':[verdict([r['actual_groups'][0]]) for r in records],
            'full_per_hop':truths}


def summarize(rows):
    summaries=[]
    for mode in ['full','complementary','symmetric','redacted','inconsistent']:
        subset=[r for r in rows if r['scenario_mode']==mode]
        for method in ['joint','local','edge_only','full_per_hop']:
            decisions=[(t,d) for r in subset for t,d in zip(r['ground_truth'],r[method])]
            summaries.append({'mode':mode,'method':method,'n':len(decisions),
              'correct':sum(t==d for t,d in decisions),
              'incorrect':sum(d in ('SATISFIED','VIOLATED') and d!=t for t,d in decisions),
              'unresolved':sum(d=='UNRESOLVED' for t,d in decisions),
              'inconsistent':sum(d=='INCONSISTENT' for t,d in decisions)})
    return summaries


def main():
    p=argparse.ArgumentParser(description=__doc__)
    p.add_argument('--input',action='append',required=True,help='v0.7 concurrent_paths.json; repeat for additional seeds')
    p.add_argument('--output',default='results/ambiguous_paths_v08')
    args=p.parse_args(); out=Path(args.output);out.mkdir(parents=True,exist_ok=True)
    rows=[];sources=[]
    for path in args.input:
        data=json.loads(Path(path).read_text())
        if data.get('version')!='0.7':raise ValueError('Expected genuine v0.7 format')
        sources.append({'source':path,'seed':data['seed'],'openssl':data['python_openssl']})
        for scenario in ['branch_b_classical','branch_a_classical']:
            requests=data['cases'][scenario]
            a=[r for r in requests if r['route']=='A']; b=[r for r in requests if r['route']=='B']
            if len(a)!=len(b):raise ValueError('balanced route pairs required')
            for x,y in zip(a,b):
                for mode in ('full','complementary','symmetric','redacted','inconsistent'):
                    row=run_pair(x,y,mode)
                    row.update({'seed':data['seed'],'source_case':scenario,'source':path})
                    rows.append(row)
    summary=summarize(rows)
    payload={'version':'0.8','sources':sources,'study_type':'offline association redaction applied to real v0.7 TLS receipts',
      'assumptions':['The two middle-hop receipts form a complete closed window for two requests',
                     'Each middle-hop receipt corresponds to exactly one request',
                     'TLS group values are trusted after measurement; association is ambiguous',
                     'Candidate receipt sets are synthetically imposed and are not experimentally derived',
                     'Inconsistent candidate sets represent a contradictory correlation input, not verified attacker activity'],
      'limitations':['No authenticated session-to-request binding',
                     'No empirical evidence of adversarial telemetry compromise',
                     'Two-request closed-window toy model; larger or open windows not evaluated',
                     'Joint-only resolution follows one-to-one matching; not yet evidence of novel inference',
                     'Full per-hop oracle remains strongest under complete observation'],
      'pairs':rows,'summary':summary}
    (out/'ambiguous_paths.json').write_text(json.dumps(payload,indent=2))
    with (out/'summary.csv').open('w',newline='') as f:
        writer=csv.DictWriter(f,fieldnames=['mode','method','n','correct','incorrect','unresolved','inconsistent'])
        writer.writeheader();writer.writerows(summary)
    for r in summary:
        if r['method'] in ('joint','local'):
            assert r['incorrect']==0,r
    for r in summary:
        if r['method'] in ('joint','local'):print(r['mode'],r['method'],f"correct={r['correct']}/{r['n']}",f"unresolved={r['unresolved']}",f"inconsistent={r['inconsistent']}")
    print('PASS:',len(rows),'paired observations from',len(sources),'real-v0.7 datasets')

if __name__=='__main__':main()
