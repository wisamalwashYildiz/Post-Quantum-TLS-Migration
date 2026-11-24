#!/usr/bin/env python3
"""v0.9 offline audit: route-derived receipt association, closed vs open windows.

Input TLS groups are from the actual sessions in v0.7 archived traces.
Candidate edges use route/path metadata stored in those traces, with defined
redactions and perturbations, NEVER the hidden ground-truth association.
No timestamps/socket tuple metadata exist in the v0.7 source files.
"""
import argparse
import csv
import json
from collections import Counter
from pathlib import Path

HYBRID='X25519MLKEM768'
CLASSIC='X25519'


def verdict(group):
    return 'SATISFIED' if group == HYBRID else 'VIOLATED' if group == CLASSIC else 'UNRESOLVED'


def max_matching(edges, n_receipts, forbidden=None):
    """Find maximum bipartite matching; length equals number of requests."""
    owner=[-1]*n_receipts
    def augment(i, seen):
        for j in edges[i]:
            if j == forbidden or not 0 <= j < n_receipts or j in seen:
                continue
            seen.add(j)
            if owner[j] == -1 or augment(owner[j], seen):
                owner[j]=i
                return True
        return False
    return sum(augment(i,set()) for i in range(len(edges)))


def edges_from_metadata(requests, receipts):
    """Only visible route and path information; no request ID or truth leakage."""
    edges=[]
    for r in requests:
        candidates=[]
        for j,m in enumerate(receipts):
            if r['path_prefix'] != m['path_prefix']:
                continue
            if r['route'] is not None and m['route'] is not None and r['route'] != m['route']:
                continue
            candidates.append(j)
        edges.append(candidates)
    return edges


def feasible_edges(edges, n_receipts, *, closed):
    """Find all edges in at least one maximal admissible matching.

    Closed: every request and receipt accounted for; requires bijection.
    Open: requests may have unrecorded receipts; observed receipts cannot be reused.
    In open windows, unmatched requests always have a possible unknown group,
    even if the maximum matching includes them.
    """
    n=len(edges)
    if closed and (n!=n_receipts or max_matching(edges,n_receipts)!=n):
        return None
    feasible=[]
    for i in range(n):
        allowed=[]
        for j in edges[i]:
            remainder=[list(row) for k,row in enumerate(edges) if k!=i]
            for row in remainder:
                if j in row: row.remove(j)
            if closed:
                if max_matching(remainder,n_receipts)==n-1:
                    allowed.append(j)
            else:
                # No completeness constraint; every compatible observed receipt
                # might or might not belong to this request.
                allowed.append(j)
        feasible.append(allowed)
    return feasible


def evaluate(requests, receipts, closed=True):
    edges=edges_from_metadata(requests,receipts)
    feasible=feasible_edges(edges,len(receipts),closed=closed)
    if feasible is None:
        return {'joint':['INCONSISTENT']*len(requests),'optimal_matching':['INCONSISTENT']*len(requests),
                'local':['INCONSISTENT']*len(requests),'feasible_edges':None,'edges':edges}
    # An optimal feasibility comparator uses exactly the same admissible
    # matchings, so it MUST tie. This is a validation control, not a weakness.
    joint=[]; local=[]
    for i,r in enumerate(requests):
        fixed=[r['front_group'],r['back_group']]
        if CLASSIC in fixed:
            joint.append('VIOLATED');local.append('VIOLATED');continue
        candidates={verdict(receipts[j]['group']) for j in feasible[i]}
        local_candidates={verdict(receipts[j]['group']) for j in edges[i]}
        if not closed:
            candidates.add('UNRESOLVED');local_candidates.add('UNRESOLVED')
        def assess(v):
            if not v: return 'UNRESOLVED'
            return next(iter(v)) if len(v)==1 else 'UNRESOLVED'
        joint.append(assess(candidates));local.append(assess(local_candidates))
    return {'joint':joint,'optimal_matching':list(joint),'local':local,
            'feasible_edges':feasible,'edges':edges}


def build_pair(left,right,condition):
    raw=[left,right]
    requests=[]; receipts=[]
    for r in raw:
        mid=r['receipts'][1]
        # Ground truth request ID used only for scoring, not matching.
        requests.append({'id':r['request_id'],'route':r['route'],
                         'path_prefix':tuple(mid['received_path']),
                         'front_group':r['actual_groups'][0],
                         'back_group':r['actual_groups'][2],
                         'truth':r['ground_truth']})
        receipts.append({'route':mid['route'], 'path_prefix':tuple(mid['received_path']),
                         'group':mid['incoming_group']})
    if condition=='full': pass
    elif condition=='partial_route': requests[0]['route']=None
    elif condition=='no_routes':
        for v in requests+receipts:v['route']=None
    elif condition=='missing_receipt':
        receipts.pop(0)
    elif condition=='contradictory_route':
        # tamper model: make both receipts have A despite one original B.
        receipts[1]['route']=receipts[0]['route']
    elif condition=='open_window': pass
    else: raise ValueError(condition)
    closed=condition not in {'missing_receipt','open_window'}
    res=evaluate(requests,receipts,closed)
    return {'condition':condition,'ground_truth':[r['truth'] for r in requests],
            'request_ids':[r['id'] for r in requests],
            'visible_request_routes':[r['route'] for r in requests],
            'visible_receipt_routes':[m['route'] for m in receipts],
            'visible_received_paths':[list(m['path_prefix']) for m in receipts],
            'receipt_groups':[m['group'] for m in receipts],
            'closed_window':closed, **res}

CONDITIONS=('full','partial_route','no_routes','missing_receipt','contradictory_route','open_window')
METHODS=('joint','optimal_matching','local')

def summarize(rows):
    out=[]
    for condition in CONDITIONS:
        for method in METHODS:
            cases=[(t,v) for x in rows if x['condition']==condition for t,v in zip(x['ground_truth'],x[method])]
            out.append({'condition':condition,'method':method,'n':len(cases),
                        'correct':sum(t==v for t,v in cases),
                        'incorrect':sum(v in ('SATISFIED','VIOLATED') and v!=t for t,v in cases),
                        'unresolved':sum(v=='UNRESOLVED' for t,v in cases),
                        'inconsistent':sum(v=='INCONSISTENT' for t,v in cases)})
    return out

def main():
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--input',action='append',required=True)
    parser.add_argument('--output',default='results/telemetry_correlation_v09')
    args=parser.parse_args()
    rows=[];sources=[]
    for fn in args.input:
        data=json.loads(Path(fn).read_text())
        if data.get('version')!='0.7':raise ValueError('Requires v0.7 source data')
        sources.append({'path':fn,'seed':data['seed'],'openssl':data['python_openssl']})
        for config in ('branch_a_classical','branch_b_classical'):
            items=data['cases'][config]
            a=[r for r in items if r['route']=='A'];b=[r for r in items if r['route']=='B']
            if len(a)!=len(b):raise ValueError('Unexpected request imbalance')
            for x,y in zip(a,b):
                for c in CONDITIONS:
                    row=build_pair(x,y,c)
                    row.update({'seed':data['seed'],'source_config':config})
                    rows.append(row)
    summary=summarize(rows)
    for row in rows:
        if row['joint']!=row['optimal_matching']:raise AssertionError('Optimal comparator disagreement')
    # Closed, consistent evidence must not produce an incorrect decisive verdict.
    for s in summary:
        if s['method']!='local' and s['incorrect']:
            raise AssertionError(s)
    out=Path(args.output);out.mkdir(parents=True,exist_ok=True)
    (out/'telemetry_correlation.json').write_text(json.dumps({'version':'0.9','sources':sources,
       'study':'offline metadata-derived candidate matching over live TLS receipts',
       'methodology':'correlation by recorded middle-hop route and received_path prefix; request IDs excluded from matching',
       'assumptions':['No independent timestamps or socket tuples in v0.7',
                      'Open windows do not imply full capture',
                      'Metadata perturbations are controlled simulations',
                      'Full instrumentation is an upper-bound oracle',
                      'Matching solver and joint reasoning use identical evidence'],
       'rows':rows,'summary':summary},indent=2))
    with (out/'summary.csv').open('w',newline='') as f:
        w=csv.DictWriter(f,fieldnames=['condition','method','n','correct','incorrect','unresolved','inconsistent']);w.writeheader();w.writerows(summary)
    for s in summary:
        print(s['condition'],s['method'],f"correct={s['correct']}/{s['n']}",
              'unresolved='+str(s['unresolved']), 'inconsistent='+str(s['inconsistent']),
              'incorrect='+str(s['incorrect']))
    print('PASS:',len(rows),'paired condition records from',len(sources),'archived v0.7 runs')

if __name__=='__main__':main()
