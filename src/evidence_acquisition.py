#!/usr/bin/env python3
"""v1.0 feasibility pilot: simulated evidence acquisition over archived live TLS groups.

Action costs and coverage are *synthetic*. No new live instrumentation is claimed.
Full per-request TLS groups are used only as oracle ground truth and hypothetical
measurements when an action is selected. Action design does not use TLS groups.
"""
import argparse
import csv
import hashlib
import itertools
import json
import random
from pathlib import Path

HYBRID='X25519MLKEM768'

def load_windows(paths, limit=12):
    windows=[]
    for path in paths:
        doc=json.loads(Path(path).read_text())
        cases=doc['cases']
        for mode in ('branch_a_classical','branch_b_classical'):
            arr=cases[mode]
            for i in range(0,min(len(arr)-1,8),2):
                pair=arr[i:i+2]
                if len(pair)!=2: continue
                for req in pair:
                    assert len(req['actual_groups'])==3 and len(req['receipts'])==3
                    assert req['actual_groups'][1]==req['receipts'][1]['incoming_group']
                windows.append({'source':str(path),'source_mode':mode,'pair_index':i//2,'requests':pair})
    return windows[:limit]

def actions_for(windows):
    """Define acquisition actions using window positions/routes only (no key-share)."""
    # 12 distinct request pairs across 3 archives; eight hypothetical sensors.
    targets=[(wi,ri) for wi,w in enumerate(windows) for ri,_ in enumerate(w['requests'])]
    acts={}
    for j in range(4):
        # route-based collectors: each samples an independently defined cohort
        acts[f'route_{j}']={'cost':2+j%2,'targets':{(wi,ri) for wi,ri in targets
                     if windows[wi]['requests'][ri]['route']==('A' if j%2==0 else 'B')
                     and wi%2==j//2},'trust':'assumed_bound'}
    for j in range(4):
        # gateway integration bundles: independently designated window cohorts
        acts[f'bundle_{j}']={'cost':3+(j%2),'targets':{(wi,ri) for wi,ri in targets
                      if wi%4==j},'trust':'assumed_bound'}
    return acts,targets

def certified(windows, selected, acts, *, untrusted=()):
    trusted=set().union(*(acts[a]['targets'] for a in selected if a not in untrusted)) if selected else set()
    outcomes=[]
    for wi,w in enumerate(windows):
        for ri,r in enumerate(w['requests']):
            full='SATISFIED' if all(g==HYBRID for g in r['actual_groups']) else 'VIOLATED'
            # Front/back are assumed independently verified in this pilot;
            # the middle receipt requires a trusted acquisition channel.
            f,b=r['actual_groups'][0],r['actual_groups'][2]
            if f!=HYBRID or b!=HYBRID: verdict='VIOLATED'
            elif (wi,ri) in trusted:
                verdict='SATISFIED' if r['actual_groups'][1]==HYBRID else 'VIOLATED'
            else: verdict='UNRESOLVED'
            outcomes.append({'truth':full,'verdict':verdict,'window':wi,'request':ri})
    return outcomes

def score(windows,selected,acts,untrusted=()):
    out=certified(windows,selected,acts,untrusted=untrusted)
    return sum(r['verdict']==r['truth'] for r in out),sum(r['verdict'] not in ('UNRESOLVED',r['truth']) for r in out)

def select_exact(windows,acts,budget):
    keys=sorted(acts); best=(); val=(-1,0,())
    for mask in range(1<<len(keys)):
        names=tuple(keys[j] for j in range(len(keys)) if mask>>j&1)
        cost=sum(acts[n]['cost'] for n in names)
        if cost>budget: continue
        correct,_=score(windows,names,acts)
        rank=(correct,-cost,tuple(-keys.index(n) for n in names))
        if rank>val: val=rank;best=names
    return best

def select_greedy(windows,acts,budget):
    chosen=[];left=set(acts)
    while left:
        cur=score(windows,chosen,acts)[0]
        possible=[a for a in left if sum(acts[x]['cost'] for x in chosen)+acts[a]['cost']<=budget]
        if not possible:break
        best=max(possible,key=lambda a:((score(windows,chosen+[a],acts)[0]-cur)/acts[a]['cost'], -acts[a]['cost'],a))
        if score(windows,chosen+[best],acts)[0]<=cur:break
        chosen.append(best);left.remove(best)
    return tuple(chosen)

def select_static(acts,budget):
    chosen=[]
    for name in sorted(acts,key=lambda x:(-len(acts[x]['targets'])/acts[x]['cost'],x)):
        if sum(acts[a]['cost'] for a in chosen)+acts[name]['cost']<=budget:chosen.append(name)
    return tuple(chosen)

def select_random(acts,budget,seed):
    keys=list(acts);random.Random(seed).shuffle(keys)
    chosen=[]
    for key in keys:
        if sum(acts[a]['cost'] for a in chosen)+acts[key]['cost']<=budget:chosen.append(key)
    return tuple(chosen)

def run(paths,outdir,limit=12):
    windows=load_windows(paths,limit)
    if len(windows)<4:raise ValueError('At least four windows required')
    acts,targets=actions_for(windows)
    rows=[]
    for budget in range(0,11):
        for method in ('exact','greedy','static','random'):
            chosen={'exact':lambda:select_exact(windows,acts,budget),
                    'greedy':lambda:select_greedy(windows,acts,budget),
                    'static':lambda:select_static(acts,budget),
                    'random':lambda:select_random(acts,budget,42017+budget)}[method]()
            correct,errors=score(windows,chosen,acts)
            # One selected source is assumed compromised; trust invalidation
            # must withdraw its evidence rather than silently accept it.
            adversarial=chosen[:1]
            robust_correct,robust_errors=score(windows,chosen,acts,adversarial)
            rows.append({'budget':budget,'method':method,'cost':sum(acts[x]['cost'] for x in chosen),
                         'correct':correct,'unresolved':len(targets)-correct,'incorrect':errors,
                         'source_revoked_correct':robust_correct,'source_revoked_incorrect':robust_errors,
                         'selected':';'.join(chosen)})
    folder=Path(outdir);folder.mkdir(parents=True,exist_ok=True)
    with (folder/'summary.csv').open('w',newline='') as f:
        writer=csv.DictWriter(f,fieldnames=rows[0]);writer.writeheader();writer.writerows(rows)
    payload={'version':'1.0 pilot','study':'offline hypothetical acquisition over archived live TLS values',
      'sources':paths,'windows':len(windows),'request_instances':len(targets),
      'limits':['No new live TLS traffic','Costs and action coverage are synthetically specified',
                'All actions assume independently trustworthy transaction-session binding',
                'Front and back TLS observations treated as free verified baseline',
                'Revocation test withdraws evidence; it does not simulate malicious false values',
                'Exact optimum is exhaustive over eight actions; no novel optimization algorithm claimed'],
      'actions':{k:{'cost':v['cost'],'targets':sorted(map(list,v['targets'])),'trust':v['trust']} for k,v in acts.items()},
      'rows':rows}
    (folder/'evidence_acquisition.json').write_text(json.dumps(payload,indent=2))
    for r in rows:
        if r['incorrect'] or r['source_revoked_incorrect']:raise AssertionError('unsafe decision')
        if r['method']=='exact' and any(s['budget']==r['budget'] and s['correct']>r['correct'] for s in rows):raise AssertionError('incorrect optimum')
    print(f'PASS: {len(windows)} paired windows; {len(targets)} request instances; 8 hypothetical actions')
    for r in rows:
        if r['budget'] in (3,5,8,10):print(f"budget={r['budget']:2} {r['method']:6} correct={r['correct']:2}/{len(targets)} cost={r['cost']:2} wrong={r['incorrect']}")
    return payload

def main():
    p=argparse.ArgumentParser();p.add_argument('--input',action='append',required=True);p.add_argument('--output',default='results/evidence_acquisition_v10');p.add_argument('--windows',type=int,default=12)
    a=p.parse_args();run(a.input,a.output,a.windows)
if __name__=='__main__':main()
