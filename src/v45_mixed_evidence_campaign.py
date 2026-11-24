#!/usr/bin/env python3
"""Deterministic case matrix with freshly generated authentic Ed25519 receipts.
Compares observed outcomes to independently stated oracles; does not modify v32/v44.
"""
import argparse,copy,csv,hashlib,json,secrets,sys,tempfile
from pathlib import Path
from datetime import datetime,timezone
import v32_protected_freshness as v
import v44_policy_aware_live as old_policy
from v45_precedence_verifier import verify_partial,PartialLedger

H1,H2,H3=old_policy.HYBRIDS
C=v.CLASSIC

def variant(batch,name):
    b=copy.deepcopy(batch)
    nodes=v.NODES
    if name=='missing_first':b['receivers'][nodes[0]].clear()
    elif name=='missing_middle':b['receivers'][nodes[1]].clear()
    elif name=='missing_last':b['receivers'][nodes[2]].pop(0)
    elif name=='unsigned_last':b['receivers'][nodes[2]][0]['record']['inbound_group']='evil'
    elif name=='unsigned_first':b['receivers'][nodes[0]][0]['record']['inbound_group']='evil'
    elif name=='proof_last':b['receivers'][nodes[2]][0]['record']['inbound_proof']='evil'
    elif name=='missing_first_unsigned_last':
        b['receivers'][nodes[0]].pop(0);b['receivers'][nodes[2]][0]['record']['inbound_proof']='evil'
    elif name=='missing_first_unsigned_middle':
        b['receivers'][nodes[0]].pop(0);b['receivers'][nodes[1]][0]['record']['inbound_proof']='evil'
    elif name=='duplicate_last':b['receivers'][nodes[2]].append(copy.deepcopy(b['receivers'][nodes[2]][0]))
    elif name=='missing_client':b['client'].clear()
    elif name=='wrong_client_group':b['client'][0]['group']='evil'
    elif name!='unaltered':raise ValueError(name)
    return b

# The oracle expresses a strict conservative corroboration rule: receiver
# signatures alone authenticate origin, while peer-group comparison requires
# both observations. A missing antecedent does not prove a classical group.
ORACLE={
 'all_hybrid':{'unaltered':'SATISFIED','missing_first':'UNRESOLVED','missing_middle':'UNRESOLVED','missing_last':'UNRESOLVED','unsigned_last':'INVALID','unsigned_first':'INVALID','proof_last':'INVALID','missing_first_unsigned_last':'INVALID','missing_first_unsigned_middle':'INVALID','duplicate_last':'INVALID','missing_client':'UNRESOLVED','wrong_client_group':'INVALID'},
 'classical_middle':{'unaltered':'VIOLATED','missing_first':'UNRESOLVED','missing_middle':'UNRESOLVED','missing_last':'VIOLATED','unsigned_last':'INVALID','unsigned_first':'INVALID','proof_last':'INVALID','missing_first_unsigned_last':'INVALID','missing_first_unsigned_middle':'INVALID','duplicate_last':'INVALID','missing_client':'VIOLATED','wrong_client_group':'INVALID'},
 'unknown_last':{'unaltered':'UNRESOLVED','missing_first':'UNRESOLVED','missing_middle':'UNRESOLVED','missing_last':'UNRESOLVED','unsigned_last':'INVALID','unsigned_first':'INVALID','proof_last':'INVALID','missing_first_unsigned_last':'INVALID','missing_first_unsigned_middle':'INVALID','duplicate_last':'INVALID','missing_client':'UNRESOLVED','wrong_client_group':'INVALID'},
 'classical_first':{'unaltered':'VIOLATED','missing_first':'UNRESOLVED','missing_middle':'VIOLATED','missing_last':'VIOLATED','unsigned_last':'INVALID','unsigned_first':'INVALID','proof_last':'INVALID','missing_first_unsigned_last':'INVALID','missing_first_unsigned_middle':'INVALID','duplicate_last':'INVALID','missing_client':'UNRESOLVED','wrong_client_group':'INVALID'},
}
GROUPS={'all_hybrid':(H1,H1,H1),'classical_middle':(H1,C,H1),'unknown_last':(H1,H1,H2),'classical_first':(C,H1,H1)}

def main():
    p=argparse.ArgumentParser();p.add_argument('--out',required=True);p.add_argument('--count',type=int,default=3);args=p.parse_args()
    if args.count<2:raise SystemExit('Require >= 2 transactions to exercise indexed omissions')
    out=Path(args.out).resolve();out.mkdir(parents=True,exist_ok=True)
    if any(out.iterdir()):raise SystemExit('Refusing nonempty output directory '+str(out))
    rows=[]
    for policy,approved in old_policy.POLICIES.items():
        for config,groups in GROUPS.items():
            batch=old_policy.synthetic(groups,args.count)
            keys=batch['registered_public_keys']
            for label in ORACLE[config]:
                tested=variant(batch,label)
                actual=verify_partial(tested,keys,approved)
                expected=ORACLE[config][label]
                if config=='unknown_last' and policy=='multi_hybrid' and label=='unaltered':expected='SATISFIED'
                rows.append(dict(policy=policy,config=config,case=label,expected=expected,actual=actual,passed=actual==expected))
            # Durable freshness checks with unique persistent ledger per case.
            with tempfile.TemporaryDirectory(prefix='v45-fresh-') as temp:
                ledger=PartialLedger(Path(temp)/'ledger.sqlite',approved)
                challenge=batch['transactions'][0]['challenge']
                baseline=verify_partial(batch,keys,approved)
                first=ledger.check(batch,keys,challenge)
                again=PartialLedger(Path(temp)/'ledger.sqlite',approved).check(batch,keys,challenge)
                foreign=ledger.check(batch,keys,secrets.token_hex(32))
                checks=[('fresh_first',baseline,first),('fresh_again','INVALID' if baseline in ('SATISFIED','VIOLATED') else baseline,again),('fresh_foreign','INVALID',foreign)]
                for label,exp,got in checks:rows.append(dict(policy=policy,config=config,case=label,expected=exp,actual=got,passed=exp==got))
    with (out/'cases.csv').open('w',newline='') as f:
        writer=csv.DictWriter(f,fieldnames=list(rows[0]));writer.writeheader();writer.writerows(rows)
    summary={'experiment':'v45 authenticated partial-evidence reference, synthetic signed fixtures','utc':datetime.now(timezone.utc).isoformat(),'cases':len(rows),'passed':sum(r['passed'] for r in rows),'failed':sum(not r['passed'] for r in rows),'count_transactions_per_bundle':args.count,'limitations':'Signed synthetic receipts; independent antecedent comparison required to count verified groups; no new live TLS; original verifiers remain untouched.'}
    (out/'summary.json').write_text(json.dumps(summary,indent=2)+'\n')
    print(json.dumps(summary,indent=2))
    return 0 if summary['failed']==0 else 1
if __name__=='__main__':sys.exit(main())
