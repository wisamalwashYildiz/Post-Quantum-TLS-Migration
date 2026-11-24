#!/usr/bin/env python3
"""Differential audit: keep legacy v32/v44 behavior as observable baselines."""
import argparse,csv,json,sys,copy,hashlib
from pathlib import Path
from datetime import datetime,timezone
import v32_protected_freshness as v
import v44_policy_aware_live as v44
from v45_precedence_verifier import verify_partial

def main():
 p=argparse.ArgumentParser();p.add_argument('--out',required=True);args=p.parse_args()
 out=Path(args.out).resolve();out.mkdir(parents=True,exist_ok=True)
 if any(out.iterdir()):raise SystemExit('Refusing nonempty directory')
 rows=[]
 for name,groups in [('hybrid',(v.HYBRID,)*3),('classical_middle',(v.HYBRID,v.CLASSIC,v.HYBRID))]:
  batch=v44.synthetic(groups,count=3);keys=batch['registered_public_keys']
  for condition in ['unaltered','missing_first','missing_last','missing_middle','unsigned_last']:
   b=copy.deepcopy(batch)
   if condition=='missing_first':b['receivers'][v.NODES[0]].pop(0)
   if condition=='missing_last':b['receivers'][v.NODES[2]].pop(0)
   if condition=='missing_middle':b['receivers'][v.NODES[1]].pop(0)
   if condition=='unsigned_last':b['receivers'][v.NODES[2]][0]['record']['inbound_group']='BAD'
   legacy=v.verify(b,keys)
   policy=v44.verify_policy(b,keys,(v.HYBRID,))
   reference=verify_partial(b,keys,(v.HYBRID,))
   rows.append(dict(path=name,intervention=condition,v32=legacy,v44=policy,v45=reference,legacy_agreement=legacy==policy,reference_diff=reference!=legacy))
 with (out/'differential.csv').open('w',newline='') as f:
  writer=csv.DictWriter(f,fieldnames=list(rows[0]));writer.writeheader();writer.writerows(rows)
 summary={'experiment':'Differential behavior against untouched v32 and v44','cases':len(rows),'legacy_agreement':sum(x['legacy_agreement'] for x in rows),'v45_differences':sum(x['reference_diff'] for x in rows),'differences':[x for x in rows if x['reference_diff']],'utc':datetime.now(timezone.utc).isoformat()}
 (out/'summary.json').write_text(json.dumps(summary,indent=2)+'\n');print(json.dumps(summary,indent=2))
 return 0 if summary['legacy_agreement']==len(rows) else 1
if __name__=='__main__':sys.exit(main())
