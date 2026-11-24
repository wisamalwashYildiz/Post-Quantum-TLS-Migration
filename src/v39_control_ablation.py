"""Matched synthetic signed evidence: selected checker removals. Weakened comparators, not production recommendations."""
import argparse,copy,secrets
from v40_common import *
def check(b, ignore_signature=False,ignore_group=False,ignore_exporter=False):
 for seq,tx in enumerate(b['transactions']):
  prior=b['client'][seq]
  for i,node in enumerate(v.NODES):
   try:sr=b['receivers'][node][seq];r=sr['record']
   except (KeyError,IndexError):return 'UNRESOLVED'
   if not ignore_signature and not v.valid(b['registered_public_keys'][node],sr):return 'INVALID'
   if r['node']!=node or r['sequence']!=seq or r['tx_hash']!=v.digest(tx):return 'INVALID'
   pg=prior['group'] if i==0 else prior['outbound_group'];pp=prior['proof'] if i==0 else prior['outbound_proof']
   if not ignore_group and r['inbound_group']!=pg:return 'INVALID'
   if not ignore_exporter and not secrets.compare_digest(r['inbound_proof'],pp):return 'INVALID'
   prior=r
 return 'VIOLATED' if any(b['receivers'][n][0]['record']['inbound_group']==C for n in v.NODES) else 'SATISFIED'
def main():
 p=argparse.ArgumentParser();p.add_argument('--out',required=True);a=p.parse_args();rows=[]
 for path in ([H,H,H],[H,C,H]):
  base,sk=fixture(path)
  for attack in ('none','unsigned_group_edit','signed_false_group','signed_false_proof','unsigned_proof_edit'):
   b=copy.deepcopy(base);r=b['receivers'][v.NODES[1]][0]
   if attack in ('unsigned_group_edit','signed_false_group'):r['record']['inbound_group']=H if path[1]==C else C
   if attack in ('unsigned_proof_edit','signed_false_proof'):r['record']['inbound_proof']='f'*64
   if attack.startswith('signed_'):b['receivers'][v.NODES[1]][0]=v.signed(sk[v.NODES[1]],r['record'])
   for mode,opts in [('full',{}),('without_signature',{'ignore_signature':True}),('without_group_check',{'ignore_group':True}),('without_exporter_check',{'ignore_exporter':True})]:
    rows.append(dict(path='|'.join(path),attack=attack,control=mode,verdict=check(b,**opts)))
 from collections import Counter
 save(a.out,rows,{'type':'synthetic matched-evidence ablation; intentionally weakened checks','cases':len(rows),'verdicts':dict(Counter(r['verdict'] for r in rows)),'warning':'Ablations are exploratory custom checkers; compare source-level definitions before manuscript inclusion.'})
if __name__=='__main__':main()
