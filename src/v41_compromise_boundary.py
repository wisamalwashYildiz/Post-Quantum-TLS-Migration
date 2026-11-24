"""Unilateral vs coordinated falsification of signed cross-hop group observations. Synthetic trust-boundary demonstration."""
import argparse,copy
from v40_common import *
def main():
 p=argparse.ArgumentParser();p.add_argument('--out',required=True);a=p.parse_args();rows=[]
 for groups in ([H,H,H],[H,C,H]):
  base,keys=fixture(groups,count=1)
  for name in ('untouched','middle_receiver_only','middle_and_previous_outbound','middle_and_previous_group_proof'):
   b=copy.deepcopy(base)
   middle=b['receivers'][v.NODES[1]][0]['record']
   if name!='untouched':
    middle['inbound_group']=H if groups[1]==C else C
    b['receivers'][v.NODES[1]][0]=v.signed(keys[v.NODES[1]],middle)
   if name in ('middle_and_previous_outbound','middle_and_previous_group_proof'):
    prior=b['receivers'][v.NODES[0]][0]['record'];prior['outbound_group']=middle['inbound_group']
    b['receivers'][v.NODES[0]][0]=v.signed(keys[v.NODES[0]],prior)
   rows.append(dict(actual='|'.join(groups),attack=name,reported_middle=middle['inbound_group'],verdict=v.verify(b,b['registered_public_keys'])))
 from collections import Counter
 save(a.out,rows,{'type':'synthetic signer-control boundary; no demonstrated real compromise','cases':len(rows),'verdicts':dict(Counter(r['verdict'] for r in rows))})
if __name__=='__main__':main()
