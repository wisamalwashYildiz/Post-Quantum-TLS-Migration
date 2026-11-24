"""Exhaustive 2^3 staged migration trajectories using unchanged signed-receiver verifier. Synthetic evidence."""
import argparse,itertools
from v40_common import *
def main():
 p=argparse.ArgumentParser();p.add_argument('--out',required=True);a=p.parse_args();rows=[]
 for mask in itertools.product((C,H),repeat=3):
  b,k=fixture(mask); actual=v.verify(b,b['registered_public_keys']);expected='SATISFIED' if H==mask[0]==mask[1]==mask[2] else 'VIOLATED'
  rows.append(dict(groups='|'.join(mask),hybrid_hops=sum(g==H for g in mask),expected=expected,observed=actual,match=actual==expected))
 save(a.out,rows,{'type':'synthetic signed receipts, not live TLS','cases':len(rows),'matched':sum(r['match'] for r in rows)})
if __name__=='__main__':main()
