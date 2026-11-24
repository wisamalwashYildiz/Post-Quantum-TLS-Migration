"""Synthetic n-hop authenticated-chain scaling. NOT live TLS or v32 verified; models signature + evidence consistency."""
import argparse,hashlib,time,statistics,copy
from v40_common import *
def build(n):
 sk=[Ed25519PrivateKey.generate() for _ in range(n)]
 p=[hashlib.sha256(f'proof-{i}'.encode()).hexdigest() for i in range(n)]
 tx={'sequence':0,'nonce':'n','challenge':'a'*64,'payload':'synthetic'}
 records=[]
 for i in range(n):
  r={'node':f'r{i}','sequence':0,'tx_hash':v.digest(tx),'inbound_group':H,'inbound_proof':p[i],'outbound_group':H if i<n-1 else None,'outbound_proof':p[i+1] if i<n-1 else None}
  records.append(v.signed(sk[i],r))
 return tx,sk,records,p

def verify_n(tx,keys,records,p):
 for i,(k,sr) in enumerate(zip(keys,records)):
  pub=k.public_key().public_bytes(serialization.Encoding.Raw,serialization.PublicFormat.Raw).hex()
  if not v.valid(pub,sr):return 'INVALID'
  r=sr['record']
  if r['sequence']!=0 or r['tx_hash']!=v.digest(tx) or r['inbound_group']!=H:return 'INVALID'
  if r['inbound_proof']!=p[i]:return 'INVALID'
  if i and r['inbound_proof']!=records[i-1]['record']['outbound_proof']:return 'INVALID'
 return 'SATISFIED'

def main():
 p=argparse.ArgumentParser();p.add_argument('--out',required=True);p.add_argument('--repetitions',type=int,default=40);a=p.parse_args();rows=[]
 for n in [3,5,7,10,16]:
  tx,keys,rec,pr=build(n);ts=[];got=[]
  for z in range(a.repetitions):
   t=time.perf_counter_ns();got.append(verify_n(tx,keys,rec,pr));ts.append((time.perf_counter_ns()-t)/1e6)
  rows.append(dict(hops=n,repetitions=a.repetitions,median_ms=round(statistics.median(ts),6),minimum_ms=round(min(ts),6),evidence_bytes=len(v.canon(rec)),all_satisfied=all(x=='SATISFIED' for x in got)))
 save(a.out,rows,{'type':'synthetic n-hop computational microbenchmark; no TLS network','hop_counts':[3,5,7,10,16],'repetitions_per_size':a.repetitions})
if __name__=='__main__':main()
