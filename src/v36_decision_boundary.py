#!/usr/bin/env python3
"""New offline decision-boundary characterization for unchanged v3.2 verifier.
Synthetic *internally consistent* signed records, NOT additional live TLS evidence.
No protected key material or TLS secrets are stored. No production claim.
"""
import copy,csv,hashlib,json,sys,datetime
from pathlib import Path
here=Path(__file__).resolve().parent
for candidate in (here,here/'src',here.parent/'src',here.parent/'pqtls_review_extract'/'src'):
    if (candidate/'v32_protected_freshness.py').exists():
        sys.path.insert(0,str(candidate));break
else:
    raise SystemExit('Cannot locate src/v32_protected_freshness.py')
import v32_protected_freshness as v
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from cryptography.hazmat.primitives import serialization

def make_batch(groups,count=3):
 keys={n:Ed25519PrivateKey.generate() for n in v.NODES}
 pubs={n:sk.public_key().public_bytes(encoding=serialization.Encoding.Raw,format=serialization.PublicFormat.Raw).hex() for n,sk in keys.items()}
 transactions=[];client=[];receivers={n:[] for n in v.NODES}
 for seq in range(count):
  tx={'sequence':seq,'nonce':f'nonce-{seq:02d}','challenge':'b'*64,'payload':'synthetic verifier control'}
  transactions.append(tx)
  proofs=[hashlib.sha256(f'{seq}-{i}-synthetic'.encode()).hexdigest() for i in range(3)]
  client.append({'group':groups[0],'proof':proofs[0]})
  for i,n in enumerate(v.NODES):
   rec={'node':n,'sequence':seq,'tx_hash':v.digest(tx),'inbound_group':groups[i], 'inbound_proof':proofs[i], 'outbound_group':groups[i+1] if i<2 else None, 'outbound_proof':proofs[i+1] if i<2 else None}
   receivers[n].append(v.signed(keys[n],rec))
 return {'transactions':transactions,'client':client,'receivers':receivers,'registered_public_keys':pubs},keys

def run():
 rows=[]; H=v.HYBRID;C=v.CLASSIC
 for scenario,groups in [('all_hybrid',[H]*3),('classical_first',[C,H,H]),('classical_middle',[H,C,H]),('classical_last',[H,H,C])]:
  base,keys=make_batch(groups)
  cases=[('complete','none',None,copy.deepcopy(base))]
  for lost in range(3):
   for seq in range(3):
    b=copy.deepcopy(base); b['receivers'][v.NODES[lost]].pop(seq)
    cases.append(('missing_receiver',v.NODES[lost],seq,b))
  for tamper in range(3):
   for seq in range(3):
    b=copy.deepcopy(base);b['receivers'][v.NODES[tamper]][seq]['record']['inbound_group']=C if groups[tamper]==H else H
    cases.append(('unsigned_group_edit',v.NODES[tamper],seq,b))
  for tamper in range(3):
   for seq in range(3):
    b=copy.deepcopy(base);b['receivers'][v.NODES[tamper]][seq]['record']['inbound_proof']='f'*64
    cases.append(('unsigned_exporter_edit',v.NODES[tamper],seq,b))
  for category,role,seq,b in cases:
   got=v.verify(b,b['registered_public_keys'])
   rows.append({'path':scenario,'perturbation':category,'role':role,'transaction_index':seq,'signed_receiver_verdict':got})
 output=Path(__file__).resolve().parent;output.mkdir(exist_ok=True)
 with (output/'v36_boundary_results.csv').open('w',newline='') as f:
  w=csv.DictWriter(f,fieldnames=rows[0].keys());w.writeheader();w.writerows(rows)
 from collections import Counter
 counts={str(k):v for k,v in sorted(Counter((r['perturbation'],r['signed_receiver_verdict']) for r in rows).items())}
 summary={'experiment':'Synthetic, offline, no live TLS; unchanged v32 verifier','n_cases':len(rows),'counts':counts,'missing_classical_middle':Counter(r['signed_receiver_verdict'] for r in rows if r['path']=='classical_middle' and r['perturbation']=='missing_receiver'),'source_verifier':'src/v32_protected_freshness.py::verify'}
 summary['missing_classical_middle']=dict(summary['missing_classical_middle'])
 (output/'v36_boundary_summary.json').write_text(json.dumps(summary,indent=2)+'\n')
 print(json.dumps(summary,indent=2))
if __name__=='__main__':run()
