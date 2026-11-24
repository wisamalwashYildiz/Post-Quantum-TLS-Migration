"""Shared synthetic evidence factory; no TLS secrets, no live-handshake claims."""
import hashlib, sys, copy, json
from pathlib import Path
P=Path(__file__).resolve().parent
sys.path.insert(0,str(P))
import v32_protected_freshness as v
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from cryptography.hazmat.primitives import serialization
H=v.HYBRID; C=v.CLASSIC

def fixture(groups, count=3, challenge='a'*64):
    assert len(groups)==3
    sk={r:Ed25519PrivateKey.generate() for r in v.NODES}
    pubs={r:k.public_key().public_bytes(serialization.Encoding.Raw,serialization.PublicFormat.Raw).hex() for r,k in sk.items()}
    txs=[]; clients=[]; receivers={r:[] for r in v.NODES}
    for seq in range(count):
        tx={'sequence':seq,'nonce':f'nonce-{seq:04d}', 'challenge':challenge,'payload':'controlled synthetic fixture'}
        txs.append(tx)
        pp=[hashlib.sha256(f'fixture/{seq}/{i}'.encode()).hexdigest() for i in range(3)]
        clients.append({'group':groups[0],'proof':pp[0]})
        for i,r in enumerate(v.NODES):
            rec={'node':r,'sequence':seq,'tx_hash':v.digest(tx),'inbound_group':groups[i], 'inbound_proof':pp[i], 'outbound_group':groups[i+1] if i<2 else None,'outbound_proof':pp[i+1] if i<2 else None}
            receivers[r].append(v.signed(sk[r],rec))
    return {'transactions':txs,'client':clients,'receivers':receivers,'registered_public_keys':pubs}, sk

def save(out,rows,summary):
    import csv
    out=Path(out);out.mkdir(parents=True,exist_ok=True)
    if rows:
        with (out/'cases.csv').open('w',newline='') as f:
            wr=csv.DictWriter(f,fieldnames=list(rows[0]));wr.writeheader();wr.writerows(rows)
    (out/'summary.json').write_text(json.dumps(summary,indent=2,sort_keys=True)+'\n')
    print(json.dumps(summary,sort_keys=True))
