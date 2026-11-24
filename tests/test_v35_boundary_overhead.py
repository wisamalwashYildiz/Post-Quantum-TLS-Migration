import copy,os,sys,tempfile,unittest
from pathlib import Path
sys.path.insert(0,str(Path(__file__).resolve().parent.parent/'src'))
import v35_boundary_overhead as x
import v32_protected_freshness as v
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

class V35Tests(unittest.TestCase):
    def fixture(self,classical=False):
        sk=[Ed25519PrivateKey.generate() for _ in range(3)]
        keymap={n:v.public_bytes(k) for n,k in zip(v.NODES,sk)}
        tx={'sequence':0,'nonce':'nonce1','challenge':'x'*64,'payload':'test'}
        proof=['proofa','proofb','proofc']
        groups=[v.HYBRID,v.CLASSIC if classical else v.HYBRID,v.HYBRID]
        client=[{'group':groups[0],'proof':proof[0]}]
        recv={}
        for i,n in enumerate(v.NODES):
            rec={'node':n,'sequence':0,'tx_hash':v.digest(tx),'inbound_group':groups[i],
                 'inbound_proof':proof[i], 'outbound_group':groups[i+1] if i<2 else None,
                 'outbound_proof':proof[i+1] if i<2 else None}
            recv[n]=[v.signed(sk[i],rec)]
        return {'transactions':[tx],'client':client,'receivers':recv},keymap,sk
    def test_compromise_has_authentic_signature_but_is_rejected(self):
        b,keys,sk=self.fixture(True)
        raw=sk[1].private_bytes_raw()
        compromised=x.compromise_one(b,raw)
        a=x.verify_compromise(b,compromised,keys)
        self.assertTrue(a['compromised_signer_receipt_authenticates'])
        self.assertEqual(a['original'],'VIOLATED')
        self.assertEqual(a['compromised_evidence_verdict'],'INVALID')
    def test_original_unchanged(self):
        b,k,sk=self.fixture(True);before=copy.deepcopy(b)
        x.compromise_one(b,sk[1].private_bytes_raw())
        self.assertEqual(b,before)
    def test_both_hybrid(self):
        b,k,_=self.fixture(False);self.assertEqual(v.verify(b,k),'SATISFIED')
    def test_timing_independent_rows(self):
        b,k,_=self.fixture(False)
        with tempfile.TemporaryDirectory() as td:
            rows=x.time_methods(b,k,'x'*64,'SATISFIED',Path(td),3)
        self.assertEqual(len(rows),9)
        self.assertEqual(set(y['method'] for y in rows),set(x.METHODS))
        self.assertTrue(all(y['verify_ns']>=0 for y in rows))
    def test_compromise_requires_legitimate_key(self):
        b,keys,sk=self.fixture(True)
        forged=x.compromise_one(b,Ed25519PrivateKey.generate().private_bytes_raw())
        self.assertFalse(v.valid(keys[v.NODES[1]],forged['receivers'][v.NODES[1]][0]))

if __name__=='__main__':unittest.main()
