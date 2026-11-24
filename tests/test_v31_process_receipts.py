import sys,unittest,copy
from pathlib import Path
sys.path.insert(0,str(Path(__file__).resolve().parents[1]/'src'))
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from v31_process_receipts import signed,valid,verify,interventions,public_bytes,NODES,HYBRID,CLASSIC,digest

def fixture(classical=False):
    tx={'nonce':'unique','sequence':0,'payload':'test'}
    sk={name:Ed25519PrivateKey.generate() for name in NODES}
    keys={name:public_bytes(v) for name,v in sk.items()}
    proof='f'*64
    r={}
    for i,node in enumerate(NODES):
        r[node]=[signed(sk[node],{'node':node,'sequence':0,'tx_hash':digest(tx),
            'inbound_group':CLASSIC if classical and i==1 else HYBRID,
            'inbound_proof':proof,'outbound_group':CLASSIC if classical and i==0 else HYBRID if i<2 else None,
            'outbound_proof':proof if i<2 else None})]
    return {'transactions':[tx],'client':[{'group':HYBRID,'proof':proof}],'receivers':r},keys
class ProcessReceiptTests(unittest.TestCase):
    def test_good(self):
        b,k=fixture();self.assertEqual(verify(b,k),'SATISFIED')
    def test_classical(self):
        b,k=fixture(True);self.assertEqual(verify(b,k),'VIOLATED')
    def test_tamper(self):
        b,k=fixture();b['receivers']['service-a'][0]['record']['inbound_group']='X25519';self.assertEqual(verify(b,k),'INVALID')
    def test_missing(self):
        b,k=fixture();b['receivers']['backend']=[];self.assertEqual(verify(b,k),'UNRESOLVED')
    def test_wrong_key(self):
        b,k=fixture();k['gateway']=k['backend'];self.assertEqual(verify(b,k),'INVALID')
    def test_replay_nonce(self):
        b,k=fixture();b['transactions'].append(dict(b['transactions'][0],sequence=1));self.assertEqual(verify(b,k),'INVALID')
    def test_complete_copy_negative_control(self):
        b,k=fixture();self.assertEqual(verify(copy.deepcopy(b),k),'SATISFIED')
    def test_changed_transaction(self):
        b,k=fixture();b['transactions'][0]['payload']='changed';self.assertEqual(verify(b,k),'INVALID')
    def test_wrong_node(self):
        b,k=fixture();b['receivers']['backend'][0]['record']['node']='gateway';self.assertEqual(verify(b,k),'INVALID')
    def test_invalid_sig(self):
        b,k=fixture();b['receivers']['gateway'][0]['signature']='not_base64!';self.assertEqual(verify(b,k),'INVALID')
if __name__=='__main__':unittest.main()
