import copy, pathlib, sys, tempfile, unittest
sys.path.insert(0,str(pathlib.Path(__file__).resolve().parents[1]/'src'))
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from v32_protected_freshness import FreshLedger, signed, public_bytes, verify, valid, choose_uids, HYBRID, CLASSIC, NODES, digest

class ProtectedGateTests(unittest.TestCase):
    def setUp(self):
        self.tmp=tempfile.TemporaryDirectory();self.addCleanup(self.tmp.cleanup)
        self.ledger=pathlib.Path(self.tmp.name)/'ledger.sqlite3'
        self.challenge='a'*64
    def batch(self, middle=HYBRID):
        tx={'nonce':'fresh-nonce','challenge':self.challenge,'sequence':0,'payload':'test'}
        keys={};records={};prior='recorded_exporter_proof'
        for i,node in enumerate(NODES):
            sk=Ed25519PrivateKey.generate();keys[node]=public_bytes(sk)
            group=middle if i==1 else HYBRID
            rec={'node':node,'sequence':0,'tx_hash':digest(tx),'inbound_group':group,
                 'inbound_proof':prior,'outbound_group':(middle if i==0 else HYBRID) if i<2 else None,
                 'outbound_proof':f'out_{i}' if i<2 else None}
            records[node]=[signed(sk,rec)];prior=rec['outbound_proof']
        return {'transactions':[tx],'client':[{'group':HYBRID,'proof':'recorded_exporter_proof'}],
                'receivers':records},keys
    def test_good_hybrid(self):
        batch,keys=self.batch();self.assertEqual(verify(batch,keys),'SATISFIED')
    def test_middle_classical(self):
        batch,keys=self.batch(CLASSIC);self.assertEqual(verify(batch,keys),'VIOLATED')
    def test_persistent_replay(self):
        batch,keys=self.batch();self.assertEqual(FreshLedger(self.ledger).check(batch,keys,self.challenge),'SATISFIED')
        self.assertEqual(FreshLedger(self.ledger).check(batch,keys,self.challenge),'INVALID')
    def test_changed_challenge(self):
        batch,keys=self.batch();self.assertEqual(FreshLedger(self.ledger).check(batch,keys,'b'*64),'INVALID')
    def test_missing_doesnt_commit(self):
        batch,keys=self.batch();batch['receivers']['service-a']=[]
        self.assertEqual(FreshLedger(self.ledger).check(batch,keys,self.challenge),'UNRESOLVED')
        complete,k2=self.batch();self.assertEqual(FreshLedger(self.ledger).check(complete,k2,self.challenge),'SATISFIED')
    def test_modified_signed_record(self):
        batch,keys=self.batch();batch['receivers']['service-a'][0]['record']['inbound_group']=CLASSIC
        self.assertEqual(FreshLedger(self.ledger).check(batch,keys,self.challenge),'INVALID')
    def test_wrong_key(self):
        batch,keys=self.batch();keys['service-a']=keys['backend']
        self.assertEqual(FreshLedger(self.ledger).check(batch,keys,self.challenge),'INVALID')
    def test_no_empty_challenge(self):
        batch,keys=self.batch();self.assertEqual(FreshLedger(self.ledger).check(batch,keys,''),'INVALID')
    def test_distinct_unused_uids(self):
        uids=choose_uids();self.assertEqual(len(set(uids)),4)

if __name__=='__main__':unittest.main()
