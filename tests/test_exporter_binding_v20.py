import copy,unittest,sys
from pathlib import Path
sys.path.insert(0,str(Path(__file__).resolve().parents[1]/'src'))
import exporter_binding_v20 as v
class BindingTests(unittest.TestCase):
    def setUp(self):
        self.tx={'nonce':'a'*32,'data':'test'}
        self.c={'transaction_hash':v.hashlib.sha256(v.canonical(self.tx)).hexdigest(),'protocol':'TLSv1.3','proof':'a'*64}
        self.s=dict(self.c)
    def test_equal(self):self.assertEqual(v.verify(self.tx,self.c,self.s)[0],'BOUND')
    def test_changed(self):
        t=dict(self.tx,data='different');self.assertEqual(v.verify(t,self.c,self.s)[0],'INVALID')
    def test_forged_peer(self):
        s=dict(self.s,proof='b'*64);self.assertEqual(v.verify(self.tx,self.c,s)[0],'INVALID')
    def test_missing(self):self.assertEqual(v.verify(self.tx,self.c,None)[0],'UNRESOLVED')
    def test_ledger(self):self.assertEqual(v.verify(self.tx,self.c,self.s,ledger={'a'*32})[0],'INVALID')
    def test_wrong_target(self):self.assertEqual(v.verify(self.tx,self.c,self.s,expected_id='b'*32)[0],'INVALID')
    def test_bad_protocol(self):self.assertEqual(v.verify(self.tx,dict(self.c,protocol='TLSv1.2'),self.s)[0],'INVALID')
if __name__=='__main__':unittest.main()
