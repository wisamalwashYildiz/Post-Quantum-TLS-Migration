import sys,unittest,copy
from pathlib import Path
sys.path.insert(0,str(Path(__file__).resolve().parents[1]/'src'))
import v30_session_gate as g
class GateTests(unittest.TestCase):
 def sample(self):
  tx={'nonce':'abcdef','sequence':0,'payload':'ok'}; h=g.digest(tx)
  return {'transactions':[tx],'client':[{'group':g.HYBRID,'proof':'a'}],
   'receivers':{'gateway':[{'transaction_hash':h,'inbound_group':g.HYBRID,'inbound_proof':'a','outbound_group':g.HYBRID,'outbound_proof':'b'}],
    'service-a':[{'transaction_hash':h,'inbound_group':g.HYBRID,'inbound_proof':'b','outbound_group':g.HYBRID,'outbound_proof':'c'}],
    'backend':[{'transaction_hash':h,'inbound_group':g.HYBRID,'inbound_proof':'c','outbound_group':None,'outbound_proof':None}]}}
 def test_hybrid(self):self.assertEqual(g.verify(self.sample()),'SATISFIED')
 def test_classical(self):
  x=self.sample();x['receivers']['service-a'][0]['inbound_group']=g.CLASSIC;x['receivers']['gateway'][0]['outbound_group']=g.CLASSIC
  self.assertEqual(g.verify(x),'VIOLATED')
 def test_mismatch(self):
  x=self.sample();x['receivers']['backend'][0]['inbound_proof']='x';self.assertEqual(g.verify(x),'INVALID')
 def test_missing(self):
  x=self.sample();x['receivers']['backend']=[];self.assertEqual(g.verify(x),'UNRESOLVED')
 def test_transaction_change(self):
  x=self.sample();x['transactions'][0]['payload']='bad';self.assertEqual(g.verify(x),'INVALID')
 def test_duplicate_nonce(self):
  x=self.sample();x['transactions'].append(copy.deepcopy(x['transactions'][0]));self.assertEqual(g.verify(x),'INVALID')
if __name__=='__main__':unittest.main()
