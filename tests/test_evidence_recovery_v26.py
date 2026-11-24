import copy, unittest
from unittest.mock import patch
import evidence_recovery_v26 as r

class RecoveryTests(unittest.TestCase):
 def setUp(self):
  self.key=b'x'*32
  self.wk={'receiver:service-a':self.key}
  self.tx=[{'nonce':str(i),'sequence':i} for i in range(3)]
  self.witnesses=[r.v11.seal({'transaction_hash':r.v11.digest(t),'in':{'group':'X25519MLKEM768','session_label':'x'},'sequence':i},'receiver:service-a',self.wk) for i,t in enumerate(self.tx)]
  self.full={'transactions':self.tx,'witnesses':{'service-a':copy.deepcopy(self.witnesses)}}
  self.partial=copy.deepcopy(self.full);self.partial['witnesses']['service-a'].pop()
  self.store={'service-a/2':copy.deepcopy(self.witnesses[2])}
  def fakeverify(b,*_):
   w=b['witnesses']['service-a']
   if len(w)<3:return 'UNRESOLVED','missing'
   if any(not r.v11.verify_seal(x,self.wk) for x in w):return 'INVALID','bad signature'
   return 'SATISFIED','complete'
  self.verification=patch.object(r.v24,'verify_batch',side_effect=fakeverify);self.verification.start();self.addCleanup(self.verification.stop)
 def test_original_missing(self):self.assertEqual(r.v24.verify_batch(self.partial,None,None)[0],'UNRESOLVED')
 def test_successful_recovery(self):self.assertEqual(r.recover(self.partial,self.store,'service-a',2,None,self.wk)[0],'SATISFIED')
 def test_unavailable(self):self.assertEqual(r.recover(self.partial,{},'service-a',2,None,self.wk)[0],'UNRESOLVED')
 def test_tampered_mac(self):
  s=copy.deepcopy(self.store);s['service-a/2']['mac']='0'*64
  self.assertEqual(r.recover(self.partial,s,'service-a',2,None,self.wk)[0],'INVALID')
 def test_wrong_transaction(self):
  s={'service-a/2':copy.deepcopy(self.witnesses[1])}
  self.assertEqual(r.recover(self.partial,s,'service-a',2,None,self.wk)[0],'INVALID')
 def test_wrong_node(self):
  s=copy.deepcopy(self.store);s['service-a/2']['node']='receiver:gateway'
  self.assertEqual(r.recover(self.partial,s,'service-a',2,None,self.wk)[0],'INVALID')
 def test_conflicting_receipt(self):
  s=copy.deepcopy(self.store);s['service-a/2/conflict']=copy.deepcopy(self.witnesses[1])
  self.assertEqual(r.recover(self.partial,s,'service-a',2,None,self.wk,mode='conflicting')[0],'INVALID')
 def test_idempotent_complete(self):self.assertEqual(r.recover(self.full,self.store,'service-a',2,None,self.wk)[0],'SATISFIED')
 def test_invalid_node(self):
  with self.assertRaises(ValueError):r.recover(self.partial,self.store,'wrong',2,None,self.wk)
 def test_out_of_range(self):
  with self.assertRaises(ValueError):r.recover(self.partial,self.store,'service-a',3,None,self.wk)
 def test_escrow_authenticity(self):self.assertTrue(r.verify_escrow_entry(self.witnesses[2],'service-a',2,self.tx[2],self.wk))
 def test_escrow_wrong_key(self):self.assertFalse(r.verify_escrow_entry(self.witnesses[2],'service-a',2,self.tx[2],{'receiver:service-a':b'y'*32}))
if __name__=='__main__':unittest.main()
