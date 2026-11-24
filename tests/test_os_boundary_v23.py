import unittest,sys
from pathlib import Path
sys.path.insert(0,str(Path(__file__).resolve().parents[1]/'src'))
import os_boundary_v23 as m
import session_chain_v11 as v
K=b'k'*32;O=b'o'*32
class BoundaryTests(unittest.TestCase):
 def case(self,group=v.HYBRID):
  tx={'nonce':'n1','sequence':0}
  obs={'group':group,'session_label':'s'}
  report=v.seal({'transaction_hash':v.digest(tx),'observed_tls':obs},m.REPORTER,{m.REPORTER:K})
  witness=v.seal({'transaction_hash':v.digest(tx),'observed_tls':obs,'sequence':0},m.NODE,{m.NODE:O})
  return tx,report,witness
 def test_hybrid(self):
  t,r,w=self.case();self.assertEqual(m.verify([t],[r],[w],K,O),'SATISFIED')
 def test_classical(self):
  t,r,w=self.case(v.CLASSIC);self.assertEqual(m.verify([t],[r],[w],K,O),'VIOLATED')
 def test_forged_report(self):
  t,r,w=self.case(v.CLASSIC);r['body']['observed_tls']={'group':v.HYBRID,'session_label':'s'}
  r=v.seal(r['body'],m.REPORTER,{m.REPORTER:K});self.assertEqual(m.verify([t],[r],[w],K,O),'INVALID')
 def test_missing(self):
  t,r,w=self.case();self.assertEqual(m.verify([t],[r],[],K,O),'UNRESOLVED')
 def test_wrong_observer_key(self):
  t,r,w=self.case();self.assertEqual(m.verify([t],[r],[w],K,b'x'*32),'INVALID')
 def test_replay(self):
  t,r,w=self.case();self.assertEqual(m.verify([t,t],[r,r],[w,w],K,O),'INVALID')
 def test_transaction_swap(self):
  t,r,w=self.case();t2=dict(t,nonce='n2');self.assertEqual(m.verify([t2],[r],[w],K,O),'INVALID')
 def test_sequence(self):
  t,r,w=self.case();w['body']['sequence']=1
  w=v.seal(w['body'],m.NODE,{m.NODE:O});self.assertEqual(m.verify([t],[r],[w],K,O),'INVALID')
if __name__=='__main__':unittest.main()
