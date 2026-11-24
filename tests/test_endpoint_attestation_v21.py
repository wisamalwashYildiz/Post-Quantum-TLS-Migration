import copy,sys,unittest
from pathlib import Path
sys.path.insert(0,str(Path(__file__).resolve().parents[1]/'src'))
import endpoint_attestation_v21 as v
class V21Tests(unittest.TestCase):
 def setUp(self):
  self.tx={'nonce':'ab'*16,'data':'test'}
  self.a=v.private_key();self.b=v.private_key();self.pub={'initiator':v.pub_hex(self.a),'responder':v.pub_hex(self.b)}
  self.r=[]
  for role,key in [('initiator',self.a),('responder',self.b)]:
   st={'schema':v.SCHEMA,'identity':role,'role':role,'protocol':'TLSv1.3','transaction_hash':v.digest(self.tx),'nonce':self.tx['nonce'],'tag':('a' if role=='initiator' else 'b')*64}
   self.r.append({'statement':st,'signature':key.sign(v.base.canonical(st)).hex()})
 def test_valid(self):self.assertEqual(v.verify(self.tx,self.r,self.pub)[0],'ATTESTED')
 def test_missing(self):self.assertEqual(v.verify(self.tx,self.r[:1],self.pub)[0],'UNRESOLVED')
 def test_cloned(self):self.assertEqual(v.verify(self.tx,[self.r[0],copy.deepcopy(self.r[0])],self.pub)[0],'INVALID')
 def test_modified(self):
  r=copy.deepcopy(self.r);r[1]['statement']['tag']='c'*64
  self.assertEqual(v.verify(self.tx,r,self.pub)[0],'INVALID')
 def test_wrong_key(self):
  self.assertEqual(v.verify(self.tx,self.r,{'initiator':self.pub['initiator'],'responder':self.pub['initiator']})[0],'INVALID')
 def test_changed_tx(self):self.assertEqual(v.verify({'nonce':self.tx['nonce'],'data':'x'},self.r,self.pub)[0],'INVALID')
 def test_replay(self):self.assertEqual(v.verify(self.tx,self.r,self.pub,ledger={self.tx['nonce']})[0],'INVALID')
 def test_duplicate(self):self.assertEqual(v.verify(self.tx,self.r+[self.r[0]],self.pub)[0],'INVALID')
 def test_authentic_but_bogus_claims(self):
  r=copy.deepcopy(self.r)
  r[0]['statement']['tag']='1'*64;r[1]['statement']['tag']='2'*64
  for i,key in enumerate((self.a,self.b)):
   r[i]['signature']=key.sign(v.base.canonical(r[i]['statement'])).hex()
  self.assertEqual(v.verify(self.tx,r,self.pub)[0],'ATTESTED')
 def test_equal_tags(self):
  r=copy.deepcopy(self.r);r[1]['statement']['tag']=r[0]['statement']['tag'];r[1]['signature']=self.b.sign(v.base.canonical(r[1]['statement'])).hex()
  self.assertEqual(v.verify(self.tx,r,self.pub)[0],'INVALID')
if __name__=='__main__':unittest.main()
