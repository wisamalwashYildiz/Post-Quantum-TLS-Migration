import copy, os, sys, unittest
sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..', 'src'))
from session_chain_v11 import seal, verify_chain, HYBRID, CLASSIC, digest
from trust_boundary_v12 import verify_corroborated, forge_middle_hybrid, receiver_witness

class V12Tests(unittest.TestCase):
    def setUp(self):
        self.nodekeys = {n: (n+'secret').encode() for n in ('client','gateway','service-a','backend')}
        self.obskeys = {'observer:'+n: (n+'observer-secret').encode() for n in ('gateway','service-a','backend')}
        self.tx = {'nonce':'case-a'}
        h=digest(self.tx)
        self.client=seal({'transaction_hash':h, 'out':{'session_label':'s1','group':HYBRID}}, 'client', self.nodekeys)
        self.receipts=[]
        self.witnesses=[]
        for node,inc,out,target in [('gateway','s1','s2','service-a'),('service-a','s2','s3','backend'),('backend','s3',None,None)]:
            body={'transaction_hash':h,'in':{'session_label':inc,'group':HYBRID},
                  'out':{'session_label':out,'group':HYBRID} if out else None,'target':target}
            self.receipts.append(seal(body,node,self.nodekeys))
            self.witnesses.append(receiver_witness(body,node,self.obskeys))
    def check(self, receipts=None, witnesses=None, tx=None):
        return verify_corroborated(tx or self.tx,self.client,self.receipts if receipts is None else receipts,
                                   self.witnesses if witnesses is None else witnesses,self.nodekeys,self.obskeys)[0]
    def test_valid(self): self.assertEqual(self.check(),'SATISFIED')
    def test_missing_witness(self): self.assertEqual(self.check(witnesses=self.witnesses[:2]),'UNRESOLVED')
    def test_modified_witness(self):
        w=copy.deepcopy(self.witnesses);w[1]['body']['in']['group']=CLASSIC
        self.assertEqual(self.check(witnesses=w),'INVALID')
    def test_wrong_nonce(self): self.assertEqual(self.check(tx={'nonce':'case-b'}),'INVALID')
    def test_wrong_observer_key(self):
        w=copy.deepcopy(self.witnesses);w[1]=seal(w[1]['body'],'observer:service-a',{'observer:service-a':b'incorrect'})
        self.assertEqual(self.check(witnesses=w),'INVALID')
    def test_false_classical_relabel_detected(self):
        r=copy.deepcopy(self.receipts)
        for i,field in ((0,'out'),(1,'in')):
            r[i]['body'][field]['group']=CLASSIC
            r[i]=seal(r[i]['body'],r[i]['node'],self.nodekeys)
        self.assertEqual(verify_chain(self.tx,self.client,r,self.nodekeys)[0],'VIOLATED')
        self.assertEqual(self.check(receipts=r),'INVALID')
    def test_compromised_forwarder_false_hybrid(self):
        r=copy.deepcopy(self.receipts);w=copy.deepcopy(self.witnesses)
        for i,field in ((0,'out'),(1,'in')):
            r[i]['body'][field]['group']=CLASSIC
            r[i]=seal(r[i]['body'],r[i]['node'],self.nodekeys)
        w[1]['body']['in']['group']=CLASSIC
        w[1]=seal(w[1]['body'],'observer:service-a',self.obskeys)
        self.assertEqual(self.check(receipts=r,witnesses=w),'VIOLATED')
        forged=forge_middle_hybrid(r,self.nodekeys)
        self.assertEqual(verify_chain(self.tx,self.client,forged,self.nodekeys)[0],'SATISFIED')
        self.assertEqual(self.check(receipts=forged,witnesses=w),'INVALID')
    def test_duplicated_witness(self):
        self.assertEqual(self.check(witnesses=[self.witnesses[0]]*3),'INVALID')
    def test_receipt_omission(self): self.assertEqual(self.check(receipts=self.receipts[:2]),'UNRESOLVED')

if __name__ == '__main__': unittest.main()
