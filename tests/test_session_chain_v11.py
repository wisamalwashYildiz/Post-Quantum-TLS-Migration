import copy, os, sys, unittest
sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..', 'src'))
from session_chain_v11 import seal, verify_chain, HYBRID, CLASSIC

class SessionChainTests(unittest.TestCase):
    def setUp(self):
        self.keys={n:(n+'key').encode() for n in ('client','gateway','service-a','backend')}
        self.tx={'nonce':'n1'}
        from session_chain_v11 import digest
        h=digest(self.tx)
        self.client=seal({'transaction_hash':h, 'out':{'session_label':'s1','group':HYBRID}},'client',self.keys)
        self.receipts=[]
        for node,inc,out,target in [('gateway','s1','s2','service-a'),('service-a','s2','s3','backend'),('backend','s3',None,None)]:
            self.receipts.append(seal({'transaction_hash':h,'in':{'session_label':inc,'group':HYBRID},'out':{'session_label':out,'group':HYBRID} if out else None,'target':target},node,self.keys))

    def verdict(self, receipts=None, tx=None, client=None):
        return verify_chain(tx or self.tx, client or self.client, receipts if receipts is not None else self.receipts, self.keys)[0]

    def test_valid(self): self.assertEqual(self.verdict(),'SATISFIED')
    def test_missing(self): self.assertEqual(self.verdict(self.receipts[:2]),'UNRESOLVED')
    def test_mutated_payload(self):
        x=copy.deepcopy(self.receipts); x[1]['body']['in']['session_label']='wrong'
        self.assertEqual(self.verdict(x),'INVALID')
    def test_reseal_but_wrong_session(self):
        x=copy.deepcopy(self.receipts);x[1]['body']['in']['session_label']='wrong'
        x[1]=seal(x[1]['body'],'service-a',self.keys)
        self.assertEqual(self.verdict(x),'INVALID')
    def test_classical(self):
        x=copy.deepcopy(self.receipts);x[1]['body']['in']['group']=CLASSIC
        x[1]=seal(x[1]['body'],'service-a',self.keys)
        self.assertEqual(self.verdict(x),'INVALID') # mismatch with upstream group's signed metadata
    def test_nonce_replay_rejected_for_new_tx(self): self.assertEqual(self.verdict(tx={'nonce':'n2'}),'INVALID')
    def test_duplicate(self): self.assertEqual(self.verdict([self.receipts[0]]*3),'INVALID')
    def test_wrong_target(self):
        x=copy.deepcopy(self.receipts);x[0]['body']['target']='wrong'
        x[0]=seal(x[0]['body'],'gateway',self.keys)
        self.assertEqual(self.verdict(x),'INVALID')

if __name__=='__main__': unittest.main()
