import copy,os,sys,unittest
sys.path.insert(0,os.path.join(os.path.dirname(__file__),'..','src'))
import isolated_observer_v13 as m
import session_chain_v11 as v
class V13Tests(unittest.TestCase):
    def setUp(self):
        self.t=[{'nonce':'a'},{'nonce':'b'}]
        self.rk={m.REPORTER:b'report-secret'};self.wk={m.OBSERVER:b'observer-secret'}
        self.s={'session_label':'test-session','group':v.HYBRID}
        self.r=[v.seal({'transaction_hash':v.digest(t),'observed_tls':self.s},m.REPORTER,self.rk) for t in self.t]
        self.w=[v.seal({'transaction_hash':v.digest(t),'observed_tls':self.s,'sequence':i},m.OBSERVER,self.wk) for i,t in enumerate(self.t)]
    def chk(self,t=None,r=None,w=None,wk=None,**kw):
        return m.verify_batch(self.t if t is None else t,self.r if r is None else r,
                              self.w if w is None else w,self.rk,self.wk if wk is None else wk,**kw)[0]
    def test_hybrid(self):self.assertEqual(self.chk(),'SATISFIED')
    def test_shared_session(self):self.assertEqual(len(set(w['body']['observed_tls']['session_label'] for w in self.w)),1)
    def test_genuine_classical(self):
        r=copy.deepcopy(self.r);w=copy.deepcopy(self.w)
        for i in range(2):
            r[i]['body']['observed_tls']['group']=v.CLASSIC;r[i]=v.seal(r[i]['body'],m.REPORTER,self.rk)
            w[i]['body']['observed_tls']['group']=v.CLASSIC;w[i]=v.seal(w[i]['body'],m.OBSERVER,self.wk)
        self.assertEqual(self.chk(r=r,w=w),'VIOLATED')
        fake=m.forge_reports(r,self.rk[m.REPORTER]);self.assertEqual(m.report_only(self.t,fake,self.rk)[0],'SATISFIED')
        self.assertEqual(self.chk(r=fake,w=w),'INVALID')
    def test_missing(self):self.assertEqual(self.chk(w=self.w[:1]),'UNRESOLVED')
    def test_duplicate_nonce(self):self.assertEqual(self.chk(t=[self.t[0]]*2),'INVALID')
    def test_ledger_replay(self):self.assertEqual(self.chk(ledger={'a'}),'INVALID')
    def test_modified_witness(self):
        w=copy.deepcopy(self.w);w[0]['body']['observed_tls']['group']=v.CLASSIC
        self.assertEqual(self.chk(w=w),'INVALID')
    def test_sequence_reorder(self):
        w=copy.deepcopy(self.w);w[1]['body']['sequence']=0;w[1]=v.seal(w[1]['body'],m.OBSERVER,self.wk)
        self.assertEqual(self.chk(w=w),'INVALID')
    def test_wrong_key(self):self.assertEqual(self.chk(wk={m.OBSERVER:b'wrong'}),'INVALID')
    def test_receipt_forged_session(self):
        r=copy.deepcopy(self.r);r[1]['body']['observed_tls']['session_label']='other';r[1]=v.seal(r[1]['body'],m.REPORTER,self.rk)
        self.assertEqual(self.chk(r=r),'INVALID')
    def test_distinct_connection_in_single_batch(self):
        r=copy.deepcopy(self.r);w=copy.deepcopy(self.w)
        for item,key in ((r[1],self.rk),(w[1],self.wk)):
            item['body']['observed_tls']['session_label']='other'
            node=item['node'];item.update(v.seal(item['body'],node,key))
        self.assertEqual(self.chk(r=r,w=w),'INVALID')
if __name__=='__main__':unittest.main()
