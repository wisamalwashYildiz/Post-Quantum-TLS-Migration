import copy, pathlib, sys, unittest
sys.path.insert(0,str(pathlib.Path(__file__).resolve().parents[1]/'src'))
import multihop_witness_v14 as v
import session_chain_v11 as old

class MultiHopTests(unittest.TestCase):
    def setUp(self):
        self.rk={k:(k*40).encode()[:32] for k in ('client',)+v.NODES}
        self.wk={v.witness_name(k):(k*40).encode()[:32] for k in v.NODES}
        self.tx={'nonce':'unique-test-nonce','data':'payload'}
        labels=[{'group':old.HYBRID,'session_label':str(i)*64} for i in range(3)]
        self.client=old.seal({'transaction_hash':old.digest(self.tx),'out':labels[0]},'client',self.rk)
        self.reports=[];self.witnesses=[]
        for i,name in enumerate(v.NODES):
            h=old.digest(self.tx);ss=copy.deepcopy(labels[i]);nxt=copy.deepcopy(labels[i+1]) if i<2 else None
            self.reports.append(old.seal({'transaction_hash':h,'in':ss,'out':nxt,
                         'target':v.NODES[i+1] if i<2 else None},name,self.rk))
            self.witnesses.append(old.seal({'transaction_hash':h,'in':ss},v.witness_name(name),self.wk))
    def result(self,tx=None,client=None,reports=None,witnesses=None,**kwargs):
        return v.verify(tx or self.tx, client or self.client, self.reports if reports is None else reports,
                        self.witnesses if witnesses is None else witnesses,self.rk,self.wk,**kwargs)[0]
    def test_valid(self):self.assertEqual(self.result(),'SATISFIED')
    def test_classical(self):
        r=copy.deepcopy(self.reports);w=copy.deepcopy(self.witnesses)
        for i,k in [(0,'out'),(1,'in')]:
            b=r[i]['body'];b[k]['group']=old.CLASSIC;r[i]=old.seal(b,v.NODES[i],self.rk)
        b=w[1]['body'];b['in']['group']=old.CLASSIC;w[1]=old.seal(b,v.witness_name(v.NODES[1]),self.wk)
        self.assertEqual(self.result(reports=r,witnesses=w),'VIOLATED')
    def test_forged_both_reports(self):
        r=copy.deepcopy(self.reports);w=copy.deepcopy(self.witnesses)
        b=w[1]['body'];b['in']['group']=old.CLASSIC;w[1]=old.seal(b,v.witness_name(v.NODES[1]),self.wk)
        self.assertEqual(self.result(reports=r,witnesses=w),'INVALID')
        self.assertEqual(old.verify_chain(self.tx,self.client,r,self.rk)[0],'SATISFIED')
    def test_missing(self):self.assertEqual(self.result(witnesses=self.witnesses[:2]),'UNRESOLVED')
    def test_mac_modified(self):
        w=copy.deepcopy(self.witnesses);w[1]['body']['in']['group']=old.CLASSIC
        self.assertEqual(self.result(witnesses=w),'INVALID')
    def test_transaction_reassign(self):
        w=copy.deepcopy(self.witnesses);b=w[1]['body'];b['transaction_hash']='0'*64
        w[1]=old.seal(b,v.witness_name(v.NODES[1]),self.wk)
        self.assertEqual(self.result(witnesses=w),'INVALID')
    def test_replay_ledger(self):self.assertEqual(self.result(ledger={self.tx['nonce']}),'INVALID')
    def test_bad_target(self):
        r=copy.deepcopy(self.reports);b=r[0]['body'];b['target']='other';r[0]=old.seal(b,v.NODES[0],self.rk)
        self.assertEqual(self.result(reports=r),'INVALID')
    def test_unrecognized_group(self):
        r=copy.deepcopy(self.reports);w=copy.deepcopy(self.witnesses)
        for i in [0]:
            b=r[i]['body'];b['in']['group']='UNKNOWN';r[i]=old.seal(b,v.NODES[i],self.rk)
            b=w[i]['body'];b['in']['group']='UNKNOWN';w[i]=old.seal(b,v.witness_name(v.NODES[i]),self.wk)
        b=self.client['body'].copy();b['out']=copy.deepcopy(b['out']);b['out']['group']='UNKNOWN'
        cl=old.seal(b,'client',self.rk)
        self.assertEqual(self.result(client=cl,reports=r,witnesses=w),'UNRESOLVED')

if __name__=='__main__':unittest.main()

class AttackCopyTests(unittest.TestCase):
    setUp=MultiHopTests.setUp
    result=MultiHopTests.result
    def test_forging_does_not_mutate_receiver_witness(self):
        case={'transaction':self.tx,'client':self.client,
              'reports':copy.deepcopy(self.reports),'witnesses':copy.deepcopy(self.witnesses)}
        # Force aliasing like payloads returned by one relay process.
        case['reports'][1]['body']['in']=case['witnesses'][1]['body']['in']
        case['reports'][0]['body']['out']['group']=old.CLASSIC
        case['reports'][1]['body']['in']['group']=old.CLASSIC
        case['witnesses'][1]=old.seal(case['witnesses'][1]['body'],v.witness_name(v.NODES[1]),self.wk)
        for i in (0,1):case['reports'][i]=old.seal(case['reports'][i]['body'],v.NODES[i],self.rk)
        forged=v.forge_middle(case,self.rk)
        self.assertEqual(forged['witnesses'][1]['body']['in']['group'],old.CLASSIC)
        self.assertEqual(v.baseline(forged,self.rk)[0],'SATISFIED')
        self.assertEqual(self.result(reports=forged['reports'],witnesses=forged['witnesses']),'INVALID')
