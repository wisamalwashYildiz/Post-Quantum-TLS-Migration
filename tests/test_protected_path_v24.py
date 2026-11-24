import copy, os, sys, unittest
from pathlib import Path
sys.path.insert(0,str(Path(__file__).resolve().parents[1]/'src'))
import protected_path_v24 as p
import session_chain_v11 as v11

def fixture(count=3, classical=False):
    rk={n:bytes([i+1])*32 for i,n in enumerate(('client',)+p.NODES)}
    wk={p.v14.witness_name(n):bytes([i+5])*32 for i,n in enumerate(p.NODES)}
    labels=['label0','label1','label2']
    groups=[v11.HYBRID,v11.CLASSIC if classical else v11.HYBRID,v11.HYBRID]
    ev=[{'group':g,'session_label':k} for g,k in zip(groups,labels)]
    txs=[];cs=[];reports={n:[] for n in p.NODES};wits={n:[] for n in p.NODES}
    for i in range(count):
        tx={'nonce':f'nonce{i}','sequence':i,'data':'abc'};h=v11.digest(tx)
        txs.append(tx);cs.append(v11.seal({'transaction_hash':h,'out':ev[0]},'client',rk))
        for j,n in enumerate(p.NODES):
            reports[n].append(v11.seal({'transaction_hash':h,'in':ev[j], 'out':ev[j+1] if j<2 else None,
                'target':p.NODES[j+1] if j<2 else None,'sequence':i},n,rk))
            wits[n].append(v11.seal({'transaction_hash':h,'in':ev[j],'sequence':i},p.v14.witness_name(n),wk))
    return {'transactions':txs,'clients':cs,'reports':reports,'witnesses':wits},rk,wk

class V24Tests(unittest.TestCase):
    def test_hybrid(self):
        b,r,w=fixture();self.assertEqual(p.verify_batch(b,r,w)[0],'SATISFIED')
    def test_classical(self):
        b,r,w=fixture(classical=True);self.assertEqual(p.verify_batch(b,r,w)[0],'VIOLATED')
    def test_forged_baseline(self):
        b,r,w=fixture(classical=True);b=p.forge_middle(b,r)
        self.assertEqual(p.report_only(b,r),'SATISFIED')
        self.assertEqual(p.verify_batch(b,r,w)[0],'INVALID')
    def test_forgery_preserves_witness(self):
        b,r,w=fixture(classical=True);original=copy.deepcopy(b['witnesses']);p.forge_middle(b,r)
        self.assertEqual(b['witnesses'],original)
    def test_missing_witness(self):
        b,r,w=fixture();b['witnesses']['service-a'].pop();self.assertEqual(p.verify_batch(b,r,w)[0],'UNRESOLVED')
    def test_swapped_witness(self):
        b,r,w=fixture();a=b['witnesses']['service-a'];a[0],a[1]=a[1],a[0]
        self.assertEqual(p.verify_batch(b,r,w)[0],'INVALID')
    def test_replay(self):
        b,r,w=fixture();b['transactions'][1]=copy.deepcopy(b['transactions'][0]);self.assertEqual(p.verify_batch(b,r,w)[0],'INVALID')
    def test_wrong_key(self):
        b,r,w=fixture();w[p.v14.witness_name('backend')]=b'! '*16
        self.assertEqual(p.verify_batch(b,r,w)[0],'INVALID')
    def test_session_reassignment(self):
        b,r,w=fixture();n='service-a';wb=copy.deepcopy(b['witnesses'][n][1]['body']);wb['in']['session_label']='other'
        b['witnesses'][n][1]=v11.seal(wb,p.v14.witness_name(n),w)
        self.assertEqual(p.verify_batch(b,r,w)[0],'INVALID')
    def test_empty_abstains(self):
        b,r,w=fixture();b['transactions']=[];self.assertEqual(p.verify_batch(b,r,w)[0],'UNRESOLVED')

if __name__=='__main__':unittest.main()
