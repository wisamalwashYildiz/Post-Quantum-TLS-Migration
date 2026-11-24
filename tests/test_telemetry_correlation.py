import sys, unittest
from pathlib import Path
sys.path.insert(0,str(Path(__file__).resolve().parents[1]/'src'))
from telemetry_correlation import evaluate, max_matching, feasible_edges, edges_from_metadata, build_pair

class V09Tests(unittest.TestCase):
    def setUp(self):
        self.requests=[{'route':'A','path_prefix':('client','gateway'),'front_group':'X25519MLKEM768','back_group':'X25519MLKEM768'},
                       {'route':'B','path_prefix':('client','gateway'),'front_group':'X25519MLKEM768','back_group':'X25519MLKEM768'}]
        self.receipts=[{'route':'A','path_prefix':('client','gateway'),'group':'X25519MLKEM768'},
                       {'route':'B','path_prefix':('client','gateway'),'group':'X25519'}]
    def test_route_metadata_edges(self):
        self.assertEqual(edges_from_metadata(self.requests,self.receipts),[[0],[1]])
    def test_full(self):
        self.assertEqual(evaluate(self.requests,self.receipts)['joint'],['SATISFIED','VIOLATED'])
    def test_partial(self):
        self.requests[0]['route']=None
        r=evaluate(self.requests,self.receipts)
        self.assertEqual(r['joint'],['SATISFIED','VIOLATED'])
        self.assertEqual(r['local'],['UNRESOLVED','VIOLATED'])
    def test_ambiguity(self):
        for m in self.requests+self.receipts:m['route']=None
        self.assertEqual(evaluate(self.requests,self.receipts)['joint'],['UNRESOLVED']*2)
    def test_open_window(self):
        self.assertEqual(evaluate(self.requests,self.receipts,closed=False)['joint'],['UNRESOLVED']*2)
    def test_missing_middle(self):
        self.assertEqual(evaluate(self.requests,self.receipts[1:],closed=False)['joint'],['UNRESOLVED']*2)
    def test_inconsistency(self):
        self.receipts[1]['route']='A'
        self.assertEqual(evaluate(self.requests,self.receipts)['joint'],['INCONSISTENT']*2)
    def test_all_different(self):
        self.assertEqual(feasible_edges([[0,1],[1]],2,closed=True),[[0],[1]])
    def test_max_matching(self):
        self.assertEqual(max_matching([[0,1],[1],[0,2]],3),3)
    def test_scalability_closed(self):
        n=40
        edges=[list(range(n)) for _ in range(n)]
        self.assertEqual(max_matching(edges,n),n)
    def test_no_truth_used_in_correlation(self):
        self.assertEqual(edges_from_metadata(self.requests,self.receipts),[[0],[1]])
        self.receipts[0]['group']='X25519'
        self.assertEqual(edges_from_metadata(self.requests,self.receipts),[[0],[1]])

if __name__=='__main__':unittest.main()
