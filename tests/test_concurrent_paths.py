import sys, unittest
from pathlib import Path
sys.path.insert(0,str(Path(__file__).resolve().parents[1]/'src'))
import concurrent_paths as c

class PathTests(unittest.TestCase):
    def test_conservative_unknown(self):
        self.assertEqual(c.verdict([c.H,None,c.H]),'UNRESOLVED')
    def test_confirmed_violation_even_with_unknown(self):
        self.assertEqual(c.verdict([c.H,None,c.C]),'VIOLATED')
    def test_unknown_value_never_approves(self):
        self.assertEqual(c.verdict([c.H,'UNRECOGNIZED',c.H]),'UNRESOLVED')
    def test_mask_deterministic(self):
        self.assertEqual(c.mask_for(42017,'r1','gateway',.5),c.mask_for(42017,'r1','gateway',.5))
    def test_dropout_limits(self):
        self.assertTrue(c.mask_for(42017,'r1','gateway',0))
        self.assertFalse(c.mask_for(42017,'r1','gateway',1))
    def test_summary_counts(self):
        cases={'a':[{'ground_truth':'SATISFIED','evidence':[{'dropout':0.0,'verdict':'SATISFIED','edge_only':'SATISFIED','conservative_per_hop':'SATISFIED','full_per_hop':'SATISFIED'}]}]}
        for row in c.summarize(cases,(0.0,)):
            self.assertEqual((row['n'],row['correct'],row['incorrect'],row['unresolved']),(1,1,0,0))
if __name__=='__main__':unittest.main()
