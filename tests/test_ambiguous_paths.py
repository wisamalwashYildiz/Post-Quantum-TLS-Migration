import sys, unittest
from pathlib import Path
sys.path.insert(0,str(Path(__file__).resolve().parents[1]/'src'))
from ambiguous_paths import *

class CorrelationTests(unittest.TestCase):
    def test_full(self):
        r=evaluate([(H,H),(H,H)],[H,C],[[0],[1]])
        self.assertEqual(r['joint'],['SATISFIED','VIOLATED'])
    def test_joint_only(self):
        r=evaluate([(H,H),(H,H)],[H,C],[[0,1],[1]])
        self.assertEqual(r['joint'],['SATISFIED','VIOLATED'])
        self.assertEqual(r['local'],['UNRESOLVED','VIOLATED'])
    def test_symmetry(self):
        r=evaluate([(H,H),(H,H)],[H,C],[[0,1],[0,1]])
        self.assertEqual(r['joint'],['UNRESOLVED','UNRESOLVED'])
        self.assertEqual(r['matchings'],2)
    def test_redaction(self):
        r=evaluate([(H,H),(H,H)],None,None)
        self.assertEqual(r['joint'],['UNRESOLVED','UNRESOLVED'])
    def test_conflict(self):
        r=evaluate([(H,H),(H,H)],[H,C],[[0],[0]])
        self.assertEqual(r['joint'],['INCONSISTENT','INCONSISTENT'])
    def test_end_violation(self):
        r=evaluate([(C,H),(H,H)],[H,C],[[0,1],[1]])
        self.assertEqual(r['joint'][0],'VIOLATED')
        self.assertEqual(r['local'][0],'VIOLATED')
    def test_no_false_positive_under_permutation(self):
        for mids in itertools.product((H,C), repeat=2):
            for true_ass in itertools.permutations((0,1)):
                for candidates in itertools.product(((0,), (1,), (0,1)),repeat=2):
                    if not all(true_ass[i] in candidates[i] for i in range(2)):continue
                    for ends in itertools.product(((H,H),(C,H)),repeat=2):
                        r=evaluate(ends,mids,candidates)
                        truth=[verdict([ends[i][0],mids[true_ass[i]],ends[i][1]]) for i in range(2)]
                        for i,decision in enumerate(r['joint']):
                            if decision in ('SATISFIED','VIOLATED'):self.assertEqual(decision,truth[i])

if __name__=='__main__':unittest.main()
