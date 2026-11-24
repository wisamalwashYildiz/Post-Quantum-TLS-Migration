import sys, unittest
from pathlib import Path
sys.path.insert(0,str(Path(__file__).resolve().parents[1]/'src'))
from evidence_acquisition import *
class EvidenceTests(unittest.TestCase):
    def setUp(self):
        self.windows=[{'requests':[{'route':'A','actual_groups':[HYBRID]*3},{'route':'B','actual_groups':[HYBRID, 'X25519', HYBRID]}]} for i in range(8)]
        self.acts,self.targets=actions_for(self.windows)
    def test_no_evidence_abstains(self):
        self.assertEqual(score(self.windows,(),self.acts),(0,0))
    def test_exact_never_worse(self):
        for budget in range(11):
            best=score(self.windows,select_exact(self.windows,self.acts,budget),self.acts)[0]
            self.assertGreaterEqual(best,score(self.windows,select_greedy(self.windows,self.acts,budget),self.acts)[0])
    def test_budget(self):
        for b in range(11):
            for method in (select_exact,select_greedy):
                chosen=method(self.windows,self.acts,b)
                self.assertLessEqual(sum(self.acts[k]['cost'] for k in chosen),b)
    def test_revocation_never_approves(self):
        chosen=tuple(self.acts)
        self.assertEqual(score(self.windows,chosen,self.acts,untrusted=chosen)[0],0)
    def test_untrusted_not_false_satisfied(self):
        chosen=tuple(self.acts)
        self.assertEqual(score(self.windows,chosen,self.acts)[1],0)
    def test_full_trust_oracle(self):
        self.assertEqual(score(self.windows,tuple(self.acts),self.acts)[0],16)
if __name__=='__main__':unittest.main()
