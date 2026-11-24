import sys,unittest
from pathlib import Path
sys.path.insert(0,str(Path(__file__).resolve().parents[1]/'src'))
from trust_cut_v22 import HYBRID,CLASSIC,assess,minimal_trust_sets,audit_from_v21
class V22Tests(unittest.TestCase):
 def test_untrusted_signed_hybrid_not_sufficient(self):self.assertEqual(assess([HYBRID]*3)['verdict'],'UNRESOLVED')
 def test_trusted_full_path(self):self.assertEqual(assess([HYBRID]*3,(0,1,2))['verdict'],'SATISFIED')
 def test_partial_path(self):self.assertEqual(assess([HYBRID]*3,(0,2))['verdict'],'UNRESOLVED')
 def test_honest_classical_violation(self):self.assertEqual(assess([HYBRID,CLASSIC,HYBRID],(1,))['verdict'],'VIOLATED')
 def test_untrusted_classical_not_proven(self):self.assertEqual(assess([HYBRID,CLASSIC,HYBRID])['verdict'],'UNRESOLVED')
 def test_eight_possible_worlds(self):self.assertEqual(assess([HYBRID]*3)['possible_worlds'],8)
 def test_one_world_with_full_trust(self):self.assertEqual(assess([HYBRID]*3,(0,1,2))['possible_worlds'],1)
 def test_minimal_trust_set(self):self.assertEqual(minimal_trust_sets([HYBRID]*3),[(0,1,2)])
 def test_single_classical_cut(self):self.assertEqual(minimal_trust_sets([HYBRID,CLASSIC,HYBRID],'VIOLATED'),[(1,)])
 def test_invalid_trust_index(self):
  with self.assertRaises(ValueError):assess([HYBRID],(2,))
 def test_v21_negative_control(self):
  x=audit_from_v21({'checks':{'dishonest_signers_limitation':['ATTESTED','']}})
  self.assertEqual(x['by_trusted_receivers']['none']['verdict'],'UNRESOLVED')
 def test_no_evidence(self):self.assertEqual(assess([])['verdict'],'UNRESOLVED')
if __name__=='__main__':unittest.main()
