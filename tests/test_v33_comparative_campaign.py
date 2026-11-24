import sys, unittest
from pathlib import Path
sys.path.insert(0,str(Path(__file__).resolve().parents[1]/'src'))
import v33_comparative_campaign as m
import v32_protected_freshness as v

class ComparisonTests(unittest.TestCase):
    def test_methods(self):self.assertEqual(len(m.METHODS),3)
    def test_scenarios(self):self.assertEqual(len(m.SCENARIOS),5)
    def test_report_all_hybrid(self):self.assertEqual(m.report_only({},[v.HYBRID]*3),'SATISFIED')
    def test_report_classical(self):self.assertEqual(m.report_only({},[v.HYBRID,v.CLASSIC,v.HYBRID]),'VIOLATED')
    def test_report_missing(self):self.assertEqual(m.report_only({},[]),'UNRESOLVED')
    def test_report_unknown(self):self.assertEqual(m.report_only({},[v.HYBRID,'?',v.HYBRID]),'UNRESOLVED')
    def test_classical_forgery_detectable_by_trust(self):
        e=m.expected('classical_middle','forwarder_false_hybrid')
        self.assertEqual(e['report_only'],'SATISFIED');self.assertEqual(e['protected_fresh'],'VIOLATED')
    def test_missing_abstains(self):self.assertEqual(m.expected('hybrid','missing_receiver')['protected_fresh'],'UNRESOLVED')
    def test_replay_differs_signed(self):
        e=m.expected('hybrid','copied_new_challenge')
        self.assertEqual(e['signed_receiver'],'SATISFIED');self.assertEqual(e['protected_fresh'],'INVALID')
    def test_unsigned_edit(self):self.assertEqual(m.expected('classical_middle','receiver_edit')['signed_receiver'],'INVALID')
    def test_no_false_hybrid_approval_by_protected_in_fixed_matrix(self):
        for attack in m.SCENARIOS:
            self.assertNotEqual(m.expected('classical_middle',attack)['protected_fresh'],'SATISFIED')
    def test_unknown_attack(self):
        with self.assertRaises(KeyError):m.expected('hybrid','unknown')
if __name__=='__main__':unittest.main()
