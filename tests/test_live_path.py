import sys
import unittest
from pathlib import Path
sys.path.insert(0, str(Path(__file__).resolve().parents[1] / 'src'))
from live_path import verdict, CLASSIC, HYBRID, context_client

class PolicyTests(unittest.TestCase):
    def test_all_hybrid(self):
        self.assertEqual(verdict([HYBRID]*3), 'SATISFIED')
    def test_classical_middle(self):
        self.assertEqual(verdict([HYBRID,CLASSIC,HYBRID]), 'VIOLATED')
    def test_missing_hybrid(self):
        self.assertEqual(verdict([HYBRID,None,HYBRID]), 'UNRESOLVED')
    def test_violation_overrides_missing(self):
        self.assertEqual(verdict([None,CLASSIC,HYBRID]), 'VIOLATED')
    def test_classical_client_context(self):
        self.assertIsNotNone(context_client(True))

if __name__ == '__main__':
    unittest.main()
