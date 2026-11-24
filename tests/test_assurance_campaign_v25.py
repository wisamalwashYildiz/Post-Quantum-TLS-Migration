import sys, unittest
from pathlib import Path
sys.path.insert(0,str(Path(__file__).resolve().parents[1]/'src'))
import assurance_campaign_v25 as m

class CampaignTests(unittest.TestCase):
    def fixture(self):
        return {'version':'2.4','openssl':'OpenSSL 3.5.9','count_per_connection':3,
                'attacker_key_read_denied':True,
                'checks':{k:[v,'test'] if k!='forged_baseline' else v for k,v in m.EXPECTED.items()},
                'groups':{'hybrid':['X25519MLKEM768']*3,
                          'classical_middle':['X25519MLKEM768','X25519','X25519MLKEM768']},
                'limits':['trusted root host'],'SECRET_PRIVATE_KEY':'do not store'}
    def test_success(self):
        clean=m.sanitized_evidence(self.fixture(),3)
        self.assertEqual(clean['checks'],m.EXPECTED)
        self.assertNotIn('SECRET_PRIVATE_KEY',str(clean))
    def test_unexpected_evidence_version(self):
        x=self.fixture();x['version']='2.3'
        with self.assertRaises(ValueError):m.sanitized_evidence(x,3)
    def test_mismatch_count(self):
        with self.assertRaises(ValueError):m.sanitized_evidence(self.fixture(),4)
    def test_wrong_hybrid_group(self):
        x=self.fixture();x['groups']['hybrid'][1]='X25519'
        with self.assertRaises(ValueError):m.sanitized_evidence(x,3)
    def test_wrong_classical_group(self):
        x=self.fixture();x['groups']['classical_middle'][1]='X25519MLKEM768'
        with self.assertRaises(ValueError):m.sanitized_evidence(x,3)
    def test_bogus_success_disallowed(self):
        x=self.fixture();x['checks']['forged_corroborated']=['SATISFIED','unsafe']
        with self.assertRaises(ValueError):m.sanitized_evidence(x,3)
    def test_lost_witness_must_abstain(self):
        x=self.fixture();x['checks']['missing_witness']=['SATISFIED','unsafe']
        with self.assertRaises(ValueError):m.sanitized_evidence(x,3)
    def test_missing_key_denial(self):
        x=self.fixture();x['attacker_key_read_denied']=False
        with self.assertRaises(ValueError):m.sanitized_evidence(x,3)
    def test_missing_check(self):
        x=self.fixture();del x['checks']['replayed_transaction']
        with self.assertRaises(ValueError):m.sanitized_evidence(x,3)
    def test_extra_check(self):
        x=self.fixture();x['checks']['fabricated']='SATISFIED'
        with self.assertRaises(ValueError):m.sanitized_evidence(x,3)
    def test_invalid_verdict_type(self):
        with self.assertRaises(ValueError):m.verdict({})
    def test_digest(self):
        import tempfile
        with tempfile.TemporaryDirectory() as t:
            p=Path(t)/'a';p.write_bytes(b'abc')
            self.assertEqual(m.sha256(p),'ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad')
if __name__=='__main__':unittest.main()
