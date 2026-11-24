import sys
import unittest
from pathlib import Path
sys.path.insert(0, str(Path(__file__).resolve().parents[1] / 'src'))
from session_evidence import decode_server_hello, GROUP_CODES

class TestSessionEvidence(unittest.TestCase):
    def make_hello(self, group):
        body=b'\x03\x03'+b'\x00'*32+b'\x00'+b'\x13\x01'+b'\x00'
        keyshare=(51).to_bytes(2,'big')+(2).to_bytes(2,'big')+group.to_bytes(2,'big')
        body+=len(keyshare).to_bytes(2,'big')+keyshare
        return b'\x02'+len(body).to_bytes(3,'big')+body
    def test_classic(self):
        self.assertEqual(decode_server_hello(self.make_hello(0x001d)), 'X25519')
    def test_hybrid(self):
        self.assertEqual(decode_server_hello(self.make_hello(0x11ec)), 'X25519MLKEM768')
    def test_unknown_is_not_accepted_as_hybrid(self):
        self.assertEqual(decode_server_hello(self.make_hello(0x9999)), 'UNKNOWN_0x9999')
    def test_truncated(self):
        self.assertIsNone(decode_server_hello(b'\x02\x00\x00'))
    def test_no_keyshare(self):
        data=self.make_hello(0x001d).replace(b'\x003',b'\x00\x2b',1)
        self.assertIsNone(decode_server_hello(data))

if __name__=='__main__':unittest.main()
