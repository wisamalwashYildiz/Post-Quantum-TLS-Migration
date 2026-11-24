import unittest,tempfile,pathlib,csv,json,hashlib,sys
sys.path.insert(0,str(pathlib.Path(__file__).resolve().parents[1]/'src'))
from v34_independent_audit import audit,METHODS,ATTACKS,SCENARIOS
class AuditTests(unittest.TestCase):
 def build(self,root):
  rows=[]
  for sc in SCENARIOS:
   for attack in ATTACKS:
    for m in METHODS: rows.append({'trial':'1','tls_scenario':sc,'intervention':attack,'method':m,'verdict':'INVALID','expected':'INVALID','expected_match':'True','verification_bundle_ns':'10','intervention_mode':'offline_after_live_tls'})
  with (root/'paired_verdicts.csv').open('w',newline='') as f:
   w=csv.DictWriter(f,fieldnames=list(rows[0]));w.writeheader();w.writerows(rows)
  (root/'live_sessions.json').write_text(json.dumps([{'status':'PASS'}]*2))
  t={m:{'n':10,'false_hybrid_approvals':0,'invalid':10,'unresolved':0} for m in METHODS}
  (root/'manifest.json').write_text(json.dumps({'trials_requested':1,'schema':'pqc-v33-paired-comparison','tallies':t}))
  (root/'checksums.sha256').write_text(''.join(hashlib.sha256((root/n).read_bytes()).hexdigest()+'  '+n+'\n' for n in ['paired_verdicts.csv','live_sessions.json','manifest.json']))
 def test_valid(self):
  with tempfile.TemporaryDirectory() as d:
   p=pathlib.Path(d);self.build(p);self.assertEqual(audit(p)['integrity'],'PASS')
 def test_tamper_detected(self):
  with tempfile.TemporaryDirectory() as d:
   p=pathlib.Path(d);self.build(p);(p/'live_sessions.json').write_text('[]');self.assertEqual(audit(p)['integrity'],'FAIL')
 def test_missing_pair_detected(self):
  with tempfile.TemporaryDirectory() as d:
   p=pathlib.Path(d);self.build(p);rows=(p/'paired_verdicts.csv').read_text().splitlines();(p/'paired_verdicts.csv').write_text('\n'.join(rows[:-1])+'\n');self.assertEqual(audit(p)['integrity'],'FAIL')
if __name__=='__main__':unittest.main()
