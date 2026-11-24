#!/usr/bin/env python3
"""Unprivileged runner for v2.6. Root holds temporary TLS files; user archives allowlisted sanitized output."""
import argparse, hashlib, json, os, shutil, subprocess, sys, uuid
from datetime import datetime, timezone
from pathlib import Path

def main():
 p=argparse.ArgumentParser()
 p.add_argument('--python',required=True);p.add_argument('--openssl',required=True)
 p.add_argument('--archive',default='results/evidence_recovery_v26')
 p.add_argument('--trials',type=int,default=3);p.add_argument('--count',type=int,default=3)
 p.add_argument('--attacker-user',default='nobody');p.add_argument('--skip-tests',action='store_true')
 a=p.parse_args()
 if os.geteuid()==0:raise SystemExit('Run this launcher as normal user; sudo will be requested for live TLS')
 target=Path(a.archive).resolve();target.mkdir(parents=True,exist_ok=True)
 tag=datetime.now(timezone.utc).strftime('%Y%m%dT%H%M%SZ')+'_'+uuid.uuid4().hex[:8]
 dest=target/('campaign_'+tag);dest.mkdir()
 def write_json(path,data):path.write_text(json.dumps(data,indent=2,sort_keys=True)+'\n')
 meta={'schema':'pqc-v26-launcher','campaign_id':tag,'status':'STARTED','trials_requested':a.trials,
       'transactions_per_connection':a.count,'source_program':'src/evidence_recovery_v26.py',
       'limits':['protected root runtime is separate from public project archive',
                 'receipt recovery is a root-trusted in-memory escrow simulation; no independent root trust domains']}
 write_json(dest/'run_manifest.json',meta)
 if not a.skip_tests:
  t=subprocess.run([a.python,'-m','unittest','discover','-s','tests','-p','test_*.py','-v'],capture_output=True,text=True)
  (dest/'test_results.txt').write_text(t.stdout+t.stderr)
  if t.returncode:
   meta['status']='FAILED_TESTS';write_json(dest/'run_manifest.json',meta)
   raise SystemExit('Tests failed: '+str(dest/'test_results.txt'))
 auth=subprocess.run(['sudo','-v'])
 if auth.returncode:raise SystemExit('sudo authentication failed')
 protected='/var/tmp/pqc-v26-'+tag
 try:
  run=[ 'sudo','env','LD_LIBRARY_PATH='+os.environ.get('LD_LIBRARY_PATH',''),a.python,
        str(Path(__file__).with_name('evidence_recovery_v26.py').resolve()),
        '--openssl',a.openssl,'--archive',protected,'--trials',str(a.trials),'--count',str(a.count),
        '--attacker-user',a.attacker_user]
  proc=subprocess.run(run,capture_output=True,text=True)
  (dest/'experiment.log').write_text(proc.stdout+proc.stderr)
  meta['root_runner_exit_code']=proc.returncode
  # The root recorder writes sanitized JSON and aggregate CSV but no secret keys.
  folders=subprocess.run(['sudo','find',protected,'-mindepth','1','-maxdepth','1','-type','d','-name','recovery_*'],capture_output=True,text=True)
  paths=[v for v in folders.stdout.splitlines() if v.startswith(protected+'/recovery_')]
  if len(paths)!=1:raise RuntimeError('Expected exactly one root campaign folder, got '+repr(paths))
  source=paths[0]
  names=subprocess.run(['sudo','find',source,'-maxdepth','1','-type','f','-printf','%f\n'],capture_output=True,text=True)
  files=[f for f in names.stdout.splitlines() if f]
  allow={'manifest.json','summary.csv','checksums.sha256'}|{'trial_%03d.json'%i for i in range(1,a.trials+1)}
  if set(files)!=allow:raise RuntimeError('Unexpected/missing public outputs: '+repr(set(files)^allow))
  for name in sorted(files):
   r=subprocess.run(['sudo','cat',source+'/'+name],capture_output=True)
   if r.returncode:raise RuntimeError('Cannot read '+name)
   (dest/name).write_bytes(r.stdout)
  # Verify copied outputs against source's checksum manifest.
  lines=(dest/'checksums.sha256').read_text().splitlines()
  checked=set()
  for line in lines:
   digest,name=line.split('  ',1)
   if name not in allow or name=='checksums.sha256':raise RuntimeError('Invalid checksum reference')
   if hashlib.sha256((dest/name).read_bytes()).hexdigest()!=digest:raise RuntimeError('Checksum mismatch: '+name)
   checked.add(name)
  if checked != allow-{'checksums.sha256'}:raise RuntimeError('Incomplete checksum coverage')
  results=json.loads((dest/'manifest.json').read_text())
  if results.get('successes')!=a.trials or results.get('failures')!=0:raise RuntimeError('Incomplete / failing live trials')
  if proc.returncode:raise RuntimeError('Live experiment failed')
  meta['status']='PASS';meta['checksums_verified']=len(checked)
  print('PASS:',a.trials,'live trials; archived to',dest)
 except Exception as exc:
  meta['status']='FAILED';meta['error']=repr(exc)
  print('FAILED:',repr(exc),'archive:',dest,file=sys.stderr)
  raise SystemExit(2)
 finally:
  write_json(dest/'run_manifest.json',meta)
  # Retain native root files for forensic diagnostics; no silent deletion.
  print('Protected temporary results:',protected)
if __name__=='__main__':main()
