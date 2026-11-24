"""Non-destructive six-module orchestrator, each subprocess separately logged."""
import argparse,datetime,subprocess,sys,os,json,hashlib,pathlib
MODULES=[('v37','v37_multigroup_live.py'),('v38','v38_migration_trajectory.py'),('v39','v39_control_ablation.py'),('v40','v40_scaling.py'),('v41','v41_compromise_boundary.py'),('v42','v42_concurrent_freshness.py')]
def main():
 p=argparse.ArgumentParser();p.add_argument('--output-root',default='results/postquantum_extension');p.add_argument('--include-live',action='store_true');p.add_argument('--openssl',default='openssl');a=p.parse_args()
 root=pathlib.Path(a.output_root).resolve();run=root/('run_'+datetime.datetime.now(datetime.timezone.utc).strftime('%Y%m%dT%H%M%SZ'));run.mkdir(parents=True,exist_ok=False)
 rows=[];scripts=pathlib.Path(__file__).resolve().parent
 for ident,script in MODULES:
  if ident=='v37' and not a.include_live:
   rows.append({'module':ident,'status':'SKIPPED','reason':'use --include-live under root after checking README'});continue
  cmd=[sys.executable,str(scripts/script),'--out',str(run/ident)]
  if ident=='v37':cmd+=['--openssl',a.openssl]
  result=subprocess.run(cmd,capture_output=True,text=True,cwd=str(scripts),timeout=360)
  (run/(ident+'.stdout.log')).write_text(result.stdout)
  (run/(ident+'.stderr.log')).write_text(result.stderr)
  rows.append({'module':ident,'status':'PASS' if result.returncode==0 else 'FAILED','return_code':result.returncode,'script':script})
 checks={}
 for f in sorted(run.rglob('*')):
  if f.is_file():checks[str(f.relative_to(run))]=hashlib.sha256(f.read_bytes()).hexdigest()
 (run/'checksums.json').write_text(json.dumps(checks,indent=2)+'\n')
 manifest={'suite':'Six independent extensions: live heterogeneity, trajectory, ablation, scaling, compromise, freshness','run_utc':datetime.datetime.now(datetime.timezone.utc).isoformat(),'python':sys.version,'project_output':str(run),'modules':rows,'source_sha256':{s:hashlib.sha256((scripts/s).read_bytes()).hexdigest() for _,s in MODULES}}
 (run/'manifest.json').write_text(json.dumps(manifest,indent=2)+'\n')
 print(json.dumps(manifest,indent=2));sys.exit(1 if any(r['status']=='FAILED' for r in rows) else 0)
if __name__=='__main__':main()
