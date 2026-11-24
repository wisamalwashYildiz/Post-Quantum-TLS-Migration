#!/usr/bin/env python3
"""User-owned archival wrapper for privileged v3.2 laboratory execution."""
import argparse, hashlib, io, json, os, pathlib, subprocess, sys, tarfile, uuid
from datetime import datetime,timezone

def run(args):
    if os.geteuid()==0:raise SystemExit('Run launcher as normal user, NOT with sudo')
    archive=pathlib.Path(args.archive).resolve()
    target=archive/('campaign_'+datetime.now(timezone.utc).strftime('%Y%m%dT%H%M%SZ')+'_'+uuid.uuid4().hex[:8])
    target.mkdir(parents=True,exist_ok=False)
    log=target/'experiment.log'
    privileged=None
    try:
        # OpenSSH/sudo permits interactive authentication when terminal is attached.
        mk=subprocess.run(['sudo','mktemp','-d','/var/tmp/pqc-v32-public.XXXXXXXX'],capture_output=True,text=True,check=True)
        privileged=mk.stdout.strip()
        subprocess.run(['sudo','chmod','700',privileged],check=True)
        cmd=['sudo','env','OPENSSL_CONF='+os.environ.get('OPENSSL_CONF','/etc/ssl/openssl.cnf'),
             'LD_LIBRARY_PATH='+os.environ.get('LD_LIBRARY_PATH',''),args.python,
             str(pathlib.Path(__file__).with_name('v32_protected_freshness.py')),
             '--openssl',args.openssl,'--archive',privileged,'--trials',str(args.trials),'--count',str(args.count)]
        proc=subprocess.run(cmd,capture_output=True,text=True)
        log.write_text('stdout:\n'+proc.stdout+'\nstderr:\n'+proc.stderr+'\n')
        print(proc.stdout,flush=True)
        if proc.returncode:print('Privileged experiment returned',proc.returncode,flush=True)
        # Tar is generated only from trusted root-owned research output.
        tar=subprocess.run(['sudo','tar','-C',privileged,'-cf','-','.'],capture_output=True)
        if tar.returncode:raise RuntimeError('archival export failed: '+tar.stderr.decode(errors='replace'))
        with tarfile.open(fileobj=io.BytesIO(tar.stdout),mode='r:') as tf:
            entries=tf.getmembers()
            for ent in entries:
                if not ent.isfile() and not ent.isdir():raise RuntimeError('unexpected archive entry type')
                p=pathlib.PurePosixPath(ent.name)
                if p.is_absolute() or '..' in p.parts:raise RuntimeError('unsafe archive path')
            tf.extractall(target,filter='data')
        all_runs=list(target.glob('gate_*/manifest.json'))
        if len(all_runs)!=1:raise RuntimeError('expected exactly one run manifest')
        run=all_runs[0].parent
        checks=(run/'checksums.sha256').read_text().splitlines()
        for line in checks:
            sha,name=line.split('  ',1)
            if hashlib.sha256((run/name).read_bytes()).hexdigest()!=sha:
                raise RuntimeError('checksum verification failure: '+name)
        manifest=json.loads((run/'manifest.json').read_text())
        (target/'launcher_manifest.json').write_text(json.dumps({
            'status':'PASS' if proc.returncode==0 else 'FAIL',
            'native_run':str(run.relative_to(target)),
            'checksums_verified':len(checks),
            'trials_requested':args.trials,
            'root_runner_exit_code':proc.returncode},indent=2)+'\n')
        print('ARCHIVED:',target,flush=True)
        if proc.returncode:raise SystemExit('Live experiment failed. Evidence retained at '+str(target))
        return target
    finally:
        if privileged:
            subprocess.run(['sudo','rm','-rf','--',privileged],check=False)

def main():
    ap=argparse.ArgumentParser()
    ap.add_argument('--python',required=True);ap.add_argument('--openssl',required=True)
    ap.add_argument('--archive',default='results/v32_protected_freshness')
    ap.add_argument('--trials',type=int,default=3);ap.add_argument('--count',type=int,default=3)
    args=ap.parse_args()
    if not 1<=args.trials<=20 or not 2<=args.count<=30:ap.error('invalid trials/count')
    run(args)
if __name__=='__main__':main()
