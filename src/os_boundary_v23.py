#!/usr/bin/env python3
"""v2.3 Linux OS-UID boundary lab. Run only as root in dedicated WSL lab.

TLS receiver is root-owned, untrusted forwarder runs as an unprivileged UID.
Receiver observes actual TLS1.3 group with CPython handshake callbacks and
signs its own observation. Root orchestrator is TRUSTED. Not host/root security.
This is a one-leg isolation experiment; do NOT claim multi-hop assurance.
"""
import argparse, copy, json, os, pwd, secrets, socket, ssl, subprocess, sys, tempfile, time
from pathlib import Path
try:
 import live_path as lp
 import session_chain_v11 as v11
except ImportError:
 from . import live_path as lp
 from . import session_chain_v11 as v11

NODE='receiver:protected'
REPORTER='forwarder'

def receiver(cert,priv,obs_key,count,classic,ready,results):
    ctx,tracker=v11.tls_context(cert=str(cert),key=str(priv),classic=classic)
    with socket.socket() as listener:
        listener.bind(('127.0.0.1',0));listener.listen(1);listener.settimeout(20)
        ready.write_text(str(listener.getsockname()[1]))
        raw,_=listener.accept();raw.settimeout(15)
        with ctx.wrap_socket(raw,server_side=True) as tls:
            ev=tracker.evidence(tls)
            records=[]
            for i in range(count):
                tx=lp.read_json(tls)
                if tx.get('sequence')!=i or not isinstance(tx.get('nonce'),str):raise ValueError('malformed application sequence')
                records.append(v11.seal({'transaction_hash':v11.digest(tx),'observed_tls':ev,'sequence':i},NODE,{NODE:obs_key}))
                lp.send_json(tls,{'ack':i,'hash':v11.digest(tx)})
            tracker.forget(tls)
    results.write_text(json.dumps(records))

def attacker_client(port,count,report_key,case,output):
    ctx,tracker=v11.tls_context(client=True,classic=case=='classical')
    with socket.create_connection(('127.0.0.1',port),timeout=15) as raw:
        with ctx.wrap_socket(raw,server_hostname='localhost') as tls:
            observed=tracker.evidence(tls)
            txs=[]; reports=[]
            for i in range(count):
                tx={'nonce':secrets.token_hex(16),'sequence':i,'data':f'v2.3 {case} {i}'}
                txs.append(tx);lp.send_json(tls,tx)
                ack=lp.read_json(tls)
                if ack!={'ack':i,'hash':v11.digest(tx)}:raise RuntimeError('unexpected ack')
                claimed=copy.deepcopy(observed)
                if case=='classical':claimed['group']=v11.HYBRID
                reports.append(v11.seal({'transaction_hash':v11.digest(tx),'observed_tls':claimed},REPORTER,{REPORTER:report_key}))
            tracker.forget(tls)
    output.write_text(json.dumps({'transactions':txs,'reports':reports}))

def verify(txs,reports,wits,rkey,okey):
    if len(txs)!=len(reports) or len(txs)!=len(wits):return 'UNRESOLVED'
    if not txs:return 'UNRESOLVED'
    seen=set(); groups=[]; labels=set()
    for i,(tx,rep,wit) in enumerate(zip(txs,reports,wits)):
        if tx.get('nonce') in seen:return 'INVALID'
        seen.add(tx.get('nonce'))
        if not v11.verify_seal(rep,{REPORTER:rkey}) or not v11.verify_seal(wit,{NODE:okey}):return 'INVALID'
        if rep.get('node')!=REPORTER or wit.get('node')!=NODE:return 'INVALID'
        if wit['body'].get('sequence')!=i:return 'INVALID'
        if rep['body'].get('transaction_hash')!=v11.digest(tx) or wit['body'].get('transaction_hash')!=v11.digest(tx):return 'INVALID'
        if rep['body'].get('observed_tls')!=wit['body'].get('observed_tls'):return 'INVALID'
        obs=wit['body']['observed_tls'];groups.append(obs.get('group'));labels.add(obs.get('session_label'))
    if len(labels)!=1:return 'INVALID'
    if v11.CLASSIC in groups:return 'VIOLATED'
    if all(x==v11.HYBRID for x in groups):return 'SATISFIED'
    return 'UNRESOLVED'

def drop(uid,gid):
    def change():
        os.setgroups([]);os.setgid(gid);os.setuid(uid)
    return change

def run(output,count,openssl,attacker_name):
    if os.geteuid()!=0:raise RuntimeError('OS ISOLATION NOT TESTED: run through sudo with deliberate approval')
    user=pwd.getpwnam(attacker_name)
    if user.pw_uid==0:raise RuntimeError('attacker user must be unprivileged')
    if ssl.OPENSSL_VERSION_INFO[:2]<(3,5):raise RuntimeError('Python OpenSSL >=3.5 required')
    out=Path(output).resolve();out.mkdir(parents=True,exist_ok=True)
    if out.stat().st_uid!=0:raise RuntimeError('output directory must be root-owned')
    public={}
    with tempfile.TemporaryDirectory(prefix='pqc-v23-os-') as tmp:
        root=Path(tmp);root.chmod(0o755)
        cert,priv=lp.make_cert(root,openssl)
        os.chmod(priv,0o600)
        obs_key=secrets.token_bytes(32);report_key=secrets.token_bytes(32)
        keyfile=root/'observer.key';keyfile.write_bytes(obs_key);keyfile.chmod(0o600)
        if keyfile.stat().st_mode & 0o077:raise RuntimeError('observer secret is not private')
        for case in ('hybrid','classical'):
            ready=root/(case+'.ready'); witness=root/(case+'.witness'); attacker_out=root/(case+'.client')
            # Receiver runs as the trusted root identity, attacker only as low-privilege identity.
            receiver_proc=subprocess.Popen([sys.executable,__file__,'--worker-receiver','--cert',str(cert),'--priv',str(priv),'--obs-key',str(keyfile),'--count',str(count),'--case',case,'--ready',str(ready),'--witness',str(witness)],stdout=subprocess.PIPE,stderr=subprocess.PIPE,text=True)
            deadline=time.monotonic()+15
            while not ready.exists() and receiver_proc.poll() is None and time.monotonic()<deadline:time.sleep(.05)
            if not ready.exists():
                err=receiver_proc.communicate(timeout=3)[1];raise RuntimeError('receiver failed: '+err[-500:])
            ready.chmod(0o644)
            # Writable folder for adversary only. Private server directory and key never writable by adversary.
            attacker_dir=root/(case+'-attacker');attacker_dir.mkdir(mode=0o777);attacker_dir.chmod(0o777)
            attacker_out=attacker_dir/'reports.json'
            cmd=[sys.executable,__file__,'--worker-attacker','--attacker-user',attacker_name,'--port',ready.read_text(),'--count',str(count),'--case',case,'--report-key',report_key.hex(),'--attacker-output',str(attacker_out),'--probe-key',str(keyfile)]
            attack=subprocess.run(cmd,capture_output=True,text=True,timeout=25)
            recv_out,recv_err=receiver_proc.communicate(timeout=25)
            if attack.returncode or receiver_proc.returncode:
                raise RuntimeError('live worker failure: attacker='+attack.stderr[-500:]+' receiver='+recv_err[-500:])
            denial='PRIVATE_KEY_DENIED' in attack.stdout
            if not denial:raise RuntimeError('OS ISOLATION FAILURE: attacker accessed observer key')
            obj=json.loads(attacker_out.read_text()); witnesses=json.loads(witness.read_text())
            status=verify(obj['transactions'],obj['reports'],witnesses,report_key,obs_key)
            baseline='SATISFIED' if all(r['body']['observed_tls']['group']==v11.HYBRID for r in obj['reports']) else 'VIOLATED'
            public[case]={'verdict':status,'report_only_baseline':baseline,'key_read_denied':denial,'transactions':count,
                'actual_receiver_groups':sorted({x['body']['observed_tls']['group'] for x in witnesses})}
    if public['hybrid']['verdict']!='SATISFIED' or public['classical']['verdict']!='INVALID' or public['classical']['report_only_baseline']!='SATISFIED':raise AssertionError(public)
    artifact={'version':'2.3','model':'root TLS receiver vs unprivileged client process, one leg, OS UID/key DAC boundary',
        'results':public,'limits':['root orchestrator and TLS receiver trusted','attacker client is a distinct unprivileged UID','not host/root compromise resistance','protected observer is TLS termination endpoint, not passive monitor','one TLS leg only','client reports fabricated by attack process','connection labels are public random hashes, NOT exporter bindings','lab certificate authentication disabled','only key-exchange migration, not post-quantum authentication']}
    (out/'os_boundary_v23.json').write_text(json.dumps(artifact,indent=2));os.chmod(out/'os_boundary_v23.json',0o644)
    for case,v in public.items():print(case,v)
    print('PASS: real TLS receiver under protected UID; attacker UID denied observer secret; forged classical claim detected')

def main():
    ap=argparse.ArgumentParser()
    ap.add_argument('--output',default='results/os_boundary_v23');ap.add_argument('--count',type=int,default=3)
    ap.add_argument('--openssl',default='openssl');ap.add_argument('--attacker-user',default='nobody')
    ap.add_argument('--worker-receiver',action='store_true');ap.add_argument('--worker-attacker',action='store_true')
    ap.add_argument('--cert');ap.add_argument('--priv');ap.add_argument('--obs-key');ap.add_argument('--ready');ap.add_argument('--witness')
    ap.add_argument('--port',type=int);ap.add_argument('--case');ap.add_argument('--report-key');ap.add_argument('--attacker-output');ap.add_argument('--probe-key')
    a=ap.parse_args()
    if a.worker_receiver:
        receiver(Path(a.cert),Path(a.priv),Path(a.obs_key).read_bytes(),a.count,a.case=='classical',Path(a.ready),Path(a.witness))
    elif a.worker_attacker:
        if os.geteuid()!=0:
            raise RuntimeError('Root bootstrap required')
        identity=pwd.getpwnam(a.attacker_user)
        # Load socket hostname encoding before restricting filesystem access.
        import encodings.idna
        drop(identity.pw_uid,identity.pw_gid)()
        if os.geteuid()!=identity.pw_uid:
            raise RuntimeError('Attacker UID drop failed')
        try:
            Path(a.probe_key).read_bytes()
        except PermissionError:print('PRIVATE_KEY_DENIED',flush=True)
        else:raise RuntimeError('attacker read observer key')
        attacker_client(a.port,a.count,bytes.fromhex(a.report_key),a.case,Path(a.attacker_output))
    else:run(a.output,a.count,a.openssl,a.attacker_user)
if __name__=='__main__':main()
