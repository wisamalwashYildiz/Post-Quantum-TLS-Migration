#!/usr/bin/env python3
"""v2.4: three live TLS legs, root-trusted receiver processes, unprivileged client.

LIMITS: all receivers share root host trust; the two coordinated relay forgeries are
OFFLINE re-signing interventions, not compromise of an OS-protected relay. Session
labels are handshake-derived, not exporters. Only KEX, not PQ authentication.
"""
import argparse, copy, json, multiprocessing as mp, os, pwd, secrets, shutil, socket, ssl, subprocess, sys, tempfile, time
from pathlib import Path
try:
 import live_path as lp
 import session_chain_v11 as v11
 import multihop_witness_v14 as v14
except ImportError:
 from . import live_path as lp, session_chain_v11 as v11, multihop_witness_v14 as v14

NODES=v14.NODES

def receiver_worker(pipe,node,cert,private,classic,downstream,report_key,witness_key,count):
    """Receives count transactions using one inbound AND one outbound TLS session."""
    try:
        if os.geteuid()!=0:raise RuntimeError('receiver is not root')
        ctx,tracker=v11.tls_context(cert=cert,key=private,classic=classic)
        with socket.socket() as listener:
            listener.bind(('127.0.0.1',0));listener.listen(1);listener.settimeout(25)
            pipe.send({'state':'ready','port':listener.getsockname()[1]})
            raw,_=listener.accept();raw.settimeout(20)
            with ctx.wrap_socket(raw,server_side=True) as inbound:
                inbound_ev=tracker.evidence(inbound)
                next_tls=None;outbound_ev=None;next_sock=None
                try:
                    if downstream:
                        cctx,ct=v11.tls_context(client=True,classic=downstream[2])
                        next_sock=socket.create_connection(('127.0.0.1',downstream[1]),timeout=20)
                        next_tls=cctx.wrap_socket(next_sock,server_hostname='localhost')
                        outbound_ev=ct.evidence(next_tls)
                    reports=[];witnesses=[]
                    for i in range(count):
                        payload=lp.read_json(inbound)
                        tx=payload.get('transaction')
                        if payload.get('kind')!='application' or not isinstance(tx,dict) or tx.get('sequence')!=i:
                            raise ValueError('invalid transaction sequence')
                        h=v11.digest(tx)
                        witnesses.append(v11.seal({'transaction_hash':h,'in':inbound_ev,'sequence':i},v14.witness_name(node),{v14.witness_name(node):witness_key}))
                        if next_tls:
                            lp.send_json(next_tls,payload)
                            response=lp.read_json(next_tls)
                        else: response={'transaction_hash':h,'status':'ok','sequence':i}
                        if response!={'transaction_hash':h,'status':'ok','sequence':i}:raise ValueError('bad downstream ack')
                        reports.append(v11.seal({'transaction_hash':h,'in':inbound_ev,'out':outbound_ev,'sequence':i,'target':downstream[3] if downstream else None},node,{node:report_key}))
                        lp.send_json(inbound,response)
                finally:
                    if next_tls:
                        ct.forget(next_tls);next_tls.close()
                    elif next_sock:next_sock.close()
                tracker.forget(inbound)
        pipe.send({'state':'complete','reports':reports,'witnesses':witnesses})
    except BaseException as exc:
        try:pipe.send({'state':'error','detail':repr(exc)})
        except Exception:pass
    finally:pipe.close()

def attacker_client(port,count,key,case,probe):
    """Executes AFTER dropping to a distinct UID in a fresh exec'd process."""
    if os.geteuid()==0:raise RuntimeError('attacker must not run as root')
    try:Path(probe).read_bytes()
    except PermissionError:print('PRIVATE_KEY_DENIED',flush=True)
    else:raise RuntimeError('observer secret accessible to attacker')
    ctx,tracker=v11.tls_context(client=True)
    with socket.create_connection(('127.0.0.1',port),timeout=20) as raw:
        with ctx.wrap_socket(raw,server_hostname='localhost') as tls:
            observed=tracker.evidence(tls);transactions=[];client_receipts=[]
            for i in range(count):
                tx={'nonce':secrets.token_hex(16),'sequence':i,'data':'v2.4 '+case+' '+str(i)}
                lp.send_json(tls,{'kind':'application','transaction':tx})
                reply=lp.read_json(tls)
                if reply!={'transaction_hash':v11.digest(tx),'status':'ok','sequence':i}:raise ValueError('unexpected ack')
                transactions.append(tx)
                client_receipts.append(v11.seal({'transaction_hash':v11.digest(tx),'out':observed},'client',{'client':key}))
            tracker.forget(tls)
    return {'transactions':transactions,'clients':client_receipts}

def verify_batch(batch,report_keys,witness_keys):
    """Cross-check each transaction PLUS one session ID per hop across batch."""
    transactions=batch.get('transactions',[])
    if not transactions:return ('UNRESOLVED','empty batch')
    seen=set();sessions={node:set() for node in NODES};states=[]
    for i,tx in enumerate(transactions):
        nonce=tx.get('nonce')
        if not isinstance(nonce,str) or not nonce or nonce in seen:return ('INVALID','duplicate/invalid nonce')
        seen.add(nonce)
        if tx.get('sequence')!=i:return ('INVALID','transaction sequence')
        try:case={'transaction':tx,'client':batch['clients'][i],
                  'reports':[batch['reports'][n][i] for n in NODES],
                  'witnesses':[batch['witnesses'][n][i] for n in NODES]}
        except (IndexError,KeyError,TypeError):return ('UNRESOLVED','missing evidence')
        for node in NODES:
            if case['witnesses'][NODES.index(node)]['body'].get('sequence')!=i:return ('INVALID','witness sequence')
            if case['reports'][NODES.index(node)]['body'].get('sequence')!=i:return ('INVALID','report sequence')
            sessions[node].add(case['witnesses'][NODES.index(node)]['body']['in']['session_label'])
        status,reason=v14.verify(tx,case['client'],case['reports'],case['witnesses'],report_keys,witness_keys)
        states.append(status)
        if status=='INVALID':return (status,reason)
    if any(len(v)!=1 for v in sessions.values()):return ('INVALID','session changed within reuse window')
    if 'VIOLATED' in states:return ('VIOLATED','trusted receiver observed classical TLS')
    if 'UNRESOLVED' in states:return ('UNRESOLVED','partial observation')
    return ('SATISFIED','all requests on three corroborated hybrid TLS legs')

def forge_middle(batch,report_keys):
    forged=copy.deepcopy(batch)
    for i in range(len(forged['transactions'])):
        for node,side in [('gateway','out'),('service-a','in')]:
            body=copy.deepcopy(forged['reports'][node][i]['body'])
            body[side]['group']=v11.HYBRID
            forged['reports'][node][i]=v11.seal(body,node,report_keys)
    return forged

def report_only(batch,report_keys):
    states=[]
    for i,tx in enumerate(batch['transactions']):
        status,_=v11.verify_chain(tx,batch['clients'][i],[batch['reports'][n][i] for n in NODES],report_keys)
        states.append(status)
    return 'SATISFIED' if states and all(s=='SATISFIED' for s in states) else states[0] if states else 'UNRESOLVED'

def run_case(cert,private,count,case,report_keys,witness_keys,attacker_uid,attacker_gid,probe,attacker_user):
    processes=[];receivers=[]
    try:
        downstream=None
        for node,classic in reversed(list(zip(NODES,[False,case=='classical_middle',False]))):
            reader,writer=mp.Pipe(duplex=False)
            proc=mp.Process(target=receiver_worker,args=(writer,node,str(cert),str(private),classic,downstream,report_keys[node],witness_keys[v14.witness_name(node)],count))
            proc.start();writer.close()
            if not reader.poll(25):raise RuntimeError(node+' start timeout')
            response=reader.recv()
            if response.get('state')!='ready':raise RuntimeError(str(response))
            downstream=('127.0.0.1',response['port'],classic,node)
            receivers.append((node,reader));processes.append(proc)
        # Exec clears inherited orchestrator memory: untrusted worker does not inherit witness keys.
        cmd=[sys.executable,str(Path(__file__).resolve()),'--worker-attacker','--port',str(downstream[1]),'--count',str(count),'--case',case,
             '--report-key',report_keys['client'].hex(),'--probe-key',str(probe),'--attacker-user',attacker_user]
        worker=subprocess.run(cmd,capture_output=True,text=True,timeout=90)
        if worker.returncode:raise RuntimeError('attacker worker: '+worker.stderr[-1300:])
        if 'PRIVATE_KEY_DENIED' not in worker.stdout:raise RuntimeError('observer key isolation failed')
        data=None
        for line in worker.stdout.splitlines():
            if line.startswith('ATTACKER_DATA='):data=json.loads(line.partition('=')[2])
        if data is None:raise RuntimeError('missing attacker batch')
        reports={};witnesses={}
        for node,reader in receivers:
            if not reader.poll(35):raise RuntimeError(node+' response timeout')
            result=reader.recv()
            if result.get('state')!='complete':raise RuntimeError(str(result))
            reports[node]=result['reports'];witnesses[node]=result['witnesses']
        return {**data,'reports':reports,'witnesses':witnesses,'attacker_key_denied':True}
    finally:
        for _,p in receivers:p.close()
        for proc in processes:
            proc.join(2)
            if proc.is_alive():proc.terminate();proc.join(2)

def main():
    p=argparse.ArgumentParser()
    p.add_argument('--openssl',default='openssl');p.add_argument('--output',default='/var/tmp/pqc-protected-path-v24')
    p.add_argument('--count',type=int,default=3);p.add_argument('--attacker-user',default='nobody')
    p.add_argument('--worker-attacker',action='store_true');p.add_argument('--port',type=int);p.add_argument('--case')
    p.add_argument('--report-key');p.add_argument('--probe-key')
    a=p.parse_args()
    if a.worker_attacker:
        if os.geteuid()!=0:raise RuntimeError('attacker bootstrap requires root')
        ident=pwd.getpwnam(a.attacker_user)
        if ident.pw_uid==0:raise RuntimeError('attacker UID root')
        # Initialize Python codecs before losing ability to traverse the custom Python install.
        import encodings.idna
        import encodings.ascii
        import encodings.utf_8
        import encodings.hex_codec
        os.setgroups([]);os.setgid(ident.pw_gid);os.setuid(ident.pw_uid)
        if os.geteuid()!=ident.pw_uid:raise RuntimeError('UID drop unsuccessful')
        result=attacker_client(a.port,a.count,bytes.fromhex(a.report_key),a.case,a.probe_key)
        print('ATTACKER_DATA='+json.dumps(result),flush=True)
        return
    if os.geteuid()!=0:raise RuntimeError('run as root (dedicated WSL laboratory only)')
    if ssl.OPENSSL_VERSION_INFO[:2]<(3,5):raise RuntimeError('OpenSSL >=3.5 required')
    if a.count<2 or a.count>100:raise ValueError('count 2..100')
    ident=pwd.getpwnam(a.attacker_user)
    if ident.pw_uid==0:raise ValueError('root cannot be attacker')
    out=Path(a.output).resolve();out.mkdir(parents=True,exist_ok=True)
    if out.stat().st_uid!=0:raise RuntimeError('output directory must be root-owned, use /var/tmp')
    report_keys={node:secrets.token_bytes(32) for node in ('client',)+NODES}
    witness_keys={v14.witness_name(n):secrets.token_bytes(32) for n in NODES}
    with tempfile.TemporaryDirectory(prefix='pqc-v24-') as t:
        root=Path(t);root.chmod(0o755)
        cert,private=lp.make_cert(root,a.openssl)
        probe=root/'observer.private';probe.write_bytes(secrets.token_bytes(32));probe.chmod(0o600)
        if probe.stat().st_uid!=0 or probe.stat().st_mode&0o077:raise RuntimeError('key protection failure')
        good=run_case(cert,private,a.count,'hybrid',report_keys,witness_keys,ident.pw_uid,ident.pw_gid,probe,a.attacker_user)
        bad=run_case(cert,private,a.count,'classical_middle',report_keys,witness_keys,ident.pw_uid,ident.pw_gid,probe,a.attacker_user)
    forged=forge_middle(bad,report_keys)
    missing=copy.deepcopy(good);missing['witnesses']['service-a'].pop()
    swapped=copy.deepcopy(good);swapped['witnesses']['service-a'][1],swapped['witnesses']['service-a'][0]=swapped['witnesses']['service-a'][0],swapped['witnesses']['service-a'][1]
    duplicate=copy.deepcopy(good);duplicate['transactions'][1]=copy.deepcopy(duplicate['transactions'][0])
    checks={'hybrid':verify_batch(good,report_keys,witness_keys),
       'classical_middle':verify_batch(bad,report_keys,witness_keys),
       'forged_baseline':report_only(forged,report_keys),
       'forged_corroborated':verify_batch(forged,report_keys,witness_keys),
       'missing_witness':verify_batch(missing,report_keys,witness_keys),
       'swapped_witness':verify_batch(swapped,report_keys,witness_keys),
       'replayed_transaction':verify_batch(duplicate,report_keys,witness_keys)}
    expected={'hybrid':'SATISFIED','classical_middle':'VIOLATED','forged_baseline':'SATISFIED',
       'forged_corroborated':'INVALID','missing_witness':'UNRESOLVED','swapped_witness':'INVALID','replayed_transaction':'INVALID'}
    for n,want in expected.items():
        actual=checks[n] if isinstance(checks[n],str) else checks[n][0]
        print(n,actual,flush=True)
        if actual!=want:raise AssertionError((n,actual,want))
    artifact={'version':'2.4','model':'three live TLS hops; three root-trusted receiving processes; unprivileged client after exec + drop; simulated OFFLINE adjacent relay re-signing',
       'openssl':ssl.OPENSSL_VERSION,'count_per_connection':a.count,'checks':checks,
       'groups':{'hybrid':[good['witnesses'][n][0]['body']['in']['group'] for n in NODES],
                 'classical_middle':[bad['witnesses'][n][0]['body']['in']['group'] for n in NODES]},
       'attacker_key_read_denied':good['attacker_key_denied'] and bad['attacker_key_denied'],
       'limits':['all receivers share same trusted root UID; NOT independent receiver trust domains',
        'attacker initially launched as root then drops UID before attacker code; no arbitrary-code sandboxing',
        'relay corruption is OFFLINE re-signing with orchestrator-held keys; no actual relay process compromise',
        'session labels are public handshake-random hashes, not TLS exporter bindings',
        'reused one inbound and outbound TLS connection per node across batch; sequential not concurrently multiplexed',
        'self-signed certificate validation disabled; hybrid TLS key-exchange only',
        'root and host compromise are outside threat model',
        'sensitive secrets are never included in public output']}
    path=out/'protected_path_v24.json';path.write_text(json.dumps(artifact,indent=2));path.chmod(0o644)
    print('PASS: OS-separated client vs root receiver chain, live three-hop TLS and evidence checks')
if __name__=='__main__':main()
