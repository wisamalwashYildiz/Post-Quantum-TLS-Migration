#!/usr/bin/env python3
"""v1.4 live multi-process three-hop TLS path with receiver-side observations.

Trust model: each TLS receiving process is honest and its witness signing key
uncompromised. Report-only compromise is simulated by offline re-signing.
All child processes use same OS user (NOT OS isolation). TLS connection labels
are public handshake labels, NOT tls-exporter bindings.
"""
import argparse, copy, json, multiprocessing as mp, secrets, shutil, socket, ssl, tempfile
from pathlib import Path
try:
    import live_path as lp
    import session_chain_v11 as v11
except ImportError:
    from . import live_path as lp, session_chain_v11 as v11

NODES=('gateway','service-a','backend')

def witness_name(node): return 'receiver:'+node

def verify(tx, client, reports, witnesses, report_keys, witness_keys, *, ledger=None):
    """Verify 3-hop (one transaction) chain with receiver corroboration.
    A full OS/process compromise invalidates the assumed witness trust.
    """
    if len(reports)!=3 or len(witnesses)!=3:
        return 'UNRESOLVED','missing node report or receiving witness'
    if not isinstance(tx,dict) or not isinstance(tx.get('nonce'),str) or not tx['nonce']:
        return 'INVALID','invalid transaction nonce'
    if ledger is not None and tx['nonce'] in ledger:
        return 'INVALID','transaction nonce replay'
    if not v11.verify_seal(client,report_keys) or client.get('node')!='client':
        return 'INVALID','invalid client evidence'
    h=v11.digest(tx)
    if client['body'].get('transaction_hash')!=h: return 'INVALID','client transaction mismatch'
    prior=client['body'].get('out')
    if not isinstance(prior,dict):return 'UNRESOLVED','missing client TLS observation'
    groups=[]
    for index,node in enumerate(NODES):
        rep,wit=reports[index],witnesses[index]
        if not v11.verify_seal(rep,report_keys) or rep.get('node')!=node:
            return 'INVALID','invalid relay report'
        if not v11.verify_seal(wit,witness_keys) or wit.get('node')!=witness_name(node):
            return 'INVALID','invalid receiver witness'
        b,w=rep['body'],wit['body']
        if b.get('transaction_hash')!=h or w.get('transaction_hash')!=h:
            return 'INVALID','transaction reassignment'
        if b.get('in')!=prior:
            return 'INVALID','relay session-link discrepancy'
        if w.get('in')!=prior:
            return 'INVALID','receiver session-link discrepancy'
        if b.get('in')!=w.get('in'):
            return 'INVALID','receiver disagrees with relay'
        if b.get('target')!=(NODES[index+1] if index<2 else None):
            return 'INVALID','invalid forwarding target'
        groups.append(w['in'].get('group'))
        prior=b.get('out')
        if index<2 and not isinstance(prior,dict):
            return 'UNRESOLVED','missing downstream TLS link'
    if prior is not None:return 'INVALID','unaccounted downstream link'
    if v11.CLASSIC in groups:return 'VIOLATED','classical group recorded at honest receiving endpoint'
    if all(group==v11.HYBRID for group in groups):
        return 'SATISFIED','hybrid group on every corroborated TLS hop (trusted receivers)'
    return 'UNRESOLVED','unknown negotiated TLS group'


def relay_worker(pipe,node,cert,private,classic,downstream,report_key,witness_key):
    """A receiver process owns its inbound TLS handshake and signs its observation."""
    try:
        ctx,tracker=v11.tls_context(cert=cert,key=private,classic=classic)
        with socket.socket() as listener:
            listener.setsockopt(socket.SOL_SOCKET,socket.SO_REUSEADDR,1)
            listener.bind(('127.0.0.1',0));listener.listen(1);listener.settimeout(20)
            pipe.send({'state':'ready','port':listener.getsockname()[1]})
            raw,_=listener.accept();raw.settimeout(15)
            with ctx.wrap_socket(raw,server_side=True) as incoming:
                inc=tracker.evidence(incoming)
                payload=lp.read_json(incoming)
                if payload.get('kind')!='application' or not isinstance(payload.get('transaction'),dict):
                    raise RuntimeError('bad inbound transaction')
                tx=payload['transaction'];h=v11.digest(tx)
                witness=v11.seal({'transaction_hash':h,'in':inc},witness_name(node),{witness_name(node):witness_key})
                outbound=None
                if downstream is not None:
                    host,port,target_classic,target_node=downstream
                    cctx,ctracker=v11.tls_context(client=True,classic=target_classic)
                    with socket.create_connection((host,port),timeout=15) as sock:
                        with cctx.wrap_socket(sock,server_hostname='localhost') as next_tls:
                            outbound=ctracker.evidence(next_tls)
                            lp.send_json(next_tls,payload)
                            response=lp.read_json(next_tls)
                            ctracker.forget(next_tls)
                else:
                    response={'transaction_hash':h,'status':'ok'}
                rep=v11.seal({'transaction_hash':h,'in':inc,'out':outbound,
                               'target':downstream[3] if downstream and len(downstream)>3 else None},node,{node:report_key})
                lp.send_json(incoming,response)
                tracker.forget(incoming)
            pipe.send({'state':'complete','report':rep,'witness':witness})
    except Exception as exc:
        try:pipe.send({'state':'error','error':type(exc).__name__+': '+str(exc)})
        except Exception:pass
    finally:pipe.close()


def capture(cert,private,report_keys,witness_keys,*,classic_middle=False):
    """Three actual TLS connections, each receiver running in a separate process."""
    processes=[];receivers=[]
    try:
        downstream=None
        for node,classic in reversed(list(zip(NODES,[False,classic_middle,False]))):
            recv,send=mp.Pipe(duplex=False)
            proc=mp.Process(target=relay_worker,args=(send,node,str(cert),str(private),classic,downstream,
                      report_keys[node],witness_keys[witness_name(node)]),daemon=True)
            proc.start();send.close()
            if not recv.poll(20):raise RuntimeError(node+' failed to start')
            ready=recv.recv()
            if ready.get('state')!='ready':raise RuntimeError(str(ready))
            downstream=('127.0.0.1',ready['port'],classic,node)
            processes.append(proc);receivers.append((node,recv))
        tx={'nonce':secrets.token_hex(16),'data':'v1.4 live three-hop forwarding'}
        ctx,tracker=v11.tls_context(client=True)
        with socket.create_connection(('127.0.0.1',downstream[1]),timeout=15) as raw:
            with ctx.wrap_socket(raw,server_hostname='localhost') as conn:
                cs=tracker.evidence(conn)
                lp.send_json(conn,{'kind':'application','transaction':tx})
                reply=lp.read_json(conn);tracker.forget(conn)
        if reply!={'transaction_hash':v11.digest(tx),'status':'ok'}:
            raise RuntimeError('forwarding reply mismatch')
        collected={}
        for node,rec in receivers:
            if not rec.poll(20):raise RuntimeError(node+' timed out')
            msg=rec.recv()
            if msg.get('state')!='complete':raise RuntimeError(str(msg))
            collected[node]=msg
        client=v11.seal({'transaction_hash':v11.digest(tx),'out':cs},'client',report_keys)
        return {'transaction':tx,'client':client,
                'reports':[collected[n]['report'] for n in NODES],
                'witnesses':[collected[n]['witness'] for n in NODES]}
    finally:
        for _,recv in receivers:recv.close()
        for proc in processes:
            proc.join(3)
            if proc.is_alive():proc.terminate();proc.join(2)

def forge_middle(case,report_keys):
    """Report-key compromise: two adjacent reports lie about same classical leg."""
    result=copy.deepcopy(case)
    for pos,field in ((0,'out'),(1,'in')):
        node=NODES[pos];body=result['reports'][pos]['body']
        # Break shared-object aliasing with the honest receiver witness before rewriting.
        body[field]=copy.deepcopy(body[field])
        body[field]['group']=v11.HYBRID
        result['reports'][pos]=v11.seal(body,node,report_keys)
    return result

def baseline(case,report_keys):
    return v11.verify_chain(case['transaction'],case['client'],case['reports'],report_keys)

def main():
    ap=argparse.ArgumentParser()
    ap.add_argument('--openssl',default=shutil.which('openssl'))
    ap.add_argument('--output',default='results/multihop_witness_v14')
    args=ap.parse_args()
    if ssl.OPENSSL_VERSION_INFO[:2]<(3,5):raise SystemExit('Python OpenSSL >= 3.5 required')
    out=Path(args.output);out.mkdir(parents=True,exist_ok=True)
    report_keys={n:secrets.token_bytes(32) for n in ('client',)+NODES}
    witness_keys={witness_name(n):secrets.token_bytes(32) for n in NODES}
    with tempfile.TemporaryDirectory(prefix='pqc-v14-') as d:
        cert,private=lp.make_cert(Path(d),args.openssl)
        good=capture(cert,private,report_keys,witness_keys)
        classic=capture(cert,private,report_keys,witness_keys,classic_middle=True)
    forged=forge_middle(classic,report_keys)
    def v(c):return verify(c['transaction'],c['client'],c['reports'],c['witnesses'],report_keys,witness_keys)
    missing=copy.deepcopy(good);missing['witnesses'].pop(1)
    reassigned=copy.deepcopy(good);reassigned['witnesses'][1]=copy.deepcopy(classic['witnesses'][1])
    checks={'valid':v(good),'classical_middle':v(classic),'forged_baseline':baseline(forged,report_keys),
            'forged_corroborated':v(forged),'missing_witness':v(missing),
            'reassigned_witness':v(reassigned)}
    expected={'valid':'SATISFIED','classical_middle':'VIOLATED','forged_baseline':'SATISFIED',
              'forged_corroborated':'INVALID','missing_witness':'UNRESOLVED','reassigned_witness':'INVALID'}
    for name,ex in expected.items():
        print(name,checks[name][0],'-',checks[name][1])
        if checks[name][0]!=ex:raise AssertionError((name,checks[name],ex))
    data={'version':'1.4','openssl':ssl.OPENSSL_VERSION,
          'model':'multi-hop TLS with each receiving endpoint in a distinct same-user process',
          'valid':good,'classical_middle':classic,'forged':forged,'checks':checks,
          'limitations':['single transaction per TLS connection in v1.4',
           'same-UID processes do not provide OS security isolation',
           'receiving endpoint and its witness key assumed honest',
           'forged reports are an offline re-signing intervention, not process takeover',
           'session label hashes handshake randoms; not exporter channel binding',
           'lab self-signed certificates and classical signatures; only KEX assessed',
           'multi-hop linkage depends on trusted receiving process and transaction payload']}
    (out/'multihop_witness.json').write_text(json.dumps(data,indent=2))
    secrets_file=out/'lab_verifier_keys.json'
    secrets_file.write_text(json.dumps({'report_keys':{k:v.hex() for k,v in report_keys.items()},
                     'witness_keys':{k:v.hex() for k,v in witness_keys.items()}},indent=2))
    secrets_file.chmod(0o600)
    print('PASS: distinct-process live three-hop TLS corroboration')
if __name__=='__main__':main()
