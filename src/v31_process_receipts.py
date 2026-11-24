#!/usr/bin/env python3
"""Experimental v3.1 gate: live three-hop TLS + independently signed per-process receipts.

Not OS isolated: processes share user; parent is trusted key registrar; no PKI or
host/root compromise resilience. Receipt public keys delivered out-of-band by pipe.
Same TLS connection is used to measure negotiated group and derive exporter proof.
"""
import argparse, base64, copy, csv, hashlib, json, multiprocessing as mp, os, secrets, socket, subprocess, tempfile, time, uuid
from datetime import datetime, timezone
from pathlib import Path
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey, Ed25519PublicKey
from cryptography.hazmat.primitives import serialization
from OpenSSL import SSL
from v30_session_gate import NODES, HYBRID, CLASSIC, canon, digest, ctx, group, proof, io, send, recv

def signed(sk, record):
    return {'record':record, 'signature':base64.b64encode(sk.sign(canon(record))).decode('ascii')}

def public_bytes(sk):
    return sk.public_key().public_bytes(encoding=serialization.Encoding.Raw,format=serialization.PublicFormat.Raw).hex()

def valid(pubhex, signed_record):
    try:
        Ed25519PublicKey.from_public_bytes(bytes.fromhex(pubhex)).verify(base64.b64decode(signed_record['signature'],validate=True),canon(signed_record['record']))
        return True
    except (ValueError,TypeError,KeyError,Exception):
        return False

def listen():
    s=socket.socket();s.setsockopt(socket.SOL_SOCKET,socket.SO_REUSEADDR,1)
    s.bind(('127.0.0.1',0));s.listen(1);s.settimeout(20)
    return s

def endpoint(index,listener,down_port,cert,key,groups,count,channel):
    name=NODES[index]
    try:
        sk=Ed25519PrivateKey.generate()
        channel.send(('pub',public_bytes(sk)))
        sock,_=listener.accept()
        with sock:
            incoming=SSL.Connection(ctx(True,cert,key,groups[index]),sock)
            incoming.set_accept_state();io(incoming,incoming.do_handshake)
            incoming_group=group(incoming)
            downstream=None;outgoing_group=None;dsock=None
            if down_port is not None:
                dsock=socket.create_connection(('127.0.0.1',down_port),timeout=15)
                downstream=SSL.Connection(ctx(False,group_name=groups[index+1]),dsock)
                downstream.set_connect_state();io(downstream,downstream.do_handshake)
                outgoing_group=group(downstream)
            records=[]
            for seq in range(count):
                tx=recv(incoming)
                if tx.get('sequence')!=seq:raise ValueError('sequence mismatch')
                if downstream:
                    send(downstream,tx);ack=recv(downstream)
                else:ack={'ok':digest(tx)}
                if ack!={'ok':digest(tx)}:raise ValueError('ack mismatch')
                record={'node':name,'sequence':seq,'tx_hash':digest(tx),
                        'inbound_group':incoming_group,'inbound_proof':proof(incoming,tx,name),
                        'outbound_group':outgoing_group,
                        'outbound_proof':proof(downstream,tx,NODES[index+1]) if downstream else None}
                records.append(signed(sk,record));send(incoming,ack)
            if downstream:downstream.shutdown();downstream.close();dsock.close()
            incoming.shutdown();incoming.close()
        channel.send(('records',records))
    except BaseException as exc:
        try:channel.send(('error',repr(exc)))
        except Exception:pass
    finally:
        listener.close();channel.close()

def live_case(cert,key,groups,count):
    if len(groups)!=3:raise ValueError('three hops required')
    if 'fork' not in mp.get_all_start_methods():raise RuntimeError('Linux fork start method required')
    context=mp.get_context('fork')
    listeners=[listen() for _ in NODES]
    ports=[s.getsockname()[1] for s in listeners]
    pipes=[context.Pipe(duplex=False) for _ in NODES]
    workers=[]
    for i in reversed(range(3)):
        parent,child=pipes[i]
        proc=context.Process(target=endpoint,args=(i,listeners[i],ports[i+1] if i<2 else None,cert,key,groups,count,child))
        proc.start();child.close();workers.append(proc)
    # Per-process public keys arrive through parent-held pipes, not through relay evidence.
    keys={}
    try:
        for i,name in enumerate(NODES):
            if not pipes[i][0].poll(20):raise TimeoutError('receiver public key timeout: '+name)
            typ,data=pipes[i][0].recv()
            if typ!='pub':raise RuntimeError('receiver startup '+str(data))
            keys[name]=data
        sock=socket.create_connection(('127.0.0.1',ports[0]),timeout=15)
        transactions=[];client=[]
        with sock:
            connection=SSL.Connection(ctx(False,group_name=groups[0]),sock)
            connection.set_connect_state();io(connection,connection.do_handshake)
            cg=group(connection)
            for seq in range(count):
                tx={'nonce':secrets.token_hex(16),'sequence':seq,'payload':'v3 protected-process gate'}
                transactions.append(tx);send(connection,tx)
                if recv(connection)!={'ok':digest(tx)}:raise RuntimeError('client ack mismatch')
                client.append({'group':cg,'proof':proof(connection,tx,NODES[0])})
            connection.shutdown();connection.close()
        received={}
        for i,name in enumerate(NODES):
            if not pipes[i][0].poll(20):raise TimeoutError('receiver trace timeout: '+name)
            typ,data=pipes[i][0].recv()
            if typ!='records':raise RuntimeError('receiver failure '+name+': '+str(data))
            received[name]=data
        return {'transactions':transactions,'client':client,'receivers':received,'registered_public_keys':keys}
    finally:
        for parent,child in pipes:parent.close()
        for proc in workers:
            proc.join(2)
            if proc.is_alive():proc.terminate();proc.join(2)
        for listener in listeners:listener.close()

def verify(batch, trusted_keys):
    txs=batch.get('transactions',[])
    if not txs:return 'UNRESOLVED'
    nonces=set();classical=False
    for seq,tx in enumerate(txs):
        if tx.get('sequence')!=seq or not isinstance(tx.get('nonce'),str) or tx['nonce'] in nonces:return 'INVALID'
        nonces.add(tx['nonce'])
        try:
            previous=batch['client'][seq]
            for i,name in enumerate(NODES):
                sr=batch['receivers'][name][seq]
                if not valid(trusted_keys[name],sr):return 'INVALID'
                rec=sr['record']
                if rec['node']!=name or rec['sequence']!=seq or rec['tx_hash']!=digest(tx):return 'INVALID'
                prior_group=previous['group'] if i==0 else previous['outbound_group']
                prior_proof=previous['proof'] if i==0 else previous['outbound_proof']
                if rec['inbound_group']!=prior_group or not secrets.compare_digest(rec['inbound_proof'],prior_proof):return 'INVALID'
                if rec['inbound_group']==CLASSIC:classical=True
                elif rec['inbound_group']!=HYBRID:return 'UNRESOLVED'
                previous=rec
        except (IndexError,KeyError,TypeError):return 'UNRESOLVED'
    return 'VIOLATED' if classical else 'SATISFIED'

def interventions(batch,keys):
    baseline=verify(batch,keys)
    forged=copy.deepcopy(batch)
    forged['receivers']['service-a'][0]['record']['inbound_group']=(CLASSIC if baseline=='SATISFIED' else HYBRID)
    # Negative control: a copied signature does not authenticate altered content.
    forged_result=verify(forged,keys)
    wrong_key=copy.deepcopy(keys);wrong_key['service-a']=keys['backend']
    missing=copy.deepcopy(batch);missing['receivers']['service-a'].pop()
    changed=copy.deepcopy(batch);changed['transactions'][0]['payload']='forged'
    copied=copy.deepcopy(batch)
    return dict(baseline=baseline, forged_unsigned_edit=forged_result,
                wrong_public_key=verify(batch,wrong_key),missing_witness=verify(missing,keys),
                changed_transaction=verify(changed,keys),copied_complete_evidence=verify(copied,keys))

def archive(args):
    root=Path(args.archive).resolve()
    target=root/('gate_'+datetime.now(timezone.utc).strftime('%Y%m%dT%H%M%SZ')+'_'+uuid.uuid4().hex[:8]);target.mkdir(parents=True,exist_ok=False)
    manifest={'schema':'pqc-v3.1-process-gate','date_utc':datetime.now(timezone.utc).isoformat(),
              'openssl':subprocess.check_output([args.openssl,'version'],text=True).strip(),
              'trials_requested':args.trials,'count':args.count,'model':'three separate receiver processes; same OS user, parent trusted registrar',
              'limits':['NO separate OS UID isolation; receivers share parent trust and user privileges',
                        'trusted parent registers ephemeral receiver keys over local Pipes',
                        'client and receiver certificate validation disabled',
                        'no remote network and no post-quantum authentication',
                        'copied complete signed evidence still verifies; freshness needs trusted independent challenge/ledger',
                        'dishonest signing endpoint can lie; one compromised endpoint not modeled',
                        'no raw exporter key material or signing private keys archived']}
    rows=[]
    with tempfile.TemporaryDirectory(prefix='pqc-v31-') as td:
        cert=Path(td)/'cert.pem';key=Path(td)/'key.pem'
        conf=os.environ.get('OPENSSL_CONF','/etc/ssl/openssl.cnf')
        cmd=[args.openssl,'req','-x509','-newkey','rsa:2048','-keyout',str(key),'-out',str(cert),'-days','1','-nodes','-subj','/CN=localhost']
        proc=subprocess.run(cmd,env=dict(os.environ,OPENSSL_CONF=conf),capture_output=True,text=True)
        if proc.returncode:raise RuntimeError('OpenSSL certificate generation failed: '+proc.stderr[-1800:])
        for trial in range(1,args.trials+1):
            for scenario,groups in [('hybrid',(HYBRID,)*3),('classical_middle',(HYBRID,CLASSIC,HYBRID))]:
                start=time.perf_counter_ns();row={'trial':trial,'scenario':scenario,'status':'FAIL'}
                try:
                    batch=live_case(cert,key,groups,args.count)
                    result=interventions(batch,batch['registered_public_keys'])
                    expected={'baseline':'SATISFIED' if scenario=='hybrid' else 'VIOLATED',
                              'forged_unsigned_edit':'INVALID','wrong_public_key':'INVALID',
                              'missing_witness':'UNRESOLVED','changed_transaction':'INVALID',
                              'copied_complete_evidence':'SATISFIED' if scenario=='hybrid' else 'VIOLATED'}
                    if result!=expected:raise RuntimeError('unexpected verdicts '+str(result))
                    row.update(status='PASS',**result,groups=[batch['receivers'][n][0]['record']['inbound_group'] for n in NODES],
                               signed_receipts=3*args.count)
                except Exception as exc:row['error']=repr(exc)
                row['elapsed_ns']=time.perf_counter_ns()-start;rows.append(row)
                (target/f'trial_{trial:03d}_{scenario}.json').write_text(json.dumps(row,indent=2)+'\n')
                print(trial,scenario,row['status'],row.get('error',''),flush=True)
    manifest.update(passes=sum(r['status']=='PASS' for r in rows),completed=len(rows))
    (target/'manifest.json').write_text(json.dumps(manifest,indent=2)+'\n')
    with (target/'summary.csv').open('w',newline='') as f:
        names=['trial','scenario','status','baseline','forged_unsigned_edit','wrong_public_key','missing_witness','changed_transaction','copied_complete_evidence','groups','signed_receipts','elapsed_ns','error']
        w=csv.DictWriter(f,fieldnames=names,extrasaction='ignore');w.writeheader();w.writerows(rows)
    (target/'checksums.sha256').write_text(''.join(hashlib.sha256(p.read_bytes()).hexdigest()+'  '+p.name+'\n' for p in sorted(target.iterdir()) if p.name!='checksums.sha256'))
    print('ARCHIVE',target)
    if manifest['passes']!=len(rows):raise SystemExit('FAIL: see saved trial evidence')
    print('PASS:',len(rows),'process-separated live TLS scenarios')

def main():
    p=argparse.ArgumentParser();p.add_argument('--openssl',required=True);p.add_argument('--archive',default='results/v31_process_gate');p.add_argument('--trials',type=int,default=3);p.add_argument('--count',type=int,default=3)
    args=p.parse_args()
    if not 1<=args.trials<=20 or not 2<=args.count<=30:p.error('invalid trial/count')
    archive(args)
if __name__=='__main__':main()
