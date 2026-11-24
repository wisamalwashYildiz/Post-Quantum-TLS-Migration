#!/usr/bin/env python3
"""v3.0 integration gate: live pyOpenSSL TLS 1.3 exporter and group on SAME connection.

This is an integration/security-negative-control gate, not independent receiver
isolation: all endpoints in same process, cert validation off, no PQ auth.
Do not present exporter proof parity as standalone endpoint authentication.
"""
import ctypes, select, argparse, copy, csv, hashlib, hmac, json, os, secrets, socket, subprocess, tempfile, threading, time, uuid
from datetime import datetime, timezone
from pathlib import Path
from OpenSSL import SSL

LABEL=b'EXPORTER-PQC-RESEARCH-v3-gate'
NODES=('gateway','service-a','backend')
HYBRID='X25519MLKEM768'; CLASSIC='X25519'

def canon(x):return json.dumps(x,sort_keys=True,separators=(',',':')).encode()
def digest(x):return hashlib.sha256(canon(x)).hexdigest()
def group(conn):
    if not hasattr(SSL._lib,'SSL_get0_group_name'):
        raise RuntimeError('OpenSSL SSL_get0_group_name unavailable')
    ptr=SSL._lib.SSL_get0_group_name(conn._ssl)
    if ptr==SSL._ffi.NULL:raise RuntimeError('negotiated group unavailable')
    return {"x25519":"X25519"}.get(SSL._ffi.string(ptr).decode(),SSL._ffi.string(ptr).decode())
def proof(conn,tx,node):
    # Exported material never written to disk; distinct context per hop and transaction.
    context=canon({'hop':node,'transaction_hash':digest(tx),'nonce':tx['nonce']})
    key=conn.export_keying_material(LABEL,32,context)
    return hmac.new(key,context,hashlib.sha256).hexdigest()
def ctx(server=False,cert=None,key=None,group_name=HYBRID):
    c=SSL.Context(SSL.TLS_METHOD)
    c.set_min_proto_version(SSL.TLS1_3_VERSION);c.set_max_proto_version(SSL.TLS1_3_VERSION)
    # SSL_CTX_set1_groups_list is a C macro; use its underlying SSL_CTX_ctrl.
    # Dynamic symbol must resolve to the *same libssl* used by pyOpenSSL.
    native=ctypes.CDLL('libssl.so.3')
    native.SSL_CTX_ctrl.argtypes=[ctypes.c_void_p,ctypes.c_int,ctypes.c_long,ctypes.c_void_p]
    native.SSL_CTX_ctrl.restype=ctypes.c_long
    ptr=int(SSL._ffi.cast('uintptr_t',c._context))
    groups=ctypes.create_string_buffer(group_name.encode())
    if native.SSL_CTX_ctrl(ptr,92,0,ctypes.cast(groups,ctypes.c_void_p))!=1:
        raise RuntimeError('failed to configure negotiated group '+group_name)
    if server:
        c.use_certificate_file(str(cert));c.use_privatekey_file(str(key));c.check_privatekey()
    else:c.set_verify(SSL.VERIFY_NONE,lambda *_:True)
    return c

def io(c,fn,*args):
    end=time.monotonic()+20
    while True:
        try:return fn(*args)
        except (SSL.WantReadError,SSL.WantWriteError) as ex:
            if time.monotonic()>end:raise TimeoutError('TLS IO timeout') from ex
            if isinstance(ex,SSL.WantReadError):select.select([c],[],[],.2)
            else:select.select([],[c],[],.2)

def send(c,x):
    data=canon(x); frame=len(data).to_bytes(4,'big')+data
    while frame:
        n=io(c,c.send,frame)
        if n<=0:raise RuntimeError('TLS write failure')
        frame=frame[n:]
def read_exact(c,n):
    b=b''
    while len(b)<n:
        chunk=io(c,c.recv,n-len(b))
        if not chunk:raise RuntimeError('TLS EOF')
        b+=chunk
    return b
def recv(c):
    n=int.from_bytes(read_exact(c,4),'big')
    if not 0<n<=100000:raise RuntimeError('invalid frame size')
    return json.loads(read_exact(c,n))

def run_case(cert,key,groups,count=3):
    if len(groups)!=3:raise ValueError('three groups required')
    traces={};errs=[]; threads=[]; listeners=[]; ready=[]
    def node_worker(node,index,listener,downstream_port):
        try:
            sock,_=listener.accept()
            with sock:
                incoming=SSL.Connection(ctx(True,cert,key,groups[index]),sock)
                incoming.set_accept_state();io(incoming,incoming.do_handshake)
                incoming_group=group(incoming)
                downstream=None; out_group=None
                if downstream_port is not None:
                    down_sock=socket.create_connection(('127.0.0.1',downstream_port),timeout=15)
                    downstream=SSL.Connection(ctx(False,group_name=groups[index+1]),down_sock)
                    downstream.set_connect_state();io(downstream,downstream.do_handshake)
                    out_group=group(downstream)
                rec=[]
                for _ in range(count):
                    tx=recv(incoming)
                    if downstream is not None:
                        send(downstream,tx);ack=recv(downstream)
                    else:ack={'ok':digest(tx)}
                    if ack!={'ok':digest(tx)}:raise RuntimeError('downstream ack mismatch')
                    rec.append({'transaction_hash':digest(tx),'inbound_group':incoming_group,
                        'inbound_proof':proof(incoming,tx,node),
                        'outbound_group':out_group,
                        'outbound_proof':proof(downstream,tx,NODES[index+1]) if downstream else None})
                    send(incoming,ack)
                traces[node]=rec
                if downstream:downstream.shutdown();downstream.close();down_sock.close()
                incoming.shutdown();incoming.close()
        except Exception as e: errs.append(node+': '+repr(e))
        finally:listener.close()
    for _ in NODES:
        listener=socket.socket();listener.setsockopt(socket.SOL_SOCKET,socket.SO_REUSEADDR,1)
        listener.bind(('127.0.0.1',0));listener.listen(1);listener.settimeout(20)
        listeners.append(listener)
    for idx in reversed(range(3)):
        t=threading.Thread(target=node_worker,args=(NODES[idx],idx,listeners[idx],listeners[idx+1].getsockname()[1] if idx<2 else None),daemon=True)
        t.start();threads.append(t)
    transactions=[]; client_proofs=[]
    with socket.create_connection(('127.0.0.1',listeners[0].getsockname()[1]),timeout=15) as sock:
        c=SSL.Connection(ctx(False,group_name=groups[0]),sock);c.set_connect_state();io(c,c.do_handshake)
        client_group=group(c)
        for i in range(count):
            tx={'nonce':secrets.token_hex(16),'sequence':i,'payload':'v3.0 integration gate'}
            transactions.append(tx)
            send(c,tx)
            if recv(c)!={'ok':digest(tx)}:raise RuntimeError('client ack mismatch')
            client_proofs.append({'group':client_group,'proof':proof(c,tx,NODES[0])})
        c.shutdown();c.close()
    for t in threads:t.join(22)
    if any(t.is_alive() for t in threads):raise RuntimeError('worker timeout')
    if errs:raise RuntimeError('; '.join(errs))
    if len(traces)!=3:raise RuntimeError('missing receiver traces')
    return {'transactions':transactions,'client':client_proofs,'receivers':traces}

def verify(batch):
    transactions=batch.get('transactions',[])
    if not transactions:return 'UNRESOLVED'
    seen=set(); classical=False
    for i,tx in enumerate(transactions):
        if tx.get('sequence')!=i or not isinstance(tx.get('nonce'),str) or tx['nonce'] in seen:return 'INVALID'
        seen.add(tx['nonce']);h=digest(tx)
        try:
            a=batch['client'][i]
            for index,node in enumerate(NODES):
                r=batch['receivers'][node][i]
                if r['transaction_hash']!=h:return 'INVALID'
                incoming=a if index==0 else batch['receivers'][NODES[index-1]][i]
                left_group=incoming['group'] if index==0 else incoming['outbound_group']
                left_proof=incoming['proof'] if index==0 else incoming['outbound_proof']
                if r['inbound_group']!=left_group or not hmac.compare_digest(r['inbound_proof'],left_proof):return 'INVALID'
                if r['inbound_group']!=HYBRID:classical=True
                if r['inbound_group'] not in (HYBRID,CLASSIC):return 'UNRESOLVED'
        except (KeyError,IndexError,TypeError):return 'UNRESOLVED'
    return 'VIOLATED' if classical else 'SATISFIED'

def checks(batch):
    positive=verify(batch)
    cloned=copy.deepcopy(batch);cloned['receivers']['service-a'][0]['inbound_proof']='0'*64
    missing=copy.deepcopy(batch);missing['receivers']['service-a'].pop()
    substitution=copy.deepcopy(batch);substitution['transactions'][0]['payload']='forged'
    copied=copy.deepcopy(batch)  # Demonstrates the verifier cannot prove independent provenance.
    return {'base':positive,'substituted_proof':verify(cloned),'missing':verify(missing),
            'changed_transaction':verify(substitution),'copied_proofs_limitation':verify(copied)}

def archive(args):
    out=Path(args.archive).resolve();tag=datetime.now(timezone.utc).strftime('%Y%m%dT%H%M%SZ')+'_'+uuid.uuid4().hex[:8]
    path=out/('gate_'+tag);path.mkdir(parents=True,exist_ok=False)
    manifest={'schema':'pqc-v3-integration-gate','date_utc':datetime.now(timezone.utc).isoformat(),
      'openssl':subprocess.check_output([args.openssl,'version'],text=True).strip(),
      'count':args.count,'trials_requested':args.trials,'model':'same-process 3-hop pyOpenSSL TLS 1.3',
      'limits':['ALL endpoints in same process; no independent receiver trust or protected keys',
      'self-signed certificate authentication disabled','no post-quantum authentication',
      'no verifier-trusted provenance: copied proofs are not independently authenticated',
      'only two fixed negotiated-group conditions; not distributional attack study',
      'copied proof negative control still passes: no independently authenticated evidence origin']}
    (path/'manifest.json').write_text(json.dumps(manifest,indent=2)+'\n')
    results=[]
    with tempfile.TemporaryDirectory(prefix='pqc-v3-cert-') as td:
        crt=Path(td)/'cert.pem';private=Path(td)/'key.pem'
        subprocess.run([args.openssl,'req','-x509','-newkey','rsa:2048','-keyout',str(private),'-out',str(crt),'-days','1','-nodes','-subj','/CN=localhost'],capture_output=True,check=True)
        for index in range(args.trials):
            for scenario,groups in [('hybrid',(HYBRID,)*3),('classical_middle',(HYBRID,CLASSIC,HYBRID))]:
                row={'trial':index+1,'scenario':scenario,'status':'FAIL'}
                t0=time.perf_counter_ns()
                try:
                    batch=run_case(crt,private,groups,args.count);verdicts=checks(batch)
                    expected={'base':'SATISFIED' if scenario=='hybrid' else 'VIOLATED',
                              'substituted_proof':'INVALID','missing':'UNRESOLVED','changed_transaction':'INVALID',
                              'copied_proofs_limitation':'SATISFIED' if scenario=='hybrid' else 'VIOLATED'}
                    if verdicts!=expected:raise RuntimeError('unexpected outcomes '+repr(verdicts))
                    # No actual exported key material or cert private key retained.
                    row.update(status='PASS',**verdicts,observed_groups=[batch['receivers'][n][0]['inbound_group'] for n in NODES])
                except Exception as e:row['error']=repr(e)
                row['elapsed_ns']=time.perf_counter_ns()-t0
                results.append(row)
                (path/f'trial_{index+1:03d}_{scenario}.json').write_text(json.dumps(row,indent=2)+'\n')
                print(row['trial'],scenario,row['status'],row.get('error',''),flush=True)
    with (path/'summary.csv').open('w',newline='') as f:
        w=csv.DictWriter(f,fieldnames=['trial','scenario','status','base','substituted_proof','missing','changed_transaction','copied_proofs_limitation','elapsed_ns','observed_groups','error'],extrasaction='ignore');w.writeheader();w.writerows(results)
    manifest['completed']=len(results);manifest['passes']=sum(r['status']=='PASS' for r in results)
    (path/'manifest.json').write_text(json.dumps(manifest,indent=2)+'\n')
    files=sorted(p for p in path.iterdir() if p.is_file() and p.name!='checksums.sha256')
    (path/'checksums.sha256').write_text(''.join(hashlib.sha256(p.read_bytes()).hexdigest()+'  '+p.name+'\n' for p in files))
    print('ARCHIVE',path)
    if manifest['passes']!=len(results):raise SystemExit('FAIL: evidence retained, inspect trial failures')
    print('PASS:',len(results),'live TLS-path conditions')

def main():
    ap=argparse.ArgumentParser();ap.add_argument('--openssl',required=True);ap.add_argument('--archive',default='results/v30_session_gate')
    ap.add_argument('--trials',type=int,default=3);ap.add_argument('--count',type=int,default=3)
    args=ap.parse_args()
    if not 1<=args.trials<=20 or not 2<=args.count<=30:ap.error('invalid trial/count')
    archive(args)
if __name__=='__main__':main()
