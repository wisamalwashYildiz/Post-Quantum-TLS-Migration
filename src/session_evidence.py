#!/usr/bin/env python3
"""v0.6: Live forwarding with TLS 1.3 ServerHello key-share evidence from actual app sessions.
Research-only: uses CPython private SSLContext._msg_callback; not a portable production API.
"""
import argparse, csv, json, shutil, ssl, socket, tempfile, time, uuid, threading
from pathlib import Path
import live_path as old

HYBRID = 'X25519MLKEM768'
CLASSIC = 'X25519'
GROUP_CODES={0x001d:CLASSIC, 0x11ec:HYBRID, 0x6399:HYBRID} # 0x11ec is standardized hybrid group

def decode_server_hello(data):
    """Return selected TLS1.3 key_share group; None when the message is not a usable ServerHello."""
    b=bytes(data)
    if len(b)>=4 and b[0]==2 and int.from_bytes(b[1:4],'big')==len(b)-4:
        b=b[4:]
    if len(b)<38: return None
    p=2+32
    sid=b[p]; p+=1+sid
    if p+5>len(b): return None
    p+=2+1
    end=p+2+int.from_bytes(b[p:p+2],'big'); p+=2
    if end>len(b): return None
    while p+4<=end:
        typ=int.from_bytes(b[p:p+2],'big'); sz=int.from_bytes(b[p+2:p+4],'big'); p+=4
        if p+sz>end: return None
        if typ==51 and sz>=2:
            return GROUP_CODES.get(int.from_bytes(b[p:p+2],'big'),f'UNKNOWN_0x{int.from_bytes(b[p:p+2],"big"):04x}')
        p+=sz
    return None

class Tracker:
    def __init__(self): self.groups={};self.lock=threading.Lock()
    def callback(self, conn, direction, version, content_type, msg_type, data):
        # Handshake ServerHello = 2. Works both client receive and server send callbacks.
        if int(msg_type)!=2: return
        result=decode_server_hello(data)
        if result:
            with self.lock: self.groups[id(conn)]=result
    def get(self,conn):
        with self.lock: return self.groups.get(id(conn))
    def forget(self,conn):
        with self.lock: self.groups.pop(id(conn),None)

def contexts(cert,key,classical,client=False):
    ctx=old.context_client(classical) if client else old.context_server(cert,key,classical)
    tracker=Tracker();ctx._msg_callback=tracker.callback
    return ctx,tracker

class ForwardNode:
    def __init__(self,name,crt,key,classical,downstream=None):
        self.name=name;self.downstream=downstream;self.classical=classical
        self.logs=[];self.errors=[]
        self.context,self.track=contexts(crt,key,classical)
        self.sock=socket.socket();self.sock.bind(('127.0.0.1',0));self.port=self.sock.getsockname()[1]
        self.sock.listen(10);self.sock.settimeout(.2);self.stopping=threading.Event()
        self.thread=threading.Thread(target=self.serve,daemon=True);self.thread.start()
    def serve(self):
        while not self.stopping.is_set():
            try: raw,_=self.sock.accept()
            except socket.timeout: continue
            except OSError: break
            try:
                raw.settimeout(8)
                with self.context.wrap_socket(raw,server_side=True) as incoming:
                    incoming_group=self.track.get(incoming)
                    req=old.read_json(incoming)
                    if req.get('kind')!='application': continue
                    rid=req['request_id']
                    receipt={'node':self.name,'request_id':rid,'incoming_negotiated_group':incoming_group,
                             'incoming_tls_version':incoming.version(),'received_path':list(req['path'])}
                    req['path'].append(self.name)
                    if self.downstream:
                        ctx,tracker=contexts(None,None,self.downstream.classical,client=True)
                        with socket.create_connection(('127.0.0.1',self.downstream.port),timeout=8) as sock:
                            with ctx.wrap_socket(sock,server_hostname='localhost') as outbound:
                                receipt['outgoing_negotiated_group']=tracker.get(outbound)
                                old.send_json(outbound,req)
                                response=old.read_json(outbound)
                                tracker.forget(outbound)
                    else:
                        response={'request_id':rid,'path':req['path'],'status':'ok'}
                    self.logs.append(receipt)
                    old.send_json(incoming,response)
                    self.track.forget(incoming)
            except Exception as e:
                self.errors.append(type(e).__name__+': '+str(e))
                try:raw.close()
                except Exception:pass
    def close(self):
        self.stopping.set();self.sock.close();self.thread.join(3)

def run_case(name,flags,visibility,crt,key):
    backend=ForwardNode('backend',crt,key,flags[2]); middle=ForwardNode('service-a',crt,key,flags[1],backend)
    gateway=ForwardNode('gateway',crt,key,flags[0],middle);nodes=[gateway,middle,backend]
    try:
        rid=str(uuid.uuid4())
        ctx,tracker=contexts(None,None,flags[0],client=True)
        with socket.create_connection(('127.0.0.1',gateway.port),timeout=8) as raw:
            with ctx.wrap_socket(raw,server_hostname='localhost') as conn:
                client_group=tracker.get(conn)
                old.send_json(conn,{'kind':'application','request_id':rid,'path':['client']})
                response=old.read_json(conn)
        assert response=={'request_id':rid,'path':['client','gateway','service-a','backend'],'status':'ok'},response
        receipts=[]
        for n in nodes:
            assert not n.errors, (n.name,n.errors)
            assert len(n.logs)==1 and n.logs[0]['request_id']==rid,(n.name,n.logs)
            receipts.append(n.logs[0])
        groups=[r['incoming_negotiated_group'] for r in receipts]
        expected=[CLASSIC if c else HYBRID for c in flags]
        assert groups==expected, ('actual application groups did not match expectation',groups,expected)
        assert client_group==groups[0]
        assert receipts[0]['outgoing_negotiated_group']==groups[1]
        assert receipts[1]['outgoing_negotiated_group']==groups[2]
        observed=[g if v else None for g,v in zip(groups,visibility)]
        return {'case':name,'request_id':rid,'application_groups':groups,'observed_application_groups':observed,
                'ground_truth':old.verdict(groups),'evidence_verdict':old.verdict(observed),
                'edge_only':old.verdict([groups[0]]),'full_per_hop':old.verdict(groups),
                'client_negotiated_group':client_group,'receipts':receipts,'response':response}
    finally:
        for n in nodes:n.close()

def main():
    p=argparse.ArgumentParser()
    p.add_argument('--openssl',default=shutil.which('openssl'))
    p.add_argument('--output',default='results/session_evidence_v06')
    a=p.parse_args()
    if ssl.OPENSSL_VERSION_INFO[:2]<(3,5):raise SystemExit('Requires Python ssl with OpenSSL >=3.5 for hybrid TLS. Existing Windows Python 3.0 cannot run this script. Run in compatible WSL/Linux Python. Do not replace Python DLLs.')
    out=Path(a.output).resolve();out.mkdir(parents=True,exist_ok=True)
    cases=[('all_hybrid',[False]*3,[True]*3),('classical_middle',[False,True,False],[True]*3),
      ('missing_classical_middle',[False,True,False],[True,False,True]),
      ('missing_hybrid_middle',[False]*3,[True,False,True]),('all_classical',[True]*3,[True]*3)]
    with tempfile.TemporaryDirectory(prefix='pqc-evidence-') as td:
        crt,key=old.make_cert(Path(td),a.openssl)
        rows=[]
        for name,flags,visible in cases:
            row=run_case(name,flags,visible,crt,key);rows.append(row)
            print(name,row['application_groups'],row['evidence_verdict'],flush=True)
    (out/'session_evidence.json').write_text(json.dumps({'python_openssl':ssl.OPENSSL_VERSION,
     'scope':'Application-session negotiated groups decoded from in-process TLS1.3 ServerHello messages',
     'limitations':['CPython private _msg_callback requires validation/portability assessment',
     'Group authentication is not established; lab certificate verification disabled',
     'Request correlation uses trusted instrumented lab application receipts',
     'Full per-hop observation remains decisive and is a stronger baseline'], 'cases':rows},indent=2))
    with (out/'summary.csv').open('w',newline='') as f:
        w=csv.DictWriter(f,fieldnames=['case','ground_truth','evidence_verdict','edge_only','full_per_hop']);w.writeheader()
        for row in rows:w.writerow({k:row[k] for k in w.fieldnames})
    print('PASS:',len(rows),'live forwarded requests; all actual application-session TLS negotiated groups captured')
if __name__=='__main__':main()
