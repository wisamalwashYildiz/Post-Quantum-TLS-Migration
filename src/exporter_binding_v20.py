#!/usr/bin/env python3
"""v2.0 first security gate: TLS 1.3 exporter proof, actual peer equality.

This is a NEW TLS session executed by pyOpenSSL, distinct from the archived
three-hop evidence. A session-bound MAC proves knowledge of exported material
but not transaction forwarding or the negotiated KEM group. Lab-only certs.
"""
import argparse, hashlib, hmac, json, secrets, socket, ssl, tempfile, threading, shutil, select, time
from pathlib import Path

LABEL=b'EXPORTER-pqc-path-assurance-v2'

def canonical(x):
    return json.dumps(x,sort_keys=True,separators=(',',':')).encode()

def mac(exporter, transaction):
    return hmac.new(exporter,canonical(transaction),hashlib.sha256).hexdigest()

def verify(transaction, client_proof, server_proof, *, expected_id=None, ledger=None):
    if not isinstance(transaction,dict) or not isinstance(transaction.get('nonce'),str):
        return 'INVALID','malformed transaction'
    if not isinstance(client_proof,dict) or not isinstance(server_proof,dict):
        return 'UNRESOLVED','missing peer proof'
    if expected_id is not None and transaction['nonce']!=expected_id:
        return 'INVALID','unexpected transaction'
    if ledger is not None and transaction['nonce'] in ledger:
        return 'INVALID','previously accepted nonce'
    ch=hashlib.sha256(canonical(transaction)).hexdigest()
    if client_proof.get('transaction_hash')!=ch or server_proof.get('transaction_hash')!=ch:
        return 'INVALID','transaction substitution'
    for p in (client_proof,server_proof):
        if p.get('protocol')!='TLSv1.3' or not isinstance(p.get('proof'),str):
            return 'INVALID','invalid peer record'
    if not hmac.compare_digest(client_proof['proof'],server_proof['proof']):
        return 'INVALID','TLS exporter peer disagreement'
    if not client_proof['proof']:
        return 'INVALID','empty exporter proof'
    return 'BOUND','matching exporter-derived proofs; requires independent trusted provenance'

def _ctx(server=False,cert=None,key=None):
    from OpenSSL import SSL
    c=SSL.Context(SSL.TLS_METHOD)
    c.set_min_proto_version(SSL.TLS1_3_VERSION)
    c.set_max_proto_version(SSL.TLS1_3_VERSION)
    if server:
        c.use_certificate_file(str(cert));c.use_privatekey_file(str(key));c.check_privatekey()
    else:
        # This laboratory's self-signed cert is NOT authenticated by a trust store.
        c.set_verify(SSL.VERIFY_NONE,lambda *_:True)
    return c

def _io(conn, method, *args):
    from OpenSSL import SSL
    stop=time.monotonic()+12
    while True:
        try: return method(*args)
        except (SSL.WantReadError,SSL.WantWriteError) as err:
            if time.monotonic()>stop:raise TimeoutError('TLS I/O timed out') from err
            if isinstance(err,SSL.WantReadError):select.select([conn],[],[],.5)
            else:select.select([],[conn],[],.5)

def _read_exact(conn,length):
    out=b''
    while len(out)<length:
        chunk=_io(conn,conn.recv,length-len(out))
        if not chunk:raise RuntimeError('peer closed early')
        out+=chunk
    return out

def _send(conn, data):
    frame=len(data).to_bytes(4,'big')+data
    while frame:
        n=_io(conn,conn.send,frame)
        if n<=0:raise RuntimeError('TLS send failed')
        frame=frame[n:]

def _recv(conn):
    length=int.from_bytes(_read_exact(conn,4),'big')
    if length<=0 or length>100000:raise ValueError('bad frame length')
    return _read_exact(conn,length)

def _peer(conn,tx):
    exporter=conn.export_keying_material(LABEL,32,bytes.fromhex(tx['nonce']))
    return {'protocol':conn.get_protocol_version_name(),
            'transaction_hash':hashlib.sha256(canonical(tx)).hexdigest(),
            'proof':mac(exporter,tx)}

def run_live(cert,key,tx):
    from OpenSSL import SSL
    holder={}
    ready=threading.Event()
    listener=socket.socket();listener.bind(('127.0.0.1',0));listener.listen(1)
    port=listener.getsockname()[1]
    def worker():
        try:
            sock,_=listener.accept()
            with sock:
                c=SSL.Connection(_ctx(server=True,cert=cert,key=key),sock)
                c.set_accept_state();_io(c,c.do_handshake)
                received=json.loads(_recv(c).decode())
                if received != tx:raise RuntimeError('server transaction mismatch')
                holder['server']=_peer(c,received)
                _send(c,canonical({'ok':True}))
        except Exception as ex:holder['error']=repr(ex)
        finally:ready.set();listener.close()
    t=threading.Thread(target=worker,daemon=True);t.start()
    with socket.create_connection(('127.0.0.1',port),timeout=10) as sock:
        c=SSL.Connection(_ctx(),sock);c.set_connect_state();c.set_tlsext_host_name(b'localhost');_io(c,c.do_handshake)
        client=_peer(c,tx)
        _send(c,canonical(tx))
        reply=json.loads(_recv(c).decode())
        if reply!={'ok':True}:raise RuntimeError('invalid application response')
    t.join(10)
    if t.is_alive():raise RuntimeError('server thread stalled')
    if 'error' in holder:raise RuntimeError(holder['error'])
    return client,holder['server']

def main():
    ap=argparse.ArgumentParser()
    ap.add_argument('--openssl',default=shutil.which('openssl'))
    ap.add_argument('--output',default='results/exporter_binding_v20')
    args=ap.parse_args()
    import OpenSSL
    from OpenSSL import SSL
    print('pyOpenSSL',OpenSSL.__version__, 'Python SSL',ssl.OPENSSL_VERSION)
    if ssl.OPENSSL_VERSION_INFO[:2]<(3,5):raise SystemExit('Python SSL >= 3.5 needed for existing research environment')
    out=Path(args.output);out.mkdir(parents=True,exist_ok=True)
    try:
        import live_path as lp
    except ImportError:
        from . import live_path as lp
    tx={'nonce':secrets.token_hex(16),'data':'v2.0 exporter-bound real TLS session'}
    with tempfile.TemporaryDirectory(prefix='pqc-exporter-v20-') as d:
        cert,key=lp.make_cert(Path(d),args.openssl)
        c,s=run_live(cert,key,tx)
    good=verify(tx,c,s)
    substitute=dict(s);substitute['proof']='0'*64
    adversarial=verify(tx,c,substitute)
    modified=dict(tx);modified['data']='substituted'
    tx_attack=verify(modified,c,s)
    replay=verify(tx,c,s,ledger={tx['nonce']})
    missing=verify(tx,c,None)
    cloned=verify(tx,c,dict(c))  # a copied proof passes: provenance is NOT established
    cases={'same_session':good,'substituted_peer':adversarial,'changed_transaction':tx_attack,'replayed_transaction':replay,'missing_peer':missing,'cloned_proof_limitation':cloned}
    expected={'same_session':'BOUND','substituted_peer':'INVALID','changed_transaction':'INVALID','replayed_transaction':'INVALID','missing_peer':'UNRESOLVED','cloned_proof_limitation':'BOUND'}
    for k,v in cases.items():
        print(k,v[0],'-',v[1])
        if v[0]!=expected[k]:raise AssertionError((k,v))
    data={'version':'2.0 exporter pilot','source':'new live TLS 1.3 session via pyOpenSSL', 'transaction':tx,
          'client_proof':c,'server_proof':s,'checks':cases,
          'limitations':['One TLS leg; not multi-hop transaction-path proof',
                         'Peer exporter equality attests a shared TLS session secret, not truthful forwarding',
                         'Does not independently confirm hybrid KEM on THIS pyOpenSSL session',
                         'Lab self-signed X.509 certificate is not verified against a trust store',
                         'No OS isolation; observer and client in same test process',
                         'Proofs are HMACs of same transaction under exporter secret; not TLS exporter value itself',
                         'CRITICAL: copied client proof passes as fake server proof: no authenticated independent endpoint provenance',
                         'No external replay ledger implemented; verifier takes an optional ledger']}
    (out/'exporter_binding.json').write_text(json.dumps(data,indent=2))
    print('PASS: live exporter peer equality; experimental v2.0 binding gate')
if __name__=='__main__':main()
