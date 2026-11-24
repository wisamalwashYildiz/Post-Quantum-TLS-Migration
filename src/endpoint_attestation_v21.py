#!/usr/bin/env python3
"""v2.1: endpoint-origin signed, role-separated TLS-exporter transcript receipts.

Lab security assumptions: trusted per-endpoint Ed25519 private keys, accurate code and
transaction observation. No OS isolation; no PQ signatures, PKI, verified TLS cert or
independent negotiated-group evidence. Does not prove honest forwarding.
"""
import argparse, hashlib, hmac, json, secrets, socket, ssl, tempfile, threading, shutil
from pathlib import Path
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey,Ed25519PublicKey
from cryptography.hazmat.primitives import serialization
try:
    import exporter_binding_v20 as base
except ImportError:
    from . import exporter_binding_v20 as base

SCHEMA='pqc-endpoint-attestation-v2.1'
LABEL=b'EXPORTER-pqc-path-assurance-v2.1'

def digest(x):return hashlib.sha256(base.canonical(x)).hexdigest()

def private_key():return Ed25519PrivateKey.generate()

def pub_hex(sk):return sk.public_key().public_bytes(encoding=serialization.Encoding.Raw,format=serialization.PublicFormat.Raw).hex()

def emit(conn, tx, role, identity, sk):
    if role not in ('initiator','responder'):raise ValueError('role')
    nonce=bytes.fromhex(tx['nonce'])
    secret=conn.export_keying_material(LABEL,32,nonce)
    statement={'schema':SCHEMA,'identity':identity,'role':role,'protocol':conn.get_protocol_version_name(),
               'transaction_hash':digest(tx),'nonce':tx['nonce'],
               'tag':hmac.new(secret,b'PQC-ASSURANCE\x00'+role.encode()+b'\x00'+base.canonical(tx),hashlib.sha256).hexdigest()}
    return {'statement':statement,'signature':sk.sign(base.canonical(statement)).hex()}

def verify(tx, records, expected_public, *, ledger=None):
    """Verify issuer identity, signature, role, and binding shape.

    Offline signatures do NOT independently prove the correctness of a claimed TLS secret;
    proof validity is interpreted under honest key holders and truthful endpoint code.
    """
    if not isinstance(tx,dict) or not isinstance(tx.get('nonce'),str):return 'INVALID','malformed transaction'
    if ledger is not None and tx['nonce'] in ledger:return 'INVALID','previously accepted nonce'
    if not isinstance(records,list) or len(records)<2:return 'UNRESOLVED','missing endpoint statement'
    if len(records)!=2:return 'INVALID','duplicate or extra endpoint statements'
    roles={}
    for rec in records:
        if not isinstance(rec,dict) or not isinstance(rec.get('statement'),dict):return 'INVALID','malformed statement'
        st=rec['statement']; role=st.get('role')
        if role not in ('initiator','responder') or role in roles:return 'INVALID','invalid or repeated role'
        if st.get('schema')!=SCHEMA or st.get('protocol')!='TLSv1.3':return 'INVALID','unexpected schema/protocol'
        if st.get('transaction_hash')!=digest(tx) or st.get('nonce')!=tx['nonce']:return 'INVALID','transaction binding mismatch'
        identity=st.get('identity')
        if identity not in expected_public or identity!=role:return 'INVALID','incorrect endpoint identity'
        try:
            Ed25519PublicKey.from_public_bytes(bytes.fromhex(expected_public[identity])).verify(bytes.fromhex(rec['signature']),base.canonical(st))
        except (ValueError,KeyError,TypeError,Exception) as exc:
            return 'INVALID','invalid endpoint signature'
        if not isinstance(st.get('tag'),str) or len(st['tag'])!=64:return 'INVALID','invalid exporter tag'
        roles[role]=st
    # A verifier cannot derive TLS exporter value without TLS session secret. It can check
    # signed role-separated attestations but cannot independently validate exporter tags.
    # In particular, two arbitrary signed tags are not proof of being on SAME session.
    if roles['initiator']['tag']==roles['responder']['tag']:
        return 'INVALID','role-separated exporter tags unexpectedly identical'
    return 'ATTESTED','both independently signed role-separated claims accepted (trusted endpoint model)'

def run_live(cert,key,tx,sk_client,sk_server):
    from OpenSSL import SSL
    holder={}; listen=socket.socket();listen.bind(('127.0.0.1',0));listen.listen(1);port=listen.getsockname()[1]
    def worker():
        try:
            sock,_=listen.accept()
            with sock:
                c=SSL.Connection(base._ctx(server=True,cert=cert,key=key),sock)
                c.set_accept_state();base._io(c,c.do_handshake)
                incoming=json.loads(base._recv(c).decode())
                if incoming!=tx:raise ValueError('transaction mismatch')
                holder['responder']=emit(c,incoming,'responder','responder',sk_server)
                base._send(c,base.canonical({'ack':digest(incoming)}))
        except Exception as e:holder['error']=repr(e)
        finally:listen.close()
    thread=threading.Thread(target=worker,daemon=True);thread.start()
    with socket.create_connection(('127.0.0.1',port),timeout=10) as sock:
        c=SSL.Connection(base._ctx(),sock);c.set_connect_state();c.set_tlsext_host_name(b'localhost');base._io(c,c.do_handshake)
        initiator=emit(c,tx,'initiator','initiator',sk_client)
        base._send(c,base.canonical(tx))
        if json.loads(base._recv(c).decode())!={'ack':digest(tx)}:raise ValueError('bad ack')
    thread.join(10)
    if thread.is_alive():raise RuntimeError('server stalled')
    if holder.get('error'):raise RuntimeError(holder['error'])
    return [initiator,holder['responder']]

def main():
    import copy
    ap=argparse.ArgumentParser();ap.add_argument('--openssl',default=shutil.which('openssl'))
    ap.add_argument('--output',default='results/endpoint_attestation_v21');args=ap.parse_args()
    try:
        import live_path as lp
    except ImportError:
        from . import live_path as lp
    out=Path(args.output);out.mkdir(parents=True,exist_ok=True)
    tx={'nonce':secrets.token_hex(16),'data':'v2.1 live endpoint-origin attestations'}
    client=private_key();server=private_key();pub={'initiator':pub_hex(client),'responder':pub_hex(server)}
    with tempfile.TemporaryDirectory(prefix='pqc-v21-') as td:
        cert,key=lp.make_cert(Path(td),args.openssl)
        receipts=run_live(cert,key,tx,client,server)
    tests={}
    tests['genuine']=verify(tx,receipts,pub)
    tests['copied_initiator']=verify(tx,[receipts[0],copy.deepcopy(receipts[0])],pub)
    tests['missing_responder']=verify(tx,receipts[:1],pub)
    tampered=copy.deepcopy(receipts);tampered[1]['statement']['tag']='0'*64
    tests['tampered_tag']=verify(tx,tampered,pub)
    wrong=copy.deepcopy(tx);wrong['data']='substituted'
    tests['changed_transaction']=verify(wrong,receipts,pub)
    tests['replay']=verify(tx,receipts,pub,ledger={tx['nonce']})
    wrong_key={'initiator':pub['initiator'],'responder':pub['initiator']}
    tests['wrong_signer']=verify(tx,receipts,wrong_key)
    bogus=copy.deepcopy(receipts)
    bogus[0]['statement']['tag']='1'*64
    bogus[1]['statement']['tag']='2'*64
    bogus[0]['signature']=client.sign(base.canonical(bogus[0]['statement'])).hex()
    bogus[1]['signature']=server.sign(base.canonical(bogus[1]['statement'])).hex()
    tests['dishonest_signers_limitation']=verify(tx,bogus,pub)
    expected={'genuine':'ATTESTED','copied_initiator':'INVALID','missing_responder':'UNRESOLVED','tampered_tag':'INVALID','changed_transaction':'INVALID','replay':'INVALID','wrong_signer':'INVALID','dishonest_signers_limitation':'ATTESTED'}
    for name,result in tests.items():
        print(name,result[0],'-',result[1]);assert result[0]==expected[name],name
    data={'version':'2.1 signed endpoint pilot','openssl':ssl.OPENSSL_VERSION,'source':'new real TLS 1.3 connection, laboratory self-signed certificate',
          'transaction':tx,'public_keys':pub,'receipts':receipts,'checks':tests,
          'limitations':['Ed25519 classical signatures, NOT post-quantum authentication',
                         'Both signing keys exist in one experiment-process address space (separate identities, not independent security domains)',
                         'Authentic signature does NOT independently prove the asserted TLS exporter tag is correct',
                         'Role separation prevents naive cloning but signed claims do NOT prove equal exporter secrets or same TLS session to an offline verifier',
                         'Single connection; no trusted multi-hop forwarding provenance or independently confirmed negotiated hybrid KEX',
                         'TLS certificate not validated against trust store; no external replay ledger',
                         'No signer compromise or compromised endpoint protection']}
    (out/'endpoint_attestation.json').write_text(json.dumps(data,indent=2)+'\n')
    print('PASS: real TLS signed endpoint-claims pilot; not cryptographically independent TLS-session verification')
if __name__=='__main__':main()
