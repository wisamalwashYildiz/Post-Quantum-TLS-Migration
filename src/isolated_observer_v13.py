#!/usr/bin/env python3
"""v1.3: distinct TLS-terminating observer process, application report simulation.

The observer owns the TLS endpoint and the signing key. The forwarding reporter
cannot read the observer signing key in the experiment's capability model.
OS-level protection against same-user debugging or root is NOT claimed.
"""
import argparse
import copy
import json
import multiprocessing as mp
import os
import secrets
import shutil
import socket
import ssl
import tempfile
from pathlib import Path

try:
    import live_path as lp
    import session_chain_v11 as v11
except ImportError:
    from . import live_path as lp
    from . import session_chain_v11 as v11

OBSERVER = 'isolated:receiver'
REPORTER = 'forwarder'


def verify_batch(transactions, reports, witnesses, report_keys, observer_keys, *, require_complete=True, ledger=None):
    """Independent verifier for a single observed TLS endpoint with connection reuse.

    Trust contract: observer truly terminates TLS, records each received payload,
    and its signing key remains outside the attacker's control.
    A return value is about the recorded TLS leg only, NOT the entire service path.
    """
    if len(transactions) != len(reports) or len(transactions) != len(witnesses):
        return 'UNRESOLVED', 'incomplete report/witness set'
    if not transactions:
        return 'UNRESOLVED', 'no transactions'
    fresh = set()
    sessions = set()
    groups = []
    observed_ledger = set() if ledger is None else ledger
    for index, (tx, report, witness) in enumerate(zip(transactions, reports, witnesses)):
        if not isinstance(tx, dict) or not isinstance(tx.get('nonce'), str) or not tx['nonce']:
            return 'INVALID', 'missing transaction nonce'
        if tx['nonce'] in fresh or tx['nonce'] in observed_ledger:
            return 'INVALID', 'nonce replay or duplicate'
        fresh.add(tx['nonce'])
        if not v11.verify_seal(report, report_keys) or report['node'] != REPORTER:
            return 'INVALID', 'bad forwarding report'
        if not v11.verify_seal(witness, observer_keys) or witness['node'] != OBSERVER:
            return 'INVALID', 'bad observer witness'
        r, w, h = report['body'], witness['body'], v11.digest(tx)
        if w.get('sequence') != index:
            return 'INVALID', 'observer transaction sequence mismatch'
        if r.get('transaction_hash') != h or w.get('transaction_hash') != h:
            return 'INVALID', 'transaction binding mismatch'
        if r.get('observed_tls') != w.get('observed_tls'):
            return 'INVALID', 'forwarder assertion contradicts independent TLS endpoint'
        ss = w.get('observed_tls')
        if not isinstance(ss, dict) or not isinstance(ss.get('session_label'), str):
            return 'UNRESOLVED', 'incomplete handshake observation'
        if 'group' not in ss:
            return 'UNRESOLVED', 'unknown TLS group'
        sessions.add(ss['session_label'])
        groups.append(ss['group'])
    if require_complete and len(sessions) != 1:
        return 'INVALID', 'expected one reused TLS connection'
    if v11.CLASSIC in groups:
        return 'VIOLATED', 'classical TLS session observed by independent endpoint'
    if all(g == v11.HYBRID for g in groups):
        return 'SATISFIED', 'all transactions arrived over observed hybrid TLS connection'
    return 'UNRESOLVED', 'unsupported negotiated group'


def report_only(transactions, reports, keys):
    if len(transactions) != len(reports):
        return 'UNRESOLVED', 'missing forwarding reports'
    groups = []
    for tx, rec in zip(transactions, reports):
        if not v11.verify_seal(rec, keys) or rec['node'] != REPORTER or rec['body'].get('transaction_hash') != v11.digest(tx):
            return 'INVALID', 'forwarder report authentication or binding failed'
        groups.append(rec['body']['observed_tls']['group'])
    if v11.CLASSIC in groups:
        return 'VIOLATED', 'forwarder claims classical TLS'
    if all(g == v11.HYBRID for g in groups):
        return 'SATISFIED', 'forwarder claims hybrid TLS (unverified)'
    return 'UNRESOLVED', 'unknown group'


def observer_worker(conn, cert, private, classic, count):
    """Observer owns endpoint and key. Never sends its signing key to reporter."""
    try:
        key = secrets.token_bytes(32)
        ctx, tracker = v11.tls_context(cert=cert, key=private, classic=classic)
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as listener:
            listener.bind(('127.0.0.1', 0)); listener.listen(1)
            conn.send({'status':'ready','port':listener.getsockname()[1]})
            raw, _ = listener.accept()
            raw.settimeout(12)
            with ctx.wrap_socket(raw, server_side=True) as tls:
                session = tracker.evidence(tls)
                witnesses = []
                for seq in range(count):
                    payload = lp.read_json(tls)
                    if payload.get('kind') != 'application' or not isinstance(payload.get('transaction'), dict):
                        raise RuntimeError('invalid application payload')
                    tx = payload['transaction']
                    witnesses.append(v11.seal({'transaction_hash':v11.digest(tx),
                          'observed_tls':session, 'sequence':seq}, OBSERVER, {OBSERVER:key}))
                    lp.send_json(tls, {'transaction_hash':v11.digest(tx),'status':'observed','sequence':seq})
                tracker.forget(tls)
        # Key is delivered ONLY to the parent independent verifier, not to the
        # (simulated, potentially compromised) forwarding reporting role.
        conn.send({'status':'complete','witnesses':witnesses,'observer_key':key.hex()})
    except Exception as exc:
        try:conn.send({'status':'error','message':str(exc)})
        except Exception:pass
    finally:
        conn.close()


def collect_live(cert, private, classic=False, count=3):
    if count < 2:
        raise ValueError('count >= 2 required to exercise TLS connection reuse')
    receive, send = mp.Pipe(duplex=True)
    process = mp.Process(target=observer_worker, args=(send,str(cert),str(private),classic,count), daemon=True)
    process.start(); send.close()
    try:
        if not receive.poll(15):raise RuntimeError('observer failed to start')
        ready = receive.recv()
        if ready['status'] != 'ready':raise RuntimeError(str(ready))
        ctx, tracker = v11.tls_context(client=True, classic=classic)
        transactions=[]
        with socket.create_connection(('127.0.0.1',ready['port']),timeout=12) as sock:
            with ctx.wrap_socket(sock,server_hostname='localhost') as tls:
                outbound = tracker.evidence(tls)
                for seq in range(count):
                    tx = {'nonce':secrets.token_hex(16),'data':f'v1.3 message {seq}'}
                    transactions.append(tx)
                    lp.send_json(tls, {'kind':'application','transaction':tx})
                    response = lp.read_json(tls)
                    if response != {'transaction_hash':v11.digest(tx),'status':'observed','sequence':seq}:
                        raise RuntimeError('unexpected reply')
                tracker.forget(tls)
        if not receive.poll(15): raise RuntimeError('observer did not complete')
        result=receive.recv()
        if result['status'] != 'complete':raise RuntimeError(str(result))
        witnesses=result['witnesses']
        if any(w['body']['observed_tls']!=outbound for w in witnesses):
            raise RuntimeError('client and independent receiver TLS observations differ')
        return transactions,witnesses,bytes.fromhex(result['observer_key'])
    finally:
        receive.close();process.join(4)
        if process.is_alive():process.terminate();process.join(2)
        if process.exitcode not in (0,None):raise RuntimeError(f'observer exit={process.exitcode}')


def forge_reports(reports, report_key):
    forged=copy.deepcopy(reports)
    for item in forged:
        item['body']['observed_tls']['group']=v11.HYBRID
        item.update(v11.seal(item['body'], REPORTER, {REPORTER:report_key}))
    return forged


def main():
    ap=argparse.ArgumentParser()
    ap.add_argument('--openssl',default=shutil.which('openssl'))
    ap.add_argument('--output',default='results/isolated_observer_v13')
    ap.add_argument('--count',type=int,default=3)
    args=ap.parse_args()
    if ssl.OPENSSL_VERSION_INFO[:2] < (3,5):raise SystemExit('Python must use OpenSSL >=3.5')
    if args.count<2:raise SystemExit('--count must be >= 2')
    out=Path(args.output);out.mkdir(parents=True,exist_ok=True)
    report_key=secrets.token_bytes(32)
    with tempfile.TemporaryDirectory(prefix='pqc-v13-') as tmp:
        cert,private=lp.make_cert(Path(tmp),args.openssl)
        txs,good_wit,good_key=collect_live(cert,private,count=args.count)
        c_txs,c_wit,c_key=collect_live(cert,private,classic=True,count=args.count)
    def make_reports(txs,wits):
        return [v11.seal({'transaction_hash':v11.digest(t),'observed_tls':copy.deepcopy(w['body']['observed_tls'])},REPORTER,{REPORTER:report_key}) for t,w in zip(txs,wits)]
    good_reports=make_reports(txs,good_wit)
    classical_reports=make_reports(c_txs,c_wit)
    fake=forge_reports(classical_reports,report_key)
    def check(tx, reports, witnesses, key):
        return verify_batch(tx,reports,witnesses,{REPORTER:report_key},{OBSERVER:key})
    checks={
        'valid':check(txs,good_reports,good_wit,good_key),
        'classical':check(c_txs,classical_reports,c_wit,c_key),
        'forged_report_only':report_only(c_txs,fake,{REPORTER:report_key}),
        'forged_corroborated':check(c_txs,fake,c_wit,c_key),
        'missing_witness':check(c_txs,classical_reports,c_wit[:-1],c_key),
        'reused_witness':check(txs+[txs[0]],good_reports+[good_reports[0]],good_wit+[good_wit[0]],good_key),
        'substituted_witness':check(c_txs,classical_reports,good_wit,good_key),
    }
    expected={'valid':'SATISFIED','classical':'VIOLATED','forged_report_only':'SATISFIED',
              'forged_corroborated':'INVALID','missing_witness':'UNRESOLVED',
              'reused_witness':'INVALID','substituted_witness':'INVALID'}
    for name,status in expected.items():
        if checks[name][0]!=status:raise AssertionError(f'{name}: {checks[name]} expected {status}')
    data={'version':'1.3','model':'separate TLS-terminating observer process; no OS-user isolation or attestation',
          'openssl':ssl.OPENSSL_VERSION,'transactions_per_connection':args.count,
          'valid':{'transactions':txs,'reports':good_reports,'witnesses':good_wit},
          'classical':{'transactions':c_txs,'reports':classical_reports,'witnesses':c_wit},
          'forged':{'transactions':c_txs,'reports':fake,'witnesses':c_wit},
          'checks':checks,
          'limitations':['Single TLS leg only; not complete multi-hop path assurance',
              'Observer process owns TLS termination; not passive network observation',
              'Same OS user can potentially inspect peer process or its memory',
              'No hardware attestation, TPM, separate identity, or anti-root assurance',
              'Reporter compromise simulated by re-signing with its authorized reporting key',
              'TLS handshake random hash is a public correlation label, not a channel binding',
              'Transactions originated at client, not independently verified forwarding provenance',
              'TLS 1.3 key exchange only; self-signed lab certificates, no PQ authentication']}
    (out/'isolated_observer.json').write_text(json.dumps(data,indent=2))
    # Lab-only verifier secret, separate from public evidence JSON.
    path=out/'lab_verifier_keys.json'
    path.write_text(json.dumps({'report_key':report_key.hex(),'valid_observer_key':good_key.hex(),
                                'classical_observer_key':c_key.hex()},indent=2))
    path.chmod(0o600)
    for name,value in checks.items():print(name,value[0],'-',value[1])
    print('PASS: separate-process TLS endpoint and connection-reuse checks')

if __name__=='__main__':main()
