#!/usr/bin/env python3
"""v1.2 laboratory receiver-side TLS corroboration (not trusted hardware).

Receiver-side observations are sealed with an observer-specific key separate from
forwarder-report keys. Assumes observer instrumentation and its key are honest.
This does not establish truth against compromise of the observer or its process.
"""
import argparse
import copy
import json
import secrets
import shutil
import socket
import ssl
import tempfile
from pathlib import Path

try:
    import session_chain_v11 as v11
    import live_path as lp
except ImportError:
    from . import session_chain_v11 as v11
    from . import live_path as lp

NODES = ('gateway', 'service-a', 'backend')


def receiver_witness(body, node, observer_keys):
    """Evidence from TLS *receiving* endpoint, not from upstream relay report."""
    return v11.seal({'transaction_hash': body['transaction_hash'],
                     'in': body['in']}, 'observer:' + node, observer_keys)


def verify_corroborated(transaction, client, receipts, witnesses, node_keys, observer_keys):
    base = v11.verify_chain(transaction, client, receipts, node_keys, nodes=NODES)
    if base[0] in ('INVALID', 'UNRESOLVED'):
        return base
    if len(witnesses) != len(NODES):
        return 'UNRESOLVED', 'missing receiver observation'
    observed_groups = []
    expected_hash = v11.digest(transaction)
    seen = set()
    for node, report, witness in zip(NODES, receipts, witnesses):
        name = 'observer:' + node
        if not v11.verify_seal(witness, observer_keys) or witness['node'] != name or name in seen:
            return 'INVALID', 'invalid or duplicate receiver observation'
        seen.add(name)
        b = witness['body']
        if b.get('transaction_hash') != expected_hash:
            return 'INVALID', 'receiver transaction mismatch'
        if b.get('in') != report['body'].get('in'):
            return 'INVALID', 'receiver-observed TLS session differs from relay assertion'
        observed_groups.append(b['in'].get('group'))
    if v11.CLASSIC in observed_groups:
        return 'VIOLATED', 'classical group confirmed by receiver observer'
    if all(x == v11.HYBRID for x in observed_groups):
        return 'SATISFIED', 'receiver-corroborated hybrid sessions (trusted observer model)'
    return 'UNRESOLVED', 'unclassified receiver handshake'


class WitnessRelay(v11.Relay):
    def __init__(self, name, cert, key, keys, observer_keys, classic=False, downstream=None):
        self.observer_keys = observer_keys
        self.witnesses = []
        super().__init__(name, cert, key, keys, classic, downstream)

    def process(self, raw):
        try:
            raw.settimeout(12)
            with self.ctx.wrap_socket(raw, server_side=True) as incoming:
                inc = self.tracker.evidence(incoming)
                payload = lp.read_json(incoming)
                if payload.get('kind') != 'application':
                    return
                tx = payload['transaction']
                body = {'transaction_hash': v11.digest(tx), 'in': inc, 'out': None,
                        'target': self.downstream.name if self.downstream else None}
                if self.downstream:
                    ctx, tracker = v11.tls_context(client=True, classic=self.downstream.classic)
                    with socket.create_connection(('127.0.0.1', self.downstream.port), timeout=12) as sock:
                        with ctx.wrap_socket(sock, server_hostname='localhost') as outgoing:
                            body['out'] = tracker.evidence(outgoing)
                            lp.send_json(outgoing, payload)
                            response = lp.read_json(outgoing)
                            tracker.forget(outgoing)
                else:
                    response = {'transaction_hash': v11.digest(tx), 'status': 'ok'}
                # The receiver's local TLS tracker is the observer. Separate keys
                # model separated trust roles; this is NOT an isolated process.
                self.witnesses.append(receiver_witness(body, self.name, self.observer_keys))
                self.receipts.append(v11.seal(body, self.name, self.keys))
                lp.send_json(incoming, response)
                self.tracker.forget(incoming)
        except Exception as exc:
            self.errors.append(type(exc).__name__ + ': ' + str(exc))
            try:
                raw.close()
            except OSError:
                pass


def run_live(cert, private, keys, observers, classical_middle=False):
    backend = WitnessRelay('backend', cert, private, keys, observers)
    service = WitnessRelay('service-a', cert, private, keys, observers, classical_middle, backend)
    gateway = WitnessRelay('gateway', cert, private, keys, observers, False, service)
    nodes = [gateway, service, backend]
    try:
        tx = {'nonce': secrets.token_hex(16), 'data': 'v1.2 observed forwarding test'}
        ctx, tracker = v11.tls_context(client=True)
        with socket.create_connection(('127.0.0.1', gateway.port), timeout=12) as sock:
            with ctx.wrap_socket(sock, server_hostname='localhost') as outgoing:
                session = tracker.evidence(outgoing)
                lp.send_json(outgoing, {'kind': 'application', 'transaction': tx})
                response = lp.read_json(outgoing)
                tracker.forget(outgoing)
        if response != {'transaction_hash': v11.digest(tx), 'status': 'ok'}:
            raise RuntimeError('unexpected backend response')
        for node in nodes:
            if node.errors or len(node.receipts) != 1 or len(node.witnesses) != 1:
                raise RuntimeError(f'{node.name}: errors={node.errors}, receipts={len(node.receipts)}, witnesses={len(node.witnesses)}')
        client = v11.seal({'transaction_hash': v11.digest(tx), 'out': session}, 'client', keys)
        receipts = [node.receipts[0] for node in nodes]
        witnesses = [node.witnesses[0] for node in nodes]
        return tx, client, receipts, witnesses
    finally:
        for node in nodes:
            node.close()


def forge_middle_hybrid(receipts, keys):
    """Simulates compromise of BOTH process report keys bordering middle leg."""
    items = copy.deepcopy(receipts)
    for idx, field in ((0, 'out'), (1, 'in')):
        items[idx]['body'][field]['group'] = v11.HYBRID
        items[idx] = v11.seal(items[idx]['body'], NODES[idx], keys)
    return items


def main():
    p = argparse.ArgumentParser()
    p.add_argument('--openssl', default=shutil.which('openssl'))
    p.add_argument('--output', default='results/trust_boundary_v12')
    args = p.parse_args()
    if ssl.OPENSSL_VERSION_INFO[:2] < (3, 5):
        raise SystemExit('Python must use OpenSSL 3.5 or newer')
    out = Path(args.output)
    out.mkdir(parents=True, exist_ok=True)
    keys = {node: secrets.token_bytes(32) for node in ('client',) + NODES}
    observers = {'observer:' + node: secrets.token_bytes(32) for node in NODES}
    with tempfile.TemporaryDirectory(prefix='pqc-v12-') as tmp:
        cert, private = lp.make_cert(Path(tmp), args.openssl)
        tx, client, receipts, witnesses = run_live(cert, private, keys, observers)
        good = verify_corroborated(tx, client, receipts, witnesses, keys, observers)
        if good[0] != 'SATISFIED':
            raise AssertionError(good)
        c_tx, c_client, c_receipts, c_witnesses = run_live(cert, private, keys, observers, classical_middle=True)
    classical = verify_corroborated(c_tx, c_client, c_receipts, c_witnesses, keys, observers)
    if classical[0] != 'VIOLATED':
        raise AssertionError(classical)
    forged = forge_middle_hybrid(c_receipts, keys)
    legacy = v11.verify_chain(c_tx, c_client, forged, keys)
    corroborated = verify_corroborated(c_tx, c_client, forged, c_witnesses, keys, observers)
    missing = verify_corroborated(c_tx, c_client, forged, c_witnesses[:2], keys, observers)
    mutated = copy.deepcopy(c_witnesses)
    mutated[1]['body']['in']['session_label'] = '0' * 64
    tampered = verify_corroborated(c_tx, c_client, forged, mutated, keys, observers)
    if legacy[0] != 'SATISFIED' or corroborated[0] != 'INVALID' or missing[0] != 'UNRESOLVED' or tampered[0] != 'INVALID':
        raise AssertionError((legacy, corroborated, missing, tampered))
    evidence = {'version': '1.2', 'model': 'trusted receiver observer instrumentation, distinct signing keys; same host process',
                'python_openssl': ssl.OPENSSL_VERSION, 'valid': {'transaction': tx, 'client': client, 'receipts': receipts, 'witnesses': witnesses},
                'classical': {'transaction': c_tx, 'client': c_client, 'receipts': c_receipts, 'witnesses': c_witnesses},
                'forged_classical': {'transaction': c_tx, 'client': c_client, 'receipts': forged, 'witnesses': c_witnesses},
                'checks': {'valid': good, 'classical': classical, 'forged_v11': legacy, 'forged_corroborated': corroborated,
                           'missing_witness': missing, 'modified_witness': tampered},
                'limitations': ['Receiver observer is instrumented IN the receiving relay process: no isolation or hardware attestation',
                                'TLS random hashes label connections but do not prove cryptographic channel binding',
                                'Receiver observer uses same application-provided transaction payload; no independent application-truth source',
                                'A malicious receiving relay can compromise its co-resident observer: not resistant to whole-process compromise',
                                'Separate lab observer keys are not a real deployment key-management architecture',
                                'Single request per TLS session, localhost only; no reuse, replay ledger or multi-host deployment',
                                'Unvalidated lab X.509 certificates; only TLS key exchange evaluated']}
    (out / 'trust_boundary.json').write_text(json.dumps(evidence, indent=2))
    secret_path = out / 'lab_keys.json'
    secret_path.write_text(json.dumps({'node_keys': {k: v.hex() for k,v in keys.items()},
                                       'observer_keys': {k:v.hex() for k,v in observers.items()}}, indent=2))
    secret_path.chmod(0o600)
    for name, result in evidence['checks'].items():
        print(name, result[0], '-', result[1])
    print('PASS: receiver-side corroboration experiment; observer trust explicitly assumed')

if __name__ == '__main__':
    main()
