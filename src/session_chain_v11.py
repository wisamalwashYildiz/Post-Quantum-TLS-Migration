#!/usr/bin/env python3
"""v1.1 laboratory: independently checked, keyed *process-reported* TLS connection chain.
NOT cryptographic proof of proxy forwarding: monitors/proxy processes and keys are trusted.
TLS key-establishment observed via CPython private SSLContext._msg_callback.
"""
import argparse, hashlib, hmac, json, secrets, socket, ssl, tempfile, threading, shutil
from pathlib import Path

try:
    import live_path as lp
    import session_evidence as se
except ImportError:
    from . import live_path as lp, session_evidence as se

HYBRID, CLASSIC = 'X25519MLKEM768', 'X25519'


def canonical(obj):
    return json.dumps(obj, sort_keys=True, separators=(',', ':'), ensure_ascii=True).encode()


def digest(obj):
    return hashlib.sha256(canonical(obj)).hexdigest()


def signature(obj, key):
    return hmac.new(key, canonical(obj), hashlib.sha256).hexdigest()


def seal(obj, node, keys):
    return {'node': node, 'body': obj, 'mac': signature({'node': node, 'body': obj}, keys[node])}


def verify_seal(item, keys):
    if not isinstance(item, dict) or item.get('node') not in keys or not isinstance(item.get('body'), dict):
        return False
    expected = signature({'node': item['node'], 'body': item['body']}, keys[item['node']])
    return isinstance(item.get('mac'), str) and hmac.compare_digest(item['mac'], expected)


class HandshakeTracker:
    """Tracks ClientHello and ServerHello random from the actual TLS handshake.
    SHA256 of public randoms is a connection correlation *label*, NOT a channel binding.
    """
    def __init__(self):
        self._lock = threading.Lock()
        self._state = {}

    def cb(self, conn, direction, version, content_type, msg_type, data):
        t = int(msg_type)
        if t not in (1, 2):
            return
        d = bytes(data)
        if len(d) >= 4 and d[0] == t and int.from_bytes(d[1:4], 'big') == len(d)-4:
            d = d[4:]
        if len(d) < 34:
            return
        with self._lock:
            item = self._state.setdefault(id(conn), {})
            if t == 1:
                item['client_random'] = d[2:34].hex()
            else:
                item['server_random'] = d[2:34].hex()
                item['group'] = se.decode_server_hello(bytes(data))

    def evidence(self, conn):
        with self._lock:
            v = self._state.get(id(conn), {}).copy()
        if not v.get('client_random') or not v.get('server_random'):
            raise RuntimeError('missing handshake randoms')
        v['session_label'] = hashlib.sha256(bytes.fromhex(v['client_random']+v['server_random'])).hexdigest()
        v.pop('client_random')
        v.pop('server_random')
        return v

    def forget(self, conn):
        with self._lock:
            self._state.pop(id(conn), None)


def tls_context(cert=None, key=None, classic=False, client=False):
    ctx = lp.context_client(classic) if client else lp.context_server(cert, key, classic)
    tracker = HandshakeTracker()
    ctx._msg_callback = tracker.cb
    return ctx, tracker


class Relay:
    def __init__(self, name, cert, key, keys, classic=False, downstream=None):
        self.name, self.keys, self.downstream = name, keys, downstream
        self.classic = classic
        self.receipts, self.errors, self.threads = [], [], []
        self.ctx, self.tracker = tls_context(cert, key, classic)
        self.server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.server.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        self.server.bind(('127.0.0.1', 0))
        self.port = self.server.getsockname()[1]
        self.server.listen(32)
        self.server.settimeout(.2)
        self.done = threading.Event()
        self.thread = threading.Thread(target=self.serve, daemon=True)
        self.thread.start()

    def serve(self):
        while not self.done.is_set():
            try:
                raw, _ = self.server.accept()
            except socket.timeout:
                continue
            except OSError:
                break
            t = threading.Thread(target=self.process, args=(raw,), daemon=True)
            self.threads.append(t)
            t.start()

    def process(self, raw):
        try:
            raw.settimeout(12)
            with self.ctx.wrap_socket(raw, server_side=True) as incoming:
                inc = self.tracker.evidence(incoming)
                payload = lp.read_json(incoming)
                if payload.get('kind') != 'application':
                    return
                transaction = payload['transaction']
                body = {'transaction_hash': digest(transaction), 'in': inc, 'out': None,
                        'target': self.downstream.name if self.downstream else None}
                if self.downstream:
                    ctx, tracker = tls_context(client=True, classic=self.downstream.classic)
                    with socket.create_connection(('127.0.0.1', self.downstream.port), timeout=12) as sock:
                        with ctx.wrap_socket(sock, server_hostname='localhost') as outbound:
                            body['out'] = tracker.evidence(outbound)
                            lp.send_json(outbound, payload)
                            response = lp.read_json(outbound)
                            tracker.forget(outbound)
                else:
                    response = {'transaction_hash': digest(transaction), 'status': 'ok'}
                self.receipts.append(seal(body, self.name, self.keys))
                lp.send_json(incoming, response)
                self.tracker.forget(incoming)
        except Exception as exc:
            self.errors.append(type(exc).__name__ + ': ' + str(exc))
            try: raw.close()
            except OSError: pass

    def close(self):
        self.done.set()
        self.server.close()
        self.thread.join(2)
        for t in self.threads:
            t.join(15)


def verify_chain(transaction, client_receipt, receipts, keys, nodes=('gateway','service-a','backend')):
    """Zero trust for supplied receipt CONTENT; explicitly trusts node HMAC keys and processes.
    Replays can be rejected only with an external nonce registry/transaction ledger.
    """
    if not verify_seal(client_receipt, keys) or client_receipt['node'] != 'client':
        return 'INVALID', 'client receipt signature'
    if len(receipts) != len(nodes):
        return 'UNRESOLVED', 'missing node evidence'
    expected_hash = digest(transaction)
    seen = set()
    prior = client_receipt['body'].get('out')
    if not isinstance(prior, dict) or client_receipt['body'].get('transaction_hash') != expected_hash:
        return 'INVALID', 'client evidence/transaction mismatch'
    groups = []
    for index, (name, rec) in enumerate(zip(nodes, receipts)):
        if not verify_seal(rec, keys) or rec['node'] != name or name in seen:
            return 'INVALID', 'bad/duplicate node evidence'
        seen.add(name)
        b = rec['body']
        if b.get('transaction_hash') != expected_hash:
            return 'INVALID', 'transaction substitution'
        inc = b.get('in')
        if not isinstance(inc, dict) or not isinstance(prior, dict) or inc != prior:
            return 'INVALID', 'TLS session substitution or missing handshake'
        if b.get('target') != (nodes[index+1] if index+1 < len(nodes) else None):
            return 'INVALID', 'wrong forwarding target'
        groups.append(inc.get('group'))
        prior = b.get('out')
        if index+1 < len(nodes) and not isinstance(prior, dict):
            return 'UNRESOLVED', 'missing downstream session evidence'
    if prior is not None:
        return 'INVALID', 'unexpected extra forwarding session'
    if CLASSIC in groups:
        return 'VIOLATED', 'classical group observed on linked session'
    if all(g == HYBRID for g in groups):
        return 'SATISFIED', 'hybrid groups on all linked sessions (trusted process model)'
    return 'UNRESOLVED', 'unknown TLS group'


def run_one(cert, key, keys, flags):
    backend = Relay('backend', cert, key, keys, flags[2])
    service = Relay('service-a', cert, key, keys, flags[1], backend)
    gateway = Relay('gateway', cert, key, keys, flags[0], service)
    nodes = [gateway, service, backend]
    try:
        transaction = {'nonce': secrets.token_hex(16), 'data': 'experimental TLS path'}
        ctx, tracker = tls_context(client=True, classic=flags[0])
        with socket.create_connection(('127.0.0.1', gateway.port), timeout=12) as sock:
            with ctx.wrap_socket(sock, server_hostname='localhost') as tls:
                client_session = tracker.evidence(tls)
                lp.send_json(tls, {'kind':'application','transaction':transaction})
                response = lp.read_json(tls)
                tracker.forget(tls)
        for node in nodes:
            if node.errors or len(node.receipts) != 1:
                raise RuntimeError(f'node {node.name}: errors={node.errors}, receipts={len(node.receipts)}')
        if response != {'transaction_hash':digest(transaction), 'status':'ok'}:
            raise RuntimeError('invalid response')
        client = seal({'transaction_hash': digest(transaction),'out':client_session},'client',keys)
        receipts = [n.receipts[0] for n in nodes]
        result = verify_chain(transaction, client, receipts, keys)
        return transaction, client, receipts, result
    finally:
        for node in nodes: node.close()


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('--openssl', default=shutil.which('openssl'))
    parser.add_argument('--output', default='results/session_chain_v11')
    args = parser.parse_args()
    if ssl.OPENSSL_VERSION_INFO[:2] < (3,5):
        raise SystemExit('Requires Python ssl linked to OpenSSL >= 3.5')
    if not args.openssl:
        raise SystemExit('OpenSSL binary missing')
    out = Path(args.output)
    out.mkdir(parents=True, exist_ok=True)
    keys = {n:secrets.token_bytes(32) for n in ['client','gateway','service-a','backend']}
    with tempfile.TemporaryDirectory(prefix='pqc-v11-') as directory:
        cert, private = lp.make_cert(Path(directory), args.openssl)
        tx, client, receipts, correct = run_one(cert, private, keys, [False]*3)
        if correct[0] != 'SATISFIED':
            raise AssertionError(correct)
        _, _, _, classical = run_one(cert, private, keys, [False,True,False])
        if classical[0] != 'VIOLATED':
            raise AssertionError(classical)
    import copy
    substitutions = copy.deepcopy(receipts)
    substitutions[1]['body']['in']['session_label'] = '0'*64
    altered = verify_chain(tx, client, substitutions, keys)
    omission = verify_chain(tx, client, receipts[:2], keys)
    fresh = dict(tx, nonce=secrets.token_hex(16))
    replay = verify_chain(fresh, client, receipts, keys)
    evidence = {'version':'1.1','python_openssl':ssl.OPENSSL_VERSION,'transaction':tx,
                'client':client,'node_receipts':receipts,
                'checks':{'valid':correct, 'classical_middle':classical,
                          'modified_receipt':altered,'missing_receipt':omission,'different_nonce':replay},
                'limitations':['HMAC receipts authenticate only instrumented lab processes, not forwarding truth',
                    'Handshake random digest is a public correlation label, NOT a TLS exporter/channel binding',
                    'In-process TLS callbacks are private CPython API and not tamper-resistant',
                    'No certificate validation / no post-quantum authentication',
                    'Independent verifier requires separately provisioned secret keys',
                    'Replay of same unchanged transaction needs a persistent external nonce registry',
                    'One TLS session per request; connection reuse not evaluated']}
    (out/'session_chain.json').write_text(json.dumps(evidence, indent=2))
    # RESEARCH LAB ONLY: secrets intentionally stored to permit a separate verifier.
    # Do not use this as a secure, publicly portable proof bundle.
    secret_file = out/'lab_verifier_keys.json'
    secret_file.write_text(json.dumps({name: key.hex() for name,key in keys.items()}, indent=2))
    secret_file.chmod(0o600)
    for name, val in evidence['checks'].items(): print(name, val[0], val[1])
    print('PASS: live TLS sessions bound by trusted local process receipts; 5 verification checks')

if __name__ == '__main__': main()
