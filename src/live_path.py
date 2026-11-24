#!/usr/bin/env python3
"""Live TLS forwarding path research pilot. Not production code.

Requires Python's ssl linked to OpenSSL >=3.5 for native hybrid defaults.
Independent OpenSSL probes document each listener's negotiated group. The probes
are NOT the application's own sessions, so session-level group assurance is not
claimed here. The application chain itself forwards real TLS request data.
"""
import argparse
import csv
import json
import os
import re
import shutil
import socket
import ssl
import subprocess
import tempfile
import threading
import time
import uuid
from pathlib import Path

HOST = '127.0.0.1'
HYBRID = 'X25519MLKEM768'
CLASSIC = 'X25519'
PATTERN = re.compile(r'(?:Negotiated TLS1\.3 group|Peer Temp Key):\s*(X25519MLKEM768|X25519)\b', re.I)


def read_json(sock):
    buf = bytearray()
    while b'\n' not in buf:
        data = sock.recv(16384)
        if not data or len(buf) > 1024 * 1024:
            raise RuntimeError('Missing/truncated request or oversized message')
        buf.extend(data)
    return json.loads(bytes(buf).split(b'\n', 1)[0])


def send_json(sock, obj):
    sock.sendall(json.dumps(obj, separators=(',', ':')).encode() + b'\n')


def context_server(cert, key, classic):
    ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    ctx.minimum_version = ssl.TLSVersion.TLSv1_3
    ctx.maximum_version = ssl.TLSVersion.TLSv1_3
    ctx.load_cert_chain(str(cert), str(key))
    if classic:
        ctx.set_ecdh_curve(CLASSIC)
    return ctx


def context_client(classic):
    ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
    ctx.minimum_version = ssl.TLSVersion.TLSv1_3
    ctx.maximum_version = ssl.TLSVersion.TLSv1_3
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE  # Lab only; excludes authentication claims.
    if classic:
        ctx.set_ecdh_curve(CLASSIC)
    return ctx


class Node:
    def __init__(self, name, cert, key, classical, downstream=None):
        self.name, self.classical, self.downstream = name, classical, downstream
        self.logs = []
        self.errors = []
        self.sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        self.sock.bind((HOST, 0))
        self.port = self.sock.getsockname()[1]
        self.sock.listen(16)
        self.sock.settimeout(.2)
        self.context = context_server(cert, key, classical)
        self.stop_event = threading.Event()
        self.thread = threading.Thread(target=self.serve, daemon=True)
        self.thread.start()

    def serve(self):
        while not self.stop_event.is_set():
            try:
                raw, _ = self.sock.accept()
            except socket.timeout:
                continue
            except OSError:
                break
            try:
                raw.settimeout(6)
                with self.context.wrap_socket(raw, server_side=True) as conn:
                    try:
                        request = read_json(conn)
                    except RuntimeError as exc:
                        if 'Missing/truncated request' in str(exc):
                            continue  # s_client probe closes without sending application data.
                        raise
                    if request.get('kind') != 'application':
                        continue  # Independent probe, not an app request.
                    rid = request['request_id']
                    entered = list(request['path'])
                    self.logs.append({'node': self.name, 'request_id': rid,
                                      'received_path': entered, 'tls_version': conn.version(),
                                      'endpoint_configuration': 'X25519_only' if self.classical else 'OpenSSL_default'})
                    request['path'] = entered + [self.name]
                    if self.downstream:
                        client_ctx = context_client(self.downstream.classical)
                        with socket.create_connection((HOST, self.downstream.port), timeout=6) as out:
                            with client_ctx.wrap_socket(out, server_hostname='localhost') as tlsout:
                                send_json(tlsout, request)
                                response = read_json(tlsout)
                    else:
                        response = {'request_id': rid, 'path': request['path'], 'status': 'ok'}
                    send_json(conn, response)
            except Exception as exc:
                self.errors.append(f'{type(exc).__name__}: {exc}')
                try: raw.close()
                except Exception: pass

    def close(self):
        self.stop_event.set()
        self.sock.close()
        self.thread.join(3)


def make_cert(root, openssl):
    cfg = root / 'lab.cnf'
    cfg.write_text('[req]\nprompt = no\ndistinguished_name = dn\n[dn]\nCN = localhost\n', encoding='ascii')
    key, crt = root / 'key.pem', root / 'cert.pem'
    proc = subprocess.run([openssl, 'req', '-x509', '-newkey', 'rsa:2048', '-nodes', '-days', '1',
                           '-keyout', str(key), '-out', str(crt), '-config', str(cfg)],
                          capture_output=True, text=True, timeout=30,
                          env=clean_env())
    if proc.returncode:
        raise RuntimeError('Certificate creation failed: ' + proc.stderr[-800:])
    return crt, key


def clean_env():
    env = os.environ.copy()
    for name in ('OPENSSL_CONF', 'OPENSSL_MODULES', 'OPENSSL_ENGINES', 'OPENSSL_CONF_INCLUDE'):
        env.pop(name, None)
    return env


def probe(openssl, port, classical):
    args = [openssl, 's_client', '-connect', f'{HOST}:{port}', '-tls1_3', '-groups',
            CLASSIC if classical else HYBRID, '-brief']
    result = subprocess.run(args, input='', capture_output=True, text=True, timeout=8, env=clean_env())
    text = result.stdout + result.stderr
    match = PATTERN.search(text)
    if not match:
        raise RuntimeError('Probe could not establish negotiated group: ' + text[-800:])
    return match.group(1)


def verdict(groups):
    if CLASSIC in groups:
        return 'VIOLATED'
    if None in groups:
        return 'UNRESOLVED'
    return 'SATISFIED'


def run_scenario(name, flags, visible, crt, key, openssl):
    backend = Node('backend', crt, key, flags[2])
    service = Node('service-a', crt, key, flags[1], backend)
    gateway = Node('gateway', crt, key, flags[0], service)
    nodes = [gateway, service, backend]
    try:
        time.sleep(.05)
        observed_probe = [probe(openssl, node.port, node.classical) for node in nodes]
        expected_groups = [CLASSIC if x else HYBRID for x in flags]
        if observed_probe != expected_groups:
            raise AssertionError(f'Independent probe mismatch: {observed_probe} != {expected_groups}')
        rid = str(uuid.uuid4())
        with socket.create_connection((HOST, gateway.port), timeout=6) as raw:
            with context_client(flags[0]).wrap_socket(raw, server_hostname='localhost') as tls:
                send_json(tls, {'kind': 'application', 'request_id': rid, 'path': ['client']})
                response = read_json(tls)
        if response['path'] != ['client', 'gateway', 'service-a', 'backend']:
            raise AssertionError('Application did not traverse full path: ' + str(response))
        if response['request_id'] != rid or response['status'] != 'ok':
            raise AssertionError('Incorrect downstream response')
        for node in nodes:
            matching = [r for r in node.logs if r['request_id'] == rid]
            if len(matching) != 1:
                raise AssertionError(f'Missing/duplicate independent application receipt: {node.name}')
            if node.errors:
                raise RuntimeError(f'Node failures on {node.name}: {node.errors}')
        evidence = [group if shown else None for group, shown in zip(observed_probe, visible)]
        actual = verdict(observed_probe)
        result = {'case': name, 'request_id': rid, 'ground_truth_by_controlled_configuration_and_probe': actual,
                  'evidence_verdict': verdict(evidence), 'edge_only': verdict([observed_probe[0]]),
                  'full_per_hop': actual, 'negotiated_probe_groups': observed_probe,
                  'visible_probe_groups': evidence, 'application_response': response,
                  'independent_node_receipts': [n.logs[0] for n in nodes],
                  'limitations': 'Probes are separate TLS sessions; app-session KEX not independently decoded; trust in lab request identifiers; no PQ authentication.'}
        return result
    finally:
        for n in nodes:
            n.close()


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument('--openssl', default=shutil.which('openssl'))
    ap.add_argument('--output', default='results/live_path_v05')
    args = ap.parse_args()
    if not args.openssl:
        ap.error('OpenSSL executable missing')
    if tuple(map(int, ssl.OPENSSL_VERSION_INFO[:2])) < (3, 5):
        raise SystemExit('LIVE PATH PREREQUISITE: Python ssl is linked to ' + ssl.OPENSSL_VERSION +
                         '. This live hybrid-path script requires Python ssl linked to OpenSSL >=3.5. '
                         'Use WSL with compatible Python/OpenSSL, or keep using v0.4 on Windows. '
                         'Do not replace DLLs inside Python.')
    output = Path(args.output).resolve()
    output.mkdir(parents=True, exist_ok=True)
    print('Python TLS:', ssl.OPENSSL_VERSION, flush=True)
    print('OpenSSL CLI:', subprocess.run([args.openssl, 'version'], capture_output=True, text=True).stdout.strip(), flush=True)
    cases = [('all_hybrid', [False, False, False], [True, True, True]),
             ('classical_middle', [False, True, False], [True, True, True]),
             ('missing_classical_middle', [False, True, False], [True, False, True]),
             ('missing_hybrid_middle', [False, False, False], [True, False, True]),
             ('all_classical', [True, True, True], [True, True, True])]
    rows = []
    with tempfile.TemporaryDirectory(prefix='pqc-live-lab-') as temp:
        crt, key = make_cert(Path(temp), args.openssl)
        for name, flags, visible in cases:
            row = run_scenario(name, flags, visible, crt, key, args.openssl)
            rows.append(row)
            print(name, row['ground_truth_by_controlled_configuration_and_probe'],
                  row['evidence_verdict'], row['negotiated_probe_groups'], flush=True)
    (output/'live_path.json').write_text(json.dumps({'openssl_python':ssl.OPENSSL_VERSION,
        'architecture':'Independent live application forwarding: client -> gateway -> service-a -> backend',
        'limitations':['Independent probes are not application sessions; their KEX is not direct proof of application-session KEX',
          'Application path is proven by lab-controlled request IDs and per-process receipts',
          'Lab TLS certificate verification disabled, no quantum-resistant authentication',
          'Python linked to OpenSSL >=3.5 required', 'Full per-hop baseline wins with complete evidence'],
        'cases': rows}, indent=2), encoding='utf-8')
    with (output/'summary.csv').open('w', newline='', encoding='utf-8') as f:
        w = csv.DictWriter(f, fieldnames=['case','ground_truth_by_controlled_configuration_and_probe','evidence_verdict','edge_only','full_per_hop'])
        w.writeheader()
        for row in rows:
            w.writerow({k:row[k] for k in w.fieldnames})
    assert all(x['evidence_verdict'] == x['ground_truth_by_controlled_configuration_and_probe'] for x in rows if None not in x['visible_probe_groups'])
    assert all(x['evidence_verdict'] == 'UNRESOLVED' for x in rows if None in x['visible_probe_groups'])
    print('PASS: 5 LIVE forwarded application requests; 15 per-node application receipts; 15 independent TLS probes.', flush=True)
    print('NOTE: Negotiated groups observed in separate probes, not the 15 application sessions.', flush=True)

if __name__ == '__main__':
    main()
