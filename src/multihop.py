#!/usr/bin/env python3
"""Portable three-segment TLS 1.3 request-carrying transport feasibility study.

OpenSSL s_server -rev provides reliable, independent TLS endpoints without
process-stdin forwarding (problematic on Windows). Python orchestrates an
application-level request through each separate TLS connection, carrying a
request_id and stage provenance. This is NOT a network gateway forwarding
through live intermediate application processes and does NOT prove independent
path correlation. Each segment is a real TLS session with a transport response.
Only TLS key establishment is assessed, not PQ authentication.
"""
import argparse
import csv
import json
import os
import re
import shutil
import socket
import subprocess
import tempfile
import threading
import time
import uuid
from pathlib import Path

HYBRID = 'X25519MLKEM768'
CLASSIC = 'X25519'
GROUP_RE = re.compile(r'(?:Negotiated TLS1\.3 group|Peer Temp Key):\s*(X25519MLKEM768|X25519)\b', re.I)


def openssl_environment():
    env = os.environ.copy()
    for name in ('OPENSSL_CONF', 'OPENSSL_MODULES', 'OPENSSL_ENGINES', 'OPENSSL_CONF_INCLUDE'):
        env.pop(name, None)
    return env


def select_openssl(explicit=None):
    if explicit:
        p = Path(explicit).expanduser().resolve()
        if not p.is_file():
            raise RuntimeError('OpenSSL executable missing: ' + str(p))
        return str(p)
    if os.name == 'nt':
        p = Path(r'C:\Program Files\OpenSSL-Win64\bin\openssl.exe')
        if p.is_file():
            return str(p)
    p = shutil.which('openssl')
    if not p:
        raise RuntimeError('OpenSSL missing; pass --openssl with the complete executable path')
    return p


def preflight(binary, env):
    def run(*args):
        return subprocess.run([binary, *args], env=env, text=True, capture_output=True, timeout=20)
    v = run('version')
    if v.returncode:
        raise RuntimeError(v.stderr)
    groups = run('list', '-tls-groups')
    if groups.returncode or HYBRID.lower() not in groups.stdout.lower().split(':'):
        raise RuntimeError('OpenSSL must support hybrid TLS group ' + HYBRID)
    help_result = run('s_server', '-help')
    if '-rev' not in (help_result.stdout + help_result.stderr):
        raise RuntimeError('OpenSSL s_server lacks -rev echo capability')
    print('Using OpenSSL:', binary, flush=True)
    print('OpenSSL version:', v.stdout.strip(), flush=True)


def ensure_cert(root, binary, env):
    cert, key = root / 'cert.pem', root / 'key.pem'
    if cert.is_file() and key.is_file():
        return str(key), str(cert)
    config = root / 'openssl-lab.cnf'
    config.write_text('[req]\ndistinguished_name = req_dn\nprompt = no\n[req_dn]\nCN = localhost\n', encoding='ascii')
    p = subprocess.run([binary, 'req', '-x509', '-newkey', 'rsa:2048', '-nodes',
                        '-days', '2', '-keyout', str(key), '-out', str(cert),
                        '-config', str(config)], env=env, text=True,
                       capture_output=True, timeout=45)
    if p.returncode:
        raise RuntimeError('Cannot generate lab certificate: ' + p.stderr[-1000:])
    return str(key), str(cert)


def free_port():
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        s.bind(('127.0.0.1', 0))
        return s.getsockname()[1]


class TLSEchoEndpoint:
    def __init__(self, name, binary, env, key, cert, group):
        self.name, self.port, self.group = name, free_port(), group
        self.errors = tempfile.TemporaryFile(mode='w+t', encoding='utf-8')
        args = [binary, 's_server', '-accept', f'127.0.0.1:{self.port}', '-tls1_3',
                '-cert', cert, '-key', key, '-groups', group, '-rev', '-naccept', '1']
        self.proc = subprocess.Popen(args, env=env, stdin=subprocess.DEVNULL,
                                     stdout=subprocess.DEVNULL, stderr=self.errors,
                                     creationflags=getattr(subprocess, 'CREATE_NO_WINDOW', 0))

    def diagnostic(self):
        self.errors.flush()
        self.errors.seek(0)
        return self.errors.read()[-1500:]

    def close(self):
        if self.proc.poll() is None:
            self.proc.terminate()
        try:
            self.proc.wait(timeout=3)
        except subprocess.TimeoutExpired:
            self.proc.kill()
            self.proc.wait(timeout=3)
        self.errors.close()


def exec_tls(binary, env, endpoint, group, payload, timeout=15):
    """Send one JSON line to OpenSSL's TLS reverse-echo test server."""
    raw_line = json.dumps(payload, separators=(',', ':'), ensure_ascii=True)
    # s_server -rev reverses each line's byte sequence. JSON is ASCII-only.
    err = tempfile.TemporaryFile(mode='w+t', encoding='utf-8')
    args = [binary, 's_client', '-connect', f'127.0.0.1:{endpoint.port}',
            '-tls1_3', '-groups', group, '-brief', '-quiet', '-ign_eof']
    proc = subprocess.Popen(args, env=env, stdin=subprocess.PIPE,
                            stdout=subprocess.PIPE, stderr=err,
                            text=True, encoding='utf-8', bufsize=1,
                            creationflags=getattr(subprocess, 'CREATE_NO_WINDOW', 0))
    response = {}
    def read_line():
        try:
            line = proc.stdout.readline()
            if not line:
                raise RuntimeError('OpenSSL returned no application response')
            response['result'] = json.loads(line.rstrip('\r\n')[::-1])
        except Exception as e:
            response['error'] = repr(e)
    t = threading.Thread(target=read_line, daemon=True)
    try:
        proc.stdin.write(raw_line + '\n')
        proc.stdin.flush()
        t.start()
        t.join(timeout)
        if t.is_alive():
            raise RuntimeError(f'TLS response timeout on {endpoint.name} port {endpoint.port}; server: {endpoint.diagnostic()}')
        if response.get('error'):
            raise RuntimeError('TLS response error: ' + response['error'] + '; server: ' + endpoint.diagnostic())
        err.flush()
        err.seek(0)
        trace = err.read()
        match = GROUP_RE.search(trace)
        if not match:
            raise RuntimeError('TLS negotiated group not found: ' + trace[-1000:])
        if response['result'] != payload:
            raise AssertionError('TLS transport payload mismatched at ' + endpoint.name)
        return match.group(1), response['result']
    finally:
        if proc.poll() is None:
            proc.kill()
        try:
            proc.communicate(timeout=3)
        except subprocess.TimeoutExpired:
            proc.kill()
            proc.wait(timeout=3)
        err.close()


def verdict(observed):
    if any(g == CLASSIC for g in observed):
        return 'VIOLATED'
    if observed and all(g == HYBRID for g in observed):
        return 'SATISFIED'
    return 'UNRESOLVED'


def scenario(name, groups, visible, binary, env, key, cert):
    rid = str(uuid.uuid4())
    endpoints = []
    try:
        for node, group in zip(('gateway', 'service-a', 'backend'), groups):
            endpoints.append(TLSEchoEndpoint(node, binary, env, key, cert, group))
        time.sleep(0.45)
        for e in endpoints:
            if e.proc.poll() is not None:
                raise RuntimeError(f'{e.name} exited during startup: {e.diagnostic()}')
        message = {'request_id': rid, 'path': ['client'], 'status': 'request'}
        negotiated = []
        receipts = []
        for endpoint, group in zip(endpoints, groups):
            negotiated_group, response = exec_tls(binary, env, endpoint, group, message)
            negotiated.append(negotiated_group)
            assert response['request_id'] == rid
            receipts.append({'request_id': rid, 'node': endpoint.name,
                             'negotiated_group': negotiated_group,
                             'received_path': response['path']})
            message = dict(response, path=response['path'] + [endpoint.name])
        assert message['path'] == ['client', 'gateway', 'service-a', 'backend']
        assert negotiated == groups
        obs = [g if v else None for g, v in zip(negotiated, visible)]
        return {'case': name, 'request_id': rid, 'ground_truth': verdict(negotiated),
                'evidence_verdict': verdict(obs), 'edge_only': verdict([obs[0]]),
                'full_per_hop': verdict(negotiated), 'groups': negotiated,
                'observed': obs, 'trace': receipts, 'response': message,
                'authentication': 'Unverified RSA self-signed laboratory certificate',
                'architecture': 'Python sequenced TLS echo segments, not live proxy forwarding'}
    finally:
        for e in reversed(endpoints):
            e.close()


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('--output', default='results/multihop')
    parser.add_argument('--openssl', default=None)
    args = parser.parse_args()
    output = Path(args.output).resolve()
    output.mkdir(parents=True, exist_ok=True)
    binary, env = select_openssl(args.openssl), openssl_environment()
    preflight(binary, env)
    key, cert = ensure_cert(output, binary, env)
    cases = [
        ('all_hybrid', [HYBRID] * 3, [1, 1, 1]),
        ('classical_middle', [HYBRID, CLASSIC, HYBRID], [1, 1, 1]),
        ('missing_classical_middle', [HYBRID, CLASSIC, HYBRID], [1, 0, 1]),
        ('missing_hybrid_middle', [HYBRID] * 3, [1, 0, 1]),
        ('all_classical', [CLASSIC] * 3, [1, 1, 1]),
    ]
    rows = []
    for name, groups, visible in cases:
        row = scenario(name, groups, visible, binary, env, key, cert)
        rows.append(row)
        print(name, row['ground_truth'], row['evidence_verdict'], row['groups'], flush=True)
    assert len(rows) == 5 and all(r['ground_truth'] == r['full_per_hop'] for r in rows)
    assert rows[2]['evidence_verdict'] == 'UNRESOLVED'
    assert rows[1]['evidence_verdict'] == 'VIOLATED'
    (output / 'multihop.json').write_text(json.dumps({
        'limitations': [
            'Python orchestrates sequential sessions; no independent live gateway-to-backend forwarding',
            'Laboratory self-signed RSA certificate with validation disabled; no PQ authentication',
            'Path membership is defined by controlled application request IDs and sequencer',
            'Full per-hop baseline is decisive under complete observation',
            'The server reverse echo is an OpenSSL diagnostic mechanism, not a production application'
        ], 'openssl': binary, 'cases': rows}, indent=2) + '\n', encoding='utf-8')
    with (output / 'summary.csv').open('w', newline='', encoding='utf-8') as f:
        keys = ['case', 'request_id', 'ground_truth', 'evidence_verdict', 'edge_only', 'full_per_hop']
        writer = csv.DictWriter(f, fieldnames=keys)
        writer.writeheader()
        writer.writerows([{k: r[k] for k in keys} for r in rows])
    print('PASS: 5 Python-sequenced requests over 15 real OpenSSL TLS 1.3 sessions', flush=True)

if __name__ == '__main__':
    main()
