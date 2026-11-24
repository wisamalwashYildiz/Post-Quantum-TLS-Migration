#!/usr/bin/env python3
"""Separate-process verifier for v1.2 (requires private laboratory keys)."""
import argparse
import json
from pathlib import Path
try:
    from trust_boundary_v12 import verify_corroborated
except ImportError:
    from .trust_boundary_v12 import verify_corroborated


def main():
    p = argparse.ArgumentParser()
    p.add_argument('--evidence', required=True)
    p.add_argument('--keys', required=True)
    args = p.parse_args()
    evidence = json.loads(Path(args.evidence).read_text())
    keydata = json.loads(Path(args.keys).read_text())
    keys = {k: bytes.fromhex(v) for k,v in keydata['node_keys'].items()}
    observers = {k: bytes.fromhex(v) for k,v in keydata['observer_keys'].items()}
    expected = {'valid':'SATISFIED', 'classical':'VIOLATED', 'forged_classical':'INVALID'}
    for label, expected_result in expected.items():
        item = evidence[label]
        result = verify_corroborated(item['transaction'], item['client'], item['receipts'], item['witnesses'], keys, observers)
        print(label, result[0], '-', result[1])
        if result[0] != expected_result:
            raise SystemExit('FAIL: unexpected ' + label + ' status')
    print('PASS: separate-process corroboration verifies all stored examples')

if __name__ == '__main__':
    main()
