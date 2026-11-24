#!/usr/bin/env python3
"""Separate offline process verifier for v1.1 lab receipts; keys must be kept private."""
import argparse,json
from pathlib import Path
from session_chain_v11 import verify_chain

def main():
    p=argparse.ArgumentParser()
    p.add_argument('--evidence',default='results/session_chain_v11/session_chain.json')
    p.add_argument('--keys',default='results/session_chain_v11/lab_verifier_keys.json')
    args=p.parse_args()
    obj=json.loads(Path(args.evidence).read_text())
    keys={n:bytes.fromhex(v) for n,v in json.loads(Path(args.keys).read_text()).items()}
    result=verify_chain(obj['transaction'], obj['client'],obj['node_receipts'],keys)
    print('independent_process_verification:', *result)
    if result[0]!='SATISFIED':
        raise SystemExit(1)
if __name__=='__main__':main()
