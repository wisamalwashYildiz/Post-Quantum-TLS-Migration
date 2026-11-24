#!/usr/bin/env python3
"""Independent PROCESS verification for v1.3 recorded observer experiment."""
import argparse,json
from pathlib import Path
try:from isolated_observer_v13 import verify_batch, report_only, REPORTER, OBSERVER
except ImportError:from .isolated_observer_v13 import verify_batch, report_only, REPORTER, OBSERVER

def main():
    ap=argparse.ArgumentParser()
    ap.add_argument('--evidence',required=True)
    ap.add_argument('--keys',required=True)
    args=ap.parse_args()
    data=json.loads(Path(args.evidence).read_text())
    k=json.loads(Path(args.keys).read_text())
    rk={REPORTER:bytes.fromhex(k['report_key'])}
    expectations={'valid':'SATISFIED','classical':'VIOLATED','forged':'INVALID'}
    for tag,expected in expectations.items():
        case=data[tag];wk={OBSERVER:bytes.fromhex(k['valid_observer_key'] if tag=='valid' else k['classical_observer_key'])}
        outcome=verify_batch(case['transactions'],case['reports'],case['witnesses'],rk,wk)
        print(tag,outcome[0],'-',outcome[1]);
        if outcome[0]!=expected:raise SystemExit(f'FAIL {tag}: expected {expected}')
    forged=data['forged']
    baseline=report_only(forged['transactions'],forged['reports'],rk)
    print('forged_report_only',baseline[0])
    if baseline[0]!='SATISFIED':raise SystemExit('FAIL baseline')
    print('PASS: separate verifier confirms recorded trust-boundary scenarios')
if __name__=='__main__':main()
