#!/usr/bin/env python3
"""Verify stored v1.4 cases with separately supplied laboratory keys."""
import argparse,json
from pathlib import Path
try: import multihop_witness_v14 as v
except ImportError: from . import multihop_witness_v14 as v

def main():
    p=argparse.ArgumentParser();p.add_argument('--evidence',required=True);p.add_argument('--keys',required=True)
    a=p.parse_args();data=json.loads(Path(a.evidence).read_text());raw=json.loads(Path(a.keys).read_text())
    rk={k:bytes.fromhex(vv) for k,vv in raw['report_keys'].items()}
    wk={k:bytes.fromhex(vv) for k,vv in raw['witness_keys'].items()}
    for name,expected in [('valid','SATISFIED'),('classical_middle','VIOLATED'),('forged','INVALID')]:
        case=data[name];result=v.verify(case['transaction'],case['client'],case['reports'],case['witnesses'],rk,wk)
        print(name,result[0],'-',result[1]);
        if result[0]!=expected:raise SystemExit('FAIL '+name)
    baseline=v.baseline(data['forged'],rk)
    print('forged_baseline',baseline[0]);
    if baseline[0]!='SATISFIED':raise SystemExit('FAIL baseline')
    print('PASS: v1.4 separate-process verification')
if __name__=='__main__':main()
