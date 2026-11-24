"""Supplementary archive-based local multi-process check; NOT multi-host validation."""
import sys, multiprocessing as mp, tempfile, pathlib, secrets, json, collections
sys.path.insert(0, '/mnt/data/pqtls_archive/Post-Quantum TLS Migration-Project/src')
import v32_protected_freshness as v
from v40_common import fixture,H

def worker(args):
    db,batch,token=args
    return v.FreshLedger(db).check(batch,batch['registered_public_keys'],token)

def main():
    token=secrets.token_hex(32)
    batch,_=fixture([H]*3,challenge=token)
    with tempfile.TemporaryDirectory(prefix='pqtls-c5-') as td:
        db=str(pathlib.Path(td)/'shared.sqlite3')
        v.FreshLedger(db)
        with mp.get_context('fork').Pool(processes=12) as pool:
            outcomes=pool.map(worker,[(db,batch,token)]*12)
        counts=dict(collections.Counter(outcomes))
        print(json.dumps({'setup':'12 distinct forked worker processes; one shared SQLite file; archived FreshLedger verifier; signed synthetic evidence','counts':counts,'single_consumption':counts.get('SATISFIED')==1 and counts.get('INVALID')==11},indent=2))
        assert counts.get('SATISFIED')==1 and counts.get('INVALID')==11
if __name__=='__main__':main()
