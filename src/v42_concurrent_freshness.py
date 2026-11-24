"""Concurrent SQLite freshness using actual v32 FreshLedger and signed synthetic evidence."""
import argparse,concurrent.futures,tempfile,pathlib,collections,secrets
from v40_common import *
def main():
 p=argparse.ArgumentParser();p.add_argument('--out',required=True);p.add_argument('--workers',type=int,default=12);a=p.parse_args();rows=[]
 with tempfile.TemporaryDirectory(prefix='pqtls-v42-') as tmp:
  token=secrets.token_hex(32);b,k=fixture([H]*3,challenge=token);db=pathlib.Path(tmp)/'freshness.sqlite';v.FreshLedger(db)
  def task(idx):return idx,v.FreshLedger(db).check(b,b['registered_public_keys'],token)
  with concurrent.futures.ThreadPoolExecutor(max_workers=a.workers) as ex:
   for idx,verdict in ex.map(task,range(a.workers)):rows.append(dict(worker=idx,verdict=verdict))
 count=collections.Counter(r['verdict'] for r in rows)
 save(a.out,rows,{'type':'real concurrent SQLite ledger, synthetic signed evidence','workers':a.workers,'counts':dict(count),'single_use_correct':count['SATISFIED']==1 and count['INVALID']==a.workers-1})
 if not (count['SATISFIED']==1 and count['INVALID']==a.workers-1):raise SystemExit('Concurrency invariant failed')
if __name__=='__main__':main()
