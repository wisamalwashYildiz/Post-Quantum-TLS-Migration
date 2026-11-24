#!/usr/bin/env python3
"""C6 measured capacity and contention audit for unmodified v32 FreshLedger.
Uses signed synthetic evidence. Saves every trial (including lock exceptions) as JSON.
Does not change original source, SQLite timeout, or measured TLS evidence.
"""
import argparse, concurrent.futures, hashlib, json, math, os, pathlib, platform
import secrets, sqlite3, statistics, sys, tempfile, time, traceback

def pctl(v,p):
    return sorted(v)[max(0, math.ceil(len(v)*p)-1)] if v else None

def main():
    ap=argparse.ArgumentParser()
    ap.add_argument('--project',default='.')
    ap.add_argument('--output',default='results/reviewer_c6_benchmark_v2')
    ap.add_argument('--batch',type=int,default=256)
    ap.add_argument('--repeats',type=int,default=3)
    ap.add_argument('--long-batch',type=int,default=4096)
    a=ap.parse_args()
    if min(a.batch,a.repeats,a.long_batch)<1: raise SystemExit('Invalid count')
    root=pathlib.Path(a.project).resolve()
    src=root/'src' if (root/'src'/'v32_protected_freshness.py').is_file() else root
    sys.path.insert(0,str(src))
    import v32_protected_freshness as v
    from v40_common import fixture, H
    out=pathlib.Path(a.output).resolve();out.mkdir(parents=True,exist_ok=True)
    record={'protocol':'C6 unmodified-v32 capacity/contention audit v2',
            'scope':'local protected-fresh verifier; synthetic signed evidence; no TLS establishment/transport',
            'environment':{'platform':platform.platform(),'python':platform.python_version(),
                'sqlite':sqlite3.sqlite_version,'cpu_count':os.cpu_count(),
                'source_hash':hashlib.sha256((src/'v32_protected_freshness.py').read_bytes()).hexdigest(),
                'fixture_hash':hashlib.sha256((src/'v40_common.py').read_bytes()).hexdigest()},
            'parameters':vars(a),'trials':[],'storage':[],'race':{}}
    target=out/'c6_benchmark_results_v2.json'
    def save(): target.write_text(json.dumps(record,indent=2,default=str)+'\n',encoding='utf-8')
    save()
    def create(n):
        xs=[]
        for _ in range(n):
            challenge=secrets.token_hex(32)
            batch,_=fixture([H]*3,challenge=challenge)
            xs.append((batch,challenge))
        return xs
    def run(workers,n,trial,kind):
        with tempfile.TemporaryDirectory(prefix='pqtls-c6-v2-') as td:
            db=pathlib.Path(td)/'ledger.sqlite'
            v.FreshLedger(db)
            data=create(n)   # outside timed region
            def check(item):
                batch,challenge=item
                tick=time.perf_counter_ns()
                try:
                    verdict=v.FreshLedger(db).check(batch,batch['registered_public_keys'],challenge)
                    return {'outcome':verdict,'elapsed_ms':(time.perf_counter_ns()-tick)/1e6}
                except Exception as ex:
                    return {'outcome':'EXCEPTION','error_type':type(ex).__name__,
                            'error':str(ex),'elapsed_ms':(time.perf_counter_ns()-tick)/1e6}
            tick=time.perf_counter_ns()
            with concurrent.futures.ThreadPoolExecutor(max_workers=workers) as pool:
                results=list(pool.map(check,data))
            duration=(time.perf_counter_ns()-tick)/1e9
            outcomes={k:sum(r['outcome']==k for r in results) for k in set(r['outcome'] for r in results)}
            success=[r['elapsed_ms'] for r in results if r['outcome']=='SATISFIED']
            exception=[r for r in results if r['outcome']=='EXCEPTION']
            with sqlite3.connect(db) as conn:
                rows=conn.execute('SELECT COUNT(*) FROM accepted').fetchone()[0]
                total_pages=conn.execute('PRAGMA page_count').fetchone()[0]
                page_size=conn.execute('PRAGMA page_size').fetchone()[0]
            res={'kind':kind,'workers':workers,'trial':trial,'requests':n,
                 'wall_seconds':duration,'completed_rps':n/duration,
                 'successful_rps':len(success)/duration,'outcomes':outcomes,
                 'all_success':len(success)==n,'db_records':rows,'db_bytes':db.stat().st_size,
                 'page_count':total_pages,'page_size':page_size,
                 'success_latency_median_ms':statistics.median(success) if success else None,
                 'success_latency_p95_ms':pctl(success,.95),'success_latency_p99_ms':pctl(success,.99),
                 'errors':[{k:r[k] for k in ('error_type','error') if k in r} for r in exception[:8]]}
            record['trials'].append(res);save()
            print(f'{kind} workers={workers} trial={trial} success={len(success)}/{n} '
                  f'successful_rps={res["successful_rps"]:.2f} p95={res["success_latency_p95_ms"]} '
                  f'errors={len(exception)}',flush=True)
    for workers in (1,2,4,8):
        for trial in range(1,a.repeats+1):run(workers,a.batch,trial,'concurrency')
    for workers in (1,8):run(workers,a.long_batch,1,'long_batch')
    for n in (0,64,256,512,1024):
        with tempfile.TemporaryDirectory(prefix='pqtls-c6-size-') as td:
            db=pathlib.Path(td)/'ledger.sqlite'; ledger=v.FreshLedger(db)
            for batch,challenge in create(n):
                result=ledger.check(batch,batch['registered_public_keys'],challenge)
                if result!='SATISFIED':raise AssertionError(('Unexpected growth verdict',result))
            with sqlite3.connect(db) as conn:
                count=conn.execute('SELECT COUNT(*) FROM accepted').fetchone()[0]
            entry={'verdicts':n,'stored':count,'sqlite_file_bytes':db.stat().st_size}
            record['storage'].append(entry);save()
    with tempfile.TemporaryDirectory(prefix='pqtls-c6-race-') as td:
        db=pathlib.Path(td)/'ledger.sqlite';v.FreshLedger(db)
        challenge=secrets.token_hex(32);batch,_=fixture([H]*3,challenge=challenge)
        def collide(_):
            try:return v.FreshLedger(db).check(batch,batch['registered_public_keys'],challenge)
            except Exception as ex:return type(ex).__name__+': '+str(ex)
        with concurrent.futures.ThreadPoolExecutor(max_workers=12) as pool:
            vals=list(pool.map(collide,range(12)))
        record['race']={'workers':12,'results':vals,'correct':vals.count('SATISFIED')==1 and vals.count('INVALID')==11}
        save()
    print('COMPLETE',target)
    print('NOTE: Lock errors are recorded as failures, not automatically retried.')
if __name__=='__main__':main()
