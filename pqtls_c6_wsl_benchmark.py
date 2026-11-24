"""C6 supplementary benchmark: real v32 verifier, synthetic signed evidence.
Run in the original project WSL environment. No changes to project source/results.
DO NOT interpret local verification latency as TLS end-to-end latency.
"""
import argparse, concurrent.futures, hashlib, json, os, pathlib, platform, secrets
import sqlite3, statistics, sys, tempfile, time

def percentile_nearest(values, pct):
    return sorted(values)[max(0, int(__import__('math').ceil(len(values)*pct))-1)]

def main():
    p=argparse.ArgumentParser(description=__doc__)
    p.add_argument('--project', default='.', help='Project root containing src/v32_protected_freshness.py')
    p.add_argument('--output',default='results/reviewer_c6_local_benchmark')
    p.add_argument('--batch',type=int,default=256)
    p.add_argument('--repeats',type=int,default=3)
    p.add_argument('--long-batch',type=int,default=4096)
    a=p.parse_args()
    root=pathlib.Path(a.project).resolve()
    src=root/'src' if (root/'src'/'v32_protected_freshness.py').is_file() else root
    if not (src/'v32_protected_freshness.py').is_file() or not (src/'v40_common.py').is_file():
        raise SystemExit('Cannot find src/v32_protected_freshness.py and src/v40_common.py under --project')
    sys.path.insert(0,str(src))
    import v32_protected_freshness as v
    from v40_common import fixture,H
    out=pathlib.Path(a.output).resolve();out.mkdir(parents=True,exist_ok=True)
    if any(n<1 for n in (a.batch,a.repeats,a.long_batch)):
        raise SystemExit('batch/repeats/long-batch must be positive')
    def create_payloads(n):
        items=[]
        for _ in range(n):
            challenge=secrets.token_hex(32)
            b,_=fixture([H]*3,challenge=challenge)
            items.append((b,challenge))
        return items
    def run_batch(workers,requests,trial,tag):
        with tempfile.TemporaryDirectory(prefix='pqtls-c6-') as td:
            db=pathlib.Path(td)/'fresh.sqlite';v.FreshLedger(db)
            payloads=create_payloads(requests) # deliberately outside timed region
            def request(item):
                batch,challenge=item
                t0=time.perf_counter_ns()
                result=v.FreshLedger(db).check(batch,batch['registered_public_keys'],challenge)
                return result,(time.perf_counter_ns()-t0)/1e6
            start=time.perf_counter_ns()
            with concurrent.futures.ThreadPoolExecutor(max_workers=workers) as pool:
                calls=list(pool.map(request,payloads))
            wall=(time.perf_counter_ns()-start)/1e9
            counts={k:sum(1 for o,_ in calls if o==k) for k in ('SATISFIED','VIOLATED','INVALID','UNRESOLVED')}
            with sqlite3.connect(db) as c:
                entries=c.execute('SELECT COUNT(*) FROM accepted').fetchone()[0]
                page_size=c.execute('PRAGMA page_size').fetchone()[0]
                page_count=c.execute('PRAGMA page_count').fetchone()[0]
            if counts['SATISFIED']!=requests or entries!=requests:
                raise RuntimeError('Unexpected decisions/ledger count: '+str((counts,entries)))
            ms=[t for _,t in calls]
            return dict(tag=tag,workers=workers,trial=trial,requests=requests,wall_seconds=wall,
                throughput_rps=requests/wall,request_median_ms=statistics.median(ms),
                request_p95_ms=percentile_nearest(ms,.95),request_p99_ms=percentile_nearest(ms,.99),
                decisions=counts,ledger_entries=entries,ledger_bytes=db.stat().st_size,
                ledger_page_size=page_size,ledger_page_count=page_count)
    rows=[]
    for workers in (1,2,4,8):
        for trial in range(1,a.repeats+1):
            r=run_batch(workers,a.batch,trial,'concurrency');rows.append(r)
            print(f'concurrency workers={workers} trial={trial} throughput={r["throughput_rps"]:.2f}/s p95={r["request_p95_ms"]:.3f}ms',flush=True)
    # A longer, continuous processing batch (still NOT a sustained production workload)
    for workers in (1,8):
        r=run_batch(workers,a.long_batch,1,'long_batch');rows.append(r)
        print(f'long_batch workers={workers} throughput={r["throughput_rps"]:.2f}/s p95={r["request_p95_ms"]:.3f}ms',flush=True)
    # Ledger file growth using REAL verifier decisions, not manual SQLite inserts
    growth=[]
    for n in (0,64,256,512,1024):
        with tempfile.TemporaryDirectory(prefix='pqtls-c6-growth-') as td:
            db=pathlib.Path(td)/'fresh.sqlite';ledger=v.FreshLedger(db)
            for batch,challenge in create_payloads(n):
                result=ledger.check(batch,batch['registered_public_keys'],challenge)
                if result!='SATISFIED':raise RuntimeError('Unexpected storage outcome '+result)
            with sqlite3.connect(db) as con:
                count=con.execute('SELECT count(*) FROM accepted').fetchone()[0]
            if count!=n:raise RuntimeError('Storage record mismatch')
            growth.append(dict(verdicts=n,sqlite_file_bytes=db.stat().st_size))
    # Same-challenge race: only one successful decisive verdict (freshness correctness)
    with tempfile.TemporaryDirectory(prefix='pqtls-c6-replay-') as td:
        db=pathlib.Path(td)/'fresh.sqlite';v.FreshLedger(db)
        challenge=secrets.token_hex(32);batch,_=fixture([H]*3,challenge=challenge)
        def collide(_):return v.FreshLedger(db).check(batch,batch['registered_public_keys'],challenge)
        with concurrent.futures.ThreadPoolExecutor(max_workers=12) as pool:
            verdicts=list(pool.map(collide,range(12)))
        race=dict(workers=12,satisfied=verdicts.count('SATISFIED'),invalid=verdicts.count('INVALID'))
        if race['satisfied']!=1 or race['invalid']!=11:raise RuntimeError('Freshness race failed')
    result=dict(benchmark='C6 local protected-fresh benchmark with real v32 verifier',
      scope='synthetic signed evidence; local per-call verifier and persistent SQLite; no network or live TLS; separate from original timing campaign',
      environment=dict(platform=platform.platform(),python=platform.python_version(),sqlite=sqlite3.sqlite_version,
          cpu_count=os.cpu_count(),project_src=str(src),project_v32_sha256=hashlib.sha256((src/'v32_protected_freshness.py').read_bytes()).hexdigest(),
          project_v40_sha256=hashlib.sha256((src/'v40_common.py').read_bytes()).hexdigest()),
      methods=dict(concurrency_workers=[1,2,4,8],batch=a.batch,repeats=a.repeats,long_batch=a.long_batch,
          inclusion='FreshLedger construction, verification, SQLite commit, threadpool scheduling and wall-clock batch',
          exclusion='synthetic fixture creation, ledger pre-creation, live TLS handshakes, network and evidence transport'),
      results=rows,storage=growth,same_challenge_race=race)
    path=out/'c6_benchmark_results.json';path.write_text(json.dumps(result,indent=2)+'\n',encoding='utf-8')
    print('PASS; output:',path)
if __name__=='__main__':main()
