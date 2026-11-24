#!/usr/bin/env python3
"""v0.7: concurrent real TLS forwarding, dynamic path selection, session-specific evidence.
Laboratory only; TLS authentication disabled and CPython private _msg_callback is used.
Requires Python ssl linked to OpenSSL >=3.5. Not a general path-discovery system.
"""
import argparse, concurrent.futures, csv, hashlib, json, shutil, socket, ssl, tempfile, threading, uuid
from pathlib import Path
import live_path as lp
import session_evidence as se

H, C = se.HYBRID, se.CLASSIC

class Node:
    def __init__(self, name, crt, key, classical=False, downstream=None, branches=None):
        self.name, self.classical, self.downstream, self.branches = name, classical, downstream, branches
        self.ctx, self.tracker = se.contexts(crt, key, classical)
        self.logs, self.errors, self.workers = [], [], []
        self.lock = threading.Lock()
        self.listener = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.listener.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        self.listener.bind(('127.0.0.1', 0))
        self.port = self.listener.getsockname()[1]
        self.listener.listen(100); self.listener.settimeout(.15)
        self.stopping = threading.Event()
        self.thread = threading.Thread(target=self.serve, daemon=True)
        self.thread.start()

    def serve(self):
        while not self.stopping.is_set():
            try: raw, _ = self.listener.accept()
            except socket.timeout: continue
            except OSError: break
            t = threading.Thread(target=self.handle, args=(raw,), daemon=True)
            with self.lock: self.workers.append(t)
            t.start()

    def handle(self, raw):
        try:
            raw.settimeout(15)
            with self.ctx.wrap_socket(raw, server_side=True) as incoming:
                group = self.tracker.get(incoming)
                request = lp.read_json(incoming)
                if request.get('kind') != 'application': return
                rid = request['request_id']; route=request['route']
                receipt = {'node': self.name, 'request_id': rid, 'route': route,
                           'incoming_group': group, 'incoming_tls_version': incoming.version(),
                           'received_path':list(request['path'])}
                target = self.branches[route] if self.branches else self.downstream
                request['path'].append(self.name)
                if target is not None:
                    context, tracker = se.contexts(None, None, target.classical, client=True)
                    with socket.create_connection(('127.0.0.1',target.port), timeout=15) as sock:
                        with context.wrap_socket(sock,server_hostname='localhost') as out:
                            receipt['outgoing_group']=tracker.get(out)
                            lp.send_json(out, request)
                            response=lp.read_json(out)
                            tracker.forget(out)
                else:
                    response={'request_id':rid,'route':route,'path':request['path'],'status':'ok'}
                with self.lock: self.logs.append(receipt)
                lp.send_json(incoming,response)
                self.tracker.forget(incoming)
        except Exception as e:
            with self.lock: self.errors.append(f'{type(e).__name__}: {e}')
            try: raw.close()
            except Exception: pass

    def close(self):
        self.stopping.set();self.listener.close();self.thread.join(3)
        with self.lock: workers=list(self.workers)
        for t in workers: t.join(16)


def verdict(groups):
    if any(g not in (H, C, None) for g in groups):return 'UNRESOLVED'
    if C in groups:return 'VIOLATED'
    if None in groups:return 'UNRESOLVED'
    return 'SATISFIED'


def selective_evidence(receipts, visible_nodes):
    """Only use observed receipts; missing node is unknown rather than absent."""
    return [r['incoming_group'] if r['node'] in visible_nodes else None for r in receipts]


def mask_for(seed, rid, node, missing_probability):
    # Deterministic across platforms and independent of threading/order.
    value=int.from_bytes(hashlib.sha256(f'{seed}|{rid}|{node}'.encode()).digest()[:8], 'big')/2**64
    return value >= missing_probability


def scenario(name, flags, count, seed, probabilities, crt, key):
    # Config order gateway, service-a, service-b, backend.
    backend=Node('backend',crt,key,flags[3])
    a=Node('service-a',crt,key,flags[1],downstream=backend)
    b=Node('service-b',crt,key,flags[2],downstream=backend)
    gateway=Node('gateway',crt,key,flags[0],branches={'A':a,'B':b})
    nodes=[gateway,a,b,backend]
    try:
        ids=[str(uuid.uuid5(uuid.NAMESPACE_DNS,f'pqc-v07:{seed}:{name}:{i}')) for i in range(count)]
        routes=['A' if i%2==0 else 'B' for i in range(count)]
        def request_one(pair):
            rid, route=pair
            ctx, tracker = se.contexts(None,None,flags[0],client=True)
            with socket.create_connection(('127.0.0.1',gateway.port),timeout=15) as sock:
                with ctx.wrap_socket(sock,server_hostname='localhost') as conn:
                    group=tracker.get(conn)
                    lp.send_json(conn,{'kind':'application','request_id':rid,'route':route,'path':['client']})
                    resp=lp.read_json(conn)
                    tracker.forget(conn)
            return rid,route,group,resp
        with concurrent.futures.ThreadPoolExecutor(max_workers=min(8,count)) as pool:
            responses=list(pool.map(request_one,zip(ids,routes)))
        all_receipts={}
        for node in nodes:
            assert not node.errors,(node.name,node.errors)
            for record in node.logs:
                keyid=(record['request_id'],node.name)
                assert keyid not in all_receipts,('duplicate receipt',keyid)
                all_receipts[keyid]=record
        records=[]
        for rid,route,client_group,resp in responses:
            nodes_on_path=[gateway,a if route=='A' else b,backend]
            actual=[all_receipts[(rid,n.name)] for n in nodes_on_path]
            expected_path=['client']+[n.name for n in nodes_on_path]
            assert resp=={'request_id':rid,'route':route,'path':expected_path,'status':'ok'},resp
            assert [r['received_path'] for r in actual]==[expected_path[:i+1] for i in range(3)]
            groups=[r['incoming_group'] for r in actual]
            assert client_group==groups[0]
            for i in range(2): assert actual[i]['outgoing_group']==groups[i+1]
            assert groups==[C if n.classical else H for n in nodes_on_path],groups
            truth=verdict(groups)
            evidence=[]
            for p in probabilities:
                visible={n.name for n in nodes_on_path if mask_for(seed,rid,n.name,p)}
                observed=selective_evidence(actual,visible)
                evidence.append({'dropout':p,'visible_nodes':sorted(visible),'observed_groups':observed,
                                 'verdict':verdict(observed),'edge_only':verdict([observed[0]]),
                                 'conservative_per_hop':verdict(observed),
                                 'full_per_hop':truth})
            records.append({'request_id':rid,'route':route,'path':expected_path,'actual_groups':groups,
                            'ground_truth':truth,'receipts':actual,'evidence':evidence})
        assert len(all_receipts)==count*3, (len(all_receipts), count*3)
        return records
    finally:
        for node in nodes: node.close()


def summarize(cases,probs):
    rows=[]
    for p in probs:
        subset=[(req,ev) for requests in cases.values() for req in requests for ev in req['evidence'] if ev['dropout']==p]
        for method in ('verdict','edge_only','conservative_per_hop','full_per_hop'):
            decisions=[(req['ground_truth'],ev[method]) for req,ev in subset]
            rows.append({'dropout':p,'method':method,'n':len(decisions),
                         'correct':sum(t==d for t,d in decisions),
                         'incorrect':sum(d!='UNRESOLVED' and t!=d for t,d in decisions),
                         'unresolved':sum(d=='UNRESOLVED' for _,d in decisions)})
    return rows


def main():
    p=argparse.ArgumentParser()
    p.add_argument('--openssl',default=shutil.which('openssl'))
    p.add_argument('--output',default='results/concurrent_paths_v07')
    p.add_argument('--requests-per-scenario',type=int,default=12)
    p.add_argument('--seed',type=int,default=42017)
    args=p.parse_args()
    if ssl.OPENSSL_VERSION_INFO[:2] < (3,5):
        raise SystemExit('Python ssl must be linked to OpenSSL >= 3.5 (use WSL/Linux or compatible Python).')
    if args.requests_per_scenario<2: raise SystemExit('Need at least two requests per scenario')
    if not args.openssl:raise SystemExit('OpenSSL CLI not found')
    out=Path(args.output).resolve();out.mkdir(parents=True,exist_ok=True)
    cases={'all_hybrid':[False,False,False,False],
           'branch_b_classical':[False,False,True,False],
           'branch_a_classical':[False,True,False,False],
           'gateway_classical':[True,False,False,False],
           'backend_classical':[False,False,False,True],
           'both_branches_classical':[False,True,True,False]}
    probs=(0.0,0.25,0.5,1.0)
    with tempfile.TemporaryDirectory(prefix='pqc-concurrent-') as td:
        cert,key=lp.make_cert(Path(td),args.openssl)
        results={}
        for name,flags in cases.items():
            results[name]=scenario(name,flags,args.requests_per_scenario,args.seed,probs,cert,key)
            print(name,len(results[name]),'completed requests',flush=True)
    rows=summarize(results,probs)
    payload={'version':'0.7','python_openssl':ssl.OPENSSL_VERSION,'seed':args.seed,
             'requests_per_scenario':args.requests_per_scenario,'dropout_probabilities':probs,
             'limitations':['Controlled route selection and trusted request IDs, not autonomous path discovery',
               'Private CPython SSL message callback is non-public API',
               'Unverified self-signed RSA certificate; no authentication security claim',
               'Missing observations are simulated by filtering genuinely collected node receipts',
               'Configured per-hop TLS group is a strong and simple matched-evidence baseline',
               'No statistical generalization from fixed synthetic dropout distributions'],
             'cases':results,'summary':rows}
    (out/'concurrent_paths.json').write_text(json.dumps(payload,indent=2))
    with (out/'summary.csv').open('w',newline='') as f:
        writer=csv.DictWriter(f,fieldnames=['dropout','method','n','correct','incorrect','unresolved'])
        writer.writeheader();writer.writerows(rows)
    assert all(r['incorrect']==0 for r in rows if r['method'] in ('verdict','conservative_per_hop','full_per_hop'))
    print('PASS:',sum(map(len,results.values())),'concurrent forwarded app requests; 3 TLS hops per request')
    for r in rows:
        if r['method']=='verdict':print('dropout',r['dropout'],'correct',r['correct'],'unresolved',r['unresolved'],'incorrect',r['incorrect'])
if __name__=='__main__':main()
