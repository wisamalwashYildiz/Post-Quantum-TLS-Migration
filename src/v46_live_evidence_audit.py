#!/usr/bin/env python3
"""v46: live TLS evidence + independently specified mutation oracle for v45.

Run --live as root in the existing WSL lab; --synthetic for smoke testing.
Never overwrites historical results or modifies original verifiers.
"""
import argparse, copy, csv, hashlib, json, os, secrets, subprocess, sys, tempfile
from pathlib import Path
from datetime import datetime,timezone
from collections import Counter
import v32_protected_freshness as v
import v44_policy_aware_live as p44
from v45_precedence_verifier import verify_partial,PartialLedger

# These scenarios preserve at least one expected authenticated observation per path.
# Per-transaction omissions use the three transaction bundle so corroboration can
# survive in other transactions. All-transaction omissions cannot be treated as
# independent evidence of the missing connection.
MUTATIONS=('unaltered','missing_first_one','missing_middle_one','missing_last_one',
 'missing_first_all','missing_middle_all','missing_last_all','missing_client_one',
 'missing_client_all','unsigned_middle_group','unsigned_last_proof',
 'missing_first_one_unsigned_last','missing_middle_one_unsigned_first',
 'client_group_conflict','duplicate_middle','unknown_group_unsigned')

def mutate(batch, name):
    b=copy.deepcopy(batch); a,mid,z=v.NODES
    if name=='unaltered': pass
    elif name=='missing_first_one':b['receivers'][a].pop(0)
    elif name=='missing_middle_one':b['receivers'][mid].pop(0)
    elif name=='missing_last_one':b['receivers'][z].pop(0)
    elif name=='missing_first_all':b['receivers'][a].clear()
    elif name=='missing_middle_all':b['receivers'][mid].clear()
    elif name=='missing_last_all':b['receivers'][z].clear()
    elif name=='missing_client_one':b['client'].pop()  # trailing observation missing
    elif name=='missing_client_shift':b['client'].pop(0)  # shifts a positional client record
    elif name=='missing_client_all':b['client'].clear()
    elif name=='unsigned_middle_group':b['receivers'][mid][0]['record']['inbound_group']='UNSIGNED_EDIT'
    elif name=='unsigned_last_proof':b['receivers'][z][0]['record']['inbound_proof']='UNSIGNED_EDIT'
    elif name=='missing_first_one_unsigned_last':
        b['receivers'][a].pop(0);b['receivers'][z][0]['record']['inbound_proof']='UNSIGNED_EDIT'
    elif name=='missing_middle_one_unsigned_first':
        b['receivers'][mid].pop(0);b['receivers'][a][0]['record']['inbound_group']='UNSIGNED_EDIT'
    elif name=='client_group_conflict':b['client'][0]['group']='UNSIGNED_EDIT'
    elif name=='duplicate_middle':b['receivers'][mid].append(copy.deepcopy(b['receivers'][mid][0]))
    elif name=='unknown_group_unsigned':b['receivers'][z][0]['record']['inbound_group']='OTHER_GROUP'
    else:raise ValueError(name)
    return b

# Oracle is independent of v45's logic: first classify integrity failures,
# then use configuration and whether a complete corroborated connection remains
# in ANY transaction. Every path has 3 transactions by precondition.
ALWAYS_INVALID={'unsigned_middle_group','unsigned_last_proof',
 'missing_first_one_unsigned_last','missing_middle_one_unsigned_first',
 'client_group_conflict','duplicate_middle','unknown_group_unsigned','missing_client_shift'}

def expected(groups,approved,mutation):
    if mutation in ALWAYS_INVALID:return 'INVALID'
    # Missing client observation: 1st transaction uncorroborated. Middle/last
    # paths can still be independently established from later transactions.
    if mutation=='missing_client_all':
        # second+third connections remain corroborated; first does not.
        present={1,2}
    elif mutation=='missing_first_all':present={0,2} # first missing means second antecedent absent
    elif mutation=='missing_middle_all':present={0} # second missing destroys third antecedent
    elif mutation=='missing_last_all':present={0,1}
    else:present={0,1,2} # only one transaction absent; others intact
    if any(groups[i]==v.CLASSIC for i in present):return 'VIOLATED'
    if any(groups[i] not in approved for i in present):return 'UNRESOLVED'
    if len(present)<3 or mutation!='unaltered':return 'UNRESOLVED'
    return 'SATISFIED'

def main():
    pa=argparse.ArgumentParser(description=__doc__)
    pa.add_argument('--out',required=True);pa.add_argument('--live',action='store_true')
    pa.add_argument('--openssl',default='openssl');pa.add_argument('--count',type=int,default=3)
    args=pa.parse_args()
    if args.count!=3:pa.error('This independent oracle requires --count 3')
    if args.live and os.geteuid()!=0:pa.error('Live UID-isolated test requires sudo')
    out=Path(args.out).resolve()
    if out.exists() and any(out.iterdir()):pa.error('Refusing to overwrite '+str(out))
    out.mkdir(parents=True,exist_ok=True)
    cases=[];live_meta=[];failures=[]
    def run_batch(config,groups,batch,origin,access=None):
        pub=batch['registered_public_keys']
        # Do not serialize signed evidence or private keys by default: these are
        # fresh, live inputs, assessed in memory; records are verdicts+hashes.
        batch_hash=hashlib.sha256(v.canon(batch)).hexdigest()
        actual=tuple(batch['receivers'][node][0]['record']['inbound_group'] for node in v.NODES)
        if actual != tuple(groups):raise AssertionError((config,'negotiated groups',actual,groups))
        if access is not None and access.get('denied')!=[True]*3:raise AssertionError((config,'uid isolation',access))
        live_meta.append(dict(config=config,source=origin,requested='|'.join(groups),observed='|'.join(actual),transactions=len(batch['transactions']),bundle_sha256=batch_hash,uid_isolation=bool(access is not None and access.get('denied')==[True]*3)))
        for policy,approved in p44.POLICIES.items():
            for mutation in MUTATIONS:
                b=mutate(batch,mutation)
                oracle=expected(groups,set(approved),mutation)
                result=verify_partial(b,pub,approved)
                try: legacy32=v.verify(b,pub)
                except Exception as exc:legacy32='EXCEPTION:'+type(exc).__name__
                try: legacy44=p44.verify_policy(b,pub,approved)
                except Exception as exc:legacy44='EXCEPTION:'+type(exc).__name__
                cases.append(dict(source=origin,config=config,policy=policy,mutation=mutation,expected=oracle,v45=result,pass_test=result==oracle,v32=legacy32,v44=legacy44,legacy_diff=result!=legacy44,source_bundle_sha256=batch_hash))
                if result!=oracle:failures.append((config,policy,mutation,oracle,result))
            # challenge ledger and tamper checks: independent ephemeral state
            with tempfile.TemporaryDirectory(prefix='v46-ledger-') as d:
                gate=PartialLedger(Path(d)/'ledger.sqlite',approved)
                challenge=batch['transactions'][0]['challenge']
                base=verify_partial(batch,pub,approved)
                first=gate.check(batch,pub,challenge)
                second=PartialLedger(Path(d)/'ledger.sqlite',approved).check(batch,pub,challenge)
                foreign=gate.check(batch,pub,secrets.token_hex(32))
                expected_repeat='INVALID' if base in ('VIOLATED','SATISFIED') else base
                for tag,got,oracle in [('fresh_first',first,base),('fresh_reuse',second,expected_repeat),('fresh_foreign',foreign,'INVALID')]:
                    cases.append(dict(source=origin,config=config,policy=policy,mutation=tag,expected=oracle,v45=got,pass_test=got==oracle,v32='NOT_APPLICABLE',v44='NOT_APPLICABLE',legacy_diff='',source_bundle_sha256=batch_hash))
                    if got!=oracle:failures.append((config,policy,tag,oracle,got))
    if args.live:
        with tempfile.TemporaryDirectory(prefix='pqtls-v46-') as td:
            os.chmod(td,0o711); tmp=Path(td)
            cert=tmp/'cert.pem';key=tmp/'key.pem'
            subprocess.run([args.openssl,'req','-x509','-newkey','rsa:2048','-nodes','-subj','/CN=localhost','-days','1','-keyout',str(key),'-out',str(cert)],check=True,stdout=subprocess.DEVNULL,stderr=subprocess.DEVNULL)
            uids=v.choose_uids()
            for config,groups in p44.CONFIGS:
                secret_dir=tmp/('keys-'+config);secret_dir.mkdir(mode=0o711);os.chmod(secret_dir,0o711)
                bundle,uidinfo,access=v.live_case(cert,key,groups,args.count,secrets.token_hex(32),uids[:3],uids[3],secret_dir)
                run_batch(config,groups,bundle,'live-TLS-1.3',access)
    else:
        for config,groups in p44.CONFIGS:
            bundle=p44.synthetic(groups,args.count)
            run_batch(config,groups,bundle,'synthetic-smoke')
    with (out/'cases.csv').open('w',newline='') as f:
        writer=csv.DictWriter(f,fieldnames=list(cases[0]));writer.writeheader();writer.writerows(cases)
    with (out/'live_evidence_manifest.csv').open('w',newline='') as f:
        writer=csv.DictWriter(f,fieldnames=list(live_meta[0]));writer.writeheader();writer.writerows(live_meta)
    counts=dict(Counter((r['policy'],r['mutation'],str(r['pass_test'])) for r in cases))
    summary={'experiment':'v46 live-evidence partial-verdict validation','source':'live-TLS-1.3' if args.live else 'synthetic-smoke','run_utc':datetime.now(timezone.utc).isoformat(),'tls_paths':len(live_meta),'decisions':len(cases),'passed':sum(r['pass_test'] for r in cases),'failed':len(failures),'v45_vs_v44_differences':sum(bool(r['legacy_diff']) for r in cases),'failures':failures,'sha256_files':{},'limitations':'Independent mutation oracle over three transactions; locally issued self-signed certificate; client observation is trusted input; evidence bundles processed in memory; no production-scale or post-quantum authentication claim.'}
    for name in ('v32_protected_freshness.py','v44_policy_aware_live.py','v45_precedence_verifier.py',Path(__file__).name):
        path=Path(__file__).resolve().parent/name
        if path.exists():summary['sha256_files'][name]=hashlib.sha256(path.read_bytes()).hexdigest()
    (out/'summary.json').write_text(json.dumps(summary,indent=2)+'\n')
    print(json.dumps(summary,indent=2))
    return 2 if failures else 0
if __name__=='__main__':sys.exit(main())
