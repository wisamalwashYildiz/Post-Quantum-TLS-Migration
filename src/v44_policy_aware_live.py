#!/usr/bin/env python3
"""Separate policy-aware v3.2 verifier, live TLS and negative-control experiment.
Does not modify original implementation or evidence. Local self-signed TLS only.
"""
import argparse, base64, copy, csv, hashlib, json, os, secrets, sqlite3, subprocess, sys, tempfile
from collections import Counter
from pathlib import Path
from datetime import datetime, timezone

import v32_protected_freshness as v

HYBRIDS = ('X25519MLKEM768', 'SecP256r1MLKEM768', 'SecP384r1MLKEM1024')
CLASSIC = v.CLASSIC
CONFIGS = (
 ('same_hybrid', (HYBRIDS[0],)*3),
 ('heterogeneous', HYBRIDS),
 ('p256_all', (HYBRIDS[1],)*3),
 ('p384_all', (HYBRIDS[2],)*3),
 ('classical_middle', (HYBRIDS[0],CLASSIC,HYBRIDS[0])),
)
POLICIES = {'strict': (HYBRIDS[0],), 'multi_hybrid': HYBRIDS}

def verify_policy(batch, keys, approved, disallowed=(CLASSIC,)):
    """Conservative positional semantics matching v32; no unsupported skip-ahead.
    Missing receipt / unrecognized group -> UNRESOLVED; failed supplied checks -> INVALID.
    Existing v32's early return means VIOLATED does not override subsequent missing data.
    """
    if not isinstance(approved, (tuple,list,set,frozenset)) or not approved:
        raise ValueError('approved groups must be nonempty')
    approved=set(approved); disallowed=set(disallowed)
    if approved & disallowed:raise ValueError('approved/disallowed overlap')
    txs=batch.get('transactions',[])
    if not txs:return 'UNRESOLVED'
    nonces=set(); violating=False; unknown=False
    for seq,tx in enumerate(txs):
        if not isinstance(tx,dict) or tx.get('sequence')!=seq or not isinstance(tx.get('nonce'),str) or not tx['nonce'] or tx['nonce'] in nonces:
            return 'INVALID'
        nonces.add(tx['nonce'])
        try:
            previous=batch['client'][seq]
            for i,node in enumerate(v.NODES):
                receipt=batch['receivers'][node][seq]
                if not v.valid(keys[node],receipt):return 'INVALID'
                record=receipt['record']
                if (record['node']!=node or record['sequence']!=seq or record['tx_hash']!=v.digest(tx)):
                    return 'INVALID'
                prev_group=previous['group'] if i==0 else previous['outbound_group']
                prev_proof=previous['proof'] if i==0 else previous['outbound_proof']
                if (record['inbound_group']!=prev_group or
                    not secrets.compare_digest(record['inbound_proof'],prev_proof)):
                    return 'INVALID'
                grp=record['inbound_group']
                if grp in disallowed:violating=True
                elif grp not in approved:unknown=True
                previous=record
        except (IndexError,KeyError,TypeError,AttributeError):return 'UNRESOLVED'
    if violating:return 'VIOLATED'
    if unknown:return 'UNRESOLVED'
    return 'SATISFIED'

class PolicyLedger:
    """Atomic verification for one verifier-defined policy and durable single-use challenge.
    Shares no ledger with v32 to avoid changes to baseline evidence state.
    """
    def __init__(self,path,approved):
        self.path=str(path);self.approved=tuple(approved)
        with sqlite3.connect(self.path) as db:
            db.execute('CREATE TABLE IF NOT EXISTS accepted (challenge_hash TEXT PRIMARY KEY, verdict TEXT NOT NULL)')
    def check(self,batch,keys,challenge):
        if not isinstance(challenge,str) or len(challenge)<32:return 'INVALID'
        txs=batch.get('transactions',[])
        if not txs:return 'UNRESOLVED'
        if any(t.get('challenge')!=challenge for t in txs):return 'INVALID'
        token=hashlib.sha256(challenge.encode()).hexdigest()
        with sqlite3.connect(self.path,timeout=10,isolation_level=None) as db:
            db.execute('BEGIN IMMEDIATE')
            if db.execute('SELECT 1 FROM accepted WHERE challenge_hash=?',(token,)).fetchone():
                db.execute('ROLLBACK');return 'INVALID'
            outcome=verify_policy(batch,keys,self.approved)
            if outcome in ('SATISFIED','VIOLATED'):
                db.execute('INSERT INTO accepted VALUES (?,?)',(token,outcome))
            db.execute('COMMIT')
            return outcome

def cases_for(batch,source,requested,actual,out):
    keys=batch['registered_public_keys']
    rows=[]
    for policy,approved in POLICIES.items():
        truth='VIOLATED' if CLASSIC in requested else ('SATISFIED' if set(requested)<=set(approved) else 'UNRESOLVED')
        baseline=verify_policy(batch,keys,approved)
        legacy=v.verify(batch,keys)
        rows.append(dict(source=source,configuration=out,policy=policy,intervention='unaltered',actual='|'.join(actual),verdict=baseline,expected=truth,pass_test=baseline==truth,legacy=legacy))
        # Modification without corresponding signing credential.
        altered=copy.deepcopy(batch)
        altered['receivers'][v.NODES[1]][0]['record']['inbound_group']=('X25519' if actual[1]!='X25519' else HYBRIDS[0])
        r=verify_policy(altered,keys,approved)
        rows.append(dict(source=source,configuration=out,policy=policy,intervention='unsigned_group_edit',actual='|'.join(actual),verdict=r,expected='INVALID',pass_test=r=='INVALID',legacy=''))
        altered=copy.deepcopy(batch)
        altered['receivers'][v.NODES[1]][0]['record']['inbound_proof']='f'*64
        r=verify_policy(altered,keys,approved)
        rows.append(dict(source=source,configuration=out,policy=policy,intervention='unsigned_exporter_edit',actual='|'.join(actual),verdict=r,expected='INVALID',pass_test=r=='INVALID',legacy=''))
        absent=copy.deepcopy(batch)
        absent['receivers'][v.NODES[1]].pop()
        r=verify_policy(absent,keys,approved)
        rows.append(dict(source=source,configuration=out,policy=policy,intervention='missing_middle_receiver',actual='|'.join(actual),verdict=r,expected='UNRESOLVED',pass_test=r=='UNRESOLVED',legacy=''))
        # Use separate isolated challenge ledgers per policy/configuration.
        path=Path(tempfile.mkdtemp(prefix='v44-policy-ledger-'))/'ledger.sqlite'
        try:
            challenge=batch['transactions'][0]['challenge']
            gate=PolicyLedger(path,approved)
            first=gate.check(batch,keys,challenge)
            rows.append(dict(source=source,configuration=out,policy=policy,intervention='fresh_first',actual='|'.join(actual),verdict=first,expected=truth,pass_test=first==truth,legacy=''))
            replay=PolicyLedger(path,approved).check(batch,keys,challenge)
            exp_replay='INVALID' if first in ('SATISFIED','VIOLATED') else truth
            rows.append(dict(source=source,configuration=out,policy=policy,intervention='same_challenge_again',actual='|'.join(actual),verdict=replay,expected=exp_replay,pass_test=replay==exp_replay,legacy=''))
            stale=PolicyLedger(path,approved).check(batch,keys,secrets.token_hex(32))
            rows.append(dict(source=source,configuration=out,policy=policy,intervention='different_challenge',actual='|'.join(actual),verdict=stale,expected='INVALID',pass_test=stale=='INVALID',legacy=''))
        finally:
            try:path.unlink(missing_ok=True);path.parent.rmdir()
            except OSError:pass
    return rows

def synthetic(groups,count=3):
    from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
    from cryptography.hazmat.primitives import serialization
    private={n:Ed25519PrivateKey.generate() for n in v.NODES}
    public={n:sk.public_key().public_bytes(serialization.Encoding.Raw,serialization.PublicFormat.Raw).hex() for n,sk in private.items()}
    challenge=secrets.token_hex(32)
    batch={'transactions':[],'client':[],'receivers':{n:[] for n in v.NODES},'registered_public_keys':public}
    for seq in range(count):
        tx={'nonce':secrets.token_hex(16),'challenge':challenge,'sequence':seq,'payload':'v44 synthetic case'}
        batch['transactions'].append(tx)
        proofs=[hashlib.sha256(f'v44/{challenge}/{seq}/{i}'.encode()).hexdigest() for i in range(3)]
        batch['client'].append({'group':groups[0],'proof':proofs[0]})
        for i,n in enumerate(v.NODES):
            rec={'node':n,'sequence':seq,'tx_hash':v.digest(tx),'inbound_group':groups[i],'inbound_proof':proofs[i], 'outbound_group':groups[i+1] if i<2 else None,'outbound_proof':proofs[i+1] if i<2 else None}
            batch['receivers'][n].append(v.signed(private[n],rec))
    return batch

def live(groups,count,cert,key,uidroot,ids):
    private=uidroot/('keys-'+secrets.token_hex(5));private.mkdir(mode=0o711)
    os.chmod(private,0o711)
    batch,uids,access=v.live_case(cert,key,groups,count,secrets.token_hex(32),ids[:3],ids[3],private)
    actual=[batch['receivers'][n][0]['record']['inbound_group'] for n in v.NODES]
    return batch,actual,uids,access

def main():
    p=argparse.ArgumentParser()
    p.add_argument('--out',required=True,help='New isolated output directory')
    p.add_argument('--live',action='store_true',help='Create real 3-hop TLS 1.3 connections (requires root)')
    p.add_argument('--openssl',default='openssl')
    p.add_argument('--count',type=int,default=3)
    args=p.parse_args()
    if args.count<1 or args.count>20:p.error('count must be 1..20')
    out=Path(args.out).resolve();out.mkdir(parents=True,exist_ok=True)
    if any(out.iterdir()):raise SystemExit('Refusing to overwrite nonempty result directory: '+str(out))
    if args.live and os.geteuid()!=0:raise SystemExit('Live run requires root (sudo) for real receiver UID isolation')
    rows=[];source='live-TLS-1.3' if args.live else 'synthetic-offline'
    if args.live:
        with tempfile.TemporaryDirectory(prefix='pqtls-v44-') as tmp:
            os.chmod(tmp,0o711);temp=Path(tmp)
            cert=temp/'cert.pem';key=temp/'key.pem'
            subprocess.run([args.openssl,'req','-x509','-newkey','rsa:2048','-nodes','-subj','/CN=localhost','-days','1','-keyout',str(key),'-out',str(cert)],check=True,stdout=subprocess.DEVNULL,stderr=subprocess.DEVNULL)
            ids=v.choose_uids()
            for config,groups in CONFIGS:
                batch,actual,uidinfo,access=live(groups,args.count,cert,key,temp,ids)
                if list(groups)!=actual:raise RuntimeError('Negotiated group mismatch: '+config)
                if access.get('denied')!=[True]*3:raise RuntimeError('Key isolation failed: '+config)
                rows.extend(cases_for(batch,source,groups,actual,config))
    else:
        for config,groups in CONFIGS:
            batch=synthetic(groups,args.count)
            rows.extend(cases_for(batch,source,groups,groups,config))
    with (out/'cases.csv').open('w',newline='') as f:
        w=csv.DictWriter(f,fieldnames=list(rows[0]));w.writeheader();w.writerows(rows)
    counts=dict(Counter((r['intervention'],str(r['pass_test'])) for r in rows))
    summary={'source':source,'cases':len(rows),'passed':sum(r['pass_test'] for r in rows),'failed':sum(not r['pass_test'] for r in rows),'configurations':len(CONFIGS),'policies':list(POLICIES),'run_utc':datetime.now(timezone.utc).isoformat(),'note':'v44 is an independent policy-aware extension; missing evidence behavior remains conservative and positional, matching v32; synthetic is not live evidence.', 'counts':{str(k):n for k,n in counts.items()}}
    (out/'summary.json').write_text(json.dumps(summary,indent=2)+'\n')
    (out/'source_sha256.txt').write_text(hashlib.sha256(Path(__file__).read_bytes()).hexdigest()+'  '+Path(__file__).name+'\n')
    print(json.dumps(summary,indent=2))
    if summary['failed']:sys.exit(2)
if __name__=='__main__':main()
