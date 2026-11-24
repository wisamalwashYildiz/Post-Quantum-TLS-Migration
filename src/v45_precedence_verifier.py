#!/usr/bin/env python3
"""v45 experimental reference: authenticated partial-evidence appraisal.

Preserves original v32/v44. Unlike positional verifiers, receipts are indexed by
signed (role, sequence). A signed receiver report is independently authenticated;
a negotiated group is *corroborated* only when the preceding endpoint observation
is available and matches. Missing antecedents cannot prove the group. Invalid
present receipts are detected independently of missing other receipts.
This is a laboratory model, not a proof against colluding trusted signers.
"""
import hashlib, secrets, sqlite3
from pathlib import Path
import v32_protected_freshness as v

VERDICTS={'SATISFIED','VIOLATED','INVALID','UNRESOLVED'}

def verify_partial(batch, keys, approved, disallowed=None):
    approved=set(approved)
    disallowed=set((v.CLASSIC,) if disallowed is None else disallowed)
    if not approved or approved & disallowed:
        raise ValueError('Approved and disallowed policy sets must be nonempty/disjoint')
    if not isinstance(batch,dict) or not isinstance(keys,dict):return 'INVALID'
    txs=batch.get('transactions')
    if not isinstance(txs,list):return 'INVALID'
    if not txs:return 'UNRESOLVED'
    nonces=set()
    for seq,tx in enumerate(txs):
        if not isinstance(tx,dict) or tx.get('sequence')!=seq or not isinstance(tx.get('nonce'),str) or not tx['nonce'] or tx['nonce'] in nonces:
            return 'INVALID'
        nonces.add(tx['nonce'])
    clients=batch.get('client',[])
    receivers=batch.get('receivers',{})
    if not isinstance(clients,list) or not isinstance(receivers,dict):return 'INVALID'
    indexed={}
    # Authenticate *all supplied receipts* first, including ones beyond gaps.
    for node in v.NODES:
        entries=receivers.get(node,[])
        if not isinstance(entries,list):return 'INVALID'
        pub=keys.get(node)
        if not isinstance(pub,str):return 'INVALID'
        for entry in entries:
            if not isinstance(entry,dict) or not v.valid(pub,entry):return 'INVALID'
            record=entry['record']
            if not isinstance(record,dict) or record.get('node')!=node:return 'INVALID'
            seq=record.get('sequence')
            if type(seq)!=int or seq<0 or seq>=len(txs):return 'INVALID'
            if (node,seq) in indexed:return 'INVALID'
            if record.get('tx_hash')!=v.digest(txs[seq]):return 'INVALID'
            indexed[(node,seq)]=record
    # Client proof is not independently authenticated by this code: trusted
    # initial-client observation is an explicitly assumed input.
    if len(clients)>len(txs):return 'INVALID'
    missing=False;unknown=False;violated=False
    for seq,tx in enumerate(txs):
        previous=clients[seq] if seq<len(clients) else None
        if previous is not None and (not isinstance(previous,dict) or not isinstance(previous.get('group'),str) or not isinstance(previous.get('proof'),str)):
            return 'INVALID'
        for i,node in enumerate(v.NODES):
            rec=indexed.get((node,seq))
            if rec is None:
                missing=True;previous=None
                continue
            group=rec.get('inbound_group');prf=rec.get('inbound_proof')
            if not isinstance(group,str) or not isinstance(prf,str):return 'INVALID'
            if previous is None:
                missing=True
                # authenticated present receipt, but cannot corroborate this
                # inbound group without its preceding observation
            else:
                p_group=previous.get('group') if i==0 else previous.get('outbound_group')
                p_proof=previous.get('proof') if i==0 else previous.get('outbound_proof')
                if not isinstance(p_group,str) or not isinstance(p_proof,str):return 'INVALID'
                if group!=p_group or not secrets.compare_digest(prf,p_proof):return 'INVALID'
                if group in disallowed:violated=True
                elif group not in approved:unknown=True
            previous=rec
    if violated:return 'VIOLATED'
    if missing or unknown:return 'UNRESOLVED'
    return 'SATISFIED'

class PartialLedger:
    def __init__(self,path,approved):
        self.path=str(path);self.approved=tuple(approved)
        Path(self.path).parent.mkdir(parents=True,exist_ok=True)
        with sqlite3.connect(self.path) as db:
            db.execute('CREATE TABLE IF NOT EXISTS accepted (challenge_hash TEXT PRIMARY KEY, verdict TEXT NOT NULL)')
    def check(self,batch,keys,challenge):
        if not isinstance(challenge,str) or len(challenge)<32:return 'INVALID'
        txs=batch.get('transactions',[]) if isinstance(batch,dict) else []
        if not txs:return 'UNRESOLVED'
        if any(not isinstance(t,dict) or t.get('challenge')!=challenge for t in txs):return 'INVALID'
        token=hashlib.sha256(challenge.encode()).hexdigest()
        with sqlite3.connect(self.path,timeout=20,isolation_level=None) as db:
            db.execute('BEGIN IMMEDIATE')
            if db.execute('SELECT 1 FROM accepted WHERE challenge_hash=?',(token,)).fetchone():
                db.execute('ROLLBACK');return 'INVALID'
            result=verify_partial(batch,keys,self.approved)
            if result in ('SATISFIED','VIOLATED'):
                db.execute('INSERT INTO accepted VALUES (?,?)',(token,result))
            db.execute('COMMIT')
            return result
