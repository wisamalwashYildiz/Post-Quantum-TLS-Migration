#!/usr/bin/env python3
"""v3.2 laboratory gate: distinct real Linux UIDs, session-bound receipts, verifier challenges.
Run only under sudo in a disposable local environment. Root is trusted; no root compromise resistance.
"""
import argparse, base64, copy, csv, hashlib, json, multiprocessing as mp, os, secrets, socket, subprocess, tempfile, time, uuid, pwd, stat, sqlite3, encodings.idna
from datetime import datetime, timezone
from pathlib import Path
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey, Ed25519PublicKey
from cryptography.hazmat.primitives import serialization
from OpenSSL import SSL
from v30_session_gate import NODES, HYBRID, CLASSIC, canon, digest, ctx, group, proof, io, send, recv

def signed(sk, record):
    return {'record':record, 'signature':base64.b64encode(sk.sign(canon(record))).decode('ascii')}

def public_bytes(sk):
    return sk.public_key().public_bytes(encoding=serialization.Encoding.Raw,format=serialization.PublicFormat.Raw).hex()

def valid(pubhex, signed_record):
    try:
        Ed25519PublicKey.from_public_bytes(bytes.fromhex(pubhex)).verify(base64.b64decode(signed_record['signature'],validate=True),canon(signed_record['record']))
        return True
    except (ValueError,TypeError,KeyError,Exception):
        return False

def listen():
    s=socket.socket();s.setsockopt(socket.SOL_SOCKET,socket.SO_REUSEADDR,1)
    s.bind(('127.0.0.1',0));s.listen(1);s.settimeout(20)
    return s

def drop_to(uid):
    os.setgroups([])
    os.setgid(uid)
    os.setuid(uid)
    if os.geteuid()!=uid or os.getegid()!=uid:raise RuntimeError('UID drop unsuccessful')

def choose_uids():
    result=[]
    for uid in range(62001,62999):
        try:pwd.getpwuid(uid)
        except KeyError:result.append(uid)
        if len(result)==4:return result
    raise RuntimeError('No unassigned test UIDs available')

def attacker_probe(paths,uid,pipe):
    try:
        drop_to(uid)
        denied=[]
        for path in paths:
            try:
                with open(path,'rb') as f:f.read(1)
                denied.append(False)
            except PermissionError:denied.append(True)
        pipe.send({'uid':os.geteuid(),'denied':denied})
    except BaseException as exc:pipe.send({'error':repr(exc)})
    finally:pipe.close()

def endpoint(index,listener,down_port,cert,key,groups,count,channel,uid,keydir):
    name=NODES[index]
    try:
        # Load certificate material into TLS contexts before restricting UID.
        # This lab reuses one certificate; peer certificate authentication is disabled.
        server_ctx=ctx(True,cert,key,groups[index])
        outgoing_ctx=ctx(False,group_name=groups[index+1]) if down_port is not None else None
        drop_to(uid)
        sk=Ed25519PrivateKey.generate()
        private=sk.private_bytes(serialization.Encoding.Raw,serialization.PrivateFormat.Raw,serialization.NoEncryption())
        private_path=Path(keydir)/'signing.key'
        fd=os.open(private_path,os.O_WRONLY|os.O_CREAT|os.O_EXCL,0o600)
        with os.fdopen(fd,'wb') as f:f.write(private)
        channel.send(('pub',{'key':public_bytes(sk),'uid':os.geteuid(),'pid':os.getpid()}))
        sock,_=listener.accept()
        with sock:
            incoming=SSL.Connection(server_ctx,sock)
            incoming.set_accept_state();io(incoming,incoming.do_handshake)
            incoming_group=group(incoming)
            downstream=None;outgoing_group=None;dsock=None
            if down_port is not None:
                dsock=socket.create_connection(('127.0.0.1',down_port),timeout=15)
                downstream=SSL.Connection(outgoing_ctx,dsock)
                downstream.set_connect_state();io(downstream,downstream.do_handshake)
                outgoing_group=group(downstream)
            records=[]
            for seq in range(count):
                tx=recv(incoming)
                if tx.get('sequence')!=seq:raise ValueError('sequence mismatch')
                if downstream:
                    send(downstream,tx);ack=recv(downstream)
                else:ack={'ok':digest(tx)}
                if ack!={'ok':digest(tx)}:raise ValueError('ack mismatch')
                record={'node':name,'sequence':seq,'tx_hash':digest(tx),
                        'inbound_group':incoming_group,'inbound_proof':proof(incoming,tx,name),
                        'outbound_group':outgoing_group,
                        'outbound_proof':proof(downstream,tx,NODES[index+1]) if downstream else None}
                records.append(signed(sk,record));send(incoming,ack)
            if downstream:downstream.shutdown();downstream.close();dsock.close()
            incoming.shutdown();incoming.close()
        channel.send(('records',records))
    except BaseException as exc:
        try:channel.send(('error',repr(exc)))
        except Exception:pass
    finally:
        listener.close();channel.close()

def live_case(cert,key,groups,count,challenge,role_uids,attacker_uid,secret_root):
    if len(groups)!=3:raise ValueError('three hops required')
    if os.geteuid()!=0:raise PermissionError('Native Linux root is required for real UID isolation')
    if len(set((*role_uids,attacker_uid)))!=4:raise ValueError('UID collision')
    if 'fork' not in mp.get_all_start_methods():raise RuntimeError('Linux fork required')
    context=mp.get_context('fork')
    listeners=[listen() for _ in NODES]
    ports=[s.getsockname()[1] for s in listeners]
    pipes=[context.Pipe(duplex=False) for _ in NODES]
    workers=[]
    keypaths=[]
    for i,name in enumerate(NODES):
        keydir=Path(secret_root)/name
        keydir.mkdir(mode=0o700)
        os.chown(keydir,role_uids[i],role_uids[i])
        os.chmod(keydir,0o700)
        keypaths.append(str(keydir/'signing.key'))
    try:
        for i in reversed(range(3)):
            parent,child=pipes[i]
            proc=context.Process(target=endpoint,args=(i,listeners[i],ports[i+1] if i<2 else None,cert,key,groups,count,child,role_uids[i],str(Path(secret_root)/NODES[i])))
            proc.start();child.close();workers.append(proc)
        keys={};uid_info={}
        for i,name in enumerate(NODES):
            if not pipes[i][0].poll(20):raise TimeoutError('receiver public key timeout: '+name)
            typ,data=pipes[i][0].recv()
            if typ!='pub':raise RuntimeError('receiver startup '+str(data))
            keys[name]=data['key'];uid_info[name]=data['uid']
            if data['uid']!=role_uids[i]:raise RuntimeError('observed UID mismatch: '+name)
            if os.stat(keypaths[i]).st_uid!=role_uids[i] or stat.S_IMODE(os.stat(keypaths[i]).st_mode)!=0o600:
                raise RuntimeError('signer key not properly protected')
        p,c=context.Pipe(duplex=False)
        attacker=context.Process(target=attacker_probe,args=(keypaths,attacker_uid,c));attacker.start();c.close()
        if not p.poll(15):raise TimeoutError('attacker test timed out')
        access=p.recv();p.close();attacker.join(4)
        if access.get('uid')!=attacker_uid or access.get('denied')!=[True]*3:
            raise RuntimeError('role key isolation FAILED: '+str(access))
        sock=socket.create_connection(('127.0.0.1',ports[0]),timeout=15)
        transactions=[];client=[]
        with sock:
            connection=SSL.Connection(ctx(False,group_name=groups[0]),sock)
            connection.set_connect_state();io(connection,connection.do_handshake)
            cg=group(connection)
            for seq in range(count):
                tx={'nonce':secrets.token_hex(16),'challenge':challenge,'sequence':seq,'payload':'v3 protected uid gate'}
                transactions.append(tx);send(connection,tx)
                if recv(connection)!={'ok':digest(tx)}:raise RuntimeError('client ack mismatch')
                client.append({'group':cg,'proof':proof(connection,tx,NODES[0])})
            connection.shutdown();connection.close()
        received={}
        for i,name in enumerate(NODES):
            if not pipes[i][0].poll(20):raise TimeoutError('receiver trace timeout: '+name)
            typ,data=pipes[i][0].recv()
            if typ!='records':raise RuntimeError('receiver failure '+name+': '+str(data))
            received[name]=data
        return {'transactions':transactions,'client':client,'receivers':received,'registered_public_keys':keys},uid_info,access
    finally:
        for parent,child in pipes:parent.close()
        for proc in workers:
            proc.join(2)
            if proc.is_alive():proc.terminate();proc.join(2)
        for listener in listeners:listener.close()

def verify(batch, trusted_keys):
    txs=batch.get('transactions',[])
    if not txs:return 'UNRESOLVED'
    nonces=set();classical=False
    for seq,tx in enumerate(txs):
        if tx.get('sequence')!=seq or not isinstance(tx.get('nonce'),str) or tx['nonce'] in nonces:return 'INVALID'
        nonces.add(tx['nonce'])
        try:
            previous=batch['client'][seq]
            for i,name in enumerate(NODES):
                sr=batch['receivers'][name][seq]
                if not valid(trusted_keys[name],sr):return 'INVALID'
                rec=sr['record']
                if rec['node']!=name or rec['sequence']!=seq or rec['tx_hash']!=digest(tx):return 'INVALID'
                prior_group=previous['group'] if i==0 else previous['outbound_group']
                prior_proof=previous['proof'] if i==0 else previous['outbound_proof']
                if rec['inbound_group']!=prior_group or not secrets.compare_digest(rec['inbound_proof'],prior_proof):return 'INVALID'
                if rec['inbound_group']==CLASSIC:classical=True
                elif rec['inbound_group']!=HYBRID:return 'UNRESOLVED'
                previous=rec
        except (IndexError,KeyError,TypeError):return 'UNRESOLVED'
    return 'VIOLATED' if classical else 'SATISFIED'

class FreshLedger:
    """Durable, atomically reserved verifier challenges (no raw exporter material)."""
    def __init__(self,path):
        self.path=str(path)
        with sqlite3.connect(self.path) as db:
            db.execute('CREATE TABLE IF NOT EXISTS accepted (challenge_hash TEXT PRIMARY KEY, verdict TEXT NOT NULL)')
    def check(self,batch,keys,expected_challenge):
        if not isinstance(expected_challenge,str) or len(expected_challenge)<32:return 'INVALID'
        tx=batch.get('transactions',[])
        if not tx:return 'UNRESOLVED'
        if any(t.get('challenge')!=expected_challenge for t in tx):return 'INVALID'
        token=hashlib.sha256(expected_challenge.encode()).hexdigest()
        with sqlite3.connect(self.path,timeout=10,isolation_level=None) as db:
            db.execute('BEGIN IMMEDIATE')
            if db.execute('SELECT 1 FROM accepted WHERE challenge_hash=?',(token,)).fetchone():
                db.execute('ROLLBACK');return 'INVALID'
            verdict=verify(batch,keys)
            if verdict in ('SATISFIED','VIOLATED'):
                db.execute('INSERT INTO accepted VALUES (?,?)',(token,verdict))
            db.execute('COMMIT')
            return verdict

def adversarial_checks(batch,keys,challenge,ledger_path):
    ledger=FreshLedger(ledger_path)
    baseline=ledger.check(batch,keys,challenge)
    # New verifier instance: test durable rejection after reopen.
    replay=FreshLedger(ledger_path).check(batch,keys,challenge)
    foreign=FreshLedger(ledger_path).check(batch,keys,secrets.token_hex(32))
    forged=copy.deepcopy(batch)
    forged['receivers']['service-a'][0]['record']['inbound_group']=CLASSIC if baseline=='SATISFIED' else HYBRID
    altered=FreshLedger(ledger_path).check(forged,keys,challenge)
    missing=copy.deepcopy(batch);missing['receivers']['service-a'].pop()
    # It must still abstain, even with a new challenge inserted into the batch.
    absent=verify(missing,keys)
    return dict(baseline=baseline,replay_same_challenge=replay,copy_new_challenge=foreign,forged_receiver=altered,missing_witness=absent)

def archive(args):
    if os.geteuid()!=0:raise SystemExit('Run with sudo; native Linux filesystem required for role keys')
    root=Path(args.archive).resolve()
    target=root/('gate_'+datetime.now(timezone.utc).strftime('%Y%m%dT%H%M%SZ')+'_'+uuid.uuid4().hex[:8])
    target.mkdir(parents=True,exist_ok=False)
    rows=[]
    with tempfile.TemporaryDirectory(prefix='pqc-v32-',dir='/var/tmp') as td:
        os.chmod(td,0o711)
        cert=Path(td)/'cert.pem';key=Path(td)/'key.pem'
        conf=os.environ.get('OPENSSL_CONF','/etc/ssl/openssl.cnf')
        cmd=[args.openssl,'req','-x509','-newkey','rsa:2048','-keyout',str(key),'-out',str(cert),'-days','1','-nodes','-subj','/CN=localhost']
        proc=subprocess.run(cmd,env=dict(os.environ,OPENSSL_CONF=conf),capture_output=True,text=True)
        if proc.returncode:raise RuntimeError('openssl certificate failure: '+proc.stderr[-800:])
        for trial in range(1,args.trials+1):
            for scenario,groups in [('hybrid',(HYBRID,)*3),('classical_middle',(HYBRID,CLASSIC,HYBRID))]:
                start=time.perf_counter_ns();row={'trial':trial,'scenario':scenario,'status':'FAIL'}
                with tempfile.TemporaryDirectory(prefix='roles-',dir=td) as role_dir:
                    os.chmod(role_dir,0o711)
                    try:
                        uids=choose_uids();challenge=secrets.token_hex(32)
                        batch,observed,access=live_case(cert,key,groups,args.count,challenge,uids[:3],uids[3],role_dir)
                        check=adversarial_checks(batch,batch['registered_public_keys'],challenge,target/'verifier_ledger.sqlite3')
                        expected={'baseline':'SATISFIED' if scenario=='hybrid' else 'VIOLATED',
                                  'replay_same_challenge':'INVALID','copy_new_challenge':'INVALID',
                                  'forged_receiver':'INVALID','missing_witness':'UNRESOLVED'}
                        if check!=expected:raise RuntimeError('verdict mismatch: '+str(check))
                        row.update(status='PASS',**check,role_uids=observed,attacker_uid=access['uid'],
                                   attacker_key_read_denied=all(access['denied']),
                                   groups=[batch['receivers'][n][0]['record']['inbound_group'] for n in NODES],
                                   signed_receipts=3*args.count)
                    except BaseException as exc:row['error']=repr(exc)
                row['elapsed_ns']=time.perf_counter_ns()-start;rows.append(row)
                (target/f'trial_{trial:03d}_{scenario}.json').write_text(json.dumps(row,indent=2)+'\n')
                print(trial,scenario,row['status'],row.get('error',''),flush=True)
    manifest={'schema':'pqc-v3.2-uid-freshness','date_utc':datetime.now(timezone.utc).isoformat(),
              'openssl':subprocess.check_output([args.openssl,'version'],text=True).strip(),
              'model':'3 distinct numeric Linux UIDs and fourth adversarial UID; trust root orchestrator',
              'trials_requested':args.trials,'transactions_per_connection':args.count,'completed':len(rows),
              'passes':sum(r['status']=='PASS' for r in rows),
              'limits':['root is trusted and could impersonate roles',
                        'worker fork preloads TLS certificate contexts before dropping UID',
                        'verifier replay ledger uses durable SQLite atomic challenge reservations; single-trusted-verifier host only',
                        'certificate verification disabled and shared TLS cert; no PQ authentication',
                        'no remote deployment; honest receiver endpoints, compromised receiver not evaluated',
                        'role signing keys exist only under temporary native Linux filesystem and are destroyed',
                        'no private keys or raw TLS exporter values archived']}
    (target/'manifest.json').write_text(json.dumps(manifest,indent=2)+'\n')
    with (target/'summary.csv').open('w',newline='') as f:
        names=['trial','scenario','status','baseline','replay_same_challenge','copy_new_challenge','forged_receiver','missing_witness','role_uids','attacker_uid','attacker_key_read_denied','groups','signed_receipts','elapsed_ns','error']
        writer=csv.DictWriter(f,fieldnames=names,extrasaction='ignore');writer.writeheader();writer.writerows(rows)
    (target/'checksums.sha256').write_text(''.join(hashlib.sha256(p.read_bytes()).hexdigest()+'  '+p.name+'\n' for p in sorted(target.iterdir()) if p.name!='checksums.sha256'))
    print('ARCHIVE',target)
    if manifest['passes']!=len(rows):raise SystemExit('FAIL: see archived diagnostic')
    print('PASS:',len(rows),'UID-isolated fresh-assurance scenarios')

def main():
    ap=argparse.ArgumentParser()
    ap.add_argument('--openssl',required=True)
    ap.add_argument('--archive',default='/var/tmp/pqc-v32-archive')
    ap.add_argument('--trials',type=int,default=3)
    ap.add_argument('--count',type=int,default=3)
    args=ap.parse_args()
    if not 1<=args.trials<=20 or not 2<=args.count<=30:ap.error('invalid trial/count')
    archive(args)
if __name__=='__main__':main()
