"""LIVE TLS 1.3, three negotiated hybrid group configurations; root UID isolation required.
   Exploratory: v32 verifier recognizes only X25519MLKEM768 and X25519.
   Group-dependent outcomes must be treated separately from negotiated-group evidence.
"""
import argparse, json, os, subprocess, tempfile, secrets, sys, pathlib
from v40_common import save
import v32_protected_freshness as v
GROUPS=['X25519MLKEM768','SecP256r1MLKEM768','SecP384r1MLKEM1024']
def main():
 p=argparse.ArgumentParser();p.add_argument('--out',required=True);p.add_argument('--openssl',default='openssl');p.add_argument('--count',type=int,default=2);a=p.parse_args()
 if os.geteuid()!=0:raise SystemExit('SKIPPED: live TLS with isolated Linux UIDs requires sudo; see README')
 configs=[('same_hybrid',[GROUPS[0]]*3),('heterogeneous',GROUPS),('p256_all',[GROUPS[1]]*3),('p384_all',[GROUPS[2]]*3),('classical_middle',[GROUPS[0],v.CLASSIC,GROUPS[0]])]
 rows=[]
 with tempfile.TemporaryDirectory(prefix='pqtls-v37-') as tmp:
  # Receivers drop privileges; allow traversal of the temporary parent only.
  # Role-specific signing-key directories remain owner-only (0700).
  os.chmod(tmp,0o711)
  cert=pathlib.Path(tmp)/'cert.pem';key=pathlib.Path(tmp)/'key.pem'
  subprocess.run([a.openssl,'req','-x509','-newkey','rsa:2048','-nodes','-subj','/CN=localhost','-days','1','-keyout',str(key),'-out',str(cert)],check=True,stdout=subprocess.DEVNULL,stderr=subprocess.DEVNULL)
  ids=v.choose_uids()
  for name,groups in configs:
   private=pathlib.Path(tmp)/('keys-'+name);private.mkdir(mode=0o711)
   os.chmod(private,0o711)
   try:
    batch,uids,access=v.live_case(cert,key,groups,a.count,secrets.token_hex(32),ids[:3],ids[3],private)
    actual=[batch['receivers'][n][0]['record']['inbound_group'] for n in v.NODES]
    verdict=v.verify(batch,batch['registered_public_keys'])
    rows.append(dict(config=name,requested='|'.join(groups),negotiated='|'.join(actual),legacy_verdict=verdict,matched=actual==groups,status='PASS'))
   except Exception as e:
    rows.append(dict(config=name,requested='|'.join(groups),negotiated='',legacy_verdict='',matched=False,status='ERROR:'+repr(e)))
 summary={'type':'live-TLS-1.3','cases':len(rows),'passed':sum(r['status']=='PASS' for r in rows),'limitations':'Original verifier fixed-group policy; this measures negotiation and baseline compatibility, not new authenticated flexible-policy decision.'}
 save(a.out,rows,summary)
 if summary['passed']!=len(rows):sys.exit(2)
if __name__=='__main__':main()
