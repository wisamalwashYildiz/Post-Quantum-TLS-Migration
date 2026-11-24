#!/usr/bin/env python3
"""v2.2: finite evidence-world trust-cut audit, not a new TLS cryptographic primitive.

Assumptions: observed signed claims can be repeated in different real-world states
when signers may be dishonest. Trusted endpoint observations rule out states in
which their recorded values differ. This finite model makes impossibility explicit.
"""
import argparse, hashlib, json, itertools
from pathlib import Path

HYBRID='X25519MLKEM768'; CLASSIC='X25519'

def worlds(hops=3):
    return tuple(itertools.product((HYBRID,CLASSIC),repeat=hops))

def compatible(world, claims, trusted):
    return all(world[i] == claims[i] for i in trusted)

def assess(claims, trusted=(), require_hybrid=True):
    n=len(claims)
    if not n:return {'verdict':'UNRESOLVED','possible_worlds':0,'hybrid_worlds':0,'classical_worlds':0}
    if any(i not in range(n) for i in trusted):raise ValueError('out-of-range trusted endpoint')
    if any(c not in (HYBRID,CLASSIC) for c in claims):raise ValueError('invalid group label')
    compatible_worlds=[w for w in worlds(n) if compatible(w,claims,trusted)]
    compliant=sum(all(x==HYBRID for x in w) for w in compatible_worlds)
    violating=len(compatible_worlds)-compliant
    verdict=('SATISFIED' if violating==0 else 'VIOLATED' if compliant==0 else 'UNRESOLVED')
    return {'verdict':verdict,'possible_worlds':len(compatible_worlds),'hybrid_worlds':compliant,'classical_worlds':violating}

def minimal_trust_sets(claims, target_verdict='SATISFIED'):
    n=len(claims);answers=[]
    for k in range(n+1):
        for subset in itertools.combinations(range(n),k):
            if any(set(s).issubset(subset) for s in answers):continue
            if assess(claims,subset)['verdict']==target_verdict:answers.append(subset)
    return answers

def audit_from_v21(v21):
    checks=v21.get('checks',{});t=checks.get('dishonest_signers_limitation')
    if not t or t[0]!='ATTESTED':raise ValueError('v2.1 negative control missing/changed')
    result={
      'version':'2.2 finite trust-cut audit',
      'source_version':v21.get('version'),
      'premise':'An authenticated claim is not an independently truthful measurement. Signing-key possession is not observer independence.',
      'comparison':{'v21_offline_authentication':'ATTESTED even for two fabricated signed tags','actual_hybrid_group_on_v21_tls':'NOT MEASURED BY v2.1'},
      'three_hop_hybrid_claims':list([HYBRID]*3),
      'by_trusted_receivers':{},
      'minimal_sufficient_trust_sets':minimal_trust_sets([HYBRID]*3),
      'one_classical_claim_with_honest_receiver':{},
      'limits':['Finite 2-state-per-hop logical audit, not live TLS measurement',
                'Trusted receivers assumed accurate and independent of adversary control',
                'Only positive whole-path assurance modeled; route completeness and transaction-link honesty also required',
                'Trust sets are minimum under this restricted model, not a measured OS compromise guarantee',
                'A malicious receiver can assert arbitrary true-looking evidence; signatures alone cannot prevent it']}
    for trusted in [(),(0,),(0,1),(0,1,2)]:
        result['by_trusted_receivers'][','.join(map(str,trusted)) or 'none']=assess([HYBRID]*3,trusted)
    claims=[HYBRID,CLASSIC,HYBRID]
    result['one_classical_claim_with_honest_receiver']={'untrusted':assess(claims,()),'middle_trusted':assess(claims,(1,))}
    return result

def main():
    p=argparse.ArgumentParser();p.add_argument('--v21-evidence',required=True);p.add_argument('--output',default='results/trust_cut_v22');a=p.parse_args()
    source=json.loads(Path(a.v21_evidence).read_text())
    result=audit_from_v21(source)
    out=Path(a.output);out.mkdir(parents=True,exist_ok=True)
    (out/'trust_cut.json').write_text(json.dumps(result,indent=2)+'\n')
    print('v2.1 dishonest_signers_limitation:',result['comparison']['v21_offline_authentication'])
    for subset,check in result['by_trusted_receivers'].items():print('trusted='+subset,check['verdict'],f"worlds={check['possible_worlds']}")
    print('trusted classical middle:',result['one_classical_claim_with_honest_receiver']['middle_trusted']['verdict'])
    assert result['by_trusted_receivers']['none']['verdict']=='UNRESOLVED'
    assert result['by_trusted_receivers']['0,1,2']['verdict']=='SATISFIED'
    print('PASS: finite trust-cut audit, no unsupported proof of live TLS trust isolation')
if __name__=='__main__':main()
