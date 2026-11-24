# v2.2 — Authenticated-claim non-identifiability and trust-cut pilot

This is an **offline finite-world reasoning audit** over the **actual v2.1 negative-control output**, not another live TLS experiment. It preserves all existing project files.

## What is being established
Two signed statements can be accepted (`ATTESTED`) in v2.1 even when their tag values are fabricated by authorized signers. Because the offline transcript cannot identify whether the reported groups/values were honestly measured, honest-hybrid and dishonest-classical worlds can be observationally indistinguishable to such a verifier.

For an illustrative three-hop *hybrid-claims* world, we enumerate 2^3 = 8 possible hybrid/classical ground-truth vectors. An independently **trusted** receiver observation rules out inconsistent worlds on its hop. With none trusted, all 8 worlds remain and whole-path hybrid assurance is `UNRESOLVED`; with all three trusted and all honestly observing hybrid, only the all-hybrid world remains and verdict is `SATISFIED` **within this restricted model**. One trusted classical observation suffices to establish `VIOLATED` for a verified path. Under these assumptions, full positive assurance requires all three receiving observations. This is a simple logical result, not a novel mathematical theorem or universal lower bound.

## Running
From a new PowerShell terminal: `wsl -d Ubuntu-22.04`.
Then in Ubuntu:

```bash
cd "/mnt/d/Articles/Post-Quantum TLS Migration/Post-Quantum TLS Migration-Project"
source "$HOME/pqc-research-venv/bin/activate"
python -m unittest discover -s tests -p 'test_*.py' -v
python src/trust_cut_v22.py --v21-evidence results/endpoint_attestation_v21/endpoint_attestation.json --output results/trust_cut_v22
```

The standalone 12 v2.2 tests pass with system Python. No new dependencies; no OpenSSL binary called in v2.2. The existing 95 tests are expected to yield 107 in the integrated Ubuntu tree, if all prior tests are present and remain passing; this was not run on the user's filesystem.

## Important caveats
- Trust must be externally grounded: HMAC/Ed25519 signatures do not make the underlying observations truthful.
- The finite model assumes a **known complete path**, truthful independently trusted receiving measurement, one negotiated TLS group per hop and trustworthy transaction-path membership. It does not model routes, asynchronous failures, TLS resumption, side channels, traffic replay, compromising observer and sender, malicious signing with protected keys, or compromised host OS.
- No cryptographic channel binding, sandboxed observer, independently authenticated KEX evidence or Q1 novelty is demonstrated by this pilot.
- For empirical progress, next build protected endpoint measurements tied to the **same** live TLS exporter and negotiated group, and run strong side-by-side baselines under identical privilege and threat models.
