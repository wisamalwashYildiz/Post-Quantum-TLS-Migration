# v2.6 Live Receiver Evidence Recovery (controlled laboratory experiment)

## Scope
- Three actual TLS 1.3 hops per condition, repeated across independently generated trials, with Python/OpenSSL >=3.5.
- Root-owned receiver processes are trusted, one unprivileged client; same root security domain for all receivers.
- A **real signed receiver receipt** generated during the TLS run is placed in root-protected escrow and omitted from the verifier input. Recovery retrieves that existing receipt, not a new witness invented from a verdict.
- Conservative results: `UNRESOLVED` prior to recovery, `SATISFIED` after hybrid receipt retrieval, `VIOLATED` after retrieval of a classical-hop receipt; missing and incorrect/transplanted receipts do not approve.
- This is a prototype for evidence escrow/recovery, **not a network retrieval protocol**, new cryptographic primitive, distinct receiver trust domains, live malicious process compromise, or a cure for fundamentally absent evidence.
- Attack with wrong transaction original receipt gives `INVALID`. It is **not** a fabricated same-transaction contradictory signed receipt; no such attack is claimed.
- Single-recovery `perf_counter_ns` records local Python retrieval and verification, not network latency. Trial time includes fresh TLS runs. Do not interpret as production overhead.
- Session labels are public handshake-random hashes and certificates are laboratory self-signed. Only TLS key exchange is checked.

## Files added (no old version overwritten)
- `src/evidence_recovery_v26.py`: live root runner, protected receipt store, recovery logic, complete case tests, hash archival.
- `src/recovery_campaign_v26.py`: normal-user launcher, regression tests, sudo boundary, archive copying and checksum validation.
- `tests/test_evidence_recovery_v26.py`: 12 focused regression tests.

## Reproduce (new PowerShell terminal)
```powershell
wsl -d Ubuntu-22.04
```

Inside Ubuntu:
```bash
cd "/mnt/d/Articles/Post-Quantum TLS Migration/Post-Quantum TLS Migration-Project"
source "$HOME/pqc-research-venv/bin/activate"
OPENSSL_HOME="$HOME/opt/openssl-3.5.9"
export LD_LIBRARY_PATH="$OPENSSL_HOME/lib64${LD_LIBRARY_PATH:+:$LD_LIBRARY_PATH}"
python -m unittest discover -s tests -p 'test_*.py' -v
python src/recovery_campaign_v26.py \
  --python "$HOME/pqc-research-venv/bin/python" \
  --openssl "$OPENSSL_HOME/bin/openssl" \
  --archive results/evidence_recovery_v26 \
  --trials 3 --count 3
```

The launcher prompts for sudo and captures live results under `results/evidence_recovery_v26/campaign_.../` as the normal user. Privileged receiver secret keys and raw in-process witness stores are never placed in the public archive. Complete trial JSON includes sanitized verdicts, measured elapsed timings and explicitly bounded assumptions; `run_manifest.json`, `manifest.json`, `checksums.sha256`, `summary.csv`, test logs and experiment log are retained.

**Expected but unverified on Ubuntu**: with 125 v2.4 regressions and 12 new focused tests, 137 total tests. Live Ubuntu results are not claimed until the user executes the campaign.
