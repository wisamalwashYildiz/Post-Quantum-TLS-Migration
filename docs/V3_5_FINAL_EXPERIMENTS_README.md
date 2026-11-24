# v3.5: Controlled signer-compromise boundary + independently timed verifier comparison

## Purpose
This is a non-destructive addition to the existing research project. It relies on existing `src/v32_protected_freshness.py`, `src/v33_comparative_campaign.py`, and `src/v30_session_gate.py`. It contains two new source programs and five tests. Keep v3.3/v3.4 results unchanged.

## Source-based security claims and limitations
- Fresh real three-hop TLS sessions, three signed receiver streams, separate Linux UID credentials.
- **Signer compromise is a controlled simulation**: the privileged laboratory orchestrator accesses the legitimate service receiver's signing key *after* live session completion. It creates a dishonest, correctly signed group assertion to establish that signature validity alone cannot guarantee truth. It is **not** an exploit, not actual attacker filesystem access, and not a compromised TLS process.
- One dishonest signed receipt here is rejected because honest adjacent hop evidence conflicts. **Do not claim arbitrary malicious signers can always be detected.** Signed-but-false claims are a real threat under a weaker observation model.
- Each verification method is invoked and timed separately with `time.perf_counter_ns()`; order is rotated. Report-only checks only 3 group strings and thus is not functionality-equivalent. Protected timing includes SQLite freshness ledger check and commit; opening the ledger schema is excluded. Numbers are Python microbenchmarks, not TCP end-to-end latency, and have no generalizable performance meaning until replicated.
- No certificate validation, no PQ authentication, root remains trusted, and experiments are over localhost.
- Signing private keys, raw TLS exporter secrets, and protected role directories are NOT exported to results.

## On Ubuntu
Extract package to existing project directory. From NEW PowerShell start `wsl -d Ubuntu-22.04` then:

```bash
cd "/mnt/d/Articles/Post-Quantum TLS Migration/Post-Quantum TLS Migration-Project"
source "$HOME/pqc-research-venv/bin/activate"
OPENSSL_HOME="$HOME/opt/openssl-3.5.9"
export LD_LIBRARY_PATH="$OPENSSL_HOME/lib64${LD_LIBRARY_PATH:+:$LD_LIBRARY_PATH}"
export OPENSSL_CONF=/etc/ssl/openssl.cnf
python -m unittest discover -s tests -p 'test_*.py' -v
python src/v35_campaign_launcher.py \
  --python "$HOME/pqc-research-venv/bin/python" \
  --openssl "$OPENSSL_HOME/bin/openssl" \
  --archive results/v35_boundary_overhead \
  --trials 10 --count 3 --iterations 100
```

## Evidence
The launcher creates `results/v35_boundary_overhead/campaign_*/final_*/` with `timings.csv`, `compromise_boundary.json`, `manifest.json`, `checksums.sha256`; also an `experiment.log` and `launcher_manifest.json` in the parent campaign directory. Failures remain archived. Do not use a report-only vs signed latency ratio as overhead of equivalent functions.

## Regression tests
New tests: 5. Expected complete suite with previous 189 files: 194, provided no earlier tests are missing.
