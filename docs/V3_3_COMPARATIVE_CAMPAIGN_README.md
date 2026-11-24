# v3.3 Paired Comparative Assurance Campaign

This is a **new research campaign** building on the unchanged v3.2 protected TLS implementation. It adds three files under `src/` and `tests/` and does not replace earlier source or results.

## Design

For each trial, run two **new real three-hop TLS paths** (all-hybrid and classical-middle) under three separately restricted receiver Linux UIDs, and a fourth attacker UID. Each receiver signs its own session-associated evidence. After recording a successful live path, inject five **offline evidence interventions** into deep copies of the SAME live evidence:

- `unaltered`: honest observation and report.
- `forwarder_false_hybrid`: forge the report-only middle-hop label to hybrid; actual receiver evidence unchanged.
- `receiver_edit`: modify a signed receiver observation without its signing key.
- `missing_receiver`: remove the complete middle receiver record list; report-only telemetry still claims hybrid.
- `copied_new_challenge`: submit an authentic signed batch to a fresh verifier-challenge round. Signatures remain valid, but a fresh-bound verifier must reject.

Three verification policies use the paired evidence:

1. `report_only`: trusts attacker-controlled claimed TLS groups.
2. `signed_receiver`: validates genuine signatures and TLS-exporter link consistency, but does **not** check independent freshness.
3. `protected_fresh`: signature and consistency verifier plus a verifier-selected unique challenge using the persistent SQLite `FreshLedger` and OS-protected signer identities.

**Important limits:** Only the report-only comparison is evaluated against attacker-controlled reports. The receiver methods use trusted receiver-supplied evidence by assumption. Injections are offline, not a real compromised forwarding process. The roots and certificate contexts are trusted; unvalidated self-signed certificate, localhost, no PQ authentication. The benchmark tests intentionally chosen attacks and NOT random real-world prevalence or receiver compromise. Live TLS observations are real; the attack modifications are offline. Method-specific processing overhead is NOT estimated (one shared bundle stopwatch covers all methods). No private keys, TLS exporter material or secrets are archived.

## Install

Extract ZIP directly into existing project root, merging `src/` and `tests/` folders. v3.2 and v3.0 files must already be installed (`src/v32_protected_freshness.py`, `src/v30_session_gate.py`).

## New Windows PowerShell terminal

```powershell
wsl -d Ubuntu-22.04
```

Then inside Ubuntu:

```bash
cd "/mnt/d/Articles/Post-Quantum TLS Migration/Post-Quantum TLS Migration-Project"
source "$HOME/pqc-research-venv/bin/activate"
OPENSSL_HOME="$HOME/opt/openssl-3.5.9"
export LD_LIBRARY_PATH="$OPENSSL_HOME/lib64${LD_LIBRARY_PATH:+:$LD_LIBRARY_PATH}"
export OPENSSL_CONF=/etc/ssl/openssl.cnf

python -m unittest discover -s tests -p 'test_*.py' -v

python src/v33_campaign_launcher.py \
  --python "$HOME/pqc-research-venv/bin/python" \
  --openssl "$OPENSSL_HOME/bin/openssl" \
  --archive results/v33_comparative_campaign \
  --trials 10 \
  --count 3
```

The launcher runs with your normal account, invoking `sudo` for protected native-Linux temporary execution, and copies public evidence to `results/v33_comparative_campaign/campaign_<timestamp>/comparison_<timestamp>/`. It checks SHA-256 hashes and preserves failures. It never copies private signing keys. Use `--trials 3` for a short smoke test, `--trials 10` for the first broader campaign. Count=3 is three sequential transactions on each TLS connection.

## Files

- `paired_verdicts.csv`: all three method decisions in each paired intervention; `intervention_mode` explicitly marks offline attacks.
- `live_sessions.json`: recorded Linux UIDs, key-access tests, true negotiated groups, receipt counts, timings.
- `manifest.json`: provenance, OpenSSL version, limitations, tallies, errors.
- `checksums.sha256`: integrity digests of all public results.
- `experiment.log`, `launcher_manifest.json`: launcher-side audit trail.

The negative-control false-hybrid-approval count is a **count over specified injected interventions**, NOT an error rate for an unknown real-world distribution. Re-run under Ubuntu OpenSSL 3.5.9 before claiming that environment's results. The existing v3.2 and earlier results stay frozen.
