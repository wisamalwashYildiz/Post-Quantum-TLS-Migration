# Post-Quantum TLS Migration — v2.5 repeatable live evidence campaign

**Scope:** This is an archival-and-replication upgrade, not a novel cryptographic primitive. It calls the **unchanged** v2.4 live three-hop system with fresh sessions and fresh ephemeral receipts on each trial. It checks a strict public result schema, repeats the live test, and saves a publication-quality *result provenance inventory*. All receiver processes share the root trust domain. Offline forged reports are not live relay compromise.

## Files

- `src/assurance_campaign_v25.py` — user-level campaign orchestrator; invokes `sudo` for protected v2.4 subprocess, invokes regression suite, validates outputs and archives safely.
- `tests/test_assurance_campaign_v25.py` — 12 adversarial and serialization regression tests.

No prior files are replaced. Do **not** extract the ZIP into `/var/tmp` as a long-term archive; extract into the existing research project and run from project root.

## Commands (from a new Windows PowerShell terminal)

```powershell
wsl -d Ubuntu-22.04
```

Then **inside Ubuntu**:

```bash
cd "/mnt/d/Articles/Post-Quantum TLS Migration/Post-Quantum TLS Migration-Project"
source "$HOME/pqc-research-venv/bin/activate"
OPENSSL_HOME="$HOME/opt/openssl-3.5.9"
export LD_LIBRARY_PATH="$OPENSSL_HOME/lib64${LD_LIBRARY_PATH:+:$LD_LIBRARY_PATH}"
"$OPENSSL_HOME/bin/openssl" version
python -m unittest discover -s tests -p 'test_*.py' -v
python src/assurance_campaign_v25.py \
  --python "$HOME/pqc-research-venv/bin/python" \
  --openssl "$OPENSSL_HOME/bin/openssl" \
  --runner src/protected_path_v24.py \
  --archive results/assurance_campaign_v25 \
  --trials 3 --count 3
```

The campaign prompts for `sudo` once; it automatically prepares the root-owned protected per-trial directory under native Linux `/var/tmp`, runs the real v2.4 experiment, reads its public JSON as root, validates the result, writes an allowlisted public evidence file to project `results/assurance_campaign_v25/campaign_<UTC>_<id>/trial_XXX/`, and cleans up root-only temporary files.

## Preserved evidence

- `manifest.json`: environment, experiment scope, count, failure statuses, security limitations
- `test_results.txt`: exact regression suite output, with subprocess exit code in manifest
- `trial_XXX/experiment.log`: combined actual runner output
- `trial_XXX/evidence.json`: sanitized, schema-checked receiver-vs-reporter outcome
- `trial_XXX/verification.json`: validation against declared expectations, **not** a new independent cryptographic verifier
- `summary.csv`: one line per trial, including FAIL rows
- `aggregate.json`: number of successful/failed runs; *6 fresh live TLS legs per successful trial* (3 hops x two conditions)
- `checksums.sha256`: digests of all public archived files

Note the checked verdicts are **pre-specified expected behavior**. That confirms reproducible operation, but does not itself establish comparative security accuracy on previously unseen attack workloads. Experiment reports only **qualitative** verdicts; no overhead/latency metric is fabricated. The campaign runs sequential transactions in each leg, *not* concurrently multiplexed traffic.

## Safety and limitations

Requires Ubuntu native `/var/tmp`, `sudo`, existing OpenSSL 3.5.9 venv and the already validated v2.4 script. Private observer keys, TLS keys and raw signed receipts are **not** copied to the Windows-mounted permanent archive. Root/host compromise remains out of scope. On failure, the campaign records an explicit FAIL and exits nonzero. Protect or redact terminal logs before publication. Do not upload private key files.

## Road to v3.0

Freeze this baseline as the **replication dataset**. A credible v3 requires (1) a cryptographic exporter + group observation from the **same sessions** on every hop; (2) explicit trust-domain compromise experiments rather than solely offline report mutation; (3) stronger fair baselines; (4) repeated runs with performance measurement and statistical uncertainty; (5) accurate novelty verification against published protocols.
