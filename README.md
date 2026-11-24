# Transaction-Level Verification of Hybrid Post-Quantum Key Establishment in Multi-Hop TLS

Research artifact accompanying the manuscript by Wisam Makki Alwash, Belal Al-Khateeb, and Hasan Hüseyin Balık, submitted to *Cryptography* (manuscript cryptography-4709438).

## Contents

- `src/`: original experimental implementations, including v32 protected freshness, v33 comparison, v44 policy-aware verification, v45 partial-evidence verifier, and v46 live-evidence audit.
- `tests/`: archived regression tests.
- `results/`: selected original experimental outputs, manifests and checksums; generated laboratory private keys, local development environments, historical exploratory results and SQLite runtime state are not distributed.
- `docs/`: original experiment-specific instructions. These retain historical local paths and version references; adapt paths to your installation.
- Top-level Python scripts: supplementary reviewer-oriented benchmark and live-test entry points.

## Evidence index

| Experiment | Source | Archived output |
|---|---|---|
| Three-hop paired comparison (20 live scenarios, 100 paired cases, 300 decisions) | `src/v33_comparative_campaign.py` | `results/v33_comparative_campaign/` |
| Independent audit | `src/v34_independent_audit.py` | `results/v34_independent_audit/` |
| Compromise boundary and timing | `src/v35_boundary_overhead.py` | `results/v35_boundary_overhead/` |
| Synthetic path-length scaling, 3–16 hops | `src/v40_scaling.py` | `results/postquantum_extension/run_20261102T155011Z/v40/` |
| Live multi-group policy evaluation (70 cases) | `src/v44_policy_aware_live.py` | `results/postquantum_extension/v44_live_laptop/` |
| Synthetic partial-evidence validation (120 cases) | `src/v45_mixed_evidence_campaign.py` | `results/postquantum_extension/v45_precedence/campaign/` |
| Live-derived partial-evidence validation (190 decisions) | `src/v46_live_evidence_audit.py` | `results/postquantum_extension/v46_live/` |

The v45 precedence verifier is in `src/v45_precedence_verifier.py`. The v46 script evaluates it using live-derived evidence and mutations; it is an audit, not a replacement verifier. The v44 and earlier methods are retained for comparison. Synthetic runs are not additional live TLS experiments.

## Environment and reproduction

The recorded main experiments used Linux/WSL and OpenSSL 3.5.9. The extension manifest records Python 3.12.12. The Python OpenSSL bindings must expose `SSL_get0_group_name` and support the negotiated hybrid groups; merely installing the OpenSSL command-line tool is insufficient. Exact Python dependency versions are not locked in the supplied archive. See the historical instructions in `docs/` for the laboratory configuration.

Use a disposable Linux laboratory or VM, not a production host. Some live campaigns require root for UID isolation. Review scripts before privileged execution. They generate transient laboratory keys and certificates; TLS peer certificate verification is disabled in the experimental setup. The exporter label is experimental, not a claim of standardized application-label allocation.

From the repository root, after configuring the compatible Python/OpenSSL environment:

```bash
python -m unittest discover -s tests -p 'test_*.py' -v
python src/v40_scaling.py --out reproduction/scaling --repetitions 40
python src/v45_mixed_evidence_campaign.py --out reproduction/partial-synthetic
```

For the privileged live campaigns, see `docs/V3_3_COMPARATIVE_CAMPAIGN_README.md`, `docs/V3_5_FINAL_EXPERIMENTS_README.md`, and the command-line options of v44/v46. Example, after activating the compatible environment:

```bash
sudo "$(command -v python)" src/v44_policy_aware_live.py --live --openssl "$(command -v openssl)" --out reproduction/v44-live
sudo "$(command -v python)" src/v46_live_evidence_audit.py --live --openssl "$(command -v openssl)" --out reproduction/v46-live
```

Use new output directories so archived results remain unchanged. Timings will depend on hardware and software environment. The archived outputs support inspection of the reported experiments; raw secret material is intentionally not released. Historical checksum manifests refer to their original campaign files and may include omitted runtime state.
