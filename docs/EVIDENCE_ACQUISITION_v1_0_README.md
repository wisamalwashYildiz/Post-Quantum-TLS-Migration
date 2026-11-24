# Post-Quantum TLS Migration — v1.0 evidence-acquisition feasibility pilot

This package preserves v0.9 and adds `src/evidence_acquisition.py` and six regression tests. The included three JSON files are archived v0.7 TLS measurements from real laboratory TLS sessions using Python/OpenSSL 3.5.5. **No new live TLS handshakes were executed by v1.0.**

## Scientific boundary

- Twelve selected request-pair windows (24 request instances) drawn from three archives.
- Eight **hypothetical** collection actions. Action coverage and acquisition costs are synthetic. The budgets are arbitrary units, not operational cost measurements.
- Exact cost-constrained maximum coverage (enumeration of 256 candidate subsets), marginal gain-per-cost greedy, static coverage/cost ordering, and seeded random ordering.
- Front and back TLS-group measurements are assumed available and trustworthy without charge. All sampled requests require a middle observation to resolve.
- Each selected action **assumes** trusted session-to-transaction binding; this binding was *not* independently measured or cryptographically authenticated in v0.7.
- Revocation scenario removes one chosen action's evidence. It does not test fabricated TLS messages, adversarial key exchange, forged authenticated receipts, or compromised endpoints.
- The existing `actual_groups` serves as oracle truth and the hypothetical evidence returned by a selected action. The design of the candidate action coverage does not inspect group values.
- Exact optimization is a conventional benchmark; no algorithmic invention is claimed.

## Preliminary results

For budgets 3, 5, 8, 10 artificial units, exact/greedy cover 6,12,18,24 out of 24 request verdicts. Static covers 6,12,15,18; one seeded random policy covers 6,12,15,15. These are deterministic choices of a small artificial action menu; they do not establish statistical superiority, and greedy matched exact on this pilot.

## Run on Ubuntu from a NEW terminal

Open a fresh Windows PowerShell window and launch:

```powershell
wsl -d Ubuntu-22.04
```

Then:

```bash
cd "/mnt/d/Articles/Post-Quantum TLS Migration/Post-Quantum TLS Migration-Project"
source "$HOME/pqc-research-venv/bin/activate"
python -c "import ssl; print(ssl.OPENSSL_VERSION)"
python -m unittest discover -s tests -p 'test_*.py' -v
python src/evidence_acquisition.py \
  --input results/v07_seed42017.json \
  --input results/v07_seed42018.json \
  --input results/v07_seed42019.json \
  --output results/evidence_acquisition_v10
```

Files: `summary.csv`, `evidence_acquisition.json`.

The zip adds only v1.0 files and v0.7 archive copies (if they are missing). Extract into the existing project root; preserve earlier implementations/results. The runs are independent of OpenSSL version once the archive is loaded, but the Ubuntu venv is retained for project consistency.

## Next evidence milestone

Replace hypothetical action/coverage and costs with externally observed binding/collection data from TLS sessions, with independent socket tuples, monotonic timestamps, exporter-based channel bindings where applicable, real capture dropouts, measured overhead, and independent third-party oracle checks. Include authenticated session–request evidence; no collector can be called independently trusted merely because it emits a UUID. Establish stronger optimization baselines and statistical replicates before novelty claims. This pilot supports the feasibility of the evaluation framework, not a novel optimal algorithm or deployed assurance system.
