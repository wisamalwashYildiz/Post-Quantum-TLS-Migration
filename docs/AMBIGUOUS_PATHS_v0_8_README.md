# v0.8 — Paired ambiguous TLS-session evidence (offline replay)

## Scope

This experiment replays real v0.7 TLS-session group receipts captured by Python/OpenSSL >=3.5 live forwarding, then synthetically varies **only the request-to-middle-receipt association evidence**. It is NOT a new network capture, authenticated attestation, or demonstration of adversarial telemetry modification.

Inputs: three existing v0.7 runs (seeds 42017, 42018, 42019). Only two route-sensitive scenarios per seed, with 12 requests each, are selected. Thus **72 distinct original requests**, grouped into **36 disjoint A/B pairs**, are reused across five conditions (180 pair-condition records; 360 request-condition verdicts). Nonselected original v0.7 requests are not part of the v0.8 comparison.

## Assumptions

- Every two-request comparison has a **closed, complete window** of exactly two received middle-hop TLS receipts.
- No middle-hop receipt is duplicated, omitted, or reused within that window, unless the entire middle observation is redacted.
- TLS group values are read from actual v0.7 receipt records; **only association candidate sets are synthetically assigned**.
- All candidate matches are treated as feasible; no independent attestation or trusted origin of candidate sets is established.
- The inconsistent condition forces two requests to claim the same unique receipt; both baselines report **INCONSISTENT**. It does not simulate a verified attacker.

## Compared methods

- **Joint matching:** enumerate all injective request→receipt matchings allowed by the candidate associations; decide only when all possible assignments agree.
- **Local candidate baseline:** decide only when all individually allowed middle receipts agree, without the one-to-one exclusivity constraint.
- **Edge-only baseline:** assess only the first TLS segment; incomplete and can be confidently wrong.
- **Full-per-hop oracle:** original complete session-group ground truth; not a method operating under missing evidence.

An exact bipartite matching/constraint solver is a legitimate stronger baseline and can reproduce the joint result; v0.8 does **not** establish an algorithmic advantage over such a baseline.

## Reproducible commands — START IN A FRESH TERMINAL

In a **new Windows PowerShell terminal**:

```powershell
wsl -d Ubuntu-22.04
```

In the Ubuntu shell:

```bash
cd "/mnt/d/Articles/Post-Quantum TLS Migration/Post-Quantum TLS Migration-Project"
source "$HOME/pqc-research-venv/bin/activate"
python -c 'import ssl; print(ssl.OPENSSL_VERSION)'
python -m unittest discover -s tests -p 'test_*.py' -v
python src/ambiguous_paths.py \
  --input results/v07_seed42017.json \
  --input results/v07_seed42018.json \
  --input results/v07_seed42019.json \
  --output results/ambiguous_paths_v08
```

The three included input snapshots are extracted from the corresponding v0.7 seed directories and included in the v0.8 ZIP for an exact offline rerun. They are not new TLS captures. The module does not require OpenSSL 3.5 to *replay* JSON, but the original source data did.

## Local verification (isolated container)

Seven unit tests passed, including exhaustive two-request no-false-decision tests under matching assumptions. Summary of 72 request-condition verdicts per mode:

| Condition | Joint correct | Local correct | Joint unresolved | Local unresolved | Inconsistent both |
|---|---:|---:|---:|---:|---:|
| Full association | 72 | 72 | 0 | 0 | 0 |
| Complementary partial | 72 | 36 | 0 | 36 | 0 |
| Symmetric ambiguity | 0 | 0 | 72 | 72 | 0 |
| Middle receipts redacted | 0 | 0 | 72 | 72 | 0 |
| Contradictory associations | 0 | 0 | 0 | 0 | 72 |

For the joint and local method: no incorrect decisive verdicts across the controlled conditions. Results are conditional on the assumptions above, not universal security guarantees. Nonindependent experimental records should not be treated as 360 independent empirical requests.

## Research implications

Positive: cross-request exclusivity can sometimes resolve one request whose local evidence is ambiguous. Negative: this is a standard global constraint effect, not a novel assurance algorithm by itself. Next decisive work: build independently produced association constraints from network or service observables, evaluate incorrect associations and open-window matching, then compare to optimal matching and a matched-evidence conservative verifier. Do not claim Q1 novelty based on this pilot.
