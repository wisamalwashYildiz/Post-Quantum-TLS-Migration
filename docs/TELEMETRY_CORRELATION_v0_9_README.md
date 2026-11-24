# Post-Quantum TLS Migration — v0.9: metadata-derived correlation

## Scope
This is an **offline correlation experiment over genuine v0.7 TLS-session observations**, not a new live forwarding run. The TLS key-share measurements originate from archived v0.7 application sessions. Three archive files have OpenSSL 3.5.5 provenance. The user's previous v0.8 reproduction under Ubuntu OpenSSL 3.5.9 does not change provenance.

Unlike v0.8's hand-authored receipt-candidate sets, candidate association edges in this experiment are computed automatically from recorded route and `received_path` prefix metadata. Middle-node request IDs are never consulted to build the matching candidates; they are retained for scoring only. Full and partial route observability, hidden routes, missing receipts, contradictory route fields, and open windows are examined. **Route labels are application-controlled observables, not independent trusted network proof; no timestamps, 5-tuples or authenticated binding were recorded in the original v0.7 inputs.** Redaction and contradictory-route cases remain controlled simulations.

## Methods
- **Local:** Independent request-to-middle receipt candidate verdicts, ignoring exclusivity.
- **Joint:** All admissible closed-window request-receipt matchings using a bipartite maximum matching feasibility test; unanimity verdict across feasible receipts.
- **Optimal matching:** A mathematically equivalent optimal feasibility benchmark over identical observations. The code explicitly asserts equality. It is not a separately implemented independent third-party solver; the shared feasibility engine is a validity baseline.
- For open windows, the method declines to infer exhaustive receipt capture, and unresolved is the conservative result when all relevant hops are not proven.
- Source TLS records are held fixed; only visibility or route metadata are changed.

## Results (three archived runs; 72 selected request instances per condition)

| Condition | Joint correct | Optimal correct | Local correct | Joint unresolved | Joint inconsistent |
|---|---:|---:|---:|---:|---:|
| full | 72 | 72 | 72 | 0 | 0 |
| partial_route | 72 | 72 | 36 | 0 | 0 |
| no_routes | 0 | 0 | 0 | 72 | 0 |
| missing_receipt | 0 | 0 | 0 | 72 | 0 |
| contradictory_route | 0 | 0 | 0 | 0 | 72 |
| open_window | 0 | 0 | 0 | 72 | 0 |

No incorrect decisive verdicts in these controlled conditions. There are 36 paired windows per condition; 216 scenario-window records and 432 request-level assessments in total (repeated conditions on the same underlying 72 requests; **not independent 432 requests**).

## Reproduce on Ubuntu 22.04 WSL2
First open a **new Windows PowerShell terminal** and enter:

```powershell
wsl -d Ubuntu-22.04
```

In Ubuntu:

```bash
cd "/mnt/d/Articles/Post-Quantum TLS Migration/Post-Quantum TLS Migration-Project"
source "$HOME/pqc-research-venv/bin/activate"
python -c 'import ssl; print(ssl.OPENSSL_VERSION)'
python -m unittest discover -s tests -p 'test_*.py' -v
python src/telemetry_correlation.py \
  --input results/v07_seed42017.json \
  --input results/v07_seed42018.json \
  --input results/v07_seed42019.json \
  --output results/telemetry_correlation_v09
```

Extract ZIP contents **into** the existing project root. It only introduces `src/telemetry_correlation.py`, `tests/test_telemetry_correlation.py`, this README, and archived inputs/results; v0.4–v0.8 files are not replaced.

## Publication decision
The optimal matching baseline ties the proposed joint method under matched evidence. Thus no inference novelty is established by v0.9. The next decisive experiment is collecting new **independent, session-bound observables** (client/server socket tuples, monotonic timestamps, TLS session correlation IDs or exportable-session metadata, route/failover logs) from actual live multi-hop traffic and introducing true candidate uncertainty through observed events rather than masking trusted route labels. Evaluate false decisive claims, coverage, inconsistency detection, and instrumentation burden under measured provenance limitations. A credible contribution may be a well-characterized measurement methodology and evidence-sufficiency benchmark, not a newly invented matching algorithm.
