# Milestone 2: Live forwarding pilot v0.5 (experimental)

## What changed
- Three independent live TLS listener processes (Python threads in one process), `gateway -> service-a -> backend`, forward each application JSON request rather than a central Python sequencer creating every hop.
- Each node records its own request receipt and incoming path; assertions check each node received exactly one application request ID per scenario.
- OpenSSL command-line probes establish the negotiated group supported by each endpoint **in a separate probe connection**. TLS 1.3 group negotiations of the actual forwarding connections are NOT directly captured. This is a central measurement limitation, not evidence of full assurance.
- Policy: PQ-resistant **key establishment** on all three transport segments. No claim of PQ authentication or production trust.

## Compatibility
- **Important**: Python `ssl` must be linked to OpenSSL **3.5+**, because this code uses native OpenSSL 3.5 default group negotiation. Merely installing `openssl.exe` 3.5 does not upgrade Windows Python's internal SSL.
- Windows user currently has Python OpenSSL 3.0.16; therefore this script will fail fast with an informative message on that Python installation. **Keep the validated v0.4 Windows results.** To execute v0.5 on Windows, use a WSL environment where `python -c "import ssl; print(ssl.OPENSSL_VERSION)"` reports at least 3.5.
- The development environment ran Python linked to OpenSSL 3.5.5 and OpenSSL CLI 3.5.5.

## Command

```bash
python src/live_path.py --output results/live_path_v05
python -m unittest discover -s tests -p 'test_live_path.py' -v
```

## Reported results in this release
- 5 forwarded requests (one for each scenario); 15 independent node receipts; 15 separate TLS probes.
- 5/5 expected policy classification scenario checks; 3 decisive, 2 unresolved due to hidden middle-segment probe observations.
- The full-per-hop probe baseline is correct for all 5. This is no evidence of method superiority.
- `results/live_path_v05/live_path.json` includes assumptions and limitations; `summary.csv` contains comparison outcomes.

## Remaining publication-critical gaps
1. Observe the negotiated group **of the forwarded application session itself** (e.g. wire-level TLS 1.3 ServerHello key_share capture, or a verified OpenSSL runtime hook), not only separate probe connections.
2. Correlate forwarded requests to cryptographic sessions via authenticated or tamper-evident telemetry, not solely application-controlled identifiers.
3. Test path branches, session resumption, policy time windows and noisy/dropout telemetry with baselines at matched evidence budgets.
4. Test an independent TLS implementation and realistic gateway/proxy configuration; quantify run-to-run variation.
5. Provide matched-evidence comparisons against conservative per-hop verification. A logical three-hop AND is not a novel research contribution.

## Security
Certificates are ephemeral, self-signed, RSA, and peer verification is explicitly disabled for the lab. Certificates and private keys are created in a temporary directory and excluded from the distribution ZIP. Do not run this outside isolated localhost experiments.
