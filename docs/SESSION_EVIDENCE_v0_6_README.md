# Post-Quantum TLS Migration — v0.6 actual-session evidence

## Achievement
Real application requests traverse Client -> Gateway -> Service A -> Backend through three separate TLS 1.3 connections. **Unlike v0.5**, this version observes `ServerHello.key_share.group` on the actual request sessions through Python's private `SSLContext._msg_callback`. Both incoming (node) and outgoing (forwarder) session observations are compared, and all five controlled cases passed under Python ssl/OpenSSL 3.5.5 on Linux. These are experimental measurements, not claims about PQ authentication or real-world deployment.

## Requirements
- Python linked against OpenSSL 3.5+ (test with `python -c "import ssl;print(ssl.OPENSSL_VERSION)"`)
- OpenSSL 3.5+ executable to generate a *disposable* local certificate
- Python standard library only
- `src/live_path.py` from v0.5 alongside `src/session_evidence.py`

Your current Windows `.venv` reports Python OpenSSL 3.0.16 and cannot run this hybrid TLS application. **Do not swap Python DLLs.** Use a Python linked with 3.5+, such as a verified WSL installation, or continue running v0.4 on native Windows. Merely upgrading the `openssl.exe` command is insufficient for this version.

## Run
```bash
python src/session_evidence.py --openssl /usr/bin/openssl --output results/session_evidence_v06
python -m unittest discover -s tests -v
```

Outputs: `results/session_evidence_v06/session_evidence.json`, `results/session_evidence_v06/summary.csv`.

## What is (and is not) measured
- Observed: three negotiated key-exchange group identifiers **on actual application-bearing TLS sessions**, receipt of one matching request ID per node, and client/forwarder-side handshake agreement.
- Not yet established: cryptographically authenticated request-to-session provenance; complete trace capture under concurrent/retried requests; non-local deployments; verified certificates, quantum-resistant signatures/authentication, downstream application-layer E2E encryption; evidence integrity against active compromise.
- Standard baseline `full_per_hop` correctly decides all test cases when all observations are present. Missing-evidence verdicts are expected conservative behavior, not evidence of superiority.
- CPython `_msg_callback` is private. It is deliberately a *research instrument*, not recommended production instrumentation. Validate ServerHello decoding under version and implementation changes.
- Ground truth is a controlled laboratory configuration cross-checked with actual handshake observations; do not imply independent production ground truth.

## Next scientific gate
Implement matched-information baselines and independent session binding under concurrency, retries, route changes and telemetry dropout. Demonstrate measurable added value beyond the straightforward per-hop approach before claiming methodology novelty.
