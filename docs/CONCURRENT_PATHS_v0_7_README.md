# v0.7 — Concurrent path experiment (2026-10-31)

This release adds `src/concurrent_paths.py`, preserving `src/multihop.py`, `src/live_path.py`, and `src/session_evidence.py`.

## Prerequisites

Python's `ssl` must report OpenSSL 3.5 or later. This is different from installing the OpenSSL CLI: the current Windows virtual environment's Python uses OpenSSL 3.0.16 and cannot run v0.7 unchanged. Run this in a compatible WSL/Linux Python environment instead. Do not replace system OpenSSL DLLs.

Check: `python -c "import ssl; print(ssl.OPENSSL_VERSION)"`

## Execute

From the project root:

```
python -m unittest discover -s tests -p 'test_*.py' -v
python src/concurrent_paths.py --requests-per-scenario 12 --seed 42017 --output results/concurrent_paths_v07
python src/concurrent_paths.py --requests-per-scenario 12 --seed 42018 --output results/concurrent_paths_v07_seed42018
python src/concurrent_paths.py --requests-per-scenario 12 --seed 42019 --output results/concurrent_paths_v07_seed42019
```

If multiple OpenSSL executables are installed, add `--openssl /path/to/openssl`.

## Architecture

One gateway uses a route indicator to forward each client request over one of two live services (`service-a` or `service-b`), which both forward to a backend. Concurrent client operations use distinct request IDs and real TLS 1.3 sessions. At each node a non-public CPython `_msg_callback` decodes a ServerHello key-share extension, recording the negotiated TLS group for the application session. Request and response paths and independent per-hop incoming/outgoing group reports are checked for agreement.

Six configuration families, 12 requests per family, 72 requests per seed, 3 TLS hops per request, 216 actual application TLS hops per seed. Two routes are exercised in each family. Three seed runs give 216 actual application requests and 648 TLS hops.

## Evidence and limitations

Ground truth is recorded with full laboratory instrumentation; filtered evidentiary views use hash-based reproducible masking with probabilities 0, 0.25, 0.5, and 1.0. Dropout is **simulated**, not organically caused by a sensor fault. A conservative policy verdict is `SATISFIED` if all observed hops are hybrid and none are missing; `VIOLATED` if any observed relevant hop is classical; `UNRESOLVED` otherwise. The policy applies only to key establishment, not TLS authentication or overall end-to-end secrecy.

The per-hop conservative matched-evidence comparator is exactly equivalent to the proposed verifier in these experiments; there is **no demonstrated methodological advantage**. The fully observed baseline is decisive in every case and correctly so. This is intentionally documented to prevent unsupported publication claims.

The route and request identity are trusted in this laboratory. This is not path discovery in an untrusted distributed system. TLS certificate verification is disabled, using ephemeral self-signed RSA authentication only. The `ssl` private `_msg_callback` is not a supported production interface. No real adversary or cryptographic compromise is modeled. The experimental fixtures and certificates do not belong in public code releases.

## Evidence files

- `results/concurrent_paths_v07/concurrent_paths.json`
- `results/concurrent_paths_v07/summary.csv`
- Two additional seed directories with matching outputs.

## Decisive next research gate

Do not submit a manuscript claiming a novel assurance algorithm yet. Compare against inventory- and session-log-only methods under explicitly different observation capabilities; test path ambiguity and integrity failures. If the method remains identical to conservative per-hop verification, position the result as a benchmark or narrow the claims rather than inventing superiority.
