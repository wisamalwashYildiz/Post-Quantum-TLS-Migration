# v1.1 — Live TLS connection-chain receipts (laboratory)

## Scope
First live transaction-to-session-chain pilot. Each TLS endpoint observes an actual TLS 1.3 ClientHello/ServerHello via the CPython private `_msg_callback`, extracts the negotiated group from ServerHello, derives a public-random session correlation label, and records a transaction hash with its incoming/outgoing connection labels. Each node authenticates its instrumented-process report with HMAC. A different process then checks all reports and adjacent TLS labels. This is **not** a cryptographic channel binding or tamper-resistant independent attestation. The proxy's own process is part of the trusted computing base.

## Additive installation
Copy only `src/session_chain_v11.py`, `src/verify_chain_v11.py`, `tests/test_session_chain_v11.py` into the corresponding directories in your existing v1.0 project. Existing `src/live_path.py` and `src/session_evidence.py` remain unchanged. The ZIP includes dependency copies for self-contained inspection; do not overwrite project files unnecessarily.

## Fresh terminal: Windows PowerShell
```powershell
wsl -d Ubuntu-22.04
```

## Within Ubuntu
```bash
cd "/mnt/d/Articles/Post-Quantum TLS Migration/Post-Quantum TLS Migration-Project"
source "$HOME/pqc-research-venv/bin/activate"
python -m unittest discover -s tests -p 'test_*.py' -v
python src/session_chain_v11.py --openssl "$HOME/opt/openssl-3.5.9/bin/openssl" --output results/session_chain_v11
python src/verify_chain_v11.py --evidence results/session_chain_v11/session_chain.json --keys results/session_chain_v11/lab_verifier_keys.json
```

## Expected semantics
- Valid all-hybrid chain: SATISFIED (subject to trusted process assertions)
- Classical group on middle connection: VIOLATED
- Tampered receipt: INVALID
- Missing receipt: UNRESOLVED
- Previously recorded receipts offered as evidence for a **different transaction nonce**: INVALID
- Reusing the very same unchanged bundle: **not prevented**; needs persistent trusted nonce registry

## Critical constraints
1. HMAC keys are exported locally in plaintext `lab_verifier_keys.json` for independently invoked verification. This is an insecure lab demonstration; never publish the keys, mistake an HMAC for a public third-party certificate, or claim a malicious proxy cannot forge reports. Use strict file permissions and discard the file after testing.
2. No TLS exporter API is used; the public-random label is **not cryptographic session binding**.
3. Client TLS certificate verification is disabled, and RSA lab certificates are used; this experiment says nothing about PQ authentication.
4. Actual live TLS negotiated groups are observed using CPython's undocumented/private callback, not network-level independently sourced pcap data.
5. Only fresh connections, one application transaction per TLS session, one three-hop fixed route, loopback transport. No reuse, rerouting, independent packet capture or hostile-node compromises.
6. No production security guarantees, no claim of novel cryptographic primitives or algorithms, and no claim of Q1 novelty established by this pilot.
7. v0.7–v1.0 results are preserved. Never place `lab_verifier_keys.json` in a shared manuscript artifact or public repository.
