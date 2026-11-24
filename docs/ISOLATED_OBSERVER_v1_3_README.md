# v1.3 — Separate-process TLS endpoint and connection reuse

## Purpose and precise limits

This additive experiment tests a **separate OS process acting as the TLS receiving endpoint**, not a passive observer. It owns the negotiated TLS session and observes each application payload over one reused TLS connection. It emits signed witnesses generated with a different HMAC key from the (simulated, attackable) forwarding reporter. The experiment has **one TLS leg**: it does **not** establish entire path assurance or actual cross-proxy forwarding provenance.

The observer signs the transaction digest, negotiated TLS key-exchange group, TLS session correlation label, and message sequence number. It verifies evidence separately from the observer process. The reported TLS label is a SHA-256 hash of public handshake randoms, NOT TLS exporter-based cryptographic channel binding. All experiments depend on a trusted observer process and on lab-generated signing keys. Process separation is not strong OS isolation: an attacker with the same OS user privileges, debugger/process-memory access, root, or control of the observer can defeat these assumptions. This lab uses self-signed certificates and examines *key establishment*, not post-quantum authentication.

### Files

- `src/isolated_observer_v13.py`: standalone live experiment using existing `live_path.py` and `session_chain_v11.py` in the project `src/`.
- `src/verify_isolated_observer_v13.py`: separate-process verifier for saved v1.3 cases.
- `tests/test_isolated_observer_v13.py`: 11 new regression tests, including forged reports, witnesses, replay and sequence tampering.

The ZIP adds only these files and does not replace previous research code.

## Run on user's working Ubuntu / WSL environment

Open a **new Windows PowerShell terminal**:

```powershell
wsl -d Ubuntu-22.04
```

**In Ubuntu**:

```bash
cd "/mnt/d/Articles/Post-Quantum TLS Migration/Post-Quantum TLS Migration-Project"
source "$HOME/pqc-research-venv/bin/activate"
OPENSSL_HOME="$HOME/opt/openssl-3.5.9"
export LD_LIBRARY_PATH="$OPENSSL_HOME/lib64${LD_LIBRARY_PATH:+:$LD_LIBRARY_PATH}"
"$OPENSSL_HOME/bin/openssl" version
python -m unittest discover -s tests -p 'test_*.py' -v
python src/isolated_observer_v13.py --openssl "$OPENSSL_HOME/bin/openssl" --output results/isolated_observer_v13 --count 3
python src/verify_isolated_observer_v13.py --evidence results/isolated_observer_v13/isolated_observer.json --keys results/isolated_observer_v13/lab_verifier_keys.json
```

**Do not upload or publish `lab_verifier_keys.json`.** Treat previously shared v1.2 keys as disclosed. Generate fresh keys on every v1.3 run (the script does this).

Expected checks: `valid SATISFIED`, `classical VIOLATED`, `forged_report_only SATISFIED` (intentionally vulnerable baseline), `forged_corroborated INVALID`, `missing_witness UNRESOLVED`, `reused_witness INVALID`, `substituted_witness INVALID`. Separate verifier reports `valid SATISFIED`, `classical VIOLATED`, `forged INVALID`. These are expected outcomes pending execution in the user's OpenSSL 3.5.9 Ubuntu environment.

### Scientific interpretation

Compared to v1.2, v1.3 makes the TLS receiver a physically separate process for each run and shows multiple messages on a single negotiated session. It does not yet demonstrate independence from a compromised host or from an instrumented TLS terminator. The forwarder-only compromise case is modeled by modifying/re-signing receipts (not by exploiting a real forwarder). Next study: enforce OS-user/container isolation with separately protected observer secrets, and implement real multi-hop forwarding with established bindings and controlled malicious forwarder behavior.
