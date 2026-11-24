# v3.1 process-separated session-evidence integration gate

**Scope:** This is a research integration gate, not full protected v3.0 or independently compromised-node resilience. It uses live TLS 1.3 on three localhost TCP legs; each receiver is an independent Linux process running under the same OS identity as the launcher. The trusted parent obtains and pins each receiver's ephemeral Ed25519 public key via a local multiprocessing pipe. The receiving process generates and retains its own private signing key; the parent does not receive those keys. Exporter proofs, negotiated group and transaction hashes originate from the same TLS connection in each receiver process. Client-to-receiver and forwarding-to-receiver exporter values must match on each hop. **No private keys or raw exporter material are stored in public results.**

This stage does not provide separate Linux UIDs, independent host trust, trusted external public key enrollment, transport PKI verification, malicious endpoint robustness, or production PQ authentication. It is necessary but not sufficient for protected v3.0; copied full signed evidence remains valid in the standalone verifier without a trusted challenge or freshness ledger. Do not claim completed OS-enforced trust separation.

## Install

Extract package to your existing project root: it adds `src/v30_session_gate.py` if needed, `src/v31_process_receipts.py` and `tests/test_v31_process_receipts.py`. If v3.0 existing source differs, preserve your prior copy and use the provided gate implementation in an isolated test directory instead of replacing it. It is identical to the previous v3.0 integration gate artifact.

## Ubuntu execution

```bash
cd "/mnt/d/Articles/Post-Quantum TLS Migration/Post-Quantum TLS Migration-Project"
source "$HOME/pqc-research-venv/bin/activate"
OPENSSL_HOME="$HOME/opt/openssl-3.5.9"
export LD_LIBRARY_PATH="$OPENSSL_HOME/lib64${LD_LIBRARY_PATH:+:$LD_LIBRARY_PATH}"
export OPENSSL_CONF=/etc/ssl/openssl.cnf
python -m unittest discover -s tests -p 'test_*.py' -v
python src/v31_process_receipts.py --openssl "$OPENSSL_HOME/bin/openssl" --archive results/v31_process_gate --trials 3 --count 3
```

The program stores every trial's outcomes, `summary.csv`, `manifest.json`, and SHA-256 checksums in a fresh timestamped directory under the project `results/`. It stores failures as failures, and exits nonzero unless all scenarios achieve expected verdicts. Do not copy private TLS keys or the private ephemeral signing keys into public archives.

## Distinguishing experimental controls

- Live three-hop TLS 1.3 in **three separate process receivers**; three sequential transactions on each connection.
- `SSL_get0_group_name` read on each actual TLS connection.
- `export_keying_material` transaction-bound with node and transaction digest on the same TLS connection.
- Receivers independently sign observations with Ed25519; verifier pins public keys from local parent IPC, verifies signed contents, and checks adjacent exporter proofs.
- Classical middle leg: `VIOLATED`; three hybrid legs: `SATISFIED` under pinned-key assumptions.
- Unsigned alteration and wrong pinned public key: `INVALID`; missing witness: `UNRESOLVED`; transaction alteration: `INVALID`.
- **Negative control:** completely copied valid signed evidence still passes a stateless verifier. Correct protection against copied historical evidence requires verifier-chosen session challenge, reliable signed request context and anti-replay ledger. Honest but compromised signed receiver remains out of scope.

## Local validation at authoring time

On Linux with OpenSSL 3.5.5: 10/10 added unit tests passed and 6/6 live scenario runs passed across 3 trials. Ubuntu OpenSSL 3.5.9 results must be obtained by running the commands above. Local test outputs are not substituted for Ubuntu measurements.
