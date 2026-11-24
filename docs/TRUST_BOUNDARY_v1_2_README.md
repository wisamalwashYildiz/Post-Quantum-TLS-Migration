# Post-Quantum TLS Migration — v1.2 trust-boundary pilot

## Purpose
Preserve v1.1 and test a distinct evidence-trust assumption: compromise of **two adjacent forwarding receipt keys** versus an additional independently **keyed receiver-side observation** of the TLS session group. A forged pair of forwarding receipts can otherwise make the v1.1 chain internally consistent while reporting a false hybrid group.

## Files
New files: `src/trust_boundary_v12.py`, `src/verify_trust_boundary_v12.py`, `tests/test_trust_boundary_v12.py`. Existing `src/session_chain_v11.py`, `src/live_path.py`, and `src/session_evidence.py` are required, but are NOT replaced by the ZIP.

## Windows → fresh Ubuntu → commands
In a freshly opened **Windows PowerShell**:

```powershell
wsl -d Ubuntu-22.04
```

Inside Ubuntu (same terminal for all commands below):

```bash
cd "/mnt/d/Articles/Post-Quantum TLS Migration/Post-Quantum TLS Migration-Project"
source "$HOME/pqc-research-venv/bin/activate"
OPENSSL_HOME="$HOME/opt/openssl-3.5.9"
if [ -f "$OPENSSL_HOME/lib64/libcrypto.so.3" ]; then
  OPENSSL_LIB="$OPENSSL_HOME/lib64"
elif [ -f "$OPENSSL_HOME/lib/libcrypto.so.3" ]; then
  OPENSSL_LIB="$OPENSSL_HOME/lib"
else
  echo "ERROR: Custom OpenSSL shared libraries not found"
  return 1 2>/dev/null || false
fi
export LD_LIBRARY_PATH="$OPENSSL_LIB${LD_LIBRARY_PATH:+:$LD_LIBRARY_PATH}"
"$OPENSSL_HOME/bin/openssl" version
python -m unittest discover -s tests -p 'test_*.py' -v
python src/trust_boundary_v12.py --openssl "$OPENSSL_HOME/bin/openssl" --output results/trust_boundary_v12
python src/verify_trust_boundary_v12.py --evidence results/trust_boundary_v12/trust_boundary.json --keys results/trust_boundary_v12/lab_keys.json
```

The final verifier must **only** be run after the experiment successfully creates the two files.

## Security interpretation
- **Baseline trust model:** v1.1 trusts every TLS forwarding process and its HMAC secret. Two adjacent malicious receipt producers can jointly re-label a classical middle TLS link as hybrid, while maintaining consistent signed session identifiers. Therefore a baseline `SATISFIED` verdict in this adversarial lab case is unsafe relative to actual handshake ground truth.
- **Additional observer trust model:** The receiving endpoint records `in` from its own TLS handshake tracker; a separate HMAC key `observer:service-a` authenticates this observation to the verifier. The forged upstream/downstream *forwarder* receipts contradict this receiver observation and are rejected.
- **Crucial boundary:** the *receiver observer is an object within the same receiving relay Python process*. Separately keyed is NOT independently hosted, tamper-resistant, authenticated hardware, or isolated from a fully compromised process. The current experiment only models a compromise restricted to selected forwarder receipt signing keys, **without compromise of the receiver observer instrumentation or signing key**.
- **Another boundary:** receiving endpoint learns the transaction from application payload. Its signed assertion is not independent evidence of transaction forwarding by a dishonest receiving endpoint. Public ClientHello/ServerHello random digests label TLS sessions, but do not prove channel possession. Certificates are unvalidated laboratory certificates. Only hybrid key agreement is measured, not PQ authentication.
- **Threats outside scope:** replay of the same nonce without a persistent registry, multi-host deployment, concurrent connections, connection reuse, false observer signing, compromise of observer process, active network-side handshake validation.

## Locally checked
9 deterministic regression tests passed in development container. The **live hybrid network run has not been executed in the development container**; run that on the user's custom OpenSSL 3.5.9 Python environment. No measured overhead or empirical robustness claim yet.

## Next decisive research step
Move corroboration into an independently hosted/isolated observer with a carefully defined ability to view handshake and transaction binding. Compare authenticity guarantees, intervention rate, latency/byte cost, and certificate-verifier correctness against similarly trusted baselines. No claim of cryptographic independent attestation from this prototype.
