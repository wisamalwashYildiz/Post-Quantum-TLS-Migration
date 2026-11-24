# v2.3 — Actual Linux UID isolation and live TLS observation

This is a **root-run laboratory privilege-boundary test**. It uses an OS-unprivileged client/reporting process (`nobody`) and a root-owned TLS receiver and witness key. The receiver directly observes the actual TLS 1.3 negotiated key-exchange group using the established CPython handshake callback; the client cannot read the receiver's protected HMAC key. One TLS connection carries three different application transactions. Both hybrid and classical TLS are observed. For the classical connection the attacker sends **correctly HMAC-signed, deliberately false hybrid reports** with its own reporting key, and the protected receiver report contradicts them.

A distinct UID and mode-0600 protected secret are **actual enforced Linux controls**. This is a *single TLS leg* and a *trusted root orchestrator/receiver* experiment. It is **not** root compromise, VM, TPM, remote attestation, cryptographic TLS exporter, or multi-hop protection. A privileged attacker can change the trust assumptions. The TLS certificate is self-signed and client-side certificate validation is disabled. No post-quantum certificate authentication is claimed.

## Install (additive)

Extract this ZIP into the established project root. It adds only:

* `src/os_boundary_v23.py`
* `tests/test_os_boundary_v23.py`
* `OS_BOUNDARY_v2_3_README.md`

Requires existing v1.1 `src/session_chain_v11.py`, `src/live_path.py`, and `src/session_evidence.py`; Python 3.12+ linked to OpenSSL 3.5+, your OpenSSL CLI, Ubuntu WSL2 with `sudo` and user `nobody`. `sudo` is deliberate and required: without root privileges the script **fails closed** rather than claim isolation.

## Start a fresh Windows PowerShell

```powershell
wsl -d Ubuntu-22.04
```

Inside Ubuntu:

```bash
cd "/mnt/d/Articles/Post-Quantum TLS Migration/Post-Quantum TLS Migration-Project"
source "$HOME/pqc-research-venv/bin/activate"
OPENSSL_HOME="$HOME/opt/openssl-3.5.9"
export LD_LIBRARY_PATH="$OPENSSL_HOME/lib64${LD_LIBRARY_PATH:+:$LD_LIBRARY_PATH}"
"$OPENSSL_HOME/bin/openssl" version
python -m unittest discover -s tests -p 'test_*.py' -v

# Ensure the output directory is owned by the trusted root orchestrator.
sudo mkdir -p results/os_boundary_v23

# sudo strips LD_LIBRARY_PATH in many Linux configurations, so pass the
# library path to `env` AFTER the sudo security boundary.
sudo env LD_LIBRARY_PATH="$LD_LIBRARY_PATH" \
  "$HOME/pqc-research-venv/bin/python" src/os_boundary_v23.py \
  --openssl "$OPENSSL_HOME/bin/openssl" \
  --output results/os_boundary_v23 \
  --attacker-user nobody \
  --count 3

cat results/os_boundary_v23/os_boundary_v23.json
```

Expected verdicts: `hybrid SATISFIED`, `classical INVALID`, `classical report-only baseline SATISFIED`, and `key_read_denied true` in both cases. Group values should be `X25519MLKEM768` vs `X25519`. This needs actual confirmation in the researcher's WSL environment; local verification used a separate Linux container.

The protected observer's key exists only inside a temporary Linux folder, readable by root. No observer keys are written to the results file. The attack process is executed using `setgroups([]); setgid(...); setuid(...)` and cannot elevate back to root. The **root experiment orchestration code** can access the key and must be considered trusted. Lab-only, do not use on a production system.

## Actual local verification

Using OpenSSL/Python 3.5 available in the test container: 8/8 v2.3 unit tests and the live root-vs-unprivileged-UID experiment passed; the old 107-test suite must be rerun by the researcher in Ubuntu after unpacking (expected 115 tests).

## Scientific interpretation

The experiment falsifies the statement that a signed forwarder claim is sufficient to establish hybrid TLS on the connection. A real root-protected receiver measurement exposes a signed forged hybrid assertion. However, the experiment's observer has authority over the TLS endpoint, not just a passive observer; its truthful code and root protection are assumptions. The group is parsed from the real handshake via internal Python callback, not independently derived from a TLS exporter. Next work: independently attested or OS-separated three-hop receivers with authentic connection-bound transaction forwarding and measured overhead.
