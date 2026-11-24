# Post-Quantum TLS Migration — v2.4 protected three-hop experiment

## Claim and scope

Three genuine TLS 1.3 connections form `client → gateway → service-a → backend`. Each trusted receiver terminates TLS in a separate root-owned process. The client/reporting agent is a fresh-exec subprocess whose UID/GID drops to `nobody` *before* attacker logic begins. Three sequential application transactions reuse each hop's TLS connection. Receiver observations attest each transaction's arrival on the measured TLS session, and the external verifier checks the three-hop chain.

This **does not** implement a different OS identity for each receiver. The receiver processes **all share root trust**. The malicious coordinated modification of the gateway and service-a reports is an **offline re-signing intervention using report keys supplied to the experimental orchestrator**. No OS-compromised relay process is simulated, and no resistance to dishonest receiver observation is established. The `nobody` key-access test concerns a root-owned key file inaccessible to its UID. The attacker subprocess starts as root to load a private Python distribution and then drops privileges; do not use this bootstrapping approach as an untrusted code sandbox.

Other limitations: same-host loopback; one TLS session per hop per case with sequential transactions (not concurrent multiplexing); public handshake random-derived session labels, not TLS exporter channel binding; self-signed unverified lab certificates; hybrid key exchange only, not post-quantum authentication; non-root attacker only, no root/host compromise resistance.

## Install without replacing earlier versions

Extract `src/protected_path_v24.py` and `tests/test_protected_path_v24.py` into the preexisting project root. The ZIP does not contain or replace earlier versions. Existing `live_path.py`, `session_chain_v11.py`, and `multihop_witness_v14.py` are required.

## Launch from a completely new PowerShell session

```powershell
wsl -d Ubuntu-22.04
```

In Ubuntu (NOT PowerShell):

```bash
cd "/mnt/d/Articles/Post-Quantum TLS Migration/Post-Quantum TLS Migration-Project"
source "$HOME/pqc-research-venv/bin/activate"
OPENSSL_HOME="$HOME/opt/openssl-3.5.9"
export LD_LIBRARY_PATH="$OPENSSL_HOME/lib64${LD_LIBRARY_PATH:+:$LD_LIBRARY_PATH}"
"$OPENSSL_HOME/bin/openssl" version
python -m unittest discover -s tests -p 'test_*.py' -v
sudo mkdir -p /var/tmp/pqc-protected-path-v24
sudo chown root:root /var/tmp/pqc-protected-path-v24
sudo chmod 700 /var/tmp/pqc-protected-path-v24
stat -c '%U %G %a %n' /var/tmp/pqc-protected-path-v24
sudo env LD_LIBRARY_PATH="$LD_LIBRARY_PATH" \
  "$HOME/pqc-research-venv/bin/python" \
  src/protected_path_v24.py \
  --openssl "$OPENSSL_HOME/bin/openssl" \
  --output /var/tmp/pqc-protected-path-v24 \
  --attacker-user nobody \
  --count 3
sudo cat /var/tmp/pqc-protected-path-v24/protected_path_v24.json
```

Do not put privileged runtime output under `/mnt/d` as DrvFs may not maintain the required root ownership. **Do not alter home-directory permissions**. Run only in a dedicated WSL laboratory under your own administrative control. Requires `sudo`, local loopback, `nobody` account, and existing OpenSSL 3.5.x-Python environment.

Expected output:

```
hybrid SATISFIED
classical_middle VIOLATED
forged_baseline SATISFIED
forged_corroborated INVALID
missing_witness UNRESOLVED
swapped_witness INVALID
replayed_transaction INVALID
PASS: OS-separated client vs root receiver chain, live three-hop TLS and evidence checks
```

The generated JSON reports group observations, policy verdicts, key-read denial and limitations. It excludes private keys and raw transaction material. The independent verifier in this pilot is called by the trusted orchestrator; **a separately launched verifier executable and publicly verifiable certificates are not yet implemented**.

## Fair evaluation and v3.0 exit criteria

v2.4 shows why a report-only baseline is unsafe under offline coordinated re-signing, but no improvement over a strong equally trusted observer baseline is claimed. For v3.0, insist on a frozen v2 full-path design with actual TLS exporter integration and measured negotiated-group evidence on the SAME sessions, at least two receiver trust domains with verifiably distinct identities and permissions, honest/compromised-receiver negative controls, multiple seeds/loads, and measured runtime/capture overhead. If these are not achieved, continue v2 rather than relabel existing tests as v3.
