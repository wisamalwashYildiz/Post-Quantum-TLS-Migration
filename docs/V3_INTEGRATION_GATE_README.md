# Post-Quantum TLS Migration — v3.0 integration gate (not final security release)

This additive release installs only `src/v30_session_gate.py` and `tests/test_v30_session_gate.py`. It does not overwrite any existing source, tests or archived results. This is a **proof-of-integration**, not an independently secured multi-process system.

## What is now new

Three live TLS 1.3 connections (client→gateway, gateway→service-a, service-a→backend) are processed in one combined pyOpenSSL experiment. On **each exact TLS Connection object**, the code asks OpenSSL for the negotiated KEX group using `SSL_get0_group_name` and derives transaction-specific exporter material using `Connection.export_keying_material`. It binds the exporter derivation to hop name, transaction hash and nonce. Exporter material and the TLS private key are never written to the public archive. The three sequential transactions are transmitted across each connection with matching application acknowledgments.

The gate compares all-hybrid `X25519MLKEM768` against a classical middle hop `X25519`; changes to the transaction, exporter-proofs and missing records are tested. The offline verifier cross-compares records and detects a classical hop when supplied with accurate receiver evidence.

**Critical negative control**: cloning a complete receipt set still passes offline verification. This demonstrates that matching exporter proofs alone do NOT establish independent, authenticated provenance or resistance to forged report sets. The sender/receivers currently share one user process and no OS separation. This gate must not be claimed as demonstrating secured end-to-end assurance or actual relay compromise resistance. Certificate validation disabled, no PQ authentication, no session resumption or performance scaling in this gate. The `SSL_CTX_ctrl` macro uses control ID 92 as specified in OpenSSL `ssl.h`, and requires compatible `libssl.so.3` with pyOpenSSL's bound OpenSSL library.

## Installation

Extract this archive into the existing `Post-Quantum TLS Migration-Project`, merging `src/` and `tests/`, without replacing other files.

Start a new PowerShell window and run `wsl -d Ubuntu-22.04`. Inside Ubuntu:

```bash
cd "/mnt/d/Articles/Post-Quantum TLS Migration/Post-Quantum TLS Migration-Project"
source "$HOME/pqc-research-venv/bin/activate"
OPENSSL_HOME="$HOME/opt/openssl-3.5.9"
export LD_LIBRARY_PATH="$OPENSSL_HOME/lib64${LD_LIBRARY_PATH:+:$LD_LIBRARY_PATH}"
python -m unittest discover -s tests -p 'test_*.py' -v
python src/v30_session_gate.py \
  --openssl "$OPENSSL_HOME/bin/openssl" \
  --archive results/v30_session_gate \
  --trials 3 --count 3
```

No root privilege is needed. Output is automatically archived under `results/v30_session_gate/gate_<timestamp>_<id>/` with a manifest, a per-trial JSON, summary.csv, and SHA-256 checksums. Failed experiments are also recorded and cause a nonzero exit code. **Do not store certificates/private keys in public results**.

## Next release gate

Integrate this same-session evidence derivation into the v2.4 OS-enforced receiver processes (prefer fresh `exec`, separate UIDs and explicit key-provenance), using actual relay-controlling attacker processes. Until that is done, label the prototype as `v3.0 integration gate` rather than an accomplished independently trustworthy v3.0 implementation. Keep v2.5/2.6 benchmark measurements unchanged.
