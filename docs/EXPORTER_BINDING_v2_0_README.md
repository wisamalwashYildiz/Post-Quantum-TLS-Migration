# v2.0 — genuine TLS exporter experiment: first binding gate, not full publishable v2.0

## What is implemented

New TLS 1.3 connection, created using `pyOpenSSL` and `OpenSSL.SSL.Connection.export_keying_material`. Both endpoints derive 32 bytes from the same exporter label and transaction nonce context. The exported secret is NEVER written to the results. Each endpoint derives an HMAC of the canonical transaction under its secret and emits a proof; equality is tested. Substitution, transaction modification, replay when a verifier ledger is supplied, and absence are rejected or unresolved. A separate negative-control test **copies a valid proof** to demonstrate that matching exporter proofs alone do NOT authenticate independent endpoint provenance (a copied proof is accepted by the current comparison). This is a documented remaining gap, not a security guarantee.

**Security limitations**: This pilot does NOT establish a cryptographically secure end-to-end path or prove real forwarding; it tests one actual TLS session, not three hops. It does NOT detect or verify the hybrid KEM chosen on this pyOpenSSL session (prior Python stdlib / v1.4 measurements are on distinct sessions). A proof copied from one endpoint can impersonate the other to this simple equality checker. Application-level report authenticity and genuine distinct OS security domains remain unimplemented. Certificates are laboratory self-signed and the client intentionally skips X.509 validation. Do not represent this as production TLS authentication, PQ signature assurance, full multi-hop assurance, proof of independently produced attestations, or resistance to host compromise.

## Install / dependency

Requires existing `src/live_path.py` as used by v1.4. Adds `pyOpenSSL` for access to the exporter API; the default Python ssl.SSLSocket exposes no public `export_keying_material` API in the tested build. In Ubuntu with the project virtualenv active, check `python -c 'import OpenSSL; print(OpenSSL.__version__)'`; install the missing dependency with `python -m pip install 'pyOpenSSL>=25,<27'` **only if not installed**. pyOpenSSL may be linked against a separately bundled OpenSSL version; therefore it must NOT be called a verified OpenSSL 3.5.9 native TLS stack solely because the Python stdlib `ssl` reports OpenSSL 3.5.9.

## Fresh Windows PowerShell

```powershell
wsl -d Ubuntu-22.04
```

## Ubuntu

Extract this archive into the existing project root, merging new `src` and `tests` files while preserving earlier versions.

```bash
cd "/mnt/d/Articles/Post-Quantum TLS Migration/Post-Quantum TLS Migration-Project"
source "$HOME/pqc-research-venv/bin/activate"
OPENSSL_HOME="$HOME/opt/openssl-3.5.9"
export LD_LIBRARY_PATH="$OPENSSL_HOME/lib64${LD_LIBRARY_PATH:+:$LD_LIBRARY_PATH}"
python -c 'import ssl; print("stdlib:", ssl.OPENSSL_VERSION); from OpenSSL import SSL; print("pyOpenSSL exporter:", hasattr(SSL.Connection,"export_keying_material"))'
python -m unittest discover -s tests -p 'test_*.py' -v
python src/exporter_binding_v20.py --openssl "$OPENSSL_HOME/bin/openssl" --output results/exporter_binding_v20
```

Expected live statuses: `same_session BOUND`, `substituted_peer INVALID`, `changed_transaction INVALID`, `replayed_transaction INVALID`, `missing_peer UNRESOLVED`, **`cloned_proof_limitation BOUND`**. This last outcome deliberately demonstrates a vulnerability of an unsigned / non-attested equality record.

## Honest novelty gate

Next actual v2 step: independent protected endpoint credentials, separate OS identities / independent observer execution, cryptographic exporter-based proof of possession linked to signed receiver observations, and real three-hop concurrent transactions, with the negotiated KEM group obtained from the **same** TLS connections. Then verify compromise and false-assurance baselines. This release makes no assertion of journal-level novelty or superiority to an optimal baseline.
