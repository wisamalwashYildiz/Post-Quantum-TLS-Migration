# Post-Quantum TLS Migration: v3.2 Protected-UID and Durable-Freshness Gate

## Scope

This is an additive, privileged Linux **laboratory** integration gate. It preserves all existing v3.1 files and earlier results. It uses the existing `src/v30_session_gate.py` library from the previously installed v3.0 package. Do **not** place private key files in the Windows-mounted project.

Each scenario uses three real localhost TLS 1.3 legs and three sequential transactions per TLS connection by default. For the three server-receiver processes, the trusted root orchestrator picks *three distinct unassigned numeric Linux UIDs*; it runs an attacker probe under a fourth UID. Each receiver creates a new Ed25519 signing key in its UID-owned, mode-0700 directory, with the key file at mode 0600. The attacker probes and is refused key-file access. The verifier checks signed TLS receiver receipts, session exporter-derived proofs, negotiated groups, and transaction hashes. An independently specified random verifier challenge is included in each transaction; a root-trusted durable SQLite ledger rejects a second decision for a previously accepted challenge, including across verifier object restarts. The ledger is retained in the public archive but only holds hashes of challenges and prior verdicts. Keys and raw exporter material are not exported.

**Security limitations:** root and system administrator are trusted, and can impersonate all roles. `fork` preloads Python and OpenSSL contexts before dropping privileges, so this does not sandbox arbitrary malicious code or provide root-compromise resistance. The code uses one local Linux host, no remote network, TLS server certificate validation is disabled, the lab uses a shared self-signed RSA certificate, and it does not test PQ authentication. Receiver endpoint compromise with its own signing key and collusion are *not* defended against. The attacker probe tests filesystem access to keys (not the entire Linux security kernel). UIDs are selected from 62001-62998 if unassigned according to passwd and must not be independently allocated by other processes during the run. Keep this to a disposable, trusted test host.

## Files

- `src/v32_protected_freshness.py` — privileged live TLS experiment, UID isolation, signed receipts, challenge and SQLite replay ledger.
- `src/v32_campaign_launcher.py` — execute as your normal account. It invokes `sudo` only for trusted temporary execution on `/var/tmp` and archives sanitized trial records in the project as the normal user.
- `tests/test_v32_protected_freshness.py` — nine standalone regression tests.

## Ubuntu 22.04 / OpenSSL 3.5.9

Extract the ZIP into the root of your existing project; it adds only v3.2 files. **Open a new PowerShell**:

```powershell
wsl -d Ubuntu-22.04
```

Then paste these lines inside Ubuntu:

```bash
cd "/mnt/d/Articles/Post-Quantum TLS Migration/Post-Quantum TLS Migration-Project"
source "$HOME/pqc-research-venv/bin/activate"
OPENSSL_HOME="$HOME/opt/openssl-3.5.9"
export LD_LIBRARY_PATH="$OPENSSL_HOME/lib64${LD_LIBRARY_PATH:+:$LD_LIBRARY_PATH}"
export OPENSSL_CONF=/etc/ssl/openssl.cnf
python -m unittest discover -s tests -p 'test_*.py' -v
python src/v32_campaign_launcher.py \
  --python "$HOME/pqc-research-venv/bin/python" \
  --openssl "$OPENSSL_HOME/bin/openssl" \
  --archive results/v32_protected_freshness \
  --trials 3 --count 3
```

The complete unittest suite should have **174 tests** if the previously recorded 165 tests are present and the nine new tests were installed.

The launcher produces `results/v32_protected_freshness/campaign_<utc>_<id>/experiment.log`, `launcher_manifest.json`, and `gate_*/` containing `manifest.json`, `summary.csv`, all six individual trial JSONs, `verifier_ledger.sqlite3` and `checksums.sha256`. It verifies each checksum after archival. Every run has a unique name, preserving historical results. If a trial fails, the program returns a failure exit status and preserves its diagnostic record.

## What counts as success

- All hybrid: `SATISFIED`; classical middle: `VIOLATED`.
- Forged signed record modification without the sender's private signing key: `INVALID`.
- Missing signed witness: `UNRESOLVED`.
- Replayed authentic evidence with the same committed challenge: `INVALID` even if verifier is recreated.
- Copied authentic evidence presented under a *new* challenge: `INVALID`.
- Different OS UID verified for all receiver processes and attacker; attacker's access to three private keys denied.

## Interpretation

These are controlled laboratory cases, not random attacks. A verifier controlled by an attacker can simply erase its ledger or substitute public keys. A dishonest endpoint that possesses its own key can sign dishonest statements; separate UIDs only protect keys from other unprivileged identities. Durable verifier state must remain trusted and backed up. Freshness does not make an untrustworthy signer trustworthy. Evidence custody and host/root compromise remain assumptions. Future publication claims require an explicit threat model and comparative distributed benchmarking.
