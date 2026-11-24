# Post-Quantum TLS — Six-Experiment Extension Suite

This package adds six **new** experiment entrypoints and one runner. It does NOT alter existing manuscript code, historical experiment outputs, or original verifier. Copy only the files in the `src/` folder into your existing project's `src/` directory. The archive intentionally excludes the two existing modules used for local testing (`v30_session_gate.py` and `v32_protected_freshness.py`): they remain yours and must **not** be overwritten.

All outputs appear below `results/postquantum_extension/run_YYYYMMDDTHHMMSSZ/`, including per-module `cases.csv`, `summary.json`, `*.stdout.log`, `*.stderr.log`, `manifest.json`, and `checksums.json`.

## The six experiments

- `v37_multigroup_live.py`: real three-hop TLS 1.3 runs with five negotiated group configurations, including heterogeneous standardized hybrid groups. **Requires native Linux root for the original v32 UID-isolation code.** The original verifier only recognizes X25519MLKEM768; `legacy_verdict` is **not** a flexible-policy result. The runtime may report unsupported-group errors; report them, do not suppress them.
- `v38_migration_trajectory.py`: exhaustive eight classical/hybrid paths, synthetic signed evidence evaluated by the unchanged v32 verifier.
- `v39_control_ablation.py`: 40 paired custom checker evaluations, intentionally disabled signature/group/proof controls. Synthetic evidence, **not** the existing production verifier for weakened configurations. Results are mechanism diagnostics.
- `v40_scaling.py`: simulated 3/5/7/10/16-hop Ed25519 evidence verification and local timing. **No live TLS or network scaling claim**.
- `v41_compromise_boundary.py`: signed unilateral and multi-role falsification of synthetic records, tested against unchanged v32 verifier. Does not prove independent compromise resistance.
- `v42_concurrent_freshness.py`: 12 concurrent uses of the **actual** v32 SQLite freshness ledger with synthetic signed evidence. Exactly one accepted outcome is the expected single-use behavior.

## Run on your Ubuntu / WSL system

In PowerShell:

```powershell
wsl -d Ubuntu-22.04
```

In Ubuntu (after copying `src/*.py` into the project `src/`):

```bash
cd "/mnt/d/Articles/Post-Quantum TLS Migration/Post-Quantum TLS Migration-Project"
source "$HOME/pqc-research-venv/bin/activate"
python src/v43_run_six.py --output-root results/postquantum_extension
```

That first run executes five nonprivileged experiments and intentionally SKIPS the live UID-isolation experiment.

For the live experiment, FIRST verify your virtualenv and OpenSSL 3.5 installation, and ensure the existing v32 lab's privileged execution already works on your machine. Check the module before authorizing it to run as root. Then:

```bash
sudo "$(command -v python)" src/v43_run_six.py \
  --output-root results/postquantum_extension \
  --include-live --openssl "$(command -v openssl)"
```

The runner also reruns the other five experiments under the same process credentials. To run *only* the live experiment instead, prefer:

```bash
sudo "$(command -v python)" src/v37_multigroup_live.py \
  --out results/postquantum_extension/live_standalone \
  --openssl "$(command -v openssl)"
```

**Important:** The v37 live experiment calls the archived `v32.live_case()` implementation. That implementation uses UID changes and writes transient signing keys in a freshly created temporary directory. It is meant for a disposable local laboratory environment; it does not test root compromise resistance. The original module does not offer a graceful privilege-free substitute. Do not invoke it as sudo on a production system.

## Scope and manuscript-integrity cautions

The five successful smoke tests were run locally in a separate environment. Your laptop remains the authoritative reproduction environment. Do not merge these findings into the original paper until scientific interpretation and numerical agreement are independently reviewed. Synthetic cases should never be represented as new TLS handshakes, and the strict policy hard-coded in v32 should not be misrepresented as general set-based hybrid policy enforcement.

The suite uses no network downloads. It requires your preexisting Python venv with `cryptography` and `pyOpenSSL` to import the existing v32 module. Source verifiers and the existing results are read-only dependencies.
