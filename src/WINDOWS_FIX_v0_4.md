# OpenSSL CLI transport fix v0.4

## Replacement
Replace `src\multihop.py` in your existing project with the enclosed version.
The script uses OpenSSL s_server -rev, rather than supplying application
responses through the Windows process stdin of s_server.

## Windows PowerShell 5.1
```powershell
cd 'D:\Articles\Post-Quantum TLS Migration\Post-Quantum TLS Migration-Project'
python .\src\multihop.py --openssl 'C:\Program Files\OpenSSL-Win64\bin\openssl.exe' --output .\results\multihop_local_v04
```

The subprocess environment removes potentially incompatible OPENSSL_CONF,
OPENSSL_MODULES, OPENSSL_ENGINES and OPENSSL_CONF_INCLUDE overrides. It does not
require changing Python's linked OpenSSL or reinstalling OpenSSL.

## Scope
This pilot transmits a request containing a persistent request ID through three
real TLS 1.3 connections, with an application orchestrator (Python) sequencing
the hops. The TLS endpoints are OpenSSL reverse-echo servers; they do not
independently forward requests. It is NOT independent network path discovery,
and it is NOT a production proxy test. The three-segment policy model is a
controlled teaching/feasibility example, not proof of a novel result.

Local validation: OpenSSL 3.5.5 Linux, all 5 scenario checks passed; Windows
3.5.9 must be validated by the project owner.

## Troubleshooting
If another timeout occurs, preserve the entire exception. In particular the
exception now includes the OpenSSL server diagnostic text, which will help
isolate a platform-dependent failure.
