# Windows OpenSSL executable correction — v0.3

This update replaces `src/multihop.py`. The code now launches OpenSSL 3.5+ CLI processes for both TLS clients and TLS servers. It no longer relies on Python's internal OpenSSL 3.0.x for server TLS.

It also strips inherited `OPENSSL_CONF`, `OPENSSL_MODULES`, `OPENSSL_CONF_INCLUDE`, and `OPENSSL_ENGINES` variables from each subprocess environment. The Windows OpenSSL binary is pinned explicitly with `--openssl`; the prior bug arose because the old Python script invoked an unqualified `openssl` binary and used Python SSL for the servers.

Run this in PowerShell 5.1:

```powershell
cd 'D:\Articles\Post-Quantum TLS Migration\Post-Quantum TLS Migration-Project'
python .\src\multihop.py --openssl 'C:\Program Files\OpenSSL-Win64\bin\openssl.exe' --output .\results\multihop_local_v03
```

The output directory is new to prevent reusing certificates or results from a prior run.

Expected final line:

```
PASS: 5 real forwarded requests over 15 OpenSSL TLS 1.3 sessions
```

Testing: executed successfully on Linux with OpenSSL 3.5.5 and all five scenario checks passed. Windows with OpenSSL 3.5.9 remains untested in this environment.

Security and science limits: this is a controlled localhost laboratory; TLS certificates are self-signed and authentication is not verified, so the test concerns negotiated key-establishment groups only. Application paths rely on trusted request IDs. A fully instrumented per-hop baseline is decisive. This pilot does not establish novelty.
