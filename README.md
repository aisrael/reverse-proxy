# reverse-proxy

A reverse proxy, and a small web server to test it with.

## Local TLS setup

Make a CA and a server certificate for local tests:

```sh
./scripts/gen-dev-certs.sh
```

The script uses `openssl`. It writes these files to `dev-certs/`:

- `ca.pem` and `ca.key`: a self-signed CA (EC P-256).
- `server.pem` and `server.key`: a server certificate (EC P-256), signed by the CA.
  It is valid for `localhost` and `127.0.0.1`.

The certificates are valid for 30 days. The script is safe to run many times.
It makes only the files that are missing or expired.

To check the files without a change, run:

```sh
./scripts/gen-dev-certs.sh check
```

The command exits with code 1 if a file is missing or a certificate is expired.

To check the certificate by hand:

```sh
openssl verify -CAfile dev-certs/ca.pem dev-certs/server.pem
openssl x509 -in dev-certs/server.pem -noout -text | grep -A1 "Alternative Name"
```

> **Warning:** Use these certificates for local development and tests only.
> Never trust the CA outside your own machine. Never commit a key.
> Git ignores `dev-certs/`.
