# reverse-proxy

A reverse proxy, and a small web server to test it with.

## Configuration

The program reads these environment variables once, at start. A variable that is
set must not be empty.

| Variable         | Default          | Mode     | Meaning                                                    |
| ---------------- | ---------------- | -------- | ---------------------------------------------------------- |
| `PROXY_ADDR`     | `127.0.0.1:8080` | `proxy`  | The address (`host:port`) that the proxy listens on.       |
| `SERVER_ADDR`    | `127.0.0.1:9000` | both     | The address of the `server` mode. The proxy sends its requests here. |
| `PROXY_TLS_CERT` | none (required)  | `proxy`  | The path of the certificate file (PEM).                    |
| `PROXY_TLS_KEY`  | none (required)  | `proxy`  | The path of the private key file (PEM).                    |
| `PROXY_CLIENT_CA` | none (required) | `proxy`  | The path of the CA bundle file (PEM) that signs the client certificates. |
| `PROXY_POLICY_FILE` | none (required) | `proxy` | The path of the policy file (YAML). See `policies.yaml`. |
| `RUST_LOG`       | `info`           | both     | The log level, for example `debug`.                        |

The `proxy` mode stops at start, with exit code 1, if `PROXY_TLS_CERT`,
`PROXY_TLS_KEY`, `PROXY_CLIENT_CA` or `PROXY_POLICY_FILE` is not set, or if a
file cannot be read or is not valid.
The `server` mode does not use the TLS variables.

The `proxy` mode requires a client certificate (mTLS). A client without a
certificate that the CA in `PROXY_CLIENT_CA` signed fails the TLS handshake.

## Policy

The `proxy` mode checks every request against the policy file
(`PROXY_POLICY_FILE`, see `policies.yaml`). The file lists, for each client
identity (SPIFFE ID), the methods and paths that it may use. A path is exact
(`/payments`) or a prefix (`/reports/*`). A prefix matches whole segments, and
needs at least one more segment. The proxy ignores the query.

The proxy answers with an empty body, and does not send the request to the
upstream, in these cases:

| Status | Case                                                            |
| ------ | --------------------------------------------------------------- |
| `401`  | The client certificate has no valid identity.                   |
| `400`  | The path is not valid: `..`, `.`, `//`, `%2f`, `%2e`, `%5c`, NUL. |
| `403`  | The policy does not allow this identity to send this request.   |

The proxy does not decode `%` sequences in the path. See
`docs/adrs/001-no-percent-decoding-in-path-policy.md`.

## Local TLS setup

Make a CA and a server certificate for local tests:

```sh
./scripts/gen-dev-certs.sh
```

The script uses `openssl`. It writes these files to `dev-certs/`:

- `ca.pem` and `ca.key`: a self-signed CA (EC P-256).
- `server.pem` and `server.key`: a server certificate (EC P-256), signed by the CA.
  It is valid for `localhost` and `127.0.0.1`.
- `payment-agent.pem` and `payment-agent.key`: a client certificate (EC P-256),
  signed by the CA. Its URI SAN is `spiffe://acme/prod/payment-agent`.
- `reporting-agent.pem` and `reporting-agent.key`: a client certificate (EC P-256),
  signed by the CA. Its URI SAN is `spiffe://acme/prod/reporting-agent`.

The script also makes files for tests that must fail. The proxy must reject
these clients:

- `other-ca.pem` and `other-ca.key`: a second CA. The proxy does not trust it.
- `untrusted-agent.pem` and `untrusted-agent.key`: a client certificate that the
  second CA signed.
- `expired-agent.pem` and `expired-agent.key`: a client certificate that the CA
  signed. It expired in January 2020. The `check` command does not report it.
- `no-uri-agent.pem` and `no-uri-agent.key`: a client certificate that the CA
  signed. It has no URI SAN, so it has no SPIFFE ID. The handshake works, but
  the proxy answers every request with `401`.

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
