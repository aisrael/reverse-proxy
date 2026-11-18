#!/usr/bin/env python3
"""Send test requests through the proxy, with the different test certificates,
and check the status of each answer.

The script needs a running `server` and a running `proxy`, with the policy
file `policies.yaml` of this repository. It needs the files of
`scripts/gen-dev-certs.sh`. To see the audit events, look at STDOUT of the proxy.

Usage:
    scripts/send-test-requests.py

Variables (the defaults are the defaults of the program):
    PROXY_ADDR    The address of the proxy.  Default: 127.0.0.1:8080
    SERVER_ADDR   The address of the server. Default: 127.0.0.1:9000

Exit code: 0 if every answer has the expected status, 1 if not, 2 if the
setup is not ready (a program is not running, or a certificate is missing).

The script uses only the standard library of Python 3.
"""

import http.client
import os
import socket
import ssl
import subprocess
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
CERTS = ROOT / "dev-certs"
PROXY_ADDR = os.environ.get("PROXY_ADDR", "127.0.0.1:8080")
SERVER_ADDR = os.environ.get("SERVER_ADDR", "127.0.0.1:9000")


def split_addr(addr: str) -> tuple[str, int]:
    host, _, port = addr.rpartition(":")
    return host, int(port)


def is_listening(addr: str) -> bool:
    """Return True if something accepts connections on `host:port`."""
    try:
        with socket.create_connection(split_addr(addr), timeout=2):
            return True
    except OSError:
        return False


def send(expected: int, cert: str, method: str, path: str) -> bool:
    """Send one request. Print the result. Return True if the status is expected.

    expected  The status that we expect. 0 means that there is no HTTP answer,
              because the TLS handshake fails.
    cert      The name of the certificate in dev-certs/ (without `.pem`), or
              `none` for a client with no certificate.
    """
    context = ssl.create_default_context(cafile=str(CERTS / "ca.pem"))
    # Python 3.13 and later check the certificates in strict mode. That mode
    # needs an Authority Key Identifier, and the dev certificates have none.
    # curl and the proxy do not need it. This is for local dev certificates only.
    context.verify_flags &= ~ssl.VERIFY_X509_STRICT
    if cert != "none":
        context.load_cert_chain(CERTS / f"{cert}.pem", CERTS / f"{cert}.key")
    host, port = split_addr(PROXY_ADDR)
    connection = http.client.HTTPSConnection(host, port, context=context, timeout=5)
    error = ""
    try:
        # `http.client` sends the path as it is. It does not remove `..`.
        # With TLS 1.3, a rejected client certificate shows up when we read.
        connection.request(method, path, body=b"" if method == "POST" else None)
        status = connection.getresponse().status
    except (OSError, http.client.HTTPException) as err:
        status = 0
        error = f"{type(err).__name__}: {err}"
    finally:
        connection.close()

    ok = status == expected
    print(
        f"{'ok' if ok else 'FAIL':<4} {status:03d}  {cert:<16} {method:<5} {path:<44} "
        f"(expected {expected:03d})"
    )
    # A failure that we did not expect: show why.
    if not ok and error:
        print(f"       {error}")
    return ok


# Each group: a title, then (expected status, certificate, method, path).
GROUPS = [
    (
        "Allowed by the policy:",
        [
            (200, "payment-agent", "POST", "/payments"),
            (200, "reporting-agent", "GET", "/reports/1"),
            (200, "reporting-agent", "GET", "/reports/1?token=not-in-the-audit-event"),
        ],
    ),
    (
        "Denied by the policy (403):",
        [
            (403, "payment-agent", "GET", "/payments"),
            (403, "payment-agent", "POST", "/reports/1"),
            (403, "reporting-agent", "POST", "/payments"),
            (403, "reporting-agent", "GET", "/reports"),
        ],
    ),
    (
        "Path that is not valid (400):",
        [
            (400, "payment-agent", "POST", "/payments//x"),
            (400, "reporting-agent", "GET", "/reports/%2e%2e/payments"),
            (400, "reporting-agent", "GET", "/reports/../payments"),
        ],
    ),
    (
        "No identity (401):",
        [(401, "no-uri-agent", "POST", "/payments")],
    ),
    (
        "TLS handshake fails (no answer):",
        [
            (0, "none", "POST", "/payments"),
            (0, "untrusted-agent", "POST", "/payments"),
            (0, "expired-agent", "POST", "/payments"),
        ],
    ),
]


def main() -> int:
    check = subprocess.run(
        [ROOT / "scripts" / "gen-dev-certs.sh", "check"], capture_output=True
    )
    if check.returncode != 0:
        print(
            "A test certificate is missing or expired. Run: scripts/gen-dev-certs.sh",
            file=sys.stderr,
        )
        return 2
    if not is_listening(SERVER_ADDR):
        print(
            f"The server is not running on {SERVER_ADDR}. Start it: cargo run -- server",
            file=sys.stderr,
        )
        return 2
    if not is_listening(PROXY_ADDR):
        print(
            f"The proxy is not running on {PROXY_ADDR}. Start it: cargo run -- proxy",
            file=sys.stderr,
        )
        return 2

    print(f"Proxy: https://{PROXY_ADDR}  Server: http://{SERVER_ADDR}\n")
    failures = 0
    for title, requests in GROUPS:
        print(title)
        for request in requests:
            if not send(*request):
                failures += 1

    print()
    if failures:
        print(f"{failures} request(s) did not get the expected status.")
        return 1
    print("Every request got the expected status.")
    print("The proxy wrote one audit event for each request that passed the handshake.")
    return 0


if __name__ == "__main__":
    sys.exit(main())
