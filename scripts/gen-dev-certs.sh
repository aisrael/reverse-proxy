#!/usr/bin/env bash
#
# Make a CA and a server certificate for local TLS tests.
#
# WARNING: Use these certificates for local development and tests only.
# The keys are not secret. Never trust this CA outside your own machine.
#
# Usage:
#   scripts/gen-dev-certs.sh         Make the files that are missing or expired.
#   scripts/gen-dev-certs.sh check   Make nothing. Exit 1 if a file is missing
#                                    or a certificate is expired.
#
# Files in dev-certs/ (at the root of the repository):
#   ca.pem, ca.key          Self-signed CA (EC P-256).
#   server.pem, server.key  Server certificate (EC P-256), signed by the CA.
#                           Valid for localhost and 127.0.0.1.

set -euo pipefail

DAYS=30
DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)/dev-certs"
CA_CERT="$DIR/ca.pem"
CA_KEY="$DIR/ca.key"
SERVER_CERT="$DIR/server.pem"
SERVER_KEY="$DIR/server.key"

# True if the certificate file exists and is not expired.
is_valid() {
    [ -f "$1" ] && openssl x509 -in "$1" -noout -checkend 0 >/dev/null 2>&1
}

# True if the CA files are all present and the CA is not expired.
ca_ok() {
    [ -f "$CA_KEY" ] && is_valid "$CA_CERT"
}

# True if the server files are all present and the certificate is not expired.
server_ok() {
    [ -f "$SERVER_KEY" ] && is_valid "$SERVER_CERT"
}

make_ca() {
    local tmp
    tmp="$(mktemp -d)"
    # Remove the temporary files when the function ends or fails.
    trap 'rm -rf "$tmp"' RETURN
    openssl ecparam -name prime256v1 -genkey -noout -out "$CA_KEY"
    chmod 600 "$CA_KEY"
    openssl req -new -key "$CA_KEY" -subj "/CN=reverse-proxy dev CA" -out "$tmp/ca.csr"
    # A TLS client accepts a CA only if the certificate says CA:TRUE.
    cat >"$tmp/ca.ext" <<EXT
basicConstraints = critical, CA:TRUE
keyUsage = critical, keyCertSign, cRLSign
EXT
    openssl x509 -req -in "$tmp/ca.csr" -signkey "$CA_KEY" -sha256 -days "$DAYS" \
        -extfile "$tmp/ca.ext" -out "$CA_CERT"
    echo "made $CA_CERT"
}

make_server() {
    local tmp
    tmp="$(mktemp -d)"
    # Remove the temporary files when the function ends or fails.
    trap 'rm -rf "$tmp"' RETURN
    openssl ecparam -name prime256v1 -genkey -noout -out "$SERVER_KEY"
    chmod 600 "$SERVER_KEY"
    openssl req -new -key "$SERVER_KEY" -subj "/CN=localhost" -out "$tmp/server.csr"
    cat >"$tmp/server.ext" <<EXT
basicConstraints = critical, CA:FALSE
keyUsage = critical, digitalSignature
extendedKeyUsage = serverAuth
subjectAltName = DNS:localhost, IP:127.0.0.1
EXT
    openssl x509 -req -in "$tmp/server.csr" -CA "$CA_CERT" -CAkey "$CA_KEY" \
        -CAcreateserial -CAserial "$tmp/ca.srl" -sha256 -days "$DAYS" \
        -extfile "$tmp/server.ext" -out "$SERVER_CERT"
    echo "made $SERVER_CERT"
}

case "${1:-}" in
check)
    status=0
    for file in "$CA_CERT" "$CA_KEY" "$SERVER_CERT" "$SERVER_KEY"; do
        if [ ! -f "$file" ]; then
            echo "missing: $file" >&2
            status=1
        fi
    done
    for file in "$CA_CERT" "$SERVER_CERT"; do
        if [ -f "$file" ] && ! is_valid "$file"; then
            echo "expired or not valid: $file" >&2
            status=1
        fi
    done
    exit "$status"
    ;;
"")
    mkdir -p "$DIR"
    if ! ca_ok; then
        # A new CA makes the old server certificate useless.
        make_ca
        make_server
    elif ! server_ok; then
        make_server
    else
        echo "nothing to do: all files exist"
    fi
    ;;
*)
    echo "usage: $0 [check]" >&2
    exit 2
    ;;
esac
