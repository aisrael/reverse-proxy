#!/usr/bin/env bash
#
# Make a CA, a server certificate and two client certificates for local TLS
# tests.
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
#   payment-agent.pem, payment-agent.key
#   reporting-agent.pem, reporting-agent.key
#                           Client certificates (EC P-256), signed by the CA.
#                           Each has a SPIFFE ID as its URI SAN:
#                           spiffe://acme/prod/payment-agent
#                           spiffe://acme/prod/reporting-agent

set -euo pipefail

DAYS=30
DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)/dev-certs"
CA_CERT="$DIR/ca.pem"
CA_KEY="$DIR/ca.key"
SERVER_CERT="$DIR/server.pem"
SERVER_KEY="$DIR/server.key"
# The client certificates: the file name, and the SPIFFE ID of the client.
CLIENT_NAMES=(payment-agent reporting-agent)
SPIFFE_PREFIX="spiffe://acme/prod"

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

# True if the client files are all present and the certificate is not expired.
client_ok() {
    [ -f "$DIR/$1.key" ] && is_valid "$DIR/$1.pem"
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

# Make the client certificate $1. Its SPIFFE ID is "$SPIFFE_PREFIX/$1".
make_client() {
    local name="$1" tmp
    tmp="$(mktemp -d)"
    # Remove the temporary files when the function ends or fails.
    trap 'rm -rf "$tmp"' RETURN
    openssl ecparam -name prime256v1 -genkey -noout -out "$DIR/$name.key"
    chmod 600 "$DIR/$name.key"
    openssl req -new -key "$DIR/$name.key" -subj "/CN=$name" -out "$tmp/client.csr"
    cat >"$tmp/client.ext" <<EXT
basicConstraints = critical, CA:FALSE
keyUsage = critical, digitalSignature
extendedKeyUsage = clientAuth
subjectAltName = URI:$SPIFFE_PREFIX/$name
EXT
    # Every certificate of the CA needs its own serial number.
    openssl x509 -req -in "$tmp/client.csr" -CA "$CA_CERT" -CAkey "$CA_KEY" \
        -set_serial "0x$(openssl rand -hex 8)" -sha256 -days "$DAYS" \
        -extfile "$tmp/client.ext" -out "$DIR/$name.pem"
    echo "made $DIR/$name.pem"
}

case "${1:-}" in
check)
    status=0
    files=("$CA_CERT" "$CA_KEY" "$SERVER_CERT" "$SERVER_KEY")
    certs=("$CA_CERT" "$SERVER_CERT")
    for name in "${CLIENT_NAMES[@]}"; do
        files+=("$DIR/$name.pem" "$DIR/$name.key")
        certs+=("$DIR/$name.pem")
    done
    for file in "${files[@]}"; do
        if [ ! -f "$file" ]; then
            echo "missing: $file" >&2
            status=1
        fi
    done
    for file in "${certs[@]}"; do
        if [ -f "$file" ] && ! is_valid "$file"; then
            echo "expired or not valid: $file" >&2
            status=1
        fi
    done
    exit "$status"
    ;;
"")
    mkdir -p "$DIR"
    made=false
    if ! ca_ok; then
        # A new CA makes the old certificates useless.
        make_ca
        make_server
        for name in "${CLIENT_NAMES[@]}"; do
            make_client "$name"
        done
        made=true
    else
        if ! server_ok; then
            make_server
            made=true
        fi
        for name in "${CLIENT_NAMES[@]}"; do
            if ! client_ok "$name"; then
                make_client "$name"
                made=true
            fi
        done
    fi
    if ! $made; then
        echo "nothing to do: all files exist"
    fi
    ;;
*)
    echo "usage: $0 [check]" >&2
    exit 2
    ;;
esac
