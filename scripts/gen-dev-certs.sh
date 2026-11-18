#!/usr/bin/env bash
#
# Make a CA, a server certificate and client certificates for local TLS tests.
#
# WARNING: Use these certificates for local development and tests only.
# The keys are not secret. Never trust these CAs outside your own machine.
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
#
# Files for tests that must fail. The proxy must reject these clients:
#   other-ca.pem, other-ca.key
#                           A second CA. The proxy does not trust it.
#   untrusted-agent.pem, untrusted-agent.key
#                           A client certificate that the second CA signed.
#   expired-agent.pem, expired-agent.key
#                           A client certificate that the CA signed. It expired
#                           in January 2020. The `check` command does not report it.
#   no-uri-agent.pem, no-uri-agent.key
#                           A client certificate that the CA signed. It has no
#                           URI SAN, so it has no SPIFFE ID. The TLS handshake
#                           works, but the proxy must answer 401.

set -euo pipefail

DAYS=30
DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)/dev-certs"
CA_CERT="$DIR/ca.pem"
CA_KEY="$DIR/ca.key"
SERVER_CERT="$DIR/server.pem"
SERVER_KEY="$DIR/server.key"
OTHER_CA_CERT="$DIR/other-ca.pem"
OTHER_CA_KEY="$DIR/other-ca.key"
# The client certificates that the CA signed. The SPIFFE ID of each one is
# "$SPIFFE_PREFIX/<name>".
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

# True if the files of the client $1 are all present and the certificate is
# not expired.
client_ok() {
    [ -f "$DIR/$1.key" ] && is_valid "$DIR/$1.pem"
}

# True if the second CA files are all present and the CA is not expired.
other_ca_ok() {
    [ -f "$OTHER_CA_KEY" ] && is_valid "$OTHER_CA_CERT"
}

# Make a self-signed CA. Arguments: the certificate file, the key file, the name.
make_ca() {
    local cert="$1" key="$2" name="$3" tmp
    tmp="$(mktemp -d)"
    # Remove the temporary files when the function ends or fails.
    trap 'rm -rf "${tmp:-}"' RETURN
    openssl ecparam -name prime256v1 -genkey -noout -out "$key"
    chmod 600 "$key"
    openssl req -new -key "$key" -subj "/CN=$name" -out "$tmp/ca.csr"
    # A TLS client accepts a CA only if the certificate says CA:TRUE.
    cat >"$tmp/ca.ext" <<EXT
basicConstraints = critical, CA:TRUE
keyUsage = critical, keyCertSign, cRLSign
EXT
    openssl x509 -req -in "$tmp/ca.csr" -signkey "$key" -sha256 -days "$DAYS" \
        -extfile "$tmp/ca.ext" -out "$cert"
    echo "made $cert"
}

make_server() {
    local tmp
    tmp="$(mktemp -d)"
    # Remove the temporary files when the function ends or fails.
    trap 'rm -rf "${tmp:-}"' RETURN
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
# Arguments: the name, the certificate file and the key file of the CA that
# signs it. Two more arguments (a start date and an end date, both as
# YYYYMMDDHHMMSSZ) set the validity. Without them, the certificate is valid for
# $DAYS days from now. A last argument sets the subject alternative name. The
# default is the SPIFFE ID.
make_client() {
    local name="$1" ca_cert="$2" ca_key="$3" start="${4:-}" end="${5:-}" tmp
    local san="${6:-URI:$SPIFFE_PREFIX/$name}"
    tmp="$(mktemp -d)"
    # Remove the temporary files when the function ends or fails.
    trap 'rm -rf "${tmp:-}"' RETURN
    openssl ecparam -name prime256v1 -genkey -noout -out "$DIR/$name.key"
    chmod 600 "$DIR/$name.key"
    openssl req -new -key "$DIR/$name.key" -subj "/CN=$name" -out "$tmp/client.csr"
    cat >"$tmp/client.ext" <<EXT
basicConstraints = critical, CA:FALSE
keyUsage = critical, digitalSignature
extendedKeyUsage = clientAuth
subjectAltName = $san
EXT
    if [ -n "$start" ]; then
        # `x509 -req` cannot set a start date, so use `ca` with a small config.
        : >"$tmp/index.txt"
        echo 01 >"$tmp/serial"
        cat >"$tmp/ca.cnf" <<CNF
[ca]
default_ca = dev
[dev]
database = $tmp/index.txt
new_certs_dir = $tmp
serial = $tmp/serial
default_md = sha256
policy = any
unique_subject = no
[any]
commonName = supplied
CNF
        openssl ca -batch -notext -config "$tmp/ca.cnf" -cert "$ca_cert" \
            -keyfile "$ca_key" -startdate "$start" -enddate "$end" \
            -extfile "$tmp/client.ext" -in "$tmp/client.csr" -out "$DIR/$name.pem"
    else
        # Every certificate of the CA needs its own serial number.
        openssl x509 -req -in "$tmp/client.csr" -CA "$ca_cert" -CAkey "$ca_key" \
            -set_serial "0x$(openssl rand -hex 8)" -sha256 -days "$DAYS" \
            -extfile "$tmp/client.ext" -out "$DIR/$name.pem"
    fi
    echo "made $DIR/$name.pem"
}

make_expired_client() {
    make_client expired-agent "$CA_CERT" "$CA_KEY" 20200101000000Z 20200102000000Z
}

# A certificate with a DNS SAN and no URI SAN.
make_no_uri_client() {
    make_client no-uri-agent "$CA_CERT" "$CA_KEY" "" "" "DNS:no-uri-agent"
}

make_untrusted_client() {
    make_client untrusted-agent "$OTHER_CA_CERT" "$OTHER_CA_KEY"
}

case "${1:-}" in
check)
    status=0
    files=("$CA_CERT" "$CA_KEY" "$SERVER_CERT" "$SERVER_KEY"
        "$OTHER_CA_CERT" "$OTHER_CA_KEY"
        "$DIR/untrusted-agent.pem" "$DIR/untrusted-agent.key"
        "$DIR/expired-agent.pem" "$DIR/expired-agent.key"
        "$DIR/no-uri-agent.pem" "$DIR/no-uri-agent.key")
    # `expired-agent.pem` is expired on purpose, so it is not in this list.
    certs=("$CA_CERT" "$SERVER_CERT" "$OTHER_CA_CERT" "$DIR/untrusted-agent.pem"
        "$DIR/no-uri-agent.pem")
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
        # A new CA makes the old certificates that it signed useless.
        make_ca "$CA_CERT" "$CA_KEY" "reverse-proxy dev CA"
        make_server
        for name in "${CLIENT_NAMES[@]}"; do
            make_client "$name" "$CA_CERT" "$CA_KEY"
        done
        make_expired_client
        make_no_uri_client
        made=true
    else
        if ! server_ok; then
            make_server
            made=true
        fi
        for name in "${CLIENT_NAMES[@]}"; do
            if ! client_ok "$name"; then
                make_client "$name" "$CA_CERT" "$CA_KEY"
                made=true
            fi
        done
        # This certificate is expired on purpose. Make it only if it is missing.
        if [ ! -f "$DIR/expired-agent.key" ] || [ ! -f "$DIR/expired-agent.pem" ]; then
            make_expired_client
            made=true
        fi
        if ! client_ok no-uri-agent; then
            make_no_uri_client
            made=true
        fi
    fi
    if ! other_ca_ok; then
        make_ca "$OTHER_CA_CERT" "$OTHER_CA_KEY" "reverse-proxy other dev CA"
        make_untrusted_client
        made=true
    elif ! client_ok untrusted-agent; then
        make_untrusted_client
        made=true
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
