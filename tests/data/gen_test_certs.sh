#!/usr/bin/env bash
# gen_test_certs.sh - Generate all test certificates non-interactively.
#
# Usage:  cd tests/data && bash gen_test_certs.sh
#
# Produces:
#   ca-cert.pem / ca-key.pem              - EC P-256 root CA
#   im-cert.pem / im-key.pem              - EC P-256 intermediate CA (signed by root)
#   im-server-cert.pem / im-server-key.pem - EC P-256 server leaf (signed by intermediate)
#                                            SAN: DNS:localhost, IP:127.0.0.1
#   chain-cert.pem                         - leaf + intermediate bundle
#   server-cert.pem / server-key.pem       - EC P-256 server (signed directly by root)
#   client-cert.pem / client-key.pem       - EC P-256 client (signed by root)
#   rsa-ca-cert.pem / rsa-ca-key.pem       - RSA 2048 CA (for negative tests)
#   rsa-server-cert.pem / rsa-server-key.pem - RSA server (signed by RSA CA)
#   rsa-client-cert.pem / rsa-client-key.pem - RSA client (signed by RSA CA)

set -euo pipefail

DIR="$(cd "$(dirname "$0")" && pwd)"
cd "$DIR"

DAYS=10000

# ---------- EC P-256 Root CA ----------
openssl ecparam -name prime256v1 -genkey -noout -out ca-key.pem
openssl req -new -x509 -sha256 -key ca-key.pem -days "$DAYS" -out ca-cert.pem \
    -subj "/CN=Test Root CA"

# ---------- EC P-256 Intermediate CA ----------
openssl ecparam -name prime256v1 -genkey -noout -out im-key.pem
openssl req -new -sha256 -key im-key.pem -out im.csr \
    -subj "/CN=Test Intermediate CA"
# The intermediate must have CA:TRUE so clients accept it as a valid issuer.
openssl x509 -req -in im.csr -CA ca-cert.pem -CAkey ca-key.pem \
    -CAcreateserial -out im-cert.pem -days "$DAYS" -sha256 \
    -extfile <(printf "basicConstraints=critical,CA:TRUE\nkeyUsage=critical,keyCertSign,cRLSign")

# ---------- EC P-256 Server (signed by intermediate, with SAN) ----------
openssl ecparam -name prime256v1 -genkey -noout -out im-server-key.pem
openssl req -new -sha256 -key im-server-key.pem -out im-server.csr \
    -subj "/CN=None" \
    -addext "subjectAltName = DNS:localhost, IP:127.0.0.1"
openssl x509 -req -in im-server.csr -CA im-cert.pem -CAkey im-key.pem \
    -CAcreateserial -out im-server-cert.pem -days "$DAYS" -sha256 \
    -copy_extensions copy
cat im-server-cert.pem im-cert.pem > chain-cert.pem

# ---------- EC P-256 Server (signed directly by root) ----------
openssl ecparam -name prime256v1 -genkey -noout -out server-key.pem
openssl req -new -sha256 -key server-key.pem -out server.csr \
    -subj "/CN=Test Server" \
    -addext "basicConstraints=critical,CA:FALSE"
openssl x509 -req -in server.csr -CA ca-cert.pem -CAkey ca-key.pem \
    -CAcreateserial -out server-cert.pem -days "$DAYS" -sha256 \
    -copy_extensions copy

# ---------- EC P-256 Client (signed by root) ----------
openssl ecparam -name prime256v1 -genkey -noout -out client-key.pem
openssl req -new -sha256 -key client-key.pem -out client.csr \
    -subj "/CN=Test Client" \
    -addext "basicConstraints=critical,CA:FALSE"
openssl x509 -req -in client.csr -CA ca-cert.pem -CAkey ca-key.pem \
    -CAcreateserial -out client-cert.pem -days "$DAYS" -sha256 \
    -copy_extensions copy

# ---------- RSA 2048 CA (for negative / cross-format tests) ----------
openssl req -x509 -newkey rsa:2048 -keyout rsa-ca-key.pem -nodes \
    -out rsa-ca-cert.pem -sha256 -days "$DAYS" \
    -subj "/CN=Test RSA CA"

# ---------- RSA Server ----------
openssl req -newkey rsa:2048 -keyout rsa-server-key.pem -nodes \
    -out rsa-server-cert.csr -sha256 \
    -subj "/CN=localhost" \
    -addext "basicConstraints=critical,CA:FALSE"
openssl x509 -req -CA rsa-ca-cert.pem -CAkey rsa-ca-key.pem \
    -in rsa-server-cert.csr -out rsa-server-cert.pem \
    -days "$DAYS" -CAcreateserial -copy_extensions copy

# ---------- RSA Client ----------
openssl req -newkey rsa:2048 -keyout rsa-client-key.pem -nodes \
    -out rsa-client-cert.csr -sha256 \
    -subj "/CN=Test RSA Client" \
    -addext "basicConstraints=critical,CA:FALSE"
openssl x509 -req -CA rsa-ca-cert.pem -CAkey rsa-ca-key.pem \
    -in rsa-client-cert.csr -out rsa-client-cert.pem \
    -days "$DAYS" -CAcreateserial -copy_extensions copy

# ---------- Cleanup CSR serial files ----------
rm -f *.srl

echo "All test certificates generated in $DIR"
