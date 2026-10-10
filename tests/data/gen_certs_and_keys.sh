# Create CA private key and certificate
openssl ecparam -name prime256v1 -genkey -noout -out ca-key.pem
openssl req -new -x509 -sha256 -key ca-key.pem -days 10000 -out ca-cert.pem

# Create private key, certificate signing request (CSR) and certificate for intermediate CA
openssl ecparam -name prime256v1 -genkey -noout -out im-key.pem
openssl req -new -sha256 -key im-key.pem -out im.csr
openssl x509 -req -in im.csr -CA ca-cert.pem -CAkey ca-key.pem -CAcreateserial -out im-cert.pem -days 10000 -sha256 -extfile <(printf 'basicConstraints = critical, CA:TRUE\n')

# Create private key, certificate signing request (CSR) and certificate for client
openssl ecparam -name prime256v1 -genkey -noout -out client-key.pem
openssl req -new -sha256 -key client-key.pem -out client.csr
openssl x509 -req -in client.csr -CA ca-cert.pem -CAkey ca-key.pem -CAcreateserial -out client-cert.pem -days 10000 -sha256

# Create private key, certificate signing request (CSR) and certificate for server
openssl ecparam -name prime256v1 -genkey -noout -out server-key.pem
openssl req -new -sha256 -key server-key.pem -out server.csr
openssl x509 -req -in server.csr -CA ca-cert.pem -CAkey ca-key.pem -CAcreateserial -out server-cert.pem -days 10000 -sha256 -extfile <(printf 'subjectAltName = DNS:localhost\n')

# Create private key, certificate signing request (CSR) and certificate from intermediate CA for server with hostname
openssl ecparam -name prime256v1 -genkey -noout -out im-server-key.pem
openssl req -new -sha256 -key im-server-key.pem -out im-server.csr -subj "/CN=None" -addext "subjectAltName = DNS:localhost, IP:127.0.0.1"
openssl x509 -req -in im-server.csr -CA im-cert.pem -CAkey im-key.pem -CAcreateserial -out im-server-cert.pem -days 10000 -sha256 -copy_extensions copy
cat im-server-cert.pem im-cert.pem > chain-cert.pem

# Create a second, unrelated root CA
openssl ecparam -name prime256v1 -genkey -noout -out other-root-key.pem
openssl req -new -x509 -sha256 -key other-root-key.pem -days 10000 -out other-root-cert.pem -subj "/CN=Other Root CA"

# Cross-sign CA
# (same public key as ca-cert.pem, but signed by "Other Root CA")
openssl req -new -key ca-key.pem -out ca-cross-signed.csr -subj "/CN=Test CA Cross-Signed"
openssl x509 -req -in ca-cross-signed.csr -CA other-root-cert.pem -CAkey other-root-key.pem -CAcreateserial -out ca-cross-signed-cert.pem -days 10000 -sha256
rm -f other-root-cert.srl

# Create Ed25519 CA private key and certificate
openssl genpkey -algorithm ed25519 -out ed-ca-key.pem
openssl req -new -x509 -key ed-ca-key.pem -days 10000 -out ed-ca-cert.pem -subj "/CN=Ed25519 Test CA"

# Create Ed25519 private key, certificate signing request (CSR) and certificate for server
openssl genpkey -algorithm ed25519 -out ed-server-key.pem
openssl req -new -key ed-server-key.pem -out ed-server.csr -subj "/CN=localhost"
openssl x509 -req -in ed-server.csr -CA ed-ca-cert.pem -CAkey ed-ca-key.pem -CAcreateserial -out ed-server-cert.pem -days 10000 -extfile <(printf 'subjectAltName = DNS:localhost\n')

# Create a P-384 CA, and certificates for server-key.pem that it signs with SHA-384 and with SHA-256
openssl ecparam -name secp384r1 -genkey -noout -out p384-ca-key.pem
openssl req -new -x509 -sha384 -key p384-ca-key.pem -days 10000 -out p384-ca-cert.pem -subj "/CN=P-384 Test CA"
openssl x509 -req -in server.csr -CA p384-ca-cert.pem -CAkey p384-ca-key.pem -CAcreateserial -out p384-server-cert.pem -days 10000 -sha384 -extfile <(printf 'subjectAltName = DNS:localhost\n')
openssl x509 -req -in server.csr -CA p384-ca-cert.pem -CAkey p384-ca-key.pem -CAcreateserial -out p384-sha256-server-cert.pem -days 10000 -sha256 -extfile <(printf 'subjectAltName = DNS:localhost\n')

# Create a P-384 server key, and a certificate for it from the P-384 CA
openssl ecparam -name secp384r1 -genkey -noout -out p384-key-server-key.pem
openssl req -new -sha384 -key p384-key-server-key.pem -out p384-key-server.csr -subj "/CN=localhost"
openssl x509 -req -in p384-key-server.csr -CA p384-ca-cert.pem -CAkey p384-ca-key.pem -CAcreateserial -out p384-key-server-cert.pem -days 10000 -sha384 -extfile <(printf 'subjectAltName = DNS:localhost\n')

# Create a certificate for server-key.pem that the P-256 CA signs with SHA-384
openssl x509 -req -in server.csr -CA ca-cert.pem -CAkey ca-key.pem -CAcreateserial -out sha384-server-cert.pem -days 10000 -sha384 -extfile <(printf 'subjectAltName = DNS:localhost\n')

# Create RSA CA private key and certificate
openssl req -x509 -newkey rsa:2048 -keyout rsa-ca-key.pem -nodes -out rsa-ca-cert.pem -sha256 -days 10000

# Create RSA private key, certificate signing request (CSR) and certificate for server
openssl req -newkey rsa:2048 -keyout rsa-server-key.pem -nodes -out rsa-server-cert.csr -sha256 -subj "/CN=localhost"
openssl x509 -req -CA rsa-ca-cert.pem -CAkey rsa-ca-key.pem -in rsa-server-cert.csr -out rsa-server-cert.pem -days 10000 -CAcreateserial -extfile <(printf 'subjectAltName = DNS:localhost\n')

# Create a 1024-bit RSA key and a certificate for it, which a verifier must refuse
openssl req -newkey rsa:1024 -keyout rsa1024-server-key.pem -nodes -out rsa1024-server-cert.csr -sha256 -subj "/CN=localhost"
openssl x509 -req -CA rsa-ca-cert.pem -CAkey rsa-ca-key.pem -in rsa1024-server-cert.csr -out rsa1024-server-cert.pem -days 10000 -CAcreateserial -extfile <(printf 'subjectAltName = DNS:localhost\n')

# Create RSA private key, certificate signing request (CSR) and certificate for client
openssl req -newkey rsa:2048 -keyout rsa-client-key.pem -nodes -out rsa-client-cert.csr -sha256
openssl x509 -req -CA rsa-ca-cert.pem -CAkey rsa-ca-key.pem -in rsa-client-cert.csr -out rsa-client-cert.pem -days 10000 -CAcreateserial
