#!/usr/bin/env bash
set -euo pipefail
cd "$(dirname "$0")/.."
tmp=$(mktemp -d); trap 'rm -rf "$tmp"' EXIT

cat > "$tmp/san.cnf" <<'EOF'
[req]
distinguished_name = dn
x509_extensions = v3
prompt = no
[dn]
CN = sgx-enclave
O = Scaphandre
C = US
[v3]
basicConstraints = CA:FALSE
subjectAltName = DNS:sgx-enclave,DNS:localhost,IP:127.0.0.1,IP:192.168.122.1
EOF

openssl req -x509 -newkey rsa:3072 -keyout "$tmp/enc.key" -out "$tmp/enc.crt" \
  -days 3650 -nodes -config "$tmp/san.cnf" -extensions v3 >/dev/null 2>&1
cp "$tmp/enc.crt" enclave_ca.pem
cp "$tmp/enc.crt" sgx/enclave_cert.pem;    cp "$tmp/enc.key" sgx/enclave_key.pem
cp "$tmp/enc.crt" sgx_vm/enclave_cert.pem; cp "$tmp/enc.key" sgx_vm/enclave_key.pem

openssl req -x509 -newkey rsa:3072 -keyout "$tmp/immu.key" -out immudb_ca.pem \
  -days 3650 -nodes -subj "/CN=immudb CA" >/dev/null 2>&1

echo "Generated placeholder certs: enclave_ca.pem, immudb_ca.pem, sgx{,_vm}/enclave_{cert,key}.pem"
echo "Replace with your own (matching your live ImmuDB) before a real deployment."
