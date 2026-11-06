#!/bin/sh
# Write a lab CA, server certificate, and client certificate under examples/certs.
# The client certificate is signed by client-ca.crt, which pharos-server trusts
# when auth.client_ca_file points at it. server.crt is what the client trusts
# via ca_file. These files are for a loopback lab, not production.
set -eu
cd "$(dirname "$0")"
mkdir -p certs
umask 077

openssl req -x509 -newkey rsa:2048 -nodes \
  -keyout certs/server.key -out certs/server.crt -days 825 \
  -subj /CN=localhost \
  -addext subjectAltName=DNS:localhost,IP:127.0.0.1 \
  -addext extendedKeyUsage=serverAuth \
  -addext keyUsage=digitalSignature,keyEncipherment

openssl req -x509 -newkey rsa:2048 -nodes \
  -keyout certs/client-ca.key -out certs/client-ca.crt -days 825 \
  -subj /CN=Pharos-Client-CA \
  -addext basicConstraints=critical,CA:TRUE \
  -addext keyUsage=critical,keyCertSign,cRLSign

openssl req -newkey rsa:2048 -nodes \
  -keyout certs/client.key -out certs/client.csr \
  -subj /CN=pharos-client

openssl x509 -req -in certs/client.csr \
  -CA certs/client-ca.crt -CAkey certs/client-ca.key -CAcreateserial \
  -out certs/client.crt -days 825 \
  -extfile /dev/stdin <<'EOF'
extendedKeyUsage=clientAuth
keyUsage=digitalSignature
subjectKeyIdentifier=hash
authorityKeyIdentifier=keyid,issuer
EOF

# A second client signed by a different CA. Use it to confirm the server rejects it.
openssl req -x509 -newkey rsa:2048 -nodes \
  -keyout certs/untrusted.key -out certs/untrusted.crt -days 30 \
  -subj /CN=not-pharos \
  -addext extendedKeyUsage=clientAuth \
  -addext keyUsage=digitalSignature

rm -f certs/client.csr certs/client-ca.srl
echo "wrote examples/certs/{server,client-ca,client,untrusted}.{crt,key}"
