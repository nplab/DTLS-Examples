#!/bin/bash
OPENSSL_BIN="/usr/local/opt/openssl@1.1/bin/openssl"

touch ca-db-index
echo 01 > ca-db-serial

# Certificate Authority
$OPENSSL_BIN req -nodes -x509 -newkey rsa:4096 -days 365 -keyout ca-key.pem -out ca-cert.pem

# Server Certificate
$OPENSSL_BIN req -nodes -new -newkey rsa:4096 -keyout server-key.pem -out server.csr

# Sign Server Certificate
$OPENSSL_BIN ca -config ca.conf -days 365 -in server.csr -out server-cert.pem

# Client Certificate
$OPENSSL_BIN req -nodes -new -newkey rsa:4096 -keyout client-key.pem -out client.csr

# Sign Client Certificate
$OPENSSL_BIN ca -config ca.conf -days 365 -in client.csr -out client-cert.pem
