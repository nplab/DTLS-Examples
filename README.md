# DTLS Examples for OpenSSL

## UDP Examples
**DTLS Echo Server and Client**  
This sample includes a multi-threaded echo server and client sending messages over an UDP connection encrypted with DTLS.

**DTLS Character Generator Server and Client**  
This sample includes a multi-threaded character generator server and client sending as many messages as possible to each other over an UDP connection encrypted with DTLS for a given time. Statistics how many messages have been sent and received and how many got lost are printed at the end.

**DTLS Discard Server and Client**  
This sample includes a multi-threaded discard server and client sending messages over an UDP connection encrypted with DTLS.

## SCTP Examples
**DTLS Echo Server and Client**  
This sample includes a multi-threaded echo server and client sending messages over an SCTP connection encrypted with DTLS.

**DTLS Character Generator Server and Client**  
This sample includes a multi-threaded character generator server and client sending as many messages as possible to each other over an SCTP connection encrypted with DTLS for a given time. Statistics how many messages have been sent and received are printed at the end.

**DTLS Discard Server and Client**  
This sample includes a multi-threaded discard server and client sending messages over an SCTP connection encrypted with DTLS.

## OpenSSL Certificates
The following commands create signed certificates for client and server of the samples above.
```
touch ca-db-index
echo 01 > ca-db-serial

# Certificate Authority
openssl req -nodes -x509 -newkey rsa:512 -days 365 -keyout ca-key.pem -out ca-cert.pem

# Server Certificate
openssl req -nodes -new -newkey rsa:512 -keyout server-key.pem -out server.csr

# Sign Server Certificate
openssl ca -config ca.conf -days 365 -in server.csr -out server-cert.pem

# Client Certificate
openssl req -nodes -new -newkey rsa:512 -keyout client-key.pem -out client.csr

# Sign Client Certificate
openssl ca -config ca.conf -days 365 -in client.csr -out client-cert.pem
```

You can create your own [ca.conf](ca.conf) file or use a minimal sample.
