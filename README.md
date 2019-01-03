# DTLS Examples for OpenSSL
The examples and tutorial require at least OpenSSL 1.1.0.

## SCTP/UDP Examples
**DTLS Echo Server and Client**  
This sample includes a multi-threaded echo server and client sending messages over an SCTP/UDP connection encrypted with DTLS.

**DTLS Character Generator Server and Client**  
This sample includes a multi-threaded character generator server and client sending as many messages as possible to each other over an SCTP/UDP connection encrypted with DTLS for a given time.
Statistics how many messages have been sent and received and how many got lost are printed at the end.

**DTLS Discard Server and Client**  
This sample includes a multi-threaded discard server and client sending messages over an SCTP/UDP connection encrypted with DTLS.

## OpenSSL with SCTP support
In order to run **SCTP** applications via DTLS, OpenSSL has to be built with SCTP support.

Grab the recent OpenSSL version, this example has been tested with OpenSSL 1.1.1a (2019/01).  
Configure OpenSSL to include SCTP support and (optionally) a custom install prefix.  
Build and install OpenSSL afterwards.
```
./config sctp --prefix=/home/weinrank/my-openssl/
make
make install
```

## OpenSSL without SCTP support
If you are not interested in the SCTP examples, you can run the UDP examples on many recent operating systems without additional packages.
FreeBSD 12 and Ubuntu 18.04 already have compatible OpenSSL Versions.

For macOS, the required libraries can be installed via brew.
```
brew install openssl@1.1
```

## Build the examples

## OpenSSL Certificates
The following commands create signed certificates for client and server of the samples above.
```
touch ca-db-index
echo 01 > ca-db-serial

# Certificate Authority
openssl req -nodes -x509 -newkey rsa:2048 -days 365 -keyout ca-key.pem -out ca-cert.pem

# Server Certificate
openssl req -nodes -new -newkey rsa:2048 -keyout server-key.pem -out server.csr

# Sign Server Certificate
openssl ca -config ca.conf -days 365 -in server.csr -out server-cert.pem

# Client Certificate
openssl req -nodes -new -newkey rsa:2048 -keyout client-key.pem -out client.csr

# Sign Client Certificate
openssl ca -config ca.conf -days 365 -in client.csr -out client-cert.pem
```

You can create your own [ca.conf](ca.conf) file or use a minimal sample.
