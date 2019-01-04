# DTLS Examples for OpenSSL
The examples and tutorial are tested with OpenSSL 1.1.1.

## SCTP/UDP Examples
**DTLS Echo Server and Client**  
This sample includes a multi-threaded echo server and client sending messages over an SCTP/UDP connection encrypted with DTLS.

**DTLS Character Generator Server and Client**  
This sample includes a multi-threaded character generator server and client sending as many messages as possible to each other over an SCTP/UDP connection encrypted with DTLS for a given time.
Statistics how many messages have been sent and received and how many got lost are printed at the end.

**DTLS Discard Server and Client**  
This sample includes a multi-threaded discard server and client sending messages over an SCTP/UDP connection encrypted with DTLS.

## OS Requirements
### FreeBSD
Since FreeBSD 12.0, the built-in OpenSSL version is sufficient to run the SCTP and UDP examples.

### Ubuntu
In order to run the example applications via DTLS, OpenSSL has to be built with SCTP support.

Download the recent OpenSSL version.
This example has been tested with OpenSSL 1.1.1a and Ubuntu 18.10.
Configure OpenSSL to include SCTP support and (optionally) set a custom install prefix.  
Build and install OpenSSL afterwards.

```
$ ./config sctp --prefix=/home/weinrank/my-openssl/
$ make
$ make install
```

In addition to a loaded SCTP module, Linux requires the SCTP AUTH support to be enabled.
```
$ modprobe sctp
$ sysctl -w net.sctp.auth_enable=1
```

### macOS
If you only want to run the UDP examples, prebuilt OpenSSL binaries can be installed via brew.
```
$ brew install openssl@1.1
```

A SCTP enabled OpenSSL version has to be compiled from source, follow the tutorial in the ubuntu section.
Since macOS does not support SCTP out of the box, it is necessary to use the SCTP NKE.

## Build the examples
Before calling `make` in the `src` directory, it may be necessary to specify custom *library* and *include* paths.
This is either done by modifying the *Makefile* or by command line.
It is also possible to only build SCTP or UDP examples instead of both.

```
$ make
$ make sctp  # only SCTP examples
$ make udp  # only UDP examples
```

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
