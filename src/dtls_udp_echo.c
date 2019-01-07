/*
 * Copyright (C) 2009 - 2012 Robin Seggelmann, seggelmann@fh-muenster.de,
 *                           Michael Tuexen, tuexen@fh-muenster.de
 *
 * All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 * 1. Redistributions of source code must retain the above copyright
 *    notice, this list of conditions and the following disclaimer.
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in the
 *    documentation and/or other materials provided with the distribution.
 * 3. Neither the name of the project nor the names of its contributors
 *    may be used to endorse or promote products derived from this software
 *    without specific prior written permission.
 *
 * THIS SOFTWARE IS PROVIDED BY THE PROJECT AND CONTRIBUTORS ``AS IS'' AND
 * ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
 * ARE DISCLAIMED.  IN NO EVENT SHALL THE PROJECT OR CONTRIBUTORS BE LIABLE
 * FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
 * DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS
 * OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
 * HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT
 * LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY
 * OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF
 * SUCH DAMAGE.
 */

#ifdef WIN32
#include <winsock2.h>
#include <Ws2tcpip.h>
#define in_port_t u_short
#define ssize_t int
#else
#include <sys/types.h>
#include <sys/socket.h>
#include <sys/time.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <stdio.h>
#include <unistd.h>
#include <stdlib.h>
#include <string.h>
#include <pthread.h>
#endif

#include <openssl/ssl.h>
#include <openssl/bio.h>
#include <openssl/err.h>
#include <openssl/rand.h>


#define BUFFER_SIZE          (1<<16)
#define COOKIE_SECRET_LENGTH 16

int verbose = 0;
int veryverbose = 0;
unsigned char cookie_secret[COOKIE_SECRET_LENGTH];
int cookie_initialized=0;

char Usage[] =
"Usage: dtls_udp_echo [options] [address]\n"
"Options:\n"
"        -l      message length (Default: 100 Bytes)\n"
"        -L      local address\n"
"        -p      port (Default: 23232)\n"
"        -n      number of messages to send (Default: 5)\n"
"        -v      verbose\n"
"        -V      very verbose\n";

#if WIN32
static HANDLE* mutex_buf = NULL;
#else
static pthread_mutex_t* mutex_buf = NULL;
#endif

static void locking_function(int mode, int n, const char *file, int line) {
	if (mode & CRYPTO_LOCK)
#ifdef WIN32
		WaitForSingleObject(mutex_buf[n], INFINITE);
	else
		ReleaseMutex(mutex_buf[n]);
#else
		pthread_mutex_lock(&mutex_buf[n]);
	else
		pthread_mutex_unlock(&mutex_buf[n]);
#endif
}

static unsigned long id_function(void) {
#ifdef WIN32
	return (unsigned long) GetCurrentThreadId();
#else
	return (unsigned long) pthread_self();
#endif
}

int THREAD_setup() {
	int i;

#ifdef WIN32
	mutex_buf = (HANDLE*) malloc(CRYPTO_num_locks() * sizeof(HANDLE));
#else
	mutex_buf = (pthread_mutex_t*) malloc(CRYPTO_num_locks() * sizeof(pthread_mutex_t));
#endif
	if (!mutex_buf)
		return 0;
	for (i = 0; i < CRYPTO_num_locks(); i++)
#ifdef WIN32
		mutex_buf[i] = CreateMutex(NULL, FALSE, NULL);
#else
		pthread_mutex_init(&mutex_buf[i], NULL);
#endif
	CRYPTO_set_id_callback(id_function);
	CRYPTO_set_locking_callback(locking_function);
	return 1;
}

int THREAD_cleanup() {
	int i;

	if (!mutex_buf)
		return 0;

	CRYPTO_set_id_callback(NULL);
	CRYPTO_set_locking_callback(NULL);
	for (i = 0; i < CRYPTO_num_locks(); i++)
#ifdef WIN32
	CloseHandle(mutex_buf[i]);
#else
	pthread_mutex_destroy(&mutex_buf[i]);
#endif
	free(mutex_buf);
	mutex_buf = NULL;
	return 1;
}

int handle_socket_error() {
	switch (errno) {
		case EINTR:
			/* Interrupted system call.
			 * Just ignore.
			 */
			printf("Interrupted system call!\n");
			return 1;
		case EBADF:
			/* Invalid socket.
			 * Must close connection.
			 */
			printf("Invalid socket!\n");
			return 0;
			break;
#ifdef EHOSTDOWN
		case EHOSTDOWN:
			/* Host is down.
			 * Just ignore, might be an attacker
			 * sending fake ICMP messages.
			 */
			printf("Host is down!\n");
			return 1;
#endif
#ifdef ECONNRESET
		case ECONNRESET:
			/* Connection reset by peer.
			 * Just ignore, might be an attacker
			 * sending fake ICMP messages.
			 */
			printf("Connection reset by peer!\n");
			return 1;
#endif
		case ENOMEM:
			/* Out of memory.
			 * Must close connection.
			 */
			printf("Out of memory!\n");
			return 0;
			break;
		case EACCES:
			/* Permission denied.
			 * Just ignore, we might be blocked
			 * by some firewall policy. Try again
			 * and hope for the best.
			 */
			printf("Permission denied!\n");
			return 1;
			break;
		default:
			/* Something unexpected happened */
			printf("Unexpected error! (errno = %d)\n", errno);
			return 0;
			break;
	}
	return 0;
}

int generate_cookie(SSL *ssl, unsigned char *cookie, unsigned int *cookie_len)
	{
	unsigned char *buffer, result[EVP_MAX_MD_SIZE];
	unsigned int length = 0, resultlength;
	union {
		struct sockaddr_storage ss;
		struct sockaddr_in6 s6;
		struct sockaddr_in s4;
	} peer;

	/* Initialize a random secret */
	if (!cookie_initialized)
		{
		if (!RAND_bytes(cookie_secret, COOKIE_SECRET_LENGTH))
			{
			printf("error setting random cookie secret\n");
			return 0;
			}
		cookie_initialized = 1;
		}

	/* Read peer information */
	(void) BIO_dgram_get_peer(SSL_get_rbio(ssl), &peer);

	/* Create buffer with peer's address and port */
	length = 0;
	switch (peer.ss.ss_family) {
		case AF_INET:
			length += sizeof(struct in_addr);
			break;
		case AF_INET6:
			length += sizeof(struct in6_addr);
			break;
		default:
			OPENSSL_assert(0);
			break;
	}
	length += sizeof(in_port_t);
	buffer = (unsigned char*) OPENSSL_malloc(length);

	if (buffer == NULL)
		{
		printf("out of memory\n");
		return 0;
		}

	switch (peer.ss.ss_family) {
		case AF_INET:
			memcpy(buffer,
				   &peer.s4.sin_port,
				   sizeof(in_port_t));
			memcpy(buffer + sizeof(peer.s4.sin_port),
				   &peer.s4.sin_addr,
				   sizeof(struct in_addr));
			break;
		case AF_INET6:
			memcpy(buffer,
				   &peer.s6.sin6_port,
				   sizeof(in_port_t));
			memcpy(buffer + sizeof(in_port_t),
				   &peer.s6.sin6_addr,
				   sizeof(struct in6_addr));
			break;
		default:
			OPENSSL_assert(0);
			break;
	}

	/* Calculate HMAC of buffer using the secret */
	HMAC(EVP_sha1(), (const void*) cookie_secret, COOKIE_SECRET_LENGTH,
		 (const unsigned char*) buffer, length, result, &resultlength);
	OPENSSL_free(buffer);

	memcpy(cookie, result, resultlength);
	*cookie_len = resultlength;

	return 1;
}

int verify_cookie(SSL *ssl, const unsigned char *cookie, unsigned int cookie_len)
	{
	unsigned char *buffer, result[EVP_MAX_MD_SIZE];
	unsigned int length = 0, resultlength;
	union {
		struct sockaddr_storage ss;
		struct sockaddr_in6 s6;
		struct sockaddr_in s4;
	} peer;

	/* If secret isn't initialized yet, the cookie can't be valid */
	if (!cookie_initialized)
		return 0;

	/* Read peer information */
	(void) BIO_dgram_get_peer(SSL_get_rbio(ssl), &peer);

	/* Create buffer with peer's address and port */
	length = 0;
	switch (peer.ss.ss_family) {
		case AF_INET:
			length += sizeof(struct in_addr);
			break;
		case AF_INET6:
			length += sizeof(struct in6_addr);
			break;
		default:
			OPENSSL_assert(0);
			break;
	}
	length += sizeof(in_port_t);
	buffer = (unsigned char*) OPENSSL_malloc(length);

	if (buffer == NULL)
		{
		printf("out of memory\n");
		return 0;
		}

	switch (peer.ss.ss_family) {
		case AF_INET:
			memcpy(buffer,
				   &peer.s4.sin_port,
				   sizeof(in_port_t));
			memcpy(buffer + sizeof(in_port_t),
				   &peer.s4.sin_addr,
				   sizeof(struct in_addr));
			break;
		case AF_INET6:
			memcpy(buffer,
				   &peer.s6.sin6_port,
				   sizeof(in_port_t));
			memcpy(buffer + sizeof(in_port_t),
				   &peer.s6.sin6_addr,
				   sizeof(struct in6_addr));
			break;
		default:
			OPENSSL_assert(0);
			break;
	}

	/* Calculate HMAC of buffer using the secret */
	HMAC(EVP_sha1(), (const void*) cookie_secret, COOKIE_SECRET_LENGTH,
		 (const unsigned char*) buffer, length, result, &resultlength);
	OPENSSL_free(buffer);

	if (cookie_len == resultlength && memcmp(result, cookie, resultlength) == 0)
		return 1;

	return 0;
	}

struct pass_info {
	union {
		struct sockaddr_storage ss;
		struct sockaddr_in6 s6;
		struct sockaddr_in s4;
	} server_addr, client_addr;
	SSL *ssl;
};

int dtls_verify_callback (int ok, X509_STORE_CTX *ctx) {
	/* This function should ask the user
	 * if he trusts the received certificate.
	 * Here we always trust.
	 */
	return 1;
}

#ifdef WIN32
DWORD WINAPI connection_handle(LPVOID *info) {
#else
void* connection_handle(void *info) {
#endif
	ssize_t len;
	char buf[BUFFER_SIZE];
	char addrbuf[INET6_ADDRSTRLEN];
	struct pass_info *pinfo = (struct pass_info*) info;
	SSL *ssl = pinfo->ssl;
	int fd, reading = 0, ret;
	const int on = 1, off = 0;
	struct timeval timeout;
	int num_timeouts = 0, max_timeouts = 5;

#ifndef WIN32
	pthread_detach(pthread_self());
#endif

	OPENSSL_assert(pinfo->client_addr.ss.ss_family == pinfo->server_addr.ss.ss_family);
	fd = socket(pinfo->client_addr.ss.ss_family, SOCK_DGRAM, 0);
	if (fd < 0) {
		perror("socket");
		goto cleanup;
	}

#ifdef WIN32
	setsockopt(fd, SOL_SOCKET, SO_REUSEADDR, (const char*) &on, (socklen_t) sizeof(on));
#else
	setsockopt(fd, SOL_SOCKET, SO_REUSEADDR, (const void*) &on, (socklen_t) sizeof(on));
#ifdef SO_REUSEPORT
	setsockopt(fd, SOL_SOCKET, SO_REUSEPORT, (const void*) &on, (socklen_t) sizeof(on));
#endif
#endif
	switch (pinfo->client_addr.ss.ss_family) {
		case AF_INET:
			bind(fd, (const struct sockaddr *) &pinfo->server_addr, sizeof(struct sockaddr_in));
			connect(fd, (struct sockaddr *) &pinfo->client_addr, sizeof(struct sockaddr_in));
			break;
		case AF_INET6:
			setsockopt(fd, IPPROTO_IPV6, IPV6_V6ONLY, (char *)&off, sizeof(off));
			bind(fd, (const struct sockaddr *) &pinfo->server_addr, sizeof(struct sockaddr_in6));
			connect(fd, (struct sockaddr *) &pinfo->client_addr, sizeof(struct sockaddr_in6));
			break;
		default:
			OPENSSL_assert(0);
			break;
	}

	/* Set new fd and set BIO to connected */
	BIO_set_fd(SSL_get_rbio(ssl), fd, BIO_NOCLOSE);
	BIO_ctrl(SSL_get_rbio(ssl), BIO_CTRL_DGRAM_SET_CONNECTED, 0, &pinfo->client_addr.ss);

	/* Finish handshake */
	do { ret = SSL_accept(ssl); }
	while (ret == 0);
	if (ret < 0) {
		perror("SSL_accept");
		printf("%s\n", ERR_error_string(ERR_get_error(), buf));
		goto cleanup;
	}

	/* Set and activate timeouts */
	timeout.tv_sec = 5;
	timeout.tv_usec = 0;
	BIO_ctrl(SSL_get_rbio(ssl), BIO_CTRL_DGRAM_SET_RECV_TIMEOUT, 0, &timeout);

	if (verbose) {
		if (pinfo->client_addr.ss.ss_family == AF_INET) {
			printf ("\nThread %lx: accepted connection from %s:%d\n",
					id_function(),
					inet_ntop(AF_INET, &pinfo->client_addr.s4.sin_addr, addrbuf, INET6_ADDRSTRLEN),
					ntohs(pinfo->client_addr.s4.sin_port));
		} else {
			printf ("\nThread %lx: accepted connection from %s:%d\n",
					id_function(),
					inet_ntop(AF_INET6, &pinfo->client_addr.s6.sin6_addr, addrbuf, INET6_ADDRSTRLEN),
					ntohs(pinfo->client_addr.s6.sin6_port));
		}
	}

	if (veryverbose && SSL_get_peer_certificate(ssl)) {
		printf ("------------------------------------------------------------\n");
		X509_NAME_print_ex_fp(stdout, X509_get_subject_name(SSL_get_peer_certificate(ssl)),
							  1, XN_FLAG_MULTILINE);
		printf("\n\n Cipher: %s", SSL_CIPHER_get_name(SSL_get_current_cipher(ssl)));
		printf ("\n------------------------------------------------------------\n\n");
	}

	while (!(SSL_get_shutdown(ssl) & SSL_RECEIVED_SHUTDOWN) && num_timeouts < max_timeouts) {

		reading = 1;
		while (reading) {
			len = SSL_read(ssl, buf, sizeof(buf));

			switch (SSL_get_error(ssl, len)) {
				case SSL_ERROR_NONE:
					if (verbose) {
						printf("Thread %lx: read %d bytes\n", id_function(), (int) len);
					}
					reading = 0;
					break;
				case SSL_ERROR_WANT_READ:
					/* Handle socket timeouts */
					if (BIO_ctrl(SSL_get_rbio(ssl), BIO_CTRL_DGRAM_GET_RECV_TIMER_EXP, 0, NULL)) {
						num_timeouts++;
						reading = 0;
					}
					/* Just try again */
					break;
				case SSL_ERROR_ZERO_RETURN:
					reading = 0;
					break;
				case SSL_ERROR_SYSCALL:
					printf("Socket read error: ");
					if (!handle_socket_error()) goto cleanup;
					reading = 0;
					break;
				case SSL_ERROR_SSL:
					printf("SSL read error: ");
					printf("%s (%d)\n", ERR_error_string(ERR_get_error(), buf), SSL_get_error(ssl, len));
					goto cleanup;
					break;
				default:
					printf("Unexpected error while reading!\n");
					goto cleanup;
					break;
			}
		}

		if (len > 0) {
			len = SSL_write(ssl, buf, len);

			switch (SSL_get_error(ssl, len)) {
				case SSL_ERROR_NONE:
					if (verbose) {
						printf("Thread %lx: wrote %d bytes\n", id_function(), (int) len);
					}
					break;
				case SSL_ERROR_WANT_WRITE:
					/* Can't write because of a renegotiation, so
					 * we actually have to retry sending this message...
					 */
					break;
				case SSL_ERROR_WANT_READ:
					/* continue with reading */
					break;
				case SSL_ERROR_SYSCALL:
					printf("Socket write error: ");
					if (!handle_socket_error()) goto cleanup;
					//reading = 0;
					break;
				case SSL_ERROR_SSL:
					printf("SSL write error: ");
					printf("%s (%d)\n", ERR_error_string(ERR_get_error(), buf), SSL_get_error(ssl, len));
					goto cleanup;
					break;
				default:
					printf("Unexpected error while writing!\n");
					goto cleanup;
					break;
			}
		}
	}

	SSL_shutdown(ssl);

cleanup:
#ifdef WIN32
	closesocket(fd);
#else
	close(fd);
#endif
	free(info);
	SSL_free(ssl);
	if (verbose)
		printf("Thread %lx: done, connection closed.\n", id_function());
#if WIN32
	ExitThread(0);
#else
	pthread_exit( (void *) NULL );
#endif
}


void start_server(int port, char *local_address) {
	int fd;
	union {
		struct sockaddr_storage ss;
		struct sockaddr_in s4;
		struct sockaddr_in6 s6;
	} server_addr, client_addr;
#if WIN32
	WSADATA wsaData;
	DWORD tid;
#else
	pthread_t tid;
#endif
	SSL_CTX *ctx;
	SSL *ssl;
	BIO *bio;
	struct timeval timeout;
	struct pass_info *info;
	const int on = 1, off = 0;

	memset(&server_addr, 0, sizeof(struct sockaddr_storage));
	if (strlen(local_address) == 0) {
		server_addr.s6.sin6_family = AF_INET6;
#ifdef HAVE_SIN6_LEN
		server_addr.s6.sin6_len = sizeof(struct sockaddr_in6);
#endif
		server_addr.s6.sin6_addr = in6addr_any;
		server_addr.s6.sin6_port = htons(port);
	} else {
		if (inet_pton(AF_INET, local_address, &server_addr.s4.sin_addr) == 1) {
			server_addr.s4.sin_family = AF_INET;
#ifdef HAVE_SIN_LEN
			server_addr.s4.sin_len = sizeof(struct sockaddr_in);
#endif
			server_addr.s4.sin_port = htons(port);
		} else if (inet_pton(AF_INET6, local_address, &server_addr.s6.sin6_addr) == 1) {
			server_addr.s6.sin6_family = AF_INET6;
#ifdef HAVE_SIN6_LEN
			server_addr.s6.sin6_len = sizeof(struct sockaddr_in6);
#endif
			server_addr.s6.sin6_port = htons(port);
		} else {
			return;
		}
	}

	THREAD_setup();
	OpenSSL_add_ssl_algorithms();
	SSL_load_error_strings();
	ctx = SSL_CTX_new(DTLS_server_method());
	/* We accept all ciphers, including NULL.
	 * Not recommended beyond testing and debugging
	 */
	//SSL_CTX_set_cipher_list(ctx, "ALL:NULL:eNULL:aNULL");
	SSL_CTX_set_session_cache_mode(ctx, SSL_SESS_CACHE_OFF);

	if (!SSL_CTX_use_certificate_file(ctx, "certs/server-cert.pem", SSL_FILETYPE_PEM))
		printf("\nERROR: no certificate found!");

	if (!SSL_CTX_use_PrivateKey_file(ctx, "certs/server-key.pem", SSL_FILETYPE_PEM))
		printf("\nERROR: no private key found!");

	if (!SSL_CTX_check_private_key (ctx))
		printf("\nERROR: invalid private key!");

	/* Client has to authenticate */
	SSL_CTX_set_verify(ctx, SSL_VERIFY_PEER | SSL_VERIFY_CLIENT_ONCE, dtls_verify_callback);

	SSL_CTX_set_read_ahead(ctx, 1);
	SSL_CTX_set_cookie_generate_cb(ctx, generate_cookie);
	SSL_CTX_set_cookie_verify_cb(ctx, &verify_cookie);

#ifdef WIN32
	WSAStartup(MAKEWORD(2, 2), &wsaData);
#endif

	fd = socket(server_addr.ss.ss_family, SOCK_DGRAM, 0);
	if (fd < 0) {
		perror("socket");
		exit(-1);
	}

#ifdef WIN32
	setsockopt(fd, SOL_SOCKET, SO_REUSEADDR, (const char*) &on, (socklen_t) sizeof(on));
#else
	setsockopt(fd, SOL_SOCKET, SO_REUSEADDR, (const void*) &on, (socklen_t) sizeof(on));
#ifdef SO_REUSEPORT
	setsockopt(fd, SOL_SOCKET, SO_REUSEPORT, (const void*) &on, (socklen_t) sizeof(on));
#endif
#endif

	if (server_addr.ss.ss_family == AF_INET) {
		bind(fd, (const struct sockaddr *) &server_addr, sizeof(struct sockaddr_in));
	} else {
		setsockopt(fd, IPPROTO_IPV6, IPV6_V6ONLY, (char *)&off, sizeof(off));
		bind(fd, (const struct sockaddr *) &server_addr, sizeof(struct sockaddr_in6));
	}
	while (1) {
		memset(&client_addr, 0, sizeof(struct sockaddr_storage));

		/* Create BIO */
		bio = BIO_new_dgram(fd, BIO_NOCLOSE);

		/* Set and activate timeouts */
		timeout.tv_sec = 5;
		timeout.tv_usec = 0;
		BIO_ctrl(bio, BIO_CTRL_DGRAM_SET_RECV_TIMEOUT, 0, &timeout);

		ssl = SSL_new(ctx);

		SSL_set_bio(ssl, bio, bio);
		SSL_set_options(ssl, SSL_OP_COOKIE_EXCHANGE);

		while (DTLSv1_listen(ssl, (BIO_ADDR *) &client_addr) <= 0);

		info = (struct pass_info*) malloc (sizeof(struct pass_info));
		memcpy(&info->server_addr, &server_addr, sizeof(struct sockaddr_storage));
		memcpy(&info->client_addr, &client_addr, sizeof(struct sockaddr_storage));
		info->ssl = ssl;

#ifdef WIN32
		if (CreateThread(NULL, 0, (LPTHREAD_START_ROUTINE) connection_handle, info, 0, &tid) == NULL) {
			exit(-1);
		}
#else
		if (pthread_create( &tid, NULL, connection_handle, info) != 0) {
			perror("pthread_create");
			exit(-1);
		}
#endif
	}

	THREAD_cleanup();
#ifdef WIN32
	WSACleanup();
#endif
}

void start_client(char *remote_address, char *local_address, int port, int length, int messagenumber) {
	int fd, retval;
	union {
		struct sockaddr_storage ss;
		struct sockaddr_in s4;
		struct sockaddr_in6 s6;
	} remote_addr, local_addr;
	char buf[BUFFER_SIZE];
	char addrbuf[INET6_ADDRSTRLEN];
	socklen_t len;
	SSL_CTX *ctx;
	SSL *ssl;
	BIO *bio;
	int reading = 0;
	struct timeval timeout;
#if WIN32
	WSADATA wsaData;
#endif

	memset((void *) &remote_addr, 0, sizeof(struct sockaddr_storage));
	memset((void *) &local_addr, 0, sizeof(struct sockaddr_storage));

	if (inet_pton(AF_INET, remote_address, &remote_addr.s4.sin_addr) == 1) {
		remote_addr.s4.sin_family = AF_INET;
#ifdef HAVE_SIN_LEN
		remote_addr.s4.sin_len = sizeof(struct sockaddr_in);
#endif
		remote_addr.s4.sin_port = htons(port);
	} else if (inet_pton(AF_INET6, remote_address, &remote_addr.s6.sin6_addr) == 1) {
		remote_addr.s6.sin6_family = AF_INET6;
#ifdef HAVE_SIN6_LEN
		remote_addr.s6.sin6_len = sizeof(struct sockaddr_in6);
#endif
		remote_addr.s6.sin6_port = htons(port);
	} else {
		return;
	}

#ifdef WIN32
	WSAStartup(MAKEWORD(2, 2), &wsaData);
#endif

	fd = socket(remote_addr.ss.ss_family, SOCK_DGRAM, 0);
	if (fd < 0) {
		perror("socket");
		exit(-1);
	}

	if (strlen(local_address) > 0) {
		if (inet_pton(AF_INET, local_address, &local_addr.s4.sin_addr) == 1) {
			local_addr.s4.sin_family = AF_INET;
#ifdef HAVE_SIN_LEN
			local_addr.s4.sin_len = sizeof(struct sockaddr_in);
#endif
			local_addr.s4.sin_port = htons(0);
		} else if (inet_pton(AF_INET6, local_address, &local_addr.s6.sin6_addr) == 1) {
			local_addr.s6.sin6_family = AF_INET6;
#ifdef HAVE_SIN6_LEN
			local_addr.s6.sin6_len = sizeof(struct sockaddr_in6);
#endif
			local_addr.s6.sin6_port = htons(0);
		} else {
			return;
		}
		OPENSSL_assert(remote_addr.ss.ss_family == local_addr.ss.ss_family);
		if (local_addr.ss.ss_family == AF_INET) {
			bind(fd, (const struct sockaddr *) &local_addr, sizeof(struct sockaddr_in));
		} else {
			bind(fd, (const struct sockaddr *) &local_addr, sizeof(struct sockaddr_in6));
		}
	}

	OpenSSL_add_ssl_algorithms();
	SSL_load_error_strings();
	ctx = SSL_CTX_new(DTLS_client_method());
	//SSL_CTX_set_cipher_list(ctx, "eNULL:!MD5");

	if (!SSL_CTX_use_certificate_file(ctx, "certs/client-cert.pem", SSL_FILETYPE_PEM))
		printf("\nERROR: no certificate found!");

	if (!SSL_CTX_use_PrivateKey_file(ctx, "certs/client-key.pem", SSL_FILETYPE_PEM))
		printf("\nERROR: no private key found!");

	if (!SSL_CTX_check_private_key (ctx))
		printf("\nERROR: invalid private key!");

	SSL_CTX_set_verify_depth (ctx, 2);
	SSL_CTX_set_read_ahead(ctx, 1);

	ssl = SSL_new(ctx);

	/* Create BIO, connect and set to already connected */
	bio = BIO_new_dgram(fd, BIO_CLOSE);
	if (remote_addr.ss.ss_family == AF_INET) {
		connect(fd, (struct sockaddr *) &remote_addr, sizeof(struct sockaddr_in));
	} else {
		connect(fd, (struct sockaddr *) &remote_addr, sizeof(struct sockaddr_in6));
	}
	BIO_ctrl(bio, BIO_CTRL_DGRAM_SET_CONNECTED, 0, &remote_addr.ss);

	SSL_set_bio(ssl, bio, bio);

	retval = SSL_connect(ssl);
	if (retval <= 0) {
		switch (SSL_get_error(ssl, retval)) {
			case SSL_ERROR_ZERO_RETURN:
				fprintf(stderr, "SSL_connect failed with SSL_ERROR_ZERO_RETURN\n");
				break;
			case SSL_ERROR_WANT_READ:
				fprintf(stderr, "SSL_connect failed with SSL_ERROR_WANT_READ\n");
				break;
			case SSL_ERROR_WANT_WRITE:
				fprintf(stderr, "SSL_connect failed with SSL_ERROR_WANT_WRITE\n");
				break;
			case SSL_ERROR_WANT_CONNECT:
				fprintf(stderr, "SSL_connect failed with SSL_ERROR_WANT_CONNECT\n");
				break;
			case SSL_ERROR_WANT_ACCEPT:
				fprintf(stderr, "SSL_connect failed with SSL_ERROR_WANT_ACCEPT\n");
				break;
			case SSL_ERROR_WANT_X509_LOOKUP:
				fprintf(stderr, "SSL_connect failed with SSL_ERROR_WANT_X509_LOOKUP\n");
				break;
			case SSL_ERROR_SYSCALL:
				fprintf(stderr, "SSL_connect failed with SSL_ERROR_SYSCALL\n");
				break;
			case SSL_ERROR_SSL:
				fprintf(stderr, "SSL_connect failed with SSL_ERROR_SSL\n");
				break;
			default:
				fprintf(stderr, "SSL_connect failed with unknown error\n");
				break;
		}
		exit(EXIT_FAILURE);
	}

	/* Set and activate timeouts */
	timeout.tv_sec = 3;
	timeout.tv_usec = 0;
	BIO_ctrl(bio, BIO_CTRL_DGRAM_SET_RECV_TIMEOUT, 0, &timeout);

	if (verbose) {
		if (remote_addr.ss.ss_family == AF_INET) {
			printf ("\nConnected to %s\n",
					 inet_ntop(AF_INET, &remote_addr.s4.sin_addr, addrbuf, INET6_ADDRSTRLEN));
		} else {
			printf ("\nConnected to %s\n",
					 inet_ntop(AF_INET6, &remote_addr.s6.sin6_addr, addrbuf, INET6_ADDRSTRLEN));
		}
	}

	if (veryverbose && SSL_get_peer_certificate(ssl)) {
		printf ("------------------------------------------------------------\n");
		X509_NAME_print_ex_fp(stdout, X509_get_subject_name(SSL_get_peer_certificate(ssl)),
							  1, XN_FLAG_MULTILINE);
		printf("\n\n Cipher: %s", SSL_CIPHER_get_name(SSL_get_current_cipher(ssl)));
		printf ("\n------------------------------------------------------------\n\n");
	}

	while (!(SSL_get_shutdown(ssl) & SSL_RECEIVED_SHUTDOWN)) {

		if (messagenumber > 0) {
			len = SSL_write(ssl, buf, length);

			switch (SSL_get_error(ssl, len)) {
				case SSL_ERROR_NONE:
					if (verbose) {
						printf("wrote %d bytes\n", (int) len);
					}
					messagenumber--;
					break;
				case SSL_ERROR_WANT_WRITE:
					/* Just try again later */
					break;
				case SSL_ERROR_WANT_READ:
					/* continue with reading */
					break;
				case SSL_ERROR_SYSCALL:
					printf("Socket write error: ");
					if (!handle_socket_error()) exit(1);
					//reading = 0;
					break;
				case SSL_ERROR_SSL:
					printf("SSL write error: ");
					printf("%s (%d)\n", ERR_error_string(ERR_get_error(), buf), SSL_get_error(ssl, len));
					exit(1);
					break;
				default:
					printf("Unexpected error while writing!\n");
					exit(1);
					break;
			}

#if 0
			/* Send heartbeat. Requires Heartbeat extension. */
			if (messagenumber == 2)
				SSL_heartbeat(ssl);
#endif

			/* Shut down if all messages sent */
			if (messagenumber == 0)
				SSL_shutdown(ssl);
		}

		reading = 1;
		while (reading) {
			len = SSL_read(ssl, buf, sizeof(buf));

			switch (SSL_get_error(ssl, len)) {
				case SSL_ERROR_NONE:
					if (verbose) {
						printf("read %d bytes\n", (int) len);
					}
					reading = 0;
					break;
				case SSL_ERROR_WANT_READ:
					/* Stop reading on socket timeout, otherwise try again */
					if (BIO_ctrl(SSL_get_rbio(ssl), BIO_CTRL_DGRAM_GET_RECV_TIMER_EXP, 0, NULL)) {
						printf("Timeout! No response received.\n");
						reading = 0;
					}
					break;
				case SSL_ERROR_ZERO_RETURN:
					reading = 0;
					break;
				case SSL_ERROR_SYSCALL:
					printf("Socket read error: ");
					if (!handle_socket_error()) exit(1);
					reading = 0;
					break;
				case SSL_ERROR_SSL:
					printf("SSL read error: ");
					printf("%s (%d)\n", ERR_error_string(ERR_get_error(), buf), SSL_get_error(ssl, len));
					exit(1);
					break;
				default:
					printf("Unexpected error while reading!\n");
					exit(1);
					break;
			}
		}
	}

#ifdef WIN32
	closesocket(fd);
#else
	close(fd);
#endif
	if (verbose)
		printf("Connection closed.\n");

#ifdef WIN32
	WSACleanup();
#endif
}

int main(int argc, char **argv)
{
	int port = 23232;
	int length = 100;
	int messagenumber = 5;
	char local_addr[INET6_ADDRSTRLEN+1];

	memset(local_addr, 0, INET6_ADDRSTRLEN+1);

	argc--;
	argv++;

	while (argc >= 1) {
		if	(strcmp(*argv, "-l") == 0) {
			if (--argc < 1) goto cmd_err;
			length = atoi(*++argv);
			if (length > BUFFER_SIZE)
				length = BUFFER_SIZE;
		}
		else if	(strcmp(*argv, "-L") == 0) {
			if (--argc < 1) goto cmd_err;
			strncpy(local_addr, *++argv, INET6_ADDRSTRLEN);
		}
		else if	(strcmp(*argv, "-n") == 0) {
			if (--argc < 1) goto cmd_err;
			messagenumber = atoi(*++argv);
		}
		else if	(strcmp(*argv, "-p") == 0) {
			if (--argc < 1) goto cmd_err;
			port = atoi(*++argv);
		}
		else if	(strcmp(*argv, "-v") == 0) {
			verbose = 1;
		}
		else if	(strcmp(*argv, "-V") == 0) {
			verbose = 1;
			veryverbose = 1;
		}
		else if	(((*argv)[0]) == '-') {
			goto cmd_err;
		}
		else break;

		argc--;
		argv++;
	}

	if (argc > 1) goto cmd_err;

	if (argc == 1)
		start_client(*argv, local_addr, port, length, messagenumber);
	else
		start_server(port, local_addr);

	return 0;

cmd_err:
	fprintf(stderr, "%s\n", Usage);
	return 1;
}
