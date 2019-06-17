/*
 * Copyright (C) 2009 - 2012 Robin Seggelmann, seggelmann@fh-muenster.de,
 *                           Michael Tuexen, tuexen@fh-muenster.de
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

#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <stdio.h>
#include <unistd.h>
#include <stdlib.h>
#include <string.h>
#include <pthread.h>
#include <math.h>
#include <time.h>
#include <sys/time.h>

#ifdef __linux__
#include <getopt.h>
#endif

#include <netinet/sctp.h>
#if !defined(SCTP_FUTURE_ASSOC) && defined(SCTP_EVENT)
#define SCTP_FUTURE_ASSOC 0
//      SCTP_CURRENT_ASSOC 1
//      SCTP_ALL_ASSOC 2
#endif
#include <signal.h>

#include <openssl/ssl.h>
#include <openssl/bio.h>
#include <openssl/err.h>


#define BUFFER_SIZE (1<<16)
#define MAX_STREAMS (256)

int verbose = 0;
int veryverbose = 0;
int unordered = 0;
int streams = 5;
int length = 100;
int done = 0;

char Usage[] =
"Usage: dtls_sctp_discard [options] [address]\n"
"Options:\n"
"        -l      message length (Default: 100 Bytes)\n"
"        -L      local address\n"
"        -s      streams (Default: 5)\n"
"        -p      port (Default: 23232)\n"
"        -t      time to send (Default: 10 sec)\n"
"        -u      unordered\n"
"        -v      verbose\n"
"        -V      very verbose\n";

static pthread_mutex_t* mutex_buf = NULL;

static void locking_function(int mode, int n, const char *file, int line) {
	if (mode & CRYPTO_LOCK)
		pthread_mutex_lock(&mutex_buf[n]);
	else
		pthread_mutex_unlock(&mutex_buf[n]);
}

static unsigned long id_function() {
	return (unsigned long) pthread_self();
}

int THREAD_setup() {
	int i;

	mutex_buf = (pthread_mutex_t*) malloc(CRYPTO_num_locks() * sizeof(pthread_mutex_t));
	if (!mutex_buf)
		return 0;
	for (i = 0; i < CRYPTO_num_locks(); i++)
		pthread_mutex_init(&mutex_buf[i], NULL);
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
		pthread_mutex_destroy(&mutex_buf[i]);
	free(mutex_buf);
	mutex_buf = NULL;
	return 1;
}

void stop_sender(int sig) {
	done = 1;
}

struct pass_info {
	int fd;
	char address[INET6_ADDRSTRLEN+1];
	unsigned short port;
	SSL_CTX *ctx;
};

#if 0
int dtls_verify_callback (int ok, X509_STORE_CTX *ctx) {
	/* This function should ask the user
	 * if he trusts the received certificate.
	 * Here we always trust.
	 */
	return 1;
}
#endif

int verify_callback(int ok, X509_STORE_CTX *store) {
	char data[256];

	if (!ok) {
		X509 *cert = X509_STORE_CTX_get_current_cert(store);
		int  depth = X509_STORE_CTX_get_error_depth(store);
		int  err = X509_STORE_CTX_get_error(store);

		fprintf(stderr, "-Error with certificate at depth: %i\n", depth);
		X509_NAME_oneline(X509_get_issuer_name(cert), data, 256);
		fprintf(stderr, "  issuer   = %s\n", data);
		X509_NAME_oneline(X509_get_subject_name(cert), data, 256);
		fprintf(stderr, "  subject  = %s\n", data);
		fprintf(stderr, "  err %i:%s\n", err, X509_verify_cert_error_string(err));
	}

	return ok;
}

void handle_notifications(BIO *bio, void *context, void *buf) {
	struct sctp_assoc_change *sac;
	struct sctp_send_failed *ssf;
	struct sctp_paddr_change *spc;
	struct sctp_remote_error *sre;
	union sctp_notification *snp = buf;
	char addrbuf[INET6_ADDRSTRLEN];
	const char *ap;
	union {
		struct sockaddr_in s4;
		struct sockaddr_in6 s6;
		struct sockaddr_storage ss;
	} addr;

	switch (snp->sn_header.sn_type) {
	case SCTP_ASSOC_CHANGE:
		sac = &snp->sn_assoc_change;
		printf("NOTIFICATION: assoc_change: state=%hu, error=%hu, instr=%hu outstr=%hu\n",
		sac->sac_state, sac->sac_error, sac->sac_inbound_streams, sac->sac_outbound_streams);
		break;

	case SCTP_PEER_ADDR_CHANGE:
		spc = &snp->sn_paddr_change;
		addr.ss = spc->spc_aaddr;
		if (addr.ss.ss_family == AF_INET) {
			ap = inet_ntop(AF_INET, &addr.s4.sin_addr, addrbuf, INET6_ADDRSTRLEN);
		} else {
			ap = inet_ntop(AF_INET6, &addr.s6.sin6_addr, addrbuf, INET6_ADDRSTRLEN);
		}
		printf("NOTIFICATION: intf_change: %s state=%d, error=%d\n", ap, spc->spc_state, spc->spc_error);
		break;

	case SCTP_REMOTE_ERROR:
		sre = &snp->sn_remote_error;
		printf("NOTIFICATION: remote_error: err=%hu len=%hu\n", ntohs(sre->sre_error), ntohs(sre->sre_length));
		break;

	case SCTP_SEND_FAILED:
		ssf = &snp->sn_send_failed;
		printf("NOTIFICATION: sendfailed: len=%u err=%d\n", ssf->ssf_length, ssf->ssf_error);
		break;

	case SCTP_SHUTDOWN_EVENT:
		printf("NOTIFICATION: shutdown event\n");
		break;

	case SCTP_ADAPTATION_INDICATION:
		printf("NOTIFICATION: adaptation event\n");
		break;

	case SCTP_PARTIAL_DELIVERY_EVENT:
		printf("NOTIFICATION: partial delivery\n");
		break;

#ifdef SCTP_AUTHENTICATION_EVENT
	case SCTP_AUTHENTICATION_EVENT:
		printf("NOTIFICATION: authentication event\n");
		break;
#endif

#ifdef SCTP_SENDER_DRY_EVENT
	case SCTP_SENDER_DRY_EVENT:
		printf("NOTIFICATION: sender dry event\n");
		break;
#endif

	default:
		printf("NOTIFICATION: unknown type: %hu\n", snp->sn_header.sn_type);
		break;
	}
}

void* connection_handle(void *info) {
	ssize_t len;
	char buf[BUFFER_SIZE];
	struct pass_info *pinfo = (struct pass_info*) info;
	SSL_CTX *ctx = pinfo->ctx;
	SSL *ssl;
	BIO *bio;
	struct bio_dgram_sctp_rcvinfo rinfo;
	int streamrcvcount[MAX_STREAMS];
	int reading = 0, rcvcount, i, activesocks;
	fd_set readsocks;
	struct timeval timeout;
	int retval;

	pthread_detach(pthread_self());

	ssl = SSL_new(ctx);

	/* Create DTLS/SCTP BIO */
	bio = BIO_new_dgram_sctp(pinfo->fd, BIO_NOCLOSE);
	if (!bio) {
		ERR_print_errors_fp(stderr);
		exit(EXIT_FAILURE);
	}

	SSL_set_bio(ssl, bio, bio);
	if (veryverbose)
		BIO_dgram_sctp_notification_cb(bio, &handle_notifications, (void*) ssl);

	retval = SSL_accept(ssl);
	if (retval <= 0) {
		switch (SSL_get_error(ssl, retval)) {
			case SSL_ERROR_ZERO_RETURN:
				fprintf(stderr, "SSL_accept failed with SSL_ERROR_ZERO_RETURN\n");
				break;
			case SSL_ERROR_WANT_READ:
				fprintf(stderr, "SSL_accept failed with SSL_ERROR_WANT_READ\n");
				break;
			case SSL_ERROR_WANT_WRITE:
				fprintf(stderr, "SSL_accept failed with SSL_ERROR_WANT_WRITE\n");
				break;
			case SSL_ERROR_WANT_CONNECT:
				fprintf(stderr, "SSL_accept failed with SSL_ERROR_WANT_CONNECT\n");
				break;
			case SSL_ERROR_WANT_ACCEPT:
				fprintf(stderr, "SSL_accept failed with SSL_ERROR_WANT_ACCEPT\n");
				break;
			case SSL_ERROR_WANT_X509_LOOKUP:
				fprintf(stderr, "SSL_accept failed with SSL_ERROR_WANT_X509_LOOKUP\n");
				break;
			case SSL_ERROR_SYSCALL:
				fprintf(stderr, "SSL_accept failed with SSL_ERROR_SYSCALL\n");
				break;
			case SSL_ERROR_SSL:
				fprintf(stderr, "SSL_accept failed with SSL_ERROR_SSL\n");
				break;
			default:
				fprintf(stderr, "SSL_accept failed with unknown error\n");
				break;
		}
		goto cleanup;
	}

	if (verbose)
		printf ("\nThread %lx: accepted connection from %s:%u\n",
				(long) pthread_self(), pinfo->address, pinfo->port);
	if (veryverbose && SSL_get_peer_certificate(ssl)) {
		printf ("------------------------------------------------------------\n");
		X509_NAME_print_ex_fp(stdout, X509_get_subject_name(SSL_get_peer_certificate(ssl)),
							  1, XN_FLAG_MULTILINE);
		printf("\n\n Cipher: %s", SSL_CIPHER_get_name(SSL_get_current_cipher(ssl)));
		printf ("\n------------------------------------------------------------\n\n");
	}

	rcvcount = 0;
	memset(&streamrcvcount, 0, MAX_STREAMS * sizeof(int));

	while (!(SSL_get_shutdown(ssl) & SSL_RECEIVED_SHUTDOWN)) {
		timeout.tv_sec = 60;
		timeout.tv_usec = 0;

		FD_ZERO(&readsocks);
		FD_SET(pinfo->fd,&readsocks);

		while ((activesocks = select(FD_SETSIZE, &readsocks, NULL, NULL, &timeout)) < 0) {
			if (errno != EINTR) {
				perror("select");
				exit(EXIT_FAILURE);
			}
		}

		if (activesocks > 0) {

			if (FD_ISSET(pinfo->fd,&readsocks)) {
				reading = 1;

				while (reading) {

					len = SSL_read(ssl, buf, sizeof(buf));

					switch (SSL_get_error(ssl, len)) {
						case SSL_ERROR_NONE:
							BIO_ctrl(bio, BIO_CTRL_DGRAM_SCTP_GET_RCVINFO, sizeof(struct bio_dgram_sctp_rcvinfo), &rinfo);
							if (verbose) {
								printf("Thread %lx: read message with %d bytes on stream %u\n", (long) pthread_self(),
									   (int) len, rinfo.rcv_sid);
							}

							rcvcount++;
							streamrcvcount[rinfo.rcv_sid] = streamrcvcount[rinfo.rcv_sid] + 1;
							reading = 0;
							break;
						case SSL_ERROR_WANT_READ:
							/* Just try again */
							break;
						case SSL_ERROR_ZERO_RETURN:
							reading = 0;
							break;
						case SSL_ERROR_SYSCALL:
							perror("Socket read error");
							goto cleanup;
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
			}
		} else {
			printf("Connection timeout!\n");
			SSL_shutdown(ssl);
			goto cleanup;
		}
	}

	SSL_shutdown(ssl);

	if (verbose) {
		printf("\nThread %lx: Statistics for %s:\n=========================================================\n",
			   (long) pthread_self(), pinfo->address);
		printf("Thread %lx: Received messages:                %6d\n\n", (long) pthread_self(), rcvcount);

		for (i = 0; streamrcvcount[i] > 0; i++)
			printf("Thread %lx: Received messages on stream %3d:  %6d\n", (long) pthread_self(), i, streamrcvcount[i]);
	}

cleanup:
	close(pinfo->fd);
	free(info);
	SSL_free(ssl);
	if (verbose)
		printf("Thread %lx: done, connection closed.\n", (long) pthread_self());
	pthread_exit( (void *) NULL );
}

void start_server(int port, char *local_address, int request_peer_certificate) {
	int fd, accfd, pid;
	union {
		struct sockaddr_in s4;
		struct sockaddr_in6 s6;
		struct sockaddr_storage ss;
	} server_addr, client_addr;
	socklen_t len;
	pthread_t tid;
	SSL_CTX *ctx;
	struct pass_info *info;
	const int on = 1, off = 0;
#ifdef SCTP_EVENT
	struct sctp_event event;
	unsigned int i;
	uint16_t event_types[] = {SCTP_ASSOC_CHANGE,
							  SCTP_PEER_ADDR_CHANGE,
							  SCTP_SHUTDOWN_EVENT,
							  SCTP_ADAPTATION_INDICATION};
#else
	struct sctp_event_subscribe event;
#endif
	BIO *bio;

	memset((void *) &server_addr, 0, sizeof(struct sockaddr_storage));
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
			server_addr_s6.sin6_len = sizeof(struct sockaddr_in6);
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
	//SSL_CTX_set_cipher_list(ctx, "ALL:NULL:eNULL:aNULL");
	pid = getpid();
	if( !SSL_CTX_set_session_id_context(ctx, (void*)&pid, sizeof pid) )
		perror("SSL_CTX_set_session_id_context");

	if (!SSL_CTX_use_certificate_file(ctx, "certs/server-cert.pem", SSL_FILETYPE_PEM))
		printf("\nERROR: no certificate found!");

	if (!SSL_CTX_use_PrivateKey_file(ctx, "certs/server-key.pem", SSL_FILETYPE_PEM))
		printf("\nERROR: no private key found!");

	if (!SSL_CTX_check_private_key (ctx))
		printf("\nERROR: invalid private key!");

	/* Client has to authenticate */
	if (request_peer_certificate) {
		SSL_CTX_set_verify(ctx, SSL_VERIFY_PEER | SSL_VERIFY_CLIENT_ONCE, verify_callback);
	} else {
		SSL_CTX_set_verify(ctx, SSL_VERIFY_NONE, verify_callback);
	}

	SSL_CTX_set_read_ahead(ctx,1);

	fd = socket(server_addr.ss.ss_family, SOCK_STREAM, IPPROTO_SCTP);
	if (fd < 0) {
		perror("socket");
		exit(-1);
	}

	setsockopt(fd, SOL_SOCKET, SO_REUSEADDR, (const void*)&on, (socklen_t)sizeof(on));

	if (server_addr.ss.ss_family == AF_INET) {
		bind(fd, (const struct sockaddr *) &server_addr, sizeof(struct sockaddr_in));
	} else {
		setsockopt(fd, IPPROTO_IPV6, IPV6_V6ONLY, (char *)&off, sizeof(off));
		bind(fd, (const struct sockaddr *) &server_addr, sizeof(struct sockaddr_in6));
	}

	if (listen(fd, 5) < 0)
		perror("listen");

#ifdef SCTP_RCVINFO
	setsockopt(fd, IPPROTO_SCTP, SCTP_RECVRCVINFO, &on, sizeof(on));
#else
	memset(&event, 0, sizeof(event));
	event.sctp_data_io_event = 1;
	if (setsockopt(fd, IPPROTO_SCTP, SCTP_EVENTS, &event, sizeof(event)) != 0) {
		perror("set event failed");
	}
#endif
	if (verbose) {
#ifdef SCTP_EVENT
		memset(&event, 0, sizeof(event));
		event.se_assoc_id = SCTP_FUTURE_ASSOC;
		event.se_on = 1;
		for (i = 0; i < sizeof(event_types)/sizeof(uint16_t); i++) {
			event.se_type = event_types[i];
			if (setsockopt(fd, IPPROTO_SCTP, SCTP_EVENT, &event, sizeof(event)) < 0) {
				perror("setsockopt");
			}
		}
#else
		memset(&event, 1, sizeof(event));
		if (setsockopt(fd, IPPROTO_SCTP, SCTP_EVENTS, &event, sizeof(event)) != 0) {
			perror("set event failed");
		}
#endif
	}

	/* Create BIO to set all necessary parameters for
	 * following connections, e.g. SCTP-AUTH.
	 * Will not be used.
	 */
	bio = BIO_new_dgram_sctp(fd, BIO_NOCLOSE);
	if (!bio) {
		ERR_print_errors_fp(stderr);
		exit(EXIT_FAILURE);
	}

	while (1) {
		memset(&client_addr, 0, sizeof(client_addr));
		len = (socklen_t)sizeof(client_addr);

		accfd = accept(fd, (struct sockaddr *) &client_addr, &len);

		info = (struct pass_info*) malloc(sizeof(struct pass_info));
		memset(info, 0, sizeof(struct pass_info));
		info->fd = accfd;
		info->ctx = ctx;
		if (client_addr.ss.ss_family == AF_INET) {
			inet_ntop(AF_INET, (const char *)&client_addr.s4.sin_addr, info->address, INET6_ADDRSTRLEN);
			info->port = ntohs(client_addr.s4.sin_port);
		} else {
			inet_ntop(AF_INET6, (const char *)&client_addr.s6.sin6_addr, info->address, INET6_ADDRSTRLEN);
			info->port = ntohs(client_addr.s6.sin6_port);
		}

		if (pthread_create( &tid, NULL, connection_handle, info) != 0) {
			perror("pthread_create");
			exit(1);
		}
	}

	THREAD_cleanup();

	if (close(fd) < 0)
		perror("close");
}

void start_client(char *remote_address, char* local_address, int port, int timetosend) {
	int fd, count = 0;
	union {
		struct sockaddr_in s4;
		struct sockaddr_in6 s6;
		struct sockaddr_storage ss;
	} remote_addr, local_addr;
	char buf[BUFFER_SIZE];
	char addrbuf[INET6_ADDRSTRLEN];
	socklen_t len;
	SSL_CTX *ctx;
	SSL *ssl;
	BIO *bio;
#ifdef SCTP_RCVINFO
	const int on = 1;
#endif
	int retval;
#ifdef SCTP_EVENT
	struct sctp_event event;
	uint16_t event_types[] = {SCTP_ASSOC_CHANGE,
							  SCTP_PEER_ADDR_CHANGE,
							  SCTP_SHUTDOWN_EVENT,
							  SCTP_ADAPTATION_INDICATION};
#else
	struct sctp_event_subscribe event;
#endif
	struct bio_dgram_sctp_sndinfo sinfo;
	int streamcount[MAX_STREAMS];
	int reading = 0, stream, activesocks;
	fd_set readsocks;
	struct timeval timeout;
	unsigned int i = 0;

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

	fd = socket(remote_addr.ss.ss_family, SOCK_STREAM, IPPROTO_SCTP);
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

#ifdef SCTP_RCVINFO
	setsockopt(fd, IPPROTO_SCTP, SCTP_RECVRCVINFO, &on, sizeof(on));
#else
	memset(&event, 0, sizeof(event));
	event.sctp_data_io_event = 1;
	if (setsockopt(fd, IPPROTO_SCTP, SCTP_EVENTS, &event, sizeof(event)) != 0) {
		perror("set event failed");
	}
#endif
	if (verbose) {
#ifdef SCTP_EVENT
		memset(&event, 0, sizeof(event));
		event.se_assoc_id = SCTP_FUTURE_ASSOC;
		event.se_on = 1;
		for (i = 0; i < sizeof(event_types)/sizeof(uint16_t); i++) {
			event.se_type = event_types[i];
			if (setsockopt(fd, IPPROTO_SCTP, SCTP_EVENT, &event, sizeof(event)) < 0) {
				perror("setsockopt");
			}
		}
#else
		memset(&event, 1, sizeof(event));
		if (setsockopt(fd, IPPROTO_SCTP, SCTP_EVENTS, &event, sizeof(event)) != 0) {
			perror("set event failed");
		}
#endif
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
	SSL_CTX_set_read_ahead(ctx,1);

	ssl = SSL_new(ctx);

	/* Create DTLS/SCTP BIO and connect */
	bio = BIO_new_dgram_sctp(fd, BIO_CLOSE);
	if (!bio) {
		ERR_print_errors_fp(stderr);
		exit(EXIT_FAILURE);
	}

	if (remote_addr.ss.ss_family == AF_INET) {
		connect(fd, (struct sockaddr *) &remote_addr, sizeof(struct sockaddr_in));
	} else {
		connect(fd, (struct sockaddr *) &remote_addr, sizeof(struct sockaddr_in6));
	}

	SSL_set_bio(ssl, bio, bio);
	if (veryverbose)
		BIO_dgram_sctp_notification_cb(bio, &handle_notifications, (void*) ssl);

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

	if (verbose) {
		if (remote_addr.ss.ss_family == AF_INET) {
			printf ("\nConnected to %s:%u\n",
					inet_ntop(AF_INET, &remote_addr.s4.sin_addr, addrbuf, INET6_ADDRSTRLEN), port);
		} else {
			printf ("\nConnected to %s:%u\n",
					inet_ntop(AF_INET6, &remote_addr.s6.sin6_addr, addrbuf, INET6_ADDRSTRLEN), port);
		}
	}

	if (veryverbose && SSL_get_peer_certificate(ssl)) {
		printf ("------------------------------------------------------------\n");
		X509_NAME_print_ex_fp(stdout, X509_get_subject_name(SSL_get_peer_certificate(ssl)),
							  1, XN_FLAG_MULTILINE);
		printf("\n\n Cipher: %s", SSL_CIPHER_get_name(SSL_get_current_cipher(ssl)));
		printf ("\n------------------------------------------------------------\n\n");
	}

	signal(SIGALRM, stop_sender);
	alarm(timetosend);

	count = 0;
	memset(&streamcount, 0, MAX_STREAMS * sizeof(int));

	while (!(SSL_get_shutdown(ssl) & SSL_RECEIVED_SHUTDOWN)) {
		timeout.tv_sec = 0;
		timeout.tv_usec = 1;

		FD_ZERO(&readsocks);
		FD_SET(fd,&readsocks);

		while ((activesocks = select(FD_SETSIZE, &readsocks, NULL, NULL, &timeout)) < 0) {
			if (errno != EINTR) {
				perror("select");
				exit(EXIT_FAILURE);
			}
		}

		if (SSL_get_shutdown(ssl) == 0) {
			memset(&sinfo, 0, sizeof(struct bio_dgram_sctp_sndinfo));

			stream = round(rand()/((double)RAND_MAX + 1) * streams);
			sinfo.snd_sid = stream;

			BIO_ctrl(bio, BIO_CTRL_DGRAM_SCTP_SET_SNDINFO, sizeof(struct bio_dgram_sctp_sndinfo), &sinfo);

			len = SSL_write(ssl, buf, length);

			switch (SSL_get_error(ssl, len)) {
				case SSL_ERROR_NONE:
					if (verbose) {
						printf("wrote num %d with %d bytes on stream %u\n", count,
							   (int) len, sinfo.snd_sid);
					}
					count++;
					streamcount[sinfo.snd_sid] = streamcount[sinfo.snd_sid] + 1;
					break;
				case SSL_ERROR_WANT_WRITE:
					/* Just try again later */
					break;
				case SSL_ERROR_WANT_READ:
					/* continue with reading */
					break;
				case SSL_ERROR_SYSCALL:
					perror("Socket write error");
					exit(1);
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

			if (done && !SSL_renegotiate_pending(ssl))
				SSL_shutdown(ssl);
		}

		/* Read if the server sent anything.
		 * BIO_dgram_sctp_msg_waiting peeks if there are msgs
		 * waiting and also processes notifications. Otherwise
		 * notifications would block here.
		 */
		if (activesocks > 0 && BIO_dgram_sctp_msg_waiting(bio)) {

			if (FD_ISSET(fd,&readsocks)) {
				reading = 1;

				while (reading) {
					len = SSL_read(ssl, buf, sizeof(buf));
					switch (SSL_get_error(ssl, len)) {
						case SSL_ERROR_NONE:
							reading = 0;
							break;
						case SSL_ERROR_WANT_READ:
							/* Just try again */
							break;
						case SSL_ERROR_ZERO_RETURN:
							reading = 0;
							break;
						case SSL_ERROR_SYSCALL:
							perror("Socket read error");
							exit(1);
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
		}
	}

	printf("\nStatistics:\n========================================\n");
	printf("Sent messages:                    %6d\n\n", count);

	for (i = 0; streamcount[i] > 0; i++) {
		printf("Sent messages on stream     %3d:  %6d\n", i, streamcount[i]);
	}

	close(fd);
	if (verbose)
		printf("Connection closed.\n");
}

int main(int argc, char **argv)
{
	int port = 23232;
	int timetosend = 10;
	char local_addr[INET6_ADDRSTRLEN+1];
	char c;
	int request_peer_certificate = 0;

	memset(local_addr, 0, INET6_ADDRSTRLEN+1);

	while ((c = getopt(argc, argv, "p:t:l:s:L:urvV")) != -1)
		switch(c) {
			case 'l':
				length = atoi(optarg);
				if (length > BUFFER_SIZE)
					length = BUFFER_SIZE;
				break;
			case 's':
				streams = atoi(optarg);
				if (streams > MAX_STREAMS)
					streams = MAX_STREAMS;
				break;
			case 't':
				timetosend = atoi(optarg);
				break;
			case 'p':
				port = atoi(optarg);
				break;
			case 'L':
				strncpy(local_addr, optarg, INET6_ADDRSTRLEN);
				break;
			case 'u':
				unordered = 1;
				break;
			case 'r':
				request_peer_certificate = 1;
				break;
			case 'v':
				verbose = 1;
				break;
			case 'V':
				verbose = 1;
				veryverbose = 1;
				break;
			default:
				fprintf(stderr, "%s\n", Usage);
				exit(1);
		}

	if (OpenSSL_version_num() != OPENSSL_VERSION_NUMBER) {
		printf("Warning: OpenSSL version mismatch!\n");
		printf("Compiled against %s\n", OPENSSL_VERSION_TEXT);
		printf("Linked against   %s\n", OpenSSL_version(OPENSSL_VERSION));

		if (OpenSSL_version_num() >> 20 != OPENSSL_VERSION_NUMBER >> 20) {
			printf("Major and minor version numbers must match, exiting.\n");
			exit(EXIT_FAILURE);
		}
	} else if (verbose) {
		printf("Using %s\n", OpenSSL_version(OPENSSL_VERSION));
	}

	if (OPENSSL_VERSION_NUMBER < 0x1010102fL) {
		printf("Error: %s is unsupported, use OpenSSL Version 1.1.1a or higher\n", OpenSSL_version(OPENSSL_VERSION));
		exit(EXIT_FAILURE);
	}

	if (optind == argc)
		start_server(port, local_addr, request_peer_certificate);
	else
		start_client(argv[optind], local_addr, port, timetosend);

	return 0;
}
