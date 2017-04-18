
CFLAGS 		= -std=c99 -pedantic -Wall -g -Wextra -Wno-unused-parameter -Wno-unused-function -Wno-overlength-strings
INCLUDES 	= -I/usr/local/include
LFLAGS 		= -L/usr/local/lib
LIBS 		= -lssl -lcrypto -pthread -lm

all: dtls_sctp_chargen dtls_sctp_discard dtls_sctp_echo dtls_udp_chargen dtls_udp_discard dtls_udp_echo

dtls_sctp_chargen: dtls_sctp_chargen.c
	$(CC) $(CFLAGS) $(INCLUDES) -o dtls_sctp_chargen dtls_sctp_chargen.c $(LFLAGS) $(LIBS)

dtls_sctp_discard: dtls_sctp_discard.c
	$(CC) $(CFLAGS) $(INCLUDES) -o dtls_sctp_discard dtls_sctp_discard.c $(LFLAGS) $(LIBS)

dtls_sctp_echo: dtls_sctp_echo.c
	$(CC) $(CFLAGS) $(INCLUDES) -o dtls_sctp_echo dtls_sctp_echo.c $(LFLAGS) $(LIBS)

dtls_udp_chargen: dtls_udp_chargen.c
	$(CC) $(CFLAGS) $(INCLUDES) -o dtls_udp_chargen dtls_udp_chargen.c $(LFLAGS) $(LIBS)

dtls_udp_discard: dtls_udp_discard.c
	$(CC) $(CFLAGS) $(INCLUDES) -o dtls_udp_discard dtls_udp_discard.c $(LFLAGS) $(LIBS)

dtls_udp_echo: dtls_udp_echo.c
	$(CC) $(CFLAGS) $(INCLUDES) -o dtls_udp_echo dtls_udp_echo.c $(LFLAGS) $(LIBS)

clean:
	rm -f dtls_sctp_chargen
	rm -f dtls_sctp_discard
	rm -f dtls_sctp_echo
	rm -f dtls_udp_chargen
	rm -f dtls_udp_discard
	rm -f dtls_udp_echo
