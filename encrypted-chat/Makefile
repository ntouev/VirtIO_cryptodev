###################################################
#
# Makefile
# encrypted-chat
#
# Gouliamou Maria-Ethel
# Ntouros Evangelos
#
###################################################

CC = gcc

CRYPTODEVDIR=/usr/local/include/crypto

CFLAGS = -Wall -I$(CRYPTODEVDIR)
CFLAGS += -g

LIBS =

BINS = crypto-test crypto-server crypto-client

all: $(BINS)

crypto-test: crypto-test.c
	$(CC) $(CFLAGS) -o $@ $< $(LIBS)

crypto-server: crypto-server.c
	$(CC) $(CFLAGS) -o $@ $< $(LIBS)

crypto-client: crypto-client.c
	$(CC) $(CFLAGS) -o $@ $< $(LIBS)

clean:
	rm -f *.o *~ $(BINS)
