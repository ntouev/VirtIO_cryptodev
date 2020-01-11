###################################################
#
# Makefile
# For server-client
#
# Gouliamou Maria-Ethel
# Ntouros Evangelos
#
###################################################

CC = gcc

CFLAGS = -Wall

LIBS =

BINS = server client

all: $(BINS)

server: server.c common.h
	$(CC) $(CFLAGS) -o $@ $< $(LIBS)

client: client.c common.h
	$(CC) $(CFLAGS) -o $@ $< $(LIBS)

clean:
	rm -f *.o *~ $(BINS)
