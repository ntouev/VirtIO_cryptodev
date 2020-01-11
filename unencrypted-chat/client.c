/*
 * client.c
 * server and client are peers and implement an unencrypted chat
 *
 * Gouliamou Maria-Ethel
 * Ntouros Evangelos
 */

#include <stdio.h>
#include <errno.h>
#include <ctype.h>
#include <string.h>
#include <stdlib.h>
#include <signal.h>
#include <unistd.h>
#include <netdb.h>

#include <sys/time.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <sys/poll.h>

#include <arpa/inet.h>
#include <netinet/in.h>

#include "common.h"

/* Insist until all of the data has been written */
ssize_t insist_write(int fd, const void *buf, size_t cnt)
{
	ssize_t ret;
	size_t orig_cnt = cnt;

	while (cnt > 0) {
	        ret = write(fd, buf, cnt);
	        if (ret < 0)
	                return ret;
	        buf += ret;
	        cnt -= ret;
	}

	return orig_cnt;
}

int main(int argc, char **argv)
{
    int sd, port;
    char *hostname;
    char buf[100];
    struct hostent *hp;
    struct sockaddr_in sa;
    ssize_t n;
    struct pollfd pfds[2];

    if (argc != 3) {
        fprintf(stderr, "Usage: %s hostname port\n", argv[0]);
        exit(1);
    }
    hostname = argv[1];
    port = atoi(argv[2]);

    /* Create TCP/IP socket, used as the main chat channel */
    if ((sd = socket(PF_INET, SOCK_STREAM, 0)) < 0) {
        perror("socket");
        exit(1);
    }
    fprintf(stderr, "Created TCP socket\n");

    /* Look up remote hostname on DNS */
    if (!(hp = gethostbyname(hostname))) {
        printf("DNS lookup failed for host %s\n", hostname);
        exit(1);
    }

    /* Connect to remote TCP port */
	sa.sin_family = AF_INET;
	sa.sin_port = htons(port);
	memcpy(&sa.sin_addr.s_addr, hp->h_addr, sizeof(struct in_addr));
	fprintf(stderr, "Connecting to remote host... "); fflush(stderr);
	if (connect(sd, (struct sockaddr *) &sa, sizeof(sa)) < 0) {
		perror("connect");
		exit(1);
	}
	fprintf(stderr, "Connected.\n");

    for (;;) {
        //poll 0 and newsd to see which has data first
        pfds[0].fd = 0;
        pfds[0].events = POLLIN;

        pfds[1].fd = sd;
        pfds[1].events = POLLIN;

        poll(pfds, 2, 0);
        if (pfds[0].revents & POLLIN) {
            n = read(0, buf, sizeof(buf));
            if (n < 0) {
                perror("[client] read from client");
                exit(1);
            }
            if (n == 0)  //EOF??
                break;

            if (insist_write(sd, buf, n) != n) {
                perror("[client] write to peer");
                exit(1);
            }
        }
        else if (pfds[1].revents & POLLIN) {
            n = read(sd, buf, sizeof(buf));
            if (n <= 0) {
                if (n < 0)
                    perror("[client] read from peer");
                else
                    fprintf(stderr, "[client] peer went away...exiting\n");
                break;
            }

            if (insist_write(1, buf, n) != n) {
                perror("[client] write to stdout");
                exit(1);
            }
        }
    }

    return 0;
}
