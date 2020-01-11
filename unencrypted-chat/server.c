/*
 * server.c
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
    char buf[100];
    char addrstr[INET_ADDRSTRLEN];
    int sd, newsd;
    struct sockaddr_in sa;
    socklen_t len;
    ssize_t n;
    struct pollfd pfds[2];

    /*Make sure a broken connection doesn't kill us*/
    signal(SIGPIPE, SIG_IGN);

    /* Create TCP/IP socket, used as the main chat channel */
    if ((sd = socket(PF_INET, SOCK_STREAM, 0)) < 0) { //protocol family IPv4, TCP
        perror("socket");
        exit(1);
    }
    fprintf(stderr, "Created TCP socket\n");

    /* Bind to a well-known port */
    memset(&sa, 0, sizeof(sa));  //is used to zero sin_zero[8]
    sa.sin_family = AF_INET;    //address family IPv4
    sa.sin_port = htons(TCP_PORT); //convert to network byte order
    //sa.sin_addr.s_addr = htonl(INADDR_ANY); //binds the socket to all available interfaces
    sa.sin_addr.s_addr = inet_addr("127.0.0.1"); //for localhost
    if (bind(sd, (struct sockaddr *)&sa, sizeof(sa)) < 0) {
        perror("bind");
        exit(1);
    }
    fprintf(stderr, "Bound TCP socket to port %d\n", TCP_PORT);

    /* Listen for incoming connections */
    if (listen(sd, TCP_BACKLOG) < 0) {
        perror("listen");
        exit(1);
    }

    /* Loop forever, accepting connections */
    for (;;) {
        fprintf(stderr, "Waiting for an incoming connection...\n");

        /* Accept an incoming connection */
        len = sizeof(struct sockaddr_in);
        if ((newsd = accept(sd, (struct sockaddr *)&sa, &len)) < 0) {
            perror("accept");
            exit(1);
        }
        if (!inet_ntop(AF_INET, &sa.sin_addr, addrstr, sizeof(addrstr))) {
            perror("could not format IP address");
            exit(1);
        }
        fprintf(stderr, "Incoming connection from %s:%d\n",
            addrstr, ntohs(sa.sin_port));

        /* We break out of the loop when the remote peer goes away */
        for (;;) {
            //poll 0 and newsd to see which has data first
            pfds[0].fd = 0;
            pfds[0].events = POLLIN;

            pfds[1].fd = newsd;
            pfds[1].events = POLLIN;

            poll(pfds, 2, 0);
            if (pfds[0].revents & POLLIN) {
                n = read(0, buf, sizeof(buf));
                if (n < 0) {
                    perror("[server] read from stdin");
                    exit(1);
                }
                if (n == 0)  //EOF??
                    break;

                if (insist_write(newsd, buf, n) != n) {
                    perror("[server] write to peer");
                    exit(1);
                }
            }
            else if (pfds[1].revents & POLLIN) {
                n = read(newsd, buf, sizeof(buf));
                if (n <= 0) {
                    if (n < 0)
                        perror("[server] read from peer");
                    else
                        fprintf(stderr, "[server] peer went away\n");
                    break;
                }

                if (insist_write(1, buf, n) != n) {
                    perror("[server] write to stdout");
                    break;
                }
            }
        }
        /* Make sure we don't leak open files */
        if (close(newsd) < 0)
            perror("close");
    }

    /* Unreachable */
    fprintf(stderr, "Reached unreachable point!\n");
    return 1;
}
