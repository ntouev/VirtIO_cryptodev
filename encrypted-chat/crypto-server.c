/*
 * crypto-server.c
 * server and client are peers and implement an encrypted chat
 *
 * Gouliamou Maria-Ethel
 * Ntouros Evangelos
 */

 #include <stdio.h>
 #include <fcntl.h>
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
 #include <sys/ioctl.h>
 #include <sys/stat.h>

 #include <arpa/inet.h>
 #include <netinet/in.h>
 #include <crypto/cryptodev.h>

 #include "common.h"

 #define DATA_SIZE       256
 #define BLOCK_SIZE      16
 #define KEY_SIZE        16  /* AES128 */

unsigned char buf[256];
unsigned char key[] = "okhfgdnbgfvtrgf";        //encryption key
unsigned char inv[] = "qghgftrgfbvgfhy";        //initialization vector
struct session_op sess;

/*Insist until all of the data has been written*/
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

int encrypt(int cfd)
{
        int i;
        struct crypt_op cryp;
        struct {
                unsigned char   in[DATA_SIZE],
                                encrypted[DATA_SIZE],
                                iv[BLOCK_SIZE];
        } data;

        memset(&cryp, 0, sizeof(cryp));

        /*Encrypt data.in to data.encrypted*/
        cryp.ses = sess.ses;
        cryp.len = sizeof(data.in);
        cryp.src = buf;
        cryp.dst = data.encrypted;
        cryp.iv = inv;
        cryp.op = COP_ENCRYPT;

        if (ioctl(cfd, CIOCCRYPT, &cryp)) {
                perror("ioctl(CIOCCRYPT)");
                return 1;
        }

        i = 0;
        memset(buf, '\0', sizeof(buf));
        while(data.encrypted[i] != '\0'){
                buf[i] = data.encrypted[i];
                i++;
        }

        return 0;
}

int decrypt(int cfd){

        int i;
        struct crypt_op cryp;
        struct {
                unsigned char   in[DATA_SIZE],
                                decrypted[DATA_SIZE],
                                iv[BLOCK_SIZE];
        } data;

        memset(&cryp, 0, sizeof(cryp));

        /*Decrypt data.encrypted to data.decrypted*/
        cryp.ses = sess.ses;
        cryp.len = sizeof(data.in);
        cryp.src = buf;
        cryp.dst = data.decrypted;
        cryp.iv = inv;
        cryp.op = COP_DECRYPT;
        if (ioctl(cfd, CIOCCRYPT, &cryp)) {
                perror("ioctl(CIOCCRYPT)");
                return 1;
        }

        i = 0;
        memset(buf, '\0', sizeof(buf));
        while(data.decrypted[i] != '\0'){
                buf[i] = data.decrypted[i];
                i++;
        }

        return 0;
}

int main(int argc, char **argv)
{
    char addrstr[INET_ADDRSTRLEN];
    int sd, newsd, cfd;
    struct sockaddr_in sa;
    socklen_t len;
    ssize_t n;
    struct pollfd pfds[2];

    memset(&sess, 0, sizeof(sess));

    /*Make sure a broken connection doesn't kill us*/
    signal(SIGPIPE, SIG_IGN);

    /*Create TCP/IP socket, used as the main chat channel*/
    if ((sd = socket(PF_INET, SOCK_STREAM, 0)) < 0) { //protocol family IPv4, TCP
        perror("socket");
        exit(1);
    }
    fprintf(stderr, "Created TCP socket\n");

    /*Bind to a well-known port*/
    memset(&sa, 0, sizeof(sa));                     //is used to zero sin_zero[8]
    sa.sin_family = AF_INET;                        //address family IPv4
    sa.sin_port = htons(TCP_PORT);                  //convert to network byte order
    //sa.sin_addr.s_addr = htonl(INADDR_ANY);       //binds the socket to all available interfaces
    sa.sin_addr.s_addr = inet_addr("127.0.0.1");    //for localhost
    if (bind(sd, (struct sockaddr *)&sa, sizeof(sa)) < 0) {
        perror("bind");
        exit(1);
    }
    fprintf(stderr, "Bound TCP socket to port %d\n", TCP_PORT);

    /*Listen for incoming connections*/
    if (listen(sd, TCP_BACKLOG) < 0) {
        perror("listen");
        exit(1);
    }

    /*Loop forever, accepting connections*/
    for (;;) {
        fprintf(stderr, "Waiting for an incoming connection...\n");

        /*Accept an incoming connection*/
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

        /*open crypto device*/
        cfd = open("/dev/crypto", O_RDWR);
        if (cfd < 0) {
            perror("open(/dev/crypto)");
            return 1;
        }

        /*Get crypto session for AES128*/
        sess.cipher = CRYPTO_AES_CBC;
        sess.keylen = KEY_SIZE;
        sess.key = key;

        if (ioctl(cfd, CIOCGSESSION, &sess)) {
            perror("ioctl(CIOCGSESSION)");
            return 1;
        }

        /*We break out of the loop when the remote peer goes away*/
        for (;;) {
            //poll 0 and newsd to see which has data first
            pfds[0].fd = 0;
            pfds[0].events = POLLIN;

            pfds[1].fd = newsd;
            pfds[1].events = POLLIN;

            poll(pfds, 2, 0);
            if (pfds[0].revents & POLLIN) {
                memset(buf, '\0', sizeof(buf));
                n = read(0, buf, sizeof(buf));
                if (n < 0) {
                    perror("[server] read from stdin");
                    exit(1);
                }
                if (n == 0)  //EOF??
                    break;

                if(encrypt(cfd)){
                        perror("encrypt");
                }

                if (insist_write(newsd, buf, sizeof(buf)) != sizeof(buf)) {
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

                if(decrypt(cfd)){
                        perror("decrypt");
                }

                if (insist_write(1, buf, n) != n) {
                    perror("[server] write to stdout");
                    break;
                }
            }
        }
        /*Make sure we don't leak open files*/
        if (close(newsd) < 0)
            perror("close");

        /*Finish crypto session*/
        if (ioctl(cfd, CIOCFSESSION, &sess.ses)) {
            perror("ioctl(CIOCFSESSION)");
            return 1;
        }

        /*close cryto device*/
        if (close(cfd) < 0) {
            perror("close(cfd)");
            return 1;
        }
    }

    /*Unreachable*/
    fprintf(stderr, "Reached unreachable point!\n");
    return 1;
}
