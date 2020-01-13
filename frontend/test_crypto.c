/*
 * test_crypto.c
 *
 * Performs a simple encryption-decryption of urandom data from /dev/urandom
 * with the use of cryptodev device.
 *
 * Stefanos Gerangelos <sgerag@cslab.ece.ntua.gr>
 *
 * Modified to test open and close only
 */

#include <stdio.h>
#include <unistd.h>
#include <fcntl.h>

#include <stdlib.h>
#include <string.h>
#include <sys/ioctl.h>
#include "cryptodev.h"

#include <sys/types.h>
#include <sys/stat.h>

int main(int argc, char **argv)
{
	int fd = -1;

printf("DONE\n");

	fd = open("/dev/cryptodev0", O_RDWR);
	printf("DONE\n");
	if (fd < 0) {
		return 1;
	}

    if (close(fd)) {
		perror("close(fd)");
		return 1;
	}

    printf("Closed file with fd = %d\n", fd);

	return 0;
}
