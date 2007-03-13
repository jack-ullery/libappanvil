/* $Id$ */

/*
 *	Copyright (C) 2002-2007 Novell/SUSE
 *
 *	This program is free software; you can redistribute it and/or
 *	modify it under the terms of the GNU General Public License as
 *	published by the Free Software Foundation, version 2 of the
 *	License.
 */

#define _GNU_SOURCE

#include <stdio.h>
#include <unistd.h>
#include <errno.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <string.h>

int main(int argc, char *argv[])
{
	int fd = -1, dirfd = -1;

	if (argc != 3){
		fprintf(stderr, "usage: %s dir file\n", argv[0]);
		return 1;
	}

	dirfd = open(argv[1], O_RDONLY | O_DIRECTORY);
	if (dirfd == -1) {
		fprintf(stderr, "FAIL: open %s failed - %s\n",
			argv[1], strerror(errno));
		return 1;
	}

	fd = openat(dirfd, argv[2], O_RDWR | O_CREAT, S_IWUSR | S_IRUSR);
	if (fd == -1) {
		fprintf(stderr, "FAIL: openat %s failed - %s\n",
			argv[2], strerror(errno));
		close(dirfd);
		return 1;
	}

	close(fd);
	close(dirfd);

	printf("PASS\n");

	return 0;
}
