/* $Id: readdir.c 6040 2006-01-11 00:15:48Z tonyj $ */

/*
 *	Copyright (C) 2002-2005 Novell/SUSE
 *
 *	This program is free software; you can redistribute it and/or
 *	modify it under the terms of the GNU General Public License as
 *	published by the Free Software Foundation, version 2 of the
 *	License.
 */

#include <stdio.h>
#include <unistd.h>
#include <errno.h>
#include <fcntl.h>
#include <linux/types.h>
#include <linux/dirent.h>
#include <linux/unistd.h>
#include <string.h>

/* define getdents since it isn't exported in glibc */
_syscall3(int, getdents, uint, fd, struct dirent *, dirp, uint, count);

int main(int argc, char *argv[])
{
int fd;
struct dirent dir;

	if (argc != 2){
		fprintf(stderr, "usage: %s dir\n",
			argv[0]);
		return 1;
	}

	fd=open(argv[1], O_RDONLY, 0);
	if (fd == -1){
		printf("FAIL - open  %s\n", strerror(errno));
		return 1;
	}

	/*
	if (fchdir(fd) == -1){
		printf("FAIL - fchdir  %s\n", strerror(errno));
		return 1;
	}
	*/

	if (getdents(fd, &dir, sizeof(struct dirent)) == -1){
		printf("FAIL - getdents  %s\n", strerror(errno));
		return 1;
	}

	printf("PASS\n");

	return 0;
}
