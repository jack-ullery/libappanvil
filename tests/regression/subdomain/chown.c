/* $Id: chown.c 6040 2006-01-11 00:15:48Z tonyj $ */

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
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <string.h>

int main(int argc, char *argv[])
{
uid_t uid;

	if (argc != 3){
		fprintf(stderr, "usage: %s file username|uid\n",
			argv[0]);
		return 1;
	}

	if (sscanf(argv[2], "%d", &uid) != 1){
		fprintf(stderr, "FAIL: bad uid %s\n", argv[2]);
		return 1;
	}
	
	if (chown(argv[1], uid, -1) == -1){
		fprintf(stderr, "FAIL: chown %s %d failed - %s\n",
			argv[1], uid,
			strerror(errno));
		return 1;
	}

	printf("PASS\n");

	return 0;
}
