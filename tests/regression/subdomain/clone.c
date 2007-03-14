/* $Id$ */

/*
 *	Copyright (C) 2007 Novell/SUSE
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
#include <sys/wait.h>
#include <sys/user.h>
#include <fcntl.h>
#include <string.h>
#include <stdlib.h>
#include <getopt.h>
#include <sched.h>
#include <linux/unistd.h>

struct option long_options[] =
{
	{"newns", 0, 0, 'n'},  /* create a new namespace */
	{"help", 0, 0, 'h'},
};

static void usage (char * program) {
	fprintf(stderr, "usage: %s [arguments]\n",
		program);
	fprintf(stderr, "%s\n", "$Id$");
	exit(1);
}

static int filedes[2] = {-1, -1};

static int do_child(void *arg)
{
	int rc;

	close(filedes[0]);
	fclose(stdout);
	rc = dup2(filedes[1], STDOUT_FILENO);
	if (rc < 0) {
		perror("FAIL: pipe failed");
		return 1;
	}

	rc = write(filedes[1], "PASS\n", strlen("PASS\n"));
	if (rc < 0) {
		perror("FAIL: write failed");
		return 1;
	}

	return 0;
}

int main(int argc, char *argv[])
{
	int rc;
	int waitstatus;
	int c;
	char buf[BUFSIZ];
	void *child_stack = malloc(PAGE_SIZE << 4);
	int clone_flags = 0;

	while ((c = getopt_long (argc, argv, "+hn", long_options, NULL)) != -1) {
		switch (c) {
		    case 'n':
			clone_flags |= CLONE_NEWNS;
			break;
		    case 'h':
		        usage(argv[0]);
			break;
		    default:
		        usage(argv[0]);
			break;
		}
	}

	if (argv[optind])
		usage(argv[0]);

	rc = pipe(filedes);
	if (rc != 0) {
		perror("FAIL: pipe failed");
		exit(1);
	}

	rc = clone(&do_child, child_stack, clone_flags, NULL);
	if (rc < 0) {
		perror("FAIL: clone failed");
		exit(1);
	}

	/* parent */
	rc = waitpid(-1, (&waitstatus), __WALL);
	close(filedes[1]);
	read(filedes[0], &buf, sizeof(buf));
	if (rc == -1){
		fprintf(stderr, "FAIL: wait failed - %s\n",
			strerror(errno));
		exit(1);
	}

	if ((WEXITSTATUS(waitstatus) == 0) && strcmp("PASS\n", buf) == 0) {
		printf("PASS\n");
	}

	return WEXITSTATUS(waitstatus);
}
