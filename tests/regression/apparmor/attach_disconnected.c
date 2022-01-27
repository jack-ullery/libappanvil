/*
 * Copyright (C) 2021 Canonical, Ltd.
 *
 * This program is free software; you can redistribute it and/or
 * modify it under the terms of version 2 of the GNU General Public
 * License published by the Free Software Foundation.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, contact Canonical Ltd.
 */

#define _GNU_SOURCE

#include <alloca.h>
#include <errno.h>
#include <sched.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/apparmor.h>
#include <sys/syscall.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <sys/mount.h>
#include <limits.h>
#include <libgen.h>
#include "unix_fd_common.h"

struct clone_arg {
	const char *socket;
	const char *disk_img;
	const char *new_root;
	const char *put_old;
};

static int _pivot_root(const char *new_root, const char *put_old)
{
#ifdef __NR_pivot_root
	return syscall(__NR_pivot_root, new_root, put_old);
#else
	errno = ENOSYS;
	return -1;
#endif
}

static int pivot_and_get_unix_clientfd(void *arg)
{
	int rc;
	const char *socket = ((struct clone_arg *)arg)->socket;
	const char *disk_img = ((struct clone_arg *)arg)->disk_img;
	const char *new_root = ((struct clone_arg *)arg)->new_root;
	const char *put_old = ((struct clone_arg *)arg)->put_old;

	char *tmp = strdup(put_old);
	char *put_old_bname = basename(tmp); // don't free

	char *socket_put_old;
	rc = asprintf(&socket_put_old, "/%s/%s", put_old_bname, socket);
	if (rc < 0) {
		perror("FAIL - asprintf socket_put_old");
		rc = errno;
		socket_put_old = NULL;
		goto out;
	}

	rc = mkdir(new_root, 0777);
	if (rc < 0 && errno != EEXIST) {
		perror("FAIL - mkdir new_root");
		rc = 100;
		goto out;
	}

	rc = mount(disk_img, new_root, "ext2", 0, NULL);
	if (rc < 0) {
		perror("FAIL - mount disk_img");
		rc = 101;
		goto out;
	}

	rc = chdir(new_root);
	if (rc < 0) {
		perror("FAIL - chdir");
		rc = 102;
		goto out;
	}

	rc = mkdir(put_old, 0777);
	if (rc < 0 && errno != EEXIST) {
		perror("FAIL - mkdir put_old");
		rc = 103;
		goto out;
	}

	rc = _pivot_root(new_root, put_old);
	if (rc < 0) {
		perror("FAIL - pivot_root");
		rc = 104;
		goto out;
	}

	/* Actual test - it tries to open the socket which is detached.
	 * Only allowed when there's the flag attach_disconnected and/or
	 * attach_disconnected.path is defined.
	 */
	rc = get_unix_clientfd(socket_put_old);

out:
	free(tmp);
	free(socket_put_old);

	exit(rc);
}

static pid_t _clone(int (*fn)(void *), void *arg)
{
	size_t stack_size = sysconf(_SC_PAGESIZE);
	void *stack = alloca(stack_size);

#ifdef __ia64__
	return __clone2(fn, stack,  stack_size,
			CLONE_NEWNS | SIGCHLD, arg);
#else
	return    clone(fn, stack + stack_size,
			CLONE_NEWNS | SIGCHLD, arg);
#endif
}

int main(int argc, char **argv)
{
	struct clone_arg arg;
	pid_t child;
	int child_status, rc;

	if (argc != 5) {
		fprintf(stderr,
			"FAIL - usage: %s <UNIX_SOCKET_PATH> <DISK_IMG> <NEW_ROOT> <PUT_OLD>\n\n"
			"  <UNIX_SOCKET_PATH>\tThe path of the unix socket the server will connect to\n"
			"  <DISK_IMG>\t\tThe loop device pointing to the disk image\n"
			"  <NEW_ROOT>\t\tThe new_root param of pivot_root()\n"
			"  <PUT_OLD>\t\tThe put_old param of pivot_root()\n\n"
			"This program clones itself in a new mount namespace, \n"
			"does a pivot and then connects to the <UNIX_SOCKET_PATH>.\n"
			"The test fails if the program does not have attach_disconnected\n"
			"permission to access the unix_socket which is disconnected.\n", argv[0]);
		exit(1);
	}

	arg.socket   = argv[1];
	arg.disk_img = argv[2];
	arg.new_root = argv[3];
	arg.put_old  = argv[4];

	child = _clone(pivot_and_get_unix_clientfd, &arg);
	if (child < 0) {
		perror("FAIL - clone");
		exit(2);
	}

	rc = waitpid(child, &child_status, 0);
	if (rc < 0) {
		perror("FAIL - waitpid");
		exit(3);
	} else if (!WIFEXITED(child_status)) {
		fprintf(stderr, "FAIL - child didn't exit\n");
		exit(4);
	} else if (WEXITSTATUS(child_status)) {
		/* The child has already printed a FAIL message */
		exit(WEXITSTATUS(child_status));
	}

	printf("PASS\n");
	exit(0);
}
