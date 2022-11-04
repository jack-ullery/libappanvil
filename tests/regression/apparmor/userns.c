/*
 * Copyright (C) 2022 Canonical, Ltd.
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
#include <sched.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <stdio.h>
#include <stdlib.h>

static int child(void *arg)
{
	printf("PASS\n");
	return EXIT_SUCCESS;
}

#define STACK_SIZE (1024 * 1024)
static char child_stack[STACK_SIZE];

int main(int argc, char *argv[])
{
	pid_t child_pid;
	int child_exit;

	child_pid = clone(child, child_stack + STACK_SIZE,
			  CLONE_NEWUSER | SIGCHLD, NULL);
	if (child_pid == -1) {
		perror("FAIL - clone");
		return EXIT_FAILURE;
	}

	if (waitpid(child_pid, &child_exit, 0) == -1) {
		perror("FAIL - waitpid");
		return EXIT_FAILURE;
	}

	if (WIFEXITED(child_exit)) {
		if (WEXITSTATUS(child_exit) != EXIT_SUCCESS) {
			fprintf(stderr, "FAIL - child ended with failure %d\n", child_exit);
			return EXIT_FAILURE;
		}
	}

	printf("PASS\n");
	return EXIT_SUCCESS;
}
