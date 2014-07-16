/*
 * Copyright (C) 2014 Canonical, Ltd.
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

#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/apparmor.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <unistd.h>

#define NO_MODE	"(null)"

#define ENV_FD0	"_SOCKETPAIR_FD0"
#define ENV_FD1	"_SOCKETPAIR_FD1"

static int get_socketpair(int pair[2])
{
	char *fd0, *fd1;

	fd0 = getenv(ENV_FD0);
	fd1 = getenv(ENV_FD1);

	if (fd0 && fd1) {
		pair[0] = atoi(fd0);
		pair[1] = atoi(fd1);
	} else {
		if (socketpair(AF_UNIX, SOCK_STREAM, 0, pair) < 0) {
			perror("FAIL - socketpair");
			return 1;
		}
	}

	return 0;
}

static int verify_confinement_context(int fd, const char *fd_name,
				      const char *expected_con,
				      const char *expected_mode)
{
	char *con, *mode;
	int rc;

	rc = aa_getpeercon(fd, &con, &mode);
	if (rc < 0) {
		fprintf(stderr, "FAIL - %s: aa_getpeercon(%d, , ): %m",
			fd_name, fd);
		return 1;
	}

	if (!mode)
		mode = NO_MODE;

	if (strcmp(con, expected_con)) {
		fprintf(stderr,
			"FAIL - %s: con \"%s\" != expected_con \"%s\"\n",
			fd_name, con, expected_con);
		rc = 2;
		goto out;
	}

	if (strcmp(mode, expected_mode)) {
		fprintf(stderr,
			"FAIL - %s: mode \"%s\" != expected_mode \"%s\"\n",
			fd_name, mode, expected_mode);
		rc = 3;
		goto out;
	}

	rc = 0;
out:
	free(con);
	return rc;
}

static int reexec(int pair[2], int argc, char **argv)
{
	char *new_profile;
	char fd_str[32];

	/* Less than 4 arguments means that no <CHANGE_ONEXEC> args exist */
	if (argc < 4)
		return 0;

	/**
	 * Save off the first <CHANGE_ONEXEC> arg and then shift all preceeding
	 * args by one to effectively pop off the first <CHANGE_ONEXEC>
	 */
	new_profile = argv[3];
	argv[3] = argv[2];
	argv[2] = argv[1];
	argv[1] = argv[0];
	argv++;

	if (aa_change_onexec(new_profile) < 0) {
		perror("FAIL - aa_change_onexec");
		return 1;
	}

	snprintf(fd_str, sizeof(fd_str), "%d", pair[0]);
	if (setenv(ENV_FD0, fd_str, 1) < 0) {
		perror("FAIL - setenv");
		return 2;
	}

	snprintf(fd_str, sizeof(fd_str), "%d", pair[1]);
	if (setenv(ENV_FD1, fd_str, 1) < 0) {
		perror("FAIL - setenv");
		return 3;
	}

	execv(argv[0], argv);

	perror("FAIL - execv");
	return 4;
}

int main(int argc, char **argv)
{
	char *expected_con, *expected_mode;
	int pair[2], rc;

	if (argc < 3) {
		fprintf(stderr,
			"FAIL - usage: %s <CON> <MODE> [<CHANGE_ONEXEC> ...]\n\n"
			"  <CON>\t\tThe expected confinement context\n"
			"  <MODE>\tThe expected confinement mode\n"
			"  <CHANGE_ONEXEC>\tThe profile to change to on exec\n\n"
			"This program gets a socket pair and then verifies \n"
			"the confinement context and mode of each file \n"
			"descriptor. If there is no expected mode string, \n"
			"<MODE> should be \"%s\".\n\n"
			"Multiple <CHANGE_ONEXEC> profiles can be specified \n"
			"and the test will run normally for the first pair, \n"
			"then call aa_change_onexec() to rexec itself under \n"
			"the next <CHANGE_ONEXEC> and verify the passed in \n"
			"socket pairs still have the correct labeling.\n" ,
			argv[0], NO_MODE);
		exit(1);
	}

	/**
	 * If ENV_FD0 and ENV_FD1 are set, they'll point to fds that were
	 * passed in. If they're not set, call socketpair().
	 */
	if (get_socketpair(pair))
		exit(2);

	expected_con = argv[1];
	expected_mode = argv[2];

	if (verify_confinement_context(pair[0], "pair[0]",
				       expected_con, expected_mode)) {
		rc = 3;
		goto out;
	}

	if (verify_confinement_context(pair[1], "pair[1]",
				       expected_con, expected_mode)) {
		rc = 4;
		goto out;
	}

	if (reexec(pair, argc, argv)) {
		rc = 5;
		goto out;
	}

	printf("PASS\n");
	rc = 0;
out:
	close(pair[0]);
	close(pair[1]);
	exit(rc);
}

