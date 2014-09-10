/*
 * Copyright (C) 2013 Canonical, Ltd.
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

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <sys/un.h>
#include <unistd.h>

#define MSG_BUF_MAX	1024

static int connection_based_messaging(int sock)
{
	char msg_buf[MSG_BUF_MAX];
	int rc;

	rc = read(sock, msg_buf, MSG_BUF_MAX);
	if (rc < 0) {
		perror("FAIL CLIENT - read");
		return 1;
	}

	rc = write(sock, msg_buf, rc);
	if (rc < 0) {
		perror("FAIL CLIENT - write");
		return 1;
	}

	return 0;
}

static int connectionless_messaging(int sock)
{
	struct sockaddr_un addr;
	char msg_buf[MSG_BUF_MAX];
	int rc;

	addr.sun_family = AF_UNIX;
	rc = bind(sock, (struct sockaddr *)&addr, sizeof(sa_family_t));
	if (rc < 0) {
		perror("FAIL CLIENT - bind");
		return 1;
	}

	rc = write(sock, NULL, 0);
	if (rc < 0) {
		perror("FAIL CLIENT - write");
		return 1;
	}

	rc = read(sock, msg_buf, MSG_BUF_MAX);
	if (rc < 0) {
		perror("FAIL CLIENT - read");
		return 1;
	}

	rc = write(sock, msg_buf, rc);
	if (rc < 0) {
		perror("FAIL CLIENT - write");
		return 1;
	}

	return 0;
}

int main(int argc, char *argv[])
{
	struct sockaddr_un peer_addr;
	const char *sun_path;
	size_t sun_path_len;
	int sock, type, rc;

	if (argc != 3) {
		fprintf(stderr, "Usage: %s <socket> <type>\n\n"
			"  type\t\tstream, dgram, or seqpacket\n",
			argv[0]);
		exit(1);
	}

	peer_addr.sun_family = AF_UNIX;
	memset(peer_addr.sun_path, 0, sizeof(peer_addr.sun_path));

	sun_path = argv[1];
	sun_path_len = strlen(sun_path);
	if (sun_path[0] == '@') {
		memcpy(peer_addr.sun_path, sun_path, sun_path_len);
		peer_addr.sun_path[0] = '\0';
		sun_path_len = sizeof(peer_addr.sun_path);
	} else {
		memcpy(peer_addr.sun_path, sun_path, sun_path_len + 1);
	}

	if (!strcmp(argv[2], "stream")) {
		type = SOCK_STREAM;
	} else if (!strcmp(argv[2], "dgram")) {
		type = SOCK_DGRAM;
	} else if (!strcmp(argv[2], "seqpacket")) {
		type = SOCK_SEQPACKET;
	} else {
		fprintf(stderr, "FAIL CLIENT - bad socket type: %s\n", argv[2]);
		exit(1);
	}

	sock = socket(AF_UNIX, type, 0);
	if (sock < 0) {
		perror("FAIL CLIENT - socket");
		exit(1);
	}

	rc = connect(sock, (struct sockaddr *)&peer_addr,
		     sun_path_len + sizeof(peer_addr.sun_family));
	if (rc < 0) {
		perror("FAIL CLIENT - connect");
		exit(1);
	}

	rc = (type == SOCK_STREAM || type == SOCK_SEQPACKET) ?
		connection_based_messaging(sock) :
		connectionless_messaging(sock);
	if (rc)
		exit(1);

	exit(0);
}
