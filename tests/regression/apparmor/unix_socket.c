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

#include <poll.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <sys/un.h>
#include <unistd.h>

#define MSG_BUF_MAX 1024

static int connection_based_messaging(int sock, char *msg_buf,
				      size_t msg_buf_len)
{
	int peer_sock, rc;

	peer_sock = accept(sock, NULL, NULL);
	if (peer_sock < 0) {
		perror("FAIL - accept");
		return 1;
	}

	rc = write(peer_sock, msg_buf, msg_buf_len);
	if (rc < 0) {
		perror("FAIL - write");
		return 1;
	}

	rc = read(peer_sock, msg_buf, msg_buf_len);
	if (rc < 0) {
		perror("FAIL - read");
		return 1;
	}

	return 0;
}

static int connectionless_messaging(int sock, char *msg_buf, size_t msg_buf_len)
{
	struct sockaddr_un peer_addr;
	socklen_t peer_addr_len = sizeof(peer_addr);
	int rc;

	peer_addr.sun_family = AF_UNIX;
	rc = recvfrom(sock, NULL, 0, 0, (struct sockaddr *)&peer_addr,
		      &peer_addr_len);
	if (rc < 0) {
		perror("FAIL - recvfrom");
		return 1;
	}

	rc = sendto(sock, msg_buf, msg_buf_len, 0,
		    (struct sockaddr *)&peer_addr, peer_addr_len);
	if (rc < 0) {
		perror("FAIL - sendto");
		return 1;
	}

	rc = recv(sock, msg_buf, msg_buf_len, 0);
	if (rc < 0) {
		perror("FAIL - recv");
		return 1;
	}

	return 0;
}

int main (int argc, char *argv[])
{
	struct sockaddr_un addr;
	struct pollfd pfd;
	char msg_buf[MSG_BUF_MAX];
	size_t msg_buf_len;
	const char *sun_path;
	size_t sun_path_len;
	pid_t pid;
	int sock, type, rc;

	if (argc != 5) {
		fprintf(stderr,
			"Usage: %s <socket> <type> <message> <client>\n\n"
			"  socket\t\ta path for a bound socket or a name prepended with '@' for an abstract socket\n"
			"  type\t\tstream, dgram, or seqpacket\n",
			argv[0]);
		exit(1);
	}

	addr.sun_family = AF_UNIX;
	memset(addr.sun_path, 0, sizeof(addr.sun_path));

	sun_path = argv[1];
	sun_path_len = strlen(sun_path);
	if (sun_path[0] == '@') {
		memcpy(addr.sun_path, sun_path, sun_path_len);
		addr.sun_path[0] = '\0';
		sun_path_len = sizeof(addr.sun_path);
	} else {
		memcpy(addr.sun_path, sun_path, sun_path_len + 1);
	}

	if (!strcmp(argv[2], "stream")) {
		type = SOCK_STREAM;
	} else if (!strcmp(argv[2], "dgram")) {
		type = SOCK_DGRAM;
	} else if (!strcmp(argv[2], "seqpacket")) {
		type = SOCK_SEQPACKET;
	} else {
		fprintf(stderr, "FAIL - bad socket type: %s\n", argv[2]);
		exit(1);
	}

	msg_buf_len = strlen(argv[3]) + 1;
	if (msg_buf_len > MSG_BUF_MAX) {
		fprintf(stderr, "FAIL - message too big\n");
		exit(1);
	}
	memcpy(msg_buf, argv[3], msg_buf_len);

	sock = socket(AF_UNIX, type | SOCK_CLOEXEC, 0);
	if (sock == -1) {
		perror("FAIL - socket");
		exit(1);
	}

	rc = bind(sock, (struct sockaddr *)&addr,
		  sun_path_len + sizeof(addr.sun_family));
	if (rc < 0) {
		perror("FAIL - bind");
		exit(1);
	}

	if (type & SOCK_STREAM || type & SOCK_SEQPACKET) {
		rc = listen(sock, 2);
		if (rc < 0) {
			perror("FAIL - listen");
			exit(1);
		}
	}

	pid = fork();
	if (pid < 0) {
		perror("FAIL - fork");
		exit(1);
	} else if (!pid) {
		execl(argv[4], argv[4], sun_path, argv[2], NULL);
		exit(0);
	}

	pfd.fd = sock;
	pfd.events = POLLIN;
	rc = poll(&pfd, 1, 500);
	if (rc < 0) {
		perror("FAIL - poll");
		exit(1);
	} else if (!rc) {
		fprintf(stderr, "FAIL - poll timed out\n");
		exit(1);
	}

	rc = (type & SOCK_STREAM || type & SOCK_SEQPACKET) ?
		connection_based_messaging(sock, msg_buf, msg_buf_len) :
		connectionless_messaging(sock, msg_buf, msg_buf_len);
	if (rc)
		exit(1);

	if (memcmp(argv[3], msg_buf, msg_buf_len)) {
		msg_buf[msg_buf_len] = '\0';
		fprintf(stderr, "FAIL - buffer comparison. Got \"%s\", expected \"%s\"\n",
			msg_buf, argv[3]);
		exit(1);
	}

	printf("PASS\n");
	exit(0);
}
