/*
 *   Copyright (c) 2014
 *   Canonical, Ltd. (All rights reserved)
 *
 *   This program is free software; you can redistribute it and/or
 *   modify it under the terms of version 2 of the GNU General Public
 *   License published by the Free Software Foundation.
 *
 *   This program is distributed in the hope that it will be useful,
 *   but WITHOUT ANY WARRANTY; without even the implied warranty of
 *   MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 *   GNU General Public License for more details.
 *
 *   You should have received a copy of the GNU General Public License
 *   along with this program; if not, contact Novell, Inc. or Canonical
 *   Ltd.
 */

#ifndef __AA_NETWORK_H
#define __AA_NETWORK_H

#include <fcntl.h>
#include <netinet/in.h>
#include <linux/socket.h>
#include <linux/limits.h>
#include <arpa/inet.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <libintl.h>

#include "parser.h"
#include "rule.h"
#include "profile.h"

/* supported AF protocols */
struct aa_network_entry {
	unsigned int family;
	unsigned int type;
	unsigned int protocol;

	struct aa_network_entry *next;
};

extern struct aa_network_entry *new_network_ent(unsigned int family,
						unsigned int type,
						unsigned int protocol);
extern struct aa_network_entry *network_entry(const char *family,
					      const char *type,
					      const char *protocol);
extern size_t get_af_max(void);

void __debug_network(unsigned int *array, const char *name);

struct network {
	unsigned int *allow;		/* array of type masks
						 * indexed by AF_FAMILY */
	unsigned int *audit;
	unsigned int *deny;
	unsigned int *quiet;

	network(void) { allow = audit = deny = quiet = NULL; }

	void dump(void) {
		if (allow)
			__debug_network(allow, "Network");
		if (audit)
			__debug_network(audit, "Audit Net");
		if (deny)
			__debug_network(deny, "Deny Net");
		if (quiet)
			__debug_network(quiet, "Quiet Net");
	}
};

#endif /* __AA_NETWORK_H */
