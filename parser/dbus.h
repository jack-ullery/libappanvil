/*
 *   Copyright (c) 2013
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

#ifndef __AA_DBUS_H
#define __AA_DBUS_H

#include "parser.h"

struct dbus_entry {
	char *bus;
	/**
	 * Be careful! ->name can be the subject or the peer name, depending on
	 * whether the rule is a bind rule or a send/receive rule. See the
	 * comments in new_dbus_entry() for details.
	 */
	char *name;
	char *peer_label;
	char *path;
	char *interface;
	char *member;
	int mode;
	int audit;
	int deny;

	struct dbus_entry *next;
};

void free_dbus_entry(struct dbus_entry *ent);
struct dbus_entry *new_dbus_entry(int mode, struct cond_entry *conds,
				  struct cond_entry *peer_conds);
struct dbus_entry *dup_dbus_entry(struct dbus_entry *ent);
void print_dbus_entry(struct dbus_entry *ent);

#endif /* __AA_DBUS_H */
