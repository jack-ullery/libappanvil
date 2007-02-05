/* $Id: parser_merge.c 86 2006-08-04 18:20:16Z jrjohansen $ */

/*
 *   Copyright (c) 1999, 2000, 2003, 2004, 2005 NOVELL (All rights reserved)
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
 *   along with this program; if not, contact Novell, Inc.
 */

#include <linux/unistd.h>

#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <errno.h>
#include <libintl.h>
#define _(s) gettext(s)

#include "parser.h"


static inline int count_net_entries(struct codomain *cod)
{
	struct cod_net_entry *list;
	int count = 0;
	for (list = cod->net_entries; list; list = list->next)
		count++;
	return count;
}

static int file_comp(const void *c1, const void *c2)
{
	struct cod_entry **e1, **e2;
	e1 = (struct cod_entry **)c1;
	e2 = (struct cod_entry **)c2;
	//PERROR("strcmp %s %s\n", (*e1)->name, (*e2)->name);
	return strcmp((*e1)->name, (*e2)->name);
}

static int process_file_entries(struct codomain *cod)
{
	int n, count;
	struct cod_entry *flist, *cur, *next;
	struct cod_entry **table;

	for (flist = cod->entries, n = 0; flist; flist = flist->next)
		n++;

	count = n;
	if (count < 2)
		return 1;

	table = malloc(sizeof(struct cod_entry *) * (count + 1));
	if (!table) {
		PERROR(_("Couldn't merge entries. Out of Memory\n"));
		return 0;
	}

	n = 0;
	for (flist = cod->entries; flist; flist = flist->next) {
		table[n] = flist;
		n++;
	}

	qsort(table, count, sizeof(struct cod_entry *), file_comp);
	table[count] = NULL;

#define CHECK_CONFLICT_UNSAFE(a, b) \
	((HAS_EXEC_UNSAFE(a) ^ HAS_EXEC_UNSAFE(b)) && \
	 ((HAS_EXEC_PROFILE(a) && HAS_EXEC_PROFILE(b)) || \
	  (HAS_EXEC_UNCONSTRAINED(a) && HAS_EXEC_UNCONSTRAINED(b))))

	/* walk the sorted table merging similar entries */
	for (cur = table[0], next = table[1], n = 1; next != NULL; n++, next = table[n]) {
		if (file_comp(&cur, &next) == 0) {
			int conflict = CHECK_CONFLICT_UNSAFE(cur->mode, next->mode);
			cur->mode |= next->mode;
			/* check for merged x consistency */
			if (HAS_MAY_EXEC(cur->mode) &&
			    ((KERN_EXEC_MODIFIERS(cur->mode) &
			      (KERN_EXEC_MODIFIERS(cur->mode) - 1)) ||
			     conflict)) {
				PERROR(_("profile %s: has merged rule %s with multiple x modifiers\n"),
				       cod->name, cur->name);
				return 0;
			}
			free(next->name);
			free(next);
			table[n] = NULL;
		} else {
			cur = next;
		}
	}

	/* rebuild the file_entry chain */
	cur = table[0];
	for (n = 1; n < count; n++) {
		if (table[n] != NULL) {
			cur->next = table[n];
			cur = table[n];
		}
	}
	cur->next = NULL;
	cod->entries = table[0];

	free(table);

	return 1;
}

static int process_net_entries(struct codomain __unused *cod)
{
	return 1;
}

int codomain_merge_rules(struct codomain *cod)
{
	if (!process_file_entries(cod))
		goto fail;
	if (!process_net_entries(cod))
		goto fail;

	/* XXX  return error from this */
	merge_hat_rules(cod);

	return 1;
fail:
	return 0;
}
