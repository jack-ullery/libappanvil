/*
 *   Copyright (c) 1999, 2000, 2001, 2002, 2003, 2004, 2005, 2006, 2007
 *   NOVELL (All rights reserved)
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


static int file_comp(const void *c1, const void *c2)
{
	struct cod_entry **e1, **e2;
	e1 = (struct cod_entry **)c1;
	e2 = (struct cod_entry **)c2;
	int res = 0;

	//PERROR("strcmp %s %s\n", (*e1)->name, (*e2)->name);
	if ((*e1)->namespace) {
		if ((*e2)->namespace)
			res = strcmp((*e1)->namespace, (*e2)->namespace);
		else
			return 1;
	} else if ((*e2)->namespace) {
		return -1;
	}
	if (res)
		return res;

	if ((*e1)->link_name) {
		if ((*e2)->link_name)
			res = strcmp((*e1)->link_name, (*e2)->link_name);
		else
			return 1;
	} else if ((*e2)->link_name) {
		return -1;
	}
	if (res)
		return res;

	if ((*e1)->link_name)
		res = (*e2)->subset - (*e1)->subset;
	if (res)
		return res;

	if ((*e1)->deny != (*e2)->deny)
		return (*e1)->deny < (*e2)->deny ? -1 : 1;

	/* rules with ptrace and change_profile can only merge with
	 * rules with exact same perm */
	if (((*e1)->mode & (AA_CHANGE_PROFILE | AA_PTRACE_PERMS)) !=
	    ((*e2)->mode & (AA_CHANGE_PROFILE | AA_PTRACE_PERMS)))
		return 1;

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


	/* walk the sorted table merging similar entries */
	for (cur = table[0], next = table[1], n = 1; next != NULL; n++, next = table[n]) {
		if (file_comp(&cur, &next) == 0) {
			/* check for merged x consistency */
			if (!is_merged_x_consistent(cur->mode, next->mode)) {
				PERROR(_("profile %s: has merged rule %s with "
					 "conflicting x modifiers\n"),
					 cod->name, cur->name);
				free(table);
				return 0;
			}
//if (next->audit)
//fprintf(stderr, "warning: merging rule 0x%x %s\n", next->audit, next->name);
			cur->mode |= next->mode;
			cur->audit |= next->audit;
			next->next = NULL;
			free_cod_entries(next);
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

int codomain_merge_rules(struct codomain *cod)
{
	if (!process_file_entries(cod))
		goto fail;

	/* XXX  return error from this */
	merge_hat_rules(cod);

	return 1;
fail:
	return 0;
}
