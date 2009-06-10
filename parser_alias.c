/*	 $Id: parser_symtab.c 565 2007-04-11 09:12:51Z jrjohansen $ 	*/

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

#define _GNU_SOURCE	/* for tdestroy(3) */
#include <search.h>
#include <stdlib.h>
#include <stdarg.h>
#include <string.h>
#include <errno.h>
#include <libintl.h>
#define _(s) gettext(s)

#include "immunix.h"
#include "parser.h"

struct alias_rule {
	char *from;
	char *to;
};

static void *alias_table;

static int compare_alias(const void *a, const void *b)
{
	char *a_name = ((struct alias_rule *) a)->from;
	char *b_name = ((struct alias_rule *) b)->from;
	return strcmp(a_name, b_name);
}

static struct alias_rule *lookup_alias(const char *alias)
{
	struct alias_rule tmp = { alias, NULL} , **lookup;

	lookup = (struct alias_rule **) tfind(&tmp, alias_table, (comparison_fn_t) &compare_alias);
	if (!lookup)
		return NULL;

	return *lookup;
}

int new_alias(const char *from, const char *to)
{
	struct alias_rule *alias, **result;

	alias = malloc(sizeof(struct alias_rule));
	if (!alias) {
		PERROR("Failed to allocate memory: %s\n", strerror(errno));
		goto fail;
	}
	memset(alias, 0, sizeof(*alias));
	alias->from = strdup(from);
	if (!alias->from) {
		PERROR("Failed to allocate memory: %s\n", strerror(errno));
		goto fail;
	}
	alias->to = strdup(to);
	if (!alias->to) {
		PERROR("Failed to allocate memory: %s\n", strerror(errno));
		goto fail;
	}

	result = (struct alias_rule **) tsearch(alias, &alias_table, (comparison_fn_t) &compare_alias);
	if (!result) {
		PERROR("Failed to allocate memory: %s\n", strerror(errno));
		goto fail;
	}

	if (*result != alias) {
		/* already existing alias */
		PERROR("'%s' is already defined\n", from);
		goto fail;
	}

	return 1;

fail:
	if (alias) {
		if (alias->from)
			free(alias->from);
		if (alias->to)
			free(alias->to);
		free(alias);
	}
	return 0;
}

static char *do_alias(struct alias_rule *alias, const char *target)
{
	int len = strlen(target) - strlen(alias->from) + strlen(alias->to);
	char *new = malloc(len + 1);
	if (!new) {
		PERROR("Failed to allocate memory: %s\n", strerror(errno));
		return NULL;
	}
	sprintf(new, "%s%s", alias->to, target + strlen(alias->from));
//fprintf(stderr, "replaced alias: from: %s, to: %s, name: %s\n  %s\n", alias->from, alias->to, target, new);
	return new;
}

static struct cod_entry *target_list;
static void process_entries(const void *nodep, VISIT value, int __unused level)
{
	struct alias_rule **t = (struct alias_rule **) nodep;
	struct cod_entry *entry;
	int len;

	if (value == preorder || value == endorder)
		return;

	len = strlen((*t)->from);

	list_for_each(target_list, entry) {
		if (entry->mode & (AA_SHARED_PERMS & AA_PTRACE_PERMS))
			continue;
		if (entry->name && strncmp((*t)->from, entry->name, len) == 0) {
			char *new = do_alias(*t, entry->name);
			if (!new)
				return;
			free(entry->name);
			entry->name = new;
		}
		if (entry->link_name &&
		    strncmp((*t)->from, entry->link_name, len) == 0) {
			char *new = do_alias(*t, entry->link_name);
			if (!new)
				return;
			free(entry->link_name);
			entry->link_name = new;
		}
	}
}

static struct codomain *target_cod;
static void process_name(const void *nodep, VISIT value, int __unused level)
{
	struct alias_rule **t = (struct alias_rule **) nodep;
	struct codomain *cod = target_cod;
	int len;

	if (value == preorder || value == endorder)
		return;

	len = strlen((*t)->from);

	if (cod->name && strncmp((*t)->from, cod->name, len) == 0) {
		char *new = do_alias(*t, cod->name);
		if (!new)
			return;
		free(cod->name);
		cod->name = new;
	}
}

void replace_aliases(struct codomain *cod)
{
	target_cod = cod;
	twalk(alias_table, process_name);

	if (cod->entries) {
		target_list = cod->entries;
		twalk(alias_table, process_entries);
	}
}

static void free_alias(void *nodep)
{
	struct alias_rule *t = (struct alias_rule *)nodep;
	free(t->from);
	free(t->to);
	free(t);
}

void free_aliases(void)
{
	if (alias_table)
		tdestroy(alias_table, &free_alias);
}
