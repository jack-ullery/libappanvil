/* $Id$ */

/*
 *   Copyright (c) 1999, 2000, 2002, 2003, 2004, 2005 NOVELL (All rights reserved)
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

#define _GNU_SOURCE	/* for strndup */
#include <stdio.h>
#include <stdlib.h>
#include <stdarg.h>
#include <search.h>
#include <string.h>
#include <libintl.h>
#define _(s) gettext(s)

#include "parser.h"
#include "parser_yacc.h"

/* #define DEBUG */
#ifdef DEBUG
#define PDEBUG(fmt, args...) printf("Lexer: " fmt, ## args)
#else
#define PDEBUG(fmt, args...)	/* Do nothing */
#endif
#define NPDEBUG(fmt, args...)	/* Do nothing */

void *policy_list = NULL;

static int codomain_compare(const void *a, const void *b)
{
	return strcmp(((struct codomain *) a)->name,
		      ((struct codomain *) b)->name);
}

void add_to_list(struct codomain *codomain)
{
	struct codomain **result;

	result = (struct codomain **) tsearch(codomain, &policy_list, codomain_compare);
	if (!result) {
		PERROR("Memory allocation error\n");
		exit(1);
	}

	if (*result != codomain) {
		PERROR("Multiple definitions for profile %s exist,"
		       "bailing out.\n", codomain->name);
		exit(1);
	}
}

void add_hat_to_policy(struct codomain *cod, struct codomain *hat)
{
	struct codomain **result;

	result = (struct codomain **) tsearch(hat, &(cod->hat_table), codomain_compare);
	if (!result) {
		PERROR("Memory allocation error\n");
		exit(1);
	}

	if (*result != hat) {
		PERROR("Multiple definitions for hat %s in profile %s exist,"
		       "bailing out.\n", hat->name, cod->name);
		exit(1);
	}
}

void add_entry_to_policy(struct codomain *cod, struct cod_entry *entry)
{
	entry->next = cod->entries;
	cod->entries = entry;
}

void add_netrule_to_policy(struct codomain *cod, struct cod_net_entry *net_entry)
{
	net_entry->next = cod->net_entries;
	cod->net_entries = net_entry;
}

static void __merge_rules(const void *nodep, const VISIT value,
			  const int __unused depth)
{
	struct codomain **t = (struct codomain **) nodep;

	if (value == preorder || value == endorder)
		return;

	if (!codomain_merge_rules(*t)) {
		PERROR(_("ERROR merging rules for profile %s, failed to load\n"),
		       (*t)->name);
		exit(1);
	}
}

int post_merge_rules(void)
{
	twalk(policy_list, __merge_rules);
	return 0;
}

int merge_hat_rules(struct codomain *cod)
{
	twalk(cod->hat_table, __merge_rules);
	return 0;
}

int die_if_any_regex(void);
static int die_if_any_hat_regex(struct codomain *cod);
static int any_regex_entries(struct cod_entry *entry_list);

/* only call if regex is not allowed */
static void __any_regex(const void *nodep, const VISIT value,
		        const int __unused depth)
{
	struct codomain **t = (struct codomain **) nodep;

	if (value == preorder || value == endorder)
		return;

	if (any_regex_entries((*t)->entries)) {
		PERROR(_("ERROR profile %s contains policy elements not usable with this kernel:\n"
			 "\t'*', '?', character ranges, and alternations are not allowed.\n"
			 "\t'**' may only be used at the end of a rule.\n"),
			(*t)->name);
		exit(1);
	}

	die_if_any_hat_regex(*t);
}

/* only call if regex is not allowed */
int die_if_any_regex(void)
{
	twalk(policy_list, __any_regex);
	return 0;
}

/* only call if regex is not allowed */
static int die_if_any_hat_regex(struct codomain *cod)
{
	twalk(cod->hat_table, __any_regex);
	return 0;
}

static int any_regex_entries(struct cod_entry *entry_list)
{
	struct cod_entry *entry;

	for (entry = entry_list; entry; entry = entry->next) {
		if (entry->pattern_type == ePatternRegex)
			return TRUE;
	}

	return FALSE;
}

static void __process_regex(const void *nodep, const VISIT value,
			    const int __unused depth)
{
	struct codomain **t = (struct codomain **) nodep;

	if (value == preorder || value == endorder)
		return;

	if (process_regex(*t) != 0) {
		PERROR(_("ERROR processing regexs for profile %s, failed to load\n"),
		       (*t)->name);
		exit(1);
	}
}

int post_process_regex(void)
{
	twalk(policy_list, __process_regex);
	return 0;
}

int process_hat_regex(struct codomain *cod)
{
	twalk(cod->hat_table, __process_regex);
	return 0;
}

static void __process_variables(const void *nodep, const VISIT value,
				const int __unused depth)
{
	struct codomain **t = (struct codomain **) nodep;

	if (value == preorder || value == endorder)
		return;

	if (process_variables(*t) != 0) {
		PERROR(_("ERROR expanding variables for profile %s, failed to load\n"),
		       (*t)->name);
		exit(1);
	}
}

int post_process_variables(void)
{
	twalk(policy_list, __process_variables);
	return 0;
}

int process_hat_variables(struct codomain *cod)
{
	twalk(cod->hat_table, __process_variables);
	return 0;
}

/* Yuck, is their no other way to pass arguments to a twalk action */
static int __load_option;

static void __load_policy(const void *nodep, const VISIT value,
			  const int __unused depth)
{
	struct codomain **t = (struct codomain **) nodep;

	if (value == preorder || value == endorder)
		return;

	if (load_codomain(__load_option, *t) != 0) {
		exit(1);
	}
}

int load_policy(int option)
{
	__load_option = option;
	twalk(policy_list, __load_policy);
	return 0;
}

/* Yuck, is their no other way to pass arguments to a twalk action */
static sd_serialize *__p;

static void __load_hat(const void *nodep, const VISIT value,
		       const int __unused depth)
{
	struct codomain **t = (struct codomain **) nodep;

	if (value == preorder || value == endorder)
		return;

	if (!sd_serialize_profile(__p, *t)) {
		PERROR(_("ERROR in profile %s, failed to load\n"),
		       (*t)->name);
		exit(1);
	}
}

int load_hats(sd_serialize *p, struct codomain *cod)
{
	__p = p;
	twalk(cod->hat_table, __load_hat);
	return 0;
}

static void __dump_policy(const void *nodep, const VISIT value,
			  const int __unused depth)
{
	struct codomain **t = (struct codomain **) nodep;

	if (value == preorder || value == endorder)
		return;

	debug_cod_list(*t);
}

void dump_policy(void)
{
	twalk(policy_list, __dump_policy);
}

void dump_policy_hats(struct codomain *cod)
{
	twalk(cod->hat_table, __dump_policy);
}

/* Gar */
static struct codomain *__dump_policy_name;

static void __dump_policy_hatnames(const void *nodep, const VISIT value,
				const int __unused depth)
{
	struct codomain **t = (struct codomain **) nodep;

	if (value == preorder || value == endorder)
		return;

	printf("%s^%s\n", __dump_policy_name->name, (*t)->sub_name);
}

void dump_policy_hatnames(struct codomain *cod)
{
	__dump_policy_name = cod;
	twalk(cod->hat_table, __dump_policy_hatnames);
}

static void __dump_policy_names(const void *nodep, const VISIT value,
				const int __unused depth)
{
	struct codomain **t = (struct codomain **) nodep;

	if (value == preorder || value == endorder)
		return;

	printf("%s\n", (*t)->name);
	dump_policy_hatnames(*t);
}

void dump_policy_names(void)
{
	twalk(policy_list, __dump_policy_names);
}

/* gar, more global arguments */
struct codomain *__hat_merge_policy;

static void __merge_hat(const void *nodep, const VISIT value,
			const int __unused depth)
{
	struct codomain **t = (struct codomain **) nodep;

        if (value == preorder || value == endorder)
		return;
	add_hat_to_policy(__hat_merge_policy, (*t));
}

/* merge_hats: merges hat_table into hat_table owned by cod */
static void merge_hats(struct codomain *cod, void *hats)
{
	__hat_merge_policy = cod;
	twalk(hats, __merge_hat);
}

/* don't want to free the hat entries in the table, as they were pushed
 * onto the other table. */
static void empty_destroy(void __unused *nodep)
{
	return;
}

struct codomain *merge_policy(struct codomain *a, struct codomain *b)
{
	struct codomain *ret = a;
	struct cod_entry *last;
	struct cod_net_entry *lastnet;
	if (!a) {
		ret = b;
		goto out;
	}
	if (!b)
		goto out;

	if (a->name || b->name) {
                PERROR("ASSERT: policy merges shouldn't have names %s %s\n",
		       a->name ? a->name : "",
		       b->name ? b->name : "");
		exit(1);
	}

	if (a->entries) {
		for (last = a->entries; last->next; last = last->next)
			/* do nothing */ ;
		last->next = b->entries;
	} else {
		a->entries = b->entries;
	}
	b->entries = NULL;

	if (a->net_entries) {
		for (lastnet = a->net_entries; lastnet->next; lastnet = lastnet->next)
			/* do nothing */ ;
		lastnet->next = b->net_entries;
	} else {
		a->net_entries = b->net_entries;
	}
	b->net_entries = NULL;

	a->flags.complain = a->flags.complain || b->flags.complain;
	a->flags.audit = a->flags.audit || b->flags.audit;

	a->capabilities = a->capabilities | b->capabilities;
	merge_hats(a, b->hat_table);
	tdestroy(b->hat_table, &empty_destroy);
	b->hat_table = NULL;

	free_policy(b);
out:
	return ret;
}

int post_process_policy(void)
{
	int retval = 0;

	retval = post_merge_rules();
	if (retval != 0) {
		PERROR(_("%s: Errors found in combining rules postprocessing. Aborting.\n"),
		       progname);
		return -1;
	}

	retval = post_process_variables();
	if (retval != 0) {
		PERROR(_("%s: Errors found during regex postprocess.  Aborting.\n"),
		       progname);
		return retval;
	}

	retval = post_process_regex();
	if (retval != 0) {
		PERROR(_("%s: Errors found during regex postprocess.  Aborting.\n"),
		       progname);
		return retval;
	}

	return retval;
}

void free_hat_entry(void *nodep)
{
	struct codomain *t = (struct codomain *)nodep;
	free_policy(t);
}

void free_hat_table(void *hat_table)
{
	if (hat_table)
		tdestroy(hat_table, &free_hat_entry);
}

void free_policy(struct codomain *cod)
{
	if (!cod)
		return;
	free_hat_table(cod->hat_table);
	free_cod_entries(cod->entries);
	free_net_entries(cod->net_entries);
	if (cod->dfarules)
		aare_delete_ruleset(cod->dfarules);
	if (cod->dfa)
		free(cod->dfa);
	free(cod);
}
