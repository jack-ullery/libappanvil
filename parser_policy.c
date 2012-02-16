/*
 *   Copyright (c) 1999, 2000, 2001, 2002, 2003, 2004, 2005, 2006, 2007
 *   NOVELL (All rights reserved)
 *
 *   Copyright (c) 2010
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
 *   along with this program; if not, contact Novell, Inc. or Canonical,
 *   Ltd.
 */

#include <stdio.h>
#include <stdlib.h>
#include <stdarg.h>
#include <search.h>
#include <string.h>
#include <libintl.h>
#include <errno.h>
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
	struct codomain *A = (struct codomain *) a;
	struct codomain *B = (struct codomain *) b;

	int res = 0;
	if (A->namespace) {
		if (B->namespace)
			res = strcmp(A->namespace, B->namespace);
		else
			res = -1;
	} else if (B->namespace)
		res = 1;
	if (res)
		return res;
	return strcmp(A->name, B->name);
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

	hat->parent = cod;

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

static int add_named_transition(struct codomain *cod, struct cod_entry *entry)
{
	char *name = NULL;
	int i;

	/* check to see if it is a local transition */
	if (!entry->namespace) {
		char *sub = strstr(entry->nt_name, "//");
		/* does the subprofile name match the rule */

		if (sub && strncmp(cod->name, sub, sub - entry->nt_name) &&
		    strcmp(sub + 2, entry->name) == 0) {
			free(entry->nt_name);
			entry->nt_name = NULL;
			return AA_EXEC_LOCAL >> 10;
		} else if (((entry->mode & AA_USER_EXEC_MODIFIERS) ==
			     SHIFT_MODE(AA_EXEC_LOCAL, AA_USER_SHIFT)) ||
			    ((entry->mode & AA_OTHER_EXEC_MODIFIERS) ==
			     SHIFT_MODE(AA_EXEC_LOCAL, AA_OTHER_SHIFT))) {
			if (strcmp(entry->nt_name, entry->name) == 0) {
				free(entry->nt_name);
				entry->nt_name = NULL;
				return AA_EXEC_LOCAL >> 10;
			}
			/* specified as cix so profile name is implicit */
			name = malloc(strlen(cod->name) + strlen(entry->nt_name)
				      + 3);
			if (!name) {
				PERROR("Memory allocation error\n");
				exit(1);
			}
			sprintf(name, "%s//%s", cod->name, entry->nt_name);
			free(entry->nt_name);
			entry->nt_name = name;
		}
	}
	if (entry->namespace) {
		name = malloc(strlen(entry->namespace) + strlen(entry->nt_name) + 3);
		if (!name) {
			PERROR("Memory allocation error\n");
			exit(1);
		}
		sprintf(name, ":%s:%s", entry->namespace, entry->nt_name);
		free(entry->namespace);
		free(entry->nt_name);
		entry->namespace = NULL;
		entry->nt_name = NULL;
	} else {
		name = entry->nt_name;
	}

	for (i = (AA_EXEC_LOCAL >> 10) + 1; i < AA_EXEC_COUNT; i++) {
		if (!cod->exec_table[i]) {
			cod->exec_table[i] = name;
			return i;
		} else if (strcmp(cod->exec_table[i], name) == 0) {
			/* name already in table */
			free(name);
			return i;
		}
	}
	free(name);
	return 0;
}

void add_entry_to_policy(struct codomain *cod, struct cod_entry *entry)
{
	entry->next = cod->entries;
	cod->entries = entry;
}

void post_process_nt_entries(struct codomain *cod)
{
	struct cod_entry *entry;

	list_for_each(cod->entries, entry) {
		if (entry->nt_name) {
			int mode = 0;
			int n = add_named_transition(cod, entry);
			if (!n) {
				PERROR("Profile %s has to many specified profile transitions.\n", cod->name);
				exit(1);
			}
			if (entry->mode & AA_USER_EXEC)
				mode |= SHIFT_MODE(n << 10, AA_USER_SHIFT);
			if (entry->mode & AA_OTHER_EXEC)
				mode |= SHIFT_MODE(n << 10, AA_OTHER_SHIFT);
			entry->mode = ((entry->mode & ~AA_ALL_EXEC_MODIFIERS) |
				       (mode & AA_ALL_EXEC_MODIFIERS));
			entry->namespace = NULL;
			entry->nt_name = NULL;
		}
	}
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

	list_for_each(entry_list, entry) {
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

static void __process_policydb(const void *nodep, const VISIT value,
			       const int __unused depth)
{
	struct codomain **t = (struct codomain **) nodep;

	if (value == preorder || value == endorder)
		return;

	if (process_policydb(*t) != 0) {
		PERROR(_("ERROR processing policydb rules for profile %s, failed to load\n"),
		       (*t)->name);
		exit(1);
	}
}

int post_process_policydb(void)
{
	twalk(policy_list, __process_policydb);
	return 0;
}

int process_hat_policydb(struct codomain *cod)
{
	twalk(cod->hat_table, __process_policydb);
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


static void __process_alias(const void *nodep, const VISIT value,
			    const int __unused depth)
{
	struct codomain **t = (struct codomain **) nodep;

	if (value == preorder || value == endorder)
		return;

	replace_aliases((*t));

	if ((*t)->hat_table)
		twalk((*t)->hat_table, __process_alias);
}

int post_process_alias(void)
{
	twalk(policy_list, __process_alias);
	return 0;
}

#define CHANGEHAT_PATH "/proc/[0-9]*/attr/current"

/* add file rules to access /proc files to call change_hat()
 */
static void __add_hat_rules_parent(const void *nodep, const VISIT value,
				   const int __unused depth)
{
	struct codomain **t = (struct codomain **) nodep;
	struct cod_entry *entry;

	if (value == preorder || value == endorder)
		return;

	/* don't add hat rules if a parent profile with no hats */
	if (!(*t)->hat_table && !(*t)->parent)
		return;

	/* don't add hat rules for local_profiles */
	if ((*t)->local)
		return;

	/* add rule to grant permission to change_hat
	 * An opensuse 11.0, AA 2.3 requirement,
	 * rules are added to the parent of the hat
	 */
	if ((flag_changehat_version == FLAG_CHANGEHAT_1_4) &&
	    (*t)->parent) {
		char *buffer = malloc(strlen((*t)->name) + 1);
		if (!buffer) {
			PERROR("Memory allocation error\n");
			exit(1);
		}

		strcpy(buffer, (*t)->name);

		entry = new_entry(NULL, buffer, AA_CHANGE_HAT, NULL);
		if (!entry) {
			PERROR("Memory allocation error\n");
			exit(1);
		}
		add_entry_to_policy((*t)->parent, entry);
	}

	entry = new_entry(NULL, strdup(CHANGEHAT_PATH), AA_MAY_WRITE, NULL);
	if (!entry) {
		PERROR(_("ERROR adding hat access rule for profile %s\n"),
		       (*t)->name);
		exit(1);
	}
	add_entry_to_policy(*t, entry);

	twalk((*t)->hat_table, __add_hat_rules_parent);
}

/* Deprecated: used to support changehat rules of AppArmor 2.3
 * add the same hat rules to the hats as the parent so that hats can
 * change to sibling hats
 */
static void __add_hat_rules_hats(const void *nodep, const VISIT value,
				 const int __unused depth)
{
	struct codomain **t = (struct codomain **) nodep;

	if (value == preorder || value == endorder)
		return;

	/* don't add hat rules if a parent profile with no hats */
	if (!(*t)->hat_table && !(*t)->parent)
		return;

	/* don't add hat rules for local_profiles */
	if ((*t)->local)
		return;

	/* hat */
	if ((*t)->parent) {
		struct cod_entry *entry, *new_ent;
		list_for_each((*t)->parent->entries, entry) {
			if (entry->mode & AA_CHANGE_HAT) {
				char *buffer = strdup(entry->name);
				if (!buffer) {
					PERROR("Memory allocation error\n");
					exit(1);
				}
				new_ent = new_entry(NULL, buffer,
						    AA_CHANGE_HAT, NULL);
				if (!entry) {
					PERROR("Memory allocation error\n");
					exit(1);
				}
				add_entry_to_policy((*t), new_ent);
			}
		}
         }
         twalk((*t)->hat_table, __add_hat_rules_hats);
}

static int add_hat_rules(void)
{
	twalk(policy_list, __add_hat_rules_parent);

	/* support hat rules of AppArmor 2.3 in opensuse 11.0 */
	if (flag_changehat_version == FLAG_CHANGEHAT_1_4)
		twalk(policy_list, __add_hat_rules_hats);
	return 0;
}

/* Yuck, is their no other way to pass arguments to a twalk action */
static int __load_option;
static int __load_error;

static void __load_policy(const void *nodep, const VISIT value,
			  const int __unused depth)
{
	struct codomain **t = (struct codomain **) nodep;

	if (value == preorder || value == endorder || __load_error)
		return;

	if (load_codomain(__load_option, *t) != 0) {
		__load_error = -EINVAL;
	}
}

int load_policy(int option)
{
	__load_option = option;
        __load_error = 0;
	twalk(policy_list, __load_policy);
	return __load_error;
}

/* Yuck, is their no other way to pass arguments to a twalk action */
static sd_serialize *__p;

static int __load_hat_error;
static void __load_hat(const void *nodep, const VISIT value,
		       const int __unused depth)
{
	struct codomain **t = (struct codomain **) nodep;

	if (value == preorder || value == endorder || __load_hat_error)
		return;

	if (!sd_serialize_profile(__p, *t, 0)) {
		PERROR(_("ERROR in profile %s, failed to load\n"),
		       (*t)->name);
		__load_hat_error = -EINVAL;
	}
}

static int __load_flattened_hat_error;
static void __load_flattened_hat(const void *nodep, const VISIT value,
				 const int __unused depth)
{
	struct codomain **t = (struct codomain **) nodep;

	if (value == preorder || value == endorder || __load_flattened_hat_error)
		return;

	if (load_codomain(__load_option, *t) != 0) {
		__load_flattened_hat_error = -EINVAL;
	}
}

int load_flattened_hats(struct codomain *cod)
{
	__load_flattened_hat_error = 0;
	twalk(cod->hat_table, __load_flattened_hat);
	return __load_flattened_hat_error;
}

int load_hats(sd_serialize *p, struct codomain *cod)
{
	__p = p;
	__load_hat_error = 0;
	twalk(cod->hat_table, __load_hat);
	return __load_hat_error;
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

	if (regex_type == AARE_DFA) {
	    printf("%s//%s\n", __dump_policy_name->name, (*t)->name);
	} else {
	    printf("%s^%s\n", __dump_policy_name->name, (*t)->name);
	}
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
		list_last_entry(a->entries, last);
		last->next = b->entries;
	} else {
		a->entries = b->entries;
	}
	b->entries = NULL;

	a->flags.complain = a->flags.complain || b->flags.complain;
	a->flags.audit = a->flags.audit || b->flags.audit;

	a->capabilities |= b->capabilities;
	a->audit_caps |= b->audit_caps;
	a->deny_caps |= b->deny_caps;
	a->quiet_caps |= b->quiet_caps;

	if (a->network_allowed) {
		size_t i;
		for (i = 0; i < get_af_max(); i++) {
			a->network_allowed[i] |= b->network_allowed[i];
			a->audit_network[i] |= b->audit_network[i];
			a->deny_network[i] |= b->deny_network[i];
			a->quiet_network[i] |= b->quiet_network[i];
		}
	}

	merge_hats(a, b->hat_table);
	tdestroy(b->hat_table, &empty_destroy);
	b->hat_table = NULL;

	free_policy(b);
out:
	return ret;
}

int post_process_policy(int debug_only)
{
	int retval = 0;

	retval = add_hat_rules();
	if (retval != 0) {
		PERROR(_("%s: Errors found during postprocessing.  Aborting.\n"),
		       progname);
		return retval;
	}

	retval = post_process_variables();
	if (retval != 0) {
		PERROR(_("%s: Errors found during regex postprocess.  Aborting.\n"),
		       progname);
		return retval;
	}

	retval = post_process_alias();
	if (retval != 0) {
		PERROR(_("%s: Errors found during postprocess.  Aborting.\n"),
		       progname);
		return retval;
	}

	retval = post_merge_rules();
	if (retval != 0) {
		PERROR(_("%s: Errors found in combining rules postprocessing. Aborting.\n"),
		       progname);
		return retval;
	}

	if (!debug_only) {
		retval = post_process_regex();
		if (retval != 0) {
			PERROR(_("%s: Errors found during regex postprocess.  Aborting.\n"),
			       progname);
			return retval;
		}
	}

	if (!debug_only) {
		retval = post_process_policydb();
		if (retval != 0) {
			PERROR(_("%s: Errors found during policydb postprocess.  Aborting.\n"),
			       progname);
			return retval;
		}
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
	if (cod->dfarules)
		aare_delete_ruleset(cod->dfarules);
	if (cod->dfa)
		free(cod->dfa);
	if (cod->policy_rules)
		aare_delete_ruleset(cod->policy_rules);
	if (cod->policy_dfa)
		free(cod->policy_dfa);
	if (cod->name)
		free(cod->name);
	if (cod->attachment)
		free(cod->attachment);
	if (cod->namespace)
		free(cod->namespace);
	if (cod->network_allowed)
		free(cod->network_allowed);
	if (cod->audit_network)
		free(cod->audit_network);
	if (cod->deny_network)
		free(cod->deny_network);
	if (cod->quiet_network)
		free(cod->quiet_network);
	free(cod);
}

void free_policies(void)
{
	if (policy_list)
		tdestroy(policy_list, (__free_fn_t)&free_policy);
	policy_list = NULL;
}
