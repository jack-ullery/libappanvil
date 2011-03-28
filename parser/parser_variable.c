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

#include <ctype.h>
#include <stdlib.h>
#include <stdio.h>
#include <stdarg.h>
#include <string.h>
#include <libintl.h>
#include <linux/limits.h>

#define _(s) gettext(s)

/* #define DEBUG */

#include "parser.h"

static inline char *get_var_end(char *var)
{
	char *eptr = var;

	while (*eptr) {
		if (*eptr == '}')
			return eptr;
		/* first character must be alpha */
		if (eptr == var) {
		 	if (!isalpha(*eptr))
				return NULL; /* invalid char */
		} else {
			if (!(*eptr == '_' || isalnum(*eptr)))
				return NULL; /* invalid char */
		}
		eptr++;
	}
	return NULL; /* no terminating '}' */
}

static struct var_string *split_string(char *string, char *var_begin,
				       char *var_end)
{
	struct var_string *new = calloc(1, sizeof(struct var_string));
	unsigned int offset = strlen("@{");
	if (!new) {
		PERROR("Memory allocation error\n");
		return NULL;
	}

	if (var_begin != string) {
		new->prefix = strndup(string, var_begin - string);
	}

	new->var = strndup(var_begin + offset, var_end - (var_begin + offset));

	if (strlen(var_end + 1) != 0) {
		new->suffix = strdup(var_end + 1);
	}

	return new;
}

struct var_string *split_out_var(char *string)
{
	struct var_string *new = NULL;
	char *sptr;
	BOOL bEscape = 0;	/* flag to indicate escape */

	if (!string) 		/* shouldn't happen */
		return NULL;

	sptr = string;

	while (!new && *sptr) {
		switch (*sptr) {
		case '\\':
			if (bEscape) {
				bEscape = FALSE;
			} else {
				bEscape = TRUE;
			}
			break;
		case '@':
			if (bEscape) {
				bEscape = FALSE;
			} else if (*(sptr + 1) == '{') {
				char *eptr = get_var_end(sptr + 2);
				if (!eptr)
					break; /* no variable end found */
				if (eptr == sptr + 2) {
					/* XXX - better diagnostics here, please */
					PERROR("Empty variable name found!\n");
					exit(1);
				}
				new = split_string(string, sptr, eptr);
			}
			break;
		default:
			if (bEscape)
				bEscape = FALSE;
		}
		sptr++;
	}

	return new;
}

void free_var_string(struct var_string *var)
{
	if (!var)
		return;
	if (var->prefix)
		free(var->prefix);
	if (var->var)
		free(var->var);
	if (var->suffix)
		free(var->suffix);
	free(var);
}

static int expand_entry_variables(struct cod_entry *entry)
{
	struct set_value *valuelist;
	int ret = TRUE;
	char *value;
	struct var_string *split_var;

	if (!entry) 		/* shouldn't happen */
		return ret;

	while ((split_var = split_out_var(entry->name))) {
		valuelist = get_set_var(split_var->var);
		if (!valuelist) {
			int boolean = get_boolean_var(split_var->var);
			if (boolean == -1)
				PERROR("Found reference to variable %s, but is never declared\n",
				       split_var->var);
			else
				PERROR("Found reference to set variable %s, but declared boolean\n",
				       split_var->var);
			exit(1);
		}

		value = get_next_set_value(&valuelist);
		if (!value) {
			PERROR("ASSERT: set variable (%s) should always have at least one value assigned to them\n",
			       split_var->var);
			exit(1);
		}
		free(entry->name);
		if (asprintf(&(entry->name), "%s%s%s",
			     split_var->prefix ? split_var->prefix : "",
			     value,
			     split_var->suffix ? split_var->suffix : "") == -1)
			return FALSE;

		while ((value = get_next_set_value(&valuelist))) {
			struct cod_entry *dupe = copy_cod_entry(entry);
			if (!dupe) {
				PERROR("Memory allocaton error while handling set variable %s\n",
				       split_var->var);
				exit(1);
			}
			entry->next = dupe;

			free(entry->name);
			if (asprintf(&(entry->name), "%s%s%s",
			      split_var->prefix ? split_var->prefix : "", value,
			      split_var->suffix ? split_var->suffix : "") == -1)
				return FALSE;
		}

		free_var_string(split_var);
	}
	return ret;
}

static int process_variables_in_entries(struct cod_entry *entry_list)
{
	int ret = TRUE, rc;
	struct cod_entry *entry;

	list_for_each(entry_list, entry) {
		rc = expand_entry_variables(entry);
		if (!rc)
			ret = FALSE;
	}

	return ret;
}

int process_variables(struct codomain *cod)
{
	int error = 0;

	if (!process_variables_in_entries(cod->entries)) {
		error = -1;
	}

	if (process_hat_variables(cod) != 0) {
			error = -1;
	}
	return error;
}

#ifdef UNIT_TEST
#define MY_TEST(statement, error)		\
	if (!(statement)) {			\
		PERROR("FAIL: %s\n", error);	\
		rc = 1;				\
	}

/* Guh, fake routine */
void yyerror(char *msg, ...)
{
	va_list arg;
	char buf[PATH_MAX];

	va_start(arg, msg);
	vsnprintf(buf, sizeof(buf), msg, arg);
	va_end(arg);

	PERROR(_("AppArmor parser error: %s\n"), buf);

	exit(1);
}
/* Guh, fake symbol */
char *progname;

int test_get_var_end(void)
{
	int rc = 0;
	char *retchar;
	char *testchar;

	testchar = "TRUE}";
	retchar = get_var_end(testchar);
	MY_TEST(retchar - testchar == strlen("TRUE"), "get var end for TRUE}");

	testchar = "some_var}some other text";
	retchar = get_var_end(testchar);
	MY_TEST(retchar - testchar == strlen("some_var"), "get var end for some_var}");

	testchar = "some_var}some other} text";
	retchar = get_var_end(testchar);
	MY_TEST(retchar - testchar == strlen("some_var"), "get var end for some_var} 2");

	testchar = "FALSE";
	retchar = get_var_end(testchar);
	MY_TEST(retchar == NULL, "get var end for FALSE");

	testchar = "pah,pah}pah ";
	retchar = get_var_end(testchar);
	MY_TEST(retchar == NULL, "get var end for pah,pah}");

	return rc;
}

int test_split_string(void)
{
	int rc = 0;
	char *tst_string, *var_start, *var_end;
	struct var_string *ret_struct;
	char *prefix = "abcdefg";
	char *var = "boogie";
	char *suffix = "suffixication";

	(void) asprintf(&tst_string, "%s@{%s}%s", prefix, var, suffix);
	var_start = tst_string + strlen(prefix);
	var_end = var_start + strlen(var) + strlen("@\{");
	ret_struct = split_string(tst_string, var_start, var_end);
	MY_TEST(strcmp(ret_struct->prefix, prefix) == 0, "split string 1 prefix");
	MY_TEST(strcmp(ret_struct->var, var) == 0, "split string 1 var");
	MY_TEST(strcmp(ret_struct->suffix, suffix) == 0, "split string 1 suffix");
	free_var_string(ret_struct);

	asprintf(&tst_string, "@{%s}%s", var, suffix);
	var_start = tst_string;
	var_end = var_start + strlen(var) + strlen("@\{");
	ret_struct = split_string(tst_string, var_start, var_end);
	MY_TEST(ret_struct->prefix == NULL, "split string 2 prefix");
	MY_TEST(strcmp(ret_struct->var, var) == 0, "split string 2 var");
	MY_TEST(strcmp(ret_struct->suffix, suffix) == 0, "split string 2 suffix");
	free_var_string(ret_struct);

	asprintf(&tst_string, "%s@{%s}", prefix, var);
	var_start = tst_string + strlen(prefix);
	var_end = var_start + strlen(var) + strlen("@\{");
	ret_struct = split_string(tst_string, var_start, var_end);
	MY_TEST(strcmp(ret_struct->prefix, prefix) == 0, "split string 3 prefix");
	MY_TEST(strcmp(ret_struct->var, var) == 0, "split string 3 var");
	MY_TEST(ret_struct->suffix == NULL, "split string 3 suffix");
	free_var_string(ret_struct);

	asprintf(&tst_string, "@{%s}", var);
	var_start = tst_string;
	var_end = var_start + strlen(var) + strlen("@\{");
	ret_struct = split_string(tst_string, var_start, var_end);
	MY_TEST(ret_struct->prefix == NULL, "split string 4 prefix");
	MY_TEST(strcmp(ret_struct->var, var) == 0, "split string 4 var");
	MY_TEST(ret_struct->suffix == NULL, "split string 4 suffix");
	free_var_string(ret_struct);

	return rc;
}

int test_split_out_var(void)
{
	int rc = 0;
	char *tst_string, *tmp;
	struct var_string *ret_struct;
	char *prefix = "abcdefg";
	char *var = "boogie";
	char *var2 = "V4rW1thNum5";
	char *var3 = "boogie_board";
	char *suffix = "suffixication";

	/* simple case */
	asprintf(&tst_string, "%s@{%s}%s", prefix, var, suffix);
	ret_struct = split_out_var(tst_string);
	MY_TEST(strcmp(ret_struct->prefix, prefix) == 0, "split out var 1 prefix");
	MY_TEST(strcmp(ret_struct->var, var) == 0, "split out var 1 var");
	MY_TEST(strcmp(ret_struct->suffix, suffix) == 0, "split out var 1 suffix");
	free_var_string(ret_struct);

	/* no prefix */
	asprintf(&tst_string, "@{%s}%s", var, suffix);
	ret_struct = split_out_var(tst_string);
	MY_TEST(ret_struct->prefix == NULL, "split out var 2 prefix");
	MY_TEST(strcmp(ret_struct->var, var) == 0, "split out var 2 var");
	MY_TEST(strcmp(ret_struct->suffix, suffix) == 0, "split out var 2 suffix");
	free_var_string(ret_struct);

	/* no suffix */
	asprintf(&tst_string, "%s@{%s}", prefix, var);
	ret_struct = split_out_var(tst_string);
	MY_TEST(strcmp(ret_struct->prefix, prefix) == 0, "split out var 3 prefix");
	MY_TEST(strcmp(ret_struct->var, var) == 0, "split out var 3 var");
	MY_TEST(ret_struct->suffix == NULL, "split out var 3 suffix");
	free_var_string(ret_struct);

	/* var only */
	asprintf(&tst_string, "@{%s}", var);
	ret_struct = split_out_var(tst_string);
	MY_TEST(ret_struct->prefix == NULL, "split out var 4 prefix");
	MY_TEST(strcmp(ret_struct->var, var) == 0, "split out var 4 var");
	MY_TEST(ret_struct->suffix == NULL, "split out var 4 suffix");
	free_var_string(ret_struct);

	/* quoted var, shouldn't split  */
	asprintf(&tst_string, "%s\\@{%s}%s", prefix, var, suffix);
	ret_struct = split_out_var(tst_string);
	MY_TEST(ret_struct == NULL, "split out var - quoted @");
	free_var_string(ret_struct);

	/* quoted \, split should succeed */
	asprintf(&tst_string, "%s\\\\@{%s}%s", prefix, var, suffix);
	ret_struct = split_out_var(tst_string);
	MY_TEST(strcmp(ret_struct->prefix, strndup(tst_string, strlen(prefix) + 2)) == 0, "split out var 5 prefix");
	MY_TEST(strcmp(ret_struct->var, var) == 0, "split out var 5 var");
	MY_TEST(strcmp(ret_struct->suffix, suffix) == 0, "split out var 5 suffix");
	free_var_string(ret_struct);

	/* un terminated var, should fail */
	asprintf(&tst_string, "%s@{%s%s", prefix, var, suffix);
	ret_struct = split_out_var(tst_string);
	MY_TEST(ret_struct == NULL, "split out var - un-terminated var");
	free_var_string(ret_struct);

	/* invalid char in var, should fail */
	asprintf(&tst_string, "%s@{%s^%s}%s", prefix, var, var, suffix);
	ret_struct = split_out_var(tst_string);
	MY_TEST(ret_struct == NULL, "split out var - invalid char in var");
	free_var_string(ret_struct);

	/* two vars, should only strip out first */
	asprintf(&tmp, "@{%s}%s}", suffix, suffix);
	asprintf(&tst_string, "%s@{%s}%s", prefix, var, tmp);
	ret_struct = split_out_var(tst_string);
	MY_TEST(strcmp(ret_struct->prefix, prefix) == 0, "split out var 6 prefix");
	MY_TEST(strcmp(ret_struct->var, var) == 0, "split out var 6 var");
	MY_TEST(strcmp(ret_struct->suffix, tmp) == 0, "split out var 6 suffix");
	free_var_string(ret_struct);

	/* quoted @ followed by var, split should succeed */
	asprintf(&tst_string, "%s\\@@{%s}%s", prefix, var, suffix);
	ret_struct = split_out_var(tst_string);
	MY_TEST(strcmp(ret_struct->prefix, strndup(tst_string, strlen(prefix) + 2)) == 0, "split out var 7 prefix");
	MY_TEST(strcmp(ret_struct->var, var) == 0, "split out var 7 var");
	MY_TEST(strcmp(ret_struct->suffix, suffix) == 0, "split out var 7 suffix");
	free_var_string(ret_struct);

	/* numeric char in var, should succeed */
	asprintf(&tst_string, "%s@{%s}%s", prefix, var2, suffix);
	ret_struct = split_out_var(tst_string);
	MY_TEST(ret_struct && strcmp(ret_struct->prefix, prefix) == 0, "split out numeric var prefix");
	MY_TEST(ret_struct && strcmp(ret_struct->var, var2) == 0, "split numeric var var");
	MY_TEST(ret_struct && strcmp(ret_struct->suffix, suffix) == 0, "split out numeric var suffix");
	free_var_string(ret_struct);

	/* numeric first char in var, should fail */
	asprintf(&tst_string, "%s@{6%s}%s", prefix, var2, suffix);
	ret_struct = split_out_var(tst_string);
	MY_TEST(ret_struct == NULL, "split out var - numeric first char in var");
	free_var_string(ret_struct);

	/* underscore char in var, should succeed */
	asprintf(&tst_string, "%s@{%s}%s", prefix, var3, suffix);
	ret_struct = split_out_var(tst_string);
	MY_TEST(ret_struct && strcmp(ret_struct->prefix, prefix) == 0, "split out underscore var prefix");
	MY_TEST(ret_struct && strcmp(ret_struct->var, var3) == 0, "split out underscore var");
	MY_TEST(ret_struct && strcmp(ret_struct->suffix, suffix) == 0, "split out underscore var suffix");
	free_var_string(ret_struct);

	/* underscore first char in var, should fail */
	asprintf(&tst_string, "%s@{_%s%s}%s", prefix, var2, var3, suffix);
	ret_struct = split_out_var(tst_string);
	MY_TEST(ret_struct == NULL, "split out var - underscore first char in var");
	free_var_string(ret_struct);

	return rc;
}
int main(void)
{
	int rc = 0;
	int retval;

	retval = test_get_var_end();
	if (retval != 0)
		rc = retval;

	retval = test_split_string();
	if (retval != 0)
		rc = retval;

	retval = test_split_out_var();
	if (retval != 0)
		rc = retval;

	return rc;
}
#endif /* UNIT_TEST */
