/*	 $Id$ 	*/

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

enum var_type {
	sd_boolean,
	sd_set,
};

struct set_value {
	char *val;
	struct set_value *next;
};

struct symtab {
	char *var_name;
	enum var_type type;
	int boolean;
	struct set_value *values;
	struct set_value *expanded;
};

static void *my_symtab = NULL;

static int __expand_variable(struct symtab *symbol);

static struct symtab *new_symtab_entry(const char *name)
{
	struct symtab *new = calloc(1, sizeof(*new));

	if (!new) {
		PERROR("Failed to allocate memory: %s\n", strerror(errno));
		return NULL;
	}

	new->var_name = strndup(name, PATH_MAX);
	if (!new->var_name) {
		PERROR("Failed to allocate memory: %s\n", strerror(errno));
		free(new);
		return NULL;
	}

	return new;
}

static struct set_value *new_set_value(const char *val)
{
	struct set_value *new = calloc(1, sizeof(*new));

	if (!new) {
		PERROR("Failed to allocate memory: %s\n", strerror(errno));
		return NULL;
	}

	new->val = strndup(val, PATH_MAX);
	if (!new->val) {
		PERROR("Failed to allocate memory: %s\n", strerror(errno));
		free(new);
		return NULL;
	}

	return new;
}

static void free_values(struct set_value *val)
{
	struct set_value *this = val, *tmp;

	while (this) {
		if (this->val)
			free(this->val);
		tmp = this;
		this = this->next;
		free(tmp);
	}
}

static void free_symtab(struct symtab *symtab)
{
	if (!symtab)
		return;

	if (symtab->var_name)
	 	free(symtab->var_name);

	free_values(symtab->values);
	free(symtab);
}

/* abstract this out in case we switch data structures */
static void add_to_set(struct set_value **list, const char *val)
{
	struct set_value *new_item = new_set_value(val);

	new_item->next = *list;
	*list = new_item;
}

static int compare_symtabs(const void *a, const void *b)
{
	char *a_name = ((struct symtab *) a)->var_name;
	char *b_name = ((struct symtab *) b)->var_name;
	return strcmp(a_name, b_name);
}

static struct symtab *lookup_existing_symbol(const char *var)
{
	struct symtab *tmp, **lookup;
	struct symtab *result = NULL;

	tmp = new_symtab_entry(var);
	if (!tmp) {
		goto out;
	}

	lookup = (struct symtab **) tfind(tmp, &my_symtab, (comparison_fn_t) &compare_symtabs);
	if (!lookup) {
		goto out;
	}

	result = (*lookup);

out:
	free_symtab(tmp);
	return result;

}

/* add_boolean_var
 * creates copies of arguments, so caller can free them after use
 */

int add_boolean_var(const char *var, int value)
{
	struct symtab *new, **result;
	int rc = 0;

	new = new_symtab_entry(var);
	if (!new) {
		rc = ENOMEM;
		goto err;
	}

	new->type = sd_boolean;
	new->boolean = value;

	result = (struct symtab **) tsearch(new, &my_symtab, (comparison_fn_t) &compare_symtabs);
	if (!result) {
		PERROR("Failed to allocate memory: %s\n", strerror(errno));
		rc = errno;
		goto err;
	}

	if (*result != new) {
		/* already existing variable */
		PERROR("'%s' is already defined\n", var);
		rc = 1;
		goto err;
	}

	return 0;

err:
	free_symtab(new);
	return rc;
};

int get_boolean_var(const char *var)
{
	struct symtab *result;
	int rc = 0;

	result = lookup_existing_symbol(var);
	if (!result) {
		rc = -1;
		goto out;
	}

	if (result->type != sd_boolean) {
		PERROR("Variable %s is not a boolean variable\n", var);
		rc = -2; /* XXX - might change this to specific values */
		goto out;
	}

	rc = result->boolean;
out:
	return rc;
}

/* new_set_var
 * creates copies of arguments, so caller can free them after use
 */
int new_set_var(const char *var, const char *value)
{
	struct symtab *new, **result;
	int rc = 0;

	new = new_symtab_entry(var);
	if (!new) {
		rc = ENOMEM;
		goto err;
	}

	new->type = sd_set;
	add_to_set(&(new->values), value);

	result = (struct symtab **) tsearch(new, &my_symtab, (comparison_fn_t) &compare_symtabs);
	if (!result) {
		PERROR("Failed to allocate memory: %s\n", strerror(errno));
		rc = errno;
		goto err;
	}

	if (*result != new) {
		/* already existing variable */
		PERROR("'%s' is already defined\n", var);
		rc = 1;
		goto err;
	}

	return 0;

err:
	free_symtab(new);
	return rc;
}


/* add_set_value
 * creates copies of arguments, so caller can free them after use
 */
int add_set_value(const char *var, const char *value)
{
	struct symtab *result;
	int rc = 0;

	result = lookup_existing_symbol(var);
	if (!result) {
		PERROR("Failed to find declaration for: %s\n", var);
		rc = 1;
		goto out;
	}

	if (result->type != sd_set) {
		PERROR("Variable %s is not a set variable\n", var);
		rc = 2;	/* XXX - might change this to specific values */
		goto out;
	}

	if (strcmp(result->var_name, var) != 0) {
		PERROR("ASSERT: tfind found  %s when looking up variable %s\n",
		       result->var_name, var);
		exit(1);
	}

	add_to_set(&(result->values), value);

out:
	return rc;
}

/* returns a pointer to the value list, which should be used as the
 * argument to the get_next_set_value() function. */
void *get_set_var(const char *var)
{
	struct symtab *result;
	struct set_value *valuelist = NULL;

	result = lookup_existing_symbol(var);
	if (!result) {
		goto out;
	}

	if (result->type != sd_set) {
		goto out;
	}

	if (strcmp(result->var_name, var) != 0) {
		PERROR("ASSERT: tfind found  %s when looking up variable %s\n",
		       result->var_name, var);
		exit(1);
	}

	if (!result->expanded) {
		int err = __expand_variable(result);
		if (err) {
			PERROR("failure expanding variable %s\n", var);
			exit(1);
		}
	}
	valuelist = result->expanded;
out:
	return valuelist;
}

/* iterator to walk the list of set values */
char *get_next_set_value(void **list)
{
	struct set_value **valuelist = (struct set_value **) list;
	char *ret;

	if (!valuelist || !(*valuelist))
		return NULL;

	ret = (*valuelist)->val;
	(*valuelist) = (*valuelist)->next;

	return ret;
}

static void *seenlist = NULL;

static int is_seen(const char *var)
{
	char **lookup;
	lookup = (char **) tfind(var, &seenlist, (comparison_fn_t) &strcmp);
	return (lookup != NULL);
}

static void push_seen_var(const char *var)
{
	char **lookup;
	lookup = (char **) tsearch(var, &seenlist, (comparison_fn_t) &strcmp);
	if (*lookup != var) {
		PERROR("ASSERT: '%s' is already in the seenlist\n", var);
		exit(1);
	}
}

static void pop_seen_var(const char *var)
{
	char **lookup;
	lookup = (char **) tdelete(var, &seenlist, (comparison_fn_t) &strcmp);
	if (lookup == NULL) {
		PERROR("ASSERT: popped var '%s' not found on the seenlist\n", var);
		exit(1);
	}
}

static int __expand_variable(struct symtab *symbol)
{
	struct set_value *list, *expanded = NULL;
	int retval = 0;
	struct var_string *split = NULL;

	if (symbol->type == sd_boolean) {
		PERROR("Referenced variable %s is a boolean used in set context\n",
		       symbol->var_name);
		return 2;
	}

	/* already done */
	if (symbol->expanded)
		return 0;

	push_seen_var(symbol->var_name);

	for (list = symbol->values; list; list = list->next) {
		struct set_value *work_list = new_set_value(list->val);
		while (work_list) {
			struct symtab *ref;
			struct set_value *ref_item;
			struct set_value *this_value = work_list;
			int rc;

			work_list = work_list->next;

			split = split_out_var(this_value->val);
			if (!split) {
				/* fully expanded */
				add_to_set(&expanded, this_value->val);
				goto next;
			}


			if (is_seen(split->var)) {
				PERROR("Variable @{%s} is referenced recursively (by @{%s})\n",
		       		       split->var, symbol->var_name);
				retval = 1;
				goto out;
			}

			ref = lookup_existing_symbol(split->var);
			if (!ref) {
				PERROR("Variable @{%s} references undefined variable @{%s}\n",
				       symbol->var_name, split->var);
				retval = 3;
				goto out;
			}

			rc = __expand_variable(ref);
			if (rc != 0) {
				retval = rc;
				goto out;
			}

			if (!ref->expanded) {
				PERROR("ASSERT: Variable @{%s} should have been expanded but isn't\n",
				       split->var);
				exit(1);
			}

			for (ref_item = ref->expanded; ref_item; ref_item = ref_item->next) {
				char *expanded_string;
				asprintf(&expanded_string, "%s%s%s",
					 split->prefix ?  split->prefix : "",
					 ref_item->val,
					 split->suffix ?  split->suffix : "");
				add_to_set(&work_list, expanded_string);
				free(expanded_string);
			}

next:
			this_value->next = NULL;
			free_values(this_value);
			free_var_string(split);
		}
	}

	symbol->expanded = expanded;
	pop_seen_var(symbol->var_name);
out:
	free_var_string(split);
	return retval;
}

static void expand_variable(const void *nodep, VISIT value, int __unused level)
{
	struct symtab **t = (struct symtab **) nodep;

	if (value == preorder || value == endorder)
		return;

	if ((*t)->type == sd_boolean)
		return;

	__expand_variable(*t);
}

void expand_variables(void)
{
	twalk(my_symtab, &expand_variable);
}

static inline void dump_set_values(struct set_value *value)
{
	struct set_value *this = value;
	while (this) {
		printf(" \"%s\"", this->val);
		this = this->next;
	}
}

static void __dump_symtab_entry(struct symtab *entry, int do_expanded)
{
	switch (entry->type) {
	case sd_boolean:
		printf("$%s = %s\n", entry->var_name,
		       entry->boolean ?  "true" : "false");
		break;
	case sd_set:
		printf("@%s =", entry->var_name);
		if (do_expanded) {
			if (!entry->expanded) {
				__expand_variable(entry);
			}
			dump_set_values(entry->expanded);
		} else {
			dump_set_values(entry->values);
		}
		printf("\n");
		break;
	default:
		PERROR("ASSERT: unknown symbol table type for %s\n", entry->var_name);
		exit(1);
	}
}

static void dump_symtab_entry(const void *nodep, VISIT value, int __unused level)
{
	struct symtab **t = (struct symtab **) nodep;

	if (value == preorder || value == endorder)
		return;

	__dump_symtab_entry(*t, 0);
}

static void dump_expanded_symtab_entry(const void *nodep, VISIT value, int __unused level)
{
	struct symtab **t = (struct symtab **) nodep;

	if (value == preorder || value == endorder)
		return;

	__dump_symtab_entry(*t, 1);
}

void dump_symtab(void)
{
	twalk(my_symtab, &dump_symtab_entry);
}

void dump_expanded_symtab(void)
{
	twalk(my_symtab, &dump_expanded_symtab_entry);
}

#ifdef UNIT_TEST
#define MY_TEST(statement, error)		\
	if (!(statement)) {			\
		PERROR("FAIL: %s\n", error);	\
		rc = 1;				\
	}

/* Guh, fake symbol */
char *progname;

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

int main(void)
{
	int rc = 0;
	int retval;
	void *retptr;
	struct symtab *a, *b;

	a = new_symtab_entry("blah");
	b = new_symtab_entry("suck");
	MY_TEST(a && b, "allocation test");

	retval = compare_symtabs(a, b);
	MY_TEST(retval < 0, "comparison 1");

	retval = compare_symtabs(b, a);
	MY_TEST(retval > 0, "comparison 2");

	retval = compare_symtabs(b, a);
	MY_TEST(retval != 0, "comparison 3");

	retval = new_set_var("test", "test value");
	MY_TEST(retval == 0, "new set variable 1");

	retval = new_set_var("test", "different value");
	MY_TEST(retval != 0, "new set variable 2");

	retval = new_set_var("testes", "testes");
	MY_TEST(retval == 0, "new set variable 3");

	retval = new_set_var("monopuff", "Mockingbird");
	MY_TEST(retval == 0, "new set variable 4");

	retval = new_set_var("stereopuff", "Unsupervised");
	MY_TEST(retval == 0, "new set variable 5");

	retval = add_set_value("stereopuff", "Fun to Steal");
	MY_TEST(retval == 0, "add set value 1");

	retval = add_set_value("stereopuff", "/in/direction");
	MY_TEST(retval == 0, "add set value 2");

	retval = add_set_value("no_such_variable", "stereopuff");
	MY_TEST(retval != 0, "add to non-existent set var");

	retval = add_boolean_var("abuse", 0);
	MY_TEST(retval == 0, "new boolean variable 1");

	retval = add_boolean_var("abuse", 1);
	MY_TEST(retval != 0, "duplicate boolean variable 1");

	retval = add_boolean_var("stereopuff", 1);
	MY_TEST(retval != 0, "duplicate boolean variable 2");

	retval = add_boolean_var("shenanigan", 1);
	MY_TEST(retval == 0, "new boolean variable 2");

	retval = get_boolean_var("shenanigan");
	MY_TEST(retval == 1, "get boolean variable 1");

	retval = get_boolean_var("abuse");
	MY_TEST(retval == 0, "get boolean variable 2");

	retval = get_boolean_var("non_existant");
	MY_TEST(retval < 0, "get nonexistant boolean variable");

	retval = get_boolean_var("stereopuff");
	MY_TEST(retval < 0, "get boolean variable that's declared a set var");

	retptr = get_set_var("daves_not_here_man");
	MY_TEST(retptr == NULL, "get non-existent set variable");

	retptr = get_set_var("abuse");
	MY_TEST(retptr == NULL, "get set variable that's declared a boolean");

	retptr = get_set_var("monopuff");
	MY_TEST(retptr != NULL, "get set variable 1");

	retval = strcmp(get_next_set_value(&retptr), "Mockingbird");
	MY_TEST(retval == 0, "get set value 1");

	MY_TEST(get_next_set_value(&retptr) == NULL, "get no more set values 1");

	MY_TEST(!is_seen("oogabooga"), "lookup unseen variable");

	push_seen_var("oogabooga");
	MY_TEST(is_seen("oogabooga"), "lookup seen variable 1");
	MY_TEST(!is_seen("not_seen"), "lookup unseen variable 2");

	push_seen_var("heebiejeebie");
	MY_TEST(is_seen("oogabooga"), "lookup seen variable 2");
	MY_TEST(is_seen("heebiejeebie"), "lookup seen variable 3");
	MY_TEST(!is_seen("not_seen"), "lookup unseen variable 3");

	pop_seen_var("oogabooga");
	MY_TEST(!is_seen("oogabooga"), "lookup unseen variable 4");
	MY_TEST(is_seen("heebiejeebie"), "lookup seen variable 4");
	MY_TEST(!is_seen("not_seen"), "lookup unseen variable 5");

	pop_seen_var("heebiejeebie");
	MY_TEST(!is_seen("heebiejeebie"), "lookup unseen variable 6");

	//pop_seen_var("not_seen"); /* triggers assert */

	retval = new_set_var("eek", "Mocking@{monopuff}bir@{stereopuff}d@{stereopuff}");
	MY_TEST(retval == 0, "new set variable 4");

	dump_symtab();
	expand_variables();
	dump_symtab();
	dump_expanded_symtab();

	return rc;
}
#endif /* UNIT_TEST */
