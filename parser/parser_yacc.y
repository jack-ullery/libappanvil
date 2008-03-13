%{
/* $Id$ */

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

#define YYERROR_VERBOSE 1
#include <stdio.h>
#include <stdarg.h>
#include <string.h>
#include <stdlib.h>
#include <getopt.h>
#include <errno.h>
#include <fcntl.h>
#include <libintl.h>
#define _(s) gettext(s)

/* #define DEBUG */

#include "parser.h"
#include <unistd.h>
#include <netinet/in.h>
#include <sys/socket.h>
#include <arpa/inet.h>

#include <linux/capability.h>

#ifndef CAP_AUDIT_WRITE
#define CAP_AUDIT_WRITE 29
#endif
#ifndef CAP_AUDIT_CONTROL
#define CAP_AUDIT_CONTROL 30
#endif

/* A few utility defines */

#define CIDR_32 htonl(0xffffffff)
#define CIDR_24 htonl(0xffffff00)
#define CIDR_16 htonl(0xffff0000)
#define CIDR_8  htonl(0xff000000)

#define CAP_TO_MASK(x) (1 << (x))

static struct flagval force_complain_flags = {0, 1, 0};

/* from lex_config, for nice error messages */
/* extern char *current_file; */
extern int current_lineno;

struct value_list {
	char *value;
	struct value_list *next;
};

void free_value_list(struct value_list *list);
struct cod_entry *do_file_rule(char *namespace, char *id, int mode,
			       char *link_id);

%}

%token TOK_ID
%token TOK_SEP
%token TOK_OPEN
%token TOK_CLOSE
%token TOK_MODE
%token TOK_END_OF_RULE
%token TOK_EQUALS
%token TOK_ARROW
%token TOK_ADD_ASSIGN
%token TOK_SET_VAR
%token TOK_BOOL_VAR
%token TOK_VALUE
%token TOK_IF
%token TOK_ELSE
%token TOK_NOT
%token TOK_DEFINED
%token TOK_CHANGE_PROFILE
%token TOK_NETWORK
%token TOK_HAT
%token TOK_UNSAFE
%token TOK_COLON
%token TOK_LINK
%token TOK_OWNER
%token TOK_SUBSET

/* capabilities */
%token TOK_CAPABILITY

/* debug flag values */
%token TOK_FLAGS
%token TOK_FLAG_OPENPAREN
%token TOK_FLAG_CLOSEPAREN
%token TOK_FLAG_SEP
%token TOK_FLAG_ID

%union {
	char *id;
	char *flag_id;
	char *mode;
	struct aa_network_entry *network_entry;
	struct codomain *cod;
	struct cod_global_entry *entry;
	struct cod_net_entry *net_entry;
	struct cod_entry *user_entry;
	struct flagval flags;
	int fmode;
	unsigned int cap;
	unsigned int allowed_protocol;
	char *set_var;
	char *bool_var;
	char *var_val;
	struct value_list *val_list;
	int boolean;
}

%type <id> 	TOK_ID
%type <mode> 	TOK_MODE
%type <fmode>   file_mode
%type <cod> 	profile
%type <cod>	rules
%type <cod>	hat
%type <cod>	cond_rule
%type <network_entry> network_rule
%type <user_entry> rule
%type <user_entry> owner_rule
%type <user_entry> owner_rules
%type <flags>	flags
%type <flags>	flagvals
%type <flags>	flagval
%type <flag_id>	TOK_FLAG_ID
%type <cap>	caps
%type <cap>	capability
%type <user_entry> change_profile
%type <set_var> TOK_SET_VAR
%type <bool_var> TOK_BOOL_VAR
%type <var_val>	TOK_VALUE
%type <val_list> valuelist
%type <boolean> expr
%type <id>	id_or_var
%type <boolean> opt_subset_flag
%%


list:	 varlist profilelist
	{ /* nothing */ };

profilelist:	{ /* nothing */ };

profilelist:	profilelist profile
	{
		PDEBUG("Matched: list profile\n");
		add_to_list($2);
	};

profile:	TOK_ID flags TOK_OPEN rules TOK_CLOSE
	{
		struct codomain *cod = $4;
		PDEBUG("Matched: id (%s) open rules close\n", $1);
		if (!cod) {
			yyerror(_("Memory allocation error."));
		}

		if ($1[0] != '/')
			yyerror(_("Profile names must begin with a '/'."));

		cod->name = $1;
		cod->flags = $2;
		if (force_complain)
			cod->flags = force_complain_flags;

		PDEBUG("%s: flags='%s%s'\n",
		       $1,
		       cod->flags.complain ? "complain, " : "",
		       cod->flags.audit ? "audit" : "");

		$$ = cod;
	};

profile:	TOK_ID TOK_COLON TOK_ID flags TOK_OPEN rules TOK_CLOSE
	{
		struct codomain *cod = $6;
		PDEBUG("Matched: id (%s:%s) open rules close\n", $1, $3);
		if (!cod) {
			yyerror(_("Memory allocation error."));
		}

		if ($3[0] != '/')
			yyerror(_("Profile names must begin with a '/'."));

		cod->namespace = $1;
		cod->name = $3;
		cod->flags = $4;
		if (force_complain)
			cod->flags = force_complain_flags;

		PDEBUG("%s: flags='%s%s'\n",
		       $1,
		       cod->flags.complain ? "complain, " : "",
		       cod->flags.audit ? "audit" : "");

		$$ = cod;
	};

varlist:	{ /* nothing */ }

varlist: 	varlist varassign
		{ /* nothing */ }

varassign:	TOK_SET_VAR TOK_EQUALS valuelist
	{
		struct value_list *list = $3;
		char *var_name = process_var($1);
		int err;
		if (!list || !list->value)
			yyerror("Assert: valuelist returned NULL");
		PDEBUG("Matched: set assignment for (%s)\n", $1);
		err = new_set_var(var_name, list->value);
		if (err) {
			yyerror("variable %s was previously declared", $1);
			/* FIXME: it'd be handy to report the previous location */
		}
		for (list = list->next; list; list = list->next) {
			err = add_set_value(var_name, list->value);
			if (err)
				yyerror("Error adding %s to set var %s",
					list->value, $1);
		}
		free_value_list($3);
		free(var_name);
		free($1);
	}

varassign:	TOK_SET_VAR TOK_ADD_ASSIGN valuelist
	{
		struct value_list *list = $3;
		char *var_name = process_var($1);
		int err;
		if (!list || !list->value)
			yyerror("Assert: valuelist returned NULL");
		PDEBUG("Matched: additive assignment for (%s)\n", $1);
		/* do the first one outside the loop, subsequent
		 * failures are indicative of symtab failures */
		err = add_set_value(var_name, list->value);
		if (err) {
			yyerror("variable %s was not previously declared, but is being assigned additional values", $1);
		}
		for (list = list->next; list; list = list->next) {
			err = add_set_value(var_name, list->value);
			if (err)
				yyerror("Error adding %s to set var %s",
					list->value, $1);
		}
		free_value_list($3);
		free(var_name);
		free($1);
	}

varassign:	TOK_BOOL_VAR TOK_EQUALS TOK_VALUE
	{
		int boolean, err;
		char *var_name = process_var($1);
		PDEBUG("Matched: boolean assignment (%s) to %s\n", $1, $3);
		boolean = str_to_boolean($3);
		if (boolean == -1) {
			yyerror("Invalid boolean assignment for (%s): %s is not true or false",
				$1, $3);
		}
		err = add_boolean_var(var_name, boolean);
		if (err) {
			yyerror("variable %s was previously declared", $1);
			/* FIXME: it'd be handy to report the previous location */
		}
		free(var_name);
		free($1);
		free($3);
	}

valuelist:	TOK_VALUE
	{
		struct value_list *new = malloc(sizeof(struct value_list));
		if (!new)
			yyerror(_("Memory allocation error."));
		PDEBUG("Matched: value (%s)\n", $1);

		new->value = $1;
		new->next = NULL;
		$$ = new;
	}

valuelist:	valuelist TOK_VALUE
	{
		struct value_list *new = malloc(sizeof(struct value_list));
		if (!new)
			yyerror(_("Memory allocation error."));
		PDEBUG("Matched: value (%s)\n", $1);

		new->value = $2;
		new->next = $1;
		$$ = new;
	}

flags:	{ /* nothing */
		struct flagval fv = { 0, 0, 0 };

		$$ = fv;
	};

flags:	TOK_FLAGS TOK_EQUALS TOK_FLAG_OPENPAREN flagvals TOK_FLAG_CLOSEPAREN
	{
		$$ = $4;
	};

flags: TOK_FLAG_OPENPAREN flagvals TOK_FLAG_CLOSEPAREN
	{
		$$ = $2;
	}

flagvals:	flagvals TOK_FLAG_SEP flagval
	{
		$1.complain = $1.complain || $3.complain;
		$1.audit = $1.audit || $3.audit;

		$$ = $1;
	};

flagvals:	flagval
	{
		$$ = $1;
	};

flagval:	TOK_FLAG_ID
	{
		struct flagval fv = {0, 0, 0};
		if (strcmp($1, "debug") == 0) {
			yyerror(_("Profile flag 'debug' is no longer valid."));
		} else if (strcmp($1, "complain") == 0) {
			fv.complain = 1;
		} else if (strcmp($1, "audit") == 0) {
			fv.audit = 1;
		} else {
			yyerror(_("Invalid profile flag: %s."), $1);
		}
		free($1);
		$$ = fv;
	};

opt_subset_flag: { /* nothing */ $$ = 0; }
	| TOK_SUBSET { $$ = 1; }

rules:	{ /* nothing */ 
		struct codomain *cod = NULL;
		cod = (struct codomain *) calloc(1, sizeof(struct codomain));
		if (!cod) {
			yyerror(_("Memory allocation error."));
		}

		$$ = cod;
	};

rules:  rules rule
	{
		PDEBUG("matched: rules rule\n");
		PDEBUG("rules rule: (%s)\n", $2->name);
		if (!$2)
			yyerror(_("Assert: `rule' returned NULL."));
		add_entry_to_policy($1, $2);
		$$ = $1;
	};

rules:  rules TOK_OWNER owner_rule
	{
		struct cod_entry *entry, *tmp;

		PDEBUG("matched: rules owner_rules\n");
		PDEBUG("rules owner_rules: (%s)\n", $3->name);
		if ($3) {
			list_for_each_safe($3, entry, tmp) {
				entry->next = NULL;
				add_entry_to_policy($1, entry);
			}
		}
		$$ = $1;
	};

rules: rules network_rule
	{
		struct aa_network_entry *entry, *tmp;

		PDEBUG("Matched: network rule\n");
		if (!$2)
			yyerror(_("Assert: `network_rule' return invalid protocol."));
		if (!$1->network_allowed) {
			$1->network_allowed = calloc(AF_MAX,
						     sizeof(unsigned int));
			if (!$1->network_allowed)
				yyerror(_("Memory allocation error."));
		}
		list_for_each_safe($2, entry, tmp) {
			if (entry->type > SOCK_PACKET) {
				/* setting mask instead of a bit */
				$1->network_allowed[entry->family] |= entry->type;
			} else {
				$1->network_allowed[entry->family] |= 1 << entry->type;
			}
			free(entry);
		}

		$$ = $1
	}

rules:	rules change_profile
	{
		PDEBUG("matched: rules change_profile\n");
		PDEBUG("rules change_profile: (%s)\n", $2->name);
		if (!$2)
			yyerror(_("Assert: `change_profile' returned NULL."));
		add_entry_to_policy($1, $2);
		$$ = $1;
	};

rules:	rules capability
	{
		$1->capabilities = $1->capabilities | $2;
		$$ = $1;
	};

rules:	rules hat
	{
		PDEBUG("Matched: hat rule\n");
		if (!$2)
			yyerror(_("Assert: 'hat rule' returned NULL."));
		add_hat_to_policy($1, $2);
		$$ = $1;
	};

rules:	rules cond_rule
	{
		PDEBUG("Matched: conditional rules\n");
		$$ = merge_policy($1, $2);
	}

cond_rule: TOK_IF expr TOK_OPEN rules TOK_CLOSE
	{
		struct codomain *ret = NULL;
		PDEBUG("Matched: found conditional rules\n");
		if ($2) {
			ret = $4;
		} else {
			free_policy($4);
		}
		$$ = ret;
	}

cond_rule: TOK_IF expr TOK_OPEN rules TOK_CLOSE TOK_ELSE TOK_OPEN rules TOK_CLOSE
	{
		struct codomain *ret = NULL;
		PDEBUG("Matched: found conditional else rules\n");
		if ($2) {
			ret = $4;
			free_policy($8);
		} else {
			ret = $8;
			free_policy($4);
		}
		$$ = ret;
	}

cond_rule: TOK_IF expr TOK_OPEN rules TOK_CLOSE TOK_ELSE cond_rule
	{
		struct codomain *ret = NULL;
		PDEBUG("Matched: found conditional else-if rules\n");
		if ($2) {
			ret = $4;
			free_policy($7);
		} else {
			ret = $7;
			free_policy($4);
		}
		$$ = ret;
	}

expr:	TOK_NOT expr
	{
		$$ = !$2;
	}

expr:	TOK_BOOL_VAR
	{
		char *var_name = process_var($1);
		int boolean  = get_boolean_var(var_name);
		PDEBUG("Matched: boolean expr %s value: %d\n", $1, boolean);
		if (boolean < 0) {
			/* FIXME check for set var */
			yyerror(_("Unset boolean variable %s used in if-expression"),
				$1);
		}
		$$ = boolean;
		free(var_name);
		free($1);
	}

expr:	TOK_DEFINED TOK_SET_VAR
	{
		char *var_name = process_var($2);
		void *set_value = get_set_var(var_name);
		PDEBUG("Matched: defined set expr %s value %lx\n", $2, (long) set_value);
		$$ = !! (long) set_value;
		free(var_name);
		free($2);
	}

expr:	TOK_DEFINED TOK_BOOL_VAR
	{
		char *var_name = process_var($2);
		int boolean = get_boolean_var(var_name);
		PDEBUG("Matched: defined set expr %s value %d\n", $2, boolean);
		$$ = (boolean != -1);
		free(var_name);
		free($2);
	}

id_or_var: TOK_ID { $$ = $1; }
id_or_var: TOK_SET_VAR { $$ = $1; };

owner_rule: TOK_OPEN owner_rules TOK_CLOSE
	{
		$$ = $2;
	};

owner_rule: rule
	{
		/* mask mode to owner permissions */
		if ($1) {
			$1->mode &= (AA_USER_PERMS | AA_SHARED_PERMS);
		}
		$$ = $1;
	};

owner_rules: { $$ = NULL; };

owner_rules: owner_rules rule
	{
		if ($2) {
			$2->mode &= (AA_USER_PERMS | AA_SHARED_PERMS);
			$2->next = $1;
		}
		$$ = $2;
	};

rule:	id_or_var file_mode TOK_END_OF_RULE
	{
		$$ = do_file_rule(NULL, $1, $2, NULL);
	};

rule:   file_mode id_or_var TOK_END_OF_RULE
	{
		$$ = do_file_rule(NULL, $2, $1 & ~ALL_AA_EXEC_UNSAFE, NULL);
 	};

rule:	TOK_UNSAFE file_mode id_or_var TOK_END_OF_RULE
	{
		int mode = (($2 & AA_EXEC_BITS) << 8) & ALL_AA_EXEC_UNSAFE;
		if (!($2 & AA_EXEC_BITS))
			yyerror(_("unsafe rule missing exec permissions"));
		$$ = do_file_rule(NULL, $3, ($2 & ~ALL_AA_EXEC_UNSAFE) | mode,
				  NULL);
	};

rule:  id_or_var file_mode id_or_var
	{
		/* Oopsie, we appear to be missing an EOL marker. If we
		 * were *smart*, we could work around it. Since we're
		 * obviously not smart, we'll just punt with a more
		 * sensible error. */
		yyerror(_("missing an end of line character? (entry: %s)"), $1);
	};

rule: TOK_LINK opt_subset_flag TOK_ID TOK_ARROW TOK_ID TOK_END_OF_RULE
	{
		struct cod_entry *entry;
		PDEBUG("Matched: link tok_id (%s) -> (%s)\n", $3, $5);
		entry = new_entry(NULL, $3, AA_LINK_BITS, $5);
		if (!entry)
			yyerror(_("Memory allocation error."));
		entry->subset = $2;
		PDEBUG("rule.entry: link (%s)\n", entry->name);
		$$ = entry;
	};

rule: file_mode opt_subset_flag TOK_ID TOK_ARROW TOK_ID TOK_END_OF_RULE
	{
		struct cod_entry *entry;
		PDEBUG("Matched: link tok_id (%s) -> (%s)\n", $3, $5);
		if ($1 & ~AA_LINK_BITS) {
			yyerror(_("only link perms can be specified in a link rule."));
		} else {
			entry = new_entry(NULL, $3, AA_LINK_BITS, $5);
			if (!entry)
				yyerror(_("Memory allocation error."));
			entry->subset = $2;
		}
		PDEBUG("rule.entry: link (%s)\n", entry->name);
		$$ = entry;
	};

hat: hat_start TOK_ID flags TOK_OPEN rules TOK_CLOSE
	{
		struct codomain *cod = $5;
		PDEBUG("Matched: sep id (%s) open rules close\n", $2);
		if (!cod) {
			yyerror(_("Memory allocation error."));
		}
		cod->name = $2;
		cod->flags = $3;
		if (force_complain)
			cod->flags = force_complain_flags;
		PDEBUG("^%s: flags='%s%s'\n",
		       $2,
		       cod->flags.complain ? "complain, " : "",
		       cod->flags.audit ? "audit" : "");
		$$ = cod;
	};

network_rule: TOK_NETWORK TOK_END_OF_RULE
	{
		int family;
		struct aa_network_entry *new_entry, *entry = NULL;
		for (family = AF_UNSPEC; family < AF_MAX; family++) {
			new_entry = new_network_ent(family, 0xffffffff,
						    0xffffffff);
			if (!new_entry)
				yyerror(_("Memory allocation error."));
			new_entry->next = entry;
			entry = new_entry;
		}
		$$ = entry;
	}

network_rule: TOK_NETWORK TOK_ID TOK_END_OF_RULE
	{
		struct aa_network_entry *entry;
		entry = network_entry($2, NULL, NULL);
		if (!entry)
			/* test for short circuiting of family */
			entry = network_entry(NULL, $2, NULL);
		if (!entry)
			yyerror(_("Invalid network entry."));
		free($2);
		$$ = entry;
	}

network_rule: TOK_NETWORK TOK_ID TOK_ID TOK_END_OF_RULE
	{
		struct aa_network_entry *entry;
		entry = network_entry($2, $3, NULL);
		if (!entry)
			yyerror(_("Invalid network entry."));
		free($2);
		free($3);
		$$ = entry;
	}

hat_start: TOK_SEP {}
	| TOK_HAT {}

file_mode: TOK_MODE
	{
		/* A single TOK_MODE maps to the same permission in all
		 * of user:group:other */
		$$ = parse_mode($1);
		free($1);
	}

change_profile:	TOK_CHANGE_PROFILE TOK_ID TOK_END_OF_RULE
	{
		struct cod_entry *entry;
		PDEBUG("Matched change_profile: tok_id (%s)\n", $2);
		entry = new_entry(NULL, $2, AA_CHANGE_PROFILE, NULL);
		if (!entry)
			yyerror(_("Memory allocation error."));
		PDEBUG("change_profile.entry: (%s)\n", entry->name);
		$$ = entry;
	};

change_profile:	TOK_CHANGE_PROFILE TOK_ID TOK_COLON TOK_ID TOK_END_OF_RULE
	{
		struct cod_entry *entry;
		PDEBUG("Matched change_profile: tok_id (%s:%s)\n", $2, $4);
		entry = new_entry($2, $4, AA_CHANGE_PROFILE, NULL);
		if (!entry)
			yyerror(_("Memory allocation error."));
		PDEBUG("change_profile.entry: (%s)\n", entry->name);
		$$ = entry;
	};

capability:	TOK_CAPABILITY caps TOK_END_OF_RULE
	{
		$$ = $2;		
	};

caps: caps TOK_ID
	{
		int cap = name_to_capability($2);
		if (cap == -1)
			yyerror(_("Invalid capability %s."), $2);
		$$ = $1 | CAP_TO_MASK(cap);
	}

caps: TOK_ID
	{
		int cap = name_to_capability($1);
		if (cap == -1)
			yyerror(_("Invalid capability %s."), $1);
		$$ = CAP_TO_MASK(cap);
	};

%%
#define MAXBUFSIZE 4096

void yyerror(char *msg, ...)
{
	va_list arg;
	char buf[MAXBUFSIZE];

	va_start(arg, msg);
	vsnprintf(buf, sizeof(buf), msg, arg);
	va_end(arg);

	if (profilename) {
		PERROR(_("AppArmor parser error in %s at line %d: %s\n"),
		       profilename, current_lineno, buf);
	} else {
		PERROR(_("AppArmor parser error, line %d: %s\n"),
		       current_lineno, buf);
	}

	exit(1);
}

void free_value_list(struct value_list *list)
{
	struct value_list *next;

	while (list) {
		next = list->next;
		if (list->value)
			free(list->value);
		free(list);
		list = next;
	}
}

struct cod_entry *do_file_rule(char *namespace, char *id, int mode,
			       char *link_id)
{
		struct cod_entry *entry;
		PDEBUG("Matched: tok_id (%s) tok_mode (0x%x)\n", id, mode);
		entry = new_entry(namespace, id, mode, link_id);
		if (!entry)
			yyerror(_("Memory allocation error."));
		PDEBUG("rule.entry: (%s)\n", entry->name);
		return entry;
}
