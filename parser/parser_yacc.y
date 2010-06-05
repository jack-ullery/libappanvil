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
#include "parser_include.h"
#include <unistd.h>
#include <netinet/in.h>
#include <arpa/inet.h>

#include <linux/capability.h>

#ifndef CAP_AUDIT_WRITE
#define CAP_AUDIT_WRITE 29
#endif
#ifndef CAP_AUDIT_CONTROL
#define CAP_AUDIT_CONTROL 30
#endif
#ifndef CAP_SETFCAP
#define CAP_SETFCAP	     31
#endif
#ifndef CAP_MAC_OVERRIDE
#define CAP_MAC_OVERRIDE     32
#endif

#define CIDR_32 htonl(0xffffffff)
#define CIDR_24 htonl(0xffffff00)
#define CIDR_16 htonl(0xffff0000)
#define CIDR_8  htonl(0xff000000)

/* undefine linux/capability.h CAP_TO_MASK */
#ifdef CAP_TO_MASK
#undef CAP_TO_MASK
#endif

#define CAP_TO_MASK(x) (1ull << (x))

struct value_list {
	char *value;
	struct value_list *next;
};

void free_value_list(struct value_list *list);
struct cod_entry *do_file_rule(char *namespace, char *id, int mode,
			       char *link_id, char *nt);

void add_local_entry(struct codomain *cod);

struct codomain *do_local_profile(struct codomain *cod, char *name, int mode, int audit);

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
%token TOK_LE
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
%token TOK_OTHER
%token TOK_SUBSET
%token TOK_AUDIT
%token TOK_DENY
%token TOK_PROFILE
%token TOK_SET
%token TOK_ALIAS
%token TOK_PTRACE

 /* rlimits */
%token TOK_RLIMIT
%token TOK_SOFT_RLIMIT
%token TOK_RLIMIT_CPU
%token TOK_RLIMIT_FSIZE
%token TOK_RLIMIT_DATA
%token TOK_RLIMIT_STACK
%token TOK_RLIMIT_CORE
%token TOK_RLIMIT_RSS
%token TOK_RLIMIT_NOFILE
%token TOK_RLIMIT_OFILE
%token TOK_RLIMIT_AS
%token TOK_RLIMIT_NPROC
%token TOK_RLIMIT_MEMLOCK
%token TOK_RLIMIT_LOCKS
%token TOK_RLIMIT_SIGPENDING
%token TOK_RLIMIT_MSGQUEUE
%token TOK_RLIMIT_NICE
%token TOK_RLIMIT_RTPRIO

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
	struct cod_net_entry *net_entry;
	struct cod_entry *user_entry;
	struct flagval flags;
	int fmode;
	uint64_t cap;
	unsigned int allowed_protocol;
	char *set_var;
	char *bool_var;
	char *var_val;
	struct value_list *val_list;
	int boolean;
	struct named_transition transition;
}

%type <id> 	TOK_ID
%type <mode> 	TOK_MODE
%type <fmode>   file_mode
%type <cod> 	profile
%type <cod>	rules
%type <cod>	hat
%type <cod>	local_profile
%type <cod>	cond_rule
%type <network_entry> network_rule
%type <user_entry> rule
%type <flags>	flags
%type <flags>	flagvals
%type <flags>	flagval
%type <flag_id>	TOK_FLAG_ID
%type <cap>	caps
%type <cap>	capability
%type <cap>	set_caps
%type <user_entry> change_profile
%type <set_var> TOK_SET_VAR
%type <bool_var> TOK_BOOL_VAR
%type <var_val>	TOK_VALUE
%type <val_list> valuelist
%type <boolean> expr
%type <id>	id_or_var
%type <boolean> opt_subset_flag
%type <boolean> opt_audit_flag
%type <boolean> opt_owner_flag
%type <boolean> opt_profile_flag
%type <transition> opt_named_transition

%%


list:	 preamble profilelist
	{ /* nothing */ };

profilelist:	{ /* nothing */ };

profilelist:	profilelist profile
	{
		PDEBUG("Matched: list profile\n");
		add_to_list($2);
	};

opt_profile_flag: { /* nothing */ $$ = 0; }
	| TOK_PROFILE { $$ = 1; }
	| hat_start { $$ = 2; }

profile:	opt_profile_flag TOK_ID flags TOK_OPEN rules TOK_CLOSE
	{
		struct codomain *cod = $5;
		PDEBUG("Matched: id (%s) open rules close\n", $2);
		if (!cod) {
			yyerror(_("Memory allocation error."));
		}

		if (!$1 && $2[0] != '/')
			yyerror(_("Profile names must begin with a '/', or keyword 'profile' or 'hat'."));

		cod->name = $2;
		cod->flags = $3;
		if (force_complain)
			cod->flags.complain = 1;
		if ($1 == 2)
			cod->flags.hat = 1;

		post_process_nt_entries(cod);
		PDEBUG("%s: flags='%s%s'\n",
		       $2,
		       cod->flags.complain ? "complain, " : "",
		       cod->flags.audit ? "audit" : "");

		$$ = cod;
	};

profile:	opt_profile_flag TOK_COLON TOK_ID TOK_COLON TOK_ID flags TOK_OPEN rules TOK_CLOSE
	{
		struct codomain *cod = $8;
		PDEBUG("Matched: id (%s:%s) open rules close\n", $3, $5);
		if (!cod) {
			yyerror(_("Memory allocation error."));
		}

		cod->namespace = $3;
		cod->name = $5;
		cod->flags = $6;
		if (force_complain)
			cod->flags.complain = 1;
		if ($1 == 2)
			cod->flags.hat = 1;

		post_process_nt_entries(cod);
		PDEBUG("%s: flags='%s%s'\n",
		       $3,
		       cod->flags.complain ? "complain, " : "",
		       cod->flags.audit ? "audit" : "");

		$$ = cod;
	};

preamble: { /* nothing */ }
	| preamble alias { /* nothing */ };
	| preamble varassign { /* nothing */ };

alias: TOK_ALIAS TOK_ID TOK_ARROW TOK_ID TOK_END_OF_RULE
	{
		if (!new_alias($2, $4))
			yyerror(_("Failed to create alias %s -> %s\n"), $2, $4);
		free($2);
		free($4);
	};

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
		struct value_list *new = calloc(1, sizeof(struct value_list));
		if (!new)
			yyerror(_("Memory allocation error."));
		PDEBUG("Matched: value (%s)\n", $1);

		new->value = $1;
		new->next = NULL;
		$$ = new;
	}

valuelist:	valuelist TOK_VALUE
	{
		struct value_list *new = calloc(1, sizeof(struct value_list));
		if (!new)
			yyerror(_("Memory allocation error."));
		PDEBUG("Matched: value (%s)\n", $1);

		new->value = $2;
		new->next = $1;
		$$ = new;
	}

flags:	{ /* nothing */
	struct flagval fv = { 0, 0, 0, 0 };

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
		$1.path = $1.path | $3.path;
		if (($1.path & (PATH_CHROOT_REL | PATH_NS_REL)) ==
		    (PATH_CHROOT_REL | PATH_NS_REL))
			yyerror(_("Profile flag chroot_relative conflicts with namespace_relative"));

		if (($1.path & (PATH_MEDIATE_DELETED | PATH_DELEGATE_DELETED)) ==
		    (PATH_MEDIATE_DELETED | PATH_DELEGATE_DELETED))
			yyerror(_("Profile flag mediate_deleted conflicts with delegate_deleted"));
		if (($1.path & (PATH_ATTACH | PATH_NO_ATTACH)) ==
		    (PATH_ATTACH | PATH_NO_ATTACH))
			yyerror(_("Profile flag attach_disconnected conflicts with no_attach_disconnected"));
		if (($1.path & (PATH_CHROOT_NSATTACH | PATH_CHROOT_NO_ATTACH)) ==
		    (PATH_CHROOT_NSATTACH | PATH_CHROOT_NO_ATTACH))
			yyerror(_("Profile flag chroot_attach conflicts with chroot_no_attach"));

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
		} else if (strcmp($1, "chroot_relative") == 0) {
			fv.path |= PATH_CHROOT_REL;
		} else if (strcmp($1, "namespace_relative") == 0) {
			fv.path |= PATH_NS_REL;
		} else if (strcmp($1, "mediate_deleted") == 0) {
			fv.path |= PATH_MEDIATE_DELETED;
		} else if (strcmp($1, "delegate_deleted") == 0) {
			fv.path |= PATH_DELEGATE_DELETED;
		} else if (strcmp($1, "attach_disconnected") == 0) {
			fv.path |= PATH_ATTACH;
		} else if (strcmp($1, "no_attach_disconnected") == 0) {
			fv.path |= PATH_NO_ATTACH;
		} else if (strcmp($1, "chroot_attach") == 0) {
			fv.path |= PATH_CHROOT_NSATTACH;
		} else if (strcmp($1, "chroot_no_attach") == 0) {
			fv.path |= PATH_CHROOT_NO_ATTACH;
		} else {
			yyerror(_("Invalid profile flag: %s."), $1);
		}
		free($1);
		$$ = fv;
	};

opt_subset_flag: { /* nothing */ $$ = 0; }
	| TOK_SUBSET { $$ = 1; }
	| TOK_LE { $$ = 1; }

opt_audit_flag: { /* nothing */ $$ = 0; }
	| TOK_AUDIT { $$ = 1; };

opt_owner_flag: { /* nothing */ $$ = 0; }
	| TOK_OWNER { $$ = 1; };
	| TOK_OTHER { $$ = 2; };

rules:	{ /* nothing */ 
		struct codomain *cod = NULL;
		cod = (struct codomain *) calloc(1, sizeof(struct codomain));
		if (!cod) {
			yyerror(_("Memory allocation error."));
		}

		$$ = cod;
	};

/*  can't fold TOK_DENY in as opt_deny_flag as it messes up the generated
 * parser, even though it shouldn't
 */
rules:  rules opt_audit_flag TOK_DENY opt_owner_flag rule
	{
		PDEBUG("matched: rules rule\n");
		PDEBUG("rules rule: (%s)\n", $5->name);
		if (!$5)
			yyerror(_("Assert: `rule' returned NULL."));
		$5->deny = 1;
		if (($5->mode & AA_EXEC_BITS) && ($5->mode & ALL_AA_EXEC_TYPE))
			yyerror(_("Invalid mode, in deny rules 'x' must not be preceded by exec qualifier 'i', 'p', or 'u'"));

		if ($4 == 1)
			$5->mode &= (AA_USER_PERMS | AA_SHARED_PERMS | AA_USER_PTRACE);
		else if ($4 == 2)
			$5->mode &= (AA_OTHER_PERMS | AA_SHARED_PERMS | AA_OTHER_PTRACE);
		/* only set audit ctl quieting if the rule is not audited */
		if (!$2)
			$5->audit = $5->mode & ~ALL_AA_EXEC_TYPE;

		add_entry_to_policy($1, $5);
		$$ = $1;
	};

rules:  rules opt_audit_flag opt_owner_flag rule
	{
		PDEBUG("matched: rules rule\n");
		PDEBUG("rules rule: (%s)\n", $4->name);
		if (!$4)
			yyerror(_("Assert: `rule' returned NULL."));
		if (($4->mode & AA_EXEC_BITS) &&
		    !($4->mode & ALL_AA_EXEC_TYPE) &&
		    !($4->nt_name))
			yyerror(_("Invalid mode, 'x' must be preceded by exec qualifier 'i', 'p', 'c', or 'u'"));

		if ($3 == 1)
			$4->mode &= (AA_USER_PERMS | AA_SHARED_PERMS | AA_USER_PTRACE);
		else if ($3 == 2)
			$4->mode &= (AA_OTHER_PERMS | AA_SHARED_PERMS | AA_OTHER_PTRACE);
		if ($2)
			$4->audit = $4->mode & ~ALL_AA_EXEC_TYPE;

		add_entry_to_policy($1, $4);
		$$ = $1;
	};

rules: rules opt_audit_flag opt_owner_flag TOK_OPEN rules TOK_CLOSE
	{
		struct cod_entry *entry, *tmp;
		PDEBUG("matched: audit block\n");
		list_for_each_safe($5->entries, entry, tmp) {
			entry->next = NULL;
			if (entry->mode & AA_EXEC_BITS) {
				if (entry->deny &&
				    (entry->mode & ALL_AA_EXEC_TYPE))
					yyerror(_("Invalid mode, in deny rules 'x' must not be preceded by exec qualifier 'i', 'p', or 'u'"));
				else if (!entry->deny &&
					 !(entry->mode & ALL_AA_EXEC_TYPE))
					yyerror(_("Invalid mode, 'x' must be preceded by exec qualifier 'i', 'p', or 'u'"));
			}
			if ($3 == 1)
 				entry->mode &= (AA_USER_PERMS | AA_SHARED_PERMS | AA_USER_PTRACE);
			else if ($3 == 2)
				entry->mode &= (AA_OTHER_PERMS | AA_SHARED_PERMS | AA_OTHER_PTRACE);

			if ($2 && !entry->deny)
				entry->audit = entry->mode & ~ALL_AA_EXEC_TYPE;
			else if (!$2 && entry->deny)
				 entry->audit = entry->mode & ~ALL_AA_EXEC_TYPE;
			add_entry_to_policy($1, entry);
		}
		$5->entries = NULL;
		// fix me transfer rules and free sub codomain
		free_policy($5);
		$$ = $1;
	};

rules: rules opt_audit_flag TOK_DENY network_rule
	{
		struct aa_network_entry *entry, *tmp;

		PDEBUG("Matched: network rule\n");
		if (!$4)
			yyerror(_("Assert: `network_rule' return invalid protocol."));
		if (!$1->network_allowed) {
			$1->network_allowed = calloc(get_af_max(),
						     sizeof(unsigned int));
			$1->audit_network = calloc(get_af_max(),
						   sizeof(unsigned int));
			$1->deny_network = calloc(get_af_max(),
						     sizeof(unsigned int));
			$1->quiet_network = calloc(get_af_max(),
						     sizeof(unsigned int));
			if (!$1->network_allowed || !$1->audit_network ||
			    !$1->deny_network || !$1->quiet_network)
				yyerror(_("Memory allocation error."));
		}
		list_for_each_safe($4, entry, tmp) {
			if (entry->type > SOCK_PACKET) {
				/* setting mask instead of a bit */
				$1->deny_network[entry->family] |= entry->type;
				if (!$2)
					$1->quiet_network[entry->family] |= entry->type;

			} else {
				$1->deny_network[entry->family] |= 1 << entry->type;
				if (!$2)
					$1->quiet_network[entry->family] |= 1 << entry->type;
			}
			free(entry);
		}

		$$ = $1;
	}

rules: rules opt_audit_flag network_rule
	{
		struct aa_network_entry *entry, *tmp;

		PDEBUG("Matched: network rule\n");
		if (!$3)
			yyerror(_("Assert: `network_rule' return invalid protocol."));
		if (!$1->network_allowed) {
			$1->network_allowed = calloc(get_af_max(),
						     sizeof(unsigned int));
			$1->audit_network = calloc(get_af_max(),
						   sizeof(unsigned int));
			$1->deny_network = calloc(get_af_max(),
						     sizeof(unsigned int));
			$1->quiet_network = calloc(get_af_max(),
						     sizeof(unsigned int));
			if (!$1->network_allowed || !$1->audit_network ||
			    !$1->deny_network || !$1->quiet_network)
				yyerror(_("Memory allocation error."));
		}
		list_for_each_safe($3, entry, tmp) {
			if (entry->type > SOCK_PACKET) {
				/* setting mask instead of a bit */
				$1->network_allowed[entry->family] |= entry->type;
				if ($2)
					$1->audit_network[entry->family] |= entry->type;

			} else {
				$1->network_allowed[entry->family] |= 1 << entry->type;
				if ($2)
					$1->audit_network[entry->family] |= 1 << entry->type;
			}
			free(entry);
		}

		$$ = $1;
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

rules:	rules opt_audit_flag TOK_DENY capability
	{
		$1->deny_caps |= $4;
		if (!$2)
			$1->quiet_caps |= $4;
		$$ = $1;
	};

rules:	rules opt_audit_flag capability
	{
		$1->capabilities |= $3;
		if ($2)
			$1->audit_caps |= $3;
		$$ = $1;
	};

rules: rules set_caps
	{
		$1->set_caps |= $2;
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

rules:	rules local_profile
	{
		PDEBUG("Matched: hat rule\n");
		if (!$2)
			yyerror(_("Assert: 'local_profile rule' returned NULL."));
		add_hat_to_policy($1, $2);
		add_local_entry($2);
		$$ = $1;
	};

rules:	rules cond_rule
	{
		PDEBUG("Matched: conditional rules\n");
		$$ = merge_policy($1, $2);
	}

rules: rules TOK_SET TOK_RLIMIT TOK_ID TOK_LE TOK_VALUE TOK_END_OF_RULE
	{
		rlim_t value = RLIM_INFINITY;
		long long tmp;
		char *end;

		int limit = get_rlimit($4);
		if (limit == -1)
			yyerror("INVALID RLIMIT '%s'\n", $4);

		if (strcmp($6, "infinity") == 0) {
			value = RLIM_INFINITY;
		} else {
			tmp = strtoll($6, &end, 0);
			switch (limit) {
			case RLIMIT_CPU:
				yyerror("RLIMIT '%s' is currently unsupported\n", $4);
				break;
			case RLIMIT_NOFILE:
			case RLIMIT_NPROC:
			case RLIMIT_LOCKS:
			case RLIMIT_SIGPENDING:
#ifdef RLIMIT_RTPRIO
			case RLIMIT_RTPRIO:
				if ($6 == end || *end != '\0' || tmp < 0)
					yyerror("RLIMIT '%s' invalid value %s\n", $4, $6);
				value = tmp;
				break;
#endif
#ifdef RLIMIT_NICE
			case RLIMIT_NICE:
				if ($6 == end || *end != '\0')
					yyerror("RLIMIT '%s' invalid value %s\n", $4, $6);
				if (tmp < -20 || tmp > 19)
					yyerror("RLIMIT '%s' out of range (-20 .. 19) %d\n", $4, tmp);
				value = tmp + 20;
				break;
#endif
			case RLIMIT_FSIZE:
			case RLIMIT_DATA:
			case RLIMIT_STACK:
			case RLIMIT_CORE:
			case RLIMIT_RSS:
			case RLIMIT_AS:
			case RLIMIT_MEMLOCK:
			case RLIMIT_MSGQUEUE:
				if ($6 == end || tmp < 0)
					yyerror("RLIMIT '%s' invalid value %s\n", $4, $6);
				if (strcmp(end, "K") == 0) {
					tmp *= 1024;
				} else if (strcmp(end, "M") == 0) {
					tmp *= 1024*1024;
				} else if (strcmp(end, "G") == 0) {
					tmp *= 1024*1024*1024;
				} else if (*end != '\0') {
					yyerror("RLIMIT '%s' invalid value %s\n", $4, $6);
				}
				value = tmp;
				break;
			default:
				yyerror("Unknown RLIMIT %d\n", $4);
			}
		}
		$1->rlimits.specified |= 1 << limit;
		$1->rlimits.limits[limit] = value;
		free($4);
		free($6);
		$$ = $1;
	};


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

opt_named_transition:
	{ /* nothing */
		$$.present = 0;
		$$.namespace = NULL;
		$$.name = NULL;
	}
	| TOK_ARROW id_or_var
	{
		$$.present = 1;
		$$.namespace = NULL;
		$$.name = $2;
	}
	| TOK_ARROW TOK_COLON id_or_var TOK_COLON id_or_var
	{
		$$.present = 1;
		$$.namespace = $3;
		$$.name = $5;
	};

rule:	id_or_var file_mode opt_named_transition TOK_END_OF_RULE
	{
		$$ = do_file_rule($3.namespace, $1, $2, NULL, $3.name);
	};

rule:   file_mode opt_subset_flag id_or_var opt_named_transition TOK_END_OF_RULE
	{
		if ($2 && ($1 & ~AA_LINK_BITS))
			yyerror(_("subset can only be used with link rules."));
		if ($4.present && ($1 & AA_LINK_BITS) && ($1 & AA_EXEC_BITS))
			yyerror(_("link and exec perms conflict on a file rule using ->"));
		if ($4.present && $4.namespace && ($1 & AA_LINK_BITS))
			yyerror(_("link perms are not allowed on a named profile transition.\n"));
		if (($1 & AA_LINK_BITS)) {
			$$ = do_file_rule(NULL, $3, $1 & ~ALL_AA_EXEC_UNSAFE,
					  $4.name, NULL);
			$$->subset = $2;

		} else {
			$$ = do_file_rule($4.namespace, $3, $1 & ~ALL_AA_EXEC_UNSAFE, NULL, $4.name);
		}
 	};

rule:	TOK_UNSAFE file_mode id_or_var opt_named_transition TOK_END_OF_RULE
	{
		int mode = (($2 & AA_EXEC_BITS) << 8) & ALL_AA_EXEC_UNSAFE;

		if (!($2 & AA_EXEC_BITS))
			yyerror(_("unsafe rule missing exec permissions"));

		if ($4.present && ($2 & AA_LINK_BITS))
			yyerror(_("link perms are not allowed on a named profile transition.\n"));

		$$ = do_file_rule($4.namespace, $3,
				  ($2 & ~ALL_AA_EXEC_UNSAFE) | mode,
				  NULL, $4.name);
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
		entry->subset = $2;
		PDEBUG("rule.entry: link (%s)\n", entry->name);
		$$ = entry;
	};

rule: TOK_PTRACE TOK_ID TOK_END_OF_RULE
	{
		struct cod_entry *entry;
		entry = new_entry(NULL, $2, AA_USER_PTRACE | AA_OTHER_PTRACE, NULL);
		if (!entry)
			yyerror(_("Memory allocation error."));
		$$ = entry;
	};

rule: TOK_PTRACE TOK_COLON TOK_ID TOK_COLON TOK_ID TOK_END_OF_RULE
	{
		struct cod_entry *entry;
		entry = new_entry($3, $5, AA_USER_PTRACE | AA_OTHER_PTRACE, NULL);
		if (!entry)
			yyerror(_("Memory allocation error."));
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
		cod->flags.hat = 1;
		if (force_complain)
			cod->flags.complain = 1;
		post_process_nt_entries(cod);
		PDEBUG("^%s: flags='%s%s'\n",
		       $2,
		       cod->flags.complain ? "complain, " : "",
		       cod->flags.audit ? "audit" : "");
		$$ = cod;
	};

/*
local_profile:   opt_audit_flag opt_owner_flag TOK_ID file_mode TOK_ARROW TOK_OPEN rules TOK_CLOSE
	{
		int audit = 0, mode = $4;
		if ($2 == 1)
			mode &= (AA_USER_PERMS | AA_SHARED_PERMS | AA_USER_PTRACE);
		else if ($2 == 2)
			mode &= (AA_OTHER_PERMS | AA_SHARED_PERMS | AA_OTHER_PTRACE);
		if ($1)
			audit = mode & ~ALL_AA_EXEC_TYPE;

		$$ = do_local_profile($7, $3, mode, audit);
	};

local_profile:   opt_audit_flag opt_owner_flag file_mode TOK_ID TOK_ARROW TOK_OPEN rules TOK_CLOSE
	{
		int audit = 0, mode = $3;
		mode &= ~ALL_AA_EXEC_UNSAFE;
		if ($2 == 1)
			mode &= (AA_USER_PERMS | AA_SHARED_PERMS | AA_USER_PTRACE);
		else if ($2 == 2)
			mode &= (AA_OTHER_PERMS | AA_SHARED_PERMS | AA_OTHER_PTRACE);
		if ($1)
			audit = mode & ~ALL_AA_EXEC_TYPE;

		$$ = do_local_profile($7, $4, mode, audit);
	};

local_profile:   opt_audit_flag opt_owner_flag TOK_UNSAFE file_mode TOK_ID TOK_ARROW TOK_OPEN rules TOK_CLOSE
	{
		int unsafe = (($4 & AA_EXEC_BITS) << 8) & ALL_AA_EXEC_UNSAFE;
		int audit = 0, mode = ($4 & ~ALL_AA_EXEC_UNSAFE) | unsafe;
		if ($2 == 1)
			mode &= (AA_USER_PERMS | AA_SHARED_PERMS | AA_USER_PTRACE);
		else if ($2 == 2)
			mode &= (AA_OTHER_PERMS | AA_SHARED_PERMS | AA_OTHER_PTRACE);
		if ($1)
			audit = mode & ~ALL_AA_EXEC_TYPE;

		$$ = do_local_profile($8, $5, mode, audit);
	};
*/

local_profile:   TOK_PROFILE TOK_ID flags TOK_OPEN rules TOK_CLOSE
	{
		struct codomain *cod = do_local_profile($5, $2, 0, 0);
		cod->flags = $3;
		$$ = cod;
	};

network_rule: TOK_NETWORK TOK_END_OF_RULE
	{
		size_t family;
		struct aa_network_entry *new_entry, *entry = NULL;
		for (family = AF_UNSPEC; family < get_af_max(); family++) {
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
		 * of user::other */
		$$ = parse_mode($1);
		free($1);
	}

change_profile:	TOK_CHANGE_PROFILE TOK_ARROW TOK_ID TOK_END_OF_RULE
	{
		struct cod_entry *entry;
		PDEBUG("Matched change_profile: tok_id (%s)\n", $3);
		entry = new_entry(NULL, $3, AA_CHANGE_PROFILE, NULL);
		if (!entry)
			yyerror(_("Memory allocation error."));
		PDEBUG("change_profile.entry: (%s)\n", entry->name);
		$$ = entry;
	};

change_profile:	TOK_CHANGE_PROFILE TOK_ARROW TOK_COLON TOK_ID TOK_COLON TOK_ID TOK_END_OF_RULE
	{
		struct cod_entry *entry;
		PDEBUG("Matched change_profile: tok_id (%s:%s)\n", $4, $6);
		entry = new_entry($4, $6, AA_CHANGE_PROFILE, NULL);
		if (!entry)
			yyerror(_("Memory allocation error."));
		PDEBUG("change_profile.entry: (%s)\n", entry->name);
		$$ = entry;
	};


set_caps:	TOK_SET TOK_CAPABILITY caps TOK_END_OF_RULE
	{
		$$ = $3;
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
		free($2);
		$$ = $1 | CAP_TO_MASK(cap);
	}

caps: TOK_ID
	{
		int cap = name_to_capability($1);
		if (cap == -1)
			yyerror(_("Invalid capability %s."), $1);
		free($1);
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
		PERROR(_("AppArmor parser error for %s%s%s at line %d: %s\n"),
		       profilename,
		       current_filename ? " in " : "",
		       current_filename ? current_filename : "",
		       current_lineno, buf);
	} else {
		PERROR(_("AppArmor parser error,%s%s line %d: %s\n"),
		       current_filename ? " in " : "",
		       current_filename ? current_filename : "",
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
			       char *link_id, char *nt)
{
		struct cod_entry *entry;
		PDEBUG("Matched: tok_id (%s) tok_mode (0x%x)\n", id, mode);
		entry = new_entry(namespace, id, mode, link_id);
		if (!entry)
			yyerror(_("Memory allocation error."));
		entry->nt_name = nt;
		PDEBUG("rule.entry: (%s)\n", entry->name);
		return entry;
}

/* Note: NOT currently in use, used for 
 * /foo x -> { /bah, }   style transitions
 */
void add_local_entry(struct codomain *cod)
{
	/* ugh this has to be called after the hat is attached to its parent */
	if (cod->local_mode) {
		struct cod_entry *entry;
		char *trans = malloc(strlen(cod->parent->name) +
				    strlen(cod->name) + 3);
		char *name = strdup(cod->name);
		if (!trans)
			yyerror(_("Memory allocation error."));
		sprintf(name, "%s//%s", cod->parent->name, cod->name);

		entry = new_entry(NULL, name, cod->local_mode, NULL);
		entry->audit = cod->local_audit;
		entry->nt_name = trans;
		if (!entry)
			yyerror(_("Memory allocation error."));

		add_entry_to_policy(cod, entry);
	}
}

struct codomain *do_local_profile(struct codomain *cod, char *name, int mode,
	int audit)
{
	PDEBUG("Matched: local profile trans (%s) open rules close\n", $1);
	if (!cod) {
		yyerror(_("Memory allocation error."));
	}
	cod->name = name;
	if (force_complain)
		cod->flags.complain = 1;
	post_process_nt_entries(cod);
	PDEBUG("profile %s: flags='%s%s'\n",
	       name,
	       cod->flags.complain ? "complain, " : "",
	       cod->flags.audit ? "audit" : "");

	cod->local = 1;
	cod->local_mode = mode;
	cod->local_audit = audit;

	return cod;
}
