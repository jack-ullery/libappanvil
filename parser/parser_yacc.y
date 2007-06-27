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

%}

%token TOK_ID
%token TOK_SEP
%token TOK_OPEN
%token TOK_CLOSE
%token TOK_MODE
%token TOK_END_OF_RULE
%token TOK_EQUALS
%token TOK_ADD_ASSIGN
%token TOK_SET_VAR
%token TOK_BOOL_VAR
%token TOK_VALUE
%token TOK_IF
%token TOK_ELSE
%token TOK_NOT
%token TOK_DEFINED
%token TOK_CHANGE_PROFILE

/* network tokens */
%token TOK_IP
%token TOK_IFACE
%token TOK_ACTION
%token TOK_PORT
%token TOK_PORT_IDENT
%token TOK_NUM
%token TOK_COLON
%token TOK_SLASH
%token TOK_RANGE
%token TOK_VIA
%token TOK_TO
%token TOK_FROM
%token TOK_TCP_CONN
%token TOK_TCP_ACPT
%token TOK_TCP_CONN_ESTB
%token TOK_TCP_ACPT_ESTB
%token TOK_UDP_SEND
%token TOK_UDP_RECV

/* capabilities */
%token TOK_CAPABILITY
%token TOK_CAP_CHOWN
%token TOK_CAP_DAC_OVERRIDE
%token TOK_CAP_DAC_READ_SEARCH
%token TOK_CAP_FOWNER
%token TOK_CAP_FSETID
%token TOK_CAP_KILL
%token TOK_CAP_SETGID
%token TOK_CAP_SETUID
%token TOK_CAP_SETPCAP
%token TOK_CAP_LINUX_IMMUTABLE
%token TOK_CAP_NET_BIND_SERVICE
%token TOK_CAP_NET_BROADCAST
%token TOK_CAP_NET_ADMIN
%token TOK_CAP_NET_RAW
%token TOK_CAP_IPC_LOCK
%token TOK_CAP_IPC_OWNER
%token TOK_CAP_SYS_MODULE
%token TOK_CAP_SYS_RAWIO
%token TOK_CAP_SYS_CHROOT
%token TOK_CAP_SYS_PTRACE
%token TOK_CAP_SYS_PACCT
%token TOK_CAP_SYS_ADMIN
%token TOK_CAP_SYS_BOOT
%token TOK_CAP_SYS_NICE
%token TOK_CAP_SYS_RESOURCE
%token TOK_CAP_SYS_TIME
%token TOK_CAP_SYS_TTY_CONFIG
%token TOK_CAP_MKNOD
%token TOK_CAP_LEASE
%token TOK_CAP_AUDIT_WRITE
%token TOK_CAP_AUDIT_CONTROL

/* debug flag values */
%token TOK_FLAGS
%token TOK_FLAG_OPENPAREN
%token TOK_FLAG_CLOSEPAREN
%token TOK_FLAG_SEP
%token TOK_FLAG_DEBUG
%token TOK_FLAG_COMPLAIN
%token TOK_FLAG_AUDIT

%union {
	char *id;
	char *ip;
	char *iface;
	char *mode;
	char *eth;
	/* char * action; */
	char *via;
	/* char * port; */
	unsigned long int num;
	struct codomain *cod;
	struct cod_global_entry *entry;
	struct cod_net_entry *net_entry;
	struct cod_entry *user_entry;
	struct ipv4_desc *ipv4;
	struct ipv4_endpoints *endpoints;
	unsigned short (*port)[2];
	int action;
	struct flagval flags;
	unsigned int cap;
	char *set_var;
	char *bool_var;
	char *var_val;
	struct value_list *val_list;
	int boolean;
}

%type <id> 	TOK_ID
%type <mode> 	TOK_MODE
%type <cod> 	profile
%type <cod>	rules
%type <cod>	hat
%type <cod>	cond_rule
%type <net_entry> netrule
%type <user_entry> rule
%type <ipv4>	address
%type <endpoints> addresses
%type <num>     mask
%type <port>    ports
%type <ip>	TOK_IP
%type <iface>	TOK_IFACE interface
%type <action>	TOK_ACTION
%type <via>	TOK_VIA
%type <port>    TOK_PORT_IDENT
%type <num>	TOK_NUM
%type <action>	action
%type <flags>	flags
%type <flags>	flagvals
%type <flags>	flagval
%type <cap>	cap
%type <cap>	capability
%type <user_entry> change_profile
%type <set_var> TOK_SET_VAR
%type <bool_var> TOK_BOOL_VAR
%type <var_val>	TOK_VALUE
%type <val_list> valuelist
%type <boolean> expr

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

flagval:	TOK_FLAG_DEBUG 
	{
		PDEBUG("Matched: flag debug\n");
		yyerror(_("flags=(debug) is no longer supported, sorry."));
	};

flagval:	TOK_FLAG_COMPLAIN
	{
		struct flagval fv = { 0, 1, 0 };

		PDEBUG("Matched: flag complain\n");

		$$ = fv;
	};

flagval:	TOK_FLAG_AUDIT
	{
		struct flagval fv = { 0, 0, 1 };

		PDEBUG("Matched: flag audit\n");

		$$ = fv;
	};

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

rules: rules netrule 
	{
		PDEBUG("Matched: netrules rule\n");
		if (!$2)
			yyerror(_("Assert: `netrule' returned NULL."));
		PDEBUG("Assigning %s\n", inet_ntoa(*$2->saddr));
		PDEBUG("Assigning %s\n", inet_ntoa(*$2->daddr));
		add_netrule_to_policy($1, $2);
		$$ = $1;
	};

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
		$1->capabilities = $1->capabilities | CAP_TO_MASK($2);
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

rule:	TOK_ID TOK_MODE TOK_END_OF_RULE
	{
		struct cod_entry *entry;
		PDEBUG("Matched: tok_id (%s) tok_mode (%s)\n", $1, $2);
		entry = new_entry($1, parse_mode($2));
		if (!entry)
			yyerror(_("Memory allocation error."));
		PDEBUG("rule.entry: (%s)\n", entry->name);
		free($2);
		$$ = entry;
	};

rule:	TOK_SET_VAR TOK_MODE TOK_END_OF_RULE
	{
		struct cod_entry *entry;
		PDEBUG("Matched: tok_id (%s) tok_mode (%s)\n", $1, $2);
		entry = new_entry($1, parse_mode($2));
		if (!entry)
			yyerror(_("Memory allocation error."));
		PDEBUG("rule.entry: (%s)\n", entry->name);
		free($2);
		$$ = entry;
	};

rule:  TOK_ID TOK_MODE TOK_ID
	{
		/* Oopsie, we appear to be missing an EOL marker. If we
		 * were *smart*, we could work around it. Since we're
		 * obviously not smart, we'll just punt with a more
		 * sensible error. */
		yyerror(_("missing an end of line character? (entry: %s)"), $1);
	};

hat: TOK_SEP TOK_ID flags TOK_OPEN rules TOK_CLOSE 
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


/*
 * The addition of an entirely new grammer set to our (previously) slim 
 * profile spec is below.  It's designed to look quite similar to 
 * (Free|Open)BSD's ipfw rules:
 * 
 * 'tcp_connect to 10.0.0.40:80 via eth0' for example.
 * 
 * 
 * mb:
 * We need to verify the following rules:
 */
  
netrule:   action addresses interface TOK_END_OF_RULE
	{
		struct cod_net_entry *entry;

		entry = NULL;
		
		if (!$2)
			yyerror(_("Assert: `addresses' returned NULL."));

		PDEBUG("Matched action (%d) via (%s)\n", $1, $3);
		entry = new_network_entry($1, $2, $3);
		if (!entry)
			yyerror(_("Memory allocation error."));

		free_ipv4_endpoints($2);
		$$ = entry;
	};
	
action:		TOK_TCP_CONN { $$ = AA_TCP_CONNECT; }
	|	TOK_TCP_ACPT { $$ = AA_TCP_ACCEPT; }
	|	TOK_TCP_CONN_ESTB { $$ = AA_TCP_CONNECTED; }
	|       TOK_TCP_ACPT_ESTB { $$ = AA_TCP_ACCEPTED; }
	|	TOK_UDP_SEND { $$ = AA_UDP_SEND; }
	|	TOK_UDP_RECV { $$ = AA_UDP_RECEIVE; }
	;
	

interface:	/* nothing, no interface specified */
	{
		$$ = NULL;
	};
interface:	TOK_VIA TOK_IFACE
	{
		PDEBUG ("Matched an interface (%s)\n", $2);
		$$ = $2;
	};

addresses:	/* Nothing */
	{
		struct ipv4_endpoints *addresses;

		addresses = (struct ipv4_endpoints *) 
				malloc (sizeof (struct ipv4_endpoints));
		if (!addresses)
			yyerror(_("Memory allocation error."));
		addresses->src = NULL;
		addresses->dest = NULL;

		$$ = addresses;
	};

addresses:	TOK_TO address
	{
		struct ipv4_endpoints *addresses;

		addresses = (struct ipv4_endpoints *) 
				malloc(sizeof (struct ipv4_endpoints));
		if (!addresses)
			yyerror(_("Memory allocation error."));
		addresses->src = NULL;
		addresses->dest = $2;

		$$ = addresses;
	};
		
addresses:	TOK_FROM address
	{
		struct ipv4_endpoints *addresses;

		addresses = (struct ipv4_endpoints *) 
				malloc(sizeof (struct ipv4_endpoints));
		if (!addresses)
			yyerror(_("Memory allocation error."));
		addresses->src = $2;
		addresses->dest = NULL;

		$$ = addresses;
	};
		
addresses:	TOK_FROM address TOK_TO address
	{
		struct ipv4_endpoints *addresses;

		addresses = (struct ipv4_endpoints *) 
				malloc (sizeof (struct ipv4_endpoints));
		if (!addresses)
			yyerror(_("Memory allocation error."));
		addresses->src = $2;
		addresses->dest = $4;

		$$ = addresses;
	};
		
addresses:	TOK_TO address TOK_FROM address
	{
		struct ipv4_endpoints *addresses;

		addresses = (struct ipv4_endpoints *) 
				malloc(sizeof (struct ipv4_endpoints));
		if (!addresses)
			yyerror(_("Memory allocation error."));
		addresses->src = $4;
		addresses->dest = $2;

		$$ = addresses;
	};
		
addresses:	TOK_TO address TOK_TO
	{
		/* better error warnings (hopefully) */
		yyerror(_("Network entries can only have one TO address."));
	};
addresses:	TOK_FROM address TOK_FROM
	{
		/* better error warnings (hopefully) */
		yyerror(_("Network entries can only have one FROM address."));
	};
address:	TOK_IP ports
	{
		/* Bleah, I have to handle address as two rules, because
		 * if the user provides an ip of 0.0.0.0 and no mask, we
		 * treat it as 0.0.0.0/0 instead of 0.0.0.0/32. */

		struct ipv4_desc *address;

		address = (struct ipv4_desc *) 
				malloc (sizeof (struct ipv4_desc));
		if (!address)
			yyerror(_("Memory allocation error."));

		address->port[0] = (*$2)[0];
		address->port[1] = (*$2)[1];
		if (inet_aton($1, &(address->addr)) == 0)
			yyerror(_("`%s' is not a valid ip address."), $1);
		if (address->addr.s_addr == 0) {
			/* the user specified 0.0.0.0 without giving an
			 * explicit mask, so treat it as 0.0.0.0/0 */
			address->mask = htonl (0UL);
		} else {
			/* otherwise, treat it as /32 */
			address->mask = htonl (0xffffffff);
		}
		PDEBUG("Matched an IP (%s/%d:%d-%d)\n",
				inet_ntoa(address->addr), address->mask,
				address->port[0], address->port[1]);

		free($1);
		free(*$2);
		$$ = address;
	};
		
address:	TOK_IP mask ports
	{
		struct ipv4_desc *address;

		address = (struct ipv4_desc *) 
				malloc(sizeof (struct ipv4_desc));
		if (!address)
			yyerror(_("Memory allocation error."));

		address->mask = $2;
		address->port[0] = (*$3)[0];
		address->port[1] = (*$3)[1];
		if (inet_aton($1, &(address->addr)) == 0)
			yyerror(_("`%s' is not a valid ip address."), $1);
		PDEBUG("Matched an IP (%s/%d:%d-%d)\n",
				inet_ntoa(address->addr), address->mask,
				address->port[0], address->port[1]);
		free($1);
		free(*$3);
		$$ = address;
	};
		
mask:		TOK_SLASH TOK_NUM
	{
		PDEBUG("Matched a netmask (%d)\n", $2);
		if (($2 < 0) || ($2 > 32))
			yyerror(_("`/%d' is not a valid netmask."), $2);
		$$ = htonl(0xffffffff << (32 - $2));
	};
mask:		TOK_SLASH TOK_IP
	{
		struct in_addr mask;
		if (inet_aton($2, &mask) == 0)
			yyerror(_("`%s' is not a valid netmask."), $2);
		PDEBUG("Matched a netmask (%d)\n", mask.s_addr);
		$$ = mask.s_addr;
	};
		
ports:	{
		/* nothing, return all ports */
		unsigned short (*ports)[2];

		ports = (unsigned short (*)[2]) 
				malloc(sizeof (unsigned short [2]));
		if (!ports)
			yyerror(_("Memory allocation error."));
		(*ports)[0] = MIN_PORT;
		(*ports)[1] = MAX_PORT;
		
		$$ = ports;
	};
ports:		TOK_COLON TOK_NUM
	{
		unsigned short (*ports)[2];
		
		PDEBUG("Matched a single port (%d)\n", $2);
		ports = (unsigned short (*)[2]) 
				malloc(sizeof (unsigned short [2]));
		if (($2 < MIN_PORT) || ($2 > MAX_PORT))
			yyerror(_("ports must be between %d and %d"),
				MIN_PORT, MAX_PORT);
		if (!ports)
			yyerror(_("Memory allocation error."));
		(*ports)[0] = $2;
		(*ports)[1] = $2;
		
		$$ = ports;
	};
ports:		TOK_COLON TOK_NUM TOK_RANGE TOK_NUM
	{
		unsigned short (*ports)[2];

		PDEBUG("Matched a port range (%d,%d)\n", $2, $4);
		ports = (unsigned short (*)[2]) 
				malloc(sizeof (unsigned short [2]));
		if (!ports)
			yyerror(_("Memory allocation error."));
		if (($2 < MIN_PORT) || ($4 > MAX_PORT) 
		 || ($2 < MIN_PORT) || ($4 > MAX_PORT))
			yyerror(_("ports must be between %d and %d"),
				 MIN_PORT, MAX_PORT);
		(*ports)[0] = $2;
		(*ports)[1] = $4;

		if ((*ports)[0] > (*ports)[1])
		{
			unsigned short tmp;
			pwarn("expected first port number to be less than the second, swapping (%ld,%ld)\n",
				$2, $4);
			tmp = (*ports)[0];
			(*ports)[0] = (*ports)[1];
			(*ports)[1] = tmp;
		}
		
		$$ = ports;
	};

change_profile:	TOK_CHANGE_PROFILE TOK_ID TOK_END_OF_RULE
	{
		struct cod_entry *entry;
		PDEBUG("Matched change_profile: tok_id (%s)\n", $2);
		entry = new_entry($2, AA_CHANGE_PROFILE);
		if (!entry)
			yyerror(_("Memory allocation error."));
		PDEBUG("change_profile.entry: (%s)\n", entry->name);
		$$ = entry;
	};

capability:	TOK_CAPABILITY cap TOK_END_OF_RULE
	{
		$$ = $2;		
	};

cap: 	TOK_CAP_CHOWN			{ $$ = CAP_CHOWN; }
	| TOK_CAP_DAC_OVERRIDE		{ $$ = CAP_DAC_OVERRIDE; }
	| TOK_CAP_DAC_READ_SEARCH	{ $$ = CAP_DAC_READ_SEARCH; }
	| TOK_CAP_FOWNER		{ $$ = CAP_FOWNER; }
	| TOK_CAP_FSETID		{ $$ = CAP_FSETID; }
	| TOK_CAP_KILL			{ $$ = CAP_KILL; }
	| TOK_CAP_SETGID		{ $$ = CAP_SETGID; }
	| TOK_CAP_SETUID		{ $$ = CAP_SETUID; }
	| TOK_CAP_SETPCAP		{ $$ = CAP_SETPCAP; }
	| TOK_CAP_LINUX_IMMUTABLE	{ $$ = CAP_LINUX_IMMUTABLE; }
	| TOK_CAP_NET_BIND_SERVICE	{ $$ = CAP_NET_BIND_SERVICE; }
	| TOK_CAP_NET_BROADCAST		{ $$ = CAP_NET_BROADCAST; }
	| TOK_CAP_NET_ADMIN		{ $$ = CAP_NET_ADMIN; }
	| TOK_CAP_NET_RAW		{ $$ = CAP_NET_RAW; }
	| TOK_CAP_IPC_LOCK		{ $$ = CAP_IPC_LOCK; }
	| TOK_CAP_IPC_OWNER		{ $$ = CAP_IPC_OWNER; }
	| TOK_CAP_SYS_MODULE		{ $$ = CAP_SYS_MODULE; }
	| TOK_CAP_SYS_RAWIO		{ $$ = CAP_SYS_RAWIO; }
	| TOK_CAP_SYS_CHROOT		{ $$ = CAP_SYS_CHROOT; }
	| TOK_CAP_SYS_PTRACE		{ $$ = CAP_SYS_PTRACE; }
	| TOK_CAP_SYS_PACCT		{ $$ = CAP_SYS_PACCT; }
	| TOK_CAP_SYS_ADMIN		{ $$ = CAP_SYS_ADMIN; }
	| TOK_CAP_SYS_BOOT		{ $$ = CAP_SYS_BOOT; }
	| TOK_CAP_SYS_NICE		{ $$ = CAP_SYS_NICE; }
	| TOK_CAP_SYS_RESOURCE		{ $$ = CAP_SYS_RESOURCE; }
	| TOK_CAP_SYS_TIME		{ $$ = CAP_SYS_TIME; }
	| TOK_CAP_SYS_TTY_CONFIG	{ $$ = CAP_SYS_TTY_CONFIG; }
	| TOK_CAP_MKNOD			{ $$ = CAP_MKNOD; }
	| TOK_CAP_LEASE			{ $$ = CAP_LEASE; }
	| TOK_CAP_AUDIT_WRITE		{ $$ = CAP_AUDIT_WRITE; }
	| TOK_CAP_AUDIT_CONTROL		{ $$ = CAP_AUDIT_CONTROL; }
		
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

