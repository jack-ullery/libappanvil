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

/* assistance routines */

#define _GNU_SOURCE	/* for strndup */
#include <stdio.h>
#include <stdlib.h>
#include <stdarg.h>
#include <string.h>
#include <libintl.h>
#define _(s) gettext(s)
#include <netinet/in.h>
#include <sys/socket.h>
#include <arpa/inet.h>
#include <linux/capability.h>

#include "parser.h"
#include "parser_yacc.h"

/* #define DEBUG */
#ifdef DEBUG
#define PDEBUG(fmt, args...) printf("Lexer: " fmt, ## args)
#else
#define PDEBUG(fmt, args...)	/* Do nothing */
#endif
#define NPDEBUG(fmt, args...)	/* Do nothing */

struct keyword_table {
	char *keyword;
	int token;
};

static struct keyword_table keyword_table[] = {
	/* flags */
	{"flags",		TOK_FLAGS},
	/* network */
	{"network",		TOK_NETWORK},
	/* misc keywords */
	{"capability",		TOK_CAPABILITY},
	{"if",			TOK_IF},
	{"else",		TOK_ELSE},
	{"not",			TOK_NOT},
	{"defined",		TOK_DEFINED},
	{"change_profile",	TOK_CHANGE_PROFILE},
	{"unsafe",		TOK_UNSAFE},
	{"link",		TOK_LINK},
	{"owner",		TOK_OWNER},
	{"user",		TOK_OWNER},
	{"other",		TOK_OTHER},
	{"subset",		TOK_SUBSET},
	{"audit",		TOK_AUDIT},
	{"deny",		TOK_DENY},
	{"profile",		TOK_PROFILE},
	{"set",			TOK_SET},
	{"rlimit",		TOK_RLIMIT},
	{"alias",		TOK_ALIAS},
	{"ptrace",		TOK_PTRACE},
	/* terminate */
	{NULL, 0}
};

static struct keyword_table rlimit_table[] = {
	{"cpu",			RLIMIT_CPU},
	{"fsize",		RLIMIT_FSIZE},
	{"data",		RLIMIT_DATA},
	{"stack",		RLIMIT_STACK},
	{"core",		RLIMIT_CORE},
	{"rss",			RLIMIT_RSS},
	{"nofile",		RLIMIT_NOFILE},
	{"ofile",		RLIMIT_OFILE},
	{"as",			RLIMIT_AS},
	{"nproc",		RLIMIT_NPROC},
	{"memlock",		RLIMIT_MEMLOCK},
	{"locks",		RLIMIT_LOCKS},
	{"sigpending",		RLIMIT_SIGPENDING},
	{"msgqueue",		RLIMIT_MSGQUEUE},
#ifdef RLIMIT_NICE
	{"nice",		RLIMIT_NICE},
#endif
#ifdef RLIMIT_RTPRIO
	{"rtprio",		RLIMIT_RTPRIO},
#endif
	/* terminate */
	{NULL, 0}
};

/* for alpha matches, check for keywords */
static int get_table_token(const char *name, struct keyword_table *table,
			   const char *keyword)
{
	int i;

	for (i = 0; table[i].keyword; i++) {
		PDEBUG("Checking %s %s\n", name, table[i].keyword);
		if (strcmp(keyword, table[i].keyword) == 0) {
			PDEBUG("Found %s %s\n", name, table[i].keyword);
			return table[i].token;
		}
	}

	PDEBUG("Unable to find %s %s\n", name, keyword);
	return -1;
}

static struct keyword_table capability_table[] = {
	/* capabilities */
	#include "cap_names.h"
	/* terminate */
	{NULL, 0}
};

/* for alpha matches, check for keywords */
int get_keyword_token(const char *keyword)
{
	return get_table_token("keyword", keyword_table, keyword);
}

int name_to_capability(const char *keyword)
{
	return get_table_token("capability", capability_table, keyword);
}

int get_rlimit(const char *name)
{
	return get_table_token("rlimit", rlimit_table, name);
}

static struct keyword_table address_family[] = {
/*	{"unix",	AF_UNIX},
	{"local",	AF_LOCAL},	*/
	{"inet",	AF_INET},
/*	{"ax25",	AF_AX25},
	{"ipx",		AF_IPX},
	{"appletalk",	AF_APPLETALK},
	{"netrom",	AF_NETROM},
	{"bridge",	AF_BRIDGE},
	{"atmpvc",	AF_ATMPVC},
	{"x25",		AF_X25}, */
	{"inet6",	AF_INET6},
/*	{"rose",	AF_ROSE},
	{"decnet",	AF_DECnet},
	{"netbeui",	AF_NETBEUI},
	{"security",	AF_SECURITY},
	{"key",		AF_KEY},
	{"netlink",	AF_NETLINK},
	{"route",	AF_ROUTE},
	{"packet",	AF_PACKET},
	{"ash",		AF_ASH},
	{"econet",	AF_ECONET},
	{"atmsvc",	AF_ATMSVC},
	{"sna",		AF_SNA},
	{"irda",	AF_IRDA},
	{"pppox",	AF_PPPOX},
	{"wanpipe",	AF_WANPIPE},
	{"llc",		AF_LLC},
	{"tipc",	AF_TIPC},
	{"bluetooth",	AF_BLUETOOTH},
	{"iucv",	AF_IUCV},
	{"rxrpc",	AF_RXRPC}, */
	/* terminate */
	{NULL, 0}
};

struct network_tuple {
	char *family_name;
	unsigned int family;
	char *type_name;
	unsigned int type;
	char *protocol_name;
	unsigned int protocol;
};

/* FIXME: currently just treating as a bit mask this will have to change
 * set up a table of mappings, there can be several mappings for a
 * given match.
 * currently the mapping does not set the protocol for stream/dgram to
 * anything other than 0.
 *   network inet tcp -> network inet stream 0 instead of
 *   network inet raw tcp.
 * some entries are just provided for completeness at this time
 */
/* values stolen from /etc/protocols - needs to change */
#define RAW_TCP 6
#define RAW_UDP 17
#define RAW_ICMP 1
#define RAW_ICMPv6 58

/* used by af_name.h to auto generate table entries for "name", AF_NAME
 * pair */
#define AA_GEN_NET_ENT(name, AF) {name, AF, "stream", SOCK_STREAM, "", 0xffffff}, {name, AF, "dgram", SOCK_DGRAM, "", 0xffffff}, {name, AF, "seqpacket", SOCK_SEQPACKET, "", 0xffffff}, {name, AF, "rdm", SOCK_RDM, "", 0xffffff}, {name, AF, "raw", SOCK_RAW, "", 0xffffff}, {name, AF, "packet", SOCK_PACKET, "", 0xffffff},
/*FIXME: missing {name, AF, "dccp", SOCK_DCCP, "", 0xfffffff}, */

static struct network_tuple network_mappings[] = {
	/* basic types */
	#include "af_names.h"
/* FIXME: af_names.h is missing AF_LLC, AF_TIPC */
	/* mapped types */
	{"inet",	AF_INET,	"raw",		SOCK_RAW,
	 "tcp",	        1 << RAW_TCP},
	{"inet",	AF_INET,	"raw",		SOCK_RAW,
	 "udp",		1 << RAW_UDP},
	{"inet",	AF_INET,	"raw",		SOCK_RAW,
	 "icmp",	1 << RAW_ICMP},
	{"inet",	AF_INET,	"tcp",		SOCK_STREAM,
	 "",		0xffffffff},	/* should we give raw tcp too? */
	{"inet",	AF_INET,	"udp",		SOCK_DGRAM,
	 "",		0xffffffff},	/* should these be open masks? */
	{"inet",	AF_INET,	"icmp",		SOCK_RAW,
	 "",		1 << RAW_ICMP},
	{"inet6",	AF_INET6,	"tcp",		SOCK_STREAM,
	 "",		0xffffffff},
	{"inet6",	AF_INET6,	"udp",		SOCK_DGRAM,
	 "",		0xffffffff},
/* what do we do with icmp on inet6?
	{"inet6",	AF_INET,	"icmp",		SOCK_RAW,	0},
	{"inet6",	AF_INET,	"icmpv6",	SOCK_RAW,	0},
*/
	/* terminate */
	{NULL, 0, NULL, 0, NULL, 0}
};

struct aa_network_entry *new_network_ent(unsigned int family,
					 unsigned int type,
					 unsigned int protocol)
{
	struct aa_network_entry *new_entry;
	new_entry = calloc(1, sizeof(struct aa_network_entry));
	if (new_entry) {
		new_entry->family = family;
		new_entry->type = type;
		new_entry->protocol = protocol;
		new_entry->next = NULL;
	}
	return new_entry;
}

struct aa_network_entry *network_entry(const char *family, const char *type,
				       const char *protocol)
{
	int i;
	struct aa_network_entry *new_entry, *entry = NULL;

	for (i = 0; network_mappings[i].family_name; i++) {
		if (family) {
			PDEBUG("Checking family %s\n", network_mappings[i].family_name);
			if (strcmp(family, network_mappings[i].family_name) != 0)
				continue;
			PDEBUG("Found family %s\n", family);
		}
		if (type) {
			PDEBUG("Checking type %s\n", network_mappings[i].type_name);
			if (strcmp(type, network_mappings[i].type_name) != 0)
				continue;
			PDEBUG("Found type %s\n", type);
		}
		if (protocol) {
			PDEBUG("Checking protocol type %s\n", network_mappings[i].protocol_name);
			if (strcmp(type, network_mappings[i].protocol_name) != 0)
				continue;
			/* fixme should we allow specifying protocol by #
			 * without needing the protocol mapping? */
		}
		/* if here we have a match */
		new_entry = new_network_ent(network_mappings[i].family,
					    network_mappings[i].type,
					    network_mappings[i].protocol);
		if (!new_entry)
			yyerror(_("Memory allocation error."));
		new_entry->next = entry;
		entry = new_entry;
	}

	return entry;
};

char *processunquoted(char *string, int len)
{
	char *tmp, *s;
	int l;

	tmp = (char *)malloc(len + 1);
	if (!tmp)
		return NULL;

	s = tmp;
	for (l = 0; l < len; l++) {
		if (string[l] == '\\' && l < len - 3) {
			if (strchr("0123", string[l + 1]) &&
			    strchr("0123456789", string[l + 2]) &&
			    strchr("0123456789", string[l + 3])) {
				/* three digit octal */
				int res = (string[l + 1] - '0') * 64 +
				    	  (string[l + 2] - '0') * 8 +
					  (string[l + 3] - '0');
				*s = res;
				l += 3;
			} else {
				*s = string[l];
			}
			s++;
		} else {
			*s = string[l];
			s++;
		}
	}

	*s = 0;

	return tmp;
}

/* rewrite a quoted string substituting escaped characters for the
 * real thing.  Strip the quotes around the string */

char *processquoted(char *string, int len)
{
	char *tmp, *s;
	int l;
	/* the result string will be shorter or equal in length */
	tmp = (char *)malloc(len + 1);
	if (!tmp)
		return NULL;

	s = tmp;
	for (l = 1; l < len - 1; l++) {
		if (string[l] == '\\' && l < len - 2) {
			switch (string[l + 1]) {
			case 't':
				*s = '\t';
				l++;
				break;
			case 'n':
				*s = '\n';
				l++;
				break;
			case 'r':
				*s = '\r';
				l++;
				break;
			case '"':
				*s = '"';
				l++;
				break;
			case '\\':
				*s = '\\';
				l++;
				break;
			case '0' - '3':
				if ((l < len - 4) &&
				    strchr("0123456789", string[l + 2]) &&
				    strchr("0123456789", string[l + 3])) {
					/* three digit octal */
					int res = (string[l + 1] - '0') * 64 +
					    (string[l + 2] - '0') * 8 +
					    (string[l + 3] - '0');
					*s = res;
					l += 3;
					break;
				}
				/* fall through */
			default:
				/* any unsupported escape sequence results in all
				   chars being copied. */
				*s = string[l];
			}
			s++;
		} else {
			*s = string[l];
			s++;
		}
	}

	*s = 0;

	return tmp;
}

/* strip off surrounding delimiters around variables */
char *process_var(const char *var)
{
	const char *orig = var;
	int len = strlen(var);

	if (*orig == '@' || *orig == '$') {
		orig++;
		len--;
	} else {
		PERROR("ASSERT: Found var '%s' without variable prefix\n",
		       var);
		return NULL;
	}

	if (*orig == '{') {
		orig++;
		len--;
		if (orig[len - 1] != '}') {
			PERROR("ASSERT: No matching '}' in variable '%s'\n",
		       		var);
			return NULL;
		} else
			len--;
	}

	return strndup(orig, len);
}

/* returns -1 if value != true or false, otherwise 0 == false, 1 == true */
int str_to_boolean(const char *value)
{
	int retval = -1;

	if (strcasecmp("TRUE", value) == 0)
		retval = 1;
	if (strcasecmp("FALSE", value) == 0)
		retval = 0;
	return retval;
}

static int warned_uppercase = 0;

static void warn_uppercase(void)
{
	if (!warned_uppercase) {
		pwarn(_("Uppercase qualifiers \"RWLIMX\" are deprecated, please convert to lowercase\n"
			"See the apparmor.d(5) manpage for details.\n"));
		warned_uppercase = 1;
	}
}

static int parse_sub_mode(const char *str_mode, const char *mode_desc)
{

#define IS_DIFF_QUAL(mode, q) (((mode) & AA_MAY_EXEC) && (((mode) & AA_EXEC_TYPE) != ((q) & AA_EXEC_TYPE)))

	int mode = 0;
	const char *p;

	PDEBUG("Parsing mode: %s\n", str_mode);

	if (!str_mode)
		return 0;

	p = str_mode;
	while (*p) {
		char this = *p;
		char next = *(p + 1);
		char lower;
		int tmode = 0;

reeval:
		switch (this) {
		case COD_READ_CHAR:
			PDEBUG("Parsing mode: found %s READ\n", mode_desc);
			mode |= AA_MAY_READ;
			break;

		case COD_WRITE_CHAR:
			PDEBUG("Parsing mode: found %s WRITE\n", mode_desc);
			if ((mode & AA_MAY_APPEND) && !(mode & AA_MAY_WRITE))
				yyerror(_("Conflict 'a' and 'w' perms are mutually exclusive."));
			mode |= AA_MAY_WRITE | AA_MAY_APPEND;
			break;

		case COD_APPEND_CHAR:
			PDEBUG("Parsing mode: found %s APPEND\n", mode_desc);
			if (mode & AA_MAY_WRITE)
				yyerror(_("Conflict 'a' and 'w' perms are mutually exclusive."));
			mode |= AA_MAY_APPEND;
			break;

		case COD_LINK_CHAR:
			PDEBUG("Parsing mode: found %s LINK\n", mode_desc);
			mode |= AA_MAY_LINK;
			break;

		case COD_LOCK_CHAR:
			PDEBUG("Parsing mode: found %s LOCK\n", mode_desc);
			mode |= AA_MAY_LOCK;
			break;

		case COD_INHERIT_CHAR:
			PDEBUG("Parsing mode: found INHERIT\n");
			if (mode & AA_EXEC_MODIFIERS) {
				yyerror(_("Exec qualifier 'i' invalid, conflicting qualifier already specified"));
			} else {
				if (next != tolower(next))
					warn_uppercase();
				mode |= (AA_EXEC_INHERIT | AA_MAY_EXEC);
				p++;	/* skip 'x' */
			}
			break;

		case COD_UNSAFE_UNCONFINED_CHAR:
			tmode = AA_EXEC_UNSAFE;
			pwarn(_("Unconfined exec qualifier (%c%c) allows some dangerous environment variables "
				"to be passed to the unconfined process; 'man 5 apparmor.d' for details.\n"),
			      COD_UNSAFE_UNCONFINED_CHAR, COD_EXEC_CHAR);
			/* fall through */
		case COD_UNCONFINED_CHAR:
			tmode |= AA_EXEC_UNCONFINED | AA_MAY_EXEC;
			PDEBUG("Parsing mode: found UNCONFINED\n");
			if (IS_DIFF_QUAL(mode, tmode)) {
				yyerror(_("Exec qualifier '%c' invalid, conflicting qualifier already specified"),
					this);
			} else {
				if (next != tolower(next))
					warn_uppercase();
				mode |=  tmode;
				p++;	/* skip 'x' */
			}
			tmode = 0;
			break;

		case COD_UNSAFE_PROFILE_CHAR:
		case COD_UNSAFE_LOCAL_CHAR:
			tmode = AA_EXEC_UNSAFE;
			/* fall through */
		case COD_PROFILE_CHAR:
		case COD_LOCAL_CHAR:
			if (tolower(this) == COD_UNSAFE_PROFILE_CHAR)
				tmode |= AA_EXEC_PROFILE | AA_MAY_EXEC;
			else
			{
				tmode |= AA_EXEC_LOCAL | AA_MAY_EXEC;
			}
			PDEBUG("Parsing mode: found PROFILE\n");
			if (tolower(next) == COD_INHERIT_CHAR) {
				tmode |= AA_EXEC_INHERIT;
				if (IS_DIFF_QUAL(mode, tmode)) {
					yyerror(_("Exec qualifier '%c%c' invalid, conflicting qualifier already specified"), this, next);
				} else {
					mode |= tmode;
					p += 2;		/* skip x */
				}
			} else if (IS_DIFF_QUAL(mode, tmode)) {
				yyerror(_("Exec qualifier '%c' invalid, conflicting qualifier already specified"), this);

			} else {
				if (next != tolower(next))
					warn_uppercase();
				mode |= tmode;
				p++;	/* skip 'x' */
			}
			tmode = 0;
			break;

		case COD_MMAP_CHAR:
			PDEBUG("Parsing mode: found %s MMAP\n", mode_desc);
			mode |= AA_EXEC_MMAP;
			break;

		case COD_EXEC_CHAR:
			/* this is valid for deny rules, and named transitions
			 * but invalid for regular x transitions
			 * sort it out later.
			 */
			mode |= AA_MAY_EXEC;
			break;

 		/* error cases */

		default:
			lower = tolower(this);
			switch (lower) {
			case COD_READ_CHAR:
			case COD_WRITE_CHAR:
			case COD_APPEND_CHAR:
			case COD_LINK_CHAR:
			case COD_INHERIT_CHAR:
			case COD_MMAP_CHAR:
			case COD_EXEC_CHAR:
				PDEBUG("Parsing mode: found invalid upper case char %c\n", this);
				warn_uppercase();
				this = lower;
				goto reeval;
				break;
			default:
				yyerror(_("Internal: unexpected mode character '%c' in input"),
					this);
				break;
			}
			break;
		}

		p++;
	}

	PDEBUG("Parsed mode: %s 0x%x\n", str_mode, mode);

	return mode;
}

int parse_mode(const char *str_mode)
{
	int tmp, mode = 0;
	tmp = parse_sub_mode(str_mode, "");
	mode = SHIFT_MODE(tmp, AA_USER_SHIFT);
	mode |= SHIFT_MODE(tmp, AA_OTHER_SHIFT);
	if (mode & ~AA_VALID_PERMS)
		yyerror(_("Internal error generated invalid perm 0x%llx\n"), mode);
	return mode;
}

struct cod_entry *new_entry(char *namespace, char *id, int mode, char *link_id)
{
	struct cod_entry *entry = NULL;

	entry = (struct cod_entry *)calloc(1, sizeof(struct cod_entry));
	if (!entry)
		return NULL;

	entry->namespace = namespace;
	entry->name = id;
	entry->link_name = link_id;
	entry->mode = mode;
	entry->audit = 0;
	entry->deny = FALSE;

	entry->pattern_type = ePatternInvalid;
	entry->pat.regex = NULL;
	entry->pat.compiled = NULL;

	entry->next = NULL;

	PDEBUG(" Insertion of: (%s)\n", entry->name);
	return entry;
}

struct cod_entry *copy_cod_entry(struct cod_entry *orig)
{
	struct cod_entry *entry = NULL;

	entry = (struct cod_entry *)calloc(1, sizeof(struct cod_entry));
	if (!entry)
		return NULL;

	entry->namespace = orig->namespace ? strdup(orig->namespace) : NULL;
	entry->name = strdup(orig->name);
	entry->link_name = orig->link_name ? strdup(orig->link_name) : NULL;
	entry->mode = orig->mode;
	entry->deny = orig->deny;

	/* XXX - need to create copies of the patterns, too */
	entry->pattern_type = orig->pattern_type;
	entry->pat.regex = NULL;
	entry->pat.compiled = NULL;

	entry->next = orig->next;

	return entry;
}

void free_cod_entries(struct cod_entry *list)
{
	if (!list)
		return;
	if (list->next)
		free_cod_entries(list->next);
	if (list->namespace)
		free(list->namespace);
	if (list->name)
		free(list->name);
	if (list->link_name)
		free(list->link_name);
	if (list->pat.regex)
		free(list->pat.regex);
	if (list->pat.compiled)
		free(list->pat.compiled);
	free(list);
}

static void debug_base_perm_mask(int mask)
{
	if (HAS_MAY_READ(mask))
		printf("%c", COD_READ_CHAR);
	if (HAS_MAY_WRITE(mask))
		printf("%c", COD_WRITE_CHAR);
	if (HAS_MAY_APPEND(mask))
		printf("%c", COD_APPEND_CHAR);
	if (HAS_MAY_LINK(mask))
		printf("%c", COD_LINK_CHAR);
	if (HAS_MAY_LOCK(mask))
		printf("%c", COD_LOCK_CHAR);
	if (HAS_EXEC_MMAP(mask))
		printf("%c", COD_MMAP_CHAR);
	if (HAS_MAY_EXEC(mask))
		printf("%c", COD_EXEC_CHAR);
}

void debug_cod_entries(struct cod_entry *list)
{
	struct cod_entry *item = NULL;

	printf("--- Entries ---\n");

	list_for_each(list, item) {
		if (!item)
			printf("Item is NULL!\n");

		printf("Mode:\t");
		if (HAS_CHANGE_PROFILE(item->mode))
			printf(" change_profile");
		if (HAS_EXEC_UNSAFE(item->mode))
			printf(" unsafe");
		debug_base_perm_mask(SHIFT_TO_BASE(item->mode, AA_USER_SHIFT));
		printf(":");
		debug_base_perm_mask(SHIFT_TO_BASE(item->mode, AA_OTHER_SHIFT));
		if (item->name)
			printf("\tName:\t(%s)\n", item->name);
		else
			printf("\tName:\tNULL\n");

		if (item->namespace)
			printf("\tNamespace:\t(%s)\n", item->namespace);

		if (AA_LINK_BITS & item->mode)
			printf("\tlink:\t(%s)\n", item->link_name ? item->link_name : "/**");

	}
}

void debug_flags(struct codomain *cod)
{
	printf("Profile Mode:\t");

	if (cod->flags.complain)
		printf("Complain");
	else
		printf("Enforce");

	if (cod->flags.audit)
		printf(", Audit");

	if (cod->flags.hat)
		printf(", Hat");

	printf("\n");
}

static const char *capnames[] = {
	"chown",
	"dac_override",
	"dac_read_search",
	"fowner",
	"fsetid",
	"kill",
	"setgid",
	"setuid",
	"setpcap",
	"linux_immutable",
	"net_bind_service",
	"net_broadcast",
	"net_admin",
	"net_raw",
	"ipc_lock",
	"ipc_owner",
	"sys_module",
	"sys_rawio",
	"sys_chroot",
	"sys_ptrace",
	"sys_pacct",
	"sys_admin",
	"sys_boot",
	"sys_nice",
	"sys_resource",
	"sys_time",
	"sys_tty_config",
	"mknod",
	"lease",
	"audit_write",
	"audit_control"
};

const char *capability_to_name(unsigned int cap)
{
	const char *capname;

	capname = (cap < (sizeof(capnames) / sizeof(char *))
		   ? capnames[cap] : "invalid-capability");

	return capname;
}

void debug_cod_list(struct codomain *cod)
{
	unsigned int i;
	if (cod->namespace)
		printf("Namespace:\t\t%s\n", cod->namespace);

	if (cod->name)
		printf("Name:\t\t%s\n", cod->name);
	else
		printf("Name:\t\tNULL\n");

	if (cod->local)
		printf("Local To:\t%s\n", cod->parent->name);

	debug_flags(cod);
	
	printf("Capabilities:\t");
	for (i = 0; i < (sizeof(capnames)/sizeof(char *)); i++) {
		if (((1 << i) & cod->capabilities) != 0) {
			printf ("%s ", capability_to_name(i));
		}
	}
	printf("\n");

	if (cod->entries)
		debug_cod_entries(cod->entries);

	printf("\n");
	dump_policy_hats(cod);
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

int test_str_to_boolean(void)
{
	int rc = 0;
	int retval;

	retval = str_to_boolean("TRUE");
	MY_TEST(retval == 1, "str2bool for TRUE");

	retval = str_to_boolean("TrUe");
	MY_TEST(retval == 1, "str2bool for TrUe");

	retval = str_to_boolean("false");
	MY_TEST(retval == 0, "str2bool for false");

	retval = str_to_boolean("flase");
	MY_TEST(retval == -1, "str2bool for flase");

	return rc;
}
int main(void)
{
	int rc = 0;
	int retval;

	retval = test_str_to_boolean();
	if (retval != 0)
		rc = retval;

	return rc;
}
#endif /* UNIT_TEST */
