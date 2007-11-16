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
	/* capabilities */
	{"capability",		TOK_CAPABILITY},
	{"chown",		TOK_CAP_CHOWN},
	{"dac_override",	TOK_CAP_DAC_OVERRIDE},
	{"dac_read_search",	TOK_CAP_DAC_READ_SEARCH},
	{"fowner",		TOK_CAP_FOWNER},
	{"fsetid",		TOK_CAP_FSETID},
	{"kill",		TOK_CAP_KILL},
	{"setgid",		TOK_CAP_SETGID},
	{"setuid",		TOK_CAP_SETUID},
	{"setpcap",		TOK_CAP_SETPCAP},
	{"linux_immutable",	TOK_CAP_LINUX_IMMUTABLE},
	{"net_bind_service",	TOK_CAP_NET_BIND_SERVICE},
	{"net_broadcast",	TOK_CAP_NET_BROADCAST},
	{"net_admin",		TOK_CAP_NET_ADMIN},
	{"net_raw",		TOK_CAP_NET_RAW},
	{"ipc_lock",		TOK_CAP_IPC_LOCK},
	{"ipc_owner",		TOK_CAP_IPC_OWNER},
	{"sys_module",		TOK_CAP_SYS_MODULE},
	{"sys_rawio",		TOK_CAP_SYS_RAWIO},
	{"sys_chroot",		TOK_CAP_SYS_CHROOT},
	{"sys_ptrace",		TOK_CAP_SYS_PTRACE},
	{"sys_pacct",		TOK_CAP_SYS_PACCT},
	{"sys_admin",		TOK_CAP_SYS_ADMIN},
	{"sys_boot",		TOK_CAP_SYS_BOOT},
	{"sys_nice",		TOK_CAP_SYS_NICE},
	{"sys_resource",	TOK_CAP_SYS_RESOURCE},
	{"sys_time",		TOK_CAP_SYS_TIME},
	{"sys_tty_config",	TOK_CAP_SYS_TTY_CONFIG},
	{"mknod",		TOK_CAP_MKNOD},
	{"lease",		TOK_CAP_LEASE},
	{"audit_write",		TOK_CAP_AUDIT_WRITE},
	{"audit_control",	TOK_CAP_AUDIT_CONTROL},
	/* flags */
	{"flags",		TOK_FLAGS},
	{"debug",		TOK_FLAG_DEBUG},
	{"complain",		TOK_FLAG_COMPLAIN},
	{"audit",		TOK_FLAG_AUDIT},
	/* network */
	{"via",			TOK_VIA},
	{"tcp_connect",		TOK_TCP_CONN},
	{"tcp_accept",		TOK_TCP_ACPT},
	{"tcp_connected",	TOK_TCP_CONN_ESTB},
	{"tcp_accepted",	TOK_TCP_ACPT_ESTB},
	{"udp_send",		TOK_UDP_SEND},
	{"udp_receive",		TOK_UDP_RECV},
	{"to",			TOK_TO},
	{"from",		TOK_FROM},
	{"network",		TOK_NETWORK},
	/* misc keywords */
	{"if",			TOK_IF},
	{"else",		TOK_ELSE},
	{"not",			TOK_NOT},
	{"defined",		TOK_DEFINED},
	{"change_profile",	TOK_CHANGE_PROFILE},
	{"unsafe",		TOK_UNSAFE},
	/* terminate */
	{NULL, 0}
};

/* for alpha matches, check for keywords */
int get_keyword_token(const char *keyword)
{
	int i;

	for (i = 0; keyword_table[i].keyword; i++) {
		PDEBUG("Checking keyword %s\n", keyword_table[i].keyword);
		if (strcmp(keyword, keyword_table[i].keyword) == 0) {
			PDEBUG("Found keyword %s\n", keyword_table[i].keyword);
			return keyword_table[i].token;
		}
	}

	PDEBUG("Unable to find keyword %s\n", keyword);
	return -1;
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
int parse_mode(const char *str_mode)
{
	/* The 'check' int is a bit of a kludge, but we need some context
	   when we're doing permission checking */

#define IS_DIFF_QUAL(mode, q) (((mode) & AA_MAY_EXEC) && (((mode) & (AA_EXEC_MODIFIERS | AA_EXEC_UNSAFE)) != (q)))

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
			PDEBUG("Parsing mode: found READ\n");
			mode |= AA_MAY_READ;
			break;

		case COD_WRITE_CHAR:
			PDEBUG("Parsing mode: found WRITE\n");
			if ((mode & AA_MAY_APPEND) && !(mode & AA_MAY_WRITE))
				yyerror(_("Conflict 'a' and 'w' perms are mutually exclusive."));
			mode |= AA_MAY_WRITE | AA_MAY_APPEND;
			break;

		case COD_APPEND_CHAR:
			PDEBUG("Parsing mode: found APPEND\n");
			if (mode & AA_MAY_WRITE)
				yyerror(_("Conflict 'a' and 'w' perms are mutually exclusive."));
			mode |= AA_MAY_APPEND;
			break;

		case COD_LINK_CHAR:
			PDEBUG("Parsing mode: found LINK\n");
			mode |= AA_MAY_LINK;
			break;

		case COD_LOCK_CHAR:
			PDEBUG("Parsing mode: found LOCK\n");
			mode |= AA_MAY_LOCK;
			break;

		case COD_INHERIT_CHAR:
			PDEBUG("Parsing mode: found INHERIT\n");
			if (IS_DIFF_QUAL(mode, AA_EXEC_INHERIT)) {
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
			PDEBUG("Parsing mode: found UNCONFINED\n");
			if (IS_DIFF_QUAL(mode, tmode | AA_EXEC_UNCONFINED)) {
				yyerror(_("Exec qualifier '%c' invalid, conflicting qualifier already specified"),
					this);
			} else {
				if (next != tolower(next))
					warn_uppercase();
				mode |= tmode | AA_EXEC_UNCONFINED |
				    AA_MAY_EXEC;
				p++;	/* skip 'x' */
			}
			tmode = 0;
			break;

		case COD_UNSAFE_PROFILE_CHAR:
			tmode = AA_EXEC_UNSAFE;
			/* fall through */
		case COD_PROFILE_CHAR:
			PDEBUG("Parsing mode: found PROFILE\n");
			if (tolower(next) == COD_INHERIT_CHAR) {
				if (IS_DIFF_QUAL(mode, tmode | AA_EXEC_PROFILE_OR_INHERIT)) {
					yyerror(_("Exec qualifier '%c%c' invalid, conflicting qualifier already specified"), this, next);
				} else {
					mode |= tmode | AA_MAY_EXEC |
					    AA_EXEC_PROFILE_OR_INHERIT;
					p += 2;		/* skip x */
				}
			} else if (IS_DIFF_QUAL(mode, tmode | AA_EXEC_PROFILE)) {
				yyerror(_("Exec qualifier '%c' invalid, conflicting qualifier already specified"),
					this);
			} else {
				if (next != tolower(next))
					warn_uppercase();
				mode |= tmode | AA_EXEC_PROFILE | AA_MAY_EXEC;
				p++;	/* skip 'x' */
			}
			tmode = 0;
			break;

		case COD_MMAP_CHAR:
			PDEBUG("Parsing mode: found MMAP\n");
			mode |= AA_EXEC_MMAP;
			break;

		case COD_EXEC_CHAR:
			PDEBUG("Parsing mode: found EXEC\n");
			yyerror(_("Invalid mode, 'x' must be preceded by exec qualifier 'i', 'p', or 'u'"));
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

struct cod_net_entry *new_network_entry(int action,
					struct ipv4_endpoints *addrs,
					char *interface)
{
	struct cod_net_entry *entry = NULL;

	entry = (struct cod_net_entry *)
	    			malloc(sizeof(struct cod_net_entry));
	entry->saddr = (struct in_addr *)malloc(sizeof(struct in_addr));
	entry->smask = (struct in_addr *)malloc(sizeof(struct in_addr));
	entry->daddr = (struct in_addr *)malloc(sizeof(struct in_addr));
	entry->dmask = (struct in_addr *)malloc(sizeof(struct in_addr));

	if (!addrs || !entry || !entry->saddr || !entry->smask ||
	    !entry->daddr || !entry->dmask) {
		yyerror(_("Memory allocation error."));
		return NULL;
	}

	entry->next = NULL;
	entry->mode = action;
	entry->iface = interface ? interface : NULL;

	if (addrs->src) {
		PDEBUG("Assigning source\n");
		entry->saddr->s_addr = addrs->src->addr.s_addr & addrs->src->mask;
		entry->smask->s_addr = addrs->src->mask;
		entry->src_port[0] = addrs->src->port[0];
		entry->src_port[1] = addrs->src->port[1];
	} else {
		entry->saddr->s_addr = 0;
		entry->smask->s_addr = 0;
		entry->src_port[0] = MIN_PORT;
		entry->src_port[1] = MAX_PORT;
	}

	if (addrs->dest) {
		PDEBUG("Assigning source\n");
		entry->daddr->s_addr = addrs->dest->addr.s_addr & addrs->dest->mask;
		entry->dmask->s_addr = addrs->dest->mask;
		entry->dst_port[0] = addrs->dest->port[0];
		entry->dst_port[1] = addrs->dest->port[1];
	} else {
		entry->daddr->s_addr = 0;
		entry->dmask->s_addr = 0;
		entry->dst_port[0] = MIN_PORT;
		entry->dst_port[1] = MAX_PORT;
	}

	return entry;
}

struct cod_entry *new_entry(char *namespace, char *id, int mode)
{
	struct cod_entry *entry = NULL;

	entry = (struct cod_entry *)malloc(sizeof(struct cod_entry));
	if (!entry)
		return NULL;

	entry->namespace = namespace;
	entry->name = id;
	entry->mode = mode;
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

	entry = (struct cod_entry *)malloc(sizeof(struct cod_entry));
	if (!entry)
		return NULL;

	entry->namespace = orig->namespace ? strdup(orig->namespace) : NULL;
	entry->name = strdup(orig->name);
	entry->mode = orig->mode;
	entry->deny = orig->deny;

	/* XXX - need to create copies of the patterns, too */
	entry->pattern_type = orig->pattern_type;
	entry->pat.regex = NULL;
	entry->pat.compiled = NULL;

	entry->next = orig->next;

	return entry;
}

void free_ipv4_endpoints(struct ipv4_endpoints *addrs)
{
	if (!addrs)
		return;
	if (addrs->src)
		free(addrs->src);
	if (addrs->dest)
		free(addrs->dest);
	free(addrs);
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
	if (list->pat.regex)
		free(list->pat.regex);
	if (list->pat.compiled)
		free(list->pat.compiled);
	free(list);
}

void free_net_entries(struct cod_net_entry *list)
{
	if (!list)
		return;
	if (list->next)
		free_net_entries(list->next);
	if (list->saddr)
		free(list->saddr);
	if (list->smask)
		free(list->smask);
	if (list->daddr)
		free(list->daddr);
	if (list->dmask)
		free(list->dmask);
	if (list->iface)
		free(list->iface);
	free(list);
}

void debug_cod_entries(struct cod_entry *list)
{
	struct cod_entry *item = NULL;

	printf("--- Entries ---\n");

	list_for_each(list, item) {
		if (!item)
			printf("Item is NULL!\n");

		printf("Mode:\t");
		if (HAS_MAY_READ(item->mode))
			printf("%c", COD_READ_CHAR);
		if (HAS_MAY_WRITE(item->mode))
			printf("%c", COD_WRITE_CHAR);
		if (HAS_MAY_APPEND(item->mode))
			printf("%c", COD_APPEND_CHAR);
		if (HAS_MAY_LINK(item->mode))
			printf("%c", COD_LINK_CHAR);
		if (HAS_MAY_LOCK(item->mode))
			printf("%c", COD_LOCK_CHAR);
		if (HAS_EXEC_INHERIT(item->mode))
			printf("%c", COD_INHERIT_CHAR);
		if (HAS_EXEC_UNCONFINED(item->mode)) {
			if (HAS_EXEC_UNSAFE(item->mode))
				printf("%c", COD_UNSAFE_UNCONFINED_CHAR);
			else
				printf("%c", COD_UNCONFINED_CHAR);
		}
		if (HAS_EXEC_PROFILE(item->mode)) {
			if (HAS_EXEC_UNSAFE(item->mode))
				printf("%c", COD_UNSAFE_PROFILE_CHAR);
			else
				printf("%c", COD_PROFILE_CHAR);
		}
		if (HAS_EXEC_MMAP(item->mode))
			printf("%c", COD_MMAP_CHAR);
		if (HAS_MAY_EXEC(item->mode))
			printf("%c", COD_EXEC_CHAR);
		if (HAS_CHANGE_PROFILE(item->mode))
			printf(" change_profile");

		if (item->name)
			printf("\tName:\t(%s)\n", item->name);

		else
			printf("\tName:\tNULL\n");

		if (item->namespace)
			printf("\tNamespace:\t(%s)\n", item->namespace);

	}
}

void debug_cod_net_entries(struct cod_net_entry *list)
{
	struct cod_net_entry *item = NULL;
	struct in_addr src_addr, dst_addr;
	unsigned long smask;
	unsigned long dmask;

	printf("--- NetwerkEntries --- \n");

	list_for_each(list, item) {
		if (!item)
			printf("Item is NULL");

		src_addr.s_addr = item->saddr->s_addr;
		dst_addr.s_addr = item->daddr->s_addr;
		smask = ntohl(item->smask->s_addr);
		dmask = ntohl(item->dmask->s_addr);

		printf("Source IP: %s\n", inet_ntoa(src_addr));
		printf("Source Port: (%hu) - (%hu)\n", item->src_port[0],
		       item->src_port[1]);
		printf("Source netmask: %lx\n", smask);
		fflush(stdout);
		printf("Destination IP: %s\n", inet_ntoa(dst_addr));
		printf("Destination Port: %hu - %hu\n", item->dst_port[0],
		       item->dst_port[1]);
		printf("Destination netmask: %lx\n", dmask);
		fflush(stdout);
		printf("Mode:\t");
		if (item->mode & AA_TCP_ACCEPT)
			printf("TA");
		if (item->mode & AA_TCP_CONNECT)
			printf("TC");
		if (item->mode & AA_TCP_ACCEPTED)
			printf("Ta");
		if (item->mode & AA_TCP_CONNECTED)
			printf("Tc");
		if (item->mode & AA_UDP_SEND)
			printf("US");
		if (item->mode & AA_UDP_RECEIVE)
			printf("UR");
		if (item->iface != NULL)
			printf("\nInterface: %s\n", item->iface);

		printf("\n");
	}
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
		printf("Namespcae:\t\t%s\n", cod->namespace);

	if (cod->name)
		printf("Name:\t\t%s\n", cod->name);
	else
		printf("Name:\t\tNULL\n");

	if (cod->sub_name)
		printf("Subname:\t%s\n", cod->sub_name);
	else
		printf("Subname:\tNULL\n");

	if (cod->default_deny)
		printf("Type:\t\tDefault Deny\t\n");
	else
		printf("Type:\t\tDefault Allow\t\n");

	printf("Capabilities:\t");
	for (i = 0; i < (sizeof(capnames)/sizeof(char *)); i++) {
		if (((1 << i) & cod->capabilities) != 0) {
			printf ("%s ", capability_to_name(i));
		}
	}
	printf("\n");

	if (cod->entries)
		debug_cod_entries(cod->entries);

	if (cod->net_entries)
		debug_cod_net_entries(cod->net_entries);

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
