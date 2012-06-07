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

#include <assert.h>
#include <ctype.h>
#include <stdio.h>
#include <stdlib.h>
#include <stdarg.h>
#include <string.h>
#include <libintl.h>
#define _(s) gettext(s)
#include <netinet/in.h>
#include <linux/socket.h>
#include <linux/limits.h>
#include <arpa/inet.h>
#include <linux/capability.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <unistd.h>

#include "parser.h"
#include "parser_yacc.h"
#include "mount.h"

/* #define DEBUG */
#ifdef DEBUG
#undef PDEBUG
#define PDEBUG(fmt, args...) printf("Lexer: " fmt, ## args)
#else
#undef PDEBUG
#define PDEBUG(fmt, args...)	/* Do nothing */
#endif
#define NPDEBUG(fmt, args...)	/* Do nothing */

struct keyword_table {
	char *keyword;
	int token;
};

static struct keyword_table keyword_table[] = {
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
	{"safe",		TOK_SAFE},
	{"link",		TOK_LINK},
	{"owner",		TOK_OWNER},
	{"user",		TOK_OWNER},
	{"other",		TOK_OTHER},
	{"subset",		TOK_SUBSET},
	{"audit",		TOK_AUDIT},
	{"deny",		TOK_DENY},
	{"set",			TOK_SET},
	{"rlimit",		TOK_RLIMIT},
	{"alias",		TOK_ALIAS},
	{"rewrite",		TOK_ALIAS},
	{"ptrace",		TOK_PTRACE},
	{"file",		TOK_FILE},
	{"mount",		TOK_MOUNT},
	{"remount",		TOK_REMOUNT},
	{"umount",		TOK_UMOUNT},
	{"unmount",		TOK_UMOUNT},
	{"pivot_root",		TOK_PIVOTROOT},
	{"in",			TOK_IN},
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
static int get_table_token(const char *name __unused, struct keyword_table *table,
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
#ifndef CAP_SYSLOG
	{"syslog", 34},
#endif
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
#define AA_GEN_NET_ENT(name, AF) \
	{name, AF, "stream",    SOCK_STREAM,    "", 0xffffff}, \
	{name, AF, "dgram",     SOCK_DGRAM,     "", 0xffffff}, \
	{name, AF, "seqpacket", SOCK_SEQPACKET, "", 0xffffff}, \
	{name, AF, "rdm",       SOCK_RDM,       "", 0xffffff}, \
	{name, AF, "raw",       SOCK_RAW,       "", 0xffffff}, \
	{name, AF, "packet",    SOCK_PACKET,    "", 0xffffff},
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

/* The apparmor kernel patches up until 2.6.38 didn't handle networking
 * tables with sizes > AF_MAX correctly.  This could happen when the
 * parser was built against newer kernel headers and then used to load
 * policy on an older kernel.  This could happen during upgrades or
 * in multi-kernel boot systems.
 *
 * Try to detect the running kernel version and use that to determine
 * AF_MAX
 */
#define PROC_VERSION "/proc/sys/kernel/osrelease"
static size_t kernel_af_max(void) {
	char buffer[32];
	int major;
	int fd, res;

	if (!net_af_max_override) {
		return 0;
	}
	/* the override parameter is specifying the max value */
	if (net_af_max_override > 0)
		return net_af_max_override;

	fd = open(PROC_VERSION, O_RDONLY);
	if (!fd)
		/* fall back to default provided during build */
		return 0;
	res = read(fd, &buffer, sizeof(buffer));
	close(fd);
	if (!res)
		return 0;
	buffer[sizeof(buffer)-1] = '\0';
	res = sscanf(buffer, "2.6.%d", &major);
	if (res != 1)
		return 0;

	switch(major) {
	case 24:
	case 25:
	case 26:
		return 34;
	case 27:
		return 35;
	case 28:
	case 29:
	case 30:
		return 36;
	case 31:
	case 32:
	case 33:
	case 34:
	case 35:
		return 37;
	case 36:
	case 37:
		return 38;
	/* kernels .38 and later should handle this correctly so no
	 * static mapping needed
	 */
	default:
		return 0;
	}
}

/* Yuck. We grab AF_* values to define above from linux/socket.h because
 * they are more accurate than sys/socket.h for what the kernel actually
 * supports. However, we can't just include linux/socket.h directly,
 * because the AF_* definitions are protected with an ifdef KERNEL
 * wrapper, but we don't want to define that because that can cause
 * other redefinitions from glibc. However, because the kernel may have
 * more definitions than glibc, we need make sure AF_MAX reflects this,
 * hence the wrapping function.
 */
size_t get_af_max() {
	size_t af_max;
	/* HACK: declare that version without "create" had a static AF_MAX */
	if (!perms_create && !net_af_max_override)
		net_af_max_override = -1;

#if AA_AF_MAX > AF_MAX
	af_max = AA_AF_MAX;
#else
	af_max = AF_MAX;
#endif

	/* HACK: some kernels didn't handle network tables from parsers
	 * compiled against newer kernel headers as they are larger than
	 * the running kernel expected.  If net_override is defined check
	 * to see if there is a static max specified for that kernel
	 */
	if (net_af_max_override) {
		size_t max = kernel_af_max();
		if (max && max < af_max)
			return max;
	}

	return af_max;
}
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

char *processid(char *string, int len)
{
	/* lexer should never call this fn if len <= 0 */
	assert(len > 0);

	if (*string == '"')
		return processquoted(string, len);
	return processunquoted(string, len);
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
			case '0': case '1': case '2': case '3':
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

static int parse_sub_mode(const char *str_mode, const char *mode_desc __unused)
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
			if (read_implies_exec) {
				PDEBUG("Parsing mode: found %s READ imply X\n", mode_desc);
				mode |= AA_MAY_READ | AA_EXEC_MMAP;
			} else {
				PDEBUG("Parsing mode: found %s READ\n", mode_desc);
				mode |= AA_MAY_READ;
			}
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
			} else if (tolower(next) == COD_UNSAFE_UNCONFINED_CHAR) {
				tmode |= AA_EXEC_PUX;
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
	entry->audit = orig->audit;
	entry->deny = orig->deny;

	/* XXX - need to create copies of the patterns, too */
	entry->pattern_type = orig->pattern_type;
	entry->pat.regex = NULL;

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
	free(list);
}

void free_mnt_entries(struct mnt_entry *list)
{
	if (!list)
		return;
	if (list->next)
		free_mnt_entries(list->next);
	free(list->mnt_point);
	free(list->device);
	free_value_list(list->dev_type);
	free_value_list(list->opts);

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
	"audit_control",
	"setfcap",
	"mac_override"
	"syslog",
};

const char *capability_to_name(unsigned int cap)
{
	const char *capname;

	capname = (cap < (sizeof(capnames) / sizeof(char *))
		   ? capnames[cap] : "invalid-capability");

	return capname;
}

void __debug_capabilities(uint64_t capset, const char *name)
{
	unsigned int i;

	printf("%s:", name);
	for (i = 0; i < (sizeof(capnames)/sizeof(char *)); i++) {
		if (((1ull << i) & capset) != 0) {
			printf (" %s", capability_to_name(i));
		}
	}
	printf("\n");
}
void debug_capabilities(struct codomain *cod)
{
	if (cod->capabilities != 0ull)
		__debug_capabilities(cod->capabilities, "Capabilities");
	if (cod->audit_caps != 0ull)
		__debug_capabilities(cod->audit_caps, "Audit Caps");
	if (cod->deny_caps != 0ull)
		__debug_capabilities(cod->deny_caps, "Deny Caps");
	if (cod->quiet_caps != 0ull)
		__debug_capabilities(cod->quiet_caps, "Quiet Caps");
}

const char *sock_types[] = {
	[0] = "none",
	[SOCK_STREAM] = "stream",
	[SOCK_DGRAM] = "dgram",
	[SOCK_RAW] = "raw",
	[SOCK_RDM] = "rdm",
	[SOCK_SEQPACKET] = "seqpacket",
	[SOCK_PACKET] = "packet",
	/*
	 * See comment above
	[SOCK_DCCP] = "dccp",
	*/
};
#define ALL_TYPES 0x43e

#undef AA_GEN_NET_ENT
#define AA_GEN_NET_ENT(name, AF) [AF] = name,

static const char *network_families[] = {
#include "af_names.h"
};

void __debug_network(unsigned int *array, const char *name)
{
	unsigned int count = sizeof(sock_types)/sizeof(sock_types[0]);
	unsigned int mask = ~((1 << count) -1);
	unsigned int i, j;
	int none = 1;
	size_t af_max = get_af_max();

	for (i = AF_UNSPEC; i < af_max; i++)
		if (array[i]) {
			none = 0;
			break;
		}

	if (none)
		return;

	printf("%s: ", name);

	/* This can only be set by an unqualified network rule */
	if (array[AF_UNSPEC]) {
		printf("<all>\n");
		return;
	}

	for (i = 0; i < af_max; i++) {
		if (array[i]) {
			const char *fam = network_families[i];
			if (fam)
				printf("%s ", fam);
			else
				printf("#%u ", i);

			/* All types/protocols */
			if (array[i] == 0xffffffff || array[i] == ALL_TYPES)
				continue;

			printf("{ ");

			for (j = 0; j < count; j++) {
				const char *type;
				if (array[i] & (1 << j)) {
					type = sock_types[j];
					if (type)
						printf("%s ", type);
					else
						printf("#%u ", j);
				}
			}
			if (array[i] & mask)
				printf("#%x ", array[i] & mask);

			printf("} ");
		}
	}
	printf("\n");
}

void debug_network(struct codomain *cod)
{
	if (cod->network_allowed)
		__debug_network(cod->network_allowed, "Network");
	if (cod->audit_network)
		__debug_network(cod->audit_network, "Audit Net");
	if (cod->deny_network)
		__debug_network(cod->deny_network, "Deny Net");
	if (cod->quiet_network)
		__debug_network(cod->quiet_network, "Quiet Net");

}

void debug_cod_list(struct codomain *cod)
{
	if (cod->namespace)
		printf("Namespace:\t\t%s\n", cod->namespace);

	if (cod->name)
		printf("Name:\t\t%s\n", cod->name);
	else
		printf("Name:\t\tNULL\n");

	if (cod->local)
		printf("Local To:\t%s\n", cod->parent->name);

	debug_flags(cod);
	
	debug_capabilities(cod);

	debug_network(cod);

	if (cod->entries)
		debug_cod_entries(cod->entries);

	printf("\n");
	dump_policy_hats(cod);
}

struct value_list *new_value_list(char *value)
{
	struct value_list *val = calloc(1, sizeof(struct value_list));
	if (val)
		val->value = value;
	return val;
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

struct value_list *dup_value_list(struct value_list *list)
{
	struct value_list *entry, *dup, *head = NULL;
	char *value;

	list_for_each(list, entry) {
		value = NULL;
		if (list->value) {
			value = strdup(list->value);
			if (!value)
				goto fail2;
		}
		dup = new_value_list(value);
		if (!dup)
			goto fail;
		if (head)
			list_append(head, dup);
		else
			head = dup;
	}

	return head;

fail:
	free(value);
fail2:
	free_value_list(head);

	return NULL;
}

void print_value_list(struct value_list *list)
{
	struct value_list *entry;

	if (!list)
		return;

	fprintf(stderr, "%s", list->value);
	list = list->next;
	list_for_each(list, entry) {
		fprintf(stderr, ", %s", entry->value);
	}
}

struct cond_entry *new_cond_entry(char *name, int eq, struct value_list *list)
{
	struct cond_entry *ent = calloc(1, sizeof(struct cond_entry));
	if (ent) {
		ent->name = name;
		ent->vals = list;
		ent->eq = eq;
	}

	return ent;
}

void free_cond_entry(struct cond_entry *ent)
{
	if (ent) {
		free(ent->name);
		free_value_list(ent->vals);
		free(ent);
	}
}

void print_cond_entry(struct cond_entry *ent)
{
	if (ent) {
		fprintf(stderr, "%s=(", ent->name);
		print_value_list(ent->vals);
		fprintf(stderr, ")\n");
	}
}

#ifdef UNIT_TEST
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

int test_processunquoted(void)
{
	int rc = 0;
	char *teststring, *processedstring;

	teststring = "";
	MY_TEST(strcmp(teststring, processunquoted(teststring, strlen(teststring))) == 0,
			"processunquoted on empty string");

	teststring = "123\\421123";
	MY_TEST(strcmp(teststring, processunquoted(teststring, strlen(teststring))) == 0,
			"processunquoted on invalid octal");

/* Oh wow, our octal processing is busticated - FIXME
	teststring = "123\\109123";
	processedstring = "123\109123";
	MY_TEST(strcmp(processedstring, processunquoted(teststring, strlen(teststring))) == 0,
			"processunquoted on octal 10");

	teststring = "123\\189123";
	processedstring = "123\189123";
	MY_TEST(strcmp(processedstring, processunquoted(teststring, strlen(teststring))) == 0,
			"processunquoted on octal 10");
*/

	return rc;
}

int test_processquoted(void)
{
	int rc = 0;
	char *teststring, *processedstring;
	char *out;

	teststring = "";
	out = processquoted(teststring, strlen(teststring));
	MY_TEST(strcmp(teststring, out) == 0,
			"processquoted on empty string");
	free(out);

	teststring = "\"abcdefg\"";
	processedstring = "abcdefg";
	out = processquoted(teststring, strlen(teststring));
	MY_TEST(strcmp(processedstring, out) == 0,
			"processquoted on simple string");
	free(out);

	teststring = "\"abcd\\tefg\"";
	processedstring = "abcd\tefg";
	out = processquoted(teststring, strlen(teststring));
	MY_TEST(strcmp(processedstring, out) == 0,
			"processquoted on string with tab");
	free(out);

	teststring = "\"abcdefg\\\"";
	processedstring = "abcdefg\\";
	out = processquoted(teststring, strlen(teststring));
	MY_TEST(strcmp(processedstring, out) == 0,
			"processquoted on trailing slash");
	free(out);

	teststring = "\"a\\\\bcdefg\"";
	processedstring = "a\\bcdefg";
	out = processquoted(teststring, strlen(teststring));
	MY_TEST(strcmp(processedstring, out) == 0,
			"processquoted on quoted slash");
	free(out);

	teststring = "\"a\\\"bcde\\\"fg\"";
	processedstring = "a\"bcde\"fg";
	out = processquoted(teststring, strlen(teststring));
	MY_TEST(strcmp(processedstring, out) == 0,
			"processquoted on quoted quotes");
	free(out);

	teststring = "\"\\rabcdefg\"";
	processedstring = "\rabcdefg";
	out = processquoted(teststring, strlen(teststring));
	MY_TEST(strcmp(processedstring, out) == 0,
			"processquoted on quoted \\r");
	free(out);

	teststring = "\"abcdefg\\n\"";
	processedstring = "abcdefg\n";
	out = processquoted(teststring, strlen(teststring));
	MY_TEST(strcmp(processedstring, out) == 0,
			"processquoted on quoted \\n");
	free(out);

	teststring = "\"\\Uabc\\Ndefg\\x\"";
	processedstring = "\\Uabc\\Ndefg\\x";
	out = processquoted(teststring, strlen(teststring));
	MY_TEST(strcmp(processedstring, out) == 0,
			"processquoted passthrough on invalid quoted chars");
	free(out);

	teststring = "\"abc\\042defg\"";
	processedstring = "abc\"defg";
	out = processquoted(teststring, strlen(teststring));
	MY_TEST(strcmp(processedstring, out) == 0,
			"processquoted on quoted octal \\042");
	free(out);

	teststring = "\"abcdefg\\176\"";
	processedstring = "abcdefg~";
	out = processquoted(teststring, strlen(teststring));
	MY_TEST(strcmp(processedstring, out) == 0,
			"processquoted on quoted octal \\176");
	free(out);

	/* yes, our octal processing is lame; patches accepted */
	teststring = "\"abc\\42defg\"";
	processedstring = "abc\\42defg";
	out = processquoted(teststring, strlen(teststring));
	MY_TEST(strcmp(processedstring, out) == 0,
			"processquoted passthrough quoted invalid octal \\42");
	free(out);

	teststring = "\"abcdefg\\04\"";
	processedstring = "abcdefg\\04";
	out = processquoted(teststring, strlen(teststring));
	MY_TEST(strcmp(processedstring, out) == 0,
			"processquoted passthrough quoted invalid trailing octal \\04");
	free(out);

	return rc;
}

int main(void)
{
	int rc = 0;
	int retval;

	retval = test_str_to_boolean();
	if (retval != 0)
		rc = retval;

	retval = test_processunquoted();
	if (retval != 0)
		rc = retval;

	retval = test_processquoted();
	if (retval != 0)
		rc = retval;

	return rc;
}
#endif /* UNIT_TEST */
