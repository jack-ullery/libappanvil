/*
 *   Copyright (c) 1999, 2000, 2001, 2002, 2003, 2004, 2005, 2006, 2007
 *   NOVELL (All rights reserved)
 *
 *   Copyright (c) 2013
 *   Canonical Ltd. (All rights reserved)
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
#include <linux/capability.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <unistd.h>
#include <sys/apparmor.h>

#include "lib.h"
#include "parser.h"
#include "profile.h"
#include "parser_yacc.h"
#include "mount.h"
#include "dbus.h"

/* #define DEBUG */
#ifdef DEBUG
#undef PDEBUG
#define PDEBUG(fmt, args...) printf("Lexer: " fmt, ## args)
#else
#undef PDEBUG
#define PDEBUG(fmt, args...)	/* Do nothing */
#endif
#define NPDEBUG(fmt, args...)	/* Do nothing */

struct ignored_suffix_t {
	const char * text;
	int len;
	int silent;
};

static struct ignored_suffix_t ignored_suffixes[] = {
	/* Debian packging files, which are in flux during install
           should be silently ignored. */
	{ ".dpkg-new", 9, 1 },
	{ ".dpkg-old", 9, 1 },
	{ ".dpkg-dist", 10, 1 },
	{ ".dpkg-bak", 9, 1 },
	/* RPM packaging files have traditionally not been silently
           ignored */
	{ ".rpmnew", 7, 0 },
	{ ".rpmsave", 8, 0 },
	/* patch file backups/conflicts */
	{ ".orig", 5, 0 },
	{ ".rej", 4, 0 },
	/* Backup files should be mentioned */
	{ "~", 1, 0 },
	{ NULL, 0, 0 }
};

int is_blacklisted(const char *name, const char *path)
{
	int name_len;
	struct ignored_suffix_t *suffix;

	/* skip dot files and files with no name */
	if (*name == '.' || !strlen(name))
		return 1;

	name_len = strlen(name);
	/* skip blacklisted suffixes */
	for (suffix = ignored_suffixes; suffix->text; suffix++) {
		char *found;
		if ( (found = strstr((char *) name, suffix->text)) &&
		     found - name + suffix->len == name_len ) {
			if (!suffix->silent)
				PERROR("Ignoring: '%s'\n", path ? path : name);
			return 1;
		}
	}

	return 0;
}

struct keyword_table {
	const char *keyword;
	int token;
};

static struct keyword_table keyword_table[] = {
	/* network */
	{"network",		TOK_NETWORK},
	{"unix",		TOK_UNIX},
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
	{"allow",		TOK_ALLOW},
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
	{"dbus",		TOK_DBUS},
	{"signal",		TOK_SIGNAL},
	{"send",                TOK_SEND},
	{"receive",             TOK_RECEIVE},
	{"bind",                TOK_BIND},
	{"read",                TOK_READ},
	{"write",               TOK_WRITE},
	{"eavesdrop",		TOK_EAVESDROP},
	{"peer",		TOK_PEER},
	{"trace",		TOK_TRACE},
	{"tracedby",		TOK_TRACEDBY},
	{"readby",		TOK_READBY},

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
#ifdef RLIMIT_RTTIME
	{"rttime",		RLIMIT_RTTIME},
#endif
	/* terminate */
	{NULL, 0}
};

/* for alpha matches, check for keywords */
static int get_table_token(const char *name unused, struct keyword_table *table,
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

char *processunquoted(const char *string, int len)
{
	char *buffer, *s;

	s = buffer = (char *) malloc(len + 1);
	if (!buffer)
		return NULL;

	while (len > 0) {
		const char *pos = string + 1;
		long c;
		if (*string == '\\' && len > 1 &&
		    (c = strn_escseq(&pos, "", len)) != -1) {
			/* catch \\ or \134 and other aare special chars and
			 * pass it through to be handled by the backend
			 * pcre conversion
			 */
			if (strchr("*?[]{}^,\\", c) != NULL) {
				*s++ = '\\';
				*s++ = c;
			} else
				*s++ = c;
			len -= pos - string;
			string = pos;
		} else {
			/* either unescaped char OR
			 * unsupported escape sequence resulting in char being
			 * copied.
			 */
			*s++ = *string++;
			len--;
		}
	}
	*s = 0;

	return buffer;
}

/* rewrite a quoted string substituting escaped characters for the
 * real thing.  Strip the quotes around the string */
char *processquoted(const char *string, int len)
{
	/* skip leading " and eat trailing " */
	if (*string == '"') {
		len -= 2;
		if (len < 0)	/* start and end point to same quote */
			len = 0;
		return processunquoted(string + 1, len);
	}

	/* no quotes? treat as unquoted */
	return processunquoted(string, len);
}

char *processid(const char *string, int len)
{
	/* lexer should never call this fn if len <= 0 */
	assert(len > 0);

	if (*string == '"')
		return processquoted(string, len);
	return processunquoted(string, len);
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

void warn_uppercase(void)
{
	if (!warned_uppercase) {
		pwarn(_("Uppercase qualifiers \"RWLIMX\" are deprecated, please convert to lowercase\n"
			"See the apparmor.d(5) manpage for details.\n"));
		warned_uppercase = 1;
	}
}

static int parse_sub_mode(const char *str_mode, const char *mode_desc unused)
{

#define IS_DIFF_QUAL(mode, q) (((mode) & AA_MAY_EXEC) && (((mode) & AA_EXEC_TYPE) != ((q) & AA_EXEC_TYPE)))

	int mode = 0;
	const char *p;

	PDEBUG("Parsing mode: %s\n", str_mode);

	if (!str_mode)
		return 0;

	p = str_mode;
	while (*p) {
		char thisc = *p;
		char next = *(p + 1);
		char lower;
		int tmode = 0;

reeval:
		switch (thisc) {
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
					thisc);
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
			if (tolower(thisc) == COD_UNSAFE_PROFILE_CHAR)
				tmode |= AA_EXEC_PROFILE | AA_MAY_EXEC;
			else
			{
				tmode |= AA_EXEC_LOCAL | AA_MAY_EXEC;
			}
			PDEBUG("Parsing mode: found PROFILE\n");
			if (tolower(next) == COD_INHERIT_CHAR) {
				tmode |= AA_EXEC_INHERIT;
				if (IS_DIFF_QUAL(mode, tmode)) {
					yyerror(_("Exec qualifier '%c%c' invalid, conflicting qualifier already specified"), thisc, next);
				} else {
					mode |= tmode;
					p += 2;		/* skip x */
				}
			} else if (tolower(next) == COD_UNSAFE_UNCONFINED_CHAR) {
				tmode |= AA_EXEC_PUX;
				if (IS_DIFF_QUAL(mode, tmode)) {
					yyerror(_("Exec qualifier '%c%c' invalid, conflicting qualifier already specified"), thisc, next);
				} else {
					mode |= tmode;
					p += 2;		/* skip x */
				}
			} else if (IS_DIFF_QUAL(mode, tmode)) {
				yyerror(_("Exec qualifier '%c' invalid, conflicting qualifier already specified"), thisc);

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
			/* thisc is valid for deny rules, and named transitions
			 * but invalid for regular x transitions
			 * sort it out later.
			 */
			mode |= AA_MAY_EXEC;
			break;

 		/* error cases */

		default:
			lower = tolower(thisc);
			switch (lower) {
			case COD_READ_CHAR:
			case COD_WRITE_CHAR:
			case COD_APPEND_CHAR:
			case COD_LINK_CHAR:
			case COD_INHERIT_CHAR:
			case COD_MMAP_CHAR:
			case COD_EXEC_CHAR:
				PDEBUG("Parsing mode: found invalid upper case char %c\n", thisc);
				warn_uppercase();
				thisc = lower;
				goto reeval;
				break;
			default:
				yyerror(_("Internal: unexpected mode character '%c' in input"),
					thisc);
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

static int parse_X_sub_mode(const char *X, const char *str_mode, int *result, int fail, const char *mode_desc unused)
{
	int mode = 0;
	const char *p;

	PDEBUG("Parsing X mode: %s\n", X, str_mode);

	if (!str_mode)
		return 0;

	p = str_mode;
	while (*p) {
		char current = *p;
		char lower;

reeval:
		switch (current) {
		case COD_READ_CHAR:
			PDEBUG("Parsing %s mode: found %s READ\n", X, mode_desc);
			mode |= AA_DBUS_RECEIVE;
			break;

		case COD_WRITE_CHAR:
			PDEBUG("Parsing %s mode: found %s WRITE\n", X,
			       mode_desc);
			mode |= AA_DBUS_SEND;
			break;

		/* error cases */

		default:
			lower = tolower(current);
			switch (lower) {
			case COD_READ_CHAR:
			case COD_WRITE_CHAR:
				PDEBUG("Parsing %s mode: found invalid upper case char %c\n",
				       X, current);
				warn_uppercase();
				current = lower;
				goto reeval;
				break;
			default:
				if (fail)
					yyerror(_("Internal: unexpected %s mode character '%c' in input"),
						X, current);
				else
					return 0;
				break;
			}
			break;
		}
		p++;
	}

	PDEBUG("Parsed %s mode: %s 0x%x\n", X, str_mode, mode);

	*result = mode;
	return 1;
}

int parse_X_mode(const char *X, int valid, const char *str_mode, int *mode, int fail)
{
	*mode = 0;
	if (!parse_X_sub_mode(X, str_mode, mode, fail, ""))
		return 0;
	if (*mode & ~valid) {
		if (fail)
			yyerror(_("Internal error generated invalid %s perm 0x%x\n"),
				X, mode);
		else
			return 0;
	}
	return 1;
}

struct cod_entry *new_entry(char *ns, char *id, int mode, char *link_id)
{
	struct cod_entry *entry = NULL;

	entry = (struct cod_entry *)calloc(1, sizeof(struct cod_entry));
	if (!entry)
		return NULL;

	entry->ns = ns;
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

	DUP_STRING(orig, entry, ns, err);
	DUP_STRING(orig, entry, name, err);
	DUP_STRING(orig, entry, link_name, err);
	entry->mode = orig->mode;
	entry->audit = orig->audit;
	entry->deny = orig->deny;

	/* XXX - need to create copies of the patterns, too */
	entry->pattern_type = orig->pattern_type;
	entry->pat.regex = NULL;

	entry->next = orig->next;

	return entry;

err:
	free_cod_entries(entry);
	return NULL;
}

void free_cod_entries(struct cod_entry *list)
{
	if (!list)
		return;
	if (list->next)
		free_cod_entries(list->next);
	if (list->ns)
		free(list->ns);
	if (list->name)
		free(list->name);
	if (list->link_name)
		free(list->link_name);
	if (list->nt_name)
		free(list->nt_name);
	if (list->pat.regex)
		free(list->pat.regex);
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

		if (item->ns)
			printf("\tNs:\t(%s)\n", item->ns);

		if (AA_LINK_BITS & item->mode)
			printf("\tlink:\t(%s)\n", item->link_name ? item->link_name : "/**");

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

struct value_list *new_value_list(char *value)
{
	struct value_list *val = (struct value_list *) calloc(1, sizeof(struct value_list));
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

void move_conditional_value(const char *rulename, char **dst_ptr,
			    struct cond_entry *cond_ent)
{
	if (*dst_ptr)
		yyerror("%s conditional \"%s\" can only be specified once\n",
			rulename, cond_ent->name);

	*dst_ptr = cond_ent->vals->value;
	cond_ent->vals->value = NULL;
}

struct cond_entry *new_cond_entry(char *name, int eq, struct value_list *list)
{
	struct cond_entry *ent = (struct cond_entry *) calloc(1, sizeof(struct cond_entry));
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

void free_cond_list(struct cond_entry *ents)
{
	struct cond_entry *entry, *tmp;

	list_for_each_safe(ents, entry, tmp) {
		free_cond_entry(entry);
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

#include "unit_test.h"

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
	const char *teststring;
	const char *resultstring;

	teststring = "";
	MY_TEST(strcmp(teststring, processunquoted(teststring, strlen(teststring))) == 0,
			"processunquoted on empty string");

	teststring = "\\1";
	resultstring = "\001";
	MY_TEST(strcmp(resultstring, processunquoted(teststring, strlen(teststring))) == 0,
			"processunquoted on one digit octal");

	teststring = "\\8";
	resultstring = "\\8";
	MY_TEST(strcmp(resultstring, processunquoted(teststring, strlen(teststring))) == 0,
			"processunquoted on invalid octal digit \\8");

	teststring = "\\18";
	resultstring = "\0018";
	MY_TEST(strcmp(resultstring, processunquoted(teststring, strlen(teststring))) == 0,
			"processunquoted on one digit octal followed by invalid octal digit");

	teststring = "\\1a";
	resultstring = "\001a";
	MY_TEST(strcmp(resultstring, processunquoted(teststring, strlen(teststring))) == 0,
			"processunquoted on one digit octal followed by hex digit a");

	teststring = "\\1z";
	resultstring = "\001z";
	MY_TEST(strcmp(resultstring, processunquoted(teststring, strlen(teststring))) == 0,
			"processunquoted on one digit octal follow by char z");

	teststring = "\\11";
	resultstring = "\011";
	MY_TEST(strcmp(resultstring, processunquoted(teststring, strlen(teststring))) == 0,
			"processunquoted on two digit octal");

	teststring = "\\118";
	resultstring = "\0118";
	MY_TEST(strcmp(resultstring, processunquoted(teststring, strlen(teststring))) == 0,
			"processunquoted on two digit octal followed by invalid octal digit");

	teststring = "\\11a";
	resultstring = "\011a";
	MY_TEST(strcmp(resultstring, processunquoted(teststring, strlen(teststring))) == 0,
			"processunquoted on two digit octal followed by hex digit a");

	teststring = "\\11z";
	resultstring = "\011z";
	MY_TEST(strcmp(resultstring, processunquoted(teststring, strlen(teststring))) == 0,
			"processunquoted on two digit octal followed by char z");

	teststring = "\\111";
	resultstring = "\111";
	MY_TEST(strcmp(resultstring, processunquoted(teststring, strlen(teststring))) == 0,
			"processunquoted on three digit octal");

	teststring = "\\378";
	resultstring = "\0378";
	MY_TEST(strcmp(resultstring, processunquoted(teststring, strlen(teststring))) == 0,
			"processunquoted on three digit octal two large, taken as 2 digit octal plus trailing char");

	teststring = "123\\421123";
	resultstring = "123\0421123";
	MY_TEST(strcmp(resultstring, processunquoted(teststring, strlen(teststring))) == 0,
			"processunquoted on two character octal followed by valid octal digit \\421");

	teststring = "123\\109123";
	resultstring = "123\109123";
	MY_TEST(strcmp(resultstring, processunquoted(teststring, strlen(teststring))) == 0,
			"processunquoted on octal 109");

	teststring = "123\\1089123";
	resultstring = "123\1089123";
	MY_TEST(strcmp(resultstring, processunquoted(teststring, strlen(teststring))) == 0,
			"processunquoted on octal 108");

	return rc;
}

int test_processquoted(void)
{
	int rc = 0;
	const char *teststring, *processedstring;
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
	processedstring = "a\\\\bcdefg";
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

	teststring = "\"abc\\429defg\"";
	processedstring = "abc\0429defg";
	out = processquoted(teststring, strlen(teststring));
	MY_TEST(strcmp(processedstring, out) == 0,
			"processquoted passthrough quoted invalid octal \\429");
	free(out);

	teststring = "\"abcdefg\\4\"";
	processedstring = "abcdefg\004";
	out = processquoted(teststring, strlen(teststring));
	MY_TEST(strcmp(processedstring, out) == 0,
			"processquoted passthrough quoted one digit trailing octal \\4");

	teststring = "\"abcdefg\\04\"";
	processedstring = "abcdefg\004";
	out = processquoted(teststring, strlen(teststring));
	MY_TEST(strcmp(processedstring, out) == 0,
			"processquoted passthrough quoted two digit trailing octal \\04");

	teststring = "\"abcdefg\\004\"";
	processedstring = "abcdefg\004";
	out = processquoted(teststring, strlen(teststring));
	MY_TEST(strcmp(processedstring, out) == 0,
			"processquoted passthrough quoted three digit trailing octal \\004");
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
