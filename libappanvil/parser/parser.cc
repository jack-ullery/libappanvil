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

#include <cassert>
#include <cstring>

#include "lib.h"
#include "common.hh"
#include "lexer.hh"

// NOLINTBEGIN
struct keyword_table {
	const char *keyword;
	unsigned int token;
};

static struct keyword_table keyword_table[] = {
	/* network */
	{"network",			token::TOK_NETWORK},
	{"unix",			token::TOK_UNIX},
	/* misc keywords */
	{"capability",		token::TOK_CAPABILITY},
	{"if",				token::TOK_IF},
	{"else",			token::TOK_ELSE},
	{"not",				token::TOK_NOT},
	{"defined",			token::TOK_DEFINED},
	{"change_profile",	token::TOK_CHANGE_PROFILE},
	{"unsafe",			token::TOK_UNSAFE},
	{"safe",			token::TOK_SAFE},
	{"link",			token::TOK_LINK},
	{"owner",			token::TOK_OWNER},
	{"user",			token::TOK_OWNER},
	{"other",			token::TOK_OTHER},
	{"subset",			token::TOK_SUBSET},
	{"audit",			token::TOK_AUDIT},
	{"deny",			token::TOK_DENY},
	{"allow",			token::TOK_ALLOW},
	{"set",				token::TOK_SET},
	{"rlimit",			token::TOK_RLIMIT},
	{"alias",			token::TOK_ALIAS},
	{"rewrite",			token::TOK_ALIAS},
	{"ptrace",			token::TOK_PTRACE},
	{"file",			token::TOK_FILE},
	{"mount",			token::TOK_MOUNT},
	{"remount",			token::TOK_REMOUNT},
	{"umount",			token::TOK_UMOUNT},
	{"unmount",			token::TOK_UMOUNT},
	{"pivot_root",		token::TOK_PIVOTROOT},
	{"in",				token::TOK_IN},
	{"dbus",			token::TOK_DBUS},
	{"signal",			token::TOK_SIGNAL},
	{"send",            token::TOK_SEND},
	{"receive",         token::TOK_RECEIVE},
	{"bind",            token::TOK_BIND},
	{"read",            token::TOK_READ},
	{"write",           token::TOK_WRITE},
	{"eavesdrop",		token::TOK_EAVESDROP},
	{"peer",			token::TOK_PEER},
	{"trace",			token::TOK_TRACE},
	{"tracedby",		token::TOK_TRACEDBY},
	{"readby",			token::TOK_READBY},
	{"abi",				token::TOK_ABI},
	{"userns",			token::TOK_USERNS},

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
#ifdef RLIMIT_OFILE
	{"ofile",		RLIMIT_OFILE},
#endif
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
static int get_table_token(struct keyword_table *table,
			   const char *keyword)
{
	int i;
	for (i = 0; table[i].keyword; i++) {
		if (strcmp(keyword, table[i].keyword) == 0) {
			return table[i].token;
		}
	}
	return -1;
}

/* for alpha matches, check for keywords */
int get_keyword_token(const char *keyword)
{
	return get_table_token(keyword_table, keyword);
}

int get_rlimit(const char *name)
{
	return get_table_token(rlimit_table, name);
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
			if (c == 0) {
				strncpy(s, string, pos - string);
				s += pos - string;
			} else if (strchr("*?[]{}^,\\", c) != NULL) {
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
		if (string[len -1] != '"')
			return NULL;
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
// NOLINTEND
