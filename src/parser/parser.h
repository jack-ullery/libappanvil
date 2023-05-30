/*
 *   Copyright (c) 1999, 2000, 2001, 2002, 2004, 2005, 2006, 2007
 *   NOVELL (All rights reserved)
 *
 *   Copyright (c) 2010 - 2012
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
 *   along with this program; if not, contact Novell, Inc. or Canonical
 *   Ltd.
 */

#ifndef __AA_PARSER_H
#define __AA_PARSER_H

#include <endian.h>
#include <stdint.h>
#include <string.h>
#include <sys/resource.h>

#include <libintl.h>
#define _(s) gettext(s)

#define MODULE_NAME "apparmor"

/* Global variable to pass token to lexer.  Will be replaced by parameter
 * when lexer and parser are made reentrant
 */
// extern int parser_token;


#define WARN_RULE_NOT_ENFORCED	0x1
#define WARN_RULE_DOWNGRADED	0x2
#define WARN_ABI		0x4
#define WARN_DEPRECATED		0x8
#define WARN_CONFIG		0x10
#define WARN_CACHE		0x20
#define WARN_DEBUG_CACHE	0x40
#define WARN_JOBS		0x80
#define WARN_DANGEROUS		0x100
#define WARN_UNEXPECTED		0x200
#define WARN_FORMAT		0x400
#define WARN_MISSING		0x800
#define WARN_OVERRIDE		0x1000
#define WARN_INCLUDE		0x2000

#define WARN_DEV (WARN_RULE_NOT_ENFORCED | WARN_RULE_DOWNGRADED | WARN_ABI | \
		  WARN_DEPRECATED | WARN_DANGEROUS | WARN_UNEXPECTED | \
		  WARN_FORMAT | WARN_MISSING | WARN_OVERRIDE | \
		  WARN_DEBUG_CACHE | WARN_INCLUDE)

#define DEFAULT_WARNINGS (WARN_CONFIG | WARN_CACHE | WARN_JOBS | \
			  WARN_UNEXPECTED | WARN_OVERRIDE)

#define WARN_ALL (WARN_RULE_NOT_ENFORCED | WARN_RULE_DOWNGRADED | WARN_ABI | \
		  WARN_DEPRECATED | WARN_CONFIG | WARN_CACHE | \
		  WARN_DEBUG_CACHE | WARN_JOBS | WARN_DANGEROUS | \
		  WARN_UNEXPECTED | WARN_FORMAT | WARN_MISSING | \
		  WARN_OVERRIDE | WARN_INCLUDE)

// 
// 
// typedef enum pattern_t pattern_t;
// 
// struct prefixes {
// 	int audit;
// 	int deny;
// 	int owner;
// };

struct cod_pattern {
	char *regex;		// posix regex
};

struct value_list {
	char *value;

	struct value_list *next;
};

struct cond_entry {
	char *name;
	int eq;			/* where equals was used in specifying list */
	struct value_list *vals;

	struct cond_entry *next;
};

struct cond_entry_list {
	char *name;

	struct cond_entry *list;
};

// struct cod_entry {
// 	char *name;
// 	union {
// 		char *link_name;
// 		char *onexec;
// 	};
// 	char *nt_name;
// 	Profile *prof;		 	/* Special profile defined
// 					 * just for this executable */
// 	int mode;			/* mode is 'or' of AA_* bits */
// 	int audit;			/* audit flags for mode */
// 	int deny;			/* TRUE or FALSE */
// 
// 	int alias_ignore;		/* ignore for alias processing */
// 
// 	int subset;
// 
// 	pattern_t pattern_type;
// 	struct cod_pattern pat;
// 
// 	struct cod_entry *next;
// };

struct aa_rlimits {
	unsigned int specified;			/* limits that are set */
	rlim_t limits[RLIMIT_NLIMITS];
};

struct alt_name {
	char *name;
	struct alt_name *next;
};

struct sd_hat {
	char *hat_name;
	unsigned int hat_magic;
};

struct var_string {
	char *prefix;
	char *var;
	char *suffix;
};

enum ProfileMode {
  PROFILE_MODE_EMPTY,
  PROFILE_MODE_START,
  PROFILE_MODE_HAT,
};

enum COD {
  COD_READ_CHAR              = 'r',
  COD_WRITE_CHAR             = 'w',
  COD_APPEND_CHAR            = 'a',
  COD_EXEC_CHAR              = 'x',
  COD_LINK_CHAR              = 'l',
  COD_LOCK_CHAR              = 'k',
  COD_MMAP_CHAR              = 'm',
  COD_INHERIT_CHAR           = 'i',
  COD_UNCONFINED_CHAR        = 'U',
  COD_UNSAFE_UNCONFINED_CHAR = 'u',
  COD_PROFILE_CHAR           = 'P',
  COD_UNSAFE_PROFILE_CHAR    = 'p',
  COD_LOCAL_CHAR             = 'C',
  COD_UNSAFE_LOCAL_CHAR      = 'c',
};

enum Option {
  OPTION_ADD     = 1,
  OPTION_REMOVE  = 2,
  OPTION_REPLACE = 3,
  OPTION_STDOUT  = 4,
  OPTION_OFILE   = 5,
};

#define PATH_CHROOT_REL 0x1
#define PATH_NS_REL 0x2
#define PATH_CHROOT_NSATTACH 0x4
#define PATH_CHROOT_NO_ATTACH 0x8
#define PATH_MEDIATE_DELETED 0x10
#define PATH_DELEGATE_DELETED 0x20
#define PATH_ATTACH 0x40
#define PATH_NO_ATTACH 0x80

enum ExecMode {
  EXEC_MODE_EMPTY = 0,
  EXEC_MODE_UNSAFE = 1,
  EXEC_MODE_SAFE = 2
};

#ifdef DEBUG
#define PDEBUG(fmt, args...)				\
do {							\
	int pdebug_error = errno;			\
	fprintf(stderr, "parser: " fmt, ## args);	\
	errno = pdebug_error;				\
} while (0)
#else
#define PDEBUG(fmt, args...)	/* Do nothing */
#endif
#define NPDEBUG(fmt, args...)	/* Do nothing */

#define PERROR(fmt, args...)			\
do {						\
	int perror_error = errno;		\
	fprintf(stderr, fmt, ## args);		\
	errno = perror_error;			\
} while (0)

#ifndef TRUE
#define TRUE	(1)
#endif
#ifndef FALSE
#define FALSE	(0)
#endif

#define MIN_PORT 0
#define MAX_PORT 65535

#ifndef unused
#define unused __attribute__ ((unused))
#endif

/* provided by parser_lex.l */
extern int yyparse(void);
extern void yyerror(const char *msg, ...);

extern char *processid(const char *string, int len);
extern char *processquoted(const char *string, int len);
extern char *processunquoted(const char *string, int len);
extern int get_keyword_token(const char *keyword);

typedef struct YYLTYPE
{
  uint64_t first_pos;
  uint64_t last_pos;
} YYLTYPE;

#endif /** __AA_PARSER_H */
