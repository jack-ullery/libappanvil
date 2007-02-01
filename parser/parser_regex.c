/* $Id$ */

/*
 *   Copyright (c) 1999, 2000, 2001, 2002, 2004, 2005, 2006 NOVELL
 *   (All rights reserved)
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

#define _GNU_SOURCE /* for strndup(3) */
#include <stdio.h>
#include <stdarg.h>
#include <string.h>
#include <libintl.h>
#define _(s) gettext(s)

/* #define DEBUG */

#include "parser.h"

enum error_type {
	e_no_error,
	e_parse_error,
	e_buffer_overflow
};

/* filter_escapes: scan input for any escape characters
 * and remove, and reduce double \\ to a single
 * NOTE: modifies in place the contents of the name argument */
static void filter_escapes(char *name)
{
	char *sptr, *dptr;
	BOOL bEscape = 0;

	if (!name)	/* shouldn't happen */
		return;

	sptr = dptr = name;
	while (*sptr) {
		if (*sptr == '\\') {
			if (bEscape) {
				*dptr++ = *sptr++;
			} else {
				++sptr;
				bEscape = TRUE;
				continue;
			}
		} else if (dptr < sptr) {
			*dptr++ = *sptr++;
		} else {
			dptr++;
			sptr++;
		}
		bEscape = 0;
	}
	*dptr = 0;
}

/* Filters out multiple slashes (except if the first two are slashes,
 * that's a distinct namespace in linux) and trailing slashes.
 * NOTE: modifies in place the contents of the path argument */

static void filter_slashes(char *path)
{
	char *sptr, *dptr;
	BOOL seen_slash = 0;
	int len;

	if (!path || (strlen(path) < 2))
		return;

	sptr = dptr = path;

	/* special case for linux // namespace */
	if (sptr[0] == '/' && sptr[1] == '/' && sptr[2] != '/') {
		sptr += 2;
		dptr += 2;
	}

	while (*sptr) {
		if (*sptr == '/') {
			if (seen_slash) {
				++sptr;
			} else {
				*dptr++ = *sptr++;
				seen_slash = TRUE;
			}
		} else {
			seen_slash = 0;
			if (dptr < sptr) {
				*dptr++ = *sptr++;
			} else {
				dptr++;
				sptr++;
			}
		}
	}
	*dptr = 0;
	/* eliminate trailing slash */
	len = strlen(path);
	if (len > 2 && path[len -1] == '/') {
		path[len - 1] = 0;
	}
}

static int process_regex_entry(struct cod_entry *entry)
{
#define STORE(_src, _dest, _len) \
	if ((const char*)_dest + _len > tbufend){ \
		error = e_buffer_overflow; \
	} else { \
		memcpy(_dest, _src, _len); \
		_dest += _len; \
	}


	int ret = TRUE;
	/* flag to indicate input error */
	enum error_type error;

	char tbuf[PATH_MAX + 3];	/* +3 for ^, $ and \0 */
	const char *tbufend = &tbuf[PATH_MAX];

	const char *sptr;
	char *dptr;
	pattern_t ptype;

	BOOL bEscape = 0;	/* flag to indicate escape */
	int ingrouping = 0;	/* flag to indicate {} context */
	int incharclass = 0;	/* flag to indicate [ ] context */

	error = e_no_error;
	ptype = ePatternBasic;	/* assume no regex */

	if (!entry) 		/* shouldn't happen */
		return TRUE;

	sptr = entry->name;
	dptr = tbuf;

	/* anchor beginning of regular expression */
	*dptr++ = '^';

	while (error == e_no_error && *sptr) {
		switch (*sptr) {

		case '\\':
			/* concurrent escapes are allowed now and
			 * output as two consecutive escapes so that
			 * pcre won't interpret them
			 * \\\{...\\\} will be emitted as \\\{...\\\}
			 * for pcre matching.  For string matching
			 * and globbing only one escape is output
			 * this is done by stripping later
			 */
			if (bEscape) {
				STORE("\\\\", dptr, 2);
			} else {
				bEscape = TRUE;
				++sptr;
				continue;	/*skip turning bEscape off */
			}	/* bEscape */
			break;
		case '*':
			if (bEscape) {
				/* '*' is a PCRE special character */
				/* We store an escaped *, in case we
				 * end up using this regex buffer (i.e another
				 * non-escaped regex follows)
				 */
				STORE("\\*", dptr, 2);
			} else {
				if (*(sptr + 1) == '*') {
					/* is this the first regex form we
					 * have seen and also the end of
					 * pattern? If so, we can use
					 * optimised tail globbing rather
					 * than full regex.
					 */
					if (*(sptr + 2) == '\0' &&
					    ptype == ePatternBasic) {
						ptype = ePatternTailGlob;
					} else {
						ptype = ePatternRegex;
					}

					STORE(".*", dptr, 2);
					sptr++;
				} else {
					ptype = ePatternRegex;
					STORE("[^/]*", dptr, 5);
				}	/* *(sptr+1) == '*' */
			}	/* bEscape */

			break;

		case '?':
			if (bEscape) {
				/* ? is not a PCRE regex character
				 * so no need to escape, just skip
				 * transform
				 */
				STORE(sptr, dptr, 1);
			} else {
				ptype = ePatternRegex;
				STORE("[^/]", dptr, 4);
			}
			break;

		case '[':
			if (bEscape) {
				/* [ is a PCRE special character */
				STORE("\\[", dptr, 2);
			} else {
				incharclass = 1;
				ptype = ePatternRegex;
				STORE(sptr, dptr, 1);
			}
			break;

		case ']':
			if (bEscape) {
				/* ] is a PCRE special character */
				STORE("\\]", dptr, 2);
			} else {
				incharclass = 0;
				STORE(sptr, dptr, 1);
			}
			break;

		case '{':
			if (bEscape) {
				/* { is a PCRE special character */
				STORE("\\{", dptr, 2);
			} else {
				if (ingrouping) {
					error = e_parse_error;
					PERROR(_("%s: Illegal open {, nesting groupings not allowed\n"),
					       progname);
				} else {
					ingrouping = 1;
					ptype = ePatternRegex;
					STORE("(", dptr, 1);
				}
			}
			break;

		case '}':
			if (bEscape) {
				/* { is a PCRE special character */
				STORE("\\}", dptr, 2);
			} else {
				if (ingrouping <= 1) {

					error = e_parse_error;

					if (ingrouping == 1) {
						PERROR(_("%s: Regex grouping error: Invalid number of items between {}\n"),
						       progname);

						ingrouping = 0;	/* prevent further errors */

					} else {	/* ingrouping == 0 */
						PERROR(_("%s: Regex grouping error: Invalid close }, no matching open { detected\n"),
						       progname);
					}
				} else {	/* ingrouping > 1 */
					ingrouping = 0;
					STORE(")", dptr, 1);
				}
			}	/* bEscape */

			break;

		case ',':
			if (bEscape) {
				/* , is not a PCRE regex character
				 * so no need to escape, just skip
				 * transform
				 */
				STORE(sptr, dptr, 1);
			} else {
				if (ingrouping) {
					++ingrouping;
					STORE("|", dptr, 1);
				} else {
					STORE(sptr, dptr, 1);
				}
			}
			break;

			/* these are special outside of character
			 * classes but not in them */
		case '^':
		case '$':
			if (incharclass) {
				STORE(sptr, dptr, 1);
			} else {
				STORE("\\", dptr, 1);
				STORE(sptr, dptr, 1);
			}
			break;

			/*
			 * Not a subdomain regex, but needs to be
			 * escaped as it is a pcre metacharacter which
			 * we don't want to support. We always escape
			 * these, so no need to check bEscape
			 */
		case '.':
		case '+':
		case '|':
		case '(':
		case ')':
			STORE("\\", dptr, 1);
			// fall through to default

		default:
			STORE(sptr, dptr, 1);
			break;
		}	/* switch (*sptr) */

		bEscape = FALSE;
		++sptr;
	}		/* while error == e_no_error && *sptr) */

	if (ingrouping > 0 || incharclass) {
		error = e_parse_error;

		PERROR(_("%s: Regex grouping error: Unclosed grouping or character class, expecting close }\n"),
		       progname);
	}

	/* anchor end and terminate pattern string */
	if (error == e_no_error) {
		char buf[2] = { '$', 0 };

		STORE(buf, dptr, 2);
	}

	/* check error  again, as above STORE may have set it */
	if (error != e_no_error) {
		if (error == e_buffer_overflow) {
			PERROR(_("%s: Internal buffer overflow detected, %d characters exceeded\n"),
			       progname, PATH_MAX);
		}

		PERROR(_("%s: Unable to parse input line '%s'\n"),
		       progname, entry->name);

		ret = FALSE;
		goto out;
	}

	entry->pattern_type = ptype;

	/*
	 * Only use buffer (tbuf) that we built above, if we
	 * identified a pattern requiring full regex support.
	 */
	if (ptype == ePatternRegex) {
		int pattlen = strlen(tbuf);

		if ((entry->pat.regex = malloc(pattlen + 1))) {
			const char *errorreason;
			int errpos;

			strcpy(entry->pat.regex, tbuf);

			if ((entry->pat.compiled =
			     pcre_compile(entry->pat.regex, 0,
					  &errorreason, &errpos,
					  NULL))) {
				/* NULL out tables, kernel will use a
				 * private version
				 */
				entry->pat.compiled->tables = NULL;
			} else {
				int i;

				PERROR(_("%s: Failed to compile regex '%s' [original: '%s']\n"),
				       progname, entry->pat.regex,
				       entry->name);

				PERROR(_("%s: error near               "),
				       progname);

				for (i = 0; i < errpos; i++) {
					fputc('.', stderr);
				}

				fputc('^', stderr);
				fputc('\n', stderr);

				PERROR(_("%s: error reason: '%s'\n"),
				       progname, errorreason);

				free(entry->pat.regex);
				entry->pat.regex = NULL;

				ret = FALSE;
			}
		} else {
			PERROR(_("%s: Failed to compile regex '%s' [original: '%s'] - malloc failed\n"),
			       progname, entry->pat.regex, entry->name);

			ret = FALSE;
		}
	} else {
		/* not a regex, scan input for any escape characters
		 * and remove, and reduce double \\ to a single */
		filter_escapes(entry->name);
	}		/* ptype == ePatternRegex */

out:
	return ret;
}

int post_process_entries(struct cod_entry *entry_list)
{
	int ret = TRUE, rc;
	struct cod_entry *entry;

	for (entry = entry_list; entry; entry = entry->next) {
		filter_slashes(entry->name);
		rc = process_regex_entry(entry);
		if (!rc)
			ret = FALSE;
	}

	return ret;
}

int process_regex(struct codomain *cod)
{
	int error = 0;

	if (!post_process_entries(cod->entries)) {
		error = -1;
	}

	/*
	 * Post process subdomain(s):
	 *
	 * They are chained from the toplevel subdomain pointer
	 * thru each <codomain> next pointer.

	 * i.e first subdomain is list->subdomain
	 *    second subdomain is list->subdomain->next
	 *
	 * N.B sub-subdomains are not valid so:
	 * if (list->subdomain) {
	 *    assert(list->subdomain->subdomain == NULL)
	 * }
	 */
	if (process_hat_regex(cod) != 0)
		error = -1;

	return error;
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
/* Guh, fake symbol */
char *progname;

static int test_filter_escapes(void)
{
	int rc = 0;
	char *test_string;

	test_string = strdup("foo\\\\foo");
	filter_escapes(test_string);
	MY_TEST(strcmp(test_string, "foo\\foo") == 0, "simple filter for \\\\");

	test_string = strdup("foo\\foo");
	filter_escapes(test_string);
	MY_TEST(strcmp(test_string, "foofoo") == 0, "simple filter for \\f");
	return rc;
}

static int test_filter_slashes(void)
{
	int rc = 0;
	char *test_string;

	test_string = strdup("///foo//////f//oo////////////////");
	filter_slashes(test_string);
	MY_TEST(strcmp(test_string, "/foo/f/oo") == 0, "simple tests");

	test_string = strdup("/foo/f/oo");
	filter_slashes(test_string);
	MY_TEST(strcmp(test_string, "/foo/f/oo") == 0, "simple test for no changes");

	test_string = strdup("/");
	filter_slashes(test_string);
	MY_TEST(strcmp(test_string, "/") == 0, "simple test for '/'");

	test_string = strdup("");
	filter_slashes(test_string);
	MY_TEST(strcmp(test_string, "") == 0, "simple test for ''");

	test_string = strdup("//usr");
	filter_slashes(test_string);
	MY_TEST(strcmp(test_string, "//usr") == 0, "simple test for // namespace");

	test_string = strdup("//");
	filter_slashes(test_string);
	MY_TEST(strcmp(test_string, "//") == 0, "simple test 2 for // namespace");

	test_string = strdup("///usr");
	filter_slashes(test_string);
	MY_TEST(strcmp(test_string, "/usr") == 0, "simple test for ///usr");

	test_string = strdup("///");
	filter_slashes(test_string);
	MY_TEST(strcmp(test_string, "/") == 0, "simple test for ///");

	test_string = strdup("/a/");
	filter_slashes(test_string);
	MY_TEST(strcmp(test_string, "/a") == 0, "simple test for /a/");

	return rc;
}

int main(void)
{
	int rc = 0;
	int retval;

	retval = test_filter_escapes();
	if (retval != 0)
		rc = retval;

	retval = test_filter_slashes();
	if (retval != 0)
		rc = retval;

	return rc;
}
#endif /* UNIT_TEST */
