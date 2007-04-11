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

/* Handle subdomain includes, as a straight forward preprocessing phase.
   While we are at it we will strip comments.  Why? because it made it
   easier.

   We support 2 types of includes

#include <name> which searches for the first occurance of name in the
   subdomain directory path.

#include "name" which will search for a relative or absolute pathed
   file

-p : preprocess only.  Dump output to stdout
-I path : add a path to be search by #include < >
-b path : set the base path to something other than /etc/subdomain.d

*/

#define _GNU_SOURCE	/* for strndup() */

#include <assert.h>
#include <ctype.h>
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <unistd.h>
#include <errno.h>
#include <libintl.h>
#include <dirent.h>
#include "parser.h"
#include "parser_include.h"
#define _(s) gettext(s)

/* An array of search directories, I sure hope 100's enough */
#define MAX_PATH 100

/* maximum depth of nesting */
#define MAX_NEST_LEVEL 100

/* Location of the subdomain.conf file */
#ifdef SUBDOMAIN_CONFDIR
#define SUBDOMAIN_CONF SUBDOMAIN_CONFDIR "/subdomain.conf"
#else	/* !defined SUBDOMAIN_CONFDIR */
#define SUBDOMAIN_CONF "/etc/subdomain.conf"
#endif	/* SUBDOMAIN_CONFDIR */

static char *path[MAX_PATH] = { NULL };
static int npath = 0;

static int fgetline(FILE * f, char *buffer, size_t len);
static int getincludestr(char **inc, int c, FILE *f, int line, char *name,
			 FILE *out);
static int stripcomment(char *s);
static char *stripblanks(char *s);
static int preprocess(FILE *f, char *name, FILE * out, int nest);

int preprocess_only;

/* default base directory is /etc/subdomain.d, it can be overriden
   with the -b option. */

static char *basedir;
static char *default_basedir = "/etc/apparmor.d";
static char *old_basedir = "/etc/subdomain.d";

/* start parsing.  */
int do_include_preprocessing(char *profilename)
{
	int retval = 0;
	FILE *tmp, *profile = NULL;

	if (profilename) {
		profile = fopen(profilename, "r");
		if (!profile) {
			PERROR(_("Error: Could not read profile %s: %s.\n"),
			       profilename, strerror(errno));
			exit(errno);
		}
	} else {
		profile = stdin;
	}

	/* Change to the base dir */
	chdir(basedir);

	if (preprocess_only) {
		retval = preprocess(profile, profilename ? profilename : "stdin",
				    stdout, 0);
		goto out;
	}

	tmp = tmpfile();
	if (!tmp) {
		PERROR(_("Error: Could not allocate temporary file.\n"));
		exit(10);
	}

	retval = preprocess(profile, profilename ? profilename : "stdin",
			    tmp, 0);

	rewind(tmp);

	dup2(fileno(tmp), 0);	/* stdin */
	fclose(tmp);

out:
	if (profilename)
		fclose(profile);

	return retval;
}

/* set up basedir so that it can be overridden/used later. */
void init_base_dir(void)
{
	int rc;
	struct stat sbuf;

	/* basedir should always start out NULL; if not, something's
	 * wrong.*/
	assert(basedir == NULL);

	rc = stat(default_basedir, &sbuf);
	if (rc == 0 && S_ISDIR(sbuf.st_mode)) {
		basedir = default_basedir;
		return;
	}

	rc = stat(old_basedir, &sbuf);
	if (rc == 0 && S_ISDIR(sbuf.st_mode)) {
		basedir = old_basedir;
		return;
	}
}

/* Set the base dir.  Used to change default path for relative includes */
void set_base_dir(char *dir)
{
	char *t;
	int i, rc;
	struct stat sbuf;

	t = strndup(dir, PATH_MAX);
	if (!t) {
		PERROR(_("Error: Out of memory.\n"));
		return;
	}

	/*strip trailing /'s */
	for (i = strlen(t) - 1; i >= 0 && t[i] == '/'; i--)
		t[i] = 0;

	rc = stat(t, &sbuf);
	if (rc == -1 || !S_ISDIR(sbuf.st_mode)) {
		PERROR(_("Error: basedir %s is not a directory, skipping.\n"), t);
		free(t);
		return;
	}

	basedir = t;
	return;
}

/* Add a directory to the search path. */
int add_search_dir(char *dir)
{
	char *t;
	if (npath >= MAX_PATH) {
		PERROR(_("Error: Could not add directory %s to search path.\n"),
		       dir);
		return 0;
	}

	if (!dir || strlen(dir) <= 0)
		return 1;

	t = malloc(strlen(dir) + 1);
	if (t == NULL) {
		PERROR(_("Error: Could not allocate memory.\n"));
		return 0;
	}
	strcpy(t, dir);
	/*strip trailing /'s */
	while (t[strlen(t) - 1] == '/')
		t[strlen(t) - 1] = 0;
	path[npath] = t;
	npath++;

	return 1;
}

/* Parse Subdomain.conf and put the default dirs in place.  

   subdomain.conf is a shell sourcable file
   we only parse entries starting with
   SUBDOMAIN_PATH=

   if there are multiple entries with SUBDOMAIN_PATH=
   each will get added.

   SUBDOMAIN_PATH=/etc/subdomain.d:/etc/subdomain.d/include
   is the same as
   SUBDOMAIN_PATH=/etc/subdomain.d
   SUBDOMAIN_PATH=/etc/subdomain.d/include */
void parse_default_paths(void)
{
	FILE *f;
	char buf[1024];
	char *t, *s;
	int saved_npath = npath;

	f = fopen(SUBDOMAIN_CONF, "r");
	if (f == NULL)
		goto out;

	memset(buf, 0, sizeof(buf));

	while (fgetline(f, buf, 1024)) {
		if (stripcomment(buf) && (t = strstr(buf, "SUBDOMAIN_PATH="))) {
			t += 15;
			/* handle : seperating path elements */
			do {
				s = strchr(t, ':');
				if (s)
					*s = 0;
				if (!add_search_dir(stripblanks(t)))
					break;
				if (s)
					t = s + 1;
			} while (s != NULL);
		}
	}
	fclose(f);

	/* if subdomain.conf doesn't set a base search dir set it to this */
out:
	if (npath - saved_npath == 0) {
		add_search_dir(basedir);
	}
}

const char incword[] = "include";

/* getincludestr:
 * returns !0 if error occurred
 * include string (or not) is returned in 'inc'
 */
static int getincludestr(char **inc, int c, FILE *f, int line, char *name,
			 FILE *out)
{
	char *b;
	size_t i = 0, a;
	int d;
	int retval = 0;

	*inc = NULL;

	if (c != '#')
		return retval;

	/* we either have a comment or an include, either process the include
	   or strip the comment to the eol.  Leave the eol char so line count
	   gets properly incremented. */

	for (i = 0; i < strlen(incword); i++) {
		c = fgetc(f);
		if (c == EOF || c == '\n' || c != incword[i]) {
			ungetc(c, f);
			goto comment;
		}
	}

	/* found "#include" now search for the file name to include */
	b = malloc(2048);
	if (!b) {
		PERROR(_("Error: Could not allocate buffer for include at line %d in %s.\n"),
		       line, name);
		retval = 1;
		goto comment;
	}

	c = fgetc(f);
	if (!isspace(c)) {
		ungetc(c, f);
		goto comment;
	}

	while ((c = fgetc(f)) != EOF && c != '\n' && isspace(c))
		/* eat whitespace */ ;
	if (c != '\"' && c != '<') {
		free(b);
		PERROR(_("Error: Bad include at line %d in %s.\n"), line, name);
		if (c == '\n')
			ungetc(c, f);
		retval = 1;
		goto comment;
	}

	b[0] = c;
	i = 1;
	while ((d = fgetc(f)) != EOF && d != '\n'
	       && d != (c == '<' ? '>' : '\"') && i < 2048)
		b[i++] = d;

	if (d == (c == '<' ? '>' : '\"')) {
		b[i] = 0;
		*inc = b;
		return retval;
	}

	free(b);
	PERROR(_("Error: Bad include at line %d in %s.\n"), line, name);
	ungetc(d, f);
	retval = 1;
	/* fall through to comment - this makes trailing stuff a comment */

comment:
	fputc('#', out);
	for (a = 0; a < i; a++) {
		fputc(incword[a], out);
	}
	while ((c = fgetc(f)) != EOF && c != '\n')
		fputc(c, out);
	if (c == '\n')
		ungetc(c, f);

	return retval;
}

/* Find the include file or directory by searching the path. */
static int process_include(char *inc, char *name, int line, FILE *out, int nest)
{
	FILE *newf = NULL;
	int retval = 0;
	char *buf;
	struct stat my_stat;
	int err;

	if (*inc == '\"') {
		buf = strdup(inc + 1);
		newf = fopen(buf, "r");
	} else {
		int i;
		for (i = 0; i < npath; i++) {
			asprintf(&buf, "%s/%s", path[i], inc + 1);
			newf = fopen(buf, "r");
			if (newf)
				break;
		}
	}

	if (!newf) {
		PERROR(_("Error: #include %s%c not found at line %d in %s.\n"),
		       inc,
		       *inc == '<' ? '>' : '\"',
		       line,
		       name);
		retval = 1;
		goto out;
	}

	err = fstat(fileno(newf), &my_stat);
	if (err) {
		retval = errno;
		goto out;
	}

	if (S_ISREG(my_stat.st_mode)) {
		err = preprocess(newf, inc + 1, out, nest + 1);
		if (err)
			retval = err;
		goto out;
	}

	if (S_ISDIR(my_stat.st_mode)) {
		DIR *dir = NULL;
		struct dirent *dirent;

		/* XXX - fdopendir not available in glibc < 2.4 */
		/* dir = fdopendir(fileno(newf)); */
		fclose(newf);
		dir = opendir(buf);
		if (!dir) {
			retval = 1;
			goto out;
		}

		while ((dirent = readdir(dir)) != NULL) {
			char *dirbuf;
			/* skip dotfiles. */
			if (dirent->d_name[0] == '.')
				continue;
			asprintf(&dirbuf, "%s/%s", buf, dirent->d_name);
			err = stat(dirbuf, &my_stat);
			if (err) {
				retval = errno;
				free(dirbuf);
				goto out;
			}

			if (S_ISREG(my_stat.st_mode)) {
				newf = fopen(dirbuf, "r");
				if (newf) {
					err = preprocess(newf, inc + 1, out, nest + 1);
					if (err)
						retval = err;
					fclose(newf);
				} else {
					retval = errno;
				}
			}
			free(dirbuf);
		}
		newf = NULL;
		closedir(dir);
	}
out:
	if (buf)
		free(buf);
	if (newf)
		fclose(newf);
	return retval;
}

static int preprocess(FILE * f, char *name, FILE * out, int nest)
{
	int line = 1;
	int c;
	int retval = 0;
	char *inc = NULL;
	char *cwd;

	if (nest > MAX_NEST_LEVEL) {
		PERROR(_("Error: Exceeded %d levels of includes.  Not processing %s include.\n"),
		       MAX_NEST_LEVEL, name);
		return 1;
	}

	if (nest == 0) {
		fprintf(out, "\n#source %s\n", name);
	} else {
		fprintf(out, "\n#included %s\n", name);
	}

	while ((c = fgetc(f)) != EOF) {
		int err = getincludestr(&inc, c, f, line, name, out);
		if (err)
			retval = err;
		if (inc) {
			cwd = get_current_dir_name();
			err = process_include(inc, name, line, out, nest);
			if (err)
				retval = err;
			chdir(cwd);
			free(cwd);
			free(inc);
		} else {
			if (c != '#')
				fputc(c, out);
			if (c == '\n')
				line++;
		}
	}
	return retval;
}

/* get a line from the file.  If it is to long truncate it. */
static int fgetline(FILE * f, char *buffer, size_t len)
{
	char *b = buffer;
	int c;

	while (((c = fgetc(f)) != EOF) && (c != '\n')
	       && (strlen(buffer) < len - 1)) {
		*b = c;
		b++;
	}
	*b = '\0';
	if (c != EOF)
		return 1;
	return 0;
}

/* If there is a comment null terminate the string,
   return strlen of the stripped string*/
static int stripcomment(char *s)
{
	char *t = s;
	while (*s != '#' && *s != 0)
		s++;
	*s = 0;

	return strlen(t);
}

static char *stripblanks(char *s)
{
	char *c;

	while (isspace(*s))
		s++;
	c = s;
	while (!isspace(*s) && *s != 0)
		s++;
	*s = 0;
	return c;
}
