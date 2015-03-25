/*
 *   Copyright (c) 2014
 *   Canonical, Ltd. (All rights reserved)
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

#include <errno.h>
#include <fcntl.h>
#include <stdio.h>
#include <string.h>
#include <stdarg.h>
#include <stdlib.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <unistd.h>
#include <libintl.h>
#include <locale.h>
#define _(s) gettext(s)

#include "features.h"
#include "lib.h"
#include "parser.h"

#define FEATURES_STRING_SIZE 8192
char *features_string = NULL;

static char *snprintf_buffer(char *buf, char *pos, ssize_t size,
			     const char *fmt, ...)
{
	va_list args;
	int i, remaining = size - (pos - buf);

	va_start(args, fmt);
	i = vsnprintf(pos, remaining, fmt, args);
	va_end(args);

	if (i >= size) {
		PERROR(_("Feature buffer full."));
		exit(1);
	}

	return pos + i;
}

struct features_struct {
	char **buffer;
	int size;
	char *pos;
};

static int features_dir_cb(DIR *dir, const char *name, struct stat *st,
			   void *data)
{
	struct features_struct *fst = (struct features_struct *) data;

	/* skip dot files and files with no name */
	if (*name == '.' || !strlen(name))
		return 0;

	fst->pos = snprintf_buffer(*fst->buffer, fst->pos, fst->size, "%s {", name);

	if (S_ISREG(st->st_mode)) {
		autoclose int file = -1;
		int len;
		int remaining = fst->size - (fst->pos - *fst->buffer);

		file = openat(dirfd(dir), name, O_RDONLY);
		if (file == -1) {
			PDEBUG("Could not open '%s'", name);
			return -1;
		}
		PDEBUG("Opened features \"%s\"\n", name);
		if (st->st_size > remaining) {
			PDEBUG("Feature buffer full.");
			return -1;
		}

		do {
			len = read(file, fst->pos, remaining);
			if (len > 0) {
				remaining -= len;
				fst->pos += len;
				*fst->pos = 0;
			}
		} while (len > 0);
		if (len < 0) {
			PDEBUG("Error reading feature file '%s'\n", name);
			return -1;
		}
	} else if (S_ISDIR(st->st_mode)) {
		if (dirat_for_each(dir, name, fst, features_dir_cb))
			return -1;
	}

	fst->pos = snprintf_buffer(*fst->buffer, fst->pos, fst->size, "}\n");

	return 0;
}

static char *handle_features_dir(const char *filename, char **buffer, int size,
				 char *pos)
{
	struct features_struct fst = { buffer, size, pos };

	if (dirat_for_each(NULL, filename, &fst, features_dir_cb)) {
		PDEBUG("Failed evaluating %s\n", filename);
		exit(1);
	}

	return fst.pos;
}

char *load_features_file(const char *name) {
	char *buffer;
	autofclose FILE *f = NULL;
	size_t size;

	f = fopen(name, "r");
	if (!f)
		return NULL;

	buffer = (char *) malloc(FEATURES_STRING_SIZE);
	if (!buffer)
		goto fail;

	size = fread(buffer, 1, FEATURES_STRING_SIZE - 1, f);
	if (!size || ferror(f))
		goto fail;
	buffer[size] = 0;

	return buffer;

fail:
	int save = errno;
	free(buffer);
	errno = save;
	return NULL;
}

int load_features(const char *name)
{
	struct stat stat_file;

	if (stat(name, &stat_file) == -1)
		return -1;

	if (S_ISDIR(stat_file.st_mode)) {
		/* if we have a features directory default to */
		features_string = (char *) malloc(FEATURES_STRING_SIZE);
		handle_features_dir(name, &features_string, FEATURES_STRING_SIZE, features_string);
	} else {
		features_string = load_features_file(name);
		if (!features_string)
			return -1;
	}

	return 0;
}
