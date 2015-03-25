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

#define FEATURES_FILE "/sys/kernel/security/" MODULE_NAME "/features"

#define STRING_SIZE 8192

struct aa_features {
	unsigned int ref_count;
	char string[STRING_SIZE];
};

struct features_struct {
	char *buffer;
	int size;
	char *pos;
};

static int features_snprintf(struct features_struct *fst, const char *fmt, ...)
{
	va_list args;
	int i, remaining = fst->size - (fst->pos - fst->buffer);

	if (remaining < 0) {
		errno = EINVAL;
		PERROR(_("Invalid features buffer offset\n"));
		return -1;
	}

	va_start(args, fmt);
	i = vsnprintf(fst->pos, remaining, fmt, args);
	va_end(args);

	if (i < 0) {
		errno = EIO;
		PERROR(_("Failed to write to features buffer\n"));
		return -1;
	} else if (i >= remaining) {
		errno = ENOBUFS;
		PERROR(_("Feature buffer full."));
		return -1;
	}

	fst->pos += i;
	return 0;
}

static int features_dir_cb(DIR *dir, const char *name, struct stat *st,
			   void *data)
{
	struct features_struct *fst = (struct features_struct *) data;

	/* skip dot files and files with no name */
	if (*name == '.' || !strlen(name))
		return 0;

	if (features_snprintf(fst, "%s {", name) == -1)
		return -1;

	if (S_ISREG(st->st_mode)) {
		autoclose int file = -1;
		int len;
		int remaining = fst->size - (fst->pos - fst->buffer);

		file = openat(dirfd(dir), name, O_RDONLY);
		if (file == -1) {
			PDEBUG("Could not open '%s'", name);
			return -1;
		}
		PDEBUG("Opened features \"%s\"\n", name);
		if (st->st_size > remaining) {
			PDEBUG("Feature buffer full.");
			errno = ENOBUFS;
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

	if (features_snprintf(fst, "}\n") == -1)
		return -1;

	return 0;
}

static int handle_features_dir(const char *filename, char *buffer, int size,
			       char *pos)
{
	struct features_struct fst = { buffer, size, pos };

	if (dirat_for_each(NULL, filename, &fst, features_dir_cb)) {
		PDEBUG("Failed evaluating %s\n", filename);
		return -1;
	}

	return 0;
}

static int load_features_file(const char *name, char *buffer, size_t size)
{
	autofclose FILE *f = NULL;
	size_t end;

	f = fopen(name, "r");
	if (!f)
		return -1;

	errno = 0;
	end = fread(buffer, 1, size - 1, f);
	if (ferror(f)) {
		if (!errno)
			errno = EIO;
		return -1;
	}
	buffer[end] = 0;

	return 0;
}

/**
 * aa_features_new - create a new features based on a path
 * @features: will point to the address of an allocated and initialized
 *            aa_features object upon success
 * @path: path to a features file or directory
 *
 * Returns: 0 on success, -1 on error with errno set and *@features pointing to
 *          NULL
 */
int aa_features_new(aa_features **features, const char *path)
{
	struct stat stat_file;
	aa_features *f;
	int retval;

	*features = NULL;

	if (stat(path, &stat_file) == -1)
		return -1;

	f = (aa_features *) calloc(1, sizeof(*f));
	if (!f) {
		errno = ENOMEM;
		return -1;
	}
	aa_features_ref(f);

	retval = S_ISDIR(stat_file.st_mode) ?
		 handle_features_dir(path, f->string, STRING_SIZE, f->string) :
		 load_features_file(path, f->string, STRING_SIZE);
	if (retval) {
		int save = errno;

		aa_features_unref(f);
		errno = save;
		return -1;
	}

	*features = f;

	return 0;
}

/**
 * aa_features_new_from_string - create a new features based on a string
 * @features: will point to the address of an allocated and initialized
 *            aa_features object upon success
 * @string: a NUL-terminated string representation of features
 * @size: the size of @string, not counting the NUL-terminator
 *
 * Returns: 0 on success, -1 on error with errno set and *@features pointing to
 *          NULL
 */
int aa_features_new_from_string(aa_features **features,
				const char *string, size_t size)
{
	aa_features *f;

	*features = NULL;

	/* Require size to be less than STRING_SIZE so there's room for a NUL */
	if (size >= STRING_SIZE)
		return ENOBUFS;

	f = (aa_features *) calloc(1, sizeof(*f));
	if (!f) {
		errno = ENOMEM;
		return -1;
	}
	aa_features_ref(f);

	memcpy(f->string, string, size);
	f->string[size] = '\0';
	*features = f;

	return 0;
}

/**
 * aa_features_new_from_kernel - create a new features based on the current kernel
 * @features: will point to the address of an allocated and initialized
 *            aa_features object upon success
 *
 * Returns: 0 on success, -1 on error with errno set and *@features pointing to
 *          NULL
 */
int aa_features_new_from_kernel(aa_features **features)
{
	return aa_features_new(features, FEATURES_FILE);
}

/**
 * aa_features_ref - increments the ref count of a features
 * @features: the features
 *
 * Returns: the features
 */
aa_features *aa_features_ref(aa_features *features)
{
	atomic_inc(&features->ref_count);
	return features;
}

/**
 * aa_features_unref - decrements the ref count and frees the features when 0
 * @features: the features (can be NULL)
 */
void aa_features_unref(aa_features *features)
{
	if (features && atomic_dec_and_test(&features->ref_count))
		free(features);
}

/**
 * aa_features_get_string - provides immutable string representation of features
 * @features: the features
 *
 * Returns: an immutable string representation of features
 */
const char *aa_features_get_string(aa_features *features)
{
	return features->string;
}

/**
 * aa_features_is_equal - equality test for two features
 * @features1: the first features (can be NULL)
 * @features2: the second features (can be NULL)
 *
 * Returns: true if they're equal, false if they're not or either are NULL
 */
bool aa_features_is_equal(aa_features *features1, aa_features *features2)
{
	return features1 && features2 &&
	       strcmp(features1->string, features2->string) == 0;
}
