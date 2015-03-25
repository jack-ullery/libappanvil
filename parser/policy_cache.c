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

#include <ctype.h>
#include <dirent.h>
#include <libintl.h>
#include <locale.h>
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <stdarg.h>
#include <sys/types.h>
#include <unistd.h>
#include <sys/stat.h>
#define _(s) gettext(s)

#include "lib.h"
#include "parser.h"
#include "policy_cache.h"

#define le16_to_cpu(x) ((uint16_t)(le16toh (*(uint16_t *) x)))

const char header_string[] = "\004\010\000version\000\002";
#define HEADER_STRING_SIZE 12
bool valid_cached_file_version(const char *cachename)
{
	char buffer[16];
	autofclose FILE *f;
	if (!(f = fopen(cachename, "r"))) {
		PERROR(_("Error: Could not read cache file '%s', skipping...\n"), cachename);
		return false;
	}
	size_t res = fread(buffer, 1, 16, f);
	if (res < 16) {
		if (debug_cache)
			pwarn("%s: cache file '%s' invalid size\n", progname, cachename);
		return false;
	}

	/* 12 byte header that is always the same and then 4 byte version # */
	if (memcmp(buffer, header_string, HEADER_STRING_SIZE) != 0) {
		if (debug_cache)
			pwarn("%s: cache file '%s' has wrong header\n", progname, cachename);
		return false;
	}

	uint32_t version = cpu_to_le32(ENCODE_VERSION(force_complain,
						      policy_version,
						      parser_abi_version,
						      kernel_abi_version));
	if (memcmp(buffer + 12, &version, 4) != 0) {
		if (debug_cache)
			pwarn("%s: cache file '%s' has wrong version\n", progname, cachename);
		return false;
	}

	return true;
}


void set_mru_tstamp(struct timespec t)
{
	mru_skip_cache = 0;
	mru_tstamp = t;
}

void update_mru_tstamp(FILE *file, const char *name)
{
	struct stat stat_file;
	if (fstat(fileno(file), &stat_file) || (mru_tstamp.tv_sec == 0 && mru_tstamp.tv_nsec == 0))
		return;
	if (mru_t_cmp(stat_file.st_mtim)) {
		if (debug_cache)
			pwarn("%s: file '%s' is newer than cache file\n", progname, name);
		mru_skip_cache = 1;
       }
}

static int clear_cache_cb(DIR *dir, const char *path, struct stat *st,
			  void *data unused)
{
	/* remove regular files */
	if (S_ISREG(st->st_mode))
		return unlinkat(dirfd(dir), path, 0);

	/* do nothing with other file types */
	return 0;
}

int clear_cache_files(const char *path)
{
	return dirat_for_each(NULL, path, NULL, clear_cache_cb);
}

int create_cache(const char *cachedir, const char *path, const char *features)
{
	struct stat stat_file;
	autofclose FILE * f = NULL;

	if (clear_cache_files(cachedir) != 0)
		goto error;

create_file:
	f = fopen(path, "w");
	if (f) {
		if (fwrite(features, strlen(features), 1, f) != 1 )
			goto error;

		return 0;
	}

error:
	/* does the dir exist? */
	if (stat(cachedir, &stat_file) == -1 && create_cache_dir) {
		if (mkdir(cachedir, 0700) == 0)
			goto create_file;
		if (show_cache)
			PERROR(_("Can't create cache directory: %s\n"), cachedir);
	} else if (!S_ISDIR(stat_file.st_mode)) {
		if (show_cache)
			PERROR(_("File in cache directory location: %s\n"), cachedir);
	} else {
		if (show_cache)
			PERROR(_("Can't update cache directory: %s\n"), cachedir);
	}

	if (show_cache)
		PERROR("Cache write disabled: cannot create %s\n", path);
	write_cache = 0;

	return -1;
}

char *cache_filename(const char *cachedir, const char *basename)
{
	char *cachename;

	if (asprintf(&cachename, "%s/%s", cachedir, basename) < 0) {
		PERROR(_("Memory allocation error."));
		exit(1);
	}

	return cachename;
}

void valid_read_cache(const char *cachename)
{
	struct stat stat_bin;

	/* Load a binary cache if it exists and is newest */
	if (!skip_read_cache) {
		if (stat(cachename, &stat_bin) == 0 &&
		    stat_bin.st_size > 0) {
			if (valid_cached_file_version(cachename))
				set_mru_tstamp(stat_bin.st_ctim);
			else if (!cond_clear_cache)
				write_cache = 0;
		} else {
			if (!cond_clear_cache)
				write_cache = 0;
			if (debug_cache)
				pwarn("%s: Invalid or missing cache file '%s' (%s)\n", progname, cachename, strerror(errno));
		}
	}
}

int cache_hit(const char *cachename)
{
	if (!mru_skip_cache) {
		if (show_cache)
			PERROR("Cache hit: %s\n", cachename);
		return true;
	}

	return false;
}

int setup_cache_tmp(const char **cachetmpname, const char *cachename)
{
	char *tmpname;
	int cache_fd = -1;

	*cachetmpname = NULL;
	if (write_cache) {
		/* Otherwise, set up to save a cached copy */
		if (asprintf(&tmpname, "%s-XXXXXX", cachename)<0) {
			perror("asprintf");
			exit(1);
		}
		if ((cache_fd = mkstemp(tmpname)) < 0) {
			perror("mkstemp");
			exit(1);
		}
		*cachetmpname = tmpname;
	}

	return cache_fd;
}

void install_cache(const char *cachetmpname, const char *cachename)
{
	/* Only install the generate cache file if it parsed correctly
	   and did not have write/close errors */
	if (cachetmpname) {
		if (rename(cachetmpname, cachename) < 0) {
			pwarn("Warning failed to write cache: %s\n", cachename);
			unlink(cachetmpname);
		}
		else if (show_cache) {
			PERROR("Wrote cache: %s\n", cachename);
		}
	}
}

int setup_cache(aa_features *kernel_features, const char *cacheloc)
{
	autofree char *cache_features_path = NULL;
	aa_features *cache_features;
	const char *kernel_features_string;

	if (!cacheloc) {
		errno = EINVAL;
		return -1;
	}

	/*
         * Deal with cache directory versioning:
         *  - If cache/.features is missing, create it if --write-cache.
         *  - If cache/.features exists, and does not match features_string,
         *    force cache reading/writing off.
         */
	if (asprintf(&cache_features_path, "%s/.features", cacheloc) == -1) {
		PERROR(_("Memory allocation error."));
		errno = ENOMEM;
		return -1;
	}

	kernel_features_string = aa_features_get_string(kernel_features);
	if (!aa_features_new(&cache_features, cache_features_path)) {
		const char *cache_features_string;

		cache_features_string = aa_features_get_string(cache_features);
		if (strcmp(kernel_features_string, cache_features_string) != 0) {
			if (write_cache && cond_clear_cache) {
				if (create_cache(cacheloc, cache_features_path,
						 kernel_features_string))
					skip_read_cache = 1;
			} else {
				if (show_cache)
					PERROR("Cache read/write disabled: Police cache is invalid\n");
				write_cache = 0;
				skip_read_cache = 1;
			}
		}
		aa_features_unref(cache_features);
	} else if (write_cache) {
		create_cache(cacheloc, cache_features_path,
			     kernel_features_string);
	}

	return 0;
}
