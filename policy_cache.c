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
	FILE *f;
	if (!(f = fopen(cachename, "r"))) {
		PERROR(_("Error: Could not read cache file '%s', skipping...\n"), cachename);
		return false;
	}
	size_t res = fread(buffer, 1, 16, f);
	fclose(f);
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
	FILE * f = NULL;

	if (clear_cache_files(cachedir) != 0)
		goto error;

create_file:
	f = fopen(path, "w");
	if (f) {
		if (fwrite(features, strlen(features), 1, f) != 1 )
			goto error;

		fclose(f);


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
