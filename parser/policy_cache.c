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

struct aa_policy_cache {
	unsigned int ref_count;
	aa_features *features;
	aa_features *kernel_features;
	char *path;
	char *features_path;
};

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

static int create_cache(aa_policy_cache *policy_cache, aa_features *features)
{
	struct stat stat_file;
	autofclose FILE * f = NULL;

	if (aa_policy_cache_remove(policy_cache->path))
		goto error;

create_file:
	if (aa_features_write_to_file(features,
				      policy_cache->features_path) == -1)
		goto error;

	aa_features_unref(policy_cache->features);
	policy_cache->features = aa_features_ref(features);
	return 0;

error:
	/* does the dir exist? */
	if (stat(policy_cache->path, &stat_file) == -1) {
		if (mkdir(policy_cache->path, 0700) == 0)
			goto create_file;
		if (show_cache)
			PERROR(_("Can't create cache directory: %s\n"),
			       policy_cache->path);
	} else if (!S_ISDIR(stat_file.st_mode)) {
		if (show_cache)
			PERROR(_("File in cache directory location: %s\n"),
			       policy_cache->path);
	} else {
		if (show_cache)
			PERROR(_("Can't update cache directory: %s\n"),
			       policy_cache->path);
	}

	if (show_cache)
		PERROR("Cache write disabled: cannot create %s\n",
		       policy_cache->features_path);
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

static int init_cache_features(aa_policy_cache *policy_cache,
			       aa_features *kernel_features, bool create)
{
	if (aa_features_new(&policy_cache->features,
			    policy_cache->features_path)) {
		policy_cache->features = NULL;
		if (!create || errno != ENOENT)
			return -1;

		return create_cache(policy_cache, kernel_features);
	}

	return 0;
}

/**
 * aa_policy_cache_new - create a new policy_cache from a path
 * @policy_cache: will point to the address of an allocated and initialized
 *                aa_policy_cache_new object upon success
 * @kernel_features: features representing the currently running kernel
 * @path: path to the policy cache
 * @create: true if the cache should be created if it doesn't already exist
 *
 * Returns: 0 on success, -1 on error with errno set and *@policy_cache
 *          pointing to NULL
 */
int aa_policy_cache_new(aa_policy_cache **policy_cache,
			aa_features *kernel_features, const char *path,
			bool create)
{
	aa_policy_cache *pc;

	*policy_cache = NULL;

	if (!path) {
		errno = EINVAL;
		return -1;
	}

	pc = (aa_policy_cache *) calloc(1, sizeof(*pc));
	if (!pc) {
		errno = ENOMEM;
		return -1;
	}
	aa_policy_cache_ref(pc);

	pc->path = strdup(path);
	if (!pc->path) {
		aa_policy_cache_unref(pc);
		errno = ENOMEM;
		return -1;
	}

	if (asprintf(&pc->features_path, "%s/.features", pc->path) == -1) {
		pc->features_path = NULL;
		aa_policy_cache_unref(pc);
		errno = ENOMEM;
		return -1;
	}

	if (init_cache_features(pc, kernel_features, create)) {
		int save = errno;

		aa_policy_cache_unref(pc);
		errno = save;
		return -1;
	}

	pc->kernel_features = aa_features_ref(kernel_features);
	*policy_cache = pc;

	return 0;
}

/**
 * aa_policy_cache_ref - increments the ref count of a policy_cache
 * @policy_cache: the policy_cache
 *
 * Returns: the policy_cache
 */
aa_policy_cache *aa_policy_cache_ref(aa_policy_cache *policy_cache)
{
	atomic_inc(&policy_cache->ref_count);
	return policy_cache;
}

/**
 * aa_policy_cache_unref - decrements the ref count and frees the policy_cache when 0
 * @policy_cache: the policy_cache (can be NULL)
 */
void aa_policy_cache_unref(aa_policy_cache *policy_cache)
{
	if (policy_cache && atomic_dec_and_test(&policy_cache->ref_count)) {
		free(policy_cache->features_path);
		free(policy_cache->path);
		free(policy_cache);
	}
}

/**
 * aa_policy_cache_is_valid - checks if the policy_cache is valid for the currently running kernel
 * @policy_cache: the policy_cache
 *
 * Returns: true if the policy_cache is valid for the currently running kernel,
 *          false if not
 */
bool aa_policy_cache_is_valid(aa_policy_cache *policy_cache)
{
	return aa_features_is_equal(policy_cache->features,
				    policy_cache->kernel_features);
}

/**
 * aa_policy_cache_create - creates a valid policy_cache for the currently running kernel
 * @policy_cache: the policy_cache
 *
 * Returns: 0 on success, -1 on error with errno set and features pointing to
 *          NULL
 */
int aa_policy_cache_create(aa_policy_cache *policy_cache)
{
	return create_cache(policy_cache, policy_cache->kernel_features);
}

/**
 * aa_policy_cache_remove - removes all policy cache files under a path
 * @path: the path to a policy cache directory
 *
 * Returns: 0 on success, -1 on error with errno set
 */
int aa_policy_cache_remove(const char *path)
{
	return dirat_for_each(NULL, path, NULL, clear_cache_cb);
}
