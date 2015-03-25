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

#include <dirent.h>
#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/types.h>
#include <unistd.h>
#include <sys/stat.h>
#include <sys/apparmor.h>

#include "private.h"

struct aa_policy_cache {
	unsigned int ref_count;
	aa_features *features;
	aa_features *kernel_features;
	char *path;
	char *features_path;
};

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
		PERROR("Can't create cache directory: %s\n",
		       policy_cache->path);
	} else if (!S_ISDIR(stat_file.st_mode)) {
		PERROR("File in cache directory location: %s\n",
		       policy_cache->path);
	} else {
		PERROR("Can't update cache directory: %s\n",
		       policy_cache->path);
	}

	return -1;
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

struct replace_all_cb_data {
	aa_policy_cache *policy_cache;
	aa_kernel_interface *kernel_interface;
};

static int replace_all_cb(DIR *dir unused, const char *name, struct stat *st,
			 void *cb_data)
{
	int retval = 0;

	if (!S_ISDIR(st->st_mode) && !_aa_is_blacklisted(name, NULL)) {
		struct replace_all_cb_data *data;
		autofree char *path = NULL;

		data = (struct replace_all_cb_data *) cb_data;
		if (asprintf(&path, "%s/%s",
			     data->policy_cache->path, name) < 0) {
			path = NULL;
			errno = ENOMEM;
			return -1;
		}
		retval = aa_kernel_interface_replace_policy_from_file(data->kernel_interface,
								      path);
	}

	return retval;
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

	pc = calloc(1, sizeof(*pc));
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
	return _aa_dirat_for_each(NULL, path, NULL, clear_cache_cb);
}

/**
 * aa_policy_cache_replace_all - performs a kernel policy replacement of all cached policies
 * @policy_cache: the policy_cache
 * @kernel_interface: the kernel interface to use when doing the replacement
 *
 * Returns: 0 on success, -1 on error with errno set and features pointing to
 *          NULL
 */
int aa_policy_cache_replace_all(aa_policy_cache *policy_cache,
				aa_kernel_interface *kernel_interface)
{
	struct replace_all_cb_data cb_data;
	int retval;

	if (kernel_interface) {
		aa_kernel_interface_ref(kernel_interface);
	} else if (aa_kernel_interface_new(&kernel_interface,
					   policy_cache->kernel_features,
					   NULL) == -1) {
		kernel_interface = NULL;
		return -1;
	}

	cb_data.policy_cache = policy_cache;
	cb_data.kernel_interface = kernel_interface;
	retval = _aa_dirat_for_each(NULL, policy_cache->path, &cb_data,
				    replace_all_cb);

	aa_kernel_interface_unref(kernel_interface);

	return retval;
}
