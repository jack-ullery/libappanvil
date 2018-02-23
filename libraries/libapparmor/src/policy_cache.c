/*
 *   Copyright (c) 2014-2017
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
#include <fcntl.h>
#include <fnmatch.h>
#include <limits.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/types.h>
#include <unistd.h>
#include <sys/stat.h>
#include <sys/apparmor.h>

#include "private.h"

#define CACHE_FEATURES_FILE	".features"

struct aa_policy_cache {
	unsigned int ref_count;
	aa_features *features;
	aa_features *kernel_features;
	int dirfd;
};

static int clear_cache_cb(int dirfd, const char *path, struct stat *st,
			  void *data unused)
{
	if (S_ISREG(st->st_mode)) {
		/* remove regular files */
		return unlinkat(dirfd, path, 0);
	} else if (S_ISDIR(st->st_mode)) {
		int retval;

		retval = _aa_dirat_for_each(dirfd, path, NULL, clear_cache_cb);
		if (retval)
			return retval;

		return unlinkat(dirfd, path, AT_REMOVEDIR);
	}

	/* do nothing with other file types */
	return 0;
}

static int create_cache(aa_policy_cache *policy_cache, aa_features *features)
{
	if (aa_policy_cache_remove(policy_cache->dirfd, "."))
		return -1;

	if (aa_features_write_to_file(features, policy_cache->dirfd,
				      CACHE_FEATURES_FILE) == -1)
		return -1;

	aa_features_unref(policy_cache->features);
	policy_cache->features = aa_features_ref(features);
	return 0;
}

static int init_cache_features(aa_policy_cache *policy_cache,
			       aa_features *kernel_features, bool create)
{
	bool call_create_cache = false;

	if (aa_features_new(&policy_cache->features, policy_cache->dirfd,
			    CACHE_FEATURES_FILE)) {
		policy_cache->features = NULL;
		if (!create || errno != ENOENT)
			return -1;

		/* The cache directory needs to be created */
		call_create_cache = true;
	} else if (!aa_features_is_equal(policy_cache->features,
					 kernel_features)) {
		if (!create) {
			errno = EEXIST;
			return -1;
		}

		/* The cache directory needs to be refreshed */
		call_create_cache = true;
	}

	return call_create_cache ?
		create_cache(policy_cache, kernel_features) : 0;
}

struct replace_all_cb_data {
	aa_policy_cache *policy_cache;
	aa_kernel_interface *kernel_interface;
};

static int replace_all_cb(int dirfd unused, const char *name, struct stat *st,
			 void *cb_data)
{
	int retval = 0;

	if (!S_ISDIR(st->st_mode) && !_aa_is_blacklisted(name)) {
		struct replace_all_cb_data *data;

		data = (struct replace_all_cb_data *) cb_data;
		retval = aa_kernel_interface_replace_policy_from_file(data->kernel_interface,
								      data->policy_cache->dirfd,
								      name);
	}

	return retval;
}

static char *path_from_fd(int fd)
{
	autofree char *proc_path = NULL;
	autoclose int proc_fd = -1;
	struct stat proc_stat;
	char *path;
	ssize_t path_len;

	if (asprintf(&proc_path, "/proc/self/fd/%d", fd) == -1) {
		proc_path = NULL;
		errno = ENOMEM;
		return NULL;
	}

	proc_fd = open(proc_path, O_RDONLY | O_CLOEXEC | O_PATH | O_NOFOLLOW);
	if (proc_fd == -1)
		return NULL;

	if (fstat(proc_fd, &proc_stat) == -1)
		return NULL;

	if (!S_ISLNK(proc_stat.st_mode)) {
		errno = EINVAL;
		return NULL;
	}

	path = malloc(proc_stat.st_size + 1);
	if (!path)
		return NULL;

	/**
	 * Since 2.6.39, symlink file descriptors opened with
	 * (O_PATH | O_NOFOLLOW) can be used as the dirfd with an empty string
	 * as the path. readlinkat() will operate on the symlink inode.
	 */
	path_len = readlinkat(proc_fd, "", path, proc_stat.st_size);
	if (path_len == -1)
		return NULL;

	path[path_len] = '\0';
	return path;
}

static int cache_check_features(int dirfd, const char *cache_name,
				aa_features *features)
{
	autofree aa_features *local_features = NULL; /* ingore ref count */
	autofree char *name = NULL;
	int len;

	len = asprintf(&name, "%s/%s", cache_name, CACHE_FEATURES_FILE);
	if (len == -1) {
		errno = ENOMEM;
		return -1;
	}

	/* verify that cache dir .features matches */
	if (aa_features_new(&local_features, dirfd, name)) {
		PDEBUG("could not setup new features object for dirfd '%d' '%s'\n", dirfd, name);
		return -1;
	}

	if (!aa_features_is_equal(local_features, features)) {
		errno = EEXIST;
		return -1;
	}
	return 0;
}

struct miss_cb_data {
	aa_features *features;
	const char *path;
	char *pattern;
	char *cache_name;	/* return */
	long n;
};

/* called on cache collision or miss where cache isn't present */
static int cache_miss_cb(int dirfd, const struct dirent *ent, void *arg)
{
	struct miss_cb_data *data = arg;
	char *cache_name, *pos, *tmp;
	long n;
	int len;

	/* TODO: update to tighter pattern match of just trailing #s */
	if (fnmatch(data->pattern, ent->d_name, 0))
		return 0;

	/* entry matches <feature_id>.<n> pattern */
	len = asprintf(&cache_name, "%s/%s", data->path, ent->d_name);
	if (len == -1) {
		errno = ENOMEM;
		return -1;
	}
	if (!cache_check_features(dirfd, cache_name, data->features) || errno == ENOENT) {
		/* found cache dir matching pattern */
		data->cache_name = cache_name;
		/* return 1 to stop iteration and signal dir found */
		return 1;
	}  else if (errno != EEXIST) {
		PDEBUG("cache_check_features() failed for dirfd '%d' '%s'\n", dirfd, cache_name);
		free(cache_name);
		return -1;
	}
	free(cache_name);

	/* check the cache dir # */
	pos = strchr(ent->d_name, '.');
	n = strtol(pos+1, &tmp, 10);
	if (n == LONG_MIN || n == LONG_MAX || tmp == pos + 1)
		return -1;
	if (n > data->n)
		data->n = n;

	/* continue processing */
	return 0;
}

/* will return cache_path on error if there is a collision */
static int cache_dir_from_path_and_features(char **cache_path,
					    int dirfd, const char *path,
					    aa_features *features)
{
	autofree const char *features_id = NULL;
	char *cache_dir;
	size_t len;
	int rc;

	features_id = aa_features_id(features);
	if (!features_id)
		return -1;

	len = asprintf(&cache_dir, "%s/%s.0", path, features_id);
	if (len == -1)
		return -1;

	if (!cache_check_features(dirfd, cache_dir, features) || errno == ENOENT) {
		PDEBUG("cache_dir_from_path_and_features() found '%s'\n", cache_dir);
		*cache_path = cache_dir;
		return 0;
	} else if (errno != EEXIST) {
		PDEBUG("cache_check_features() failed for dirfd '%d' %s\n", dirfd, cache_dir);
		free(cache_dir);
		return -1;
	}

	PDEBUG("Cache collision '%s' falling back to next dir on fd '%d' path %s", cache_dir, dirfd, path);
	free(cache_dir);

	struct miss_cb_data data = {
		.features = features,
		.path = path,
		.cache_name = NULL,
		.n = -1,
	};

	if (asprintf(&data.pattern, "%s.*", features_id) == -1)
		return -1;

	rc = _aa_dirat_for_each2(dirfd, path, &data, cache_miss_cb);
	free(data.pattern);
	if (rc == 1) {
		/* found matching feature dir */
		PDEBUG("cache_dir_from_path_and_features() callback found '%s'\n", data.cache_name);
		*cache_path = data.cache_name;
		return 0;
	} else if (rc)
		return -1;
	/* no dir found use 1 higher than highest dir n searched */
	len = asprintf(&cache_dir, "%s/%s.%d", path, features_id, data.n + 1);
	if (len == -1)
		return -1;

	PDEBUG("Cache collision no dir found using %d + 1 = %s\n", data.n + 1, cache_dir);
	*cache_path = cache_dir;
	return 0;
}

/**
 * aa_policy_cache_new - create a new aa_policy_cache object from a path
 * @policy_cache: will point to the address of an allocated and initialized
 *                aa_policy_cache_new object upon success
 * @kernel_features: features representing a kernel (may be NULL if you want to
 *                   use the features of the currently running kernel)
 * @dirfd: directory file descriptor or AT_FDCWD (see openat(2))
 * @path: path to the policy cache
 * @max_caches: The maximum number of policy caches, one for each unique set of
 *              kernel features, before older caches are auto-reaped. 0 means
 *              that no new caches should be created (existing, valid caches
 *              will be used) and auto-reaping is disabled. UINT16_MAX means
 *              that a cache can be created and auto-reaping is disabled.
 *
 * Returns: 0 on success, -1 on error with errno set and *@policy_cache
 *          pointing to NULL
 */
int aa_policy_cache_new(aa_policy_cache **policy_cache,
			aa_features *kernel_features,
			int dirfd, const char *path, uint16_t max_caches)
{
	aa_policy_cache *pc;
	bool create = max_caches > 0;
	autofree const char *features_id = NULL;
	autofree char *cache_dir = NULL;

	*policy_cache = NULL;

	if (!path) {
		errno = EINVAL;
		return -1;
	}

	if (max_caches > 1) {
		errno = ENOTSUP;
		return -1;
	}

	pc = calloc(1, sizeof(*pc));
	if (!pc) {
		errno = ENOMEM;
		return -1;
	}
	pc->dirfd = -1;
	aa_policy_cache_ref(pc);

	if (kernel_features) {
		aa_features_ref(kernel_features);
	} else if (aa_features_new_from_kernel(&kernel_features) == -1) {
		aa_policy_cache_unref(pc);
		return -1;
	}
	pc->kernel_features = kernel_features;

	if (cache_dir_from_path_and_features(&cache_dir, dirfd, path,
					     kernel_features)) {
		aa_policy_cache_unref(pc);
		return -1;
	}

open:
	pc->dirfd = openat(dirfd, cache_dir, O_RDONLY | O_CLOEXEC | O_DIRECTORY);
	if (pc->dirfd < 0) {
		/* does the dir exist? */
		if (create && errno == ENOENT) {
			/**
			 * 1) Attempt to create the cache location, such as
			 *    /etc/apparmor.d/cache.d/
			 * 2) Attempt to create the cache directory, for the
			 *    passed in aa_features, such as
			 *    /etc/apparmor.d/cache.d/<features_id>/
			 * 3) Try to reopen the cache directory
			 */
			if (mkdirat(dirfd, path, 0700) == -1 &&
			    errno != EEXIST) {
				PERROR("Can't create cache location '%s': %m\n",
				       path);
			} else if (mkdirat(dirfd, cache_dir, 0700) == -1 &&
				   errno != EEXIST) {
				PERROR("Can't create cache directory '%s': %m\n",
				       cache_dir);
			} else {
				goto open;
			}
		} else if (create) {
			PERROR("Can't update cache directory '%s': %m\n", cache_dir);
		} else {
			PDEBUG("Cache directory '%s' does not exist\n", cache_dir);
		}

		aa_policy_cache_unref(pc);
		return -1;
	}

	if (init_cache_features(pc, kernel_features, create)) {
		PDEBUG("%s: failed init_cache_features for dirfd '%d' name '%s' opened as pc->dirfd '%d'\n", __FUNCTION__, dirfd, cache_dir, pc->dirfd);
		aa_policy_cache_unref(pc);
		return -1;
	}

	PDEBUG("%s: created policy_cache for dirfd '%d' name '%s' opened as pc->dirfd '%d'\n", __FUNCTION__, dirfd, cache_dir, pc->dirfd);
	*policy_cache = pc;

	return 0;
}

/**
 * aa_policy_cache_ref - increments the ref count of an aa_policy_cache object
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
 * aa_policy_cache_unref - decrements the ref count and frees the aa_policy_cache object when 0
 * @policy_cache: the policy_cache (can be NULL)
 */
void aa_policy_cache_unref(aa_policy_cache *policy_cache)
{
	int save = errno;

	if (policy_cache && atomic_dec_and_test(&policy_cache->ref_count)) {
		aa_features_unref(policy_cache->features);
		aa_features_unref(policy_cache->kernel_features);
		if (policy_cache->dirfd != -1)
			close(policy_cache->dirfd);
		free(policy_cache);
	}

	errno = save;
}

/**
 * aa_policy_cache_remove - removes all policy cache files under a path
 * @dirfd: directory file descriptor or AT_FDCWD (see openat(2))
 * @path: the path to a policy cache directory
 *
 * Returns: 0 on success, -1 on error with errno set
 */
int aa_policy_cache_remove(int dirfd, const char *path)
{
	return _aa_dirat_for_each(dirfd, path, NULL, clear_cache_cb);
}

/**
 * aa_policy_cache_replace_all - performs a kernel policy replacement of all cached policies
 * @policy_cache: the policy_cache
 * @kernel_interface: the kernel interface to use when doing the replacement
 *                    (may be NULL if the currently running kernel features
 *                    were used when calling aa_policy_cache_new())
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
	retval = _aa_dirat_for_each(policy_cache->dirfd, ".", &cb_data,
				    replace_all_cb);

	aa_kernel_interface_unref(kernel_interface);

	return retval;
}

/**
 * aa_policy_cache_dir_path - returns the path to the aa_policy_cache directory
 * @policy_cache: the policy_cache
 *
 * Returns: The path to the policy cache directory on success, NULL on
 * error with errno set.
 */
char *aa_policy_cache_dir_path(aa_policy_cache *policy_cache)
{
	char *path = path_from_fd(policy_cache->dirfd);

	if (!path)
		PERROR("Can't return the path to the aa_policy_cache directory: %m\n");

	return path;
}

/**
 * aa_policy_cache_dir_path_preview - returns the path to the aa_policy_cache directory
 * @kernel_features: features representing a kernel (may be NULL if you want to
 *                   use the features of the currently running kernel)
 * @dirfd: directory file descriptor or AT_FDCWD (see openat(2))
 * @path: path to the policy cache
 *
 * Returns: The path to the policy cache directory on success, NULL on
 * error with errno set.
 */
char *aa_policy_cache_dir_path_preview(aa_features *kernel_features,
				       int dirfd, const char *path)
{
	autofree char *cache_loc = NULL;
	autofree char *cache_dir = NULL;
	char *dir_path;

	if (kernel_features) {
		aa_features_ref(kernel_features);
	} else if (aa_features_new_from_kernel(&kernel_features) == -1) {
		return NULL;
	}

	/**
	 * Leave cache_loc set to NULL if dirfd is AT_FDCWD and handle a
	 * NULL cache_loc in the asprintf() below
	 */
	if (dirfd != AT_FDCWD) {
		cache_loc = path_from_fd(dirfd);
		if (!cache_loc) {
			int save = errno;

			PERROR("Can't return the path to the aa_policy_cache cache location: %m\n");
			aa_features_unref(kernel_features);
			errno = save;
			return NULL;
		}
	}

	PDEBUG("Looking up cachedir path for AT_FDCWD\n");
	if (cache_dir_from_path_and_features(&cache_dir, dirfd, path,
					     kernel_features)) {
		int save = errno;

		PERROR("Can't return the path to the aa_policy_cache directory: %m\n");
		aa_features_unref(kernel_features);
		errno = save;
		return NULL;
	}

	aa_features_unref(kernel_features);

	if (asprintf(&dir_path, "%s%s%s",
		     cache_loc ? : "", cache_loc ? "/" : "", cache_dir) == -1) {
		errno = ENOMEM;
		return NULL;
	}

	PDEBUG("aa_policy_cache_dir_path_preview() returning '%s'\n", dir_path);
	return dir_path;
}
