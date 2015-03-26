/*
 * Copyright (C) 2015 Canonical, Ltd.
 *
 * This program is free software; you can redistribute it and/or
 * modify it under the terms of version 2 of the GNU General Public
 * License published by the Free Software Foundation.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, contact Canonical Ltd.
 */

#include <errno.h>
#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include <sys/apparmor.h>

#define OPT_CREATE		"create"
#define OPT_IS_VALID		"is-valid"
#define OPT_NEW			"new"
#define OPT_NEW_CREATE		"new-create"
#define OPT_REMOVE		"remove"
#define OPT_REMOVE_POLICY	"remove-policy"
#define OPT_REPLACE_ALL		"replace-all"

static void usage(const char *prog)
{
	fprintf(stderr,
		"FAIL - usage: %s %s <PATH>\n"
		"              %s %s <PATH>\n"
		"              %s %s <PATH>\n"
		"              %s %s <PATH>\n"
		"              %s %s <PATH>\n"
		"              %s %s <PROFILE_NAME>\n"
		"              %s %s <PATH>\n",
		prog, OPT_CREATE, prog, OPT_IS_VALID, prog, OPT_NEW,
		prog, OPT_NEW_CREATE, prog, OPT_REMOVE, prog, OPT_REMOVE_POLICY,
		prog, OPT_REPLACE_ALL);
}

static int test_create(const char *path)
{
	aa_features *features = NULL;
	aa_policy_cache *policy_cache = NULL;
	int rc = 1;

	if (aa_features_new_from_kernel(&features)) {
		perror("FAIL - aa_features_new_from_kernel");
		goto out;
	}

	if (aa_policy_cache_new(&policy_cache, features, path, false)) {
		perror("FAIL - aa_policy_cache_new");
		goto out;
	}

	if (aa_policy_cache_create(policy_cache)) {
		perror("FAIL - aa_policy_cache_create");
		goto out;
	}

	rc = 0;
out:
	aa_features_unref(features);
	aa_policy_cache_unref(policy_cache);
	return rc;
}

static int test_is_valid(const char *path)
{
	aa_features *features = NULL;
	aa_policy_cache *policy_cache = NULL;
	int rc = 1;

	if (aa_features_new_from_kernel(&features)) {
		perror("FAIL - aa_features_new_from_kernel");
		goto out;
	}

	if (aa_policy_cache_new(&policy_cache, features, path, false)) {
		perror("FAIL - aa_policy_cache_new");
		goto out;
	}

	if (!aa_policy_cache_is_valid(policy_cache)) {
		errno = EINVAL;
		perror("FAIL - aa_policy_cache_is_valid");
		goto out;
	}

	rc = 0;
out:
	aa_features_unref(features);
	aa_policy_cache_unref(policy_cache);
	return rc;
}

static int test_new(const char *path, bool create)
{
	aa_features *features = NULL;
	aa_policy_cache *policy_cache = NULL;
	int rc = 1;

	if (aa_features_new_from_kernel(&features)) {
		perror("FAIL - aa_features_new_from_kernel");
		goto out;
	}

	if (aa_policy_cache_new(&policy_cache, features, path, create)) {
		perror("FAIL - aa_policy_cache_new");
		goto out;
	}

	rc = 0;
out:
	aa_features_unref(features);
	aa_policy_cache_unref(policy_cache);
	return rc;
}

static int test_remove(const char *path)
{
	int rc = 1;

	if (aa_policy_cache_remove(path)) {
		perror("FAIL - aa_policy_cache_remove");
		goto out;
	}

	rc = 0;
out:
	return rc;
}

static int test_remove_policy(const char *name)
{
	aa_features *features = NULL;
	aa_kernel_interface *kernel_interface = NULL;
	int rc = 1;

	if (aa_features_new_from_kernel(&features)) {
		perror("FAIL - aa_features_new_from_kernel");
		goto out;
	}

	if (aa_kernel_interface_new(&kernel_interface, features, NULL)) {
		perror("FAIL - aa_kernel_interface_new");
		goto out;
	}

	if (aa_kernel_interface_remove_policy(kernel_interface, name)) {
		perror("FAIL - aa_kernel_interface_remove_policy");
		goto out;
	}

	rc = 0;
out:
	aa_kernel_interface_unref(kernel_interface);
	aa_features_unref(features);
	return rc;
}

static int test_replace_all(const char *path)
{
	aa_features *features = NULL;
	aa_policy_cache *policy_cache = NULL;
	int rc = 1;

	if (aa_features_new_from_kernel(&features)) {
		perror("FAIL - aa_features_new_from_kernel");
		goto out;
	}

	if (aa_policy_cache_new(&policy_cache, features, path, false)) {
		perror("FAIL - aa_policy_cache_new");
		goto out;
	}

	if (aa_policy_cache_replace_all(policy_cache, NULL)) {
		perror("FAIL - aa_policy_cache_replace_all");
		goto out;
	}

	rc = 0;
out:
	aa_features_unref(features);
	aa_policy_cache_unref(policy_cache);
	return rc;
}

int main(int argc, char **argv)
{
	int rc = 1;

	if (argc != 3) {
		usage(argv[0]);
		exit(1);
	}

	if (strcmp(argv[1], OPT_CREATE) == 0) {
		rc = test_create(argv[2]);
	} else if (strcmp(argv[1], OPT_IS_VALID) == 0) {
		rc = test_is_valid(argv[2]);
	} else if (strcmp(argv[1], OPT_NEW) == 0) {
		rc = test_new(argv[2], false);
	} else if (strcmp(argv[1], OPT_NEW_CREATE) == 0) {
		rc = test_new(argv[2], true);
	} else if (strcmp(argv[1], OPT_REMOVE) == 0) {
		rc = test_remove(argv[2]);
	} else if (strcmp(argv[1], OPT_REMOVE_POLICY) == 0) {
		rc = test_remove_policy(argv[2]);
	} else if (strcmp(argv[1], OPT_REPLACE_ALL) == 0) {
		rc = test_replace_all(argv[2]);
	} else {
		usage(argv[0]);
	}

	if (!rc)
		printf("PASS\n");

	exit(rc);
}
