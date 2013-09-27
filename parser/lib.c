/*
 *   Copyright (c) 2012
 *   Canonical Ltd. (All rights reserved)
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
 *   along with this program; if not, contact Novell, Inc. or Canonical,
 *   Ltd.
 */

#include <dirent.h>
#include <errno.h>
#include <fcntl.h>
#include <stdio.h>
#include <string.h>
#include <stddef.h>
#include <stdlib.h>
#include <unistd.h>
#define _(s) gettext(s)

#include <sys/stat.h>
#include <sys/types.h>

#include "parser.h"

/**
 * dirat_for_each: iterate over a directory calling cb for each entry
 * @dir: already opened directory (MAY BE NULL)
 * @name: name of the directory (MAY BE NULL)
 * @data: data pointer to pass to the callback fn (MAY BE NULL)
 * @cb: the callback to pass entry too (NOT NULL)
 *
 * Iterate over the entries in a directory calling cb for each entry.
 * The directory to iterate is determined by a combination of @dir and
 * @name.
 *
 * IF @name is a relative path it is determine relative to at @dir if it
 * is specified, else it the lookup is done relative to the current
 * working directory.
 *
 * If @name is not specified then @dir is used as the directory to iterate
 * over.
 *
 * It is an error if both @name and @dir are null
 *
 * The cb function is called with the DIR in use and the name of the
 * file in that directory.  If the file is to be opened it should
 * use the openat, fstatat, and related fns.
 *
 * Returns: 0 on success, else -1 and errno is set to the error code
 */
int dirat_for_each(DIR *dir, const char *name, void *data,
		   int (* cb)(DIR *, const char *, struct stat *, void *))
{
	struct dirent *dirent = NULL, *ent;
	DIR *d = NULL;
	int error = 0;

	if (!cb || (!dir && !name)) {
		errno = EINVAL;
		return -1;
	}

	if (dir && (!name || *name != '/')) {
		dirent = (struct dirent *)
			malloc(offsetof(struct dirent, d_name) +
			       fpathconf(dirfd(dir), _PC_NAME_MAX) + 1);
	} else {
		dirent = (struct dirent *)
			malloc(offsetof(struct dirent, d_name) +
			       pathconf(name, _PC_NAME_MAX) + 1);
	}
	if (!dirent) {
		PDEBUG("could not alloc dirent");
		return -1;
	}

	if (name) {
		if (dir && *name != '/') {
			int fd = openat(dirfd(dir), name, O_RDONLY);
			if (fd == -1)
				goto fail;
			d = fdopendir(fd);
		} else {
			d = opendir(name);
		}
		PDEBUG("Open dir '%s': %s\n", name, d ? "succeeded" : "failed");
		if (!(d))
			goto fail;
	} else { /* dir && !name */
		PDEBUG("Recieved cache directory\n");
		d = dir;
	}

	for (error = readdir_r(d, dirent, &ent);
	     error == 0 && ent != NULL;
	     error = readdir_r(d, dirent, &ent)) {
		struct stat my_stat;

		if (strcmp(ent->d_name, ".") == 0 ||
		    strcmp(ent->d_name, "..") == 0)
			continue;

		if (fstatat(dirfd(d), ent->d_name, &my_stat, 0)) {
			PDEBUG("stat failed for '%s'", name);
			goto fail;
		}

		if (cb(d, ent->d_name, &my_stat, data)) {
			PDEBUG("dir_for_each callback failed\n");
			goto fail;
		}
	}

	if (d != dir)
		closedir(d);
	free(dirent);

	return error;

fail:
	error = errno;
	if (d && d != dir)
		closedir(d);
	free(dirent);
	errno = error;

	return -1;
}
