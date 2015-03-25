/*
 * Copyright 2014 Canonical Ltd.
 *
 * The libapparmor library is licensed under the terms of the GNU
 * Lesser General Public License, version 2.1. Please see the file
 * COPYING.LGPL.
 *
 * This library is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU Lesser General Public License for more details.
 *
 * You should have received a copy of the GNU Lesser General Public License
 * along with this program.  If not, see <http://www.gnu.org/licenses/>.
 */

#include <dirent.h>
#include <errno.h>
#include <fcntl.h>
#include <stdarg.h>
#include <stdbool.h>
#include <stddef.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <syslog.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <unistd.h>

#include "private.h"

struct ignored_suffix_t {
	const char * text;
	int len;
	int silent;
};

static struct ignored_suffix_t ignored_suffixes[] = {
	/* Debian packging files, which are in flux during install
           should be silently ignored. */
	{ ".dpkg-new", 9, 1 },
	{ ".dpkg-old", 9, 1 },
	{ ".dpkg-dist", 10, 1 },
	{ ".dpkg-bak", 9, 1 },
	/* RPM packaging files have traditionally not been silently
           ignored */
	{ ".rpmnew", 7, 0 },
	{ ".rpmsave", 8, 0 },
	/* patch file backups/conflicts */
	{ ".orig", 5, 0 },
	{ ".rej", 4, 0 },
	/* Backup files should be mentioned */
	{ "~", 1, 0 },
	{ NULL, 0, 0 }
};

#define DEBUG_ENV_VAR	"LIBAPPARMOR_DEBUG"

void print_error(bool honor_env_var, const char *ident, const char *fmt, ...)
{
	va_list args;
	int openlog_options = 0;

	if (honor_env_var && secure_getenv(DEBUG_ENV_VAR))
		openlog_options |= LOG_PERROR;

	openlog(ident, openlog_options, LOG_ERR);
	va_start(args, fmt);
	vsyslog(LOG_ERR, fmt, args);
	va_end(args);
	closelog();
}

void print_debug(const char *fmt, ...)
{
	va_list args;

	if (!secure_getenv(DEBUG_ENV_VAR))
		return;

	va_start(args, fmt);
	vfprintf(stderr, fmt, args);
	va_end(args);
}

void atomic_inc(unsigned int *v)
{
	__sync_add_and_fetch(v, 1);
}

bool atomic_dec_and_test(unsigned int *v)
{
	return __sync_sub_and_fetch(v, 1) == 0;
}

int _aa_is_blacklisted(const char *name, const char *path)
{
	int name_len;
	struct ignored_suffix_t *suffix;

	/* skip dot files and files with no name */
	if (*name == '.' || !strlen(name))
		return 1;

	name_len = strlen(name);
	/* skip blacklisted suffixes */
	for (suffix = ignored_suffixes; suffix->text; suffix++) {
		char *found;
		if ( (found = strstr((char *) name, suffix->text)) &&
		     found - name + suffix->len == name_len ) {
			if (!suffix->silent)
				return -1;
			return 1;
		}
	}

	return 0;
}

/* automaticly free allocated variables tagged with autofree on fn exit */
void _aa_autofree(void *p)
{
	void **_p = (void**)p;
	free(*_p);
}

void _aa_autoclose(int *fd)
{
	if (*fd != -1) {
		/* if close was interrupted retry */
		while(close(*fd) == -1 && errno == EINTR);
		*fd = -1;
	}
}

void _aa_autofclose(FILE **f)
{
	if (*f) {
		fclose(*f);
		*f = NULL;
	}
}

/**
 * _aa_dirat_for_each: iterate over a directory calling cb for each entry
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
int _aa_dirat_for_each(DIR *dir, const char *name, void *data,
		       int (* cb)(DIR *, const char *, struct stat *, void *))
{
	autofree struct dirent *dirent = NULL;
	DIR *d = NULL;
	int error;

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
		errno = ENOMEM;
		PDEBUG("could not alloc dirent: %m\n");
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

	for (;;) {
		struct dirent *ent;
		struct stat my_stat;

		error = readdir_r(d, dirent, &ent);
		if (error) {
			errno = error; /* readdir_r directly returns an errno */
			PDEBUG("readdir_r failed: %m\n");
			goto fail;
		} else if (!ent) {
			break;
		}

		if (strcmp(ent->d_name, ".") == 0 ||
		    strcmp(ent->d_name, "..") == 0)
			continue;

		if (fstatat(dirfd(d), ent->d_name, &my_stat, 0)) {
			PDEBUG("stat failed for '%s': %m\n", name);
			goto fail;
		}

		if (cb(d, ent->d_name, &my_stat, data)) {
			PDEBUG("dir_for_each callback failed\n");
			goto fail;
		}
	}

	if (d != dir)
		closedir(d);

	return 0;

fail:
	error = errno;
	if (d && d != dir)
		closedir(d);
	errno = error;

	return -1;
}
