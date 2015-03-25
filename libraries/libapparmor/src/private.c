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

#include <stdarg.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <syslog.h>

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
