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

#ifndef _AA_PRIVATE_H
#define _AA_PRIVATE_H 1

#include <stdbool.h>

#if ENABLE_DEBUG_OUTPUT

#define PERROR(fmt, args...)	print_error(true, "libapparmor", fmt, ## args)
#define PDEBUG(fmt, args...)	print_debug("libapparmor: " fmt, ## args)

#else /* ENABLE_DEBUG_OUTPUT */

#define PERROR(fmt, args...)	print_error(false, "libapparmor", fmt, ## args)
#define PDEBUG(fmt, args...)	/* do nothing */

#endif /* ENABLE_DEBUG_OUTPUT */

void print_error(bool honor_env_var, const char *ident, const char *fmt, ...);
void print_debug(const char *fmt, ...);

#endif /* _AA_PRIVATE_H */
