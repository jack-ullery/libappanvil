/*
 * Copyright (c) 2006 Novell, Inc. (All rights reserved)
 *
 * The libimmunix library is licensed under the terms of the GNU
 * Lesser General Public License, version 2.1. Please see the file
 * COPYING.LGPL.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
 * GNU Lesser General Public License for more details.
 *
 * You should have received a copy of the GNU Lesser General Public
 * License * along with this program. If not, see <http://www.gnu.org/licenses/>.
 */

#include <syslog.h>

void __libimmunix_warning(void) __attribute__ ((constructor));
void __libimmunix_warning(void)
{
	extern const char *__progname; /* global from linux crt0 */
	openlog (__progname, LOG_PID|LOG_PERROR, LOG_USER);
	syslog(LOG_NOTICE,
			"%s links against libimmunix.so, which is deprecated. "
			"Please link against libapparmor instead\n",
			__progname);
	closelog();

}
