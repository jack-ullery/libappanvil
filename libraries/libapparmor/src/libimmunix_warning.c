/*   $Id: libimmunix_warning.c 13 2006-04-12 21:43:34Z steve-beattie $

     Copyright (c) 2006 Novell, Inc. (All rights reserved)
     The libimmunix library is licensed under the terms of the GNU
     Lesser General Public License, version 2.1. Please see the file
     COPYING.LGPL.

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
