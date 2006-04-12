/*   $Id$

     Copyright (c) 2003, 2004, 2005, 2006 Novell, Inc. (All rights reserved)

     The libapparmor library is licensed under the terms of the GNU
     Lesser General Public License, version 2.1. Please see the file
     COPYING.LGPL.

*/

#define _GNU_SOURCE	/* for asprintf */

#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <unistd.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <sys/syscall.h>
#include <fcntl.h>
#include <errno.h>
#include <limits.h>

int change_hat(char *subprofile, unsigned int token)
{
	int rc = -1;
	int fd, ret, len = 0, ctlerr = 0;
	char *buf = NULL;
	const char *cmd = "changehat";
	char *ctl = NULL;
	pid_t tid = syscall(SYS_gettid);

	/* both may not be null */
	if (!(token || subprofile)) {
		errno = EINVAL;
		goto out;
	}

	if (subprofile && strnlen(subprofile, PATH_MAX + 1) > PATH_MAX) {
		errno = EPROTO;
		goto out;
	}

	len = asprintf(&buf, "%s %08x^%s", cmd, token,
		       subprofile ? subprofile : "");
	if (len < 0) {
		goto out;
	}

	ctlerr = asprintf(&ctl, "/proc/%d/attr/current", tid);
	if (ctlerr < 0) {
		goto out;
	}

	fd = open(ctl, O_WRONLY);
	if (fd == -1) {
		goto out;
	}

	ret = write(fd, buf, len);
	if (ret != len) {
		int saved;
		if (ret != -1) {
			errno = EPROTO;
		}
		saved = errno;
		(void)close(fd);
		errno = saved;
		goto out;
	}

	rc = 0;
	(void)close(fd);

out:
	if (buf) {
		/* clear local copy of magic token before freeing */
		memset(buf, '\0', len);
		free(buf);
	}
	if (ctl) {
		free(ctl);
	}
	return rc;
}
