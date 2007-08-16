/*   $Id: change_hat.c 13 2006-04-12 21:43:34Z steve-beattie $

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

#define symbol_version(real, name, version) \
		__asm__ (".symver " #real "," #name "@" #version)
#define default_symbol_version(real, name, version) \
		__asm__ (".symver " #real "," #name "@@" #version)

static int do_change_x(const char *cmd, const char *name, unsigned long token)
{
	int rc = -1;
	int fd, ret, len = 0, ctlerr = 0;
	char *buf = NULL;
	const char *fmt = "%s %016x^%s";
	char *ctl = NULL;
	pid_t tid = syscall(SYS_gettid);

	/* both may not be null */
	if (!(token || name)) {
		errno = EINVAL;
		goto out;
	}

	if (name && strnlen(name, PATH_MAX + 1) > PATH_MAX) {
		errno = EPROTO;
		goto out;
	}

	len = asprintf(&buf, fmt, cmd, token,
		       name ? name : "");
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

int aa_change_hat(const char *subprofile, unsigned long token)
{
	return do_change_x("changehat", subprofile, token);
}

/* original change_hat interface */
int __change_hat(char *subprofile, unsigned int token)
{
	return aa_change_hat(subprofile, (unsigned long) token);
}

/* create an alias for the old change_hat@IMMUNIX_1.0 symbol */
extern typeof((__change_hat)) __old_change_hat __attribute__((alias ("__change_hat")));
symbol_version(__old_change_hat, change_hat, IMMUNIX_1.0);
default_symbol_version(__change_hat, change_hat, APPARMOR_1.0);
