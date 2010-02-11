/*   $Id$

     Copyright (c) 2003-2007 Novell, Inc. (All rights reserved)

     The libapparmor library is licensed under the terms of the GNU
     Lesser General Public License, version 2.1. Please see the file
     COPYING.LGPL.

*/

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

static int setprocattr(const char *path, const char *buf, int len)
{
	int rc = -1;
	int fd, ret, ctlerr = 0;
	char *ctl = NULL;
	pid_t tid = syscall(SYS_gettid);

	if (!buf) {
		errno = EINVAL;
		goto out;
	}

	ctlerr = asprintf(&ctl, path, tid);
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
	if (ctl) {
		free(ctl);
	}
	return rc;
}

int aa_change_hat(const char *subprofile, unsigned long token)
{
	int rc = -1;
	int len = 0;
	char *buf = NULL;
	const char *fmt = "changehat %016x^%s";

	/* both may not be null */
	if (!(token || subprofile)) {
		errno = EINVAL;
		goto out;
	}

	if (subprofile && strnlen(subprofile, PATH_MAX + 1) > PATH_MAX) {
		errno = EPROTO;
		goto out;
	}

	len = asprintf(&buf, fmt, token, subprofile ? subprofile : "");
	if (len < 0) {
		goto out;
	}

	rc = setprocattr("/proc/%d/attr/current", buf, len);
out:
	if (buf) {
		/* clear local copy of magic token before freeing */
		memset(buf, '\0', len);
		free(buf);
	}
	return rc;
}

/* original change_hat interface */
int __change_hat(char *subprofile, unsigned int token)
{
	return aa_change_hat(subprofile, (unsigned long) token);
}

int aa_change_profile(const char *profile)
{
	char *buf = NULL;
	int len;
	int rc;

	if (!profile) {
		errno = EINVAL;
		return -1;
	}

	len = asprintf(&buf, "changeprofile %s", profile);
	if (len < 0)
		return -1;

	rc = setprocattr("/proc/%d/attr/current", buf, len);

	free(buf);
	return rc;
}

int aa_change_onexec(const char *profile)
{
	char *buf = NULL;
	int len;
	int rc;

	if (!profile) {
		errno = EINVAL;
		return -1;
	}

	len = asprintf(&buf, "exec %s", profile);
	if (len < 0)
		return -1;

	rc = setprocattr("/proc/%d/attr/exec", buf, len);

	free(buf);
	return rc;
}

/* create an alias for the old change_hat@IMMUNIX_1.0 symbol */
extern typeof((__change_hat)) __old_change_hat __attribute__((alias ("__change_hat")));
symbol_version(__old_change_hat, change_hat, IMMUNIX_1.0);
default_symbol_version(__change_hat, change_hat, APPARMOR_1.0);
