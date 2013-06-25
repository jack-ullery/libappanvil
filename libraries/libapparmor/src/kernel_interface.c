/*
 * Copyright (c) 2003-2008 Novell, Inc. (All rights reserved)
 * Copyright 2009-2010 Canonical Ltd.
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

#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <unistd.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <sys/syscall.h>
#include <sys/socket.h>
#include <fcntl.h>
#include <errno.h>
#include <limits.h>
#include <stdarg.h>
#include <mntent.h>

#include "apparmor.h"

/* some non-Linux systems do not define a static value */
#ifndef PATH_MAX
# define PATH_MAX 4096
#endif

#define symbol_version(real, name, version) \
		__asm__ (".symver " #real "," #name "@" #version)
#define default_symbol_version(real, name, version) \
		__asm__ (".symver " #real "," #name "@@" #version)

/**
 * aa_find_mountpoint - find where the apparmor interface filesystem is mounted
 * @mnt: returns buffer with the mountpoint string
 *
 * Returns: 0 on success else -1 on error
 *
 * NOTE: this function only supports versions of apparmor using securityfs
 */
int aa_find_mountpoint(char **mnt)
{
	struct stat statbuf;
	struct mntent *mntpt;
	FILE *mntfile;
	int rc = -1;

	if (!mnt) {
		errno = EINVAL;
		return -1;
	}

	mntfile = setmntent("/proc/mounts", "r");
	if (!mntfile)
		return -1;

	while ((mntpt = getmntent(mntfile))) {
		char *proposed = NULL;
		if (strcmp(mntpt->mnt_type, "securityfs") != 0)
			continue;

		if (asprintf(&proposed, "%s/apparmor", mntpt->mnt_dir) < 0)
			/* ENOMEM */
			break;

		if (stat(proposed, &statbuf) == 0) {
			*mnt = proposed;
			rc = 0;
			break;
		}
		free(proposed);
	}
	endmntent(mntfile);
	if (rc == -1)
		errno = ENOENT;
	return rc;
}

/**
 * aa_is_enabled - determine if apparmor is enabled
 *
 * Returns: 1 if enabled else reason it is not, or 0 on error
 *
 * ENOSYS - no indication apparmor is present in the system
 * ENOENT - enabled but interface could not be found
 * ECANCELED - disabled at boot
 * ENOMEM - out of memory
 */
int aa_is_enabled(void)
{
	int serrno, fd, rc, size;
	char buffer[2];
	char *mnt;

	/* if the interface mountpoint is available apparmor is enabled */
	rc = aa_find_mountpoint(&mnt);
	if (rc == 0) {
		free(mnt);
		return 1;
	}

	/* determine why the interface mountpoint isn't available */
	fd = open("/sys/module/apparmor/parameters/enabled", O_RDONLY);
	if (fd == -1) {
		if (errno == ENOENT)
			errno = ENOSYS;
		return 0;
	}

	size = read(fd, &buffer, 2);
	serrno = errno;
	close(fd);
	errno = serrno;

	if (size > 0) {
		if (buffer[0] == 'Y')
			errno = ENOENT;
		else
			errno = ECANCELED;
	}
	return 0;
}

static inline pid_t aa_gettid(void)
{
#ifdef SYS_gettid
	return syscall(SYS_gettid);
#else
	return getpid();
#endif
}

static char *procattr_path(pid_t pid, const char *attr)
{
	char *path = NULL;
	if (asprintf(&path, "/proc/%d/attr/%s", pid, attr) > 0)
		return path;
	return NULL;
}

/**
 * parse_confinement_mode - get the mode from the confinement string
 * @con: the confinement string
 * @size: size of the confinement string
 *
 * Modifies con to NUL-terminate the label string and the mode string.
 *
 * Returns: a pointer to the NUL-terminated mode inside the confinement string
 * or NULL if the mode was not found
 */
static char *parse_confinement_mode(char *con, int size)
{
	if (strcmp(con, "unconfined") != 0 &&
	    size > 4 && con[size - 2] == ')') {
		int pos = size - 3;

		while (pos > 0 && !(con[pos] == ' ' && con[pos + 1] == '('))
			pos--;
		if (pos > 0) {
			con[pos] = 0; /* overwrite ' ' */
			con[size - 2] = 0; /* overwrite trailing ) */
			return &con[pos + 2]; /* skip '(' */
		}
	}
	return NULL;
}

/**
 * aa_getprocattr_raw - get the contents of @attr for @tid into @buf
 * @tid: tid of task to query
 * @attr: which /proc/<tid>/attr/<attr> to query
 * @buf: buffer to store the result in
 * @len: size of the buffer
 * @mode: if set will point to mode string within buffer if it is present
 *
 * Returns: size of data read or -1 on error, and sets errno
 */
int aa_getprocattr_raw(pid_t tid, const char *attr, char *buf, int len,
		       char **mode)
{
	int rc = -1;
	int fd, ret;
	char *tmp = NULL;
	int size = 0;

	if (!buf || len <= 0) {
		errno = EINVAL;
		goto out;
	}

	tmp = procattr_path(tid, attr);
	if (!tmp)
		goto out;

	fd = open(tmp, O_RDONLY);
	free(tmp);
	if (fd == -1) {
		goto out;
	}

	tmp = buf;
	do {
		ret = read(fd, tmp, len);
		if (ret <= 0)
			break;
		tmp += ret;
		size += ret;
		len -= ret;
		if (len < 0) {
			errno = ERANGE;
			goto out2;
		}
	} while (ret > 0);

	if (ret < 0) {
		int saved;
		if (ret != -1) {
			errno = EPROTO;
		}
		saved = errno;
		(void)close(fd);
		errno = saved;
		goto out;
	} else if (size > 0 && buf[size - 1] != 0) {
		/* check for null termination */
		if (buf[size - 1] == '\n') {
			buf[size - 1] = 0;
		} else if (len == 0) {
			errno = ERANGE;
			goto out2;
		} else {
			buf[size] = 0;
			size++;
		}

		if (mode)
			*mode = parse_confinement_mode(buf, size);
	}
	rc = size;

out2:
	(void)close(fd);
out:
	return rc;
}

#define INITIAL_GUESS_SIZE 128

/**
 * aa_getprocattr - get the contents of @attr for @tid into @buf
 * @tid: tid of task to query
 * @attr: which /proc/<tid>/attr/<attr> to query
 * @buf: allocated buffer the result is stored in
 * @mode: if set will point to mode string within buffer if it is present
 *
 * Returns: size of data read or -1 on error, and sets errno
 */
int aa_getprocattr(pid_t tid, const char *attr, char **buf, char **mode)
{
	int rc, size = INITIAL_GUESS_SIZE/2;
	char *buffer = NULL;

	if (!buf) {
		errno = EINVAL;
		return -1;
	}

	do {
		size <<= 1;
		buffer = realloc(buffer, size);
		if (!buffer)
			return -1;
		memset(buffer, 0, size);

		rc = aa_getprocattr_raw(tid, attr, buffer, size, mode);
	} while (rc == -1 && errno == ERANGE);

	if (rc == -1) {
		free(buffer);
		*buf = NULL;
		*mode = NULL;
	} else
		*buf = buffer;

	return rc;
}

static int setprocattr(pid_t tid, const char *attr, const char *buf, int len)
{
	int rc = -1;
	int fd, ret;
	char *ctl = NULL;

	if (!buf) {
		errno = EINVAL;
		goto out;
	}

	ctl = procattr_path(tid, attr);
	if (!ctl)
		goto out;

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

	rc = setprocattr(aa_gettid(), "current", buf, len);
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

	rc = setprocattr(aa_gettid(), "current", buf, len);

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

	rc = setprocattr(aa_gettid(), "exec", buf, len);

	free(buf);
	return rc;
}

/* create an alias for the old change_hat@IMMUNIX_1.0 symbol */
extern typeof((__change_hat)) __old_change_hat __attribute__((alias ("__change_hat")));
symbol_version(__old_change_hat, change_hat, IMMUNIX_1.0);
default_symbol_version(__change_hat, change_hat, APPARMOR_1.0);


int aa_change_hatv(const char *subprofiles[], unsigned long token)
{
	int size, totallen = 0, hatcount = 0;
	int rc = -1;
	const char **hats;
	char *pos, *buf = NULL;
	const char *cmd = "changehat";

	/* both may not be null */
	if (!token && !(subprofiles && *subprofiles)) {
		errno = EINVAL;
                goto out;
        }

	/* validate hat lengths and while we are at it count how many and
	 * mem required */
	if (subprofiles) {
		for (hats = subprofiles; *hats; hats++) {
			int len = strnlen(*hats, PATH_MAX + 1);
			if (len > PATH_MAX) {
				errno = EPROTO;
				goto out;
			}
			totallen += len + 1;
			hatcount++;
                }
	}

	/* allocate size of cmd + space + token + ^ + vector of hats */
	size = strlen(cmd) + 18 + totallen + 1;
	buf = malloc(size);
	if (!buf) {
                goto out;
        }

	/* setup command string which is of the form
	 * changehat <token>^hat1\0hat2\0hat3\0..\0
	 */
	sprintf(buf, "%s %016lx^", cmd, token);
	pos = buf + strlen(buf);
	if (subprofiles) {
		for (hats = subprofiles; *hats; hats++) {
			strcpy(pos, *hats);
			pos += strlen(*hats) + 1;
		}
	} else
		/* step pos past trailing \0 */
		pos++;

	rc = setprocattr(aa_gettid(), "current", buf, pos - buf);

out:
	if (buf) {
		/* clear local copy of magic token before freeing */
		memset(buf, '\0', size);
		free(buf);
	}

	return rc;
}

/**
 * change_hat_vargs - change_hatv but passing the hats as fn arguments
 * @token: the magic token
 * @nhat: the number of hats being passed in the arguments
 * ...: a argument list of const char * being passed
 *
 * change_hat_vargs can be called directly but it is meant to be called
 * through its macro wrapper of the same name.  Which automatically
 * fills in the nhats arguments based on the number of parameters
 * passed.
 * to call change_hat_vargs direction do
 * (change_hat_vargs)(token, nhats, hat1, hat2...)
 */
int (aa_change_hat_vargs)(unsigned long token, int nhats, ...)
{
	va_list ap;
	const char *argv[nhats+1];
	int i;

	va_start(ap, nhats);
	for (i = 0; i < nhats ; i++) {
		argv[i] = va_arg(ap, char *);
	}
	argv[nhats] = NULL;
	va_end(ap);
	return aa_change_hatv(argv, token);
}

/**
 * aa_gettaskcon - get the confinement for task @target in an allocated buffer
 * @target: task to query
 * @con: pointer to returned buffer with the confinement string
 * @mode: if provided will point to the mode string in @con if present
 *
 * Returns: length of confinement data or -1 on error and sets errno
 *
 * Guarentees that @con and @mode are null terminated.  The length returned
 * is for all data including both @con and @mode, and maybe > than strlen(@con)
 * even if @mode is NULL
 *
 * Caller is responsible for freeing the buffer returned in @con.  @mode is
 * always contained within @con's buffer and so NEVER do free(@mode)
 */
int aa_gettaskcon(pid_t target, char **con, char **mode)
{
	return aa_getprocattr(target, "current", con, mode);
}

/**
 * aa_getcon - get the confinement for current task in an allocated buffer
 * @con: pointer to return buffer with the confinement if successful
 * @mode: if provided will point to the mode string in @con if present
 *
 * Returns: length of confinement data or -1 on error and sets errno
 *
 * Guarentees that @con and @mode are null terminated.  The length returned
 * is for all data including both @con and @mode, and may > than strlen(@con)
 * even if @mode is NULL
 *
 * Caller is responsible for freeing the buffer returned in @con.  @mode is
 * always contained within @con's buffer and so NEVER do free(@mode)
 */
int aa_getcon(char **con, char **mode)
{
	return aa_gettaskcon(aa_gettid(), con, mode);
}


#ifndef SO_PEERSEC
#define SO_PEERSEC 31
#endif

/**
 * aa_getpeercon_raw - get the confinement of the socket's peer (other end)
 * @fd: socket to get peer confinement for
 * @con: pointer to buffer to store confinement string
 * @size: initially contains size of the buffer, returns size of data read
 *
 * Returns: length of confinement data including null termination or -1 on error
 *          if errno == ERANGE then @size will hold the size needed
 */
int aa_getpeercon_raw(int fd, char *buffer, int *size)
{
	socklen_t optlen = *size;
	int rc;

	if (optlen <= 0 || buffer == NULL) {
		errno = EINVAL;
		return -1;
	}

	rc = getsockopt(fd, SOL_SOCKET, SO_PEERSEC, buffer, &optlen);
	if (rc == -1 || optlen <= 0)
		goto out;

	/* check for null termination */
	if (buffer[optlen - 1] != 0) {
		if (optlen < *size) {
			buffer[optlen] = 0;
			optlen++;
		} else {
			/* buffer needs to be bigger by 1 */
			rc = -1;
			errno = ERANGE;
			optlen++;
		}
	}

	rc = optlen;
out:
	*size = optlen;
	return rc;
}

/**
 * aa_getpeercon - get the confinement of the socket's peer (other end)
 * @fd: socket to get peer confinement for
 * @con: pointer to allocated buffer with the confinement string
 *
 * Returns: length of confinement data including null termination or -1 on error
 *
 * Caller is responsible for freeing the buffer returned.
 */
int aa_getpeercon(int fd, char **con)
{
	int rc, last_size, size = INITIAL_GUESS_SIZE;
	char *buffer = NULL;

	if (!con) {
		errno = EINVAL;
		return -1;
	}

	do {
		last_size = size;
		buffer = realloc(buffer, size);
		if (!buffer)
			return -1;
		memset(buffer, 0, size);

		rc = aa_getpeercon_raw(fd, buffer, &size);
		/* size should contain actual size needed if errno == ERANGE */
	} while (rc == -1 && errno == ERANGE && size > last_size);

	if (rc == -1) {
		free(buffer);
		*con = NULL;
		size = -1;
	} else
		*con = buffer;

	return size;
}
