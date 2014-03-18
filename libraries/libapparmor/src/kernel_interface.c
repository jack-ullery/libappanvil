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
#include <inttypes.h>
#include <pthread.h>

#include <sys/apparmor.h>

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
 * @mode: if non-NULL and a mode is present, will point to mode string in @buf
 *
 * Returns: size of data read or -1 on error, and sets errno
 */
int aa_getprocattr_raw(pid_t tid, const char *attr, char *buf, int len,
		       char **mode)
{
	int rc = -1;
	int fd, ret;
	char *tmp = NULL;
	char *mode_str;
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

		mode_str = parse_confinement_mode(buf, size);
		if (mode)
			*mode = mode_str;
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
 * @con: allocated buffer the result is stored in
 * @mode: if non-NULL and a mode is present, will point to mode string in @con
 *
 * Returns: size of data read or -1 on error, and sets errno
 *
 * Guarantees that @con and @mode are null terminated.  The length returned
 * is for all data including both @con and @mode, and maybe > than strlen(@con)
 * even if @mode is NULL
 *
 * Caller is responsible for freeing the buffer returned in @con.  @mode is
 * always contained within @con's buffer and so NEVER do free(@mode)
 */
int aa_getprocattr(pid_t tid, const char *attr, char **con, char **mode)
{
	int rc, size = INITIAL_GUESS_SIZE/2;
	char *buffer = NULL;

	if (!con) {
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
		*con = NULL;
		if (mode)
			*mode = NULL;
	} else
		*con = buffer;

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
	const char *fmt = "changehat %016lx^%s";

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
 * @mode: if non-NULL and a mode is present, will point to mode string in @con
 *
 * Returns: length of confinement data or -1 on error and sets errno
 *
 * Guarantees that @con and @mode are null terminated.  The length returned
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
 * @mode: if non-NULL and a mode is present, will point to mode string in @con
 *
 * Returns: length of confinement data or -1 on error and sets errno
 *
 * Guarantees that @con and @mode are null terminated.  The length returned
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
 * @buf: buffer to store the result in
 * @len: initially contains size of the buffer, returns size of data read
 * @mode: if non-NULL and a mode is present, will point to mode string in @buf
 *
 * Returns: length of confinement data including null termination or -1 on error
 *          if errno == ERANGE then @len will hold the size needed
 */
int aa_getpeercon_raw(int fd, char *buf, int *len, char **mode)
{
	socklen_t optlen = *len;
	char *mode_str;
	int rc;

	if (optlen <= 0 || buf == NULL) {
		errno = EINVAL;
		return -1;
	}

	rc = getsockopt(fd, SOL_SOCKET, SO_PEERSEC, buf, &optlen);
	if (rc == -1 || optlen <= 0)
		goto out;

	/* check for null termination */
	if (buf[optlen - 1] != 0) {
		if (optlen < *len) {
			buf[optlen] = 0;
			optlen++;
		} else {
			/* buf needs to be bigger by 1 */
			rc = -1;
			errno = ERANGE;
			optlen++;
			goto out;
		}
	}

	mode_str = parse_confinement_mode(buf, optlen);
	if (mode)
		*mode = mode_str;

	rc = optlen;
out:
	*len = optlen;
	return rc;
}

/**
 * aa_getpeercon - get the confinement of the socket's peer (other end)
 * @fd: socket to get peer confinement for
 * @con: pointer to allocated buffer with the confinement string
 * @mode: if non-NULL and a mode is present, will point to mode string in @con
 *
 * Returns: length of confinement data including null termination or -1 on error
 *
 * Guarantees that @con and @mode are null terminated.  The length returned
 * is for all data including both @con and @mode, and maybe > than strlen(@con)
 * even if @mode is NULL
 *
 * Caller is responsible for freeing the buffer returned in @con.  @mode is
 * always contained within @con's buffer and so NEVER do free(@mode)
 */
int aa_getpeercon(int fd, char **con, char **mode)
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

		rc = aa_getpeercon_raw(fd, buffer, &size, mode);
		/* size should contain actual size needed if errno == ERANGE */
	} while (rc == -1 && errno == ERANGE && size > last_size);

	if (rc == -1) {
		free(buffer);
		*con = NULL;
		if (mode)
			*mode = NULL;
		size = -1;
	} else
		*con = buffer;

	return size;
}

static pthread_once_t aafs_access_control = PTHREAD_ONCE_INIT;
static char *aafs_access = NULL;

static void aafs_access_init_once(void)
{
	char *aafs;
	int ret;

	ret = aa_find_mountpoint(&aafs);
	if (ret < 0)
		return;

	ret = asprintf(&aafs_access, "%s/.access", aafs);
	if (ret < 0)
		aafs_access = NULL;

	free(aafs);
}

/* "allow 0x00000000\ndeny 0x00000000\naudit 0x00000000\nquiet 0x00000000\n" */
#define QUERY_LABEL_REPLY_LEN	67

/**
 * aa_query_label - query the access(es) of a label
 * @mask: permission bits to query
 * @query: binary query string, must be offset by AA_QUERY_CMD_LABEL_SIZE
 * @size: size of the query string must include AA_QUERY_CMD_LABEL_SIZE
 * @allowed: upon successful return, will be 1 if query is allowed and 0 if not
 * @audited: upon successful return, will be 1 if query should be audited and 0
 *           if not
 *
 * Returns: 0 on success else -1 and sets errno. If -1 is returned and errno is
 *          ENOENT, the subject label in the query string is unknown to the
 *          kernel.
 */
int query_label(uint32_t mask, char *query, size_t size, int *allowed,
		int *audited)
{
	char buf[QUERY_LABEL_REPLY_LEN];
	uint32_t allow, deny, audit, quiet;
	int fd, ret, saved;

	if (!mask || size <= AA_QUERY_CMD_LABEL_SIZE) {
		errno = EINVAL;
		return -1;
	}

	ret = pthread_once(&aafs_access_control, aafs_access_init_once);
	if (ret) {
		errno = EINVAL;
		return -1;
	} else if (!aafs_access) {
		errno = ENOMEM;
		return -1;
	}

	fd = open(aafs_access, O_RDWR);
	if (fd == -1) {
		if (errno == ENOENT)
			errno = EPROTONOSUPPORT;
		return -1;
	}

	memcpy(query, AA_QUERY_CMD_LABEL, AA_QUERY_CMD_LABEL_SIZE);
	errno = 0;
	ret = write(fd, query, size);
	if (ret != size) {
		if (ret >= 0)
			errno = EPROTO;
		/* IMPORTANT: This is the only valid error path that can have
		 * errno set to ENOENT. It indicates that the subject label
		 * could not be found by the kernel.
		 */
		(void)close(fd);
		return -1;
	}

	ret = read(fd, buf, QUERY_LABEL_REPLY_LEN);
	saved = errno;
	(void)close(fd);
	errno = saved;
	if (ret != QUERY_LABEL_REPLY_LEN) {
		errno = EPROTO;
		return -1;
	}

	ret = sscanf(buf, "allow 0x%8" SCNx32 "\n"
			  "deny 0x%8"  SCNx32 "\n"
			  "audit 0x%8" SCNx32 "\n"
			  "quiet 0x%8" SCNx32 "\n",
		     &allow, &deny, &audit, &quiet);
	if (ret != 4) {
		errno = EPROTONOSUPPORT;
		return -1;
	}

	*allowed = mask & ~(allow & ~deny) ? 0 : 1;
	if (!(*allowed))
		audit = 0xFFFFFFFF;
	*audited = mask & ~(audit & ~quiet) ? 0 : 1;

	return 0;
}

/* export multiple aa_query_label symbols to compensate for downstream
 * releases with differing symbol versions. */
extern typeof((query_label)) __aa_query_label __attribute__((alias ("query_label")));
symbol_version(__aa_query_label, aa_query_label, APPARMOR_1.1);
default_symbol_version(query_label, aa_query_label, APPARMOR_2.9);
