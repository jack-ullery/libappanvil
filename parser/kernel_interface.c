/*
 *   Copyright (c) 2014
 *   Canonical, Ltd. (All rights reserved)
 *
 *   This program is free software; you can redistribute it and/or
 *   modify it under the terms of version 2 of the GNU General Public
 *   License published by the Free Software Foundation.
 *
 *   This program is distributed in the hope that it will be useful,
 *   but WITHOUT ANY WARRANTY; without even the implied warranty of
 *   MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 *   GNU General Public License for more details.
 *
 *   You should have received a copy of the GNU General Public License
 *   along with this program; if not, contact Novell, Inc. or Canonical
 *   Ltd.
 */

#include <errno.h>
#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <sys/apparmor.h>
#include <unistd.h>

#include "kernel_interface.h"
#include "lib.h"
#include "parser.h"

#define DEFAULT_APPARMORFS "/sys/kernel/security/apparmor"

/**
 * aa_find_iface_dir - find where the apparmor interface is located
 * @dir - RETURNs: stored location of interface director
 *
 * Returns: 0 on success, -1 with errno set if there is an error
 */
int aa_find_iface_dir(char **dir)
{
	if (aa_find_mountpoint(dir) == -1) {
		struct stat buf;
		if (stat(DEFAULT_APPARMORFS, &buf) == -1) {
			return -1;
		} else {
			*dir = strdup(DEFAULT_APPARMORFS);
			if (*dir == NULL)
				return -1;
		}
	}

	return 0;
}

/**
 * open_iface_dir - open the apparmor interface dir
 *
 * Returns: opened file descriptor, or -1 with errno on error
 */
static int open_iface_dir(void)
{
	autofree char *dir = NULL;

	if (aa_find_iface_dir(&dir) == -1)
		return -1;

	return open(dir, O_RDONLY | O_CLOEXEC | O_DIRECTORY);
}


/* bleah the kernel should just loop and do multiple load, but to support
 * older systems we need to do this
 */
#define PROFILE_HEADER_SIZE
static char header_version[] = "\x04\x08\x00version";

static const char *next_profile_buffer(const char *buffer, int size)
{
	const char *b = buffer;

	for (; size - sizeof(header_version); b++, size--) {
		if (memcmp(b, header_version, sizeof(header_version)) == 0) {
			return b;
		}
	}
	return NULL;
}

static int write_buffer(int fd, const char *buffer, int size, int set)
{
	const char *err_str = set ? "profile set" : "profile";
	int wsize = write(fd, buffer, size);
	if (wsize < 0) {
		PERROR(_("%s: Unable to write %s\n"), progname, err_str);
		return -1;
	} else if (wsize < size) {
		PERROR(_("%s: Unable to write %s\n"), progname, err_str);
		errno = EPROTO;
		return -1;
	}
	return 0;
}

/**
 * write_policy_buffer - load compiled policy into the kernel
 * @fd: kernel iterface to write to
 * @atomic: whether to load all policy in buffer atomically (true)
 * @buffer: buffer of policy to load
 * @size: the size of the data in the buffer
 *
 * Returns: 0 if the buffer loaded correctly
 *         -1 if the load failed with errno set to the error
 *
 * @atomic should only be set to true if the kernel supports atomic profile
 * set loads, otherwise only the 1st profile in the buffer will be loaded
 * (older kernels only support loading one profile at a time).
 */
static int write_policy_buffer(int fd, int atomic,
			       const char *buffer, size_t size)
{
	size_t bsize;
	int rc;

	if (atomic) {
		rc = write_buffer(fd, buffer, size, true);
	} else {
		const char *b, *next;

		rc = 0;	/* in case there are no profiles */
		for (b = buffer; b; b = next, size -= bsize) {
			next = next_profile_buffer(b + sizeof(header_version),
						   size);
			if (next)
				bsize = next - b;
			else
				bsize = size;
			if (write_buffer(fd, b, bsize, false) == -1)
				return -1;
		}
	}

	if (rc)
		return -1;

	return 0;
}

/**
 * open_option_iface - open the interface file for @option
 * @aadir: apparmorfs dir
 * @option: load command option
 *
 * Returns: fd to interface or -1 on error, with errno set.
 */
static int open_option_iface(int aadir, int option)
{
	const char *name;

	switch (option) {
	case OPTION_ADD:
		name = ".load";
		break;
	case OPTION_REPLACE:
		name = ".replace";
		break;
	case OPTION_REMOVE:
		name = ".remove";
		break;
	default:
		errno = EINVAL;
		return -1;
	}

	return openat(aadir, name, O_WRONLY);

	/* TODO: push up */
	/*
	if (fd < 0) {
		PERROR(_("Unable to open %s - %s\n"), filename,
		       strerror(errno));
		return -errno;
	}
	*/
}

int aa_load_buffer(int option, char *buffer, int size)
{
	autoclose int dirfd = -1;
	autoclose int fd = -1;

	/* TODO: push backup into caller */
	if (!kernel_load)
		return 0;

	dirfd = open_iface_dir();
	if (dirfd == -1)
		return -1;

	fd = open_option_iface(dirfd, option);
	if (fd == -1)
		return -1;

	return write_policy_buffer(fd, kernel_supports_setload, buffer, size);
}

/**
 * aa_remove_profile - remove a profile from the kernel
 * @fqname: the fully qualified name of the profile to remove
 *
 * Returns: 0 on success, -1 on error with errno set
 */
int aa_remove_profile(const char *fqname)
{
	autoclose int dirfd = -1;
	autoclose int fd = -1;

	dirfd = open_iface_dir();
	if (dirfd == -1)
		return -1;

	fd = open_option_iface(dirfd, OPTION_REMOVE);
	if (fd == -1)
		return -1;

	/* include trailing \0 in buffer write */
	return write_buffer(fd, fqname, strlen(fqname) + 1, 0);
}
