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

static int write_buffer(int fd, const char *buffer, int size)
{
	int wsize = write(fd, buffer, size);
	if (wsize < 0) {
		return -1;
	} else if (wsize < size) {
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
		rc = write_buffer(fd, buffer, size);
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
			if (write_buffer(fd, b, bsize) == -1)
				return -1;
		}
	}

	if (rc)
		return -1;

	return 0;
}

#define AA_IFACE_FILE_LOAD	".load"
#define AA_IFACE_FILE_REMOVE	".remove"
#define AA_IFACE_FILE_REPLACE	".replace"

static int write_policy_buffer_to_iface(const char *iface_file,
					const char *buffer, size_t size)
{
	autoclose int dirfd = -1;
	autoclose int fd = -1;

	dirfd = open_iface_dir();
	if (dirfd == -1)
		return -1;

	fd = openat(dirfd, iface_file, O_WRONLY | O_CLOEXEC);
	if (fd == -1)
		return -1;

	return write_policy_buffer(fd, kernel_supports_setload, buffer, size);
}

static int write_policy_fd_to_iface(const char *iface_file, int fd)
{
	autofree char *buffer = NULL;
	int size = 0, asize = 0, rsize;
	int chunksize = 1 << 14;

	do {
		if (asize - size == 0) {
			buffer = (char *) realloc(buffer, chunksize);
			asize = chunksize;
			chunksize <<= 1;
			if (!buffer) {
				errno = ENOMEM;
				return -1;
			}
		}

		rsize = read(fd, buffer + size, asize - size);
		if (rsize)
			size += rsize;
	} while (rsize > 0);

	if (rsize == -1)
		return -1;

	return write_policy_buffer_to_iface(iface_file, buffer, size);
}

static int write_policy_file_to_iface(const char *iface_file, const char *path)
{
	autoclose int fd;

	fd = open(path, O_RDONLY);
	if (fd == -1)
		return -1;

	return write_policy_fd_to_iface(iface_file, fd);
}

/**
 * aa_kernel_interface_load_policy - load a policy into the kernel
 * @buffer: a buffer containing a policy
 * @size: the size of the buffer
 *
 * Returns: 0 on success, -1 on error with errno set
 */
int aa_kernel_interface_load_policy(const char *buffer, size_t size)
{
	return write_policy_buffer_to_iface(AA_IFACE_FILE_LOAD, buffer, size);
}

/**
 * aa_kernel_interface_load_policy_from_file - load a policy into the kernel
 * @path: path to a policy binary
 *
 * Returns: 0 on success, -1 on error with errno set
 */
int aa_kernel_interface_load_policy_from_file(const char *path)
{
	return write_policy_file_to_iface(AA_IFACE_FILE_LOAD, path);
}

/**
 * aa_kernel_interface_load_policy_from_fd - load a policy into the kernel
 * @fd: a pre-opened, readable file descriptor at the correct offset
 *
 * Returns: 0 on success, -1 on error with errno set
 */
int aa_kernel_interface_load_policy_from_fd(int fd)
{
	return write_policy_fd_to_iface(AA_IFACE_FILE_LOAD, fd);
}

/**
 * aa_kernel_interface_replace_policy - replace a policy in the kernel
 * @buffer: a buffer containing a policy
 * @size: the size of the buffer
 *
 * Returns: 0 on success, -1 on error with errno set
 */
int aa_kernel_interface_replace_policy(const char *buffer, size_t size)
{
	return write_policy_buffer_to_iface(AA_IFACE_FILE_REPLACE,
					    buffer, size);
}

/**
 * aa_kernel_interface_replace_policy_from_file - replace a policy in the kernel
 * @path: path to a policy binary
 *
 * Returns: 0 on success, -1 on error with errno set
 */
int aa_kernel_interface_replace_policy_from_file(const char *path)
{
	return write_policy_file_to_iface(AA_IFACE_FILE_REPLACE, path);
}

/**
 * aa_kernel_interface_replace_policy_from_fd - replace a policy in the kernel
 * @fd: a pre-opened, readable file descriptor at the correct offset
 *
 * Returns: 0 on success, -1 on error with errno set
 */
int aa_kernel_interface_replace_policy_from_fd(int fd)
{
	return write_policy_fd_to_iface(AA_IFACE_FILE_REPLACE, fd);
}

/**
 * aa_kernel_interface_remove_policy - remove a policy from the kernel
 * @fqname: nul-terminated fully qualified name of the policy to remove
 *
 * Returns: 0 on success, -1 on error with errno set
 */
int aa_kernel_interface_remove_policy(const char *fqname)
{
	return write_policy_buffer_to_iface(AA_IFACE_FILE_REMOVE,
					    fqname, strlen(fqname) + 1);
}

/**
 * aa_kernel_interface_write_policy - write a policy to a file descriptor
 * @fd: a pre-opened, writeable file descriptor at the correct offset
 * @buffer: a buffer containing a policy
 * @size: the size of the buffer
 *
 * Returns: 0 on success, -1 on error with errno set
 */
int aa_kernel_interface_write_policy(int fd, const char *buffer, size_t size)
{
	return write_policy_buffer(fd, 1, buffer, size);
}
