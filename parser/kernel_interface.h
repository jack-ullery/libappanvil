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

#ifndef __AA_KERNEL_INTERFACE_H
#define __AA_KERNEL_INTERFACE_H

int aa_find_iface_dir(char **dir);
int aa_kernel_interface_load_policy(const char *buffer, size_t size);
int aa_kernel_interface_load_policy_from_file(const char *path);
int aa_kernel_interface_load_policy_from_fd(int fd);
int aa_kernel_interface_replace_policy(const char *buffer, size_t size);
int aa_kernel_interface_replace_policy_from_file(const char *path);
int aa_kernel_interface_replace_policy_from_fd(int fd);
int aa_kernel_interface_remove_policy(const char *fqname);
int aa_kernel_interface_write_policy(int fd, const char *buffer, size_t size);

#endif /* __AA_KERNEL_INTERFACE_H */
