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

#include "features.h"

typedef struct aa_kernel_interface aa_kernel_interface;

int aa_kernel_interface_new(aa_kernel_interface **kernel_interface,
			    aa_features *kernel_features,
			    const char *apparmorfs);
aa_kernel_interface *aa_kernel_interface_ref(aa_kernel_interface *kernel_interface);
void aa_kernel_interface_unref(aa_kernel_interface *kernel_interface);

int aa_kernel_interface_load_policy(aa_kernel_interface *kernel_interface,
				    const char *buffer, size_t size);
int aa_kernel_interface_load_policy_from_file(aa_kernel_interface *kernel_interface,
					      const char *path);
int aa_kernel_interface_load_policy_from_fd(aa_kernel_interface *kernel_interface,
					    int fd);
int aa_kernel_interface_replace_policy(aa_kernel_interface *kernel_interface,
				       const char *buffer, size_t size);
int aa_kernel_interface_replace_policy_from_file(aa_kernel_interface *kernel_interface,
						 const char *path);
int aa_kernel_interface_replace_policy_from_fd(aa_kernel_interface *kernel_interface,
					       int fd);
int aa_kernel_interface_remove_policy(aa_kernel_interface *kernel_interface,
				      const char *fqname);
int aa_kernel_interface_write_policy(int fd, const char *buffer, size_t size);

#endif /* __AA_KERNEL_INTERFACE_H */
