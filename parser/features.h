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

#ifndef __AA_FEATURES_H
#define __AA_FEATURES_H

typedef struct aa_features aa_features;

int aa_features_new(aa_features **features, const char *path);
int aa_features_new_from_string(aa_features **features,
				const char *string, size_t size);
int aa_features_new_from_kernel(aa_features **features);
aa_features *aa_features_ref(aa_features *features);
void aa_features_unref(aa_features *features);
const char *aa_features_get_string(aa_features *features);
bool aa_features_is_equal(aa_features *features1, aa_features *features2);
bool aa_features_supports(aa_features *features, const char *str);

#endif /* __AA_FEATURES_H */
