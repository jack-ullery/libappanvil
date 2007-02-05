/* $Id: parser_include.h 8 2006-04-12 04:09:10Z steve-beattie $ */

/*
 *   Copyright (c) 2004, 2005 NOVELL (All rights reserved)
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
 *   along with this program; if not, contact Novell, Inc.
 */

#ifndef PARSER_INCLUDE_H
#define PARSER_INCLUDE_H

extern int preprocess_only;

extern int add_search_dir(char *dir);
extern void init_base_dir(void);
extern void set_base_dir(char *dir);
extern void parse_default_paths(void);
extern int do_include_preprocessing(char *profilename);

#endif
