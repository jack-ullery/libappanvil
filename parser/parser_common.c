/*
 *   Copyright (c) 2010, 2011
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
 *   along with this program; if not, contact Novell, Inc. or Canonical,
 *   Ltd.
 */
#include <stdlib.h>
#include <stdarg.h>
#include <libintl.h>
#include <locale.h>
#define _(s) gettext(s)
#include "parser.h"

int regex_type = AARE_DFA;
int perms_create = 0;                   /* perms contain create flag */
int net_af_max_override = -1;           /* use kernel to determine af_max */
int kernel_load = 1;
int kernel_supports_network = 1;        /* kernel supports network rules */
int kernel_supports_mount = 0;	        /* kernel supports mount rules */
int flag_changehat_version = FLAG_CHANGEHAT_1_5;
int conf_verbose = 0;
int conf_quiet = 0;
int names_only = 0;
int current_lineno = 1;
int option = OPTION_ADD;

dfaflags_t dfaflags = DFA_CONTROL_TREE_NORMAL | DFA_CONTROL_TREE_SIMPLE | DFA_CONTROL_MINIMIZE | DFA_CONTROL_MINIMIZE_HASH_TRANS;

char *subdomainbase = NULL;
char *progname = __FILE__;
char *profile_namespace = NULL;
char *profilename = NULL;
char *current_filename = NULL;

FILE *ofile = NULL;

#ifdef FORCE_READ_IMPLIES_EXEC
int read_implies_exec = 1;
#else
int read_implies_exec = 0;
#endif

void pwarn(char *fmt, ...)
{
        va_list arg;
        char *newfmt;

        if (conf_quiet || names_only || option == OPTION_REMOVE)
                return;

        if (asprintf(&newfmt, _("Warning from %s (%s%sline %d): %s"),
		     profilename ? profilename : "stdin",
		     current_filename ? current_filename : "",
		     current_filename ? " " : "",
		     current_lineno,
		     fmt) == -1)
                return;

        va_start(arg, fmt);
        vfprintf(stderr, newfmt, arg);
        va_end(arg);

        free(newfmt);
}
