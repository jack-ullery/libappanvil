/* $Id: parser_main.c 6367 2006-04-04 22:44:04Z sarnold $ */

/*
 *   Copyright (c) 1999, 2000, 2003, 2004, 2005, 2006 NOVELL
 *   (All rights reserved)
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

#define _GNU_SOURCE	/* for strndup, asprintf */

#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <getopt.h>
#include <errno.h>
#include <fcntl.h>
#include <mntent.h>
#include <libintl.h>
#include <locale.h>
#define _(s) gettext(s)

/* enable the following line to get voluminous debug info */
/* #define DEBUG */

#include <unistd.h>
#include <sys/sysctl.h>

#include "parser.h"
#include "parser_version.h"
#include "parser_include.h"

#define MODULE_NAME "apparmor"
#define OLD_MODULE_NAME "subdomain"
#define PROC_MODULES "/proc/modules"
#define DEFAULT_APPARMORFS "/sys/kernel/security/" MODULE_NAME
#define MOUNTED_FS "/proc/mounts"

#define UNPRIVILEGED_OPS (debug || preprocess_only || option == OPTION_STDOUT || names_only || \
			  dump_vars || dump_expanded_vars)

const char *parser_title	= "Novell/SUSE AppArmor parser";
const char *parser_copyright	= "Copyright (C) 1999, 2000, 2003, 2004, 2005, 2006 Novell Inc.";

char *progname;
int force_complain = 0;
int names_only = 0;
int dump_vars = 0;
int dump_expanded_vars = 0;
char *subdomainbase = NULL;
char *profilename;

struct option long_options[] = {
	{"add", 		0, 0, 'a'},
	{"base",		1, 0, 'b'},
	{"debug",		0, 0, 'd'},
	{"subdomainfs",		0, 0, 'f'},
	{"help",		0, 0, 'h'},
	{"replace",		0, 0, 'r'},
	{"reload",		0, 0, 'r'},	/* undocumented reload option == replace */
	{"version",		0, 0, 'v'},
	{"preprocess",		0, 0, 'p'},
	{"complain",		0, 0, 'C'},
	{"dump-variables",	0, 0, 'D'},
	{"dump-expanded-variables",	0, 0, 'E'},
	{"Include",		1, 0, 'I'},
	{"remove",		0, 0, 'R'},
	{"names",		0, 0, 'N'},	/* undocumented only emit profilenames */
	{"stdout",		0, 0, 'S'},
	{NULL, 0, 0, 0},
};

static int debug = 0;

static void display_version(void)
{
	printf("%s version " PARSER_VERSION "\n%s\n", parser_title,
	       parser_copyright);
}

static void display_usage(char *command)
{
	display_version();
	printf("\nUsage: %s [options] [profile]\n\n"
	       "Options:\n"
	       "--------\n"
	       "-a, --add		Add apparmor definitions [default]\n"
	       "-d, --debug 		Debug apparmor definitions\n"
	       "-h, --help		Display this text and exit\n"
	       "-r, --replace		Replace apparmor definitions\n"
	       "-R, --remove		Remove apparmor definitions\n"
	       "-v, --version		Display version info and exit\n"
	       "-p, --preprocess	Preprocess only\n"
	       "-C, --Complain		Force the profile into complain mode\n"
	       "-I n, --Include n	Add n to the search path\n"
	       "-b n, --base n		Set base dir and cwd\n"
	       "-f n, --subdomainfs n	Set location of apparmor filesystem\n"
	       "-S, --stdout		Write output to stdout\n", command);
}

static int process_args(int argc, char *argv[])
{
	int c, o;
	int option = OPTION_ADD;
	int count = 0;

	while ((c = getopt_long(argc, argv, "adf:hrRvpI:b:CNS", long_options, &o)) != -1)
	{
		switch (c) {
		case 0:
			PERROR("Assert, in getopt_long handling\n");
			display_usage(progname);
			exit(0);
			break;
		case 'a':
			count++;
			option = OPTION_ADD;
			break;
		case 'd':
			debug++;
			break;
		case 'h':
			display_usage(progname);
			exit(0);
			break;
		case 'r':
			count++;
			option = OPTION_REPLACE;
			break;
		case 'R':
			count++;
			option = OPTION_REMOVE;
			break;
		case 'v':
			display_version();
			exit(0);
			break;
		case 'p':
			count++;
			preprocess_only = 1;
			break;
		case 'I':
			add_search_dir(optarg);
			break;
		case 'b':
			set_base_dir(optarg);
			break;
		case 'C':
			force_complain = 1;
			break;
		case 'N':
			names_only = 1;
			break;
		case 'S':
			count++;
			option = OPTION_STDOUT;
			break;
		case 'f':
			subdomainbase = strndup(optarg, PATH_MAX);
			break;
		case 'D':
			dump_vars = 1;
			break;
		case 'E':
			dump_expanded_vars = 1;
			break;
		default:
			display_usage(progname);
			exit(0);
			break;
		}
	}

	if (count > 1) {
		PERROR("%s: Too many options given on the command line.\n",
		       progname);
		goto abort;
	}

	PDEBUG("optind = %d argc = %d\n", optind, argc);
	if (optind < argc) {
		/* we only support one profile at a time */
		if (argc - optind == 1) {
			PDEBUG("Using profile in '%s'\n", argv[optind]);
			profilename = strndup(argv[optind], PATH_MAX);
		} else {
			goto abort;
		}
	}

	return option;

abort:
	display_usage(progname);
	exit(1);
}

static inline char *try_subdomainfs_mountpoint(const char *mntpnt,
					       const char *path)
{
	char *proposed_base = NULL;
	char *retval = NULL;
	struct stat buf;

	asprintf(&proposed_base, "%s%s", mntpnt, path);
	if (!proposed_base) {
		PERROR(_("%s: Could not allocate memory for subdomainbase mount point\n"),
		       progname);
		exit(ENOMEM);
	}
	if (stat(proposed_base, &buf) == 0) {
		retval = proposed_base;
	} else {
		free(proposed_base);
	}
	return retval;
}

void find_subdomainfs_mountpoint(void)
{
	FILE *mntfile;
	struct mntent *mntpt;

	if (!(mntfile = setmntent(MOUNTED_FS, "r"))) {
		/* Ugh, what's the right default if you can't open /proc/mounts? */
		PERROR(_("Warning: unable to open %s, attempting to use %s\n"
			 "as the subdomainfs location. Use --subdomainfs to override.\n"),
		       MOUNTED_FS, DEFAULT_APPARMORFS);
		subdomainbase = DEFAULT_APPARMORFS;
		return;
	}

	while ((mntpt = getmntent(mntfile))) {
		char *proposed = NULL;
		if (strcmp(mntpt->mnt_type, "securityfs") == 0) {
			proposed = try_subdomainfs_mountpoint(mntpt->mnt_dir, "/" MODULE_NAME);
			if (proposed != NULL) {
				subdomainbase = proposed;
				break;
			}
			proposed = try_subdomainfs_mountpoint(mntpt->mnt_dir, "/" OLD_MODULE_NAME);
			if (proposed != NULL) {
				subdomainbase = proposed;
				break;
			}
		}
		if (strcmp(mntpt->mnt_type, "subdomainfs") == 0) {
			proposed = try_subdomainfs_mountpoint(mntpt->mnt_dir, "");
			if (proposed != NULL) {
				subdomainbase = proposed;
				break;
			}
		}
	}

	if (!subdomainbase) {
		PERROR(_("Warning: unable to find a suitable fs in %s, is it mounted?\n"
			 "Attempting to use %s as the subdomainfs location.\n"
			 "Use --subdomainfs to override.\n"),
		       MOUNTED_FS, DEFAULT_APPARMORFS);
		subdomainbase = DEFAULT_APPARMORFS;
	}
	endmntent(mntfile);
}

int is_module_loaded(void)
{
	char *query_failed = NULL;
	int module_loaded = 0;
	int mlen = strlen(MODULE_NAME);
	int oldmlen = strlen(OLD_MODULE_NAME);
	FILE *fp;

	fp = fopen(PROC_MODULES, "r");
	if (fp) {
		while (!feof(fp)) {
			const int buflen = 256;
			char buf[buflen];

			if (fgets(buf, buflen, fp)) {
				buf[buflen - 1] = 0;

				if (strncmp(buf, MODULE_NAME, mlen) == 0 &&
				    buf[mlen] == ' ') {
					module_loaded = 1;
				}
				if (strncmp(buf, OLD_MODULE_NAME, oldmlen) == 0 &&
				    buf[oldmlen] == ' ') {
					module_loaded = 1;
				}
			}
		}
		(void)fclose(fp);
	} else {
		query_failed = "unable to open " PROC_MODULES;
	}

	if (query_failed) {
		PERROR(_("%s: Unable to query modules - '%s'\n"
			 "Either modules are disabled or your kernel is"
			 " too old.\n"), progname, query_failed);
		return 1;
	} else if (!module_loaded) {
		PERROR(_("%s: Unable to find " MODULE_NAME "!\n"
			 "Ensure that it has been loaded.\n"), progname);
		return 1;
	}

	return 0;
}

int have_enough_privilege(void)
{
	uid_t uid, euid;

	uid = getuid();
	euid = geteuid();

	if (uid != 0 && euid != 0) {
		PERROR(_("%s: Sorry. You need root privileges to run this program.\n\n"),
		       progname);
		display_usage(progname);
		return EPERM;
	}

	if (uid != 0 && euid == 0) {
		PERROR(_("%s: Warning! You've set this program setuid root.\n"
			 "Anybody who can run this program can update "
			 "your AppArmor profiles.\n\n"), progname);
	}

	return 0;
}

int process_profile(int option, char *profilename)
{
	int retval = 0;

	retval = do_include_preprocessing(profilename);
	if (preprocess_only || retval != 0)
		return retval;

	retval = yyparse();
	if (retval != 0)
		goto out;

	retval = post_process_policy();
  	if (retval != 0) {
  		PERROR(_("%s: Errors found in file. Aborting.\n"), progname);
  		return retval;
  	}

	if (dump_vars) {
		dump_symtab();
		goto out;
	}


	if (dump_expanded_vars) {
		dump_expanded_symtab();
		goto out;
	}

	if (debug > 0) {
		if (debug > 1) {
			printf("----- Debugging built structures -----\n");
			dump_policy();
		}
		goto out;
	}

	if (names_only) {
		dump_policy_names();
		goto out;
	}

	if (!subdomainbase && !preprocess_only && !(option == OPTION_STDOUT))
			find_subdomainfs_mountpoint();

	retval = load_policy(option);

out:
	return retval;
}

int main(int argc, char *argv[])
{
	int retval;
	int option;

	/* name of executable, for error reporting and usage display */
	progname = argv[0];

	init_base_dir();

	option = process_args(argc, argv);

	setlocale(LC_MESSAGES, "");
	bindtextdomain(PACKAGE, LOCALEDIR);
	textdomain(PACKAGE);

	/* Check to see if we have superuser rights, if we're not
	 * debugging */
	if (!(UNPRIVILEGED_OPS) && ((retval = have_enough_privilege()))) {
		return retval;
	}

	/* Check to make sure modules are enabled */
	if (!(UNPRIVILEGED_OPS) && ((retval = is_module_loaded()))) {
		return retval;
	}

	parse_default_paths();
	retval = process_profile(option, profilename);
	if (retval != 0)
		return retval;

	return retval;
}
