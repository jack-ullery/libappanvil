/* $Id$ */

/*
 *   Copyright (c) 1999, 2000, 2001, 2002, 2003, 2004, 2005, 2006, 2007
 *   NOVELL (All rights reserved)
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
#include <stdarg.h>
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
#define MATCH_STRING "/sys/kernel/security/" MODULE_NAME "/matching"
#define MOUNTED_FS "/proc/mounts"
#define PCRE "pattern=pcre"
#define AADFA "pattern=aadfa"

#define UNPRIVILEGED_OPS (debug || preprocess_only || option == OPTION_STDOUT || names_only || \
			  dump_vars || dump_expanded_vars)

const char *parser_title	= "Novell/SUSE AppArmor parser";
const char *parser_copyright	= "Copyright (C) 1999, 2000, 2003, 2004, 2005, 2006 Novell Inc.";

char *progname;
int option = OPTION_ADD;
int force_complain = 0;
int binary_input = 0;
int names_only = 0;
int dump_vars = 0;
int dump_expanded_vars = 0;
int conf_quiet = 0;
char *subdomainbase = NULL;
char *profilename;
char *match_string = NULL;
int regex_type = AARE_DFA;
char *profile_namespace = NULL;

extern int current_lineno;

struct option long_options[] = {
	{"add", 		0, 0, 'a'},
	{"binary",		0, 0, 'B'},
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
	{"names",		0, 0, 'N'},
	{"stdout",		0, 0, 'S'},
	{"match-string",	1, 0, 'm'},
	{"quiet",		0, 0, 'q'},
	{"namespace",		1, 0, 'n'},
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
	       "-r, --replace		Replace apparmor definitions\n"
	       "-R, --remove		Remove apparmor definitions\n"
	       "-C, --Complain		Force the profile into complain mode\n"
	       "-B, --binary		Input is precompiled profile\n"
	       "-p, --preprocess	Dump profiles with includes expanded\n"
	       "-N, --names		Dump names of profiles in input.\n"
	       "-S, --stdout		Dump compiled profile to stdout\n"
	       "-b n, --base n		Set base dir and cwd\n"
	       "-I n, --Include n	Add n to the search path\n"
	       "-f n, --subdomainfs n	Set location of apparmor filesystem\n"
	       "-m n, --match-string n  Use only match features n\n"
	       "-n n, --namespace n	Set Namespace for the profile\n"
	       "-q, --quiet		Don't emit warnings\n"
	       "-v, --version		Display version info and exit\n"
	       "-d, --debug 		Debug apparmor definitions\n"
	       "-h, --help		Display this text and exit\n"
	       ,command);
}

void pwarn(char *fmt, ...)
{
	va_list arg;
	char *newfmt;
	int rc;

	if (conf_quiet || names_only || option == OPTION_REMOVE)
		return;

	rc = asprintf(&newfmt, _("Warning (%s line %d): %s"),
		      profilename ? profilename : "stdin",
		      current_lineno,
		      fmt);
	if (!newfmt)
		return;

	va_start(arg, fmt);
	vfprintf(stderr, newfmt, arg);
	va_end(arg);
}

static int process_args(int argc, char *argv[])
{
	int c, o;
	int count = 0;
	option = OPTION_ADD;

	while ((c = getopt_long(argc, argv, "adf:hrRvpI:b:BCNSm:qn:", long_options, &o)) != -1)
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
		case 'B':
			binary_input =1;
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
		case 'm':
			match_string = strdup(optarg);
			break;
		case 'q':
			conf_quiet = 1;
			break;
		case 'n':
			profile_namespace = strdup(optarg);
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

	if (asprintf(&proposed_base, "%s%s", mntpnt, path)<0 || !proposed_base) {
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

int find_subdomainfs_mountpoint(void)
{
	FILE *mntfile;
	struct mntent *mntpt;

	if ((mntfile = setmntent(MOUNTED_FS, "r"))) {
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
		endmntent(mntfile);
	}

	if (!subdomainbase) {
		struct stat buf;
		if (stat(DEFAULT_APPARMORFS, &buf) == -1) {
		PERROR(_("Warning: unable to find a suitable fs in %s, is it "
			 "mounted?\nUse --subdomainfs to override.\n"),
		       MOUNTED_FS);
		} else {
			subdomainbase = DEFAULT_APPARMORFS;
		}
	}

	return (subdomainbase == NULL);
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

/* match_string == NULL --> no match_string available
   match_string != NULL --> either a matching string specified on the
   command line, or the kernel supplied a match string */
static void get_match_string(void) {

	FILE *ms = NULL;

	/* has process_args() already assigned a match string? */
	if (match_string)
		goto out;

	ms = fopen(MATCH_STRING, "r");
	if (!ms)
		return;

	match_string = malloc(1000);
	if (!match_string) {
		goto out;
	}

	if (!fgets(match_string, 1000, ms)) {
		free(match_string);
		match_string = NULL;
	}

out:
	if (match_string) {
		if (strstr(match_string, PCRE))
			regex_type = AARE_PCRE;

		if (strstr(match_string, AADFA))
			regex_type = AARE_DFA;
	}

	if (ms)
		fclose(ms);
	return;
}

/* return 1 --> PCRE should work fine
   return 0 --> no PCRE support */
static int regex_support(void) {
	/* no match string, predates (or postdates?) the split matching
	module design */
	if (!match_string)
		return 1;

	if (regex_type != AARE_NONE)
		return 1;

	return 0;
}

int process_binary(int option, char *profilename)
{
	char *buffer = NULL;
	int retval = 0, size = 0, asize = 0, rsize;
	int chunksize = 1 << 14;
	int fd;

	if (profilename) {
		fd = open(profilename, O_RDONLY);
		if (fd == -1) {
			PERROR(_("Error: Could not read profile %s: %s.\n"),
			       profilename, strerror(errno));
			exit(errno);
		}
	} else {
		fd = dup(0);
	}

	do {
		if (asize - size == 0) {
			buffer = realloc(buffer, chunksize);
			asize = chunksize;
			chunksize <<= 1;
			if (!buffer) {
				PERROR(_("Memory allocation error."));
				exit(errno);
			}
		}

		rsize = read(fd, buffer + size, asize - size);
		if (rsize)
			size += rsize;
	} while (rsize > 0);

	close(fd);

	if (rsize == 0)
		retval = sd_load_buffer(option, buffer, size);
	else
		retval = rsize;

	free(buffer);

	return retval;
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

	if (names_only) {
		dump_policy_names();
		goto out;
	}

	/* Get the match string to determine type of regex support needed */
	get_match_string();

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

	if (!regex_support()) {
		die_if_any_regex();
	}

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

	/* Check to make sure there is an interface to load policy */
	if (!(UNPRIVILEGED_OPS) && (subdomainbase == NULL) &&
	    (retval = find_subdomainfs_mountpoint())) {
		return retval;
	}

	if (binary_input) {
		retval = process_binary(option, profilename);
	} else {
		parse_default_paths();
		retval = process_profile(option, profilename);
	}

	return retval;
}
