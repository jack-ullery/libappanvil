/*
 *   Copyright (c) 1999, 2000, 2001, 2002, 2003, 2004, 2005, 2006, 2007
 *   NOVELL (All rights reserved)
 *
 *   Copyright (c) 2010 - 2013
 *   Canonical Ltd. (All rights reserved)
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

#include <ctype.h>
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <stdarg.h>
#include <stddef.h>
#include <getopt.h>
#include <errno.h>
#include <fcntl.h>
#include <dirent.h>

/* enable the following line to get voluminous debug info */
/* #define DEBUG */

#include <unistd.h>
#include <limits.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <sys/apparmor.h>

#include "lib.h"
#include "features.h"
#include "kernel_interface.h"
#include "parser.h"
#include "parser_version.h"
#include "parser_include.h"
#include "common_optarg.h"
#include "policy_cache.h"
#include "libapparmor_re/apparmor_re.h"

#define OLD_MODULE_NAME "subdomain"
#define PROC_MODULES "/proc/modules"
#define MATCH_FILE "/sys/kernel/security/" MODULE_NAME "/matching"
#define MOUNTED_FS "/proc/mounts"
#define AADFA "pattern=aadfa"

#define PRIVILEGED_OPS (kernel_load)
#define UNPRIVILEGED_OPS (!(PRIVILEGED_OPS))

const char *parser_title	= "AppArmor parser";
const char *parser_copyright	= "Copyright (C) 1999-2008 Novell Inc.\nCopyright 2009-2012 Canonical Ltd.";

int opt_force_complain = 0;
int binary_input = 0;
int dump_vars = 0;
int dump_expanded_vars = 0;
int show_cache = 0;
int skip_cache = 0;
int skip_read_cache = 0;
int write_cache = 0;
int cond_clear_cache = 1;		/* only applies if write is set */
int force_clear_cache = 0;		/* force clearing regargless of state */
int create_cache_dir = 0;		/* create the cache dir if missing? */
int preprocess_only = 0;
int skip_mode_force = 0;
int abort_on_error = 0;			/* stop processing profiles if error */
int skip_bad_cache_rebuild = 0;
int mru_skip_cache = 1;
int debug_cache = 0;
struct timespec mru_tstamp;

static char *cacheloc = NULL;

/* Make sure to update BOTH the short and long_options */
static const char *short_options = "adf:h::rRVvI:b:BCD:NSm:M:qQn:XKTWkL:O:po:";
struct option long_options[] = {
	{"add", 		0, 0, 'a'},
	{"binary",		0, 0, 'B'},
	{"base",		1, 0, 'b'},
	{"subdomainfs",		1, 0, 'f'},
	{"help",		2, 0, 'h'},
	{"replace",		0, 0, 'r'},
	{"reload",		0, 0, 'r'},	/* undocumented reload option == replace */
	{"version",		0, 0, 'V'},
	{"complain",		0, 0, 'C'},
	{"Complain",		0, 0, 'C'},	/* Erk, apparently documented as --Complain */
	{"Include",		1, 0, 'I'},
	{"remove",		0, 0, 'R'},
	{"names",		0, 0, 'N'},
	{"stdout",		0, 0, 'S'},
	{"ofile",		1, 0, 'o'},
	{"match-string",	1, 0, 'm'},
	{"features-file",	1, 0, 'M'},
	{"quiet",		0, 0, 'q'},
	{"skip-kernel-load",	0, 0, 'Q'},
	{"verbose",		0, 0, 'v'},
	{"namespace",		1, 0, 'n'},
	{"readimpliesX",	0, 0, 'X'},
	{"skip-cache",		0, 0, 'K'},
	{"skip-read-cache",	0, 0, 'T'},
	{"write-cache",		0, 0, 'W'},
	{"show-cache",		0, 0, 'k'},
	{"skip-bad-cache",	0, 0, 129},	/* no short option */
	{"purge-cache",		0, 0, 130},	/* no short option */
	{"create-cache-dir",	0, 0, 131},	/* no short option */
	{"cache-loc",		1, 0, 'L'},
	{"debug",		0, 0, 'd'},
	{"dump",		1, 0, 'D'},
	{"Dump",		1, 0, 'D'},
	{"optimize",		1, 0, 'O'},
	{"Optimize",		1, 0, 'O'},
	{"preprocess",		0, 0, 'p'},
	{"abort-on-error",	0, 0, 132},	/* no short option */
	{"skip-bad-cache-rebuild",	0, 0, 133},	/* no short option */
	{"warn",		1, 0, 134},	/* no short option */
	{"debug-cache",		0, 0, 135},	/* no short option */
	{NULL, 0, 0, 0},
};

static int debug = 0;

void display_version(void)
{
	printf("%s version " PARSER_VERSION "\n%s\n", parser_title,
	       parser_copyright);
}

static void display_usage(const char *command)
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
	       "-N, --names		Dump names of profiles in input.\n"
	       "-S, --stdout		Dump compiled profile to stdout\n"
	       "-o n, --ofile n		Write output to file n\n"
	       "-b n, --base n		Set base dir and cwd\n"
	       "-I n, --Include n	Add n to the search path\n"
	       "-f n, --subdomainfs n	Set location of apparmor filesystem\n"
	       "-m n, --match-string n  Use only features n\n"
	       "-M n, --features-file n Use only features in file n\n"
	       "-n n, --namespace n	Set Namespace for the profile\n"
	       "-X, --readimpliesX	Map profile read permissions to mr\n"
	       "-k, --show-cache	Report cache hit/miss details\n"
	       "-K, --skip-cache	Do not attempt to load or save cached profiles\n"
	       "-T, --skip-read-cache	Do not attempt to load cached profiles\n"
	       "-W, --write-cache	Save cached profile (force with -T)\n"
	       "    --skip-bad-cache	Don't clear cache if out of sync\n"
	       "    --purge-cache	Clear cache regardless of its state\n"
	       "    --create-cache-dir	Create the cache dir if missing\n"
	       "    --debug-cache       Debug cache file checks\n"
	       "-L, --cache-loc n	Set the location of the profile cache\n"
	       "-q, --quiet		Don't emit warnings\n"
	       "-v, --verbose		Show profile names as they load\n"
	       "-Q, --skip-kernel-load	Do everything except loading into kernel\n"
	       "-V, --version		Display version info and exit\n"
	       "-d, --debug 		Debug apparmor definitions\n"
	       "-p, --preprocess	Dump preprocessed profile\n"
	       "-D [n], --dump		Dump internal info for debugging\n"
	       "-O [n], --Optimize	Control dfa optimizations\n"
	       "-h [cmd], --help[=cmd]  Display this text or info about cmd\n"
	       "--abort-on-error	Abort processing of profiles on first error\n"
	       "--skip-bad-cache-rebuild Do not try rebuilding the cache if it is rejected by the kernel\n"
	       "--warn n		Enable warnings (see --help=warn)\n"
	       ,command);
}

optflag_table_t warnflag_table[] = {
	{ 0, "rule-not-enforced", "warn if a rule is not enforced", WARN_RULE_NOT_ENFORCED },
	{ 0, "rule-downgraded", "warn if a rule is downgraded to a lesser but still enforcing rule", WARN_RULE_DOWNGRADED },
	{ 0, NULL, NULL, 0 },
};

void display_warn(const char *command)
{
	display_version();
	printf("\n%s: --warn [Option]\n\n"
	       "Options:\n"
	       "--------\n"
	       ,command);
	print_flag_table(warnflag_table);
}

/* Treat conf file like options passed on command line
 */
static int getopt_long_file(FILE *f, const struct option *longopts,
			    char **optarg, int *longindex)
{
	static char line[256];
	char *pos, *opt, *save;
	int i;

	for (;;) {
		if (!fgets(line, 256, f))
			return -1;
		pos = line;
		while (isblank(*pos))
			pos++;
		if (*pos == '#')
			continue;
		opt = strtok_r(pos, " \t\r\n=", &save);
		/* blank line */
		if (!opt)
			continue;

		for (i = 0; longopts[i].name &&
			     strcmp(longopts[i].name, opt) != 0; i++) ;
		if (!longopts[i].name) {
			PERROR("%s: unknown option (%s) in config file.\n",
			       progname, opt);
			/* skip it */
			continue;
		}
		break;
	}

	if (longindex)
		*longindex = i;

	if (*save) {
		int len;
		while(isblank(*save))
			save++;
		len = strlen(save) - 1;
		if (save[len] == '\n')
			save[len] = 0;
	}

	switch (longopts[i].has_arg) {
	case 0:
		*optarg = NULL;
		break;
	case 1:
		if (!strlen(save)) {
			*optarg = NULL;
			return '?';
		}
		*optarg = save;
		break;
	case 2:
		*optarg = save;
		break;
	default:
		PERROR("%s: internal error bad longopt value\n", progname);
		exit(1);
	}

	if (longopts[i].flag == NULL)
		return longopts[i].val;
	else
		*longopts[i].flag = longopts[i].val;
	return 0;
}

/* process a single argment from getopt_long
 * Returns: 1 if an action arg, else 0
 */
static int process_arg(int c, char *optarg)
{
	int count = 0;

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
		skip_read_cache = 1;
		break;
	case 'h':
		if (!optarg) {
			display_usage(progname);
		} else if (strcmp(optarg, "Dump") == 0 ||
			   strcmp(optarg, "dump") == 0 ||
			   strcmp(optarg, "D") == 0) {
			display_dump(progname);
		} else if (strcmp(optarg, "Optimize") == 0 ||
			   strcmp(optarg, "optimize") == 0 ||
			   strcmp(optarg, "O") == 0) {
			display_optimize(progname);
		} else if (strcmp(optarg, "warn") == 0) {
			display_warn(progname);
		} else {
			PERROR("%s: Invalid --help option %s\n",
			       progname, optarg);
			exit(1);
		}
		exit(0);
		break;
	case 'r':
		count++;
		option = OPTION_REPLACE;
		break;
	case 'R':
		count++;
		option = OPTION_REMOVE;
		skip_cache = 1;
		break;
	case 'V':
		display_version();
		exit(0);
		break;
	case 'I':
		add_search_dir(optarg);
		break;
	case 'b':
		set_base_dir(optarg);
		break;
	case 'B':
		binary_input = 1;
		skip_cache = 1;
		break;
	case 'C':
		opt_force_complain = 1;
		skip_cache = 1;
		break;
	case 'N':
		count++;
		names_only = 1;
		skip_cache = 1;
		kernel_load = 0;
		break;
	case 'S':
		count++;
		option = OPTION_STDOUT;
		skip_read_cache = 1;
		kernel_load = 0;
		break;
	case 'o':
		count++;
		option = OPTION_OFILE;
		skip_read_cache = 1;
		kernel_load = 0;
		ofile = fopen(optarg, "w");
		if (!ofile) {
			PERROR("%s: Could not open file %s\n",
			       progname, optarg);
			exit(1);
		}
		break;
	case 'f':
		subdomainbase = strndup(optarg, PATH_MAX);
		break;
	case 'D':
		skip_read_cache = 1;
		if (!optarg) {
			dump_vars = 1;
		} else if (strcmp(optarg, "variables") == 0) {
			dump_vars = 1;
		} else if (strcmp(optarg, "expanded-variables") == 0) {
			dump_expanded_vars = 1;
		} else if (!handle_flag_table(dumpflag_table, optarg,
					      &dfaflags)) {
			PERROR("%s: Invalid --Dump option %s\n",
			       progname, optarg);
			exit(1);
		}
		break;
	case 'O':
		skip_read_cache = 1;

		if (!handle_flag_table(optflag_table, optarg,
				       &dfaflags)) {
			PERROR("%s: Invalid --Optimize option %s\n",
			       progname, optarg);
			exit(1);
		}
		break;
	case 'm':
		features_string = strdup(optarg);
		break;
	case 'M':
		if (load_features(optarg) == -1) {
			fprintf(stderr, "Failed to load features from '%s'\n",
				optarg);
			exit(1);
		}
		break;
	case 'q':
		conf_verbose = 0;
		conf_quiet = 1;
		warnflags = 0;
		break;
	case 'v':
		conf_verbose = 1;
		conf_quiet = 0;
		break;
	case 'n':
		profile_ns = strdup(optarg);
		break;
	case 'X':
		read_implies_exec = 1;
		break;
	case 'K':
		skip_cache = 1;
		break;
	case 'k':
		show_cache = 1;
		break;
	case 'W':
		write_cache = 1;
		break;
	case 'T':
		skip_read_cache = 1;
		break;
	case 129:
		cond_clear_cache = 0;
		break;
	case 130:
		force_clear_cache = 1;
		break;
	case 131:
		create_cache_dir = 1;
		break;
	case 132:
		abort_on_error = 1;
		break;
	case 133:
		skip_bad_cache_rebuild = 1;
		break;
	case 'L':
		cacheloc = strdup(optarg);
		break;
	case 'Q':
		kernel_load = 0;
		break;
	case 'p':
		count++;
		kernel_load = 0;
		skip_cache = 1;
		preprocess_only = 1;
		skip_mode_force = 1;
		break;
	case 134:
		if (!handle_flag_table(warnflag_table, optarg,
				       &warnflags)) {
			PERROR("%s: Invalid --warn option %s\n",
			       progname, optarg);
			exit(1);
		}
		break;
	case 135:
		debug_cache = 1;
		break;
	default:
		display_usage(progname);
		exit(1);
		break;
	}

	return count;
}

static int process_args(int argc, char *argv[])
{
	int c, o;
	int count = 0;
	option = OPTION_ADD;

	while ((c = getopt_long(argc, argv, short_options, long_options, &o)) != -1)
	{
		count += process_arg(c, optarg);
	}

	if (count > 1) {
		PERROR("%s: Too many actions given on the command line.\n",
		       progname);
		display_usage(progname);
		exit(1);
	}

	PDEBUG("optind = %d argc = %d\n", optind, argc);
	return optind;
}

static int process_config_file(const char *name)
{
	char *optarg;
	autofclose FILE *f = NULL;
	int c, o;

	f = fopen(name, "r");
	if (!f)
		return 0;

	while ((c = getopt_long_file(f, long_options, &optarg, &o)) != -1)
		process_arg(c, optarg);
	return 1;
}


int find_subdomainfs_mountpoint(void)
{
	if (aa_find_iface_dir(&subdomainbase) == -1) {
		PERROR(_("Warning: unable to find a suitable fs in %s, is it "
			 "mounted?\nUse --subdomainfs to override.\n"),
		       MOUNTED_FS);
		return false;
	}

	return true;
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

static void set_features_by_match_file(void)
{
	autofclose FILE *ms = fopen(MATCH_FILE, "r");
	if (ms) {
		autofree char *match_string = (char *) malloc(1000);
		if (!match_string)
			goto no_match;
		if (!fgets(match_string, 1000, ms))
			goto no_match;
		if (strstr(match_string, " perms=c"))
			perms_create = 1;
		kernel_supports_network = 1;
		return;
	}
no_match:
	perms_create = 1;
}

static void set_supported_features(void) {

	/* has process_args() already assigned a match string? */
	if (!features_string) {
		if (load_features(FEATURES_FILE) == -1) {
			set_features_by_match_file();
			return;
		}
	}

	perms_create = 1;

	/* TODO: make this real parsing and config setting */
	if (strstr(features_string, "file {"))	/* pre policydb is file= */
		kernel_supports_policydb = 1;
	if (strstr(features_string, "v6"))
		kernel_abi_version = 6;
	if (strstr(features_string, "v7"))
		kernel_abi_version = 7;
	if (strstr(features_string, "set_load"))
		kernel_supports_setload = 1;
	if (strstr(features_string, "network"))
		kernel_supports_network = 1;
	if (strstr(features_string, "af_unix"))
		kernel_supports_unix = 1;
	if (strstr(features_string, "mount"))
		kernel_supports_mount = 1;
	if (strstr(features_string, "dbus"))
		kernel_supports_dbus = 1;
	if (strstr(features_string, "signal"))
		kernel_supports_signal = 1;
	if (strstr(features_string, "ptrace {"))
		kernel_supports_ptrace = 1;
	if (strstr(features_string, "diff_encode"))
		kernel_supports_diff_encode = 1;
	else if (dfaflags & DFA_CONTROL_DIFF_ENCODE)
		/* clear diff_encode because it is not supported */
		dfaflags &= ~DFA_CONTROL_DIFF_ENCODE;
}

int process_binary(int option, const char *profilename)
{
	autofree char *buffer = NULL;
	int retval = 0, size = 0, asize = 0, rsize;
	int chunksize = 1 << 14;
	autoclose int fd = -1;

	if (profilename) {
		fd = open(profilename, O_RDONLY);
		if (fd == -1) {
			retval = errno;
			PERROR(_("Error: Could not read binary profile or cache file %s: %s.\n"),
			       profilename, strerror(errno));
			return retval;
		}
	} else {
		fd = dup(0);
	}

	do {
		if (asize - size == 0) {
			buffer = (char *) realloc(buffer, chunksize);
			asize = chunksize;
			chunksize <<= 1;
			if (!buffer) {
				PERROR(_("Memory allocation error."));
				return ENOMEM;
			}
		}

		rsize = read(fd, buffer + size, asize - size);
		if (rsize)
			size += rsize;
	} while (rsize > 0);

	if (rsize == 0) {
		retval = aa_load_buffer(option, buffer, size);
		if (retval == -1)
			retval = -errno;
	} else
		retval = rsize;

	if (conf_verbose) {
		switch (option) {
		case OPTION_ADD:
			printf(_("Cached load succeeded for \"%s\".\n"),
			       profilename ? profilename : "stdin");
			break;
		case OPTION_REPLACE:
			printf(_("Cached reload succeeded for \"%s\".\n"),
			       profilename ? profilename : "stdin");
			break;
		default:
			break;
		}
	}

	return retval;
}

void reset_parser(const char *filename)
{
	memset(&mru_tstamp, 0, sizeof(mru_tstamp));
	mru_skip_cache = 1;
	free_aliases();
	free_symtabs();
	free_policies();
	reset_regex();
	reset_include_stack(filename);
}

int test_for_dir_mode(const char *basename, const char *linkdir)
{
	int rc = 0;

	if (!skip_mode_force) {
		autofree char *target = NULL;
		if (asprintf(&target, "%s/%s/%s", basedir, linkdir, basename) < 0) {
			perror("asprintf");
			exit(1);
		}

		if (access(target, R_OK) == 0)
			rc = 1;
	}

	return rc;
}

int process_profile(int option, const char *profilename, const char *cachedir)
{
	int retval = 0;
	autofree const char *cachename = NULL;
	autofree const char *cachetmpname = NULL;
	autoclose int cachetmp = -1;
	const char *basename = NULL;

	/* per-profile states */
	force_complain = opt_force_complain;

	if (profilename) {
		if ( !(yyin = fopen(profilename, "r")) ) {
			PERROR(_("Error: Could not read profile %s: %s.\n"),
			       profilename, strerror(errno));
			return errno;
		}
	} else {
		pwarn("%s: cannot use or update cache, disable, or force-complain via stdin\n", progname);
	}

	reset_parser(profilename);

	if (profilename && option != OPTION_REMOVE) {
		/* make decisions about disabled or complain-mode profiles */
		basename = strrchr(profilename, '/');
		if (basename)
			basename++;
		else
			basename = profilename;

		if (test_for_dir_mode(basename, "disable")) {
 			if (!conf_quiet)
 				PERROR("Skipping profile in %s/disable: %s\n", basedir, basename);
			goto out;
		}

		if (test_for_dir_mode(basename, "force-complain")) {
			PERROR("Warning: found %s in %s/force-complain, forcing complain mode\n", basename, basedir);
 			force_complain = 1;
 		}

		/* setup cachename and tstamp */
		if (!force_complain && !skip_cache) {
			cachename = cache_filename(cachedir, basename);
			valid_read_cache(cachename);
		}

	}

	if (yyin) {
		yyrestart(yyin);
		update_mru_tstamp(yyin, profilename ? profilename : "stdin");
	}

	retval = yyparse();
	if (retval != 0)
		goto out;

	/* Test to see if profile is for another namespace, if so disable
	 * caching for now
	 * TODO: Add support for caching profiles in an alternate namespace
	 * TODO: Add support for embedded namespace defines if they aren't
	 *       removed from the language.
	 * TODO: test profile->ns NOT profile_ns (must be after parse)
	 */
	if (profile_ns)
		skip_cache = 1;

	if (cachename) {
		/* Load a binary cache if it exists and is newest */
		if (cache_hit(cachename)) {
			retval = process_binary(option, cachename);
			if (!retval || skip_bad_cache_rebuild)
				return retval;
		}

		cachetmp = setup_cache_tmp(&cachetmpname, cachename);
	}

	if (show_cache)
		PERROR("Cache miss: %s\n", profilename ? profilename : "stdin");

	if (preprocess_only)
		goto out;

	if (names_only) {
		dump_policy_names();
		goto out;
	}

	if (dump_vars) {
		dump_symtab();
		goto out;
	}

	retval = post_process_policy(debug);
  	if (retval != 0) {
  		PERROR(_("%s: Errors found in file. Aborting.\n"), progname);
		goto out;
  	}

	if (dump_expanded_vars) {
		dump_expanded_symtab();
		goto out;
	}

	if (debug > 0) {
		printf("----- Debugging built structures -----\n");
		dump_policy();
		goto out;
	}

	/* cache file generated by load_policy */
	retval = load_policy(option, cachetmp);
	if (retval == 0 && write_cache) {
		if (cachetmp == -1) {
			unlink(cachetmpname);
			PERROR("Warning failed to create cache: %s\n",
			       basename);
		} else {
			install_cache(cachetmpname, cachename);
		}
	}
out:

	return retval;
}

struct dir_cb_data {
	const char *dirname;	/* name of the parent dir */
	const char *cachedir;	/* path to the cache sub directory */
};

/* data - pointer to a dir_cb_data */
static int profile_dir_cb(DIR *dir unused, const char *name, struct stat *st,
			  void *data)
{
	int rc = 0;

	if (!S_ISDIR(st->st_mode) && !is_blacklisted(name, NULL)) {
		struct dir_cb_data *cb_data = (struct dir_cb_data *)data;
		autofree char *path = NULL;
		if (asprintf(&path, "%s/%s", cb_data->dirname, name) < 0)
			PERROR(_("Out of memory"));
		rc = process_profile(option, path, cb_data->cachedir);
	}
	return rc;
}

/* data - pointer to a dir_cb_data */
static int binary_dir_cb(DIR *dir unused, const char *name, struct stat *st,
			 void *data)
{
	int rc = 0;

	if (!S_ISDIR(st->st_mode) && !is_blacklisted(name, NULL)) {
		struct dir_cb_data *cb_data = (struct dir_cb_data *)data;
		autofree char *path = NULL;
		if (asprintf(&path, "%s/%s", cb_data->dirname, name) < 0)
			PERROR(_("Out of memory"));
		rc = process_binary(option, path);
	}
	return rc;
}

static void setup_flags(void)
{
	/* Get the match string to determine type of regex support needed */
	set_supported_features();

	/* Gracefully handle AppArmor kernel without compatibility patch */
	if (!features_string) {
		PERROR("Cache read/write disabled: %s interface file missing. "
			"(Kernel needs AppArmor 2.4 compatibility patch.)\n",
			FEATURES_FILE);
		write_cache = 0;
		skip_read_cache = 1;
		return;
	}
}

int main(int argc, char *argv[])
{
	int retval, last_error;
	int i;
	int optind;

	/* name of executable, for error reporting and usage display */
	progname = argv[0];

	init_base_dir();

	process_config_file("/etc/apparmor/parser.conf");
	optind = process_args(argc, argv);

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
	    !find_subdomainfs_mountpoint()) {
		return 1;
	}

	if (!binary_input) parse_default_paths();

	setup_flags();

	if (!cacheloc && asprintf(&cacheloc, "%s/cache", basedir) == -1) {
		PERROR(_("Memory allocation error."));
		return 1;
	}

	retval = setup_cache(cacheloc);
	if (retval) {
		PERROR(_("Failed setting up policy cache (%s): %s\n"),
		       cacheloc, strerror(errno));
		return 1;
	}

	retval = last_error = 0;
	for (i = optind; i <= argc; i++) {
		struct stat stat_file;

		if (i < argc && !(profilename = strdup(argv[i]))) {
			perror("strdup");
			last_error = ENOMEM;
			if (abort_on_error)
				break;
			continue;
		}
		/* skip stdin if we've seen other command line arguments */
		if (i == argc && optind != argc)
			continue;

		if (profilename && stat(profilename, &stat_file) == -1) {
			PERROR("File %s not found, skipping...\n", profilename);
			continue;
		}

		if (profilename && S_ISDIR(stat_file.st_mode)) {
			int (*cb)(DIR *dir, const char *name, struct stat *st,
				  void *data);
			struct dir_cb_data cb_data;

			cb_data.dirname = profilename;
			cb_data.cachedir = cacheloc;
			cb = binary_input ? binary_dir_cb : profile_dir_cb;
			if ((retval = dirat_for_each(NULL, profilename,
						     &cb_data, cb))) {
				PDEBUG("Failed loading profiles from %s\n",
				       profilename);
			}
		} else if (binary_input) {
			retval = process_binary(option, profilename);
		} else {
			retval = process_profile(option, profilename, cacheloc);
		}

		if (profilename) free(profilename);
		profilename = NULL;

		if (retval) {
			last_error = retval;
			if (abort_on_error)
				break;
		}
	}

	if (ofile)
		fclose(ofile);

	return last_error;
}
