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
#include "parser.h"
#include "parser_version.h"
#include "parser_include.h"
#include "common_optarg.h"
#include "libapparmor_re/apparmor_re.h"

#define MODULE_NAME "apparmor"
#define OLD_MODULE_NAME "subdomain"
#define PROC_MODULES "/proc/modules"
#define DEFAULT_APPARMORFS "/sys/kernel/security/" MODULE_NAME
#define MATCH_FILE "/sys/kernel/security/" MODULE_NAME "/matching"
#define FEATURES_FILE "/sys/kernel/security/" MODULE_NAME "/features"
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
struct timespec mru_tstamp;

#define FEATURES_STRING_SIZE 8192
char *features_string = NULL;
char *cacheloc = NULL;

/* per-profile settings */

static int load_features(const char *name);

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
	FILE *f;
	int c, o;

	f = fopen(name, "r");
	if (!f)
		return 0;

	while ((c = getopt_long_file(f, long_options, &optarg, &o)) != -1)
		process_arg(c, optarg);
	fclose(f);
	return 1;
}


int find_subdomainfs_mountpoint(void)
{
	if (aa_find_mountpoint(&subdomainbase) == -1) {
		struct stat buf;
		if (stat(DEFAULT_APPARMORFS, &buf) == -1) {
		PERROR(_("Warning: unable to find a suitable fs in %s, is it "
			 "mounted?\nUse --subdomainfs to override.\n"),
		       MOUNTED_FS);
		} else {
			subdomainbase = strdup(DEFAULT_APPARMORFS);
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

char *snprintf_buffer(char *buf, char *pos, ssize_t size, const char *fmt, ...)
{
	va_list args;
	int i, remaining = size - (pos - buf);

	va_start(args, fmt);
	i = vsnprintf(pos, remaining, fmt, args);
	va_end(args);

	if (i >= size) {
		PERROR(_("Feature buffer full."));
		exit(1);
	}

	return pos + i;
}

struct features_struct {
	char **buffer;
	int size;
	char *pos;
};

static int features_dir_cb(DIR *dir, const char *name, struct stat *st,
			   void *data)
{
	struct features_struct *fst = (struct features_struct *) data;

	/* skip dot files and files with no name */
	if (*name == '.' || !strlen(name))
		return 0;

	fst->pos = snprintf_buffer(*fst->buffer, fst->pos, fst->size, "%s {", name);

	if (S_ISREG(st->st_mode)) {
		int len, file;
		int remaining = fst->size - (fst->pos - *fst->buffer);
		if (!(file = openat(dirfd(dir), name, O_RDONLY))) {
			PDEBUG("Could not open '%s'", name);
			return -1;
		}
		PDEBUG("Opened features \"%s\"\n", name);
		if (st->st_size > remaining) {
			PDEBUG("Feature buffer full.");
			return -1;
		}

		do {
			len = read(file, fst->pos, remaining);
			if (len > 0) {
				remaining -= len;
				fst->pos += len;
				*fst->pos = 0;
			}
		} while (len > 0);
		if (len < 0) {
			PDEBUG("Error reading feature file '%s'\n", name);
			return -1;
		}
		close(file);
	} else if (S_ISDIR(st->st_mode)) {
		if (dirat_for_each(dir, name, fst, features_dir_cb))
			return -1;
	}

	fst->pos = snprintf_buffer(*fst->buffer, fst->pos, fst->size, "}\n");

	return 0;
}

static char *handle_features_dir(const char *filename, char **buffer, int size,
				 char *pos)
{
	struct features_struct fst = { buffer, size, pos };

	if (dirat_for_each(NULL, filename, &fst, features_dir_cb)) {
		PDEBUG("Failed evaluating %s\n", filename);
		exit(1);
	}

	return fst.pos;
}

static char *load_features_file(const char *name) {
	char *buffer;
	FILE *f = NULL;
	size_t size;

	f = fopen(name, "r");
	if (!f)
		return NULL;

	buffer = (char *) malloc(FEATURES_STRING_SIZE);
	if (!buffer)
		goto fail;

	size = fread(buffer, 1, FEATURES_STRING_SIZE - 1, f);
	if (!size || ferror(f))
		goto fail;
	buffer[size] = 0;

	fclose(f);
	return buffer;

fail:
	int save = errno;
	free(buffer);
	if (f)
		fclose(f);
	errno = save;
	return NULL;
}

static int load_features(const char *name)
{
	struct stat stat_file;

	if (stat(name, &stat_file) == -1)
		return -1;

	if (S_ISDIR(stat_file.st_mode)) {
		/* if we have a features directory default to */
		features_string = (char *) malloc(FEATURES_STRING_SIZE);
		handle_features_dir(name, &features_string, FEATURES_STRING_SIZE, features_string);
	} else {
		features_string = load_features_file(name);
		if (!features_string)
			return -1;
	}

	return 0;
}

static void set_features_by_match_file(void)
{
	FILE *ms = fopen(MATCH_FILE, "r");
	if (ms) {
		char *match_string = (char *) malloc(1000);
		if (!match_string)
			goto no_match;
		if (!fgets(match_string, 1000, ms)) {
			free(match_string);
			goto no_match;
		}
		if (strstr(match_string, " perms=c"))
			perms_create = 1;
		free(match_string);
		kernel_supports_network = 1;
		goto out;
	}
no_match:
	perms_create = 1;

out:
	if (ms)
		fclose(ms);
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
	char *buffer = NULL;
	int retval = 0, size = 0, asize = 0, rsize;
	int chunksize = 1 << 14;
	int fd;

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

	close(fd);

	if (rsize == 0)
		retval = sd_load_buffer(option, buffer, size);
	else
		retval = rsize;

	free(buffer);

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
		char *target = NULL;
		if (asprintf(&target, "%s/%s/%s", basedir, linkdir, basename) < 0) {
			perror("asprintf");
			exit(1);
		}

		if (access(target, R_OK) == 0)
			rc = 1;

		free(target);
	}

	return rc;
}

#define le16_to_cpu(x) ((uint16_t)(le16toh (*(uint16_t *) x)))

const char header_string[] = "\004\010\000version\000\002";
#define HEADER_STRING_SIZE 12
static bool valid_cached_file_version(const char *cachename)
{
	char buffer[16];
	FILE *f;
	if (!(f = fopen(cachename, "r"))) {
		PERROR(_("Error: Could not read cache file '%s', skipping...\n"), cachename);
		return false;
	}
	size_t res = fread(buffer, 1, 16, f);
	fclose(f);
	if (res < 16)
		return false;

	/* 12 byte header that is always the same and then 4 byte version # */
	if (memcmp(buffer, header_string, HEADER_STRING_SIZE) != 0)
		return false;

	uint32_t version = cpu_to_le32(ENCODE_VERSION(force_complain,
						      policy_version,
						      parser_abi_version,
						      kernel_abi_version));
	if (memcmp(buffer + 12, &version, 4) != 0)
		return false;

	return true;
}

/* returns true if time is more recent than mru_tstamp */
#define mru_t_cmp(a) \
(((a).tv_sec == (mru_tstamp).tv_sec) ? \
  (a).tv_nsec > (mru_tstamp).tv_nsec : (a).tv_sec > (mru_tstamp).tv_sec)

void update_mru_tstamp(FILE *file)
{
	struct stat stat_file;
	if (fstat(fileno(file), &stat_file))
		return;
	if (mru_t_cmp(stat_file.st_mtim))
		mru_tstamp = stat_file.st_mtim;
}

int process_profile(int option, const char *profilename)
{
	struct stat stat_bin;
	int retval = 0;
	char * cachename = NULL;
	char * cachetemp = NULL;
	const char *basename = NULL;

	/* per-profile states */
	force_complain = opt_force_complain;

	if (profilename) {
		if ( !(yyin = fopen(profilename, "r")) ) {
			PERROR(_("Error: Could not read profile %s: %s.\n"),
			       profilename, strerror(errno));
			return errno;
		}
	}
	else {
		pwarn("%s: cannot use or update cache, disable, or force-complain via stdin\n", progname);
	}

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

		/* TODO: add primary cache check.
		 * If .file for cached binary exists get the list of profile
		 * names and check their time stamps.
		 */
		/* TODO: primary cache miss/hit messages */
	}

	reset_parser(profilename);
	if (yyin) {
		yyrestart(yyin);
		update_mru_tstamp(yyin);
	}

	retval = yyparse();
	if (retval != 0)
		goto out;

	/* Test to see if profile is for another namespace, if so disable
	 * caching for now
	 * TODO: Add support for caching profiles in an alternate namespace
	 * TODO: Add support for embedded namespace defines if they aren't
	 *       removed from the language.
	 */
	if (profile_ns)
		skip_cache = 1;

	/* Do secondary test to see if cached binary profile is good,
	 * instead of checking against a presupplied list of files
	 * use the timestamps from the files that were parsed.
	 * Parsing the profile is slower that doing primary cache check
	 * its still faster than doing full compilation
	 */
	if ((profilename && option != OPTION_REMOVE) && !force_complain &&
	    !skip_cache) {
		if (asprintf(&cachename, "%s/%s", cacheloc, basename)<0) {
			PERROR(_("Memory allocation error."));
			return ENOMEM;
		}
		/* Load a binary cache if it exists and is newest */
		if (!skip_read_cache &&
		    stat(cachename, &stat_bin) == 0 &&
		    stat_bin.st_size > 0 && (mru_t_cmp(stat_bin.st_mtim)) &&
		    valid_cached_file_version(cachename)) {
			if (show_cache)
				PERROR("Cache hit: %s\n", cachename);
			retval = process_binary(option, cachename);
			if (!retval || skip_bad_cache_rebuild)
				goto out;
		}
		if (write_cache) {
			/* Otherwise, set up to save a cached copy */
			if (asprintf(&cachetemp, "%s-XXXXXX", cachename)<0) {
				perror("asprintf");
				return ENOMEM;
			}
			if ( (cache_fd = mkstemp(cachetemp)) < 0) {
				perror("mkstemp");
				return ENOMEM;
			}
		}
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

	retval = load_policy(option);

out:
	if (cachetemp) {
		/* Only install the generate cache file if it parsed correctly
                   and did not have write/close errors */
		int useable_cache = (cache_fd != -1 && retval == 0);
		if (cache_fd != -1) {
			if (close(cache_fd))
				useable_cache = 0;
			cache_fd = -1;
		}

		if (useable_cache) {
			if (rename(cachetemp, cachename) < 0) {
				pwarn("Warning failed to write cache: %s\n", cachename);
				unlink(cachetemp);
			}
			else if (show_cache)
				PERROR("Wrote cache: %s\n", cachename);
		}
		else {
			unlink(cachetemp);
			PERROR("Warning failed to create cache: %s\n", basename);
		}
		free(cachetemp);
	}
	if (cachename)
		free(cachename);
	return retval;
}

/* data - name of parent dir */
static int profile_dir_cb(DIR *dir unused, const char *name, struct stat *st,
			  void *data)
{
	int rc = 0;

	if (!S_ISDIR(st->st_mode) && !is_blacklisted(name, NULL)) {
		const char *dirname = (const char *)data;
		char *path;
		if (asprintf(&path, "%s/%s", dirname, name) < 0)
			PERROR(_("Out of memory"));
		rc = process_profile(option, path);
		free(path);
	}
	return rc;
}

/* data - name of parent dir */
static int binary_dir_cb(DIR *dir unused, const char *name, struct stat *st,
			 void *data)
{
	int rc = 0;

	if (!S_ISDIR(st->st_mode) && !is_blacklisted(name, NULL)) {
		const char *dirname = (const char *)data;
		char *path;
		if (asprintf(&path, "%s/%s", dirname, name) < 0)
			PERROR(_("Out of memory"));
		rc = process_binary(option, path);
		free(path);
	}
	return rc;
}

static int clear_cache_cb(DIR *dir, const char *path, struct stat *st,
			  void *data unused)
{
	/* remove regular files */
	if (S_ISREG(st->st_mode))
		return unlinkat(dirfd(dir), path, 0);

	/* do nothing with other file types */
	return 0;
}

static int clear_cache_files(const char *path)
{
	return dirat_for_each(NULL, path, NULL, clear_cache_cb);
}

static int create_cache(const char *cachedir, const char *path,
			const char *features)
{
	struct stat stat_file;
	FILE * f = NULL;

	if (clear_cache_files(cacheloc) != 0)
		goto error;

create_file:
	f = fopen(path, "w");
	if (f) {
		if (fwrite(features, strlen(features), 1, f) != 1 )
			goto error;

		fclose(f);


		return 0;
	}

error:
	/* does the dir exist? */
	if (stat(cachedir, &stat_file) == -1 && create_cache_dir) {
		if (mkdir(cachedir, 0700) == 0)
			goto create_file;
		if (show_cache)
			PERROR(_("Can't create cache directory: %s\n"), cachedir);
	} else if (!S_ISDIR(stat_file.st_mode)) {
		if (show_cache)
			PERROR(_("File in cache directory location: %s\n"), cachedir);
	} else {
		if (show_cache)
			PERROR(_("Can't update cache directory: %s\n"), cachedir);
	}

	if (show_cache)
		PERROR("Cache write disabled: cannot create %s\n", path);
	write_cache = 0;

	return -1;
}

static void setup_flags(void)
{
	char *cache_features_path = NULL;
	char *cache_flags = NULL;

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


	/*
         * Deal with cache directory versioning:
         *  - If cache/.features is missing, create it if --write-cache.
         *  - If cache/.features exists, and does not match features_string,
         *    force cache reading/writing off.
         */
	if (asprintf(&cache_features_path, "%s/.features", cacheloc) == -1) {
		PERROR(_("Memory allocation error."));
		exit(1);
	}

	cache_flags = load_features_file(cache_features_path);
	if (cache_flags) {
		if (strcmp(features_string, cache_flags) != 0) {
			if (write_cache && cond_clear_cache) {
				if (create_cache(cacheloc, cache_features_path,
						 features_string))
					skip_read_cache = 1;
			} else {
				if (show_cache)
					PERROR("Cache read/write disabled: %s does not match %s\n", FEATURES_FILE, cache_features_path);
				write_cache = 0;
				skip_read_cache = 1;
			}
		}
		free(cache_flags);
		cache_flags = NULL;
	} else if (write_cache) {
		create_cache(cacheloc, cache_features_path, features_string);
	}

	free(cache_features_path);
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

	/* create the cacheloc once and use it everywhere */
	if (!cacheloc) {
		if (asprintf(&cacheloc, "%s/cache", basedir) == -1) {
			PERROR(_("Memory allocation error."));
			exit(1);
		}
	}

	if (force_clear_cache) 
		exit(clear_cache_files(cacheloc));

	/* Check to make sure there is an interface to load policy */
	if (!(UNPRIVILEGED_OPS) && (subdomainbase == NULL) &&
	    (retval = find_subdomainfs_mountpoint())) {
		return retval;
	}

	if (!binary_input) parse_default_paths();

	setup_flags();

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
			cb = binary_input ? binary_dir_cb : profile_dir_cb;
			if ((retval = dirat_for_each(NULL, profilename, profilename, cb))) {
				PDEBUG("Failed loading profiles from %s\n",
				       profilename);
			}
		} else if (binary_input) {
			retval = process_binary(option, profilename);
		} else {
			retval = process_profile(option, profilename);
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
