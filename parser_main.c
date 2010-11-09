/* $Id$ */

/*
 *   Copyright (c) 1999, 2000, 2001, 2002, 2003, 2004, 2005, 2006, 2007
 *   NOVELL (All rights reserved)
 *
 *   Copyright (c) 2010
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

#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <stdarg.h>
#include <getopt.h>
#include <errno.h>
#include <fcntl.h>
#include <mntent.h>
#include <libintl.h>
#include <linux/limits.h>
#include <locale.h>
#define _(s) gettext(s)

/* enable the following line to get voluminous debug info */
/* #define DEBUG */

#include <unistd.h>
#include <sys/sysctl.h>
#include <sys/types.h>
#include <sys/stat.h>

#include "parser.h"
#include "parser_version.h"
#include "parser_include.h"
#include "libapparmor_re/apparmor_re.h"

#define MODULE_NAME "apparmor"
#define OLD_MODULE_NAME "subdomain"
#define PROC_MODULES "/proc/modules"
#define DEFAULT_APPARMORFS "/sys/kernel/security/" MODULE_NAME
#define MATCH_STRING "/sys/kernel/security/" MODULE_NAME "/matching"
#define FLAGS_FILE "/sys/kernel/security/" MODULE_NAME "/features"
#define MOUNTED_FS "/proc/mounts"
#define AADFA "pattern=aadfa"

#define PRIVILEGED_OPS (kernel_load)
#define UNPRIVILEGED_OPS (!(PRIVILEGED_OPS))

const char *parser_title	= "Novell/SUSE AppArmor parser";
const char *parser_copyright	= "Copyright (C) 1999, 2000, 2003, 2004, 2005, 2006 Novell Inc.";

char *progname;
int option = OPTION_ADD;
int opt_force_complain = 0;
int binary_input = 0;
int names_only = 0;
int dump_vars = 0;
int dump_expanded_vars = 0;
dfaflags_t dfaflags = DFA_CONTROL_TREE_NORMAL | DFA_CONTROL_TREE_SIMPLE | DFA_CONTROL_MINIMIZE | DFA_CONTROL_MINIMIZE_HASH_TRANS;
int conf_verbose = 0;
int conf_quiet = 0;
int kernel_load = 1;
int show_cache = 0;
int skip_cache = 0;
int skip_read_cache = 0;
int write_cache = 0;
#ifdef FORCE_READ_IMPLIES_EXEC
int read_implies_exec = 1;
#else
int read_implies_exec = 0;
#endif
int preprocess_only = 0;
int skip_mode_force = 0;
struct timespec mru_tstamp;

char *subdomainbase = NULL;
char *match_string = NULL;
char *flags_string = NULL;
int regex_type = AARE_DFA;
int perms_create = 0;		/* perms contain create flag */
int kernel_supports_network = 1;	/* kernel supports network rules */
char *profile_namespace = NULL;
int flag_changehat_version = FLAG_CHANGEHAT_1_5;
FILE *ofile = NULL;

/* per-profile settings */
int force_complain = 0;
char *profilename = NULL;

struct option long_options[] = {
	{"add", 		0, 0, 'a'},
	{"binary",		0, 0, 'B'},
	{"base",		1, 0, 'b'},
	{"subdomainfs",		0, 0, 'f'},
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
	{"quiet",		0, 0, 'q'},
	{"skip-kernel-load",	0, 0, 'Q'},
	{"verbose",		0, 0, 'v'},
	{"namespace",		1, 0, 'n'},
	{"readimpliesX",	0, 0, 'X'},
	{"skip-cache",		0, 0, 'K'},
	{"skip-read-cache",	0, 0, 'T'},
	{"write-cache",		0, 0, 'W'},
	{"show-cache",		0, 0, 'k'},
	{"debug",		0, 0, 'd'},
	{"dump",		1, 0, 'D'},
	{"Dump",		1, 0, 'D'},
	{"optimize",		1, 0, 'O'},
	{"Optimize",		1, 0, 'O'},
	{"preprocess",		0, 0, 'p'},
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
	       "-N, --names		Dump names of profiles in input.\n"
	       "-S, --stdout		Dump compiled profile to stdout\n"
	       "-o n, --ofile n		Write output to file n\n"
	       "-b n, --base n		Set base dir and cwd\n"
	       "-I n, --Include n	Add n to the search path\n"
	       "-f n, --subdomainfs n	Set location of apparmor filesystem\n"
	       "-m n, --match-string n  Use only match features n\n"
	       "-n n, --namespace n	Set Namespace for the profile\n"
	       "-X, --readimpliesX	Map profile read permissions to mr\n"
	       "-k, --show-cache	Report cache hit/miss details\n"
	       "-K, --skip-cache	Do not attempt to load or save cached profiles\n"
	       "-T, --skip-read-cache	Do not attempt to load cached profiles\n"
	       "-W, --write-cache	Save cached profile (force with -T)\n"
	       "-q, --quiet		Don't emit warnings\n"
	       "-v, --verbose		Show profile names as they load\n"
	       "-Q, --skip-kernel-load	Do everything except loading into kernel\n"
	       "-V, --version		Display version info and exit\n"
	       "-d, --debug 		Debug apparmor definitions\n"
	       "-p, --preprocess	Dump preprocessed profile\n"
	       "-D [n], --dump		Dump internal info for debugging\n"
	       "-O [n], --Optimize	Control dfa optimizations\n"
	       "-h [cmd], --help[=cmd]  Display this text or info about cmd\n"
	       ,command);
}

static void display_dump(char *command)
{
	display_version();
	printf("\n%s: --dump [Option]\n\n"
	       "Options:\n"
	       "--------\n"
	       "no option specified	Dump variables\n"
	       "variables		Dump variables\n"
	       "expanded-variables	Dump expanded variables\n"
	       "rule-exprs		Dump rule to expr tree conversions\n"
	       "expr-stats		Dump stats on expr tree\n"
	       "expr-tree		Dump expression tree\n"
	       "expr-simple		Dump simplified expression tree\n"
	       "dfa-progress		Dump dfa creation as in progress\n"
	       "dfa-stats		Dump dfa creation stats\n"
	       "dfa-states		Dump dfa state diagram\n"
	       "dfa-graph		Dump dfa dot (graphviz) graph\n"
	       "dfa-minimize		Dump dfa minimization\n"
	       "dfa-unreachable		Dump dfa unreachable states\n"
	       "trans-progress		Dump progress of transition table\n"
	       "trans-stats		Dump stats on transition table\n"
	       "trans-table		Dump transition table\n"
	       "equiv-stats		Dump equivance class stats\n"
	       "equiv			Dump equivance class\n"
	       ,command);
}

static void display_optimize(char *command)
{
	display_version();
	printf("\n%s: -O [Option]\n\n"
	       "Options:\n"
	       "--------\n"
	       "0			no optimizations\n"
	       "[no-]equiv		use equivalent classes\n"
	       "[no-]expr-normalize	do expr normalization\n"
	       "[no-]expr-simplify	do expr tree simplification\n"
	       "expr-left-simplify	do left simplification first\n"
	       "expr-right-simplify	do right simplification first\n"
	       "[no-]minimize		do state minimization\n"
	       "[no-]hash-perms		use permission hashing to setup partitions at start of minimization\n"
	       "[no-]hash-trans		use transition hashing to setup partitions at start of minimization\n"
	       "[no-]remove-unreachable	do unreachable state removal\n"
	       "trans-comp-high		try to do extra transition table compression\n"
	       "trans-comp-fast		do faster transition table compression\n"
	       ,command);
}

void pwarn(char *fmt, ...)
{
	va_list arg;
	char *newfmt;
	int rc;

	if (conf_quiet || names_only || option == OPTION_REMOVE)
		return;

	rc = asprintf(&newfmt, _("Warning from %s (%s%sline %d): %s"),
		      profilename ? profilename : "stdin",
		      current_filename ? current_filename : "",
		      current_filename ? " " : "",
		      current_lineno,
		      fmt);
	if (!newfmt)
		return;

	va_start(arg, fmt);
	vfprintf(stderr, newfmt, arg);
	va_end(arg);

	free(newfmt);
}

static int process_args(int argc, char *argv[])
{
	int c, o;
	int count = 0;
	option = OPTION_ADD;

	while ((c = getopt_long(argc, argv, "adf:h::rRVvI:b:BCD:NSm:qQn:XKTWkO:po:", long_options, &o)) != -1)
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
			names_only = 1;
			skip_cache = 1;
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
			} else if (strcmp(optarg, "rule-exprs") == 0) {
				dfaflags |= DFA_DUMP_RULE_EXPR;
			} else if (strcmp(optarg, "expr-tree") == 0) {
				dfaflags |= DFA_DUMP_TREE;
			} else if (strcmp(optarg, "expr-simple") == 0) {
				dfaflags |= DFA_DUMP_SIMPLE_TREE;
			} else if (strcmp(optarg, "expr-stats") == 0) {
				dfaflags |= DFA_DUMP_TREE_STATS;
			} else if (strcmp(optarg, "dfa-progress") == 0) {
				dfaflags |= DFA_DUMP_PROGRESS | DFA_DUMP_STATS;
			} else if (strcmp(optarg, "dfa-stats") == 0) {
				dfaflags |= DFA_DUMP_STATS;
			} else if (strcmp(optarg, "dfa-states") == 0) {
				dfaflags |= DFA_DUMP_STATES;
			} else if (strcmp(optarg, "dfa-graph") == 0) {
				dfaflags |= DFA_DUMP_GRAPH;
			} else if (strcmp(optarg, "dfa- minimize") == 0) {
				dfaflags |= DFA_DUMP_MINIMIZE;
			} else if (strcmp(optarg, "dfa-unreachable") == 0) {
				dfaflags |= DFA_DUMP_UNREACHABLE;
			} else if (strcmp(optarg, "trans-progress") == 0) {
				dfaflags |= DFA_DUMP_TRANS_PROGRESS |
				  DFA_DUMP_TRANS_STATS;
			} else if (strcmp(optarg, "trans-stats") == 0) {
				dfaflags |= DFA_DUMP_TRANS_STATS;
			} else if (strcmp(optarg, "trans-table") == 0) {
				dfaflags |= DFA_DUMP_TRANS_TABLE;
			} else if (strcmp(optarg, "equiv") == 0) {
				dfaflags |= DFA_DUMP_EQUIV;
			} else if (strcmp(optarg, "equiv-stats") == 0) {
				dfaflags |= DFA_DUMP_EQUIV_STATS;
			} else {
				PERROR("%s: Invalid --Dump option %s\n",
				       progname, optarg);
				exit(1);
			}
			break;
		case 'O':
			skip_read_cache = 1;
			if (strcmp(optarg, "0") == 0) {
				dfaflags &= ~(DFA_CONTROL_TREE_NORMAL |
					      DFA_CONTROL_TREE_SIMPLE |
					      DFA_CONTROL_MINIMIZE |
					      DFA_CONTROL_REMOVE_UNREACHABLE);
			} else if (strcmp(optarg, "equiv") == 0) {
				dfaflags |= DFA_CONTROL_EQUIV;
			} else if (strcmp(optarg, "no-equiv") == 0) {
				dfaflags &= ~DFA_CONTROL_EQUIV;
			} else if (strcmp(optarg, "expr-normalize") == 0) {
				dfaflags |= DFA_CONTROL_TREE_NORMAL;
			} else if (strcmp(optarg, "no-expr-normalize") == 0) {
				dfaflags &= ~DFA_CONTROL_TREE_NORMAL;
			} else if (strcmp(optarg, "expr-simplify") == 0) {
				dfaflags |= DFA_CONTROL_TREE_SIMPLE;
			} else if (strcmp(optarg, "no-expr-simplify") == 0) {
				dfaflags &= ~DFA_CONTROL_TREE_SIMPLE;
			} else if (strcmp(optarg, "expr-left-simplify") == 0) {
				dfaflags |= DFA_CONTROL_TREE_LEFT;
			} else if (strcmp(optarg, "expr-right-simplify") == 0) {
				dfaflags &= ~DFA_CONTROL_TREE_LEFT;
			} else if (strcmp(optarg, "minimize") == 0) {
				dfaflags |= DFA_CONTROL_MINIMIZE;
			} else if (strcmp(optarg, "no-minimize") == 0) {
				dfaflags &= ~DFA_CONTROL_MINIMIZE;
			} else if (strcmp(optarg, "hash-trans") == 0) {
				dfaflags |= DFA_CONTROL_MINIMIZE_HASH_TRANS;
			} else if (strcmp(optarg, "no-hash-trans") == 0) {
				dfaflags &= ~DFA_CONTROL_MINIMIZE_HASH_TRANS;
			} else if (strcmp(optarg, "hash-perms") == 0) {
				dfaflags |= DFA_CONTROL_MINIMIZE_HASH_PERMS;
			} else if (strcmp(optarg, "no-hash-perms") == 0) {
				dfaflags &= ~DFA_CONTROL_MINIMIZE_HASH_PERMS;
			} else if (strcmp(optarg, "trans-comp-fast") == 0) {
				dfaflags &= ~DFA_CONTROL_TRANS_HIGH;
			} else if (strcmp(optarg, "trans-comp-high") == 0) {
				dfaflags |= DFA_CONTROL_TRANS_HIGH;
			} else if (strcmp(optarg, "remove-unreachable") == 0) {
				dfaflags |= DFA_CONTROL_REMOVE_UNREACHABLE;
			} else if (strcmp(optarg, "no-remove-unreachable") == 0) {
				dfaflags &= ~DFA_CONTROL_REMOVE_UNREACHABLE;
			} else {
				PERROR("%s: Invalid --Optimize option %s\n",
				       progname, optarg);
				exit(1);
			}
			break;
		case 'm':
			match_string = strdup(optarg);
			break;
		case 'q':
			conf_verbose = 0;
			conf_quiet = 1;
			break;
		case 'v':
			conf_verbose = 1;
			conf_quiet = 0;
			break;
		case 'n':
			profile_namespace = strdup(optarg);
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
		default:
			display_usage(progname);
			exit(0);
			break;
		}
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
		goto out;

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
		if (strstr(match_string, AADFA))
			regex_type = AARE_DFA;

		if (strstr(match_string, " perms=c"))
			perms_create = 1;
	} else {
		/* no match string default to 2.6.36 version which doesn't
		 * have a match string
		 */
		regex_type = AARE_DFA;
		perms_create = 1;
		kernel_supports_network = 0;
	}

	if (ms)
		fclose(ms);
	return;
}

static void get_flags_string(char **flags, char *flags_file) {
	char *pos;
	FILE *f = NULL;

	/* abort if missing or already set */
	if (!flags || *flags) return;

	f = fopen(flags_file, "r");
	if (!f)
		return;

	*flags = malloc(1024);
	if (!*flags)
		goto fail;

	if (!fgets(*flags, 1024, f))
		goto fail;

	fclose(f);
	pos = strstr(*flags, "change_hat=");
	if (pos) {
		if (strncmp(pos, "change_hat=1.4", 14) == 0)
			flag_changehat_version = FLAG_CHANGEHAT_1_4;
//fprintf(stderr, "flags string: %s\n", flags_string);
//fprintf(stderr, "changehat %d\n", flag_changehat_version);
	}
	return;

fail:
	free(*flags);
	*flags = NULL;
	if (f)
		fclose(f);
	return;
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

void reset_parser(char *filename)
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


/* returns true if time is more recent than mru_tstamp */
#define mru_t_cmp(a) \
(((a).tv_sec == (mru_tstamp).tv_sec) ? \
  (a).tv_nsec > (mru_tstamp).tv_nsec : (a).tv_sec > (mru_tstamp).tv_sec)

void update_mru_tstamp(FILE *file)
{
	struct stat stat_file;
	if (fstat(fileno(file), &stat_file))
		return;
	if (mru_t_cmp(stat_file.st_ctim))
		mru_tstamp = stat_file.st_ctim;
}

int process_profile(int option, char *profilename)
{
	struct stat stat_bin;
	int retval = 0;
	char * cachename = NULL;
	char * cachetemp = NULL;
	char *basename = NULL;

	/* per-profile states */
	force_complain = opt_force_complain;

	if (profilename) {
		if ( !(yyin = fopen(profilename, "r")) ) {
			PERROR(_("Error: Could not read profile %s: %s.\n"),
			       profilename, strerror(errno));
			exit(errno);
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

	/* Do secondary test to see if cached binary profile is good,
	 * instead of checking against a presupplied list of files
	 * use the timestamps from the files that were parsed.
	 * Parsing the profile is slower that doing primary cache check
	 * its still faster than doing full compilation
	 */
	if ((profilename && option != OPTION_REMOVE) && !force_complain &&
	    !skip_cache) {
		if (asprintf(&cachename, "%s/%s/%s", basedir, "cache", basename)<0) {
			perror("asprintf");
			exit(1);
		}
		/* Load a binary cache if it exists and is newest */
		if (!skip_read_cache &&
		    stat(cachename, &stat_bin) == 0 &&
		    stat_bin.st_size > 0 && (mru_t_cmp(stat_bin.st_mtim))) {
			if (show_cache)
				PERROR("Cache hit: %s\n", cachename);
			retval = process_binary(option, cachename);
			goto out;
		}
		if (write_cache) {
			/* Otherwise, set up to save a cached copy */
			if (asprintf(&cachetemp, "%s/%s/%s-XXXXXX", basedir, "cache", basename)<0) {
				perror("asprintf");
				exit(1);
			}
			if ( (cache_fd = mkstemp(cachetemp)) < 0) {
				perror("mkstemp");
				exit(1);
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
			rename(cachetemp, cachename);
			if (show_cache)
				PERROR("Wrote cache: %s\n", cachename);
		}
		else {
			unlink(cachetemp);
			if (show_cache)
				PERROR("Removed cache attempt: %s\n", cachetemp);
		}
		free(cachetemp);
	}
	if (cachename)
		free(cachename);
	return retval;
}

static void setup_flags(void)
{
	char *cache_features_path = NULL;
	char *cache_flags = NULL;

	/* Get the match string to determine type of regex support needed */
	get_match_string();
	/* Get kernel features string */
	get_flags_string(&flags_string, FLAGS_FILE);
	/* Gracefully handle AppArmor kernel without compatibility patch */
	if (!flags_string) {
		PERROR("Cache read/write disabled: %s interface file missing. "
			"(Kernel needs AppArmor 2.4 compatibility patch.)\n",
			FLAGS_FILE);
		write_cache = 0;
		skip_read_cache = 1;
		return;
	}

	/*
         * Deal with cache directory versioning:
         *  - If cache/.features is missing, create it if --write-cache.
         *  - If cache/.features exists, and does not match flags_string,
         *    force cache reading/writing off.
         */
	if (asprintf(&cache_features_path, "%s/cache/.features", basedir) == -1) {
		perror("asprintf");
		exit(1);
	}

	get_flags_string(&cache_flags, cache_features_path);
	if (cache_flags) {
		if (strcmp(flags_string, cache_flags) != 0) {
			if (show_cache) PERROR("Cache read/write disabled: %s does not match %s\n", FLAGS_FILE, cache_features_path);
			write_cache = 0;
			skip_read_cache = 1;
		}
		free(cache_flags);
		cache_flags = NULL;
	}
	else if (write_cache) {
		FILE * f = NULL;
		int failure = 0;

		f = fopen(cache_features_path, "w");
		if (!f) failure = 1;
		else {
			if (fwrite(flags_string, strlen(flags_string), 1, f) != 1 ) {
				failure = 1;
			}
			if (fclose(f) != 0) failure = 1;
		}

		if (failure) {
			if (show_cache) PERROR("Cache write disabled: cannot write to %s\n", cache_features_path);
			write_cache = 0;
		}
	}

	free(cache_features_path);
}

int main(int argc, char *argv[])
{
	int retval;
	int i;
	int optind;

	/* name of executable, for error reporting and usage display */
	progname = argv[0];

	init_base_dir();

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
	    (retval = find_subdomainfs_mountpoint())) {
		return retval;
	}

	if (!binary_input) parse_default_paths();

	setup_flags();

	retval = 0;
	for (i = optind; retval == 0 && i <= argc; i++) {
		if (i < argc && !(profilename = strdup(argv[i]))) {
			perror("strdup");
			return -1;
		}
		/* skip stdin if we've seen other command line arguments */
		if (i == argc && optind != argc)
			continue;

		if (binary_input) {
			retval = process_binary(option, profilename);
		} else {
			retval = process_profile(option, profilename);
		}

		if (profilename) free(profilename);
		profilename = NULL;
	}

	if (ofile)
		fclose(ofile);

	return retval;
}
