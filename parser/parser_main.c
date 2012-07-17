/*
 *   Copyright (c) 1999, 2000, 2001, 2002, 2003, 2004, 2005, 2006, 2007
 *   NOVELL (All rights reserved)
 *
 *   Copyright (c) 2010 - 2012
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
#include <getopt.h>
#include <errno.h>
#include <fcntl.h>
#include <mntent.h>
#include <libintl.h>
#include <locale.h>
#include <dirent.h>
#define _(s) gettext(s)

/* enable the following line to get voluminous debug info */
/* #define DEBUG */

#include <unistd.h>
#include <limits.h>
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

const char *parser_title	= "AppArmor parser";
const char *parser_copyright	= "Copyright (C) 1999-2008 Novell Inc.\nCopyright 2009-2012 Canonical Ltd.";

char *progname;
int opt_force_complain = 0;
int binary_input = 0;
int dump_vars = 0;
int dump_expanded_vars = 0;
int show_cache = 0;
int skip_cache = 0;
int skip_read_cache = 0;
int write_cache = 0;
int preprocess_only = 0;
int skip_mode_force = 0;
struct timespec mru_tstamp;

#define FLAGS_STRING_SIZE 1024
char *match_string = NULL;
char *flags_string = NULL;
char *cacheloc = NULL;

/* per-profile settings */
int force_complain = 0;

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
	{"cache-loc",		1, 0, 'L'},
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
	       ,command);
}

/*
 * flag: 1 - allow no- inversion
 * flag: 2 - flags specified should be masked off
 */
typedef struct {
	int control;
	const char *option;
	const char *desc;
	dfaflags_t flags;
} optflag_table_t;

optflag_table_t dumpflag_table[] = {
	{ 1, "rule-exprs", "Dump rule to expr tree conversions",
	  DFA_DUMP_RULE_EXPR },
	{ 1, "expr-stats", "Dump stats on expr tree", DFA_DUMP_TREE_STATS },
	{ 1, "expr-tree", "Dump expression tree", DFA_DUMP_TREE },
	{ 1, "expr-simplified", "Dump simplified expression tree",
	  DFA_DUMP_SIMPLE_TREE },
	{ 1, "stats", "Dump all compile stats",
	  DFA_DUMP_TREE_STATS | DFA_DUMP_STATS | DFA_DUMP_TRANS_STATS |
	  DFA_DUMP_EQUIV_STATS },
	{ 1, "progress", "Dump progress for all compile phases",
	  DFA_DUMP_PROGRESS | DFA_DUMP_STATS | DFA_DUMP_TRANS_PROGRESS |
	  DFA_DUMP_TRANS_STATS },
	{ 1, "dfa-progress", "Dump dfa creation as in progress",
	  DFA_DUMP_PROGRESS | DFA_DUMP_STATS },
	{ 1, "dfa-stats", "Dump dfa creation stats", DFA_DUMP_STATS },
	{ 1, "dfa-states", "Dump dfa state diagram", DFA_DUMP_STATES },
	{ 1, "dfa-graph", "Dump dfa dot (graphviz) graph", DFA_DUMP_GRAPH },
	{ 1, "dfa-minimize", "Dump dfa minimization", DFA_DUMP_MINIMIZE },
	{ 1, "dfa-unreachable", "Dump dfa unreachable states",
	  DFA_DUMP_UNREACHABLE },
	{ 1, "dfa-node-map", "Dump expr node set to state mapping",
	  DFA_DUMP_NODE_TO_DFA },
	{ 1, "dfa-uniq-perms", "Dump unique perms",
	  DFA_DUMP_UNIQ_PERMS },
	{ 1, "dfa-minimize-uniq-perms", "Dump unique perms post minimization",
	  DFA_DUMP_MIN_UNIQ_PERMS },
	{ 1, "dfa-minimize-partitions", "Dump dfa minimization partitions",
	  DFA_DUMP_MIN_PARTS },
	{ 1, "compress-progress", "Dump progress of compression",
	  DFA_DUMP_TRANS_PROGRESS | DFA_DUMP_TRANS_STATS },
	{ 1, "compress-stats", "Dump stats on compression",
	  DFA_DUMP_TRANS_STATS },
	{ 1, "compressed-dfa", "Dump compressed dfa", DFA_DUMP_TRANS_TABLE },
	{ 1, "equiv-stats", "Dump equivance class stats",
	  DFA_DUMP_EQUIV_STATS },
	{ 1, "equiv", "Dump equivance class", DFA_DUMP_EQUIV },
	{ 0, NULL, NULL, 0 },
};

optflag_table_t optflag_table[] = {
	{ 2, "0", "no optimizations",
	  DFA_CONTROL_TREE_NORMAL | DFA_CONTROL_TREE_SIMPLE |
	  DFA_CONTROL_MINIMIZE | DFA_CONTROL_REMOVE_UNREACHABLE
	},
	{ 1, "equiv", "use equivalent classes", DFA_CONTROL_EQUIV },
	{ 1, "expr-normalize", "expression tree normalization",
	  DFA_CONTROL_TREE_NORMAL },
	{ 1, "expr-simplify", "expression tree simplification",
	  DFA_CONTROL_TREE_SIMPLE },
	{ 0, "expr-left-simplify", "left simplification first",
	  DFA_CONTROL_TREE_LEFT },
	{ 2, "expr-right-simplify", "right simplification first",
	  DFA_CONTROL_TREE_LEFT },
	{ 1, "minimize", "dfa state minimization", DFA_CONTROL_MINIMIZE },
	{ 1, "hash-trans", "minimization - hash transitions during setup",
	  DFA_CONTROL_MINIMIZE_HASH_TRANS },
	{ 1, "filter-deny", "filter out deny information from final dfa",
	  DFA_CONTROL_FILTER_DENY },
	{ 1, "remove-unreachable", "dfa unreachable state removal",
	  DFA_CONTROL_REMOVE_UNREACHABLE },
	{ 0, "compress-small",
	  "do slower dfa transition table compression",
	  DFA_CONTROL_TRANS_HIGH },
	{ 2, "compress-fast", "do faster dfa transition table compression",
	  DFA_CONTROL_TRANS_HIGH },
	{ 0, NULL, NULL, 0 },
};

static void print_flag_table(optflag_table_t *table)
{
	int i;
	unsigned int longest = 0;
	for (i = 0; table[i].option; i++) {
		if (strlen(table[i].option) > longest)
			longest = strlen(table[i].option);
	}

	for (i = 0; table[i].option; i++) {
		printf("%5s%-*s \t%s\n", (table[i].control & 1) ? "[no-]" : "",
		       longest, table[i].option, table[i].desc);
	}
}

static int handle_flag_table(optflag_table_t *table, const char *optarg,
			     dfaflags_t *flags)
{
	const char *arg = optarg;
	int i, invert = 0;

	if (strncmp(optarg, "no-", 3) == 0) {
		arg = optarg + 3;
		invert = 1;
	}

	for (i = 0; table[i].option; i++) {
		if (strcmp(table[i].option, arg) == 0) {
			/* check if leading no- was specified but is not
			 * supported by the option */
			if (invert && !(table[i].control & 1))
				return 0;
			if (table[i].control & 2)
				invert |= 1;
			if (invert)
				*flags &= ~table[i].flags;
			else
				*flags |= table[i].flags;
			return 1;
		}
	}
	return 0;
}

static void display_dump(char *command)
{
	display_version();
	printf("\n%s: --dump [Option]\n\n"
	       "Options:\n"
	       "--------\n"
	       "     none specified \tDump variables\n"
	       "     variables      \tDump variables\n"
	       ,command);
	print_flag_table(dumpflag_table);
}

static void display_optimize(char *command)
{
	display_version();
	printf("\n%s: -O [Option]\n\n"
	       "Options:\n"
	       "--------\n"
	       ,command);
	print_flag_table(optflag_table);
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
	default:
		display_usage(progname);
		exit(0);
		break;
	}

	return count;
}

static int process_args(int argc, char *argv[])
{
	int c, o;
	int count = 0;
	option = OPTION_ADD;

	while ((c = getopt_long(argc, argv, "adf:h::rRVvI:b:BCD:NSm:qQn:XKTWkO:po:", long_options, &o)) != -1)
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
	return 1;
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

static char *handle_features_dir(const char *filename, char **buffer, int size,
				 char *pos)
{
	DIR *dir = NULL;
	char *dirent_path = NULL;
	struct dirent *dirent;
	struct stat my_stat;
	int len;

	PDEBUG("Opened features directory \"%s\"\n", filename);
	if (!(dir = opendir(filename))) {
		PDEBUG("opendir failed '%s'", filename);
		exit(1);
	}

	while ((dirent = readdir(dir)) != NULL) {
		int name_len;
		/* skip dotfiles silently. */
		if (dirent->d_name[0] == '.')
			continue;

		if (dirent_path)
			free(dirent_path);
		if (asprintf(&dirent_path, "%s/%s", filename, dirent->d_name) < 0)
		{
			PERROR(_("Memory allocation error."));
			exit(1);
		}

		name_len = strlen(dirent->d_name);
		if (!name_len)
			continue;

		if (stat(dirent_path, &my_stat)) {
			PERROR(_("stat failed for '%s'"), dirent_path);
			exit(1);
		}

		pos = snprintf_buffer(*buffer, pos, size, "%s {", dirent->d_name);
		if (S_ISREG(my_stat.st_mode)) {
			int file;
			int remaining = size - (pos - *buffer);
			if (!(file = open(dirent_path, O_RDONLY))) {
				PDEBUG("Could not open '%s' in '%s'", dirent_path, filename);
				exit(1);
				break;
			}
			PDEBUG("Opened features \"%s\" in \"%s\"\n", dirent_path, filename);
			if (my_stat.st_size > remaining) {
				PERROR(_("Feature buffer full."));
				exit(1);
			}

			do {
				len = read(file, pos, remaining);
				if (len > 0) {
					remaining -= len;
					pos += len;
					*pos = 0;
				}
			} while (len > 0);
			if (len < 0) {
				PDEBUG("Error reading feature file '%s'\n",
				       dirent_path);
				exit(1);
			}
			close(file);

		} else if (S_ISDIR(my_stat.st_mode)) {
			pos = handle_features_dir(dirent_path, buffer, size,
						  pos);
			if (!pos)
				break;

		}

		pos = snprintf_buffer(*buffer, pos, size, "}\n");
	}
	if (dirent_path)
		free(dirent_path);
	closedir(dir);

	return pos;
}

/* match_string == NULL --> no match_string available
   match_string != NULL --> either a matching string specified on the
   command line, or the kernel supplied a match string */
static void get_match_string(void) {

	FILE *ms = NULL;
	struct stat stat_file;

	/* has process_args() already assigned a match string? */
	if (match_string)
		goto out;

	if (stat(FLAGS_FILE, &stat_file) == -1)
		goto out;

	if (S_ISDIR(stat_file.st_mode)) {
		/* if we have a features directory default to */
		regex_type = AARE_DFA;
		perms_create = 1;

		flags_string = malloc(FLAGS_STRING_SIZE);
		handle_features_dir(FLAGS_FILE, &flags_string, FLAGS_STRING_SIZE, flags_string);
		if (strstr(flags_string, "network"))
			kernel_supports_network = 1;
		else
			kernel_supports_network = 0;
		if (strstr(flags_string, "mount"))
			kernel_supports_mount = 1;
		return;
	}

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
	size_t size;

	/* abort if missing or already set */
	if (!flags || *flags)
		return;

	f = fopen(flags_file, "r");
	if (!f)
		return;

	*flags = malloc(FLAGS_STRING_SIZE);
	if (!*flags)
		goto fail;

	size = fread(*flags, 1, FLAGS_STRING_SIZE - 1, f);
	if (!size || ferror(f))
		goto fail;
	(*flags)[size] = 0;

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
	FILE *cmd;

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

	cmd = fopen("/proc/self/exe", "r");
	if (cmd) {
		update_mru_tstamp(cmd);
		fclose(cmd);
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
	if (profile_namespace)
		skip_cache = 1;

	/* Do secondary test to see if cached binary profile is good,
	 * instead of checking against a presupplied list of files
	 * use the timestamps from the files that were parsed.
	 * Parsing the profile is slower that doing primary cache check
	 * its still faster than doing full compilation
	 */
	if ((profilename && option != OPTION_REMOVE) && !force_complain &&
	    !skip_cache) {
		if (cacheloc) {
			cachename = strdup(cacheloc);
			if (!cachename) {
				PERROR(_("Memory allocation error."));
				exit(1);
			}
		} else if (asprintf(&cachename, "%s/%s/%s", basedir, "cache", basename)<0) {
			PERROR(_("Memory allocation error."));
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
			PERROR("Warning failed to create cache: %s\n", basename);
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
	} else if (strstr(flags_string, "network"))
		kernel_supports_network = 1;
	else
		kernel_supports_network = 0;



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
