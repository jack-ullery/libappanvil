/*
 *   Copyright (c) 1999, 2000, 2001, 2002, 2004, 2005, 2006, 2007
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
 *   along with this program; if not, contact Novell, Inc. or Canonical
 *   Ltd.
 */

#include <netinet/in.h>
#include <sys/resource.h>
#include "immunix.h"
#include "libapparmor_re/apparmor_re.h"
#include "libapparmor_re/aare_rules.h"

/* Global variable to pass token to lexer.  Will be replaced by parameter
 * when lexer and parser are made reentrant
 */
extern int parser_token;

typedef enum pattern_t pattern_t;

struct flagval {
  	int hat;
  	int complain;
  	int audit;
	int path;
};

struct named_transition {
	int present;
	char *namespace;
	char *name;
};

struct cod_pattern {
	char *regex;		// posix regex
};

struct cod_entry {
	char *namespace;
	char *name;
	char *link_name;
	char *nt_name;
	struct codomain *codomain; 	/* Special codomain defined
					 * just for this executable */
	int mode;			/* mode is 'or' of AA_* bits */
	int audit;			/* audit flags for mode */
	int deny;			/* TRUE or FALSE */

	int alias_ignore;		/* ignore for alias processing */

	int subset;

	pattern_t pattern_type;
	struct cod_pattern pat;

	struct cod_entry *next;
};

/* supported AF protocols */
struct aa_network_entry {
	unsigned int family;
	unsigned int type;
	unsigned int protocol;

	struct aa_network_entry *next;
};

struct aa_rlimits {
	unsigned int specified;			/* limits that are set */
	rlim_t limits[RLIMIT_NLIMITS];
};

struct alt_name {
	char *name;
	struct alt_name *next;
};

struct codomain {
	char *namespace;
	char *name;				/* codomain name */
	char *attachment;
	struct alt_name *altnames;
	void *xmatch;
	size_t xmatch_size;
	int xmatch_len;

	/* char *sub_name; */			/* subdomain name or NULL */
	/* int default_deny; */			/* TRUE or FALSE */
	int local;
	int local_mode;				/* true if local, not hat */
	int local_audit;

	struct codomain *parent;

	struct flagval flags;

	uint64_t capabilities;
	uint64_t audit_caps;
	uint64_t deny_caps;
	uint64_t quiet_caps;

	unsigned int *network_allowed;		/* array of type masks
						 * indexed by AF_FAMILY */
	unsigned int *audit_network;
	unsigned int *deny_network;
	unsigned int *quiet_network;

	struct aa_rlimits rlimits;

	char *exec_table[AA_EXEC_COUNT];
	struct cod_entry *entries;
	void *hat_table;
	//struct codomain *next;

	aare_ruleset_t *dfarules;
	int dfarule_count;
	void *dfa;
	size_t dfa_size;
};

struct sd_hat {
	char *hat_name;
	unsigned int hat_magic;
};

/* describe an ip address */
struct ipv4_desc {
	struct in_addr addr;
	unsigned long mask;
	unsigned short port[2];
};

struct ipv4_endpoints {
	struct ipv4_desc * src;
	struct ipv4_desc * dest;
};

struct var_string {
	char *prefix;
	char *var;
	char *suffix;
};

#define COD_READ_CHAR 		'r'
#define COD_WRITE_CHAR 		'w'
#define COD_APPEND_CHAR		'a'
#define COD_EXEC_CHAR 		'x'
#define COD_LINK_CHAR 		'l'
#define COD_LOCK_CHAR		'k'
#define COD_MMAP_CHAR		'm'
#define COD_INHERIT_CHAR 	'i'
#define COD_UNCONFINED_CHAR	'U'
#define COD_UNSAFE_UNCONFINED_CHAR	'u'
#define COD_PROFILE_CHAR	'P'
#define COD_UNSAFE_PROFILE_CHAR	'p'
#define COD_LOCAL_CHAR		'C'
#define COD_UNSAFE_LOCAL_CHAR	'c'

#define OPTION_ADD      1
#define OPTION_REMOVE   2
#define OPTION_REPLACE  3
#define OPTION_STDOUT	4
#define OPTION_OFILE	5

#define AARE_NONE 0
#define AARE_DFA 2

#define BOOL int

#define FLAG_CHANGEHAT_1_4  2
#define FLAG_CHANGEHAT_1_5  3

extern int preprocess_only;

#define PATH_CHROOT_REL 0x1
#define PATH_NS_REL 0x2
#define PATH_CHROOT_NSATTACH 0x4
#define PATH_CHROOT_NO_ATTACH 0x8
#define PATH_MEDIATE_DELETED 0x10
#define PATH_DELEGATE_DELETED 0x20
#define PATH_ATTACH 0x40
#define PATH_NO_ATTACH 0x80



#ifdef DEBUG
#define PDEBUG(fmt, args...) printf("parser: " fmt, ## args)
#else
#define PDEBUG(fmt, args...)	/* Do nothing */
#endif
#define NPDEBUG(fmt, args...)	/* Do nothing */

#define PERROR(fmt, args...) fprintf(stderr, fmt, ## args)

#ifndef TRUE
#define TRUE	(1)
#endif
#ifndef FALSE
#define FALSE	(0)
#endif

#define MIN_PORT 0
#define MAX_PORT 65535

#ifndef __unused
#define __unused __attribute__ ((unused))
#endif

#define list_for_each(LIST, ENTRY) \
	for ((ENTRY) = (LIST); (ENTRY); (ENTRY) = (ENTRY)->next)
#define list_for_each_safe(LIST, ENTRY, TMP) \
	for ((ENTRY) = (LIST), (TMP) = (LIST) ? (LIST)->next : NULL; (ENTRY); (ENTRY) = (TMP), (TMP) = (TMP) ? (TMP)->next : NULL)
#define list_last_entry(LIST, ENTRY) \
	for ((ENTRY) = (LIST); (ENTRY) && (ENTRY)->next; (ENTRY) = (ENTRY)->next)

/* from parser_common.c */
extern int regex_type;
extern int perms_create;
extern int net_af_max_override;
extern int kernel_load;
extern int kernel_supports_network;
extern int flag_changehat_version;
extern int conf_verbose;
extern int conf_quiet;
extern int names_only;
extern int option;
extern int current_lineno;
extern dfaflags_t dfaflags;
extern char *progname;
extern char *subdomainbase;
extern char *profilename;
extern char *profile_namespace;
extern char *current_filename;
extern FILE *ofile;
extern int read_implies_exec;
extern void pwarn(char *fmt, ...) __attribute__((__format__(__printf__, 1, 2)));

/* from parser_main (cannot be used in tst builds) */
extern int force_complain;
extern struct timespec mru_tstamp;
extern void update_mru_tstamp(FILE *file);

/* provided by parser_lex.l (cannot be used in tst builds) */
extern FILE *yyin;
extern void yyrestart(FILE *fp);
extern int yyparse(void);
extern void yyerror(char *msg, ...);
extern int yylex(void);

/* parser_include.c */
extern char *basedir;

/* parser_regex.c */
extern int process_regex(struct codomain *cod);
extern int post_process_entry(struct cod_entry *entry);
extern void reset_regex(void);

/* parser_variable.c */
extern int process_variables(struct codomain *cod);
extern struct var_string *split_out_var(char *string);
extern void free_var_string(struct var_string *var);

/* parser_misc.c */
extern char *processid(char *string, int len);
extern char *processquoted(char *string, int len);
extern char *processunquoted(char *string, int len);
extern int get_keyword_token(const char *keyword);
extern int name_to_capability(const char *keyword);
extern int get_rlimit(const char *name);
extern char *process_var(const char *var);
extern int parse_mode(const char *mode);
extern struct cod_entry *new_entry(char *namespace, char *id, int mode,
				   char *link_id);
extern struct aa_network_entry *new_network_ent(unsigned int family,
						unsigned int type,
						unsigned int protocol);
extern struct aa_network_entry *network_entry(const char *family,
					      const char *type,
					      const char *protocol);
extern size_t get_af_max(void);

extern void debug_cod_list(struct codomain *list);
/* returns -1 if value != true or false, otherwise 0 == false, 1 == true */
extern int str_to_boolean(const char* str);
extern struct cod_entry *copy_cod_entry(struct cod_entry *cod);
extern void free_cod_entries(struct cod_entry *list);

/* parser_symtab.c */
struct set_value {;
	char *val;
	struct set_value *next;
};
extern int add_boolean_var(const char *var, int boolean);
extern int get_boolean_var(const char *var);
extern int new_set_var(const char *var, const char *value);
extern int add_set_value(const char *var, const char *value);
extern struct set_value *get_set_var(const char *var);
extern char *get_next_set_value(struct set_value **context);
extern void dump_symtab(void);
extern void dump_expanded_symtab(void);
void free_symtabs(void);

/* parser_alias.c */
extern int new_alias(const char *from, const char *to);
extern void replace_aliases(struct codomain *cod);
extern void free_aliases(void);

/* parser_merge.c */
extern int codomain_merge_rules(struct codomain *cod);

/* parser_interface.c */
typedef struct __sdserialize sd_serialize;
extern int load_codomain(int option, struct codomain *cod);
extern int sd_serialize_profile(sd_serialize *p, struct codomain *cod,
				int flatten);
extern int sd_load_buffer(int option, char *buffer, int size);
extern int cache_fd;


/* parser_policy.c */
extern void add_to_list(struct codomain *codomain);
extern void add_hat_to_policy(struct codomain *policy, struct codomain *hat);
extern void add_entry_to_policy(struct codomain *policy, struct cod_entry *entry);
extern void post_process_nt_entries(struct codomain *cod);
extern int post_process_policy(int debug_only);
extern int process_hat_regex(struct codomain *cod);
extern int process_hat_variables(struct codomain *cod);
extern int post_merge_rules(void);
extern int merge_hat_rules(struct codomain *cod);
extern struct codomain *merge_policy(struct codomain *a, struct codomain *b);
extern int load_policy(int option);
extern int load_hats(sd_serialize *p, struct codomain *cod);
extern int load_flattened_hats(struct codomain *cod);
extern void free_policy(struct codomain *cod);
extern void dump_policy(void);
extern void dump_policy_hats(struct codomain *cod);
extern void dump_policy_names(void);
extern int die_if_any_regex(void);
void free_policies(void);

#ifdef UNIT_TEST
/* For the unit-test builds, we must include function stubs for stuff that
 * only exists in the excluded object files; everything else should live
 * in parser_common.c.
 */

/* parser_yacc.y */
void yyerror(char *msg, ...)
{
        va_list arg;
        char buf[PATH_MAX];

        va_start(arg, msg);
        vsnprintf(buf, sizeof(buf), msg, arg);
        va_end(arg);

        PERROR(_("AppArmor parser error: %s\n"), buf);

        exit(1);
}

#define MY_TEST(statement, error)               \
        if (!(statement)) {                     \
                PERROR("FAIL: %s\n", error);    \
                rc = 1;                         \
        }

#endif
