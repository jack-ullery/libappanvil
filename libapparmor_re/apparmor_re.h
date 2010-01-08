/*   $Id$
 *
 *   Copyright (c) 2003, 2004, 2005, 2006, 2007 Novell, Inc.
 *   (All rights reserved)
 *
 *   The libapparmor library is licensed under the terms of the GNU
 *   Lesser General Public License, version 2.1. Please see the file
 *   COPYING.LGPL.
 */

#ifndef APPARMOR_RE_H
#define APPARMOR_RE_H

typedef enum dfaflags {
  DFA_DUMP_TREE_STATS =		1 << 8,
  DFA_DUMP_TREE =		1 << 9,
  DFA_DUMP_SIMPLE_TREE =	1 << 10,
  DFA_DUMP_PROGRESS =		1 << 11,
  DFA_DUMP_STATS =		1 << 12,
  DFA_DUMP_STATES =		1 << 13,
  DFA_DUMP_GRAPH =		1 << 14,
  DFA_DUMP_TRANS_PROGRESS =	1 << 15,
  DFA_DUMP_TRANS_STATS =	1 << 16,
  DFA_DUMP_TRANS_TABLE =	1 << 17,
  DFA_DUMP_EQUIV =		1 << 18,
  DFA_DUMP_EQUIV_STATS =	1 << 19,
} dfaflags_t;

#ifdef __cplusplus
extern "C" {
#endif

struct aare_ruleset;

typedef struct aare_ruleset aare_ruleset_t;

aare_ruleset_t *aare_new_ruleset(int reverse);
void aare_delete_ruleset(aare_ruleset_t *rules);
int aare_add_rule(aare_ruleset_t *rules, char *rule, int deny,
		  uint32_t perms, uint32_t audit);
int aare_add_rule_vec(aare_ruleset_t *rules, int deny, uint32_t perms,
		      uint32_t audit, int count, char **rulev);
void *aare_create_dfa(aare_ruleset_t *rules, int equiv_classes, size_t *size,
		      dfaflags_t flags);
void aare_reset_matchflags(void);

#ifdef __cplusplus
}
#endif

#endif /* APPARMOR_RE_H */
