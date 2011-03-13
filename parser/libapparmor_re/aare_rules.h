/*
 * (C) 2006, 2007 Andreas Gruenbacher <agruen@suse.de>
 * Copyright (c) 2003-2008 Novell, Inc. (All rights reserved)
 * Copyright 2009-2010 Canonical Ltd.
 *
 * The libapparmor library is licensed under the terms of the GNU
 * Lesser General Public License, version 2.1. Please see the file
 * COPYING.LGPL.
 *
 * This library is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU Lesser General Public License for more details.
 *
 * You should have received a copy of the GNU Lesser General Public License
 * along with this program.  If not, see <http://www.gnu.org/licenses/>.
 *
 *
 * Wrapper around the dfa to convert aa rules into a dfa
 */
#ifndef __LIBAA_RE_RULES_H
#define __LIBAA_RE_RULES_H

#ifdef __cplusplus
extern "C" {
#endif

struct aare_ruleset;

typedef struct aare_ruleset aare_ruleset_t;

aare_ruleset_t *aare_new_ruleset(int reverse);
void aare_delete_ruleset(aare_ruleset_t *rules);
int aare_add_rule(aare_ruleset_t *rules, char *rule, int deny,
		  uint32_t perms, uint32_t audit, dfaflags_t flags);
int aare_add_rule_vec(aare_ruleset_t *rules, int deny, uint32_t perms,
		      uint32_t audit, int count, char **rulev, dfaflags_t flags);
void *aare_create_dfa(aare_ruleset_t *rules, size_t *size, dfaflags_t flags);
void aare_reset_matchflags(void);

#ifdef __cplusplus
}
#endif

#endif /* __LIBAA_RE_RULES_H */
