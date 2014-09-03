/*
 * (C) 2006, 2007 Andreas Gruenbacher <agruen@suse.de>
 * Copyright (c) 2003-2008 Novell, Inc. (All rights reserved)
 * Copyright 2009-2012 Canonical Ltd.
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

#include <stdint.h>

#include "apparmor_re.h"
#include "expr-tree.h"

class aare_rules {
	Node *root;
	void add_to_rules(Node *tree, Node *perms);
public:
	int reverse;
	int rule_count;
	aare_rules(): root(NULL), reverse(0), rule_count(0) { };
	aare_rules(int reverse): root(NULL), reverse(reverse), rule_count(0) { };
	~aare_rules();

	bool add_rule(const char *rule, int deny, uint32_t perms,
		      uint32_t audit, dfaflags_t flags);
	bool add_rule_vec(int deny, uint32_t perms, uint32_t audit, int count,
			  const char **rulev, dfaflags_t flags);
	void *create_dfa(size_t *size, dfaflags_t flags);
};

void aare_reset_matchflags(void);

#endif				/* __LIBAA_RE_RULES_H */
