/*
 * (C) 2006, 2007 Andreas Gruenbacher <agruen@suse.de>
 * Copyright (c) 2003-2008 Novell, Inc. (All rights reserved)
 * Copyright 2009-2013 Canonical Ltd. (All rights reserved)
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

#include <ostream>
#include <iostream>
#include <fstream>
#include <sstream>
#include <ext/stdio_filebuf.h>
#include <assert.h>
#include <stdlib.h>

#include "aare_rules.h"
#include "expr-tree.h"
#include "parse.h"
#include "hfa.h"
#include "chfa.h"
#include "../immunix.h"



aare_rules::~aare_rules(void)
{
	if (root)
		root->release();

	aare_reset_matchflags();
}

bool aare_rules::add_rule(const char *rule, int deny, uint32_t perms,
			  uint32_t audit, dfaflags_t flags)
{
	return add_rule_vec(deny, perms, audit, 1, &rule, flags);
}

#define FLAGS_WIDTH 2
#define MATCH_FLAGS_SIZE (sizeof(uint32_t) * 8 - 1)
MatchFlag *match_flags[FLAGS_WIDTH][MATCH_FLAGS_SIZE];
DenyMatchFlag *deny_flags[FLAGS_WIDTH][MATCH_FLAGS_SIZE];
#define EXEC_MATCH_FLAGS_SIZE (AA_EXEC_COUNT *2 * 2 * 2)	/* double for each of ix pux, unsafe x bits * u::o */
MatchFlag *exec_match_flags[FLAGS_WIDTH][EXEC_MATCH_FLAGS_SIZE];	/* mods + unsafe + ix + pux * u::o */
ExactMatchFlag *exact_match_flags[FLAGS_WIDTH][EXEC_MATCH_FLAGS_SIZE];	/* mods + unsafe + ix + pux *u::o */

void aare_reset_matchflags(void)
{
	uint32_t i, j;
#define RESET_FLAGS(group, size) { \
	for (i = 0; i < FLAGS_WIDTH; i++) { \
		for (j = 0; j < size; j++) { \
		    if ((group)[i][j]) delete (group)[i][j];	\
			(group)[i][j] = NULL; \
		} \
	} \
}
	RESET_FLAGS(match_flags, MATCH_FLAGS_SIZE);
	RESET_FLAGS(deny_flags, MATCH_FLAGS_SIZE);
	RESET_FLAGS(exec_match_flags, EXEC_MATCH_FLAGS_SIZE);
	RESET_FLAGS(exact_match_flags, EXEC_MATCH_FLAGS_SIZE);
#undef RESET_FLAGS
}

void aare_rules::add_to_rules(Node *tree, Node *perms)
{
	if (reverse)
		flip_tree(tree);
	if (root)
		root = new AltNode(root, new CatNode(tree, perms));
	else
		root = new CatNode(tree, perms);
}

static Node *cat_with_null_seperator(Node *l, Node *r)
{
	return new CatNode(new CatNode(l, new CharNode(0)), r);
}

static Node *convert_file_perms(int deny, uint32_t perms, uint32_t audit,
				bool exact_match)
{
	Node *accept;

	assert(perms != 0);

/* 0x7f == 4 bits x mods + 1 bit unsafe mask + 1 bit ix, + 1 pux after shift */
#define EXTRACT_X_INDEX(perm, shift) (((perm) >> (shift + 7)) & 0x7f)


	/* the permissions set is assumed to be non-empty if any audit
	 * bits are specified */
	accept = NULL;
	for (unsigned int n = 0; perms && n < (sizeof(perms) * 8); n++) {
		uint32_t mask = 1 << n;

		if (!(perms & mask))
			continue;

		int ai = audit & mask ? 1 : 0;
		perms &= ~mask;

		Node *flag;
		if (mask & ALL_AA_EXEC_TYPE)
			/* these cases are covered by EXEC_BITS */
			continue;
		if (deny) {
			if (deny_flags[ai][n]) {
				flag = deny_flags[ai][n];
			} else {
//fprintf(stderr, "Adding deny ai %d mask 0x%x audit 0x%x\n", ai, mask, audit & mask);
				deny_flags[ai][n] = new DenyMatchFlag(mask, audit & mask);
				flag = deny_flags[ai][n];
			}
		} else if (mask & AA_EXEC_BITS) {
			uint32_t eperm = 0;
			uint32_t index = 0;
			if (mask & AA_USER_EXEC) {
				eperm = mask | (perms & AA_USER_EXEC_TYPE);
				index = EXTRACT_X_INDEX(eperm, AA_USER_SHIFT);
			} else {
				eperm = mask | (perms & AA_OTHER_EXEC_TYPE);
				index = EXTRACT_X_INDEX(eperm, AA_OTHER_SHIFT) + (AA_EXEC_COUNT << 2);
			}
//fprintf(stderr, "index %d eperm 0x%x\n", index, eperm);
			if (exact_match) {
				if (exact_match_flags[ai][index]) {
					flag = exact_match_flags[ai][index];
				} else {
					exact_match_flags[ai][index] = new ExactMatchFlag(eperm, audit & mask);
					flag = exact_match_flags[ai][index];
				}
			} else {
				if (exec_match_flags[ai][index]) {
					flag = exec_match_flags[ai][index];
				} else {
					exec_match_flags[ai][index] = new MatchFlag(eperm, audit & mask);
					flag = exec_match_flags[ai][index];
				}
			}
		} else {
			if (match_flags[ai][n]) {
				flag = match_flags[ai][n];
			} else {
				match_flags[ai][n] = new MatchFlag(mask, audit & mask);
				flag = match_flags[ai][n];
			}
		}
		if (accept)
			accept = new AltNode(accept, flag);
		else
			accept = flag;
	} /* for ... */

	return accept;
}

bool aare_rules::add_rule_vec(int deny, uint32_t perms, uint32_t audit,
			      int count, const char **rulev, dfaflags_t flags)
{
	Node *tree = NULL, *accept;
	int exact_match;

	if (regex_parse(&tree, rulev[0]))
		return false;
	for (int i = 1; i < count; i++) {
		Node *subtree = NULL;
		if (regex_parse(&subtree, rulev[i]))
			return false;
		tree = cat_with_null_seperator(tree, subtree);
	}

	/*
	 * Check if we have an expression with or without wildcards. This
	 * determines how exec modifiers are merged in accept_perms() based
	 * on how we split permission bitmasks here.
	 */
	exact_match = 1;
	for (depth_first_traversal i(tree); i && exact_match; i++) {
		if (dynamic_cast<StarNode *>(*i) ||
		    dynamic_cast<PlusNode *>(*i) ||
		    dynamic_cast<AnyCharNode *>(*i) ||
		    dynamic_cast<CharSetNode *>(*i) ||
		    dynamic_cast<NotCharSetNode *>(*i))
			exact_match = 0;
	}

	if (reverse)
		flip_tree(tree);

	accept = convert_file_perms(deny, perms, audit, exact_match);

	if (flags & DFA_DUMP_RULE_EXPR) {
		cerr << "rule: ";
		cerr << rulev[0];
		for (int i = 1; i < count; i++) {
			cerr << "\\x00";
			cerr << rulev[i];
		}
		cerr << "  ->  ";
		tree->dump(cerr);
		if (deny)
			cerr << " deny";
		cerr << " (0x" << hex << perms <<"/" << audit << dec << ")";
		accept->dump(cerr);
 		cerr << "\n\n";
	}

	add_to_rules(tree, accept);

	rule_count++;

	return true;
}

/* create a dfa from the ruleset
 * returns: buffer contain dfa tables, @size set to the size of the tables
 *          else NULL on failure
 */
void *aare_rules::create_dfa(size_t *size, dfaflags_t flags)
{
	char *buffer = NULL;

	label_nodes(root);
	if (flags & DFA_DUMP_TREE) {
		cerr << "\nDFA: Expression Tree\n";
		root->dump(cerr);
		cerr << "\n\n";
	}

	if (flags & DFA_CONTROL_TREE_SIMPLE) {
		root = simplify_tree(root, flags);

		if (flags & DFA_DUMP_SIMPLE_TREE) {
			cerr << "\nDFA: Simplified Expression Tree\n";
			root->dump(cerr);
			cerr << "\n\n";
		}
	}

	stringstream stream;
	try {
		DFA dfa(root, flags);
		if (flags & DFA_DUMP_UNIQ_PERMS)
			dfa.dump_uniq_perms("dfa");

		if (flags & DFA_CONTROL_MINIMIZE) {
			dfa.minimize(flags);

			if (flags & DFA_DUMP_MIN_UNIQ_PERMS)
				dfa.dump_uniq_perms("minimized dfa");
		}

		if (flags & DFA_CONTROL_FILTER_DENY &&
		    flags & DFA_CONTROL_MINIMIZE &&
		    dfa.apply_and_clear_deny()) {
			/* Do a second minimization pass as removal of deny
			 * information has moved some states from accepting
			 * to none accepting partitions
			 *
			 * TODO: add this as a tail pass to minimization
			 *       so we don't need to do a full second pass
			 */
			dfa.minimize(flags);

			if (flags & DFA_DUMP_MIN_UNIQ_PERMS)
				dfa.dump_uniq_perms("minimized dfa");
		}

		if (flags & DFA_CONTROL_REMOVE_UNREACHABLE)
			dfa.remove_unreachable(flags);

		if (flags & DFA_DUMP_STATES)
			dfa.dump(cerr);

		if (flags & DFA_DUMP_GRAPH)
			dfa.dump_dot_graph(cerr);

		map<uchar, uchar> eq;
		if (flags & DFA_CONTROL_EQUIV) {
			eq = dfa.equivalence_classes(flags);
			dfa.apply_equivalence_classes(eq);

			if (flags & DFA_DUMP_EQUIV) {
				cerr << "\nDFA equivalence class\n";
				dump_equivalence_classes(cerr, eq);
			}
		} else if (flags & DFA_DUMP_EQUIV)
			cerr << "\nDFA did not generate an equivalence class\n";

		if (flags & DFA_CONTROL_DIFF_ENCODE) {
			dfa.diff_encode(flags);

			if (flags & DFA_DUMP_DIFF_ENCODE)
				dfa.dump_diff_encode(cerr);
		}

		CHFA chfa(dfa, eq, flags);
		if (flags & DFA_DUMP_TRANS_TABLE)
			chfa.dump(cerr);
		chfa.flex_table(stream, "");
	}
	catch(int error) {
		*size = 0;
		return NULL;
	}

	stringbuf *buf = stream.rdbuf();

	buf->pubseekpos(0);
	*size = buf->in_avail();

	buffer = (char *)malloc(*size);
	if (!buffer)
		return NULL;
	buf->sgetn(buffer, *size);
	return buffer;
}
