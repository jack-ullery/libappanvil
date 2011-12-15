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
  * Base of implementation based on the Lexical Analysis chapter of:
 *   Alfred V. Aho, Ravi Sethi, Jeffrey D. Ullman:
 *   Compilers: Principles, Techniques, and Tools (The "Dragon Book"),
 *   Addison-Wesley, 1986.
 */
#ifndef __LIBAA_RE_HFA_H
#define __LIBAA_RE_HFA_H

#include <list>
#include <map>
#include <vector>

#include <stdint.h>

#include "expr-tree.h"

class State;

typedef map<uchar, State *> StateTrans;
typedef list<State *> Partition;

uint32_t accept_perms(NodeSet *state, uint32_t *audit_ctl, int *error);

/*
 * hashedNodes - for efficient set comparison
 */
class hashedNodeSet {
public:
	unsigned long hash;
	NodeSet *nodes;

	hashedNodeSet(NodeSet *n): nodes(n)
	{
		hash = hash_NodeSet(n);
	}

	bool operator<(hashedNodeSet const &rhs)const
	{
		if (hash == rhs.hash) {
			if (nodes->size() == rhs.nodes->size())
				return *nodes < *(rhs.nodes);
			else
				return nodes->size() < rhs.nodes->size();
		} else {
			return hash < rhs.hash;
		}
	}
};

/*
 * ProtoState - NodeSet and ancillery information used to create a state
 */
class ProtoState {
public:
	typedef NodeSet::iterator iterator;
	iterator begin() { return nodes->begin(); }
	iterator end() { return nodes->end(); }

	NodeSet *nodes;

	ProtoState(NodeSet *n): nodes(n) { };
	bool operator<(ProtoState const &rhs)const
	{
		return nodes < rhs.nodes;
	}

	unsigned long size(void) { return nodes->size(); }
};

/*
 * State - DFA individual state information
 * label: a unique label to identify the state used for pretty printing
 *        the non-matching state is setup to have label == 0 and
 *        the start state is setup to have label == 1
 * audit: the audit permission mask for the state
 * accept: the accept permissions for the state
 * trans: set of transitions from this state
 * otherwise: the default state for transitions not in @trans
 * parition: Is a temporary work variable used during dfa minimization.
 *           it can be replaced with a map, but that is slower and uses more
 *           memory.
 * nodes: Is a temporary work variable used during dfa creation.  It can
 *        be replaced by using the nodemap, but that is slower
 */
class State {
public:
	State(int l, ProtoState &n, State *other) throw(int):
		label(l), audit(0), accept(0), trans()
	{
		int error;

		if (other)
			otherwise = other;
		else
			otherwise = this;

		proto = n;

		/* Compute permissions associated with the State. */
		accept = accept_perms(n.nodes, &audit, &error);
		if (error) {
			//cerr << "Failing on accept perms " << error << "\n";
			throw error;
		}
	};

	int label;
	uint32_t audit, accept;
	StateTrans trans;
	State *otherwise;

	/* temp storage for State construction */
	union {
		Partition *partition;
		ProtoState proto;
	};
};

ostream &operator<<(ostream &os, const State &state);


typedef map<ProtoState, State *> NodeMap;
/* Transitions in the DFA. */

/* dfa_stats - structure to group various stats about dfa creation
 * duplicates - how many duplicate NodeSets where encountered and discarded
 * proto_max - maximum length of a NodeSet encountered during dfa construction
 * proto_sum - sum of NodeSet length during dfa construction.  Used to find
 *             average length.
 */
typedef struct dfa_stats {
	unsigned int duplicates, proto_max, proto_sum;
} dfa_stats_t;

class DFA {
	void dump_node_to_dfa(void);
	State *add_new_state(NodeMap &nodemap,
			     ProtoState &proto, State *other, dfa_stats_t &stats);
	void update_state_transitions(NodeMap &nodemap,
				      list<State *> &work_queue,
				      State *state, dfa_stats_t &stats);
	State *find_target_state(NodeMap &nodemap, list<State *> &work_queue,
				 NodeSet *nodes, dfa_stats_t &stats);

	/* temporary values used during computations */
	set<hashedNodeSet> uniq_nodes;

public:
	DFA(Node *root, dfaflags_t flags);
	virtual ~DFA();
	void remove_unreachable(dfaflags_t flags);
	bool same_mappings(State *s1, State *s2);
	size_t hash_trans(State *s);
	void minimize(dfaflags_t flags);
	void dump(ostream &os);
	void dump_dot_graph(ostream &os);
	void dump_uniq_perms(const char *s);
	map<uchar, uchar> equivalence_classes(dfaflags_t flags);
	void apply_equivalence_classes(map<uchar, uchar> &eq);
	Node *root;
	State *nonmatching, *start;
	Partition states;
};

void dump_equivalence_classes(ostream &os, map<uchar, uchar> &eq);

#endif /* __LIBAA_RE_HFA_H */
