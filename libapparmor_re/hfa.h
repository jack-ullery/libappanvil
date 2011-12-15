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


class hashedNodeVec {
public:
	typedef ImportantNode ** iterator;
	iterator begin() { return nodes; }
	iterator end() { iterator t = nodes ? &nodes[len] : NULL; return t; }

	unsigned long hash;
	unsigned long len;
	ImportantNode **nodes;

	hashedNodeVec(NodeSet *n)
	{
		hash = hash_NodeSet(n);
		len = n->size();
		nodes = new ImportantNode *[n->size()];

		unsigned int j = 0;
		for (NodeSet::iterator i = n->begin(); i != n->end(); i++, j++) {
			nodes[j] = *i;
		}
	}

	hashedNodeVec(NodeSet *n, unsigned long h): hash(h)
	{
		len = n->size();
		nodes = new ImportantNode *[n->size()];
		ImportantNode **j = nodes;
		for (NodeSet::iterator i = n->begin(); i != n->end(); i++) {
			*(j++) = *i;
		}
	}

	~hashedNodeVec()
	{
		delete nodes;
	}

	unsigned long size()const { return len; }

	bool operator<(hashedNodeVec const &rhs)const
	{
		if (hash == rhs.hash) {
			if (len == rhs.size()) {
				for (unsigned int i = 0; i < len; i++) {
					if (nodes[i] != rhs.nodes[i])
						return nodes[i] < rhs.nodes[i];
				}
				return false;
			}
			return len < rhs.size();
		}
		return hash < rhs.hash;
	}
};

class CacheStats {
public:
	unsigned long dup, sum, max;

	CacheStats(void): dup(0), sum(0), max(0) { };

	void clear(void) { dup = sum = max = 0; }
	virtual unsigned long size(void) const = 0;
};

class NodeCache: public CacheStats {
public:
	set<hashedNodeSet> cache;

	NodeCache(void): cache() { };
	~NodeCache() { clear(); };

	virtual unsigned long size(void) const { return cache.size(); }

	void clear()
	{
		for (set<hashedNodeSet>::iterator i = cache.begin();
		     i != cache.end(); i++) {
			delete i->nodes;
		}
		cache.clear();
		CacheStats::clear();
	}

	NodeSet *insert(NodeSet *nodes)
	{
		if (!nodes)
			return NULL;
		pair<set<hashedNodeSet>::iterator,bool> uniq;
		uniq = cache.insert(hashedNodeSet(nodes));
		if (uniq.second == false) {
			delete(nodes);
			dup++;
		} else {
			sum += nodes->size();
			if (nodes->size() > max)
				max = nodes->size();
		}
		return uniq.first->nodes;
	}
};

struct deref_less_than {
       bool operator()(hashedNodeVec * const &lhs, hashedNodeVec * const &rhs)const
		{
			return *lhs < *rhs;
		}
};

class NodeVecCache: public CacheStats {
public:
	set<hashedNodeVec *, deref_less_than> cache;

	NodeVecCache(void): cache() { };
	~NodeVecCache() { clear(); };

	virtual unsigned long size(void) const { return cache.size(); }

	void clear()
	{
		for (set<hashedNodeVec *>::iterator i = cache.begin();
		     i != cache.end(); i++) {
			delete *i;
		}
		cache.clear();
		CacheStats::clear();
	}

	hashedNodeVec *insert(NodeSet *nodes)
	{
		if (!nodes)
			return NULL;
		pair<set<hashedNodeVec *>::iterator,bool> uniq;
		hashedNodeVec *nv = new hashedNodeVec(nodes);
		uniq = cache.insert(nv);
		if (uniq.second == false) {
			delete nv;
			dup++;
		} else {
			sum += nodes->size();
			if (nodes->size() > max)
				max = nodes->size();
		}
		delete(nodes);
		return (*uniq.first);
	}
};

/*
 * ProtoState - NodeSet and ancillery information used to create a state
 */
class ProtoState {
public:
	hashedNodeVec *nnodes;
	NodeSet *anodes;

	ProtoState(hashedNodeVec *n, NodeSet *a = NULL): nnodes(n), anodes(a) { };
	bool operator<(ProtoState const &rhs)const
	{
		if (nnodes == rhs.nnodes)
			return anodes < rhs.anodes;
		return nnodes < rhs.nnodes;
	}

	unsigned long size(void)
	{
		if (anodes)
			return nnodes->size() + anodes->size();
		return nnodes->size();
	}
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
		accept = accept_perms(n.anodes, &audit, &error);
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

class NodeMap: public CacheStats
{
public:
	typedef map<ProtoState, State *>::iterator iterator;
	iterator begin() { return cache.begin(); }
	iterator end() { return cache.end(); }

	map<ProtoState, State *> cache;

	NodeMap(void): cache() { };
	~NodeMap() { clear(); };

	virtual unsigned long size(void) const { return cache.size(); }

	void clear()
	{
		cache.clear();
		CacheStats::clear();
	}

	pair<iterator,bool> insert(ProtoState &proto, State *state)
	{
		pair<iterator,bool> uniq;
		uniq = cache.insert(make_pair(proto, state));
		if (uniq.second == false) {
			dup++;
		} else {
			sum += proto.size();
			if (proto.size() > max)
				max = proto.size();
		}
		return uniq;
	}
};

/* Transitions in the DFA. */

class DFA {
	void dump_node_to_dfa(void);
	State *add_new_state(NodeSet *nodes, State *other);
	void update_state_transitions(State *state);

	/* temporary values used during computations */
	NodeCache anodes_cache;
	NodeVecCache nnodes_cache;
	NodeMap node_map;
	list<State *> work_queue;

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
