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

#include <list>
#include <vector>
#include <stack>
#include <set>
#include <map>
#include <ostream>
#include <iostream>
#include <fstream>


#include <string.h>
#include <getopt.h>
#include <assert.h>
#include <arpa/inet.h>

#include <iostream>
#include <fstream>

#include "expr-tree.h"
#include "../immunix.h"




class State;
/**
 * State cases are identical to NodesCases except they map to State *
 * instead of NodeSet.
 * Out-edges from a state to another: we store the follow State
 * for each input character that is not a default match in  cases and
 * default matches in otherwise as well as in all matching explicit cases
 * This avoids enumerating all the explicit tranitions for default matches.
 */
typedef struct Cases {
	typedef map<uchar, State *>::iterator iterator;
	iterator begin() { return cases.begin(); }
	iterator end() { return cases.end(); }

	Cases() : otherwise(0) { }
	map<uchar, State *> cases;
	State *otherwise;
} Cases;

typedef list<State *> Partition;

uint32_t accept_perms(NodeSet *state, uint32_t *audit_ctl, int *error);

/*
 * State - DFA individual state information
 * label: a unique label to identify the state used for pretty printing
 *        the non-matching state is setup to have label == 0 and
 *        the start state is setup to have label == 1
 * audit: the audit permission mask for the state
 * accept: the accept permissions for the state
 * cases: set of transitions from this state
 * parition: Is a temporary work variable used during dfa minimization.
 *           it can be replaced with a map, but that is slower and uses more
 *           memory.
 * nodes: Is a temporary work variable used during dfa creation.  It can
 *        be replaced by using the nodemap, but that is slower
 */
class State {
public:
	State() : label (0), audit(0), accept(0), cases(), nodes(NULL) { };
	State(int l): label (l), audit(0), accept(0), cases(), nodes(NULL) { };
	State(int l, NodeSet *n) throw (int):
		label(l), audit(0), accept(0), cases(), nodes(n)
	{
		int error;

		/* Compute permissions associated with the State. */
		accept = accept_perms(nodes, &audit, &error);
		if (error) {
cerr << "Failing on accept perms " << error << "\n";
			throw error;
		}
	};

	int label;
	uint32_t audit, accept;
	Cases cases;
	union {
		Partition *partition;
		NodeSet *nodes;
	};
};

ostream& operator<<(ostream& os, const State& state)
{
	/* dump the state label */
	os << '{';
	os << state.label;
	os << '}';
	return os;
}

typedef map<pair<unsigned long, NodeSet *>, State *, deref_less_than > NodeMap;
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
    State* add_new_state(NodeMap &nodemap, pair <unsigned long, NodeSet *> index, NodeSet *nodes, dfa_stats_t &stats);
    void update_state_transitions(NodeMap &nodemap, list <State *> &work_queue, State *state, dfa_stats_t &stats);
    State *find_target_state(NodeMap &nodemap, list <State *> &work_queue,
			     NodeSet *nodes, dfa_stats_t &stats);
public:
    DFA(Node *root, dfaflags_t flags);
    virtual ~DFA();
    void remove_unreachable(dfaflags_t flags);
    bool same_mappings(State *s1, State *s2);
    size_t hash_trans(State *s);
    void minimize(dfaflags_t flags);
    void dump(ostream& os);
    void dump_dot_graph(ostream& os);
    void dump_uniq_perms(const char *s);
    map<uchar, uchar> equivalence_classes(dfaflags_t flags);
    void apply_equivalence_classes(map<uchar, uchar>& eq);
    Node *root;
    State *nonmatching, *start;
    Partition states;
};

State* DFA::add_new_state(NodeMap &nodemap, pair <unsigned long, NodeSet *> index, NodeSet *nodes, dfa_stats_t &stats)
{
	State *state = new State(nodemap.size(), nodes);
	states.push_back(state);
	nodemap.insert(make_pair(index, state));
	stats.proto_sum += nodes->size();
	if (nodes->size() > stats.proto_max)
		stats.proto_max = nodes->size();
	return state;
}

State *DFA::find_target_state(NodeMap &nodemap, list <State *> &work_queue,
			      NodeSet *nodes, dfa_stats_t &stats)
{
	State *target;

	pair <unsigned long, NodeSet *> index = make_pair(hash_NodeSet(nodes), nodes);

	map<pair <unsigned long, NodeSet *>, State *, deref_less_than>::iterator x = nodemap.find(index);

	if (x == nodemap.end()) {
		/* set of nodes isn't known so create new state, and nodes to
		 * state mapping
		 */
		target = add_new_state(nodemap, index, nodes, stats);
		work_queue.push_back(target);
	} else {
		/* set of nodes already has a mapping so free this one */
		stats.duplicates++;
		delete (nodes);
		target = x->second;
	}

	return target;
}

void DFA::update_state_transitions(NodeMap &nodemap,
				   list <State *> &work_queue, State *state,
				   dfa_stats_t &stats)
{
	/* Compute possible transitions for state->nodes.  This is done by
	 * iterating over all the nodes in state->nodes and combining the
	 * transitions.
	 *
	 * The resultant transition set is a mapping of characters to
	 * sets of nodes.
	 */
	NodeCases cases;
	for (NodeSet::iterator i = state->nodes->begin(); i != state->nodes->end(); i++)
		(*i)->follow(cases);

	/* Now for each set of nodes in the computed transitions, make
	 * sure that there is a state that maps to it, and add the
	 * matching case to the state.
	 */

	/* check the default transition first */
	if (cases.otherwise)
		state->cases.otherwise = find_target_state(nodemap, work_queue,
							   cases.otherwise,
							   stats);;

	/* For each transition from *from, check if the set of nodes it
	 * transitions to already has been mapped to a state
	 */
	for (NodeCases::iterator j = cases.begin(); j != cases.end(); j++) {
		State *target;
		target = find_target_state(nodemap, work_queue, j->second,
					   stats);

		/* Don't insert transition that the default transition
		 * already covers
		 */
		if (target != state->cases.otherwise)
			state->cases.cases[j->first] = target;
	}
}


/* WARNING: This routine can only be called from within DFA creation as
 * the nodes value is only valid during dfa construction.
 */
void DFA::dump_node_to_dfa(void)
{
	cerr << "Mapping of States to expr nodes\n"
		"  State  <=   Nodes\n"
		"-------------------\n";
	for (Partition::iterator i = states.begin(); i != states.end(); i++)
		cerr << "  " << (*i)->label << " <= " << *(*i)->nodes << "\n";
}

/**
 * Construct a DFA from a syntax tree.
 */
DFA::DFA(Node *root, dfaflags_t flags) : root(root)
{
	dfa_stats_t stats = { 0, 0, 0 };
	int i = 0;

	if (flags & DFA_DUMP_PROGRESS)
		fprintf(stderr, "Creating dfa:\r");

	for (depth_first_traversal i(root); i; i++) {
		(*i)->compute_nullable();
		(*i)->compute_firstpos();
		(*i)->compute_lastpos();
	}

	if (flags & DFA_DUMP_PROGRESS)
		fprintf(stderr, "Creating dfa: followpos\r");
	for (depth_first_traversal i(root); i; i++) {
		(*i)->compute_followpos();
	}

	NodeMap nodemap;
	NodeSet *emptynode = new NodeSet;
	nonmatching = add_new_state(nodemap,
				  make_pair(hash_NodeSet(emptynode), emptynode),
				    emptynode, stats);

	NodeSet *first = new NodeSet(root->firstpos);
	start = add_new_state(nodemap, make_pair(hash_NodeSet(first), first),
			      first, stats);

	/* the work_queue contains the states that need to have their
	 * transitions computed.  This could be done with a recursive
	 * algorithm instead of a work_queue, but it would be slightly slower
	 * and consume more memory.
	 *
	 * TODO: currently the work_queue is treated in a breadth first
	 *       search manner.  Test using the work_queue in a depth first
	 *       manner, this may help reduce the number of entries on the
	 *       work_queue at any given time, thus reducing peak memory use.
	 */
	list<State *> work_queue;
	work_queue.push_back(start);

	while (!work_queue.empty()) {
		if (i % 1000 == 0 && (flags & DFA_DUMP_PROGRESS))
			fprintf(stderr, "\033[2KCreating dfa: queue %ld\tstates %ld\teliminated duplicates %d\r", work_queue.size(), states.size(), stats.duplicates);
		i++;

		State *from = work_queue.front();
		work_queue.pop_front();

		/* Update 'from's transitions, and if it transitions to any
		 * unknown State create it and add it to the work_queue
		 */
		update_state_transitions(nodemap, work_queue, from, stats);

	} /* for (NodeSet *nodes ... */

	/* cleanup Sets of nodes used computing the DFA as they are no longer
	 * needed.
	 */
	for (depth_first_traversal i(root); i; i++) {
		(*i)->firstpos.clear();
		(*i)->lastpos.clear();
		(*i)->followpos.clear();
	}

	if (flags & DFA_DUMP_NODE_TO_DFA)
		dump_node_to_dfa();

	for (NodeMap::iterator i = nodemap.begin(); i != nodemap.end(); i++)
		delete i->first.second;
	nodemap.clear();

	if (flags & (DFA_DUMP_STATS))
	  fprintf(stderr, "\033[2KCreated dfa: states %ld,\teliminated duplicates %d,\tprotostate sets: longest %u, avg %u\n", states.size(), stats.duplicates, stats.proto_max, (unsigned int) (stats.proto_sum/states.size()));

}


DFA::~DFA()
{
    for (Partition::iterator i = states.begin(); i != states.end(); i++)
	delete *i;
}

class MatchFlag : public AcceptNode {
public:
MatchFlag(uint32_t flag, uint32_t audit) : flag(flag), audit(audit) {}
    ostream& dump(ostream& os)
    {
	return os << '<' << flag << '>';
    }

    uint32_t flag;
    uint32_t audit;
 };

class ExactMatchFlag : public MatchFlag {
public:
    ExactMatchFlag(uint32_t flag, uint32_t audit) : MatchFlag(flag, audit) {}
};

class DenyMatchFlag : public MatchFlag {
public:
    DenyMatchFlag(uint32_t flag, uint32_t quiet) : MatchFlag(flag, quiet) {}
};


void DFA::dump_uniq_perms(const char *s)
{
	set < pair<uint32_t, uint32_t> > uniq;
	for (Partition::iterator i = states.begin(); i != states.end(); i++)
		uniq.insert(make_pair((*i)->accept, (*i)->audit));

	cerr << "Unique Permission sets: " << s << " (" << uniq.size() << ")\n";
	cerr << "----------------------\n";
	for (set< pair<uint32_t, uint32_t> >::iterator i = uniq.begin();
	     i != uniq.end(); i++) {
		cerr << "  " << hex << i->first << " " << i->second << dec <<"\n";
	}
}


/* Remove dead or unreachable states */
void DFA::remove_unreachable(dfaflags_t flags)
{
	set <State *> reachable;
	list <State *> work_queue;

	/* find the set of reachable states */
	reachable.insert(nonmatching);
	work_queue.push_back(start);
	while (!work_queue.empty()) {
		State *from = work_queue.front();
		work_queue.pop_front();
		reachable.insert(from);

		if (from->cases.otherwise &&
		    (reachable.find(from->cases.otherwise) == reachable.end()))
			work_queue.push_back(from->cases.otherwise);

		for (Cases::iterator j = from->cases.begin();
		     j != from->cases.end(); j++) {
			if (reachable.find(j->second) == reachable.end())
				work_queue.push_back(j->second);
		}
	}

	/* walk the set of states and remove any that aren't reachable */
	if (reachable.size() < states.size()) {
		int count = 0;
		Partition::iterator i;
		Partition::iterator next;
		for (i = states.begin(); i != states.end(); i = next) {
			next = i;
			next++;
			if (reachable.find(*i) == reachable.end()) {
				if (flags & DFA_DUMP_UNREACHABLE) {
					cerr << "unreachable: "<< **i;
					if (*i == start)
						cerr << " <==";
					if ((*i)->accept) {
						cerr << " (0x" << hex << (*i)->accept
						     << " " << (*i)->audit << dec << ')';
					}
					cerr << endl;
				}
				State *current = *i;
				states.erase(i);
				delete(current);
				count++;
			}
		}

		if (count && (flags & DFA_DUMP_STATS))
			cerr << "DFA: states " << states.size() << " removed "
			     << count << " unreachable states\n";
	}
}

/* test if two states have the same transitions under partition_map */
bool DFA::same_mappings(State *s1, State *s2)
{
	if (s1->cases.otherwise && s1->cases.otherwise != nonmatching) {
		if (!s2->cases.otherwise || s2->cases.otherwise == nonmatching)
			return false;
		Partition *p1 = s1->cases.otherwise->partition;
		Partition *p2 = s2->cases.otherwise->partition;
		if (p1 != p2)
			return false;
	} else if (s2->cases.otherwise && s2->cases.otherwise != nonmatching) {
		return false;
	}

	if (s1->cases.cases.size() != s2->cases.cases.size())
		return false;
	for (Cases::iterator j1 = s1->cases.begin(); j1 != s1->cases.end();
	     j1++){
		Cases::iterator j2 = s2->cases.cases.find(j1->first);
		if (j2 == s2->cases.end())
			return false;
		Partition *p1 = j1->second->partition;
		Partition *p2 = j2->second->partition;
		if (p1 != p2)
			return false;
	}

	return true;
}

/* Do simple djb2 hashing against a States transition cases
 * this provides a rough initial guess at state equivalence as if a state
 * has a different number of transitions or has transitions on different
 * cases they will never be equivalent.
 * Note: this only hashes based off of the alphabet (not destination)
 * as different destinations could end up being equiv
 */
size_t DFA::hash_trans(State *s)
{
        unsigned long hash = 5381;

	for (Cases::iterator j = s->cases.begin(); j != s->cases.end(); j++){
		hash = ((hash << 5) + hash) + j->first;
		State *k = j->second;
		hash = ((hash << 5) + hash) + k->cases.cases.size();
	}

	if (s->cases.otherwise && s->cases.otherwise != nonmatching) {
		hash = ((hash << 5) + hash) + 5381;
		State *k = s->cases.otherwise;
		hash = ((hash << 5) + hash) + k->cases.cases.size();
	}

	hash = (hash << 8) | s->cases.cases.size();
        return hash;
}

/* minimize the number of dfa states */
void DFA::minimize(dfaflags_t flags)
{
	map <pair <uint64_t, size_t>, Partition *> perm_map;
	list <Partition *> partitions;
	
	/* Set up the initial partitions
	 * minimium of - 1 non accepting, and 1 accepting
	 * if trans hashing is used the accepting and non-accepting partitions
	 * can be further split based on the number and type of transitions
	 * a state makes.
	 * If permission hashing is enabled the accepting partitions can
	 * be further divided by permissions.  This can result in not
	 * obtaining a truely minimized dfa but comes close, and can speedup
	 * minimization.
	 */
	int accept_count = 0;
	int final_accept = 0;
	for (Partition::iterator i = states.begin(); i != states.end(); i++) {
		uint64_t perm_hash = 0;
		if (flags & DFA_CONTROL_MINIMIZE_HASH_PERMS) {
			/* make every unique perm create a new partition */
			perm_hash = ((uint64_t)(*i)->audit)<<32 |
				(uint64_t)(*i)->accept;
		} else if ((*i)->audit || (*i)->accept) {
			/* combine all perms together into a single parition */
			perm_hash = 1;
		} /* else not an accept state so 0 for perm_hash */

		size_t trans_hash = 0;
		if (flags & DFA_CONTROL_MINIMIZE_HASH_TRANS)
			trans_hash = hash_trans(*i);
		pair <uint64_t, size_t> group = make_pair(perm_hash, trans_hash);
		map <pair <uint64_t, size_t>, Partition *>::iterator p = perm_map.find(group);
		if (p == perm_map.end()) {
			Partition *part = new Partition();
			part->push_back(*i);
			perm_map.insert(make_pair(group, part));
			partitions.push_back(part);
			(*i)->partition = part;
			if (perm_hash)
				accept_count++;
		} else {
			(*i)->partition = p->second;
			p->second->push_back(*i);
		}

		if ((flags & DFA_DUMP_PROGRESS) &&
		    (partitions.size() % 1000 == 0))
			cerr << "\033[2KMinimize dfa: partitions " << partitions.size() << "\tinit " << partitions.size() << " (accept " << accept_count << ")\r";
	}

	/* perm_map is no longer needed so free the memory it is using.
	 * Don't remove - doing it manually here helps reduce peak memory usage.
	 */
	perm_map.clear();

	int init_count = partitions.size();
	if (flags & DFA_DUMP_PROGRESS)
		cerr << "\033[2KMinimize dfa: partitions " << partitions.size() << "\tinit " << init_count << " (accept " << accept_count << ")\r";

	/* Now do repartitioning until each partition contains the set of
	 * states that are the same.  This will happen when the partition
	 * splitting stables.  With a worse case of 1 state per partition
	 * ie. already minimized.
	 */
	Partition *new_part;
	int new_part_count;
	do {
		new_part_count = 0;
		for (list <Partition *>::iterator p = partitions.begin();
		     p != partitions.end(); p++) {
			new_part = NULL;
			State *rep = *((*p)->begin());
			Partition::iterator next;
			for (Partition::iterator s = ++(*p)->begin();
			     s != (*p)->end(); ) {
				if (same_mappings(rep, *s)) {
					++s;
					continue;
				}
				if (!new_part) {
					new_part = new Partition;
					list <Partition *>::iterator tmp = p;
					partitions.insert(++tmp, new_part);
					new_part_count++;
				}
				new_part->push_back(*s);
				s = (*p)->erase(s);
			}
			/* remapping partition_map for new_part entries
			 * Do not do this above as it messes up same_mappings
			 */
			if (new_part) {
				for (Partition::iterator m = new_part->begin();
				     m != new_part->end(); m++) {
					(*m)->partition = new_part;
				}
			}
		if ((flags & DFA_DUMP_PROGRESS) &&
		    (partitions.size() % 100 == 0))
			cerr << "\033[2KMinimize dfa: partitions " << partitions.size() << "\tinit " << init_count << " (accept " << accept_count << ")\r";
		}
	} while(new_part_count);

	if (partitions.size() == states.size()) {
		if (flags & DFA_DUMP_STATS)
			cerr << "\033[2KDfa minimization no states removed: partitions " << partitions.size() << "\tinit " << init_count << " (accept " << accept_count << ")\n";


		goto out;
	}

	/* Remap the dfa so it uses the representative states
	 * Use the first state of a partition as the representative state
	 * At this point all states with in a partion have transitions
	 * to states within the same partitions, however this can slow
	 * down compressed dfa compression as there are more states,
	 */
       	for (list <Partition *>::iterator p = partitions.begin();
	     p != partitions.end(); p++) {
		/* representative state for this partition */
		State *rep = *((*p)->begin());

		/* update representative state's transitions */
		if (rep->cases.otherwise) {
			Partition *partition = rep->cases.otherwise->partition;
			rep->cases.otherwise = *partition->begin();
		}
		for (Cases::iterator c = rep->cases.begin();
		     c != rep->cases.end(); c++) {
			Partition *partition = c->second->partition;
			c->second = *partition->begin();
		}

//if ((*p)->size() > 1)
//cerr << rep->label << ": ";
		/* clear the state label for all non representative states,
		 * and accumulate permissions */
		for (Partition::iterator i = ++(*p)->begin(); i != (*p)->end(); i++) {
//cerr << " " << (*i)->label;
			(*i)->label = -1;
			rep->accept |= (*i)->accept;
			rep->audit |= (*i)->audit;
		}
		if (rep->accept || rep->audit)
			final_accept++;
//if ((*p)->size() > 1)
//cerr << "\n";
	}
	if (flags & DFA_DUMP_STATS)
		cerr << "\033[2KMinimized dfa: final partitions " << partitions.size() << " (accept " << final_accept << ")" << "\tinit " << init_count << " (accept " << accept_count << ")\n";



	/* make sure nonmatching and start state are up to date with the
	 * mappings */
	{
		Partition *partition = nonmatching->partition;
		if (*partition->begin() != nonmatching) {
			nonmatching = *partition->begin();
		}

		partition = start->partition;
		if (*partition->begin() != start) {
			start = *partition->begin();
		}
	}

	/* Now that the states have been remapped, remove all states
	 * that are not the representive states for their partition, they
	 * will have a label == -1
	 */
	for (Partition::iterator i = states.begin(); i != states.end(); ) {
		if ((*i)->label == -1) {
			State *s = *i;
			i = states.erase(i);
			delete(s);
		} else
			i++;
	}

out:
	/* Cleanup */
	while (!partitions.empty()) {
		Partition *p = partitions.front();
		partitions.pop_front();
		delete(p);
	}
}

/**
 * text-dump the DFA (for debugging).
 */
void DFA::dump(ostream& os)
{
    for (Partition::iterator i = states.begin(); i != states.end(); i++) {
	    if (*i == start || (*i)->accept) {
	    os << **i;
	    if (*i == start)
		os << " <==";
	    if ((*i)->accept) {
		    os << " (0x" << hex << (*i)->accept << " " << (*i)->audit << dec << ')';
	    }
	    os << endl;
	}
    }
    os << endl;

    for (Partition::iterator i = states.begin(); i != states.end(); i++) {
	    if ((*i)->cases.otherwise)
	      os << **i << " -> " << (*i)->cases.otherwise << endl;
	    for (Cases::iterator j = (*i)->cases.begin(); j != (*i)->cases.end(); j++) {
	    os << **i << " -> " << j->second << ":  " << j->first << endl;
	}
    }
    os << endl;
}

/**
 * Create a dot (graphviz) graph from the DFA (for debugging).
 */
void DFA::dump_dot_graph(ostream& os)
{
    os << "digraph \"dfa\" {" << endl;

    for (Partition::iterator i = states.begin(); i != states.end(); i++) {
	if (*i == nonmatching)
	    continue;

	os << "\t\"" << **i << "\" [" << endl;
	if (*i == start) {
	    os << "\t\tstyle=bold" << endl;
	}
	uint32_t perms = (*i)->accept;
	if (perms) {
	    os << "\t\tlabel=\"" << **i << "\\n("
	       << perms << ")\"" << endl;
	}
	os << "\t]" << endl;
    }
    for (Partition::iterator i = states.begin(); i != states.end(); i++) {
	    Cases& cases = (*i)->cases;
	Chars excluded;

	for (Cases::iterator j = cases.begin(); j != cases.end(); j++) {
	    if (j->second == nonmatching)
		excluded.insert(j->first);
	    else {
		    os << "\t\"" << **i << "\" -> \"";
		    os << j->second << "\" [" << endl;
		    os << "\t\tlabel=\"" << j->first << "\"" << endl;
		    os << "\t]" << endl;
	    }
	}
	if (cases.otherwise && cases.otherwise != nonmatching) {
		os << "\t\"" << **i << "\" -> \"" << cases.otherwise
	       << "\" [" << endl;
	    if (!excluded.empty()) {
		os << "\t\tlabel=\"[^";
		for (Chars::iterator i = excluded.begin();
		     i != excluded.end();
		     i++) {
		    os << *i;
		}
		os << "]\"" << endl;
	    }
	    os << "\t]" << endl;
	}
    }
    os << '}' << endl;
}

/**
 * Compute character equivalence classes in the DFA to save space in the
 * transition table.
 */
map<uchar, uchar> DFA::equivalence_classes(dfaflags_t flags)
{
    map<uchar, uchar> classes;
    uchar next_class = 1;

    for (Partition::iterator i = states.begin(); i != states.end(); i++) {
	    Cases& cases = (*i)->cases;

	/* Group edges to the same next state together */
	map<const State *, Chars> node_sets;
	for (Cases::iterator j = cases.begin(); j != cases.end(); j++)
	    node_sets[j->second].insert(j->first);

	for (map<const State *, Chars>::iterator j = node_sets.begin();
	     j != node_sets.end();
	     j++) {
	    /* Group edges to the same next state together by class */
	    map<uchar, Chars> node_classes;
	    bool class_used = false;
	    for (Chars::iterator k = j->second.begin();
		 k != j->second.end();
		 k++) {
		pair<map<uchar, uchar>::iterator, bool> x =
		    classes.insert(make_pair(*k, next_class));
		if (x.second)
		    class_used = true;
		pair<map<uchar, Chars>::iterator, bool> y =
		    node_classes.insert(make_pair(x.first->second, Chars()));
		y.first->second.insert(*k);
	    }
	    if (class_used) {
		next_class++;
		class_used = false;
	    }
	    for (map<uchar, Chars>::iterator k = node_classes.begin();
		 k != node_classes.end();
		 k++) {
		/**
		 * If any other characters are in the same class, move
		 * the characters in this class into their own new class
		 */
		map<uchar, uchar>::iterator l;
		for (l = classes.begin(); l != classes.end(); l++) {
		    if (l->second == k->first &&
			k->second.find(l->first) == k->second.end()) {
			class_used = true;
			break;
		    }
		}
		if (class_used) {
		    for (Chars::iterator l = k->second.begin();
			 l != k->second.end();
			 l++) {
			classes[*l]  = next_class;
		    }
		    next_class++;
		    class_used = false;
		}
	    }
	}
    }

    if (flags & DFA_DUMP_EQUIV_STATS)
	fprintf(stderr, "Equiv class reduces to %d classes\n", next_class - 1);
    return classes;
}

/**
 * Text-dump the equivalence classes (for debugging).
 */
void dump_equivalence_classes(ostream& os, map<uchar, uchar>& eq)
{
    map<uchar, Chars> rev;

    for (map<uchar, uchar>::iterator i = eq.begin(); i != eq.end(); i++) {
	Chars& chars = rev.insert(make_pair(i->second,
				      Chars())).first->second;
	chars.insert(i->first);
    }
    os << "(eq):" << endl;
    for (map<uchar, Chars>::iterator i = rev.begin(); i != rev.end(); i++) {
	os << (int)i->first << ':';
	Chars& chars = i->second;
	for (Chars::iterator j = chars.begin(); j != chars.end(); j++) {
	    os << ' ' << *j;
	}
	os << endl;
    }
}

/**
 * Replace characters with classes (which are also represented as
 * characters) in the DFA transition table.
 */
void DFA::apply_equivalence_classes(map<uchar, uchar>& eq)
{
    /**
     * Note: We only transform the transition table; the nodes continue to
     * contain the original characters.
     */
    for (Partition::iterator i = states.begin(); i != states.end(); i++) {
	map<uchar, State *> tmp;
	tmp.swap((*i)->cases.cases);
	for (Cases::iterator j = tmp.begin(); j != tmp.end(); j++)
		(*i)->cases.cases.insert(make_pair(eq[j->first], j->second));
    }
}

/**
 * Flip the children of all cat nodes. This causes strings to be matched
 * back-forth.
 */
void flip_tree(Node *node)
{
    for (depth_first_traversal i(node); i; i++) {
	if (CatNode *cat = dynamic_cast<CatNode *>(*i)) {
	    swap(cat->child[0], cat->child[1]);
	}
    }
}

class TransitionTable {
    typedef vector<pair<const State *, size_t> > DefaultBase;
    typedef vector<pair<const State *, const State *> > NextCheck;
public:
    TransitionTable(DFA& dfa, map<uchar, uchar>& eq, dfaflags_t flags);
    void dump(ostream& os);
    void flex_table(ostream& os, const char *name);
    void init_free_list(vector <pair<size_t, size_t> > &free_list, size_t prev, size_t start);
    bool fits_in(vector <pair<size_t, size_t> > &free_list,
		 size_t base, Cases& cases);
    void insert_state(vector <pair<size_t, size_t> > &free_list,
		      State *state, DFA& dfa);

private:
    vector<uint32_t> accept;
    vector<uint32_t> accept2;
    DefaultBase default_base;
    NextCheck next_check;
    map<const State *, size_t> num;
    map<uchar, uchar>& eq;
    uchar max_eq;
    size_t first_free;
};


void TransitionTable::init_free_list(vector <pair<size_t, size_t> > &free_list,
				     size_t prev, size_t start) {
	for (size_t i = start; i < free_list.size(); i++) {
		if (prev)
			free_list[prev].second = i;
		free_list[i].first = prev;
		prev = i;
	}
	free_list[free_list.size() -1].second = 0;
}

/**
 * new Construct the transition table.
 */
TransitionTable::TransitionTable(DFA& dfa, map<uchar, uchar>& eq,
				 dfaflags_t flags)
    : eq(eq)
{

	if (flags & DFA_DUMP_TRANS_PROGRESS)
		fprintf(stderr, "Compressing trans table:\r");


	if (eq.empty())
		max_eq = 255;
	else {
		max_eq = 0;
		for(map<uchar, uchar>::iterator i = eq.begin(); i != eq.end(); i++) {
			if (i->second > max_eq)
				max_eq = i->second;
		}
	}

	/* Do initial setup adding up all the transitions and sorting by
	 * transition count.
	 */
	size_t optimal = 2;
	multimap <size_t, State *> order;
	vector <pair<size_t, size_t> > free_list;

	for (Partition::iterator i = dfa.states.begin(); i != dfa.states.end(); i++) {
		if (*i == dfa.start || *i == dfa.nonmatching)
			continue;
		optimal += (*i)->cases.cases.size();
		if (flags & DFA_CONTROL_TRANS_HIGH) {
			size_t range = 0;
			if ((*i)->cases.cases.size())
				range = (*i)->cases.cases.rbegin()->first - (*i)->cases.begin()->first;
			size_t ord = ((256 - (*i)->cases.cases.size()) << 8) |
				(256 - range);
			/* reverse sort by entry count, most entries first */
			order.insert(make_pair(ord, *i));
		}
	}

	/* Insert the dummy nonmatching transition by hand */
	next_check.push_back(make_pair(dfa.nonmatching, dfa.nonmatching));
	default_base.push_back(make_pair(dfa.nonmatching, 0));
	num.insert(make_pair(dfa.nonmatching, num.size()));

	accept.resize(dfa.states.size());
	accept2.resize(dfa.states.size());
	next_check.resize(optimal);
	free_list.resize(optimal);

	accept[0] = 0;
	accept2[0] = 0;
	first_free = 1;
	init_free_list(free_list, 0, 1);

	insert_state(free_list, dfa.start, dfa);
	accept[1] = 0;
	accept2[1] = 0;
	num.insert(make_pair(dfa.start, num.size()));

	int count = 2;

	if (!(flags & DFA_CONTROL_TRANS_HIGH)) {
		for (Partition::iterator i = dfa.states.begin(); i != dfa.states.end();
		     i++) {
			if (*i != dfa.nonmatching && *i != dfa.start) {
				insert_state(free_list, *i, dfa);
				accept[num.size()] = (*i)->accept;
				accept2[num.size()] = (*i)->audit;
				num.insert(make_pair(*i, num.size()));
			}
			if (flags & (DFA_DUMP_TRANS_PROGRESS)) {
				count++;
				if (count % 100 == 0)
					fprintf(stderr, "\033[2KCompressing trans table: insert state: %d/%ld\r", count, dfa.states.size());
			}
		}
	} else {
		for (multimap <size_t, State *>::iterator i = order.begin();
		     i != order.end(); i++) {
			if (i->second != dfa.nonmatching && i->second != dfa.start) {
				insert_state(free_list, i->second, dfa);
				accept[num.size()] = i->second->accept;
				accept2[num.size()] = i->second->audit;
				num.insert(make_pair(i->second, num.size()));
			}
			if (flags & (DFA_DUMP_TRANS_PROGRESS)) {
				count++;
				if (count % 100 == 0)
					fprintf(stderr, "\033[2KCompressing trans table: insert state: %d/%ld\r", count, dfa.states.size());
			}
		}
	}

	if (flags & (DFA_DUMP_TRANS_STATS | DFA_DUMP_TRANS_PROGRESS)) {
		ssize_t size = 4 * next_check.size() + 6 * dfa.states.size();
		fprintf(stderr, "\033[2KCompressed trans table: states %ld, next/check %ld, optimal next/check %ld avg/state %.2f, compression %ld/%ld = %.2f %%\n", dfa.states.size(), next_check.size(), optimal, (float)next_check.size()/(float)dfa.states.size(), size, 512 * dfa.states.size(), 100.0 - ((float) size * 100.0 / (float)(512 * dfa.states.size())));
	}
}


/**
 * Does <cases> fit into position <base> of the transition table?
 */
bool TransitionTable::fits_in(vector <pair<size_t, size_t> > &free_list __attribute__((unused)),
			      size_t pos, Cases& cases)
{
	size_t c, base = pos - cases.begin()->first;
	for (Cases::iterator i = cases.begin(); i != cases.end(); i++) {
		c = base + i->first;
		/* if it overflows the next_check array it fits in as we will
		 * resize */
		if (c >= next_check.size())
			return true;
		if (next_check[c].second)
			return false;
	}

	return true;
}

/**
 * Insert <state> of <dfa> into the transition table.
 */
void TransitionTable::insert_state(vector <pair<size_t, size_t> > &free_list,
				   State *from, DFA& dfa)
{
	State *default_state = dfa.nonmatching;
	size_t base = 0;
	int resize;

	Cases& cases = from->cases;
	size_t c = cases.begin()->first;
	size_t prev = 0;
	size_t x = first_free;

	if (cases.otherwise)
		default_state = cases.otherwise;
	if (cases.cases.empty())
		goto do_insert;

repeat:
	resize = 0;
	/* get the first free entry that won't underflow */
	while (x && (x < c)) {
		prev = x;
		x = free_list[x].second;
	}

	/* try inserting until we succeed. */
	while (x && !fits_in(free_list, x, cases)) {
		prev = x;
		x = free_list[x].second;
	}
	if (!x) {
		resize = 256 - cases.begin()->first;
		x = free_list.size();
		/* set prev to last free */
	} else if (x + 255 - cases.begin()->first >= next_check.size()) {
		resize = (255 - cases.begin()->first - (next_check.size() - 1 - x));
		for (size_t y = x; y; y = free_list[y].second)
			prev = y;
	}
	if (resize) {
		/* expand next_check and free_list */
	        size_t old_size = free_list.size();
		next_check.resize(next_check.size() + resize);
		free_list.resize(free_list.size() + resize);
		init_free_list(free_list, prev, old_size);
		if (!first_free)
			first_free = old_size;;
		if (x == old_size)
			goto repeat;
	}

	base = x - c;
	for (Cases::iterator j = cases.begin(); j != cases.end(); j++) {
	    next_check[base + j->first] = make_pair(j->second, from);
	    size_t prev = free_list[base + j->first].first;
	    size_t next = free_list[base + j->first].second;
	    if (prev)
		    free_list[prev].second = next;
	    if (next)
		    free_list[next].first = prev;
	    if (base + j->first == first_free)
		    first_free = next;
	}

do_insert:
	default_base.push_back(make_pair(default_state, base));
}

/**
 * Text-dump the transition table (for debugging).
 */
void TransitionTable::dump(ostream& os)
{
    map<size_t, const State *> st;
    for (map<const State *, size_t>::iterator i = num.begin();
	 i != num.end();
	 i++) {
	st.insert(make_pair(i->second, i->first));
    }

    os << "size=" << default_base.size() << " (accept, default, base):  {state} -> {default state}" << endl;
    for (size_t i = 0; i < default_base.size(); i++) {
        os << i << ": ";
	os << "(" << accept[i] << ", "
	   << num[default_base[i].first] << ", "
	   << default_base[i].second << ")";
	if (st[i])
	    os << " " << *st[i];
	if (default_base[i].first)
	    os << " -> " << *default_base[i].first;
	os << endl;
    }

    os << "size=" << next_check.size() << " (next, check): {check state} -> {next state} : offset from base" << endl;
    for (size_t i = 0; i < next_check.size(); i++) {
	if (!next_check[i].second)
	    continue;

	os << i << ": ";
	if (next_check[i].second) {
	    os << "(" << num[next_check[i].first] << ", "
	       << num[next_check[i].second] << ")" << " "
	       << *next_check[i].second << " -> "
	       << *next_check[i].first << ": ";

	    size_t offs = i - default_base[num[next_check[i].second]].second;
	    if (eq.size())
		os << offs;
	    else
		os << (uchar)offs;
	}
	os << endl;
    }
}

#if 0
template<class Iter>
class FirstIterator {
public:
    FirstIterator(Iter pos) : pos(pos)  { }
    typename Iter::value_type::first_type operator*()  { return pos->first; }
    bool operator!=(FirstIterator<Iter>& i)  { return pos != i.pos; }
    void operator++()  { ++pos; }
    ssize_t operator-(FirstIterator<Iter> i)  { return pos - i.pos; }
private:
    Iter pos;
};

template<class Iter>
FirstIterator<Iter> first_iterator(Iter iter)
{
    return FirstIterator<Iter>(iter);
}

template<class Iter>
class SecondIterator {
public:
    SecondIterator(Iter pos) : pos(pos)  { }
    typename Iter::value_type::second_type operator*()  { return pos->second; }
    bool operator!=(SecondIterator<Iter>& i)  { return pos != i.pos; }
    void operator++()  { ++pos; }
    ssize_t operator-(SecondIterator<Iter> i)  { return pos - i.pos; }
private:
    Iter pos;
};

template<class Iter>
SecondIterator<Iter> second_iterator(Iter iter)
{
    return SecondIterator<Iter>(iter);
}
#endif

/**
 * Create a flex-style binary dump of the DFA tables. The table format
 * was partly reverse engineered from the flex sources and from
 * examining the tables that flex creates with its --tables-file option.
 * (Only the -Cf and -Ce formats are currently supported.)
 */

#include "flex-tables.h"
#define YYTH_REGEX_MAGIC 0x1B5E783D

static inline size_t pad64(size_t i)
{
    return (i + (size_t)7) & ~(size_t)7;
}

string fill64(size_t i)
{
    const char zeroes[8] = { };
    string fill(zeroes, (i & 7) ? 8 - (i & 7) : 0);
    return fill;
}

template<class Iter>
size_t flex_table_size(Iter pos, Iter end)
{
    return pad64(sizeof(struct table_header) + sizeof(*pos) * (end - pos));
}

template<class Iter>
void write_flex_table(ostream& os, int id, Iter pos, Iter end)
{
    struct table_header td = { 0, 0, 0, 0 };
    size_t size = end - pos;

    td.td_id = htons(id);
    td.td_flags = htons(sizeof(*pos));
    td.td_lolen = htonl(size);
    os.write((char *)&td, sizeof(td));

    for (; pos != end; ++pos) {
	switch(sizeof(*pos)) {
	    case 4:
		os.put((char)(*pos >> 24));
		os.put((char)(*pos >> 16));
	    case 2:
		os.put((char)(*pos >> 8));
	    case 1:
		os.put((char)*pos);
	}
    }

    os << fill64(sizeof(td) + sizeof(*pos) * size);
}

void TransitionTable::flex_table(ostream& os, const char *name)
{
    const char th_version[] = "notflex";
    struct table_set_header th = { 0, 0, 0, 0 };

    /**
     * Change the following two data types to adjust the maximum flex
     * table size.
     */
    typedef uint16_t state_t;
    typedef uint32_t trans_t;

    if (default_base.size() >= (state_t)-1) {
	cerr << "Too many states (" << default_base.size() << ") for "
		"type state_t" << endl;
	exit(1);
    }
    if (next_check.size() >= (trans_t)-1) {
	cerr << "Too many transitions (" << next_check.size() << ") for "
	        "type trans_t" << endl;
	exit(1);
    }

    /**
     * Create copies of the data structures so that we can dump the tables
     * using the generic write_flex_table() routine.
     */
    vector<uint8_t> equiv_vec;
    if (eq.size()) {
	equiv_vec.resize(256);
	for (map<uchar, uchar>::iterator i = eq.begin(); i != eq.end(); i++) {
	    equiv_vec[i->first] = i->second;
	}
    }

    vector<state_t> default_vec;
    vector<trans_t> base_vec;
    for (DefaultBase::iterator i = default_base.begin();
	 i != default_base.end();
	 i++) {
	default_vec.push_back(num[i->first]);
	base_vec.push_back(i->second);
    }

    vector<state_t> next_vec;
    vector<state_t> check_vec;
    for (NextCheck::iterator i = next_check.begin();
	 i != next_check.end();
	 i++) {
	next_vec.push_back(num[i->first]);
	check_vec.push_back(num[i->second]);
    }

    /* Write the actual flex parser table. */

    size_t hsize = pad64(sizeof(th) + sizeof(th_version) + strlen(name) + 1);
    th.th_magic = htonl(YYTH_REGEX_MAGIC);
    th.th_hsize = htonl(hsize);
    th.th_ssize = htonl(hsize +
	    flex_table_size(accept.begin(), accept.end()) +
	    flex_table_size(accept2.begin(), accept2.end()) +
	    (eq.size() ?
		flex_table_size(equiv_vec.begin(), equiv_vec.end()) : 0) +
	    flex_table_size(base_vec.begin(), base_vec.end()) +
	    flex_table_size(default_vec.begin(), default_vec.end()) +
	    flex_table_size(next_vec.begin(), next_vec.end()) +
	    flex_table_size(check_vec.begin(), check_vec.end()));
    os.write((char *)&th, sizeof(th));
    os << th_version << (char)0 << name << (char)0;
    os << fill64(sizeof(th) + sizeof(th_version) + strlen(name) + 1);


    write_flex_table(os, YYTD_ID_ACCEPT, accept.begin(), accept.end());
    write_flex_table(os, YYTD_ID_ACCEPT2, accept2.begin(), accept2.end());
    if (eq.size())
	write_flex_table(os, YYTD_ID_EC, equiv_vec.begin(), equiv_vec.end());
    write_flex_table(os, YYTD_ID_BASE, base_vec.begin(), base_vec.end());
    write_flex_table(os, YYTD_ID_DEF, default_vec.begin(), default_vec.end());
    write_flex_table(os, YYTD_ID_NXT, next_vec.begin(), next_vec.end());
    write_flex_table(os, YYTD_ID_CHK, check_vec.begin(), check_vec.end());
}

#if 0
typedef set<ImportantNode *> AcceptNodes;
map<ImportantNode *, AcceptNodes> dominance(DFA& dfa)
{
    map<ImportantNode *, AcceptNodes> is_dominated;

    for (States::iterator i = dfa.states.begin(); i != dfa.states.end(); i++) {
	AcceptNodes set1;
	for (State::iterator j = (*i)->begin(); j != (*i)->end(); j++) {
	    if (AcceptNode *accept = dynamic_cast<AcceptNode *>(*j))
		set1.insert(accept);
	}
	for (AcceptNodes::iterator j = set1.begin(); j != set1.end(); j++) {
	    pair<map<ImportantNode *, AcceptNodes>::iterator, bool> x =
		is_dominated.insert(make_pair(*j, set1));
	    if (!x.second) {
		AcceptNodes &set2(x.first->second), set3;
		for (AcceptNodes::iterator l = set2.begin();
		     l != set2.end();
		     l++) {
		    if (set1.find(*l) != set1.end())
			set3.insert(*l);
		}
		set3.swap(set2);
	    }
	}
    }
    return is_dominated;
}
#endif

void dump_regexp_rec(ostream& os, Node *tree)
{
    if (tree->child[0])
	dump_regexp_rec(os, tree->child[0]);
    os << *tree;
    if (tree->child[1])
	dump_regexp_rec(os, tree->child[1]);
}

void dump_regexp(ostream& os, Node *tree)
{
    dump_regexp_rec(os, tree);
    os << endl;
}


static inline int diff_qualifiers(uint32_t perm1, uint32_t perm2)
{
	return ((perm1 & AA_EXEC_TYPE) && (perm2 & AA_EXEC_TYPE) &&
		(perm1 & AA_EXEC_TYPE) != (perm2 & AA_EXEC_TYPE));
}

/**
 * Compute the permission flags that this state corresponds to. If we
 * have any exact matches, then they override the execute and safe
 * execute flags.
 */
uint32_t accept_perms(NodeSet *state, uint32_t *audit_ctl, int *error)
{
    uint32_t perms = 0, exact_match_perms = 0, audit = 0, exact_audit = 0,
	    quiet = 0, deny = 0;

    if (error)
	    *error = 0;
    for (NodeSet::iterator i = state->begin(); i != state->end(); i++) {
	    MatchFlag *match;
	    if (!(match= dynamic_cast<MatchFlag *>(*i)))
		continue;
	    if (dynamic_cast<ExactMatchFlag *>(match)) {
		    /* exact match only ever happens with x */
		    if (!is_merged_x_consistent(exact_match_perms,
						match->flag) && error)
			    *error = 1;;
		    exact_match_perms |= match->flag;
		    exact_audit |= match->audit;
	    } else if (dynamic_cast<DenyMatchFlag *>(match)) {
		    deny |= match->flag;
		    quiet |= match->audit;
	    } else {
		    if (!is_merged_x_consistent(perms, match->flag) && error)
			    *error = 1;
		    perms |= match->flag;
		    audit |= match->audit;
	    }
    }

//if (audit || quiet)
//fprintf(stderr, "perms: 0x%x, audit: 0x%x exact: 0x%x eaud: 0x%x deny: 0x%x quiet: 0x%x\n", perms, audit, exact_match_perms, exact_audit, deny, quiet);

    perms |= exact_match_perms &
	    ~(AA_USER_EXEC_TYPE | AA_OTHER_EXEC_TYPE);

    if (exact_match_perms & AA_USER_EXEC_TYPE) {
	    perms = (exact_match_perms & AA_USER_EXEC_TYPE) |
		    (perms & ~AA_USER_EXEC_TYPE);
	    audit = (exact_audit & AA_USER_EXEC_TYPE) |
		    (audit & ~ AA_USER_EXEC_TYPE);
    }
    if (exact_match_perms & AA_OTHER_EXEC_TYPE) {
	    perms = (exact_match_perms & AA_OTHER_EXEC_TYPE) |
		    (perms & ~AA_OTHER_EXEC_TYPE);
	    audit = (exact_audit & AA_OTHER_EXEC_TYPE) |
		    (audit & ~AA_OTHER_EXEC_TYPE);
    }
    if (perms & AA_USER_EXEC & deny)
	    perms &= ~AA_USER_EXEC_TYPE;

    if (perms & AA_OTHER_EXEC & deny)
	    perms &= ~AA_OTHER_EXEC_TYPE;

    perms &= ~deny;

    if (audit_ctl)
	    *audit_ctl = PACK_AUDIT_CTL(audit, quiet & deny);

// if (perms & AA_ERROR_BIT) {
//     fprintf(stderr, "error bit 0x%x\n", perms);
//     exit(255);
//}

 //if (perms & AA_EXEC_BITS)
 //fprintf(stderr, "accept perm: 0x%x\n", perms);
 /*
     if (perms & ~AA_VALID_PERMS)
 	yyerror(_("Internal error accumulated invalid perm 0x%llx\n"), perms);
 */

//if (perms & AA_CHANGE_HAT)
//     fprintf(stderr, "change_hat 0x%x\n", perms);

    if (*error)
	    fprintf(stderr, "profile has merged rule with conflicting x modifiers\n");

    return perms;
}
