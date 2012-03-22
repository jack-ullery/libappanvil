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

#include "expr-tree.h"
#include "hfa.h"
#include "../immunix.h"


ostream &operator<<(ostream &os, const CacheStats &cache)
{
	/* dump the state label */
	os << "cache: size=";
	os << cache.size();
	os << " dups=";
	os << cache.dup;
	os << " longest=";
	os << cache.max;
	if (cache.size()) {
		os << " avg=";
		os << cache.sum / cache.size();
	}
	return os;
}

ostream &operator<<(ostream &os, const ProtoState &proto)
{
	/* dump the state label */
	os << '{';
	os << proto.nnodes;
	os << ',';
	os << proto.anodes;
	os << '}';
	return os;
}

ostream &operator<<(ostream &os, const State &state)
{
	/* dump the state label */
	os << '{';
	os << state.label;
	os << '}';
	return os;
}

static void split_node_types(NodeSet *nodes, NodeSet **anodes, NodeSet **nnodes
)
{
	*anodes = *nnodes = NULL;
	for (NodeSet::iterator i = nodes->begin(); i != nodes->end(); ) {
		if ((*i)->is_accept()) {
			if (!*anodes)
				*anodes = new NodeSet;
			(*anodes)->insert(*i);
			NodeSet::iterator k = i++;
			nodes->erase(k);
		} else
			i++;
	}
	*nnodes = nodes;
}

State *DFA::add_new_state(NodeSet *nodes, State *other)
{
	/* The splitting of nodes should probably get pushed down into
	 * follow(), ie. put in separate lists from the start
	 */
	NodeSet *anodes, *nnodes;
	hashedNodeVec *nnodev;
	split_node_types(nodes, &anodes, &nnodes);
	nnodev = nnodes_cache.insert(nnodes);
	anodes = anodes_cache.insert(anodes);

	ProtoState proto(nnodev, anodes);
	State *state = new State(node_map.size(), proto, other);
	pair<NodeMap::iterator,bool> x = node_map.insert(proto, state);
	if (x.second == false) {
		delete state;
	} else {
		states.push_back(state);
		work_queue.push_back(state);
	}

	return x.first->second;
}

void DFA::update_state_transitions(State *state)
{
	/* Compute possible transitions for state->nodes.  This is done by
	 * iterating over all the nodes in state->nodes and combining the
	 * transitions.
	 *
	 * The resultant transition set is a mapping of characters to
	 * sets of nodes.
	 *
	 * Note: the follow set for accept nodes is always empty so we don't
	 * need to compute follow for the accept nodes in a protostate
	 */
	Cases cases;
	for (hashedNodeVec::iterator i = state->proto.nnodes->begin(); i != state->proto.nnodes->end(); i++)
		(*i)->follow(cases);

	/* Now for each set of nodes in the computed transitions, make
	 * sure that there is a state that maps to it, and add the
	 * matching case to the state.
	 */

	/* check the default transition first */
	if (cases.otherwise)
		state->otherwise = add_new_state(cases.otherwise, nonmatching);
	else
		state->otherwise = nonmatching;

	/* For each transition from *from, check if the set of nodes it
	 * transitions to already has been mapped to a state
	 */
	for (Cases::iterator j = cases.begin(); j != cases.end(); j++) {
		State *target;
		target = add_new_state(j->second, nonmatching);

		/* Don't insert transition that the otherwise transition
		 * already covers
		 */
		if (target != state->otherwise)
			state->trans[j->first] = target;
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
		cerr << "  " << (*i)->label << " <= " << (*i)->proto << "\n";
}

/**
 * Construct a DFA from a syntax tree.
 */
DFA::DFA(Node *root, dfaflags_t flags): root(root)
{
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

	nonmatching = add_new_state(new NodeSet, NULL);
	start = add_new_state(new NodeSet(root->firstpos), nonmatching);

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
	work_queue.push_back(start);

	while (!work_queue.empty()) {
		if (i % 1000 == 0 && (flags & DFA_DUMP_PROGRESS)) {
			cerr << "\033[2KCreating dfa: queue "
			     << work_queue.size()
			     << "\tstates "
			     << states.size()
			     << "\teliminated duplicates "
			     << node_map.dup
			     << "\r";
		}
		i++;

		State *from = work_queue.front();
		work_queue.pop_front();

		/* Update 'from's transitions, and if it transitions to any
		 * unknown State create it and add it to the work_queue
		 */
		update_state_transitions(from);

	}  /* while (!work_queue.empty()) */

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

	if (flags & (DFA_DUMP_STATS)) {
		cerr << "\033[2KCreated dfa: states "
		     << states.size()
		     << " proto { "
		     << node_map
		     << " }, nnodes { "
		     << nnodes_cache
		     << " }, anodes { "
		     << anodes_cache
		     << " }\n";
	}

	/* Clear out uniq_nnodes as they are no longer needed.
	 * Do not clear out uniq_anodes, as we need them for minimizations
	 * diffs, unions, ...
	 */
	nnodes_cache.clear();
	node_map.clear();
}

DFA::~DFA()
{
	anodes_cache.clear();
	nnodes_cache.clear();

	for (Partition::iterator i = states.begin(); i != states.end(); i++)
		delete *i;
}

State *DFA::match_len(State *state, const char *str, size_t len)
{
	for (; len > 0; ++str, --len)
		state = state->next(*str);

	return state;
}

State *DFA::match_until(State *state, const char *str, const char term)
{
	while (*str != term)
		state = state->next(*str++);

	return state;
}

State *DFA::match(const char *str)
{
	return match_until(start, str, 0);
}

void DFA::dump_uniq_perms(const char *s)
{
	set<perms_t> uniq;
	for (Partition::iterator i = states.begin(); i != states.end(); i++)
		uniq.insert((*i)->perms);

	cerr << "Unique Permission sets: " << s << " (" << uniq.size() << ")\n";
	cerr << "----------------------\n";
	for (set<perms_t >::iterator i = uniq.begin(); i != uniq.end(); i++) {
		cerr << "  allow:" << hex << i->allow << " deny:"
		     << i->deny << " audit:" << i->audit
		     << " quiet:" << i->quiet << dec << "\n";
	}
}

/* Remove dead or unreachable states */
void DFA::remove_unreachable(dfaflags_t flags)
{
	set<State *> reachable;

	/* find the set of reachable states */
	reachable.insert(nonmatching);
	work_queue.push_back(start);
	while (!work_queue.empty()) {
		State *from = work_queue.front();
		work_queue.pop_front();
		reachable.insert(from);

		if (from->otherwise != nonmatching &&
		    reachable.find(from->otherwise) == reachable.end())
			work_queue.push_back(from->otherwise);

		for (StateTrans::iterator j = from->trans.begin(); j != from->trans.end(); j++) {
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
					cerr << "unreachable: " << **i;
					if (*i == start)
						cerr << " <==";
					if ((*i)->perms.is_accept())
						(*i)->perms.dump(cerr);
					cerr << "\n";
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
	if (s1->otherwise->partition != s2->otherwise->partition)
		return false;

	if (s1->trans.size() != s2->trans.size())
		return false;

	for (StateTrans::iterator j1 = s1->trans.begin(); j1 != s1->trans.end(); j1++) {
		StateTrans::iterator j2 = s2->trans.find(j1->first);
		if (j2 == s2->trans.end())
			return false;
		if (j1->second->partition != j2->second->partition)
			return false;
	}

	return true;
}

/* Do simple djb2 hashing against a States transition cases
 * this provides a rough initial guess at state equivalence as if a state
 * has a different number of transitions or has transitions on different
 * trans they will never be equivalent.
 * Note: this only hashes based off of the alphabet (not destination)
 * as different destinations could end up being equiv
 */
size_t DFA::hash_trans(State *s)
{
	unsigned long hash = 5381;

	for (StateTrans::iterator j = s->trans.begin(); j != s->trans.end(); j++) {
		hash = ((hash << 5) + hash) + j->first;
		State *k = j->second;
		hash = ((hash << 5) + hash) + k->trans.size();
	}

	if (s->otherwise != nonmatching) {
		hash = ((hash << 5) + hash) + 5381;
		State *k = s->otherwise;
		hash = ((hash << 5) + hash) + k->trans.size();
	}

	hash = (hash << 8) | s->trans.size();
	return hash;
}

int DFA::apply_and_clear_deny(void)
{
	int c = 0;
	for (Partition::iterator i = states.begin(); i != states.end(); i++)
		c += (*i)->apply_and_clear_deny();

	return c;
}

/* minimize the number of dfa states */
void DFA::minimize(dfaflags_t flags)
{
	map<pair<uint64_t, size_t>, Partition *> perm_map;
	list<Partition *> partitions;

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
		size_t hash = 0;
		uint64_t permtype = ((uint64_t) (PACK_AUDIT_CTL((*i)->perms.audit, (*i)->perms.quiet & (*i)->perms.deny)) << 32) | (uint64_t) (*i)->perms.allow;
		if (flags & DFA_CONTROL_MINIMIZE_HASH_TRANS)
			hash |= hash_trans(*i);
		pair<uint64_t, size_t> group = make_pair(permtype, hash);
		map<pair<uint64_t, size_t>, Partition *>::iterator p = perm_map.find(group);
		if (p == perm_map.end()) {
			Partition *part = new Partition();
			part->push_back(*i);
			perm_map.insert(make_pair(group, part));
			partitions.push_back(part);
			(*i)->partition = part;
			if (permtype)
				accept_count++;
		} else {
			(*i)->partition = p->second;
			p->second->push_back(*i);
		}

		if ((flags & DFA_DUMP_PROGRESS) && (partitions.size() % 1000 == 0))
			cerr << "\033[2KMinimize dfa: partitions "
			     << partitions.size() << "\tinit " << partitions.size()
			     << " (accept " << accept_count << ")\r";
	}

	/* perm_map is no longer needed so free the memory it is using.
	 * Don't remove - doing it manually here helps reduce peak memory usage.
	 */
	perm_map.clear();

	int init_count = partitions.size();
	if (flags & DFA_DUMP_PROGRESS)
		cerr << "\033[2KMinimize dfa: partitions " << partitions.size()
		     << "\tinit " << init_count << " (accept "
		     << accept_count << ")\r";

	/* Now do repartitioning until each partition contains the set of
	 * states that are the same.  This will happen when the partition
	 * splitting stables.  With a worse case of 1 state per partition
	 * ie. already minimized.
	 */
	Partition *new_part;
	int new_part_count;
	do {
		new_part_count = 0;
		for (list<Partition *>::iterator p = partitions.begin();
		     p != partitions.end(); p++) {
			new_part = NULL;
			State *rep = *((*p)->begin());
			Partition::iterator next;
			for (Partition::iterator s = ++(*p)->begin(); s != (*p)->end();) {
				if (same_mappings(rep, *s)) {
					++s;
					continue;
				}
				if (!new_part) {
					new_part = new Partition;
					list<Partition *>::iterator tmp = p;
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
			if ((flags & DFA_DUMP_PROGRESS) && (partitions.size() % 100 == 0))
				cerr << "\033[2KMinimize dfa: partitions "
				     << partitions.size() << "\tinit "
				     << init_count << " (accept "
				     << accept_count << ")\r";
		}
	} while (new_part_count);

	if (partitions.size() == states.size()) {
		if (flags & DFA_DUMP_STATS)
			cerr << "\033[2KDfa minimization no states removed: partitions "
			     << partitions.size() << "\tinit " << init_count
			     << " (accept " << accept_count << ")\n";

		goto out;
	}

	/* Remap the dfa so it uses the representative states
	 * Use the first state of a partition as the representative state
	 * At this point all states with in a partion have transitions
	 * to states within the same partitions, however this can slow
	 * down compressed dfa compression as there are more states,
	 */
	if (flags & DFA_DUMP_MIN_PARTS)
		cerr << "Partitions after minimization\n";
	for (list<Partition *>::iterator p = partitions.begin();
	     p != partitions.end(); p++) {
		/* representative state for this partition */
		State *rep = *((*p)->begin());
		if (flags & DFA_DUMP_MIN_PARTS)
			cerr << *rep << " : ";

		/* update representative state's transitions */
		rep->otherwise = *rep->otherwise->partition->begin();

		for (StateTrans::iterator c = rep->trans.begin(); c != rep->trans.end(); c++) {
			Partition *partition = c->second->partition;
			c->second = *partition->begin();
		}

//if ((*p)->size() > 1)
//cerr << rep->label << ": ";
		/* clear the state label for all non representative states,
		 * and accumulate permissions */
		for (Partition::iterator i = ++(*p)->begin(); i != (*p)->end(); i++) {
//cerr << " " << (*i)->label;
			if (flags & DFA_DUMP_MIN_PARTS)
				cerr << **i << ", ";
			(*i)->label = -1;
			rep->perms.add((*i)->perms);
		}
		if (rep->perms.is_accept())
			final_accept++;
//if ((*p)->size() > 1)
//cerr << "\n";
		if (flags & DFA_DUMP_MIN_PARTS)
			cerr << "\n";
	}
	if (flags & DFA_DUMP_STATS)
		cerr << "\033[2KMinimized dfa: final partitions "
		     << partitions.size() << " (accept " << final_accept
		     << ")" << "\tinit " << init_count << " (accept "
		     << accept_count << ")\n";

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
	for (Partition::iterator i = states.begin(); i != states.end();) {
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
void DFA::dump(ostream & os)
{
	for (Partition::iterator i = states.begin(); i != states.end(); i++) {
		if (*i == start || (*i)->perms.is_accept()) {
			os << **i;
			if (*i == start)
				os << " <== (allow/deny/audit/quiet)";
			if ((*i)->perms.is_accept())
				(*i)->perms.dump(os);
			os << "\n";
		}
	}
	os << "\n";

	for (Partition::iterator i = states.begin(); i != states.end(); i++) {
		Chars excluded;

		for (StateTrans::iterator j = (*i)->trans.begin();
		     j != (*i)->trans.end(); j++) {
			if (j->second == nonmatching) {
				excluded.insert(j->first);
			} else {
				os << **i;
				if ((*i)->perms.is_accept())
					os << " ", (*i)->perms.dump(os);
				os << " -> " << *(j)->second << ": 0x"
				   << hex << (int) j->first;
				if (isprint(j->first))
					os << " " << j->first;
				os << dec << "\n";
			}
		}

		if ((*i)->otherwise != nonmatching) {
			os << **i;
			if ((*i)->perms.is_accept())
				os << " ", (*i)->perms.dump(os);
			os << " -> " << *(*i)->otherwise << ": [";
			if (!excluded.empty()) {
				os << "^";
				for (Chars::iterator k = excluded.begin();
				     k != excluded.end(); k++) {
					if (isprint(*k))
						os << *k;
					else
						os << "\\0x" << hex << (int) *k << dec;
				}
			}
			os << "]\n";
		}
	}
	os << "\n";
}

/**
 * Create a dot (graphviz) graph from the DFA (for debugging).
 */
void DFA::dump_dot_graph(ostream & os)
{
	os << "digraph \"dfa\" {" << "\n";

	for (Partition::iterator i = states.begin(); i != states.end(); i++) {
		if (*i == nonmatching)
			continue;

		os << "\t\"" << **i << "\" [" << "\n";
		if (*i == start) {
			os << "\t\tstyle=bold" << "\n";
		}
		if ((*i)->perms.is_accept()) {
			os << "\t\tlabel=\"" << **i << "\\n";
			(*i)->perms.dump(os);
			os << "\"\n";
		}
		os << "\t]" << "\n";
	}
	for (Partition::iterator i = states.begin(); i != states.end(); i++) {
		Chars excluded;

		for (StateTrans::iterator j = (*i)->trans.begin(); j != (*i)->trans.end(); j++) {
			if (j->second == nonmatching)
				excluded.insert(j->first);
			else {
				os << "\t\"" << **i << "\" -> \"" << *j->second
				   << "\" [" << "\n";
				os << "\t\tlabel=\"";
				if (isprint(j->first))
					os << j->first;
				else
					os << "\\0x" << hex << (int) j->first << dec;

				os << "\"\n\t]" << "\n";
			}
		}
		if ((*i)->otherwise != nonmatching) {
			os << "\t\"" << **i << "\" -> \"" << *(*i)->otherwise
			   << "\" [" << "\n";
			if (!excluded.empty()) {
				os << "\t\tlabel=\"[^";
				for (Chars::iterator i = excluded.begin();
				     i != excluded.end(); i++) {
					if (isprint(*i))
						os << *i;
					else
						os << "\\0x" << hex << (int) *i << dec;
				}
				os << "]\"" << "\n";
			}
			os << "\t]" << "\n";
		}
	}
	os << '}' << "\n";
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
		/* Group edges to the same next state together */
		map<const State *, Chars> node_sets;
		for (StateTrans::iterator j = (*i)->trans.begin(); j != (*i)->trans.end(); j++)
			node_sets[j->second].insert(j->first);

		for (map<const State *, Chars>::iterator j = node_sets.begin();
		     j != node_sets.end(); j++) {
			/* Group edges to the same next state together by class */
			map<uchar, Chars> node_classes;
			bool class_used = false;
			for (Chars::iterator k = j->second.begin();
			     k != j->second.end(); k++) {
				pair<map<uchar, uchar>::iterator, bool> x = classes.insert(make_pair(*k, next_class));
				if (x.second)
					class_used = true;
				pair<map<uchar, Chars>::iterator, bool> y = node_classes.insert(make_pair(x.first->second, Chars()));
				y.first->second.insert(*k);
			}
			if (class_used) {
				next_class++;
				class_used = false;
			}
			for (map<uchar, Chars>::iterator k = node_classes.begin();
			     k != node_classes.end(); k++) {
			  /**
			   * If any other characters are in the same class, move
			   * the characters in this class into their own new
			   * class
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
					     l != k->second.end(); l++) {
						classes[*l] = next_class;
					}
					next_class++;
					class_used = false;
				}
			}
		}
	}

	if (flags & DFA_DUMP_EQUIV_STATS)
		fprintf(stderr, "Equiv class reduces to %d classes\n",
			next_class - 1);
	return classes;
}

/**
 * Text-dump the equivalence classes (for debugging).
 */
void dump_equivalence_classes(ostream &os, map<uchar, uchar> &eq)
{
	map<uchar, Chars> rev;

	for (map<uchar, uchar>::iterator i = eq.begin(); i != eq.end(); i++) {
		Chars &chars = rev.insert(make_pair(i->second, Chars())).first->second;
		chars.insert(i->first);
	}
	os << "(eq):" << "\n";
	for (map<uchar, Chars>::iterator i = rev.begin(); i != rev.end(); i++) {
		os << (int)i->first << ':';
		Chars &chars = i->second;
		for (Chars::iterator j = chars.begin(); j != chars.end(); j++) {
			os << ' ' << *j;
		}
		os << "\n";
	}
}

/**
 * Replace characters with classes (which are also represented as
 * characters) in the DFA transition table.
 */
void DFA::apply_equivalence_classes(map<uchar, uchar> &eq)
{
    /**
     * Note: We only transform the transition table; the nodes continue to
     * contain the original characters.
     */
	for (Partition::iterator i = states.begin(); i != states.end(); i++) {
		map<uchar, State *> tmp;
		tmp.swap((*i)->trans);
		for (StateTrans::iterator j = tmp.begin(); j != tmp.end(); j++)
			(*i)->trans.insert(make_pair(eq[j->first], j->second));
	}
}

#if 0
typedef set <ImportantNode *>AcceptNodes;
map<ImportantNode *, AcceptNodes> dominance(DFA & dfa)
{
	map<ImportantNode *, AcceptNodes> is_dominated;

	for (States::iterator i = dfa.states.begin(); i != dfa.states.end(); i++) {
		AcceptNodes set1;
		for (State::iterator j = (*i)->begin(); j != (*i)->end(); j++) {
			if (AcceptNode * accept = dynamic_cast<AcceptNode *>(*j))
				set1.insert(accept);
		}
		for (AcceptNodes::iterator j = set1.begin(); j != set1.end(); j++) {
			pair<map<ImportantNode *, AcceptNodes>::iterator, bool> x = is_dominated.insert(make_pair(*j, set1));
			if (!x.second) {
				AcceptNodes & set2(x.first->second), set3;
				for (AcceptNodes::iterator l = set2.begin();
				     l != set2.end(); l++) {
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
int accept_perms(NodeSet *state, perms_t &perms)
{
	int error = 0;
	uint32_t exact_match_allow = 0;
	uint32_t exact_audit = 0;

	perms.clear();

	if (!state)
		return error;

	for (NodeSet::iterator i = state->begin(); i != state->end(); i++) {
		MatchFlag *match;
		if (!(match = dynamic_cast<MatchFlag *>(*i)))
			continue;
		if (dynamic_cast<ExactMatchFlag *>(match)) {
			/* exact match only ever happens with x */
			if (!is_merged_x_consistent(exact_match_allow,
						    match->flag))
				error = 1;;
			exact_match_allow |= match->flag;
			exact_audit |= match->audit;
		} else if (dynamic_cast<DenyMatchFlag *>(match)) {
			perms.deny |= match->flag;
			perms.quiet |= match->audit;
		} else {
			if (!is_merged_x_consistent(perms.allow, match->flag))
				error = 1;
			perms.allow |= match->flag;
			perms.audit |= match->audit;
		}
	}

	perms.allow |= exact_match_allow & ~(ALL_AA_EXEC_TYPE);

	if (exact_match_allow & AA_USER_EXEC_TYPE) {
		perms.allow = (exact_match_allow & AA_USER_EXEC_TYPE) |
			(perms.allow & ~AA_USER_EXEC_TYPE);
		perms.audit = (exact_audit & AA_USER_EXEC_TYPE) |
			(perms.audit & ~AA_USER_EXEC_TYPE);
		perms.exact = AA_USER_EXEC_TYPE;
	}
	if (exact_match_allow & AA_OTHER_EXEC_TYPE) {
		perms.allow = (exact_match_allow & AA_OTHER_EXEC_TYPE) |
			(perms.allow & ~AA_OTHER_EXEC_TYPE);
		perms.audit = (exact_audit & AA_OTHER_EXEC_TYPE) |
			(perms.audit & ~AA_OTHER_EXEC_TYPE);
		perms.exact |= AA_OTHER_EXEC_TYPE;
	}
	if (AA_USER_EXEC & perms.deny)
		perms.deny |= AA_USER_EXEC_TYPE;

	if (AA_OTHER_EXEC & perms.deny)
		perms.deny |= AA_OTHER_EXEC_TYPE;

	perms.allow &= ~perms.deny;
	perms.quiet &= perms.deny;

	if (error)
		fprintf(stderr, "profile has merged rule with conflicting x modifiers\n");

	return error;
}
