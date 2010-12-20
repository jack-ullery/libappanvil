/*
 * regexp.y -- Regular Expression Matcher Generator
 * (C) 2006, 2007 Andreas Gruenbacher <agruen@suse.de>
 *
 * Implementation based on the Lexical Analysis chapter of:
 *   Alfred V. Aho, Ravi Sethi, Jeffrey D. Ullman:
 *   Compilers: Principles, Techniques, and Tools (The "Dragon Book"),
 *   Addison-Wesley, 1986.
 *
 *  This program is free software; you can redistribute it and/or modify
 *  it under the terms of the GNU General Public License version 2 as
 *  published by the Free Software Foundation.
 *
 *  See http://www.gnu.org for more details.
 */

%{
    /* #define DEBUG_TREE */

    #include <list>
    #include <vector>
    #include <stack>
    #include <set>
    #include <map>
    #include <ostream>
    #include <iostream>
    #include <fstream>

    using namespace std;

    typedef unsigned char uchar;
    typedef set<uchar> Chars;

    ostream& operator<<(ostream& os, uchar c);

    /* Compute the union of two sets. */
    template<class T>
    set<T> operator+(const set<T>& a, const set<T>& b)
    {
	set<T> c(a);
	c.insert(b.begin(), b.end());
	return c;
    }

    /**
     * When creating DFAs from regex trees, a DFA state is constructed from
     * a set of important nodes in the syntax tree. This includes AcceptNodes,
     * which indicate that when a match ends in a particular state, the
     * regular expressions that the AcceptNode belongs to match.
     */
    class ImportantNode;
    typedef set <ImportantNode *> NodeSet;

    /**
     * Out-edges from a state to another: we store the follow-set of Nodes
     * for each input character that is not a default match in
     * cases (i.e., following a CharNode or CharSetNode), and default
     * matches in otherwise as well as in all matching explicit cases
     * (i.e., following an AnyCharNode or NotCharSetNode). This avoids
     * enumerating all the explicit tranitions for default matches.
     */
    typedef struct NodeCases {
	typedef map<uchar, NodeSet *>::iterator iterator;
	iterator begin() { return cases.begin(); }
	iterator end() { return cases.end(); }

	NodeCases() : otherwise(0) { }
	map<uchar, NodeSet *> cases;
	NodeSet *otherwise;
    } NodeCases;


    /* An abstract node in the syntax tree. */
    class Node {
    public:
	Node() :
	    nullable(false) { child[0] = child[1] = 0; }
	Node(Node *left) :
	    nullable(false) { child[0] = left; child[1] = 0; }
	Node(Node *left, Node *right) :
	    nullable(false) { child[0] = left; child[1] = right; }
	virtual ~Node()
	{
	    if (child[0])
		    child[0]->release();
	    if (child[1])
		    child[1]->release();
	}

	/**
	 * See the "Dragon Book" for an explanation of nullable, firstpos,
	 * lastpos, and followpos.
	 */
	virtual void compute_nullable() { }
	virtual void compute_firstpos() = 0;
	virtual void compute_lastpos() = 0;
	virtual void compute_followpos() { }
	virtual int eq(Node *other) = 0;
	virtual ostream& dump(ostream& os) = 0;

	bool nullable;
	NodeSet firstpos, lastpos, followpos;
	/* child 0 is left, child 1 is right */
	Node *child[2];

	unsigned int label;	/* unique number for debug etc */
	/**
	 * We indirectly release Nodes through a virtual function because
	 * accept and Eps Nodes are shared, and must be treated specially.
	 * We could use full reference counting here but the indirect release
	 * is sufficient and has less overhead
	 */
	virtual void release(void) {
	    delete this;
	}
    };

    class InnerNode : public Node {
    public:
        InnerNode() : Node() { };
        InnerNode(Node *left) : Node(left) {};
        InnerNode(Node *left, Node *right) : Node(left, right) { };
    };

    class OneChildNode : public InnerNode {
    public:
        OneChildNode(Node *left) : InnerNode(left) { };
    };

    class TwoChildNode : public InnerNode {
    public:
        TwoChildNode(Node *left, Node *right) :  InnerNode(left, right) { };
    };

    class LeafNode : public Node {
    public:
        LeafNode() : Node() { };

    };

    /* Match nothing (//). */
    class EpsNode : public LeafNode {
    public:
    EpsNode() : LeafNode()
	{
	    nullable = true;
	    label = 0;
	}
	void release(void)
	{
	  /* don't delete Eps nodes because there is a single static instance
	   * shared by all trees.  Look for epsnode in the code
	   */
	}

	void compute_firstpos()
	{
	}
	void compute_lastpos()
	{
	}
	int eq(Node *other) {
		if (dynamic_cast<EpsNode *>(other))
			return 1;
		return 0;
	}
	ostream& dump(ostream& os)
	{
	    return os << "[]";
	}
    };

    /**
     * Leaf nodes in the syntax tree are important to us: they describe the
     * characters that the regular expression matches. We also consider
     * AcceptNodes import: they indicate when a regular expression matches.
     */
    class ImportantNode : public LeafNode {
    public:
        ImportantNode() : LeafNode() { }
	void compute_firstpos()
	{
	    firstpos.insert(this);
	}
	void compute_lastpos() {
	    lastpos.insert(this);
	}
	virtual void follow(NodeCases& cases) = 0;
    };

    /* common base class for all the different classes that contain
     * character information.
     */
    class CNode : public ImportantNode {
    public:
        CNode() : ImportantNode() { }

    };

    /* Match one specific character (/c/). */
    class CharNode : public CNode {
    public:
	CharNode(uchar c) : c(c) { }
	void follow(NodeCases& cases)
	{
	    NodeSet **x = &cases.cases[c];
	    if (!*x) {
		if (cases.otherwise)
		    *x = new NodeSet(*cases.otherwise);
		else
		    *x = new NodeSet;
	    }
	    (*x)->insert(followpos.begin(), followpos.end());
	}
	int eq(Node *other) {
		CharNode *o = dynamic_cast<CharNode *>(other);
		if (o) {
			return c == o->c;
		}
		return 0;
	}
	ostream& dump(ostream& os)
	{
	    return os << c;
	}

	uchar c;
    };

    /* Match a set of characters (/[abc]/). */
    class CharSetNode : public CNode {
    public:
	CharSetNode(Chars& chars) : chars(chars) { }
	void follow(NodeCases& cases)
	{
	    for (Chars::iterator i = chars.begin(); i != chars.end(); i++) {
		NodeSet **x = &cases.cases[*i];
		if (!*x) {
		    if (cases.otherwise)
			*x = new NodeSet(*cases.otherwise);
		    else
			*x = new NodeSet;
		}
		(*x)->insert(followpos.begin(), followpos.end());
	    }
	}
	int eq(Node *other) {
		CharSetNode *o = dynamic_cast<CharSetNode *>(other);
		if (!o || chars.size() != o->chars.size())
			return 0;

		for (Chars::iterator i = chars.begin(), j = o->chars.begin();
		     i != chars.end() && j != o->chars.end();
		     i++, j++) {
			if (*i != *j)
				return 0;
		}
		return 1;
	}
	ostream& dump(ostream& os)
	{
	    os << '[';
	    for (Chars::iterator i = chars.begin(); i != chars.end(); i++)
		os << *i;
	    return os << ']';
	}

	Chars chars;
    };

    /* Match all except one character (/[^abc]/). */
    class NotCharSetNode : public CNode {
    public:
	NotCharSetNode(Chars& chars) : chars(chars) { }
	void follow(NodeCases& cases)
	{
	    if (!cases.otherwise)
		cases.otherwise = new NodeSet;
	    for (Chars::iterator j = chars.begin(); j != chars.end(); j++) {
		NodeSet **x = &cases.cases[*j];
		if (!*x)
		    *x = new NodeSet(*cases.otherwise);
	    }
	    /**
	     * Note: Add to the nonmatching characters after copying away the
	     * old otherwise state for the matching characters.
	     */
	    cases.otherwise->insert(followpos.begin(), followpos.end());
	    for (NodeCases::iterator i = cases.begin(); i != cases.end(); i++) {
		if (chars.find(i->first) == chars.end())
		    i->second->insert(followpos.begin(), followpos.end());
	    }
	}
	int eq(Node *other) {
		NotCharSetNode *o = dynamic_cast<NotCharSetNode *>(other);
		if (!o || chars.size() != o->chars.size())
			return 0;

		for (Chars::iterator i = chars.begin(), j = o->chars.begin();
		     i != chars.end() && j != o->chars.end();
		     i++, j++) {
			if (*i != *j)
				return 0;
		}
		return 1;
	}
	ostream& dump(ostream& os)
	{
	    os << "[^";
	    for (Chars::iterator i = chars.begin(); i != chars.end(); i++)
		os << *i;
	    return os << ']';
	}

	Chars chars;
    };

    /* Match any character (/./). */
    class AnyCharNode : public CNode {
    public:
	AnyCharNode() { }
	void follow(NodeCases& cases)
	{
	    if (!cases.otherwise)
		cases.otherwise = new NodeSet;
	    cases.otherwise->insert(followpos.begin(), followpos.end());
	    for (NodeCases::iterator i = cases.begin(); i != cases.end(); i++)
		i->second->insert(followpos.begin(), followpos.end());
	}
	int eq(Node *other) {
		if (dynamic_cast<AnyCharNode *>(other))
			return 1;
		return 0;
	}
	ostream& dump(ostream& os) {
	    return os << ".";
	}
    };

    /**
     * Indicate that a regular expression matches. An AcceptNode itself
     * doesn't match anything, so it will never generate any transitions.
     */
    class AcceptNode : public ImportantNode {
    public:
	AcceptNode() {}
	void release(void)
	{
	  /* don't delete AcceptNode via release as they are shared,
	   * and will be deleted when the table the are stored in is deleted
	   */
	}

	void follow(NodeCases& cases __attribute__((unused)))
	{
	    /* Nothing to follow. */
	}
	/* requires accept nodes to be common by pointer */
	int eq(Node *other) {
		if (dynamic_cast<AcceptNode *>(other))
			return (this == other);
		return 0;
	}
    };

    /* Match a node zero or more times. (This is a unary operator.) */
    class StarNode : public OneChildNode {
    public:
	StarNode(Node *left) :
	    OneChildNode(left)
	{
	    nullable = true;
	}
	void compute_firstpos()
	{
	    firstpos = child[0]->firstpos;
	}
	void compute_lastpos()
	{
	    lastpos = child[0]->lastpos;
	}
	void compute_followpos()
	{
	    NodeSet from = child[0]->lastpos, to = child[0]->firstpos;
	    for(NodeSet::iterator i = from.begin(); i != from.end(); i++) {
		(*i)->followpos.insert(to.begin(), to.end());
	    }
	}
	int eq(Node *other) {
		if (dynamic_cast<StarNode *>(other))
			return child[0]->eq(other->child[0]);
		return 0;
	}
	ostream& dump(ostream& os)
	{
	    os << '(';
	    child[0]->dump(os);
	    return os << ")*";
	}
    };

    /* Match a node one or more times. (This is a unary operator.) */
    class PlusNode : public OneChildNode {
    public:
	PlusNode(Node *left) :
	    OneChildNode(left) { }
	void compute_nullable()
	{
	    nullable = child[0]->nullable;
	}
	void compute_firstpos()
	{
	    firstpos = child[0]->firstpos;
	}
	void compute_lastpos()
	{
	    lastpos = child[0]->lastpos;
	}
	void compute_followpos()
	{
	    NodeSet from = child[0]->lastpos, to = child[0]->firstpos;
	    for(NodeSet::iterator i = from.begin(); i != from.end(); i++) {
		(*i)->followpos.insert(to.begin(), to.end());
	    }
	}
	int eq(Node *other) {
		if (dynamic_cast<PlusNode *>(other))
			return child[0]->eq(other->child[0]);
		return 0;
	}
	ostream& dump(ostream& os)
	{
	    os << '(';
	    child[0]->dump(os);
	    return os << ")+";
	}
    };

    /* Match a pair of consecutive nodes. */
    class CatNode : public TwoChildNode {
    public:
	CatNode(Node *left, Node *right) :
	    TwoChildNode(left, right) { }
	void compute_nullable()
	{
	    nullable = child[0]->nullable && child[1]->nullable;
	}
	void compute_firstpos()
	{
	    if (child[0]->nullable)
		firstpos = child[0]->firstpos + child[1]->firstpos;
	    else
		firstpos = child[0]->firstpos;
	}
	void compute_lastpos()
	{
	    if (child[1]->nullable)
		lastpos = child[0]->lastpos + child[1]->lastpos;
	    else
		lastpos = child[1]->lastpos;
	}
	void compute_followpos()
	{
	    NodeSet from = child[0]->lastpos, to = child[1]->firstpos;
	    for(NodeSet::iterator i = from.begin(); i != from.end(); i++) {
		(*i)->followpos.insert(to.begin(), to.end());
	    }
	}
	int eq(Node *other) {
		if (dynamic_cast<CatNode *>(other)) {
			if (!child[0]->eq(other->child[0]))
				return 0;
			return child[1]->eq(other->child[1]);
		}
		return 0;
	}
	ostream& dump(ostream& os)
	{
	    child[0]->dump(os);
	    child[1]->dump(os);
	    return os;
	    //return os << ' ';
	}
    };

    /* Match one of two alternative nodes. */
    class AltNode : public TwoChildNode {
    public:
	AltNode(Node *left, Node *right) :
	    TwoChildNode(left, right) { }
	void compute_nullable()
	{
	    nullable = child[0]->nullable || child[1]->nullable;
	}
	void compute_lastpos()
	{
	    lastpos = child[0]->lastpos + child[1]->lastpos;
	}
	void compute_firstpos()
	{
	    firstpos = child[0]->firstpos + child[1]->firstpos;
	}
	int eq(Node *other) {
		if (dynamic_cast<AltNode *>(other)) {
			if (!child[0]->eq(other->child[0]))
				return 0;
			return child[1]->eq(other->child[1]);
		}
		return 0;
	}
	ostream& dump(ostream& os)
	{
	    os << '(';
	    child[0]->dump(os);
	    os << '|';
	    child[1]->dump(os);
	    os << ')';
	    return os;
	}
    };

/* Use a single static EpsNode as it carries no node specific information */
static EpsNode epsnode;

/*
 * Normalize the regex parse tree for factoring and cancelations. Normalization
 * reorganizes internal (alt and cat) nodes into a fixed "normalized" form that
 * simplifies factoring code, in that it produces a canonicalized form for
 * the direction being normalized so that the factoring code does not have
 * to consider as many cases.
 *
 * left normalization (dir == 0) uses these rules
 * (E | a) -> (a | E)
 * (a | b) | c -> a | (b | c)
 * (ab)c -> a(bc)
 *
 * right normalization (dir == 1) uses the same rules but reversed
 * (a | E) -> (E | a)
 * a | (b | c) -> (a | b) | c
 * a(bc) -> (ab)c
 *
 * Note: This is written iteratively for a given node (the top node stays
 *       fixed and the children are rotated) instead of recursively.
 *       For a given node under examination rotate over nodes from
 *       dir to !dir.   Until no dir direction node meets the criterial.
 *       Then recurse to the children (which will have a different node type)
 *       to make sure they are normalized.
 *       Normalization of a child node is guarenteed to not affect the
 *       normalization of the parent.
 *
 *       For cat nodes the depth first traverse order is guarenteed to be
 *       maintained.  This is not necessary for altnodes.
 *
 * Eg. For left normalization
 *
 *              |1               |1
 *             / \              / \
 *            |2  T     ->     a   |2
 *           / \                  / \
 *          |3  c                b   |3
 *         / \                      / \
 *        a   b                    c   T
 *
 */
static void rotate_node(Node *t, int dir) {
	// (a | b) | c -> a | (b | c)
	// (ab)c -> a(bc)
	Node *left = t->child[dir];
	t->child[dir] = left->child[dir];
	left->child[dir] = left->child[!dir];
	left->child[!dir] = t->child[!dir];
	t->child[!dir] = left;
}

void normalize_tree(Node *t, int dir)
{
	if (dynamic_cast<LeafNode *>(t))
		return;

	for (;;) {
		if ((&epsnode == t->child[dir]) &&
		    (&epsnode != t->child[!dir]) &&
		     dynamic_cast<TwoChildNode *>(t)) {
			// (E | a) -> (a | E)
			// Ea -> aE
			Node *c = t->child[dir];
			t->child[dir] = t->child[!dir];
			t->child[!dir] = c;
			// Don't break here as 'a' may be a tree that
			// can be pulled up.
		} else if ((dynamic_cast<AltNode *>(t) &&
			    dynamic_cast<AltNode *>(t->child[dir])) ||
			   (dynamic_cast<CatNode *>(t) &&
			    dynamic_cast<CatNode *>(t->child[dir]))) {
			// (a | b) | c -> a | (b | c)
			// (ab)c -> a(bc)
			rotate_node(t, dir);
		} else if (dynamic_cast<AltNode *>(t) &&
			   dynamic_cast<CharSetNode *>(t->child[dir]) &&
			   dynamic_cast<CharNode *>(t->child[!dir])) {
			// [a] | b  ->  b | [a]
			Node *c = t->child[dir];
			t->child[dir] = t->child[!dir];
			t->child[!dir] = c;
		} else {
			break;
		}
	}
	if (t->child[dir])
		normalize_tree(t->child[dir], dir);
	if (t->child[!dir])
		normalize_tree(t->child[!dir], dir);
}

//charset conversion is disabled for now,
//it hinders tree optimization in some cases, so it need to be either
//done post optimization, or have extra factoring rules added
#if 0
static Node *merge_charset(Node *a, Node *b)
{
	if (dynamic_cast<CharNode *>(a) &&
	    dynamic_cast<CharNode *>(b)) {
		Chars chars;
		chars.insert(dynamic_cast<CharNode *>(a)->c);
		chars.insert(dynamic_cast<CharNode *>(b)->c);
		CharSetNode *n = new CharSetNode(chars);
		return n;
	} else if (dynamic_cast<CharNode *>(a) &&
		   dynamic_cast<CharSetNode *>(b)) {
		Chars *chars = &dynamic_cast<CharSetNode *>(b)->chars;
		chars->insert(dynamic_cast<CharNode *>(a)->c);
		return b;
	} else if (dynamic_cast<CharSetNode *>(a) &&
		   dynamic_cast<CharSetNode *>(b)) {
		Chars *from = &dynamic_cast<CharSetNode *>(a)->chars;
		Chars *to = &dynamic_cast<CharSetNode *>(b)->chars;
		for (Chars::iterator i = from->begin(); i != from->end(); i++)
			to->insert(*i);
		return b;
	}

	//return ???;
}

static Node *alt_to_charsets(Node *t, int dir)
{
/*
	Node *first = NULL;
	Node *p = t;
	Node *i = t;
	for (;dynamic_cast<AltNode *>(i);) {
		if (dynamic_cast<CharNode *>(i->child[dir]) ||
		    dynamic_cast<CharNodeSet *>(i->child[dir])) {
			if (!first) {
				first = i;
				p = i;
				i = i->child[!dir];
			} else {
				first->child[dir] = merge_charset(first->child[dir],
						      i->child[dir]);
				p->child[!dir] = i->child[!dir];
				Node *tmp = i;
				i = tmp->child[!dir];
				tmp->child[!dir] = NULL;
				tmp->release();
			}
		} else {
			p = i;
			i = i->child[!dir];
		}
	}
	// last altnode of chain check other dir as well
	if (first && (dynamic_cast<charNode *>(i) ||
		      dynamic_cast<charNodeSet *>(i))) {
		
	}
*/

/*
		if (dynamic_cast<CharNode *>(t->child[dir]) ||
		    dynamic_cast<CharSetNode *>(t->child[dir]))
		    char_test = true;
			    (char_test &&
			     (dynamic_cast<CharNode *>(i->child[dir]) ||
			      dynamic_cast<CharSetNode *>(i->child[dir])))) {
*/
	return t;
}
#endif

static Node *basic_alt_factor(Node *t, int dir)
{
	if (!dynamic_cast<AltNode *>(t))
		return t;

	if (t->child[dir]->eq(t->child[!dir])) {
		// (a | a) -> a
		Node *tmp = t->child[dir];
		t->child[dir] = NULL;
		t->release();
		return tmp;
	}

	// (ab) | (ac) -> a(b|c)
	if (dynamic_cast<CatNode *>(t->child[dir]) &&
	    dynamic_cast<CatNode *>(t->child[!dir]) &&
	    t->child[dir]->child[dir]->eq(t->child[!dir]->child[dir])) {
		// (ab) | (ac) -> a(b|c)
		Node *left = t->child[dir];
		Node *right = t->child[!dir];
		t->child[dir] = left->child[!dir];
		t->child[!dir] = right->child[!dir];
		right->child[!dir] = NULL;
		right->release();
		left->child[!dir] = t;
		return left;
	}

	// a | (ab) -> a (E | b) -> a (b | E)
	if (dynamic_cast<CatNode *>(t->child[!dir]) &&
	    t->child[dir]->eq(t->child[!dir]->child[dir])) {
		Node *c = t->child[!dir];
		t->child[dir]->release();
		t->child[dir] = c->child[!dir];
		t->child[!dir] = &epsnode;
		c->child[!dir] = t;
		return c;
	}

	// ab | (a) -> a (b | E)
	if (dynamic_cast<CatNode *>(t->child[dir]) &&
	    t->child[dir]->child[dir]->eq(t->child[!dir])) {
		Node *c = t->child[dir];
		t->child[!dir]->release();
		t->child[dir] = c->child[!dir];
		t->child[!dir] = &epsnode;
		c->child[!dir] = t;
		return c;
	}

	return t;
}

static Node *basic_simplify(Node *t, int dir)
{
	if (dynamic_cast<CatNode *>(t) &&
	    &epsnode == t->child[!dir]) {
		// aE -> a
		Node *tmp = t->child[dir];
		t->child[dir] = NULL;
		t->release();
		return tmp;
	}

	return basic_alt_factor(t, dir);
}

/*
 * assumes a normalized tree.  reductions shown for left normalization
 * aE -> a
 * (a | a) -> a
 ** factoring patterns
 * a | (a | b) -> (a | b)
 * a | (ab) -> a (E | b) -> a (b | E)
 * (ab) | (ac) -> a(b|c)
 *
 * returns t - if no simplifications were made
 *         a new root node - if simplifications were made
 */
Node *simplify_tree_base(Node *t, int dir, bool &mod)
{
	if (dynamic_cast<ImportantNode *>(t))
		return t;

	for (int i=0; i < 2; i++) {
		if (t->child[i]) {
			Node *c = simplify_tree_base(t->child[i], dir, mod);
			if (c != t->child[i]) {
				t->child[i] = c;
				mod = true;
			}
		}
	}

	// only iterate on loop if modification made
	for (;; mod = true) {

		Node *tmp = basic_simplify(t, dir);
		if (tmp != t) {
			t = tmp;
			continue;
		}


		/* all tests after this must meet 2 alt node condition */
		if (!dynamic_cast<AltNode *>(t) ||
		    !dynamic_cast<AltNode *>(t->child[!dir]))
			break;

		// a | (a | b) -> (a | b)
		// a | (b | (c | a)) -> (b | (c | a))
		Node *p = t;
		Node *i = t->child[!dir];
		for (;dynamic_cast<AltNode *>(i); p = i, i = i->child[!dir]) {
			if (t->child[dir]->eq(i->child[dir])) {
				Node *tmp = t->child[!dir];
				t->child[!dir] = NULL;
				t->release();
				t = tmp;
				continue;
			}
		}
		// last altnode of chain check other dir as well
		if (t->child[dir]->eq(p->child[!dir])) {
			Node *tmp = t->child[!dir];
			t->child[!dir] = NULL;
			t->release();
			t = tmp;
			continue;
		}

		//exact match didn't work, try factoring front
		//a | (ac | (ad | () -> (a (E | c)) | (...)
		//ab | (ac | (...)) -> (a (b | c)) | (...)
		//ab | (a | (...)) -> (a (b | E)) | (...)
		Node *pp;
		int count = 0;
		Node *subject = t->child[dir];
		Node *a = subject;
		if (dynamic_cast<CatNode *>(subject))
		    a = subject->child[dir];

		for (pp = p = t, i = t->child[!dir];
		     dynamic_cast<AltNode *>(i); ) {
			if ((dynamic_cast<CatNode *>(i->child[dir]) &&
			     a->eq(i->child[dir]->child[dir])) ||
			    (a->eq(i->child[dir]))) {
				// extract matching alt node
				p->child[!dir] = i->child[!dir];
				i->child[!dir] = subject;
				subject = basic_simplify(i, dir);
				if (dynamic_cast<CatNode *>(subject))
					a = subject->child[dir];
				else
					a = subject;

				i = p->child[!dir];
				count++;
			} else {
				pp = p; p = i; i = i->child[!dir];
			}
		}

		// last altnode in chain check other dir as well
		if ((dynamic_cast<CatNode *>(i) &&
		     a->eq(i->child[dir])) ||
		    (a->eq(i))) {
			count++;
			if (t == p) {
				t->child[dir] = subject;
				t = basic_simplify(t, dir);
			} else {
				t->child[dir] = p->child[dir];
				p->child[dir] = subject;
				pp->child[!dir] = basic_simplify(p, dir);
			}
		} else {
			t->child[dir] = i;
			p->child[!dir] = subject;
		}

		if (count == 0)
			break;
	}
	return t;
}

int debug_tree(Node *t)
{
	int nodes = 1;

	if (!dynamic_cast<ImportantNode *>(t)) {
		if (t->child[0])
			nodes += debug_tree(t->child[0]);
		if (t->child[1])
			nodes += debug_tree(t->child[1]);
	}
	return nodes;
}

struct node_counts {
	int charnode;
	int charset;
	int notcharset;
	int alt;
	int plus;
	int star;
	int any;
	int cat;
};


static void count_tree_nodes(Node *t, struct node_counts *counts)
{
	if (dynamic_cast<AltNode *>(t)) {
		counts->alt++;
		count_tree_nodes(t->child[0], counts);
		count_tree_nodes(t->child[1], counts);
	} else if (dynamic_cast<CatNode *>(t)) {
		counts->cat++;
		count_tree_nodes(t->child[0], counts);
		count_tree_nodes(t->child[1], counts);
	} else if (dynamic_cast<PlusNode *>(t)) {
		counts->plus++;
		count_tree_nodes(t->child[0], counts);
	} else if (dynamic_cast<StarNode *>(t)) {
		counts->star++;
		count_tree_nodes(t->child[0], counts);
	} else if (dynamic_cast<CharNode *>(t)) {
		counts->charnode++;
	} else if (dynamic_cast<AnyCharNode *>(t)) {
		counts->any++;
	} else if (dynamic_cast<CharSetNode *>(t)) {
		counts->charset++;
	} else if (dynamic_cast<NotCharSetNode *>(t)) {
		counts->notcharset++;
	}
}

#include "stdio.h"
#include "stdint.h"
#include "apparmor_re.h"

Node *simplify_tree(Node *t, dfaflags_t flags)
{
	bool update;

	if (flags & DFA_DUMP_TREE_STATS) {
		struct node_counts counts = { 0, 0, 0, 0, 0, 0, 0, 0 };
		count_tree_nodes(t, &counts);
		fprintf(stderr, "expr tree: c %d, [] %d, [^] %d, | %d, + %d, * %d, . %d, cat %d\n", counts.charnode, counts.charset, counts.notcharset, counts.alt, counts.plus, counts.star, counts.any, counts.cat);
	}
	do {
		update = false;
		//default to right normalize first as this reduces the number
		//of trailing nodes which might follow an internal *
		//or **, which is where state explosion can happen
		//eg. in one test this makes the difference between
		//    the dfa having about 7 thousands states,
		//    and it having about  1.25 million states
		int dir = 1;
		if (flags & DFA_CONTROL_TREE_LEFT)
			dir = 0;
		for (int count = 0; count < 2; count++) {
			bool modified;
			do {
			    modified = false;
			    if (flags & DFA_CONTROL_TREE_NORMAL)
				normalize_tree(t, dir);
			    t = simplify_tree_base(t, dir, modified);
			    if (modified)
				update = true;
			} while (modified);
			if (flags & DFA_CONTROL_TREE_LEFT)
				dir++;
			else
				dir--;
		}
	} while(update);
	if (flags & DFA_DUMP_TREE_STATS) {
		struct node_counts counts = { 0, 0, 0, 0, 0, 0, 0, 0 };
		count_tree_nodes(t, &counts);
		fprintf(stderr, "simplified expr tree: c %d, [] %d, [^] %d, | %d, + %d, * %d, . %d, cat %d\n", counts.charnode, counts.charset, counts.notcharset, counts.alt, counts.plus, counts.star, counts.any, counts.cat);
	}
	return t;
}


%}

%union {
    char c;
    Node *node;
    Chars *cset;
}

%{
    void regexp_error(Node **, const char *, const char *);
#   define YYLEX_PARAM &text
    int regexp_lex(YYSTYPE *, const char **);

    static inline Chars*
    insert_char(Chars* cset, uchar a)
    {
	cset->insert(a);
	return cset;
    }

    static inline Chars*
    insert_char_range(Chars* cset, uchar a, uchar b)
    {
	if (a > b)
	    swap(a, b);
	for (uchar i = a; i <= b; i++)
	    cset->insert(i);
	return cset;
    }
%}

%pure-parser
/* %error-verbose */
%parse-param {Node **root}
%parse-param {const char *text}
%name-prefix = "regexp_"

%token <c> CHAR
%type <c> regex_char cset_char1 cset_char cset_charN
%type <cset> charset cset_chars
%type <node> regexp expr terms0 terms qterm term

/**
 * Note: destroy all nodes upon failure, but *not* the start symbol once
 * parsing succeeds!
 */
%destructor { $$->release(); } expr terms0 terms qterm term

%%

/* FIXME: Does not parse "[--]", "[---]", "[^^-x]". I don't actually know
          which precise grammer Perl regexps use, and rediscovering that
	  is proving to be painful. */

regexp	    : /* empty */	{ *root = $$ = &epsnode; }
	    | expr		{ *root = $$ = $1; }
	    ;

expr	    : terms
	    | expr '|' terms0	{ $$ = new AltNode($1, $3); }
	    | '|' terms0	{ $$ = new AltNode(&epsnode, $2); }
	    ;

terms0	    : /* empty */	{ $$ = &epsnode; }
	    | terms
	    ;

terms	    : qterm
	    | terms qterm	{ $$ = new CatNode($1, $2); }
	    ;

qterm	    : term
	    | term '*'		{ $$ = new StarNode($1); }
	    | term '+'		{ $$ = new PlusNode($1); }
	    ;

term	    : '.'		{ $$ = new AnyCharNode; }
	    | regex_char	{ $$ = new CharNode($1); }
	    | '[' charset ']'	{ $$ = new CharSetNode(*$2);
				  delete $2; }
	    | '[' '^' charset ']'
				{ $$ = new NotCharSetNode(*$3);
				  delete $3; }
	    | '[' '^' '^' cset_chars ']'
				{ $4->insert('^');
				  $$ = new NotCharSetNode(*$4);
				  delete $4; }
	    | '(' regexp ')'	{ $$ = $2; }
	    ;

regex_char  : CHAR
	    | '^'		{ $$ = '^'; }
	    | '-'		{ $$ = '-'; }
	    | ']'		{ $$ = ']'; }
	    ;

charset	    : cset_char1 cset_chars
				{ $$ = insert_char($2, $1); }
	    | cset_char1 '-' cset_charN cset_chars
				{ $$ = insert_char_range($4, $1, $3); }
	    ;

cset_chars  : /* nothing */	{ $$ = new Chars; }
	    | cset_chars cset_charN
				{ $$ = insert_char($1, $2); }
	    | cset_chars cset_charN '-' cset_charN
				{ $$ = insert_char_range($1, $2, $4); }
	    ;

cset_char1  : cset_char
	    | ']'		{ $$ = ']'; }
	    | '-'		{ $$ = '-'; }
	    ;

cset_charN  : cset_char
	    | '^'		{ $$ = '^'; }
	    ;

cset_char   : CHAR
	    | '['		{ $$ = '['; }
	    | '*'		{ $$ = '*'; }
	    | '+'		{ $$ = '+'; }
	    | '.'		{ $$ = '.'; }
	    | '|'		{ $$ = '|'; }
	    | '('		{ $$ = '('; }
	    | ')'		{ $$ = ')'; }
	    ;

%%

#include <string.h>
#include <getopt.h>
#include <assert.h>
#include <arpa/inet.h>

#include <iostream>
#include <fstream>

#include "../immunix.h"

/* Traverse the syntax tree depth-first in an iterator-like manner. */
class depth_first_traversal {
    stack<Node *> pos;
    void push_left(Node *node)
    {
	pos.push(node);

        while (dynamic_cast<InnerNode *>(node)) {
            pos.push(node->child[0]);
            node = node->child[0];
        }
    }

public:
    depth_first_traversal(Node *node) {
	push_left(node);
    }
    Node *operator*()
    {
        return pos.top();
    }
    Node* operator->()
    {
	return pos.top();
    }
    operator bool()
    {
        return !pos.empty();
    }
    void operator++(int)
    {
        Node *last = pos.top();
        pos.pop();

        if (!pos.empty()) {
            /* no need to dynamic cast, as we just popped a node so the top node
             * must be an inner node */
            InnerNode *node = (InnerNode *)(pos.top());

            if (node->child[1] && node->child[1] != last) {
                push_left(node->child[1]);
	    }
	}
    }
};

ostream& operator<<(ostream& os, Node& node)
{
    node.dump(os);
    return os;
}

ostream& operator<<(ostream& os, uchar c)
{
    const char *search = "\a\033\f\n\r\t|*+[](). ",
	       *replace = "aefnrt|*+[](). ", *s;

    if ((s = strchr(search, c)) && *s != '\0')
	os << '\\' << replace[s - search];
    else if (c < 32 || c >= 127)
	os << '\\' << '0' << char('0' + (c >> 6))
	   << char('0' + ((c >> 3) & 7)) << char('0' + (c & 7));
    else
	os << (char)c;
    return os;
}

int
octdigit(char c)
{
    if (c >= '0' && c <= '7')
	return c - '0';
    return -1;
}

int
hexdigit(char c)
{
    if (c >= '0' && c <= '9')
	return c - '0';
    else if (c >= 'A' && c <= 'F')
	return 10 + c - 'A';
    else if (c >= 'a' && c <= 'f')
	return 10 + c - 'A';
    else
	return -1;
}

int
regexp_lex(YYSTYPE *val, const char **pos)
{
    int c;

    val->c = **pos;
    switch(*(*pos)++) {
	case '\0':
	    (*pos)--;
	    return 0;

	case '*': case '+': case '.': case '|': case '^': case '-':
	case '[': case ']': case '(' : case ')':
	    return *(*pos - 1);

	case '\\':
	    val->c = **pos;
	    switch(*(*pos)++) {
		case '\0':
		    (*pos)--;
		    /* fall through */
		case '\\':
		    val->c = '\\';
		    break;

		case '0':
		    val->c = 0;
		    if ((c = octdigit(**pos)) >= 0) {
			val->c = c;
			(*pos)++;
		    }
		    if ((c = octdigit(**pos)) >= 0) {
			val->c = (val->c << 3) + c;
			(*pos)++;
		    }
		    if ((c = octdigit(**pos)) >= 0) {
			val->c = (val->c << 3) + c;
			(*pos)++;
		    }
		    break;

		case 'x':
		    val->c = 0;
		    if ((c = hexdigit(**pos)) >= 0) {
			val->c = c;
			(*pos)++;
		    }
		    if ((c = hexdigit(**pos)) >= 0) {
			val->c = (val->c << 4) + c;
			(*pos)++;
		    }
		    break;

		case 'a':
		    val->c = '\a';
		    break;

		case 'e':
		    val->c = 033  /* ESC */;
		    break;

		case 'f':
		    val->c = '\f';
		    break;

		case 'n':
		    val->c = '\n';
		    break;

		case 'r':
		    val->c = '\r';
		    break;

		case 't':
		    val->c = '\t';
		    break;
	    }
    }
    return CHAR;
}

void
regexp_error(Node ** __attribute__((unused)),
	     const char *text __attribute__((unused)),
	     const char *error __attribute__((unused)))
{
    /* We don't want the library to print error messages. */
}

/**
 * Assign a consecutive number to each node. This is only needed for
 * pretty-printing the debug output.
 *
 * The epsnode is labeled 0.  Start labeling at 1
 */
void label_nodes(Node *root)
{
    int nodes = 1;
    for (depth_first_traversal i(root); i; i++)
       i->label = nodes++;
}

/**
 * Text-dump a state (for debugging).
 */
ostream& operator<<(ostream& os, const NodeSet& state)
{
    os << '{';
    if (!state.empty()) {
	NodeSet::iterator i = state.begin();
	for(;;) {
	   os << (*i)->label;
	    if (++i == state.end())
		break;
	    os << ',';
	}
    }
    os << '}';
    return os;
}

/**
 * Text-dump the syntax tree (for debugging).
 */
void dump_syntax_tree(ostream& os, Node *node) {
    for (depth_first_traversal i(node); i; i++) {
	os << i->label << '\t';
	if ((*i)->child[0] == 0)
	    os << **i << '\t' << (*i)->followpos << endl;
	else {
	    if ((*i)->child[1] == 0)
		os << (*i)->child[0]->label << **i;
	    else
		os << (*i)->child[0]->label << **i
		   << (*i)->child[1]->label;
	    os << '\t' << (*i)->firstpos
		       << (*i)->lastpos << endl;
	}
    }
    os << endl;
}

/* Comparison operator for sets of <NodeSet *>.
 * Compare set hashes, and if the sets have the same hash
 * do compare pointer comparison on set of <Node *>, the pointer comparison
 * allows us to determine which Sets of <Node *> we have seen already from
 * new ones when constructing the DFA.
 */
struct deref_less_than {
  bool operator()(pair <unsigned long, NodeSet *> const & lhs, pair <unsigned long, NodeSet *> const & rhs) const
  {
	  if (lhs.first == rhs.first)
		  return *(lhs.second) < *(rhs.second);
	  else
		  return lhs.first < rhs.first;
  }
};

unsigned long hash_NodeSet(const NodeSet *ns)
{
        unsigned long hash = 5381;

	for (NodeSet::iterator i = ns->begin(); i != ns->end(); i++) {
	  hash = ((hash << 5) + hash) + (unsigned long) *i;
	}

        return hash;
}

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
#include "regexp.h"

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
    th.th_magic = htonl(YYTH_REGEXP_MAGIC);
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

#include <sstream>
#include <ext/stdio_filebuf.h>

struct aare_ruleset {
    int reverse;
    Node *root;
};

extern "C" aare_ruleset_t *aare_new_ruleset(int reverse)
{
    aare_ruleset_t *container = (aare_ruleset_t *) malloc(sizeof(aare_ruleset_t));
    if (!container)
	return NULL;

    container->root = NULL;
    container->reverse = reverse;

    return container;
}

extern "C" void aare_delete_ruleset(aare_ruleset_t *rules)
{
    if (rules) {
	if (rules->root)
	    rules->root->release();
	free(rules);
    }
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

    return perms;
}

extern "C" int aare_add_rule(aare_ruleset_t *rules, char *rule, int deny,
			     uint32_t perms, uint32_t audit,  dfaflags_t flags)
{
	return aare_add_rule_vec(rules, deny, perms, audit, 1, &rule, flags);
}

#define FLAGS_WIDTH 2
#define MATCH_FLAGS_SIZE (sizeof(uint32_t) * 8 - 1)
MatchFlag *match_flags[FLAGS_WIDTH][MATCH_FLAGS_SIZE];
DenyMatchFlag *deny_flags[FLAGS_WIDTH][MATCH_FLAGS_SIZE];
#define EXEC_MATCH_FLAGS_SIZE (AA_EXEC_COUNT *2 * 2 * 2)	/* double for each of ix pux, unsafe x bits * u::o */
MatchFlag *exec_match_flags[FLAGS_WIDTH][EXEC_MATCH_FLAGS_SIZE];	/* mods + unsafe + ix + pux * u::o*/
ExactMatchFlag *exact_match_flags[FLAGS_WIDTH][EXEC_MATCH_FLAGS_SIZE];/* mods + unsafe + ix + pux *u::o*/

extern "C" void aare_reset_matchflags(void)
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
	RESET_FLAGS(match_flags,MATCH_FLAGS_SIZE);
	RESET_FLAGS(deny_flags,MATCH_FLAGS_SIZE);
	RESET_FLAGS(exec_match_flags,EXEC_MATCH_FLAGS_SIZE);
	RESET_FLAGS(exact_match_flags,EXEC_MATCH_FLAGS_SIZE);
#undef RESET_FLAGS
}

extern "C" int aare_add_rule_vec(aare_ruleset_t *rules, int deny,
				 uint32_t perms, uint32_t audit,
				 int count, char **rulev,
				 dfaflags_t flags)
{
    Node *tree = NULL, *accept;
    int exact_match;

    assert(perms != 0);

    if (regexp_parse(&tree, rulev[0]))
	return 0;
    for (int i = 1; i < count; i++) {
	    Node *subtree = NULL;
	    Node *node = new CharNode(0);
	    if (!node)
		return 0;
	    tree = new CatNode(tree, node);
	    if (regexp_parse(&subtree, rulev[i]))
		return 0;
	    tree = new CatNode(tree, subtree);
    }

    /*
     * Check if we have an expression with or without wildcards. This
     * determines how exec modifiers are merged in accept_perms() based
     * on how we split permission bitmasks here.
     */
    exact_match = 1;
    for (depth_first_traversal i(tree); i; i++) {
	if (dynamic_cast<StarNode *>(*i) ||
	    dynamic_cast<PlusNode *>(*i) ||
	    dynamic_cast<AnyCharNode *>(*i) ||
	    dynamic_cast<CharSetNode *>(*i) ||
	    dynamic_cast<NotCharSetNode *>(*i))
		exact_match = 0;
    }

    if (rules->reverse)
	flip_tree(tree);


/* 0x7f == 4 bits x mods + 1 bit unsafe mask + 1 bit ix, + 1 pux after shift */
#define EXTRACT_X_INDEX(perm, shift) (((perm) >> (shift + 7)) & 0x7f)

//if (perms & ALL_AA_EXEC_TYPE && (!perms & AA_EXEC_BITS))
//	fprintf(stderr, "adding X rule without MAY_EXEC: 0x%x %s\n", perms, rulev[0]);

//if (perms & ALL_EXEC_TYPE)
//    fprintf(stderr, "adding X rule %s 0x%x\n", rulev[0], perms);

//if (audit)
//fprintf(stderr, "adding rule with audit bits set: 0x%x %s\n", audit, rulev[0]);

//if (perms & AA_CHANGE_HAT)
//    fprintf(stderr, "adding change_hat rule %s\n", rulev[0]);

/* the permissions set is assumed to be non-empty if any audit
 * bits are specified */
    accept = NULL;
    for (unsigned int n = 0; perms && n < (sizeof(perms) * 8) ; n++) {
	uint32_t mask = 1 << n;

	if (perms & mask) {
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
			    deny_flags[ai][n] = new DenyMatchFlag(mask, audit&mask);
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
				    exact_match_flags[ai][index] = new ExactMatchFlag(eperm, audit&mask);
				    flag = exact_match_flags[ai][index];
			    }
		    } else {
			    if (exec_match_flags[ai][index]) {
				    flag = exec_match_flags[ai][index];
			    } else {
				    exec_match_flags[ai][index] = new MatchFlag(eperm, audit&mask);
				    flag = exec_match_flags[ai][index];
			    }
		    }
	    } else {
		    if (match_flags[ai][n]) {
		        flag = match_flags[ai][n];
		    } else {
			    match_flags[ai][n] = new MatchFlag(mask, audit&mask);
			    flag = match_flags[ai][n];
		    }
	    }
	    if (accept)
		    accept = new AltNode(accept, flag);
	    else
		    accept = flag;
	}
    }

    if (flags & DFA_DUMP_RULE_EXPR) {
	    cerr << "rule: ";
	    cerr << rulev[0];
	    for (int i = 1; i < count; i++) {
		    cerr << "\\x00";
		    cerr << rulev[i];
	    }
	    cerr << "  ->  ";
	    tree->dump(cerr);
	    cerr << "\n\n";
    }

    if (rules->root)
	rules->root = new AltNode(rules->root, new CatNode(tree, accept));
    else
	rules->root = new CatNode(tree, accept);

    return 1;

}

/* create a dfa from the ruleset
 * returns: buffer contain dfa tables, @size set to the size of the tables
 *          else NULL on failure
 */
extern "C" void *aare_create_dfa(aare_ruleset_t *rules, size_t *size, dfaflags_t flags)
{
    char *buffer = NULL;

    label_nodes(rules->root);
    if (flags & DFA_DUMP_TREE) {
	    cerr << "\nDFA: Expression Tree\n";
	    rules->root->dump(cerr);
	    cerr << "\n\n";
    }

    if (flags & DFA_CONTROL_TREE_SIMPLE) {
	    rules->root = simplify_tree(rules->root, flags);

	    if (flags & DFA_DUMP_SIMPLE_TREE) {
		    cerr << "\nDFA: Simplified Expression Tree\n";
		    rules->root->dump(cerr);
		    cerr << "\n\n";
	    }
    }

    stringstream stream;
    try {
	    DFA dfa(rules->root, flags);
	    if (flags & DFA_DUMP_UNIQ_PERMS)
		    dfa.dump_uniq_perms("dfa");

	    if (flags & DFA_CONTROL_MINIMIZE) {
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

	    TransitionTable transition_table(dfa, eq, flags);
	    if (flags & DFA_DUMP_TRANS_TABLE)
		    transition_table.dump(cerr);
	    transition_table.flex_table(stream, "");
    } catch (int error) {
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
