#ifndef PARSE_TREE_HH
#define PARSE_TREE_HH

#include "TreeNode.hh"

// The root node of the abstract syntax tree
class ParseTree : public TreeNode {
  public:
    ParseTree(TreeNode preamble, TreeNode profilelist);
};

#endif // PARSE_TREE_HH