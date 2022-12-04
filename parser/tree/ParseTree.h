#ifndef PARSE_TREE_H
#define PARSE_TREE_H

#include "TreeNode.h"

// The root node of the abstract syntax tree
class ParseTree : public TreeNode {
  public:
    ParseTree(TreeNode *preamble, TreeNode *profilelist);
};

#endif // PARSE_TREE_H