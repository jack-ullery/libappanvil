#include "ParseTree.h"
#include "tree/TreeNode.h"

ParseTree::ParseTree(TreeNode &preamble, TreeNode &profilelist)
  : TreeNode("hi")
{
  this->appendChild(preamble);
  this->appendChild(profilelist);
}
