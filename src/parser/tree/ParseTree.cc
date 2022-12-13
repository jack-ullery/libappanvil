#include "ParseTree.hh"
#include "tree/TreeNode.hh"

ParseTree::ParseTree(TreeNode *preamble, TreeNode *profilelist)
  : TreeNode()
{
  this->appendChild(preamble);
  this->appendChild(profilelist);
}
