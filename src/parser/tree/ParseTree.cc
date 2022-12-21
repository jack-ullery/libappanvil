#include "ParseTree.hh"
#include "TreeNode.hh"

ParseTree::ParseTree(TreeNode preamble, std::shared_ptr<std::list<ProfileNode>> profileList)
  : preamble{preamble}, 
    profileList{profileList}
{   }
