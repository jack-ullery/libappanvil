#include <utility>

#include "ParseTree.hh"
#include "TreeNode.hh"

ParseTree::ParseTree(TreeNode preamble, std::shared_ptr<std::list<ProfileNode>> profileList)
  : preamble{std::move(preamble)}, 
    profileList{std::move(profileList)}
{   }
