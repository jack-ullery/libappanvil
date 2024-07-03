#include <utility>

#include "ParseTree.hh"
#include "TreeNode.hh"

AppArmor::Tree::ParseTree::ParseTree(TreeNode preamble, std::shared_ptr<std::list<ProfileRule>> profileList)
  : preamble{std::move(preamble)}, 
    profileList{std::move(profileList)}
{   }
