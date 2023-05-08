#include "PrefixNode.hh"
#include "tree/TreeNode.hh"

AppArmor::Tree::PrefixNode::PrefixNode(bool audit, bool should_deny, bool owner)
  : audit{audit},
    should_deny{should_deny},
    owner{owner}
{   }
