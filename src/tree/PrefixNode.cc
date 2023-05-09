#include "PrefixNode.hh"
#include "tree/TreeNode.hh"

AppArmor::Tree::PrefixNode::PrefixNode(bool audit, bool should_deny, bool owner)
  : audit{audit},
    should_deny{should_deny},
    owner{owner}
{   }

bool AppArmor::Tree::PrefixNode::operator==(const PrefixNode &other) const
{
  return this->audit == other.audit &&
         this->should_deny == other.should_deny &&
         this->owner == other.owner;
}
