#include "PrefixNode.hh"
#include "tree/TreeNode.hh"

#include <sstream>

AppArmor::Tree::PrefixNode::PrefixNode(bool audit, bool should_deny, bool owner)
  : audit{audit},
    should_deny{should_deny},
    owner{owner}
{   }

bool AppArmor::Tree::PrefixNode::getAudit() const
{
  return audit;
}

bool AppArmor::Tree::PrefixNode::getShouldDeny() const
{
  return should_deny;
}

bool AppArmor::Tree::PrefixNode::getOwner() const
{
  return owner;
}

bool AppArmor::Tree::PrefixNode::operator==(const PrefixNode &other) const
{
  return this->audit == other.audit &&
         this->should_deny == other.should_deny &&
         this->owner == other.owner;
}

AppArmor::Tree::PrefixNode::operator std::string() const
{
  std::stringstream ss;

  if(audit) {
    ss << "audit ";
  }

  if(should_deny) {
    ss << "deny ";
  }

  if(owner) {
    ss << "owner ";
  }

  return ss.str();
}
