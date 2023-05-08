#include "ProfileNode.hh"
#include "tree/TreeNode.hh"

AppArmor::Tree::ProfileNode::ProfileNode(const std::string &profile_name, const RuleList &rules)
  : TreeNode(profile_name),
    rules{rules}
{   }

std::string AppArmor::Tree::ProfileNode::name() const
{
  return this->getText();
}

AppArmor::Tree::RuleList AppArmor::Tree::ProfileNode::getRules() const
{
  return rules;
}
