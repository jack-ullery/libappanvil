#include "ProfileNode.hh"
#include "tree/TreeNode.hh"

ProfileNode::ProfileNode(const std::string &profile_name, const RuleList &rules)
  : TreeNode(profile_name),
    rules{rules}
{   }

RuleList ProfileNode::getRules()
{
  return rules;
}
