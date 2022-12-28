#include "ProfileNode.hh"
#include "tree/TreeNode.hh"

ProfileNode::ProfileNode(const std::string &profile_name, const RuleList<ProfileNode> &rules)
  : TreeNode(profile_name),
    rules{rules}
{   }

RuleList<ProfileNode> ProfileNode::getRules()
{
  return rules;
}
