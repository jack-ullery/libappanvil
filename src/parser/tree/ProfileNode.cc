#include "ProfileNode.hh"
#include "tree/TreeNode.hh"

ProfileNode::ProfileNode(const std::string &profile_name, TreeNode *rules)
  : TreeNode(profile_name)
{
  this->appendChild(rules);
}
