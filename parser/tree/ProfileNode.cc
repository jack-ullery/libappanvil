#include "ProfileNode.h"
#include "tree/TreeNode.h"

ProfileNode::ProfileNode(const std::string &profile_name, TreeNode *rules)
  : TreeNode(profile_name)
{
  this->appendChild(rules);
}
