#ifndef PROFILE_NODE_HH
#define PROFILE_NODE_HH

#include "TreeNode.hh"
#include <string>

class ProfileNode : public TreeNode {
  public:
    ProfileNode(const std::string &profile_name, TreeNode rules);
    ProfileNode() = default;
};

#endif // PROFILE_NODE_HH