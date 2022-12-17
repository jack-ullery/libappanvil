#ifndef PROFILE_NODE_HH
#define PROFILE_NODE_HH

#include "TreeNode.hh"
#include <string>

// The root node of the abstract syntax tree
class ProfileNode : public TreeNode {
  public:
    ProfileNode(const std::string &profile_name, TreeNode rules);
};

#endif // PROFILE_NODE_HH