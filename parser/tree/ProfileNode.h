#ifndef PROFILE_NODE_H
#define PROFILE_NODE_H

#include "TreeNode.h"
#include <string>

// The root node of the abstract syntax tree
class ProfileNode : public TreeNode {
  public:
    ProfileNode(const std::string &profile_name, TreeNode *rules);
};

#endif // PROFILE_NODE_H