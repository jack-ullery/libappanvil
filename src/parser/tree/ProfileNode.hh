#ifndef PROFILE_NODE_HH
#define PROFILE_NODE_HH

#include "RuleList.hh"
#include "TreeNode.hh"

#include <string>

class ProfileNode : public TreeNode {
  public:
    ProfileNode(const std::string &profile_name, const RuleList<ProfileNode> &rules);
    ProfileNode() = default;

    RuleList<ProfileNode> getRules();

  private:
    RuleList<ProfileNode> rules;
};

#endif // PROFILE_NODE_HH