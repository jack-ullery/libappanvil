#ifndef PROFILE_NODE_HH
#define PROFILE_NODE_HH

#include "RuleList.hh"
#include "TreeNode.hh"

#include <string>

class ProfileNode : public TreeNode {
  public:
    ProfileNode(const std::string &profile_name, const RuleList &rules);
    ProfileNode() = default;

    RuleList getRules();

  protected:
    RuleList rules;
};

#endif // PROFILE_NODE_HH