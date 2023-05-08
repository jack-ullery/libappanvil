#ifndef PROFILE_NODE_HH
#define PROFILE_NODE_HH

#include "RuleList.hh"
#include "TreeNode.hh"

#include <string>

namespace AppArmor::Tree {
  class ProfileNode : protected TreeNode {
    public:
      ProfileNode(const std::string &profile_name, const RuleList &rules);
      ProfileNode() = default;

      std::string name() const;
      RuleList getRules() const;

    private:
      RuleList rules;
  };
} // namespace AppArmor::Tree

#endif // PROFILE_NODE_HH