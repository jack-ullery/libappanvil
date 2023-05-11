#ifndef LINK_RULE_HH
#define LINK_RULE_HH

#include "RuleNode.hh"
#include <string>

namespace AppArmor::Tree {
  class LinkRule : public RuleNode {
    public:
      LinkRule() = default;
      LinkRule(uint64_t startPos, uint64_t stopPos, bool isSubset, const std::string &linkFrom, const std::string &linkTo);

      virtual explicit operator std::string() const;

    private:
      bool isSubset = false;
      std::string from;
      std::string to;
  };
} // namespace AppArmor::Tree

#endif // LINK_RULE_HH