#ifndef ALL_NODE_HH
#define ALL_NODE_HH

#include <string>

#include "RuleNode.hh"

namespace AppArmor::Tree {
class AllRule : public RuleNode
{
public:
  AllRule() = default;
  AllRule(const PrefixNode &prefix, uint64_t startPos, uint64_t stopPos);

  virtual explicit operator std::string() const;
};
} // namespace AppArmor::Tree

#endif // ALL_NODE_HH