#include "AllRule.hh"
#include "tree/RuleNode.hh"

#include <sstream>
#include <stdexcept>

AppArmor::Tree::AllRule::AllRule(const PrefixNode &prefix, uint64_t startPos, uint64_t stopPos)
  : RuleNode(startPos, stopPos)
{
  if(prefix.getOwner())
  {
    throw std::runtime_error("owner prefix not allowed on capability rules");
  }

  this->setPrefix(prefix);
}

AppArmor::Tree::AllRule::operator std::string() const
{
  std::stringstream stream;
  stream << getPrefix().operator std::string() << " all,\n";
  return stream.str();
};
