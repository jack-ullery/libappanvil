#include "AbstractionRule.hh"

#include <sstream>

AppArmor::Tree::AbstractionRule::AbstractionRule(uint64_t startPos, uint64_t stopPos, const std::string &path, bool is_if_exists)
  : RuleNode("abstraction", startPos, stopPos),
    path{path},
    is_if_exists{is_if_exists}
{   }

AppArmor::Tree::AbstractionRule::operator std::string() const
{
  std::stringstream stream;
  stream << "include (" << getStartPosition() << ", " << getEndPosition() << ") " << path << ",\n";
  return stream.str();
};

std::string AppArmor::Tree::AbstractionRule::getPath() const
{
  return path;
}
bool AppArmor::Tree::AbstractionRule::operator==(const AbstractionRule &other) const
{
  return this->path == other.path &&
         this->is_if_exists == other.is_if_exists &&
         ((RuleNode) *this) == ((RuleNode) other);
}

bool AppArmor::Tree::AbstractionRule::operator==(const std::string &path) const
{
  return this->path == path;
}
