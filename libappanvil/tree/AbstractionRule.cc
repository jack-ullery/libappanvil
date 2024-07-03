#include "AbstractionRule.hh"

#include <sstream>

AppArmor::Tree::AbstractionRule::AbstractionRule(uint64_t startPos, uint64_t stopPos, const std::string &path, bool is_relative, bool is_if_exists)
  : RuleNode("abstraction", startPos, stopPos),
    path{path},
    is_relative{is_relative},
    is_if_exists{is_if_exists}
{   }

AppArmor::Tree::AbstractionRule::AbstractionRule(const std::string &path, bool is_relative, bool is_if_exists)
  : AbstractionRule(0, -1, path, is_relative, is_if_exists)
{   }

std::string AppArmor::Tree::AbstractionRule::getPath() const
{
  return path;
}

bool AppArmor::Tree::AbstractionRule::isRelative() const
{
  return is_relative;
}

bool AppArmor::Tree::AbstractionRule::isIfExists() const
{
  return is_if_exists;
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

AppArmor::Tree::AbstractionRule::operator std::string() const
{
  std::stringstream stream;
  stream << "#include ";

  if(is_if_exists) {
    stream << "if exists ";
  }

  if(is_relative) {
    stream << "<" << path << ">";
  }
  else {
    stream << "\"" << path << "\"";
  }

  return stream.str();
};
