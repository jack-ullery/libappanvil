#include "AbstractionNode.hh"

#include <sstream>

AppArmor::Tree::AbstractionNode::AbstractionNode(uint64_t startPos, uint64_t stopPos, const std::string &path, bool is_if_exists)
  : RuleNode("abstraction", startPos, stopPos),
    path{path},
    is_if_exists{is_if_exists}
{   }

AppArmor::Tree::AbstractionNode::operator std::string() const
{
  std::stringstream stream;
  stream << "include (" << getStartPosition() << ", " << getEndPosition() << ") " << path << ",\n";
  return stream.str();
};

std::string AppArmor::Tree::AbstractionNode::getPath() const
{
  return path;
}
bool AppArmor::Tree::AbstractionNode::operator==(const AbstractionNode &other) const
{
  return this->path == other.path &&
         this->is_if_exists == other.is_if_exists &&
         ((RuleNode) *this) == ((RuleNode) other);
}

bool AppArmor::Tree::AbstractionNode::operator==(const std::string &path) const
{
  return this->path == path;
}
