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
  stream << "include (" << getStartPosition() << ", " << getStopPosition() << ") " << path << ",\n";
  return stream.str();
};

std::string AppArmor::Tree::AbstractionNode::getPath() const
{
  return path;
}