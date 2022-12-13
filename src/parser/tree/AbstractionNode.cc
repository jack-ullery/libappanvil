#include "AbstractionNode.hh"

#include <sstream>

AbstractionNode::AbstractionNode(uint64_t startPos, uint64_t stopPos, const std::string &path, bool is_if_exists)
  : RuleNode("abstraction", startPos, stopPos),
    path{path},
    is_if_exists{is_if_exists}
{   }

AbstractionNode::operator std::string() const
{
  std::stringstream stream;
  stream << "include (" << getStartPosition() << ", " << getStopPosition() << ") " << path << ",\n";
  return stream.str();
};
