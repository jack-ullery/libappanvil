#include "AbstractionNode.h"

#include <sstream>

AbstractionNode::AbstractionNode(const std::string &path, bool is_if_exists)
  : TreeNode("abstraction"),
    path{path},
    is_if_exists{is_if_exists}
{   }

AbstractionNode::operator std::string() const
{
  std::stringstream stream;
  stream << "include " << path << ",\n";
  return stream.str();
};
