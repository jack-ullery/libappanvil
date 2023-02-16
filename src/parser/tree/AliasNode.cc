#include "AliasNode.hh"
#include "tree/TreeNode.hh"

#include <sstream>

AliasNode::AliasNode(const std::string &from, const std::string &to)
  : from{from},
    to{to}
{   }

AliasNode::operator std::string() const
{
  std::stringstream stream;
  stream << "alias " << from << " => " << to << ",\n";
  return stream.str();
};
