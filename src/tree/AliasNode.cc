#include "AliasNode.hh"
#include "tree/TreeNode.hh"

#include <sstream>

AppArmor::Tree::AliasNode::AliasNode(const std::string &from, const std::string &to)
  : from{from},
    to{to}
{   }

AppArmor::Tree::AliasNode::operator std::string() const
{
  std::stringstream stream;
  stream << "alias " << from << " => " << to << ",\n";
  return stream.str();
};
