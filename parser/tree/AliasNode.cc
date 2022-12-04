#include "AliasNode.h"
#include "tree/TreeNode.h"

#include <sstream>

AliasNode::AliasNode(const std::string &from, const std::string &to)
  : TreeNode(),
    from{from},
    to{to}
{   }

AliasNode::operator std::string() const
{
  std::stringstream stream;
  stream << "alias " << from << " => " << to << ",\n";
  return stream.str();
};
