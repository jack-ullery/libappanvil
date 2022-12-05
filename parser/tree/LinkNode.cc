#include "LinkNode.h"
#include "tree/TreeNode.h"

#include <sstream>

LinkNode::LinkNode(bool isSubset, const std::string &from, const std::string &to)
  : TreeNode("link"),
    isSubset{isSubset},
    from{from},
    to{to}
{   }

LinkNode::operator std::string() const
{
  std::stringstream stream;
  stream << "link " << (isSubset? "subset " : "") << from << " -> " << to << ",\n";
  return stream.str();
};
