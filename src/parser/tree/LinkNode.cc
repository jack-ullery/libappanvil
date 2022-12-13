#include "LinkNode.hh"
#include "tree/RuleNode.hh"
#include "tree/TreeNode.hh"

#include <sstream>

LinkNode::LinkNode(uint64_t startPos, uint64_t stopPos, bool isSubset, const std::string &from, const std::string &to)
  : RuleNode("link", startPos, stopPos),
    isSubset{isSubset},
    from{from},
    to{to}
{   }

LinkNode::operator std::string() const
{
  std::stringstream stream;
  stream << "(" << getStartPosition() << ", " << getStopPosition() << "): ";
  stream << "link " << (isSubset? "subset " : "") << from << " -> " << to << "," << std::endl;;
  return stream.str();
};
