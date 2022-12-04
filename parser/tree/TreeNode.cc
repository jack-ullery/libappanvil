#include "TreeNode.h"

#include <memory>
#include <sstream>
#include <string>

TreeNode::TreeNode(const std::string &text)
  : text{text}
{   }

TreeNode::TreeNode(const TreeNode &node)
  : text{node.text},
    children{node.children}
{   }

// void TreeNode::appendChildren(std::list<TreeNode> &nextChildren)
// {
//     children.splice(children.end(), nextChildren);
// }

void TreeNode::appendChild(TreeNode *child)
{
  if(child != nullptr) {
    std::shared_ptr<TreeNode> shared_child{child};
    children.push_back(shared_child);
  }
}

TreeNode::operator std::string() const
{
  std::stringstream stream;
  if(text != "") {
    stream << text << std::endl;
  }

  for(auto child : children)
  {
    // Use this operator on all the children
    stream << std::string(*child);
  }

  return stream.str();
};
