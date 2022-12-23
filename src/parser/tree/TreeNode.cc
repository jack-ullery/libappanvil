#include "TreeNode.hh"

#include <initializer_list>
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

TreeNode::TreeNode(std::initializer_list<TreeNode> children)
  : TreeNode()
{
  appendChildren(children);
}

void TreeNode::appendChildren(std::initializer_list<TreeNode> children)
{
  for(auto child : children) {
    appendChild(child);
  }
}

void TreeNode::appendChild(TreeNode child)
{
  children.push_back(child);
}
