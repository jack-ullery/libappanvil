#include "TreeNode.hh"

#include <initializer_list>
#include <memory>
#include <sstream>
#include <string>

TreeNode::TreeNode(const std::string &text)
  : text{text}
{   }

TreeNode::TreeNode(std::initializer_list<TreeNode> children)
  : TreeNode()
{
  appendChildren(children);
}

void TreeNode::appendChildren(std::initializer_list<TreeNode> children)
{
  for(const auto &child : children) {
    appendChild(child);
  }
}

void TreeNode::appendChild(const TreeNode &child)
{
  children.push_back(child);
}

std::string TreeNode::getText() const
{
  return text;
}
