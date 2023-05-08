#include "TreeNode.hh"

#include <initializer_list>
#include <memory>
#include <sstream>
#include <string>

AppArmor::Tree::TreeNode::TreeNode(const std::string &text)
  : text{text}
{   }

AppArmor::Tree::TreeNode::TreeNode(std::initializer_list<TreeNode> children)
  : TreeNode()
{
  appendChildren(children);
}

void AppArmor::Tree::TreeNode::appendChildren(std::initializer_list<TreeNode> children)
{
  for(const auto &child : children) {
    appendChild(child);
  }
}

void AppArmor::Tree::TreeNode::appendChild(const TreeNode &child)
{
  children.push_back(child);
}

std::string AppArmor::Tree::TreeNode::getText() const
{
  return text;
}
