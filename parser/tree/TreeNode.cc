#include "TreeNode.h"

#include <sstream>
#include <string>

TreeNode::TreeNode(const std::string &text)
  : text{text}
{   }

TreeNode::TreeNode(const std::string &text, std::list<TreeNode> &children)
  : text{text},
    children{children}
{   }

TreeNode::TreeNode(const TreeNode &node)
  : text{node.text},
    children{node.children}
{   }

void TreeNode::appendChildren(std::list<TreeNode> &nextChildren)
{
    children.splice(children.end(), nextChildren);
}

void TreeNode::appendChild(const TreeNode &child)
{
    children.push_back(child);
}

TreeNode::operator std::string() const
{
    std::stringstream stream(text);

    for(auto child : children)
    {
        // stream << child.to_string();
    }

    return stream.str();
};
