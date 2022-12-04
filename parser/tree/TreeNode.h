#ifndef TREE_NODE_H
#define TREE_NODE_H

#include <list>
#include <memory>
#include <string>

class TreeNode {
  public:
    // Constructors
    TreeNode() = default;
    TreeNode(const std::string &text);

    // Copy constructor
    TreeNode(const TreeNode &children);

    // Append all nodes into the internal list of children
    // void appendChildren(std::list<TreeNode> &nextChildren);
    void appendChild(TreeNode *child);

    // Operator to recursively convert Tree to string
    virtual operator std::string() const;

  protected:
    const std::string text;
    std::list<std::shared_ptr<TreeNode>> children;
};

#endif // TREE_NODE_H