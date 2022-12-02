#ifndef TREE_NODE_H
#define TREE_NODE_H

#include <list>
#include <string>

class TreeNode {
  public:
    // Constructors
    TreeNode() = default;
    TreeNode(const std::string &text);
    TreeNode(const std::string &text, std::list<TreeNode> &children);

    // Copy constructor
    TreeNode(const TreeNode &children);

    // Append all nodes into the internal list of children
    void appendChildren(std::list<TreeNode> &nextChildren);
    void appendChild(const TreeNode &child);

    // Operator to recursively convert Tree to string
    virtual operator std::string() const;

  protected:
    const std::string text;
    std::list<TreeNode> children;
};

#endif // TREE_NODE_H