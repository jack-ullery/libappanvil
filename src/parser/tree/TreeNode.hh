#ifndef TREE_NODE_HH
#define TREE_NODE_HH

#include <cstdarg>
#include <list>
#include <memory>
#include <string>

class TreeNode {
  public:
    // Constructors
    TreeNode() = default;
    TreeNode(const std::string &text);
    TreeNode(std::initializer_list<TreeNode> children);

    // Copy constructor
    TreeNode(const TreeNode &children);

    // Append node into the internal list of children
    void appendChild(TreeNode child);

    std::string getText() const;

    // Copy/Move assignment operator
    TreeNode& operator=(const TreeNode &) = default;
    TreeNode& operator=(TreeNode &&) = default;

  protected:
    std::string text;
    std::list<TreeNode> children;

    void appendChildren(std::initializer_list<TreeNode> children);
};

#endif // TREE_NODE_HH