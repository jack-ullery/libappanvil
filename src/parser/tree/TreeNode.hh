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
    TreeNode(std::initializer_list<TreeNode*> children);

    // Copy constructor
    TreeNode(const TreeNode &children);

    // Append nodes into the internal list of children
    void appendChildren(std::initializer_list<TreeNode*> children);
    void appendChild(TreeNode *child);

    // Operator to recursively convert Tree to string
    virtual operator std::string() const;

  protected:
    const std::string text;
    std::list<std::shared_ptr<TreeNode>> children;
};

#endif // TREE_NODE_HH