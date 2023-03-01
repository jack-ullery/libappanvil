#ifndef TREE_NODE_HH
#define TREE_NODE_HH

#include <cstdarg>
#include <list>
#include <memory>
#include <string>

class TreeNode {
  public:
    // Constructors
    explicit TreeNode(const std::string &text);
    TreeNode(std::initializer_list<TreeNode> children);

    // Default constructors and destructor
    TreeNode() = default;
    virtual ~TreeNode() = default;

    // Append node into the internal list of children
    void appendChild(const TreeNode &child);

    std::string getText() const;

    // Copy/Move assignment operator
    TreeNode& operator=(const TreeNode &) = default;
    TreeNode& operator=(TreeNode &&) = default;

    // Delete move and copy constructor
    TreeNode(const TreeNode &children) = default;
    TreeNode(TreeNode &&) = default;

  private:
    std::string text;
    std::list<TreeNode> children;

    void appendChildren(std::initializer_list<TreeNode> children);
};

#endif // TREE_NODE_HH