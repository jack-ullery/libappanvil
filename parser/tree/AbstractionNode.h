#ifndef ABSTRACTION_NODE_H
#define ABSTRACTION_NODE_H

#include "TreeNode.h"
#include <string>

// The root node of the abstract syntax tree
class AbstractionNode : public TreeNode {
  public:
    AbstractionNode(const std::string &path, bool is_if_exists = false);

  private:
    virtual operator std::string() const;

    std::string path;
    bool is_if_exists;
};

#endif // ABSTRACTION_NODE_H