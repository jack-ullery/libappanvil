#ifndef ALIAS_NODE_H
#define ALIAS_NODE_H

#include "TreeNode.h"
#include <string>

// The root node of the abstract syntax tree
class AliasNode : public TreeNode {
  public:
    AliasNode(const std::string &from, const std::string &to);

  private:
    virtual operator std::string() const;
    std::string from;
    std::string to;
};

#endif // ALIAS_NODE_H