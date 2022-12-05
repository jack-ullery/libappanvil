#ifndef LINK_NODE_H
#define LINK_NODE_H

#include "TreeNode.h"
#include <string>

// The root node of the abstract syntax tree
class LinkNode : public TreeNode {
  public:
    LinkNode(bool isSubset, const std::string &from, const std::string &to);

  private:
    virtual operator std::string() const;
    bool isSubset;
    std::string from;
    std::string to;
};

#endif // LINK_NODE_H