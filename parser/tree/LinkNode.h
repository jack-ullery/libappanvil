#ifndef LINK_NODE_H
#define LINK_NODE_H

#include "RuleNode.h"
#include <string>

// The root node of the abstract syntax tree
class LinkNode : public RuleNode {
  public:
    LinkNode(uint64_t startPos, uint64_t stopPos, bool isSubset, const std::string &linkFrom, const std::string &linkTo);

  private:
    virtual operator std::string() const;
    bool isSubset;
    std::string from;
    std::string to;
};

#endif // LINK_NODE_H