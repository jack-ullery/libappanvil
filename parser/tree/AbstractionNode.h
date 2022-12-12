#ifndef ABSTRACTION_NODE_H
#define ABSTRACTION_NODE_H

#include "RuleNode.h"
#include <string>

// The root node of the abstract syntax tree
class AbstractionNode : public RuleNode {
  public:
    AbstractionNode(uint64_t startPos, uint64_t stopPos, const std::string &path, bool is_if_exists = false);

  private:
    virtual operator std::string() const;

    std::string path;
    bool is_if_exists;
};

#endif // ABSTRACTION_NODE_H