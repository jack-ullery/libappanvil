#ifndef LINK_NODE_HH
#define LINK_NODE_HH

#include "RuleNode.hh"
#include <string>

class LinkNode : public RuleNode {
  public:
    LinkNode() = default;
    LinkNode(uint64_t startPos, uint64_t stopPos, bool isSubset, const std::string &linkFrom, const std::string &linkTo);

    virtual explicit operator std::string() const;

  private:
    bool isSubset = false;
    std::string from;
    std::string to;
};

#endif // LINK_NODE_HH