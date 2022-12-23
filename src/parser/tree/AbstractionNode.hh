#ifndef ABSTRACTION_NODE_HH
#define ABSTRACTION_NODE_HH

#include "RuleNode.hh"
#include <string>

class AbstractionNode : public RuleNode {
  public:
    AbstractionNode() = default;
    AbstractionNode(uint64_t startPos, uint64_t stopPos, const std::string &path, bool is_if_exists = false);

    std::string getPath();

  private:
    virtual operator std::string() const;

    std::string path;
    bool is_if_exists;
};

#endif // ABSTRACTION_NODE_HH