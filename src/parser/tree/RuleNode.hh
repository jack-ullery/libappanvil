#ifndef RULE_NODE_HH
#define RULE_NODE_HH

#include "TreeNode.hh"
#include <cstdint>
#include <string>

// The root node of the abstract syntax tree
class RuleNode : public TreeNode {
  public:
    RuleNode(uint64_t startPos, uint64_t stopPos);
    RuleNode(const std::string &text, uint64_t startPos, uint64_t stopPos);

    uint64_t getStartPosition() const;
    uint64_t getStopPosition()  const;

  private:
    uint64_t startPos;
    uint64_t stopPos;
};

#endif // RULE_NODE_HH