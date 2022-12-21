#ifndef RULE_LIST_HH
#define RULE_LIST_HH

#include "TreeNode.hh"
#include "RuleNode.hh"

#include <cstdint>
#include <string>

class RuleList : public RuleNode {
  public:
    RuleList() = default;
    RuleList(uint64_t startPos);

    void setStartPosition(uint64_t start_pos);
    void setStopPosition(uint64_t stop_pos);
};

#endif // RULE_LIST_HH