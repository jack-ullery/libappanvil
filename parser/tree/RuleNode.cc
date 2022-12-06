#include "RuleNode.h"
#include "tree/TreeNode.h"

RuleNode::RuleNode(uint64_t startPos, uint64_t stopPos)
  : TreeNode(),
    startPos{startPos},
    stopPos{stopPos}
{   }

RuleNode::RuleNode(const std::string &text, uint64_t startPos, uint64_t stopPos)
  : TreeNode(text),
    startPos{startPos},
    stopPos{stopPos}
{   }

uint64_t RuleNode::getStartPosition() const
{
  return startPos;
}

uint64_t RuleNode::getStopPosition() const
{
  return stopPos;
}
