#include "RuleNode.hh"
#include "TreeNode.hh"

#include <assert.h>
#include <cstdint>

#define assert_things assert(startPos <= stopPos)

// Used by Bison to create as a default value
// Objects using this constructor should be overwritten, not used! 
RuleNode::RuleNode()
  : TreeNode("invalid"),
    startPos{UINT64_MAX},
    stopPos{0}
{   }

RuleNode::RuleNode(uint64_t startPos, uint64_t stopPos)
  : TreeNode("rule"),
    startPos{startPos},
    stopPos{stopPos}
{
  assert_things;
}

RuleNode::RuleNode(const std::string &text, uint64_t startPos, uint64_t stopPos)
  : TreeNode(text),
    startPos{startPos},
    stopPos{stopPos}
{
  assert_things;
}

void RuleNode::setPrefix(PrefixNode &prefix)
{
  assert_things;
  this->prefix = prefix;
}

uint64_t RuleNode::getStartPosition() const
{
  assert_things;
  return startPos;
}

uint64_t RuleNode::getStopPosition() const
{
  assert_things;
  return stopPos;
}
