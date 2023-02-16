#include "RuleNode.hh"
#include "TreeNode.hh"

#include <cassert>
#include <cstdint>

#define assert_things assert(startPos <= stopPos) //NOLINT(cppcoreguidelines-pro-bounds-array-to-pointer-decay,hicpp-no-array-decay)

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

void RuleNode::setPrefix(const PrefixNode &prefix)
{
  assert_things;
  this->prefix = prefix;
}

void RuleNode::setStartPosition(const uint64_t &startPos)
{
  this->startPos = startPos;
}

void RuleNode::setStopPosition(const uint64_t &stopPos)
{
  this->stopPos = stopPos;
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
