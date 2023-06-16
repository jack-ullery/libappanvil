#include "RuleNode.hh"
#include "TreeNode.hh"

#include <cassert>
#include <cstdint>

#define assert_things assert(startPos <= stopPos) //NOLINT(cppcoreguidelines-pro-bounds-array-to-pointer-decay,hicpp-no-array-decay)

// Used by Bison to create as a default value
// Objects using this constructor should be overwritten, not used! 
AppArmor::Tree::RuleNode::RuleNode()
  : TreeNode("invalid"),
    startPos{UINT64_MAX},
    stopPos{0}
{   }

AppArmor::Tree::RuleNode::RuleNode(uint64_t startPos, uint64_t stopPos)
  : TreeNode("rule"),
    startPos{startPos},
    stopPos{stopPos}
{
  assert_things;
}

AppArmor::Tree::RuleNode::RuleNode(const std::string &text, uint64_t startPos, uint64_t stopPos)
  : TreeNode(text),
    startPos{startPos},
    stopPos{stopPos}
{
  assert_things;
}

void AppArmor::Tree::RuleNode::setPrefix(const PrefixNode &prefix)
{
  assert_things;
  this->prefix = prefix;
}

void AppArmor::Tree::RuleNode::setStartPosition(const uint64_t &startPos)
{
  this->startPos = startPos;
}

void AppArmor::Tree::RuleNode::setStopPosition(const uint64_t &stopPos)
{
  this->stopPos = stopPos;
}

uint64_t AppArmor::Tree::RuleNode::getStartPosition() const
{
  assert_things;
  return startPos;
}

uint64_t AppArmor::Tree::RuleNode::getEndPosition() const
{
  assert_things;
  return stopPos;
}

bool AppArmor::Tree::RuleNode::operator==(const RuleNode &other) const
{
  return this->prefix == other.prefix &&
         this->startPos == other.startPos &&
         this->stopPos == other.stopPos;
}

bool AppArmor::Tree::RuleNode::operator!=(const RuleNode &other) const
{
  return !(*this == other);
}

AppArmor::Tree::PrefixNode AppArmor::Tree::RuleNode::getPrefix() const
{
  return prefix;
}
