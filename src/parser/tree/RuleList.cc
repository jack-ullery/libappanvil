#include "RuleList.hh"
#include "tree/RuleNode.hh"

RuleList::RuleList(uint64_t startPos)
  : RuleNode(startPos, startPos)
{   }

void RuleList::setStartPosition(uint64_t startPos)
{
  this->startPos = startPos;
}

void RuleList::setStopPosition(uint64_t stopPos)
{
  this->stopPos = stopPos;
}
