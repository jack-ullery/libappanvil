#include "RuleList.hh"
#include "tree/RuleNode.hh"

#include <iostream>

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

/** Append methods **/
template <typename T, typename = typename std::enable_if<std::is_base_of<RuleNode, T>::value, T>::type>
inline void appendPrefixedNode(const PrefixNode &prefix, T &node, std::list<T> list)
{
  node.setPrefix(prefix);
  list.push_back(node);
}

void RuleList::appendFileNode(const PrefixNode &prefix, FileNode &node)
{
  appendPrefixedNode(prefix, node, files);
}

void RuleList::appendLinkNode(const PrefixNode &prefix, LinkNode &node)
{
  appendPrefixedNode(prefix, node, links);
}

void RuleList::appendRuleList(const PrefixNode &prefix, RuleList &node)
{
  appendPrefixedNode(prefix, node, rules);
}

void RuleList::appendAbstraction(AbstractionNode &node)
{
  abstractions.push_back(node);
}

/** Get methods **/
std::list<FileNode> RuleList::getFileList()
{
  return files;
}

std::list<LinkNode> RuleList::getLinkList()
{
  return links;
}

std::list<RuleList> RuleList::getRuleList()
{
  return rules;
}

std::list<AbstractionNode> RuleList::getAbstractionList()
{
  return abstractions;
}
