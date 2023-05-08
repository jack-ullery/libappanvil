#include "AbstractionNode.hh"
#include "FileNode.hh"
#include "LinkNode.hh"
#include "PrefixNode.hh"
#include "ProfileNode.hh"
#include "TreeNode.hh"

#include <iostream>

RuleList::RuleList(uint64_t startPos)
  : RuleNode(startPos, startPos)
{   }

void RuleList::appendFileNode(const PrefixNode &prefix, FileNode &node)
{
  node.setPrefix(prefix);
  files.push_back(node);
}

void RuleList::appendLinkNode(const PrefixNode &prefix, LinkNode &node)
{
  node.setPrefix(prefix);
  links.push_back(node);
}

void RuleList::appendRuleList(const PrefixNode &prefix, RuleList &node)
{
  node.setPrefix(prefix);
  rules.push_back(node);
}

void RuleList::appendAbstraction(AbstractionNode &node)
{
  abstractions.push_back(node);
}

void RuleList::appendSubprofile(ProfileNode &node)
{
  subprofiles.push_back(node);
}

/** Get methods **/
std::list<FileNode> RuleList::getFileList() const
{
  return files;
}

std::list<LinkNode> RuleList::getLinkList() const
{
  return links;
}

std::list<RuleList> RuleList::getRuleList() const
{
  return rules;
}

std::list<AbstractionNode> RuleList::getAbstractionList() const
{
  return abstractions;
}

std::list<ProfileNode> RuleList::getSubprofiles() const
{
  return subprofiles;
}
