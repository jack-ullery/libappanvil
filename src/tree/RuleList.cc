#include "AbstractionNode.hh"
#include "FileNode.hh"
#include "LinkNode.hh"
#include "PrefixNode.hh"
#include "ProfileNode.hh"
#include "TreeNode.hh"

#include <iostream>

using namespace AppArmor::Tree;

AppArmor::Tree::RuleList::RuleList(uint64_t startPos)
  : RuleNode(startPos, startPos)
{   }

void AppArmor::Tree::RuleList::appendFileNode(const PrefixNode &prefix, FileNode &node)
{
  node.setPrefix(prefix);
  files.push_back(node);
}

void AppArmor::Tree::RuleList::appendLinkNode(const PrefixNode &prefix, LinkNode &node)
{
  node.setPrefix(prefix);
  links.push_back(node);
}

void AppArmor::Tree::RuleList::appendRuleList(const PrefixNode &prefix, RuleList &node)
{
  node.setPrefix(prefix);
  rules.push_back(node);
}

void AppArmor::Tree::RuleList::appendAbstraction(AbstractionNode &node)
{
  abstractions.push_back(node);
}

void AppArmor::Tree::RuleList::appendSubprofile(ProfileNode &node)
{
  subprofiles.push_back(node);
}

/** Get methods **/
std::list<FileNode> AppArmor::Tree::RuleList::getFileList() const
{
  return files;
}

std::list<LinkNode> AppArmor::Tree::RuleList::getLinkList() const
{
  return links;
}

std::list<RuleList> AppArmor::Tree::RuleList::getRuleList() const
{
  return rules;
}

std::list<AbstractionNode> AppArmor::Tree::RuleList::getAbstractions() const
{
  return abstractions;
}

std::list<ProfileNode> AppArmor::Tree::RuleList::getSubprofiles() const
{
  return subprofiles;
}
