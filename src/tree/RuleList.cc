#include "AbstractionRule.hh"
#include "FileRule.hh"
#include "LinkRule.hh"
#include "PrefixNode.hh"
#include "ProfileRule.hh"
#include "TreeNode.hh"

#include <iostream>

using namespace AppArmor::Tree;

AppArmor::Tree::RuleList::RuleList(uint64_t startPos)
  : RuleNode(startPos, startPos)
{   }

void AppArmor::Tree::RuleList::appendFileRule(const PrefixNode &prefix, FileRule &node)
{
  node.setPrefix(prefix);
  files.push_back(node);
}

void AppArmor::Tree::RuleList::appendLinkRule(const PrefixNode &prefix, LinkRule &node)
{
  node.setPrefix(prefix);
  links.push_back(node);
}

void AppArmor::Tree::RuleList::appendRuleList(const PrefixNode &prefix, RuleList &node)
{
  node.setPrefix(prefix);
  rules.push_back(node);
}

void AppArmor::Tree::RuleList::appendAbstraction(AbstractionRule &node)
{
  abstractions.push_back(node);
}

void AppArmor::Tree::RuleList::appendSubprofile(ProfileRule &node)
{
  subprofiles.push_back(node);
}

/** Get methods **/
std::list<FileRule> AppArmor::Tree::RuleList::getFileList() const
{
  return files;
}

std::list<LinkRule> AppArmor::Tree::RuleList::getLinkList() const
{
  return links;
}

std::list<RuleList> AppArmor::Tree::RuleList::getRuleList() const
{
  return rules;
}

std::list<AbstractionRule> AppArmor::Tree::RuleList::getAbstractions() const
{
  return abstractions;
}

std::list<ProfileRule> AppArmor::Tree::RuleList::getSubprofiles() const
{
  return subprofiles;
}
