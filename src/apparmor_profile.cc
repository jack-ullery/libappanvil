#include "apparmor_profile.hh"
#include "parser/tree/AbstractionNode.hh"
#include "parser/tree/FileNode.hh"
#include "parser/tree/ProfileNode.hh"

#include <iostream>
#include <utility>

AppArmor::Profile::Profile(std::shared_ptr<ProfileNode> profile_model)
  : profile_model{std::move(profile_model)}
{   }

std::string AppArmor::Profile::name() const
{
    return profile_model->getText();
}

std::unordered_set<std::string> AppArmor::Profile::getAbstractions() const
{
  std::unordered_set<std::string> set;

  auto ruleList = profile_model->getRules();
  auto abstractionList = ruleList.getAbstractionList();

  for(AbstractionNode node : abstractionList) {
    set.insert(node.getPath());
  }

  return set;
}

// Returns a list of file rules included in the profile
std::list<AppArmor::FileRule> AppArmor::Profile::getFileRules() const
{
  std::list<AppArmor::FileRule> set;

  auto ruleList = profile_model->getRules();
  auto fileRuleList = ruleList.getFileList();

  for(FileNode node : fileRuleList) {
    auto ptr = std::make_shared<FileNode>(node);
    set.emplace_back(ptr);
  }

  return set;
}