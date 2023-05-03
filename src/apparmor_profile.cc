#include "apparmor_profile.hh"
#include "apparmor_file_rule.hh"
#include "parser/tree/AbstractionNode.hh"
#include "parser/tree/FileNode.hh"
#include "parser/tree/ProfileNode.hh"

#include <iostream>
#include <sstream>
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

uint64_t AppArmor::Profile::getRuleStartPosition() const
{
  return profile_model->getRules().getStartPosition();
}

uint64_t AppArmor::Profile::getRuleEndPosition() const
{
  return profile_model->getRules().getStopPosition();  
}

bool AppArmor::Profile::operator==(const Profile& that) const
{
  return this->profile_model == that.profile_model;
}

bool AppArmor::Profile::operator!=(const Profile& that) const
{
  return this->profile_model != that.profile_model;
}

void AppArmor::Profile::checkFileRuleValid(AppArmor::FileRule &file_rule) const
{
    const auto &rules = profile_model->getRules();
    const auto &file_rules = rules.getFileList();

    // Attempt to find profile from the list and return on success
    for(const auto &node : file_rules) {
        if(file_rule == node) {
            return;
        }
    }

    // Profile was not found so throw an exception
    std::stringstream message;
    message << "Invalid AppArmor::FileRule \"" << file_rule.getFilename() << "\" was given as argument. This rule could not be found in Profile: " << this->name() << ".\n";
    throw std::domain_error(message.str());
}
