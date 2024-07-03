#include "ProfileRule.hh"
#include "tree/TreeNode.hh"
#include <cstddef>
#include <sstream>

// NOLINTNEXTLINE(google-build-using-namespace)
using namespace AppArmor::Tree;

AppArmor::Tree::ProfileRule::ProfileRule(const std::string &profile_name, const RuleList &rules)
  : TreeNode(profile_name),
    rules{rules}
{   }

std::string AppArmor::Tree::ProfileRule::name() const
{
  return this->getText();
}

std::list<FileRule> AppArmor::Tree::ProfileRule::getFileRules() const
{
  return rules.getFileRules();
}

std::list<LinkRule> AppArmor::Tree::ProfileRule::getLinkRules() const
{
  return rules.getLinkRules();
}

std::list<RuleList> AppArmor::Tree::ProfileRule::getRuleList() const
{
  return rules.getRuleList();
}

std::list<AbstractionRule> AppArmor::Tree::ProfileRule::getAbstractions() const
{
  return rules.getAbstractions();
}

std::list<ProfileRule> AppArmor::Tree::ProfileRule::getSubprofiles() const
{
  return rules.getSubprofiles();
}

uint64_t AppArmor::Tree::ProfileRule::getRuleStartPosition() const
{
  return rules.getStartPosition();
}

uint64_t AppArmor::Tree::ProfileRule::getRuleEndPosition() const
{
  return rules.getEndPosition();  
}

template<class T>
inline void AppArmor::Tree::ProfileRule::checkRuleInList(const T &obj, 
                                               const std::list<T> &list,
                                               const std::string &class_name,
                                               const std::string &obj_name) const
{
    // Attempt to find profile from the list and return on success
    for(auto &node : list) {
        if(obj == node) {
            return;
        }
    }

    // Profile was not found so throw an exception
    std::stringstream message;
    message << "Invalid " << class_name << " \"" << obj_name << "\" was given as argument. This rule could not be found in Profile: " << this->name() << ".\n";
    throw std::domain_error(message.str());
}

void AppArmor::Tree::ProfileRule::checkRuleValid(const FileRule &file_rule) const
{
  const auto &list = rules.getFileRules();
  checkRuleInList(file_rule, list, "AppArmor::Tree::FileRule", file_rule.getFilename());

  if(file_rule.getFilemode().empty()) {
    std::stringstream message;
    message << "Invalid FileRule \"" << file_rule.getFilename() << "\" was given as argument. This rule had an empty FileMode.";
  }
}

void AppArmor::Tree::ProfileRule::checkRuleValid(const LinkRule &rule) const
{
  const auto &list = rules.getLinkRules();
  checkRuleInList(rule, list, "AppArmor::Tree::LinkRule", "link");
}

void AppArmor::Tree::ProfileRule::checkRuleValid(const RuleList &rule) const
{
  const auto &list = rules.getRuleList();
  checkRuleInList(rule, list, "AppArmor::Tree::RuleList", "rulelist");
}

void AppArmor::Tree::ProfileRule::checkRuleValid(const AbstractionRule &rule) const
{
  const auto &list = rules.getAbstractions();
  checkRuleInList(rule, list, "AppArmor::Tree::AbstractionRule", rule.getPath());
}

void AppArmor::Tree::ProfileRule::checkRuleValid(const ProfileRule &rule) const
{
  const auto &list = rules.getSubprofiles();
  checkRuleInList(rule, list, "AppArmor::Tree::ProfileRule", rule.name());
}

bool AppArmor::Tree::ProfileRule::operator==(const ProfileRule &other) const
{
  return this->rules == other.rules;
}

bool AppArmor::Tree::ProfileRule::operator!=(const ProfileRule &other) const
{
  return this->rules != other.rules;
}
