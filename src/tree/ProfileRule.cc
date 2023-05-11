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

std::list<FileRule> AppArmor::Tree::ProfileRule::getFileList() const
{
  return rules.getFileList();
}

std::list<LinkRule> AppArmor::Tree::ProfileRule::getLinkList() const
{
  return rules.getLinkList();
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
  const auto &list = rules.getFileList();
  checkRuleInList(file_rule, list, "AppArmor::Tree::FileRule", file_rule.getFilemode());
}

void AppArmor::Tree::ProfileRule::checkRuleValid(const LinkRule &rule) const
{
  const auto &list = rules.getLinkList();
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

template<class T>
inline bool AppArmor::Tree::ProfileRule::tryCheckRuleValid(const RuleNode &rule) const
{
  auto *cast_rule = dynamic_cast<const T*>(&rule);
  if(cast_rule != nullptr) {
    checkRuleValid(*cast_rule);
    return true;
  }
  return false;
}

void AppArmor::Tree::ProfileRule::checkRuleValid(const RuleNode &rule) const
{
  // Attempt to cast the rule to the following types, and run checkRUleValid on that type
  if(!(tryCheckRuleValid<FileRule>(rule)        ||
       tryCheckRuleValid<LinkRule>(rule)        ||
       tryCheckRuleValid<RuleList>(rule)        ||
       tryCheckRuleValid<AbstractionRule>(rule) ||
       tryCheckRuleValid<ProfileRule>(rule)))
  {
    // If the rule was not a FileRule, LinkRule, RuleList, AbstractionRule, or ProfileRule
    //   then it was some other invalid type of RuleNode, so we should throw an error
    std::stringstream message;
    message << "Invalid rule type was given as argument. This rule could not be found in Profile: " << this->name() << ".\n";
    throw std::domain_error(message.str());
  }
}

bool AppArmor::Tree::ProfileRule::operator==(const ProfileRule &other) const
{
  return this->rules == other.rules;
}

bool AppArmor::Tree::ProfileRule::operator!=(const ProfileRule &other) const
{
  return this->rules != other.rules;
}
