#include "ProfileNode.hh"
#include "tree/TreeNode.hh"
#include <cstddef>
#include <sstream>

// NOLINTNEXTLINE(google-build-using-namespace)
using namespace AppArmor::Tree;

AppArmor::Tree::ProfileNode::ProfileNode(const std::string &profile_name, const RuleList &rules)
  : TreeNode(profile_name),
    rules{rules}
{   }

std::string AppArmor::Tree::ProfileNode::name() const
{
  return this->getText();
}

std::list<FileNode> AppArmor::Tree::ProfileNode::getFileList() const
{
  return rules.getFileList();
}

std::list<LinkNode> AppArmor::Tree::ProfileNode::getLinkList() const
{
  return rules.getLinkList();
}

std::list<RuleList> AppArmor::Tree::ProfileNode::getRuleList() const
{
  return rules.getRuleList();
}

std::list<AbstractionNode> AppArmor::Tree::ProfileNode::getAbstractions() const
{
  return rules.getAbstractions();
}

std::list<ProfileNode> AppArmor::Tree::ProfileNode::getSubprofiles() const
{
  return rules.getSubprofiles();
}

uint64_t AppArmor::Tree::ProfileNode::getRuleStartPosition() const
{
  return rules.getStartPosition();
}

uint64_t AppArmor::Tree::ProfileNode::getRuleEndPosition() const
{
  return rules.getEndPosition();  
}

template<class T>
inline void AppArmor::Tree::ProfileNode::checkRuleInList(const T &obj, 
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

void AppArmor::Tree::ProfileNode::checkRuleValid(const FileNode &file_rule) const
{
  const auto &list = rules.getFileList();
  checkRuleInList(file_rule, list, "AppArmor::Tree::FileNode", file_rule.getFilemode());
}

void AppArmor::Tree::ProfileNode::checkRuleValid(const LinkNode &rule) const
{
  const auto &list = rules.getLinkList();
  checkRuleInList(rule, list, "AppArmor::Tree::LinkNode", "link");
}

void AppArmor::Tree::ProfileNode::checkRuleValid(const RuleList &rule) const
{
  const auto &list = rules.getRuleList();
  checkRuleInList(rule, list, "AppArmor::Tree::RuleList", "rulelist");
}

void AppArmor::Tree::ProfileNode::checkRuleValid(const AbstractionNode &rule) const
{
  const auto &list = rules.getAbstractions();
  checkRuleInList(rule, list, "AppArmor::Tree::AbstractionNode", rule.getPath());
}

void AppArmor::Tree::ProfileNode::checkRuleValid(const ProfileNode &rule) const
{
  const auto &list = rules.getSubprofiles();
  checkRuleInList(rule, list, "AppArmor::Tree::ProfileNode", rule.name());
}

template<class T>
inline bool AppArmor::Tree::ProfileNode::tryCheckRuleValid(const RuleNode &rule) const
{
  auto *cast_rule = dynamic_cast<const T*>(&rule);
  if(cast_rule != nullptr) {
    checkRuleValid(*cast_rule);
    return true;
  }
  return false;
}

void AppArmor::Tree::ProfileNode::checkRuleValid(const RuleNode &rule) const
{
  // Attempt to cast the rule to the following types, and run checkRUleValid on that type
  if(!(tryCheckRuleValid<FileNode>(rule)        ||
       tryCheckRuleValid<LinkNode>(rule)        ||
       tryCheckRuleValid<RuleList>(rule)        ||
       tryCheckRuleValid<AbstractionNode>(rule) ||
       tryCheckRuleValid<ProfileNode>(rule)))
  {
    // If the rule was not a FileNode, LinkNode, RuleList, AbstractionNode, or ProfileNode
    //   then it was some other invalid type of RuleNode, so we should throw an error
    std::stringstream message;
    message << "Invalid rule type was given as argument. This rule could not be found in Profile: " << this->name() << ".\n";
    throw std::domain_error(message.str());
  }
}

bool AppArmor::Tree::ProfileNode::operator==(const ProfileNode &other) const
{
  return this->rules == other.rules;
}

bool AppArmor::Tree::ProfileNode::operator!=(const ProfileNode &other) const
{
  return this->rules != other.rules;
}
