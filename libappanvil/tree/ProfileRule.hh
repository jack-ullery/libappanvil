#ifndef PROFILE_RULE_HH
#define PROFILE_RULE_HH

#include "RuleList.hh"
#include "TreeNode.hh"

#include <string>

namespace AppArmor::Tree {
  class ProfileRule : protected TreeNode {
    public:
      ProfileRule(const std::string &profile_name, const RuleList &rules);
      ProfileRule() = default;

      // Returns the name of this profile
      std::string name() const;

      // Returns a list of RuleLists in the profile
      std::list<RuleList> getRuleList() const;

      // Returns a list of file rules included in the profile
      std::list<FileRule> getFileRules() const;

      // Returns a list of link rules included in the profile
      std::list<LinkRule> getLinkRules() const;

      // Returns a list of abstractions included in the profile
      std::list<AbstractionRule> getAbstractions() const;

      // Returns a list of subprofiles defined in this profile
      std::list<ProfileRule> getSubprofiles() const;

      // Gets the character position where the rules start (after the first '{' of this profile)
      uint64_t getRuleStartPosition() const;

      // Gets the character position where the rules end (before the last '}' of this profile)
      uint64_t getRuleEndPosition() const;

      // Checks whether a given RuleNode is in the profile_model
      // Throws an exception if it is not
      void checkRuleValid(const FileRule &file_rule) const;
      void checkRuleValid(const LinkRule &rule) const;
      void checkRuleValid(const RuleList &rule) const;
      void checkRuleValid(const AbstractionRule &rule) const;
      void checkRuleValid(const ProfileRule &rule) const;

      virtual bool operator==(const ProfileRule &other) const;
      virtual bool operator!=(const ProfileRule &other) const;

    private:
      RuleList rules;

      // Helper methods for checkRuleValid()
      template<class T>
      inline void checkRuleInList(const T &obj, 
                                  const std::list<T> &list,
                                  const std::string &class_name,
                                  const std::string &obj_name) const;
  };
} // namespace AppArmor::Tree

#endif // PROFILE_RULE_HH