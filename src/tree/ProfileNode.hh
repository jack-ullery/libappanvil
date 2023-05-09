#ifndef PROFILE_NODE_HH
#define PROFILE_NODE_HH

#include "RuleList.hh"
#include "TreeNode.hh"

#include <string>

namespace AppArmor::Tree {
  class ProfileNode : protected TreeNode {
    public:
      ProfileNode(const std::string &profile_name, const RuleList &rules);
      ProfileNode() = default;

      // Returns the name of this profile
      std::string name() const;

      // Returns a list of RuleLists in the profile
      std::list<RuleList> getRuleList() const;

      // Returns a list of file rules included in the profile
      std::list<FileNode> getFileList() const;

      // Returns a list of link rules included in the profile
      std::list<LinkNode> getLinkList() const;

      // Returns a list of abstractions included in the profile
      std::list<AbstractionNode> getAbstractions() const;

      // Returns a list of subprofiles defined in this profile
      std::list<ProfileNode> getSubprofiles() const;

      // Gets the character position where the rules start (after the first '{' of this profile)
      uint64_t getRuleStartPosition() const;

      // Gets the character position where the rules end (before the last '}' of this profile)
      uint64_t getRuleEndPosition() const;

      // Checks whether a given RuleNode is in the profile_model
      // Throws an exception if it is not
      void checkRuleValid(const RuleNode &file_rule) const;
      void checkRuleValid(const FileNode &file_rule) const;
      void checkRuleValid(const LinkNode &rule) const;
      void checkRuleValid(const RuleList &rule) const;
      void checkRuleValid(const AbstractionNode &rule) const;
      void checkRuleValid(const ProfileNode &rule) const;

      virtual bool operator==(const ProfileNode &other) const;
      virtual bool operator!=(const ProfileNode &other) const;

    private:
      RuleList rules;

      // Helper methods for checkRuleValid()
      template<class T>
      inline void checkRuleInList(const T &obj, 
                                  const std::list<T> &list,
                                  const std::string &class_name,
                                  const std::string &obj_name) const;

      template<class T>
      inline bool tryCheckRuleValid(const RuleNode &rule) const;
  };
} // namespace AppArmor::Tree

#endif // PROFILE_NODE_HH