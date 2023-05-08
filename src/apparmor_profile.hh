#ifndef APPARMOR_PROFILE_HH
#define APPARMOR_PROFILE_HH

#include <list>
#include <memory>
#include <unordered_set>

#include "apparmor_file_rule.hh"

namespace AppArmor {
  namespace Tree {
    class ProfileNode;
  }

  class Profile {
    public:
      explicit Profile(std::shared_ptr<AppArmor::Tree::ProfileNode> profile_model);

      // Returns the name of this profile
      std::string name() const;

      // Returns a set of abstractions included in the profile
      std::unordered_set<std::string> getAbstractions() const;

      // Returns a list of file rules included in the profile
      std::list<AppArmor::FileRule> getFileRules() const;

      // Gets the start position of the rule list (after the opening bracket)
      uint64_t getRuleStartPosition() const;

      // Gets the end position of the rule list (before the closing bracket)
      uint64_t getRuleEndPosition() const;

      // Checks whether two Profiles are the same object by comparing their profile_model pointers, to see if they are the same
      bool operator==(const Profile& that) const;
      bool operator!=(const Profile& that) const;

      // Checks whether a given FileRule is in the profile_model
      // Throws an exception if it is not
      void checkFileRuleValid(AppArmor::FileRule &file_rule) const;

    private:
      std::shared_ptr<AppArmor::Tree::ProfileNode> profile_model;
  };
} // namespace AppArmor

#endif // APPARMOR_PROFILE_HH