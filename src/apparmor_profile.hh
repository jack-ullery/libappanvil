#ifndef APPARMOR_PROFILE_HH
#define APPARMOR_PROFILE_HH

#include <list>
#include <memory>
#include <unordered_set>

#include "apparmor_file_rule.hh"

class ProfileNode;

namespace AppArmor {
  class Profile {
    public:
      explicit Profile(std::shared_ptr<ProfileNode> profile_model);

      // Returns the name of this profile
      std::string name() const;

      // Returns a set of abstractions included in the profile
      std::unordered_set<std::string> getAbstractions() const;

      // Returns a list of file rules included in the profile
      std::list<AppArmor::FileRule> getFileRules() const;

    private:
      std::shared_ptr<ProfileNode> profile_model;
  };
} // namespace AppArmor

#endif // APPARMOR_PROFILE_HH