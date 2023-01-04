#ifndef APPARMOR_PROFILE_HH
#define APPARMOR_PROFILE_HH

#include <memory>
#include <unordered_set>

class ProfileNode;

namespace AppArmor {
  class Profile {
    public:
      Profile(std::shared_ptr<ProfileNode> profile_model);

      // Returns the name of this profile
      std::string getName() const;

      // Returns a list of abstractions included in the profile
      std::unordered_set<std::string> getAbstractions() const;

    private:
      std::shared_ptr<ProfileNode> profile_model;
  };
}

#endif // APPARMOR_PROFILE_HH