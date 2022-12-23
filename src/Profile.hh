#ifndef PROFILE_HH
#define PROFILE_HH

#include "parser/tree/ProfileNode.hh"

#include <unordered_set>

class Profile {
  public:
    Profile(ProfileNode &profile_model);

    // Returns the name of this profile
    std::string getName();

    // Returns a list of abstractions included in the profile
    std::unordered_set<std::string> getAbstractions();

  private:
    ProfileNode profile_model;
};

#endif // PROFILE_HH