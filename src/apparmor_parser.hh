#ifndef APPARMOR_PARSER_HH
#define APPARMOR_PARSER_HH

#include "apparmor_profile.hh"

#include <fstream>
#include <list>
#include <string>

std::string trim(const std::string& str);

class ParseTree;

namespace AppArmor {
  class Parser {
    public:
      Parser(std::string path);
      std::list<Profile> getProfileList() const;
      void removeRule(AppArmor::Profile profile, AppArmor::FileRule fileRule);

    private:
      void initializeProfileList(std::shared_ptr<ParseTree> ast);
      std::string path;
      std::list<Profile> profile_list; 
      void removeRuleFromFile(const std::string& profile, const std::string& remove);
  };
}

AppArmor::Parser removeRule(std::string path, AppArmor::Profile profile, AppArmor::FileRule fileRule);

#endif // APPARMOR_PARSER_HH

