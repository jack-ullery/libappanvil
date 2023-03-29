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
      Parser(std::ifstream &stream);

      std::list<Profile> getProfileList() const;
      AppArmor::Parser removeRule(std::string path, AppArmor::Profile profile, AppArmor::FileRule fileRule);
      AppArmor::Parser addRule(std::string path, AppArmor::Profile profile, const std::string& fileRule, std::string& fileMode);

    private:
      void initializeProfileList(std::shared_ptr<ParseTree> ast);
      std::string path;

      std::list<Profile> profile_list; 
  };
}

#endif // APPARMOR_PARSER_HH