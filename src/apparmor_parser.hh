#ifndef APPARMOR_PARSER_HH
#define APPARMOR_PARSER_HH

#include "apparmor_profile.hh"

#include <fstream>
#include <list>
#include <string>

std::string trim(const std::string &str);

class ParseTree;

namespace AppArmor {
  class Parser {
    public:
      explicit Parser(const std::string &path);

      std::list<Profile> getProfileList() const;
      Parser removeRule(Profile profile, FileRule fileRule);
      Parser addRule(Profile profile, const std::string &fileRule, std::string &fileMode);
      Parser editRule(Profile profile, FileRule oldFileRule, const std::string &newFileRule, const std::string &newFileMode);

    private:
      void initializeProfileList(std::shared_ptr<ParseTree> ast);
      std::string path;
      std::list<Profile> profile_list; 
  };
} // namespace AppArmor

#endif // APPARMOR_PARSER_HH
