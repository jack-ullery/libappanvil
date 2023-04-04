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
      explicit Parser(std::ifstream &stream);

      std::list<Profile> getProfileList() const;
      AppArmor::Parser removeRule(const std::string &path, const AppArmor::Profile &profile, const AppArmor::FileRule &fileRule);
      AppArmor::Parser addRule(const std::string &path, const AppArmor::Profile &profile, const std::string& fileRule, const std::string& fileMode);

    private:
      void initializeProfileList(const std::shared_ptr<ParseTree> &ast);
      std::string path;

      std::list<Profile> profile_list; 
  };
} // namespace AppArmor

#endif // APPARMOR_PARSER_HH