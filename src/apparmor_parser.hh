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

      bool removeRule(std::string path, std::string profileName, std::string ruleName, std::string ruleMode);

    private:
      void initializeProfileList(std::shared_ptr<ParseTree> ast);
      void removeRuleFromFile(const std::string& path, const std::string& profile, const std::string& remove);
      std::string path;

      std::list<Profile> profile_list; 
  };
}

#endif // APPARMOR_PARSER_HH