#ifndef APPARMOR_PARSER_HH
#define APPARMOR_PARSER_HH

#include "apparmor_profile.hh"

#include <fstream>
#include <list>
#include <ostream>
#include <string>

std::string trim(const std::string &str);

class ParseTree;

namespace AppArmor {
  class Parser {
    public:
      explicit Parser(const std::string &path);

      std::list<Profile> getProfileList() const;

      void removeRule(AppArmor::Profile &profile, AppArmor::FileRule &fileRule);
      void removeRule(AppArmor::Profile &profile, AppArmor::FileRule &fileRule, std::ostream &output);

      void addRule(Profile &profile, const std::string &fileglob, const std::string &fileMode);
      void addRule(Profile &profile, const std::string &fileglob, const std::string &fileMode, std::ostream &output);

      Parser editRule(Profile &profile, FileRule &oldFileRule, const std::string &newFileRule, const std::string &newFileMode);

    private:
      void initializeProfileList(const std::shared_ptr<ParseTree> &ast);

      std::string path;
      std::string file_contents;

      std::list<Profile> profile_list; 
  };
} // namespace AppArmor

#endif // APPARMOR_PARSER_HH
