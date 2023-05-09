#ifndef APPARMOR_PARSER_HH
#define APPARMOR_PARSER_HH

#include <fstream>
#include <list>
#include <ostream>
#include <string>

#include "tree/ParseTree.hh"
#include "tree/FileNode.hh"
#include "tree/ProfileNode.hh"

std::string trim(const std::string &str);

namespace AppArmor {
  using Profile = Tree::ProfileNode;
  using FileNode = Tree::FileNode;
  using RuleNode = Tree::RuleNode;

  class Parser {
    public:
      explicit Parser(const std::string &path);

      std::list<Profile> getProfileList() const;

      void removeRule(Profile &profile, RuleNode &rule);
      void removeRule(Profile &profile, RuleNode &rule, std::ostream &output);

      void addRule(Profile &profile, const std::string &fileglob, const std::string &filemode);
      void addRule(Profile &profile, const std::string &fileglob, const std::string &filemode, std::ostream &output);

      void editRule(Profile &profile, FileNode &oldRule, const std::string &fileglob, const std::string &filemode);
      void editRule(Profile &profile, FileNode &oldRule, const std::string &fileglob, const std::string &filemode, std::ostream &output);

    private:
      void update_from_file_contents();
      void update_from_stream(std::istream &stream);
      void initializeProfileList(const std::shared_ptr<AppArmor::Tree::ParseTree> &ast);

      // Checks whether a given Profile is in the profile_list
      // Throws an exception if it is not
      void checkProfileValid(Profile &profile);

      std::string path;
      std::string file_contents;

      std::list<Profile> profile_list; 
  };
} // namespace AppArmor

#endif // APPARMOR_PARSER_HH
