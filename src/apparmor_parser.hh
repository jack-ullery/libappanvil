#ifndef APPARMOR_PARSER_HH
#define APPARMOR_PARSER_HH

#include <algorithm>
#include <fstream>
#include <list>
#include <ostream>
#include <string>

#include "tree/FileRule.hh"
#include "tree/ProfileRule.hh"

namespace AppArmor {
  namespace Tree {
    class ParseTree;
  } // namespace Tree

  using Profile = Tree::ProfileRule;
  using FileRule = Tree::FileRule;
  using RuleNode = Tree::RuleNode;

  // Concept checks whether class is a subclass of RuleNode
  // Does not match RuleNode
  template<class RuleType>
  concept RuleDerived = std::is_base_of<RuleNode, RuleType>::value && !std::is_base_of<RuleType, RuleNode>::value;

  class Parser {
    public:
      explicit Parser(const std::string &path);

      std::list<Profile> getProfileList() const;

      template<RuleDerived RuleType>
      void removeRule(Profile &profile, RuleType &rule);

      template<RuleDerived RuleType>
      void removeRule(Profile &profile, RuleType &rule, std::ostream &output);

      void addRule(Profile &profile, const FileRule &newRule);
      void addRule(Profile &profile, const FileRule &newRule, std::ostream &output);

      void editRule(Profile &profile, FileRule &oldRule, const FileRule &newRule);
      void editRule(Profile &profile, FileRule &oldRule, const FileRule &newRule, std::ostream &output);

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
