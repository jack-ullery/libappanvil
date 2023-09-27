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

      // Returns the path that was used to create the constructor
      std::string getPath() const;

      std::list<Profile> getProfileList() const;

      template<RuleDerived RuleType>
      void removeRule(Profile &profile, RuleType &rule);

      template<RuleDerived RuleType>
      void removeRule(Profile &profile, RuleType &rule, std::ostream &output);

      void addRule(Profile &profile, const FileRule &newRule);
      void addRule(Profile &profile, const FileRule &newRule, std::ostream &output);

      void editRule(Profile &profile, FileRule &oldRule, const FileRule &newRule);
      void editRule(Profile &profile, FileRule &oldRule, const FileRule &newRule, std::ostream &output);

      /**
      * @brief Attempts to parse profile from a user-supplied string, and replace this profile with it
      *
      * @details
      * If the string parses successfully, this replaces the content of this class with that data.
      * In this case the following things will change:
      *   - output of getProfileList()
      *   - file_contents (private variable)
      *   - profile_list  (private variable)
      *
      * The following things would not change:
      *   - output of getPath()
      *   - old_file_contents (private variable)
      *
      * If the string does not parse successfully, there should be no changes.
      *
      * @param new_file_contents the string to parse
      *
      * @throws std::runtime_error if the profile did not parse correctly
      */
      void updateFromString(const std::string &new_file_contents);

      /**
      * @brief Returns whether this class has staged change to the AppArmor profile, which are not saved
      *
      * @returns boolean, true if there are unsaved changes to the AppArmor profile
      */
      bool hasChanges();

      /**
      * @brief Save changes to AppArmor profile, loading them into the kernel
      *
      * @details
      * This method call 'pkexec aa-replace' to save and load profile changes to the kernel.
      * aa-replace is a binary we created that does two things: it first overwrites a file with the current profile data,
      * then it calls 'apparmor_parser -r' to replace the profile in the kernel.
      *
      * @returns int, the exit status of aa-replace. This should be zero if and only if there was no error.
      */
      int saveChanges();

      void cancelChanges();

      // Converts class to std::string by returning the up-to-date raw file data, which this class represents
      explicit operator std::string() const;

    private:
      void update_from_file_contents();
      void update_from_stream(std::istream &stream);
      void initializeProfileList(const std::shared_ptr<AppArmor::Tree::ParseTree> &ast);

      // Checks whether a given Profile is in the profile_list
      // Throws an exception if it is not
      void checkProfileValid(Profile &profile);

      std::string path;
      std::string file_contents;
      std::string old_file_contents;

      std::list<Profile> profile_list; 
  };
} // namespace AppArmor

#endif // APPARMOR_PARSER_HH
