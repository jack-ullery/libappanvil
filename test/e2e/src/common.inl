#ifndef COMMON_INL
#define COMMON_INL

#include <gtest/gtest.h>

#include "apparmor_parser.hh"
#include "tree/FileRule.hh"

namespace Common {

  template<class T>
  inline void checkRuleListsEqual(const std::list<T> &expected, const std::list<T> &observed)
  {
    EXPECT_EQ(expected.size(), observed.size()) << "There should be the same number of abstractions";

    // Iterate over every value of each list to ensure that they point to the same path
    auto it1 = expected.begin();
    auto it2 = observed.begin();
    while(it1 != expected.end() && 
          it2 != observed.end())
    {
      EXPECT_TRUE(it1->almostEquals(*it2)) << "These two values should be equal";

      // Increment iterator
      it1++;
      it2++;
    }
  }

  // Checks that the AppArmor::Parser contains a profile with the expected file rules
  inline void check_file_rules_for_profile(const AppArmor::Parser &parser,
                                           const std::list<AppArmor::Tree::FileRule> &expected_file_rules,
                                           const std::string &profile_name)
  {
      auto profile_list = parser.getProfileList();
      ASSERT_NE(profile_list.size(), 0) << "There should be a profile";

      while(profile_name != profile_list.front().name() && !profile_list.empty()){
          profile_list.pop_front();
      }

      auto profile = profile_list.front();
      EXPECT_EQ(profile.name(), profile_name) << "No profile name matched";

      auto file_rules = profile.getFileRules();
      checkRuleListsEqual(expected_file_rules, file_rules);
  }

  // Calls 'check_file_rules_for_profile()' on two parsers, checking that they both have the same expected file_rules
  inline void check_file_rules_for_profile(const AppArmor::Parser &old_parser,
                                           const AppArmor::Parser &new_parser,
                                           const std::list<AppArmor::Tree::FileRule> &expected_file_rules,
                                           const std::string &profile_name)
  {
    check_file_rules_for_profile(old_parser, expected_file_rules, profile_name);
    check_file_rules_for_profile(new_parser, expected_file_rules, profile_name);
  }

  // Creates a AppArmor::Tree::FileRule at the front of the list
  [[maybe_unused]]
  static void emplace_front(std::list<AppArmor::Tree::FileRule> &list,
                            const std::string &filename,
                            const std::string &filemode,
                            std::string optional_exec_mode = "",
                            bool is_subset = false)
  {
    AppArmor::Tree::FileRule rule(0, 1, filename, filemode, optional_exec_mode, is_subset);
    list.emplace_front(rule);
  }

  // Creates a AppArmor::Tree::FileRule at the back of the list
  [[maybe_unused]]
  static void emplace_back(std::list<AppArmor::Tree::FileRule> &list,
                           const std::string &filename,
                           const std::string &filemode,
                           std::string optional_exec_mode = "",
                           bool is_subset = false)
  {
    AppArmor::Tree::FileRule rule(0, 1, filename, filemode, optional_exec_mode, is_subset);
    list.emplace_back(rule);
  }
} // namespace Common

#endif // COMMON_INL