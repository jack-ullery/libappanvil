#ifndef COMMON_INL
#define COMMON_INL

#include <gtest/gtest.h>

#include "apparmor_parser.hh"
#include "tree/FileNode.hh"

namespace Common {
  // Checks that the AppArmor::Parser contains a profile with the expected file rules
  inline void check_file_rules_for_profile(const AppArmor::Parser &parser,
                                           const std::list<AppArmor::FileRule> &expected_file_rules,
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
      ASSERT_EQ(file_rules, expected_file_rules);
  }

  // Calls 'check_file_rules_for_profile()' on two parsers, checking that they both have the same expected file_rules
  inline void check_file_rules_for_profile(const AppArmor::Parser &old_parser,
                                           const AppArmor::Parser &new_parser,
                                           const std::list<AppArmor::FileRule> &expected_file_rules,
                                           const std::string &profile_name)
  {
    check_file_rules_for_profile(old_parser, expected_file_rules, profile_name);
    check_file_rules_for_profile(new_parser, expected_file_rules, profile_name);
  }

  // Creates a AppArmor::FileRule at the front of the list
  [[maybe_unused]]
  static void emplace_front(std::list<AppArmor::FileRule> &list, const std::string &filename, const std::string &filemode)
  {
      AppArmor::Tree::FileNode node(0, 1, filename, filemode);
      auto node_pointer = std::make_shared<AppArmor::Tree::FileNode>(node);
      AppArmor::FileRule rule(node_pointer);
      list.emplace_front(rule);
  }

  // Creates a AppArmor::FileRule at the back of the list
  [[maybe_unused]]
  static void emplace_back(std::list<AppArmor::FileRule> &list, const std::string &filename, const std::string &filemode)
  {
      AppArmor::Tree::FileNode node(0, 1, filename, filemode);
      auto node_pointer = std::make_shared<AppArmor::Tree::FileNode>(node);
      AppArmor::FileRule rule(node_pointer);
      list.emplace_back(rule);
  }
} // namespace Common

#endif // COMMON_INL