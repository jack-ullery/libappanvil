#ifndef COMMON_INL
#define COMMON_INL

#include <gtest/gtest.h>

#include "apparmor_parser.hh"
#include "parser/tree/FileNode.hh"

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

  static void emplace_back(std::list<AppArmor::FileRule> &list, const std::string &filename, const std::string &filemode)
  {
      FileNode node(0, 1, filename, filemode);
      auto node_pointer = std::make_shared<FileNode>(node);
      AppArmor::FileRule rule(node_pointer);
      list.emplace_back(rule);
  }
} // namespace Common

#endif // COMMON_INL