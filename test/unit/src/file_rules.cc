#include <exception>
#include <fstream>
#include <gtest/gtest-param-test.h>
#include <gtest/gtest.h>
#include <iostream>
#include <memory>
#include <unordered_set>

#include "apparmor_parser.hh"
#include "common.inl"

using Common::emplace_back;

namespace FileRuleCheck {
  inline void check_file_rules_for_single_profile(const std::string &filename, const std::list<AppArmor::Tree::FileRule> &expected_file_rules, const std::string &profile_name)
  {
    AppArmor::Parser parser(filename);
    auto profile_list = parser.getProfileList();
  
    EXPECT_EQ(profile_list.size(), 1) << "There should only be one profile";
  
    auto first_profile = profile_list.begin();
    EXPECT_EQ(first_profile->name(), profile_name);

    auto file_rules = first_profile->getFileRules();
    Common::checkRuleListsEqual(file_rules, expected_file_rules);
  }

  TEST(FileRuleCheck, abi_ok_1)
  {
    auto filename = PROFILE_SOURCE_DIR "/abi/ok_1.sd";
    std::list<AppArmor::Tree::FileRule> expected_file_rules{};

    check_file_rules_for_single_profile(filename, expected_file_rules, "/does/not/exist");
  }

  TEST(FileRuleCheck, file_ok_1)
  {
    auto filename = PROFILE_SOURCE_DIR "/file/ok_1.sd";
    std::list<AppArmor::Tree::FileRule> expected_file_rules;

    emplace_back(expected_file_rules, "/usr/bin/foo", "r");

    check_file_rules_for_single_profile(filename, expected_file_rules, "/usr/bin/foo");
  }

  TEST(FileRuleCheck, file_ok_2)
  {
    auto filename = PROFILE_SOURCE_DIR "/file/ok_2.sd";
    std::list<AppArmor::Tree::FileRule> expected_file_rules;

    emplace_back(expected_file_rules, "/usr/bin/foo", "RWM");

    check_file_rules_for_single_profile(filename, expected_file_rules, "/usr/bin/foo");
  }

  TEST(FileRuleCheck, file_ok_3)
  {
    auto filename = PROFILE_SOURCE_DIR "/file/ok_3.sd";
    std::list<AppArmor::Tree::FileRule> expected_file_rules;

    emplace_back(expected_file_rules, "/usr/bin/foo", "r");
    emplace_back(expected_file_rules, "/usr/bin/blah", "rix");

    check_file_rules_for_single_profile(filename, expected_file_rules, "/usr/bin/foo");
  }

  TEST(FileRuleCheck, file_ok_4)
  {
    auto filename = PROFILE_SOURCE_DIR "/file/ok_4.sd";
    std::list<AppArmor::Tree::FileRule> expected_file_rules;

    emplace_back(expected_file_rules, "/usr/bin/foo", "iX");

    check_file_rules_for_single_profile(filename, expected_file_rules, "/usr/bin/foo");
  }

  TEST(FileRuleCheck, file_ok_5)
  {
    auto filename = PROFILE_SOURCE_DIR "/file/ok_5.sd";
    std::list<AppArmor::Tree::FileRule> expected_file_rules;

    emplace_back(expected_file_rules, "/usr/bin/foo", "UX");

    check_file_rules_for_single_profile(filename, expected_file_rules, "/usr/bin/foo");
  }

  TEST(FileRuleCheck, file_ok_append_1)
  {
    auto filename = PROFILE_SOURCE_DIR "/file/ok_append_1.sd";
    std::list<AppArmor::Tree::FileRule> expected_file_rules;

    emplace_back(expected_file_rules, "/bin/cat", "a");
    emplace_back(expected_file_rules, "/bin/true", "ra");
    emplace_back(expected_file_rules, "/bin/false", "ma");
    emplace_back(expected_file_rules, "/lib/libc.so", "la");
    emplace_back(expected_file_rules, "/bin/less", "ixa");
    emplace_back(expected_file_rules, "/bin/more", "pxa");
    emplace_back(expected_file_rules, "/a", "uxa");

    check_file_rules_for_single_profile(filename, expected_file_rules, "/usr/bin/foo");
  }

  TEST(FileRuleCheck, file_ok_link_1)
  {
    auto filename = PROFILE_SOURCE_DIR "/file/ok_link_1.sd";
    std::list<AppArmor::Tree::FileRule> expected_file_rules;

    emplace_back(expected_file_rules, "/alpha/beta", "rl");
    emplace_back(expected_file_rules, "/gamma/*", "rwl");

    check_file_rules_for_single_profile(filename, expected_file_rules, "test");
  }

  TEST(FileRuleCheck, file_stacking_ok_1)
  {
    auto filename = PROFILE_SOURCE_DIR "/file/stacking_ok_1.sd";
    std::list<AppArmor::Tree::FileRule> expected_file_rules;

    emplace_back(expected_file_rules, "/bin/bar", "px", "&baz");

    check_file_rules_for_single_profile(filename, expected_file_rules, "/usr/bin/foo");
  }
}
