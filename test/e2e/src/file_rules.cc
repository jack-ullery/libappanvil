#include <exception>
#include <fstream>
#include <gtest/gtest-param-test.h>
#include <gtest/gtest.h>
#include <iostream>
#include <memory>
#include <unordered_set>

#include "apparmor_parser.hh"
#include "parser/tree/FileNode.hh"

namespace FileRuleCheck {

  std::list<AppArmor::Profile> getProfileList(std::string filename)
  {
    AppArmor::Parser parser(filename);
    return parser.getProfileList();
  }
  
  void check_file_rules_for_single_profile(std::string filename, std::list<AppArmor::FileRule> expected_file_rules, std::string profile_name)
  {
    auto profile_list = getProfileList(filename);
  
    EXPECT_EQ(profile_list.size(), 1) << "There should only be one profile";
  
    auto first_profile = profile_list.begin();
    EXPECT_EQ(first_profile->name(), profile_name);

    auto file_rules = first_profile->getFileRules();
    ASSERT_EQ(file_rules, expected_file_rules);
  }
  
  // Creates and inserts an AppArmor::FileRule to the end of a list
  void emplace_back(std::list<AppArmor::FileRule> &list, const std::string &filename, const std::string &filemode)
  {
    FileNode node(0, 1, filename, filemode);
    auto node_pointer = std::make_shared<FileNode>(node);
    AppArmor::FileRule rule(node_pointer);
    list.emplace_back(rule);
  }

  TEST(FileRuleCheck, abi_ok_1)
  {
    auto filename = PROFILE_SOURCE_DIR "/abi/ok_1.sd";
    std::list<AppArmor::FileRule> expected_file_rules{};

    check_file_rules_for_single_profile(filename, expected_file_rules, "/does/not/exist");
  }

  TEST(FileRuleCheck, file_ok_1)
  {
    auto filename = PROFILE_SOURCE_DIR "/file/ok_1.sd";
    std::list<AppArmor::FileRule> expected_file_rules;

    emplace_back(expected_file_rules, "/usr/bin/foo", "r");

    check_file_rules_for_single_profile(filename, expected_file_rules, "/usr/bin/foo");
  }

  TEST(FileRuleCheck, file_ok_2)
  {
    auto filename = PROFILE_SOURCE_DIR "/file/ok_2.sd";
    std::list<AppArmor::FileRule> expected_file_rules;

    emplace_back(expected_file_rules, "/usr/bin/foo", "RWM");

    check_file_rules_for_single_profile(filename, expected_file_rules, "/usr/bin/foo");
  }

  TEST(FileRuleCheck, file_ok_3)
  {
    auto filename = PROFILE_SOURCE_DIR "/file/ok_3.sd";
    std::list<AppArmor::FileRule> expected_file_rules;

    emplace_back(expected_file_rules, "/usr/bin/foo", "r");
    emplace_back(expected_file_rules, "/usr/bin/blah", "rix");

    check_file_rules_for_single_profile(filename, expected_file_rules, "/usr/bin/foo");
  }

  TEST(FileRuleCheck, file_ok_4)
  {
    auto filename = PROFILE_SOURCE_DIR "/file/ok_4.sd";
    std::list<AppArmor::FileRule> expected_file_rules;

    emplace_back(expected_file_rules, "/usr/bin/foo", "iX");

    check_file_rules_for_single_profile(filename, expected_file_rules, "/usr/bin/foo");
  }

  TEST(FileRuleCheck, file_ok_5)
  {
    auto filename = PROFILE_SOURCE_DIR "/file/ok_5.sd";
    std::list<AppArmor::FileRule> expected_file_rules;

    emplace_back(expected_file_rules, "/usr/bin/foo", "UX");

    check_file_rules_for_single_profile(filename, expected_file_rules, "/usr/bin/foo");
  }

  TEST(FileRuleCheck, file_ok_append_1)
  {
    auto filename = PROFILE_SOURCE_DIR "/file/ok_append_1.sd";
    std::list<AppArmor::FileRule> expected_file_rules;

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
    std::list<AppArmor::FileRule> expected_file_rules;

    emplace_back(expected_file_rules, "/alpha/beta", "rl");
    emplace_back(expected_file_rules, "/gamma/*", "rwl");

    check_file_rules_for_single_profile(filename, expected_file_rules, "test");
  }
}
