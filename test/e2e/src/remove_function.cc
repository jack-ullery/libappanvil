#include <gtest/gtest.h>
#include <exception>
#include <fstream>
#include <iostream>
#include <memory>
#include <ostream>
#include <unordered_set>

#include "apparmor_parser.hh"
#include "common.inl"
#include "remove_function.hh"
#include "tree/FileNode.hh"

using Common::check_file_rules_for_profile;
using Common::emplace_back;

inline void RemoveFunctionCheck::remove_file_rule_from_first_profile(AppArmor::Parser &parser)
{
    auto profile_list = parser.getProfileList();
    ASSERT_FALSE(profile_list.empty()) << "There should be at least one profile";
    auto prof = profile_list.front();

    // Get first file rule in the profile
    auto rule_list = prof.getFileList();
    ASSERT_FALSE(rule_list.empty()) << "There should be at least one file rule";
    auto frule = rule_list.front();

    // Remove file rule and push changes to temporary file
    std::ofstream temp_stream(temp_file);
    EXPECT_NO_THROW(parser.removeRule(prof, frule, temp_stream));
    temp_stream.close();
}

//Test to remove a rule from a file with 1 profile and 1 rule
TEST_F(RemoveFunctionCheck, test1_remove) // NOLINT
{
    std::string filename = ADDITIONAL_PROFILE_SOURCE_DIR "/remove-untouched/test1_remove.sd";

    std::list<AppArmor::Tree::FileNode> expected_file_rules;

    //remove rule /usr/X11R6/lib/lib*so* rrr,
    AppArmor::Parser parser(filename);

    remove_file_rule_from_first_profile(parser);
    AppArmor::Parser new_parser(temp_file);

    // Check that the expected file rules are present for both the old and new parser
    check_file_rules_for_profile(parser, new_parser, expected_file_rules, "/**");
}

//Test to remove a rule from a file with 1 profile and more than 1 rule
TEST_F(RemoveFunctionCheck, test2_remove) // NOLINT
{
    std::string filename = ADDITIONAL_PROFILE_SOURCE_DIR "/remove-untouched/test2_remove.sd";
    std::list<AppArmor::Tree::FileNode> expected_file_rules;

    emplace_back(expected_file_rules, "/does/not/exist", "r");
    emplace_back(expected_file_rules, "/var/log/messages", "www");

    AppArmor::Parser parser(filename);
    remove_file_rule_from_first_profile(parser);
    AppArmor::Parser new_parser(temp_file);

    check_file_rules_for_profile(parser, new_parser, expected_file_rules, "/**");
}

//Test to remove a rule from a file with 2 profiles and 1 rule each
TEST_F(RemoveFunctionCheck, test3_remove) // NOLINT
{
    std::string filename = ADDITIONAL_PROFILE_SOURCE_DIR "/remove-untouched/test3_remove.sd";
    std::list<AppArmor::Tree::FileNode> expected_file_rules1;
    std::list<AppArmor::Tree::FileNode> expected_file_rules2;

    emplace_back(expected_file_rules2, "/usr/X11R6/lib/lib*so*", "rrr");

    AppArmor::Parser parser(filename);
    remove_file_rule_from_first_profile(parser);
    AppArmor::Parser new_parser(temp_file);

    check_file_rules_for_profile(parser, new_parser, expected_file_rules1, "/**");
    check_file_rules_for_profile(parser, new_parser, expected_file_rules2, "/*");
}

//Test to remove a rule from a file with 2 profiles and more than 1 rule each
TEST_F(RemoveFunctionCheck, test4_remove) // NOLINT
{
    std::string filename = ADDITIONAL_PROFILE_SOURCE_DIR "/remove-untouched/test4_remove.sd";
    std::list<AppArmor::Tree::FileNode> expected_file_rules1;
    std::list<AppArmor::Tree::FileNode> expected_file_rules2;

    emplace_back(expected_file_rules1, "/does/not/exist", "r");
    emplace_back(expected_file_rules1, "/var/log/messages", "www");

    emplace_back(expected_file_rules2, "/usr/X11R6/lib/lib*so*", "rrr");
    emplace_back(expected_file_rules2, "/does/not/exist", "r");
    emplace_back(expected_file_rules2, "/var/log/messages", "www");

    AppArmor::Parser parser(filename);
    remove_file_rule_from_first_profile(parser);
    AppArmor::Parser new_parser(temp_file);

    check_file_rules_for_profile(parser, new_parser, expected_file_rules1, "/**");
    check_file_rules_for_profile(parser, new_parser, expected_file_rules2, "/*");
}

// Attempts to remove a non-existant rule from a profile
TEST_F(RemoveFunctionCheck, test1_invalid_remove) // NOLINT
{
    std::string filename = ADDITIONAL_PROFILE_SOURCE_DIR "/remove-untouched/test1_remove.sd";

    AppArmor::Parser parser(filename);
    auto profile_list = parser.getProfileList();
    ASSERT_FALSE(profile_list.empty()) << "There should be at least one profile";
    auto prof = profile_list.front();

    // Create a fake file rule
    AppArmor::Tree::FileNode frule(0, 10, "/does/not/exist", "rw");

    // Attempt to remove file rule and push changes to temporary file
    std::ofstream temp_stream(temp_file);
    EXPECT_ANY_THROW(parser.removeRule(prof, frule, temp_stream));
    temp_stream.close();
}

// Attempts to remove a file rule from the wrong profile
TEST_F(RemoveFunctionCheck, test2_invalid_remove) // NOLINT
{
    std::string filename = ADDITIONAL_PROFILE_SOURCE_DIR "/remove-untouched/test3_remove.sd";

    AppArmor::Parser parser(filename);
    auto profile_list = parser.getProfileList();
    ASSERT_FALSE(profile_list.empty()) << "There should be at least one profile";
    auto front_prof = profile_list.front();
    auto back_prof = profile_list.back();
    ASSERT_NE(front_prof, back_prof) << "These should be two distinct profiles";

    // Get a frule from the first profile
    auto rule_list = front_prof.getFileList();
    ASSERT_FALSE(rule_list.empty()) << "There should be at least one file rule";
    auto frule = rule_list.front();

    // Attempt to remove file rule from the second profile
    std::ofstream temp_stream(temp_file);
    EXPECT_ANY_THROW(parser.removeRule(back_prof, frule, temp_stream));
    temp_stream.close();
}

// Attempts to remove a file rule from fake profile
TEST_F(RemoveFunctionCheck, test3_invalid_remove) // NOLINT
{
    std::string filename = ADDITIONAL_PROFILE_SOURCE_DIR "/remove-untouched/test1_remove.sd";

    AppArmor::Parser parser(filename);
    auto profile_list = parser.getProfileList();
    ASSERT_FALSE(profile_list.empty()) << "There should be at least one profile";
    auto prof = profile_list.front();

    // Get a frule from the profile
    auto rule_list = prof.getFileList();
    ASSERT_FALSE(rule_list.empty()) << "There should be at least one file rule";
    auto frule = rule_list.front();

    // Create fake profile
    AppArmor::Tree::ProfileNode fake_prof;

    // Attempt to edit file rule
    std::ofstream temp_stream(temp_file);
    EXPECT_ANY_THROW(parser.removeRule(fake_prof, frule, temp_stream));
    temp_stream.close();
}

// Attempts to remove a file rule from an outdated parser
TEST_F(RemoveFunctionCheck, test4_invalid_remove) // NOLINT
{
    std::string filename = ADDITIONAL_PROFILE_SOURCE_DIR "/remove-untouched/test4_remove.sd";
    AppArmor::Parser parser(filename);

    // Gets the profile from the first parser
    auto old_profile_list = parser.getProfileList();
    ASSERT_FALSE(old_profile_list.empty()) << "There should be at least one profile";
    auto old_prof = old_profile_list.back();

    // Get a frule from the old profile
    auto rule_list = old_prof.getFileList();
    ASSERT_FALSE(rule_list.empty()) << "There should be at least one file rule";
    auto frule = rule_list.front();

    // Remove a rule from the first profile
    remove_file_rule_from_first_profile(parser);
    AppArmor::Parser new_parser(temp_file);

    auto new_profile_list = new_parser.getProfileList();
    ASSERT_FALSE(new_profile_list.empty()) << "There should be at least one profile";
    auto new_prof = new_profile_list.front();

    // Attempt to remove old file rule from new parser
    std::ofstream temp_stream(temp_file);
    EXPECT_ANY_THROW(new_parser.removeRule(new_prof, frule, temp_stream));
    temp_stream.close();
}
