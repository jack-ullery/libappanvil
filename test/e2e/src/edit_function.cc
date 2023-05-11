#include <gtest/gtest-param-test.h>
#include <gtest/gtest.h>
#include <exception>
#include <fstream>
#include <iostream>
#include <memory>
#include <unordered_set>

#include "common.inl"
#include "edit_function.hh"

using Common::check_file_rules_for_profile;
using Common::emplace_front;
using Common::emplace_back;

inline void EditFunctionCheck::edit_file_rule_in_profile(AppArmor::Parser &parser, 
                                                         const std::string &fileglob,
                                                         const std::string &filemode,
                                                         std::list<AppArmor::Tree::FileRule> &expected_file_rules,
                                                         const bool &first_profile,
                                                         const bool &first_rule)
{
    // Retrieve either the first or last profile if it exists
    auto profile_list = parser.getProfileList();
    ASSERT_FALSE(profile_list.empty()) << "There should be at least one profile";
    auto prof = (first_profile)? profile_list.front() : profile_list.back();

    // Retrieve either the first or last file rule in profile
    auto rule_list = prof.getFileList();
    ASSERT_FALSE(rule_list.empty()) << "There should be at least one file rule";
    auto frule = (first_rule)? rule_list.front() : rule_list.back();

    // Edit file rule and push changes to temporary file
    std::ofstream temp_stream(temp_file);
    EXPECT_NO_THROW(parser.editRule(prof, frule, fileglob, filemode, temp_stream));
    temp_stream.close();

    // Add rule to expected rules
    if(first_rule) {
        emplace_front(expected_file_rules, fileglob, filemode);
    }
    else {
        emplace_back(expected_file_rules, fileglob, filemode);
    }
}

//Test to edit a rule from a file with 1 profile and 1 rule
TEST_F(EditFunctionCheck, test1_edit) // NOLINT
{
    std::string filename = ADDITIONAL_PROFILE_SOURCE_DIR "/edit-untouched/test1_edit.sd";
    std::list<AppArmor::Tree::FileRule> expected_file_rules;

    AppArmor::Parser parser(filename);
    edit_file_rule_in_profile(parser, "/bin/ls", "ixixixix", expected_file_rules);
    AppArmor::Parser new_parser(temp_file);

    // Check that the expected file rules are present for both the old and new parser
    check_file_rules_for_profile(parser, new_parser, expected_file_rules, "/**");
}

//Test to edit a rule from a file with 1 profile and 2 rules
TEST_F(EditFunctionCheck, test2_edit) // NOLINT
{
    std::string filename = ADDITIONAL_PROFILE_SOURCE_DIR "/edit-untouched/test2_edit.sd";
    std::list<AppArmor::Tree::FileRule> expected_file_rules;

    emplace_back(expected_file_rules, "/bin/echo", "uxuxuxuxux");

    AppArmor::Parser parser(filename);
    edit_file_rule_in_profile(parser, "/bin/ls", "ixixixix", expected_file_rules);
    AppArmor::Parser new_parser(temp_file);

    check_file_rules_for_profile(parser, new_parser, expected_file_rules, "/**");
}

//Test to edit a rule from a file with 2 profiles and 1 rule each
TEST_F(EditFunctionCheck, test3_edit) // NOLINT
{
    std::string filename = ADDITIONAL_PROFILE_SOURCE_DIR "/edit-untouched/test3_edit.sd";
    std::list<AppArmor::Tree::FileRule> expected_file_rules1;
    std::list<AppArmor::Tree::FileRule> expected_file_rules2;

    emplace_back(expected_file_rules2, "/usr/X11R6/lib/lib*so*", "rrr");

    AppArmor::Parser parser(filename);
    edit_file_rule_in_profile(parser, "/bin/ls", "ixixixix", expected_file_rules1);
    AppArmor::Parser new_parser(temp_file);

    check_file_rules_for_profile(parser, new_parser, expected_file_rules2, "/*");
}

//Test to edit a rule from a file with 2 profiles and 2 rules each
TEST_F(EditFunctionCheck, test4_edit) // NOLINT
{
    std::string filename = ADDITIONAL_PROFILE_SOURCE_DIR "/edit-untouched/test4_edit.sd";
    std::list<AppArmor::Tree::FileRule> expected_file_rules1;
    std::list<AppArmor::Tree::FileRule> expected_file_rules2;

    emplace_back(expected_file_rules1, "/bin/echo", "uxuxuxuxux");
    emplace_back(expected_file_rules2, "/usr/X11R6/lib/lib*so*", "rrr");
    emplace_back(expected_file_rules2, "/var/log/messages", "www");

    AppArmor::Parser parser(filename);
    edit_file_rule_in_profile(parser, "/bin/ls", "ixixixix", expected_file_rules1);
    AppArmor::Parser new_parser(temp_file);

    check_file_rules_for_profile(parser, new_parser, expected_file_rules1, "/**");
    check_file_rules_for_profile(parser, new_parser, expected_file_rules2, "/*");
}

//Test to edit 2 rules from a file with 1 profile and 2 rule
TEST_F(EditFunctionCheck, test5_edit_reverse) // NOLINT
{
    std::string filename = ADDITIONAL_PROFILE_SOURCE_DIR "/edit-untouched/test5_edit.sd";
    std::list<AppArmor::Tree::FileRule> expected_file_rules;

    AppArmor::Parser parser(filename);
    edit_file_rule_in_profile(parser, "/bin/ls", "ixixixix", expected_file_rules, true, false);
    edit_file_rule_in_profile(parser, "/var/log/messages", "www", expected_file_rules);
    AppArmor::Parser new_parser(temp_file);

    check_file_rules_for_profile(parser, new_parser, expected_file_rules, "/**");
}

//Test to edit 2 rules from a file with 1 profile and 2 rule sequentially
TEST_F(EditFunctionCheck, test5_edit_sequential) // NOLINT
{
    std::string filename = ADDITIONAL_PROFILE_SOURCE_DIR "/edit-untouched/test5_edit.sd";
    std::list<AppArmor::Tree::FileRule> expected_file_rules;

    AppArmor::Parser parser(filename);
    edit_file_rule_in_profile(parser, "/var/log/messages", "www", expected_file_rules);
    edit_file_rule_in_profile(parser, "/bin/ls", "ixixixix", expected_file_rules, true, false);
    AppArmor::Parser new_parser(temp_file);

    check_file_rules_for_profile(parser, new_parser, expected_file_rules, "/**");
}

//Test to edit 2 rules from a file with 2 profiles and 1 rule each
TEST_F(EditFunctionCheck, test6_edit) // NOLINT
{
    std::string filename = ADDITIONAL_PROFILE_SOURCE_DIR "/edit-untouched/test6_edit.sd";
    std::list<AppArmor::Tree::FileRule> expected_file_rules1;
    std::list<AppArmor::Tree::FileRule> expected_file_rules2;

    AppArmor::Parser parser(filename);
    edit_file_rule_in_profile(parser, "/var/log/messages", "www", expected_file_rules1);
    edit_file_rule_in_profile(parser, "/bin/ls", "ixixixix", expected_file_rules2, false);
    AppArmor::Parser new_parser(temp_file);

    check_file_rules_for_profile(parser, new_parser, expected_file_rules1, "/**");
    check_file_rules_for_profile(parser, new_parser, expected_file_rules2, "/*");
}

//Test to edit a rule twice from a file with 1 profile and 1 rule
TEST_F(EditFunctionCheck, test7_edit) // NOLINT
{
    std::string filename = ADDITIONAL_PROFILE_SOURCE_DIR "/edit-untouched/test7_edit.sd";
    std::list<AppArmor::Tree::FileRule> dummy_list;
    std::list<AppArmor::Tree::FileRule> expected_file_rules;

    AppArmor::Parser parser(filename);
    edit_file_rule_in_profile(parser, "/var/log/messages", "www", dummy_list);
    edit_file_rule_in_profile(parser, "/bin/ls", "ixixixix", expected_file_rules);
    AppArmor::Parser new_parser(temp_file);

    check_file_rules_for_profile(parser, new_parser, expected_file_rules, "/**");
}

// Attempts to edit a non-existant rule in a profile
TEST_F(EditFunctionCheck, test1_invalid_edit) // NOLINT
{
    std::string filename = ADDITIONAL_PROFILE_SOURCE_DIR "/remove-untouched/test1_remove.sd";

    AppArmor::Parser parser(filename);
    auto profile_list = parser.getProfileList();
    ASSERT_FALSE(profile_list.empty()) << "There should be at least one profile";
    auto prof = profile_list.front();

    // Create a fake file rule
    AppArmor::Tree::FileRule frule(0, 10, "/does/not/exist", "rw");

    // Attempt to edit file rule
    std::ofstream temp_stream(temp_file);
    EXPECT_ANY_THROW(parser.editRule(prof, frule, "/usr/bin/echo", "rwx", temp_stream));
    temp_stream.close();
}

// Attempts to edit a file rule using the wrong profile
TEST_F(EditFunctionCheck, test2_invalid_edit) // NOLINT
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

    // Attempt to edit file rule with the second profile
    std::ofstream temp_stream(temp_file);
    EXPECT_ANY_THROW(parser.editRule(back_prof, frule, "/usr/bin/echo", "rwx", temp_stream));
    temp_stream.close();
}

// Attempts to edit a file rule using fake profile
TEST_F(EditFunctionCheck, test3_invalid_edit) // NOLINT
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
    AppArmor::Tree::ProfileRule fake_prof;

    // Attempt to edit file rule
    std::ofstream temp_stream(temp_file);
    EXPECT_ANY_THROW(parser.editRule(fake_prof, frule, "/usr/bin/echo", "rwx", temp_stream));
    temp_stream.close();
}

// Attempts to edit a file rule in an outdated parser
TEST_F(EditFunctionCheck, test4_invalid_edit) // NOLINT
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
    std::ofstream temp(temp_file);
    EXPECT_NO_THROW(parser.editRule(old_prof, frule, "/usr/bin/echo", "r", temp));
    temp.close();

    AppArmor::Parser new_parser(temp_file);

    auto new_profile_list = new_parser.getProfileList();
    ASSERT_FALSE(new_profile_list.empty()) << "There should be at least one profile";
    auto new_prof = new_profile_list.front();

    // Attempt to remove old file rule from new parser
    std::ofstream temp_stream(temp_file);
    EXPECT_ANY_THROW(new_parser.editRule(new_prof, frule, "/usr/bin/echo", "rwx", temp_stream));
    temp_stream.close();
}
