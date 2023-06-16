#include <gtest/gtest.h>
#include <exception>
#include <fstream>
#include <iostream>
#include <memory>
#include <unordered_set>

#include "apparmor_parser.hh"
#include "common.inl"
#include "add_function.hh"
#include "tree/FileRule.hh"

using Common::check_file_rules_for_profile;
using Common::emplace_back;

inline void AddFunctionCheck::add_file_rule_to_profile(AppArmor::Parser &parser, 
                                                       const std::string &fileglob,
                                                       const std::string &filemode,
                                                       std::list<AppArmor::Tree::FileRule> &expected_file_rules,
                                                       const bool &first_profile,
                                                       std::string optional_exec_mode,
                                                       bool is_subset)
{
    auto profile_list = parser.getProfileList();
    ASSERT_FALSE(profile_list.empty()) << "There should be at least one profile";
    auto prof = (first_profile)? profile_list.front() : profile_list.back();

    // Add file rule and push changes to temporary file
    AppArmor::Tree::FileRule new_rule(0, 1, fileglob, filemode, optional_exec_mode, is_subset);
    std::ofstream temp_stream(temp_file);
    EXPECT_NO_THROW(parser.addRule(prof, new_rule, temp_stream));
    temp_stream.close();

    // Add rule to expected rules
    expected_file_rules.emplace_back(new_rule);
}

//Test to add a rule to a file with 1 profile and 0 rules
TEST_F(AddFunctionCheck, test1_add) // NOLINT
{
    std::string filename = ADDITIONAL_PROFILE_SOURCE_DIR "/add-untouched/test1_add.sd";
    std::list<AppArmor::Tree::FileRule> expected_file_rules;

    AppArmor::Parser parser(filename);
    add_file_rule_to_profile(parser, "/bin/echo", "uxuxuxuxux", expected_file_rules);
    AppArmor::Parser new_parser(temp_file);

    // Check that the expected file rules are present for both the old and new parser
    check_file_rules_for_profile(parser, new_parser, expected_file_rules, "/**");
}

//Test to add a rule to a file with 1 profile and 1 rule
TEST_F(AddFunctionCheck, test2_add) // NOLINT
{
    std::string filename = ADDITIONAL_PROFILE_SOURCE_DIR "/add-untouched/test2_add.sd";
    std::list<AppArmor::Tree::FileRule> expected_file_rules;
    emplace_back(expected_file_rules, "/usr/X11R6/lib/lib*so*", "rrr");

    AppArmor::Parser parser(filename);
    add_file_rule_to_profile(parser, "/bin/echo", "uxuxuxuxux", expected_file_rules);
    AppArmor::Parser new_parser(temp_file);

    check_file_rules_for_profile(parser, new_parser, expected_file_rules, "/**");
}

//Test to add 2 rules to a file with 1 profile and 0 rules
TEST_F(AddFunctionCheck, test3_add) // NOLINT
{
    std::string filename = ADDITIONAL_PROFILE_SOURCE_DIR "/add-untouched/test3_add.sd";
    std::list<AppArmor::Tree::FileRule> expected_file_rules;

    AppArmor::Parser parser(filename);
    add_file_rule_to_profile(parser, "/bin/echo", "uxuxuxuxux", expected_file_rules);
    add_file_rule_to_profile(parser, "/var/log/messages", "www", expected_file_rules);
    AppArmor::Parser new_parser(temp_file);

    check_file_rules_for_profile(parser, new_parser, expected_file_rules, "/**");
}

//Test to add 2 rules to a file with 1 profile and 1 rule
TEST_F(AddFunctionCheck, test4_add) // NOLINT
{
    std::string filename = ADDITIONAL_PROFILE_SOURCE_DIR "/add-untouched/test4_add.sd";
    std::list<AppArmor::Tree::FileRule> expected_file_rules;
    emplace_back(expected_file_rules, "/usr/X11R6/lib/lib*so*", "rrr");

    AppArmor::Parser parser(filename);
    add_file_rule_to_profile(parser, "/bin/echo", "uxuxuxuxux", expected_file_rules);
    add_file_rule_to_profile(parser, "/var/log/messages", "www", expected_file_rules);
    AppArmor::Parser new_parser(temp_file);

    check_file_rules_for_profile(parser, new_parser, expected_file_rules, "/**");
}

//Test to add 1 rule to a file with 2 profiles and 0 rules each
TEST_F(AddFunctionCheck, test5_add) // NOLINT
{
    std::string filename = ADDITIONAL_PROFILE_SOURCE_DIR "/add-untouched/test5_add.sd";
    std::list<AppArmor::Tree::FileRule> expected_file_rules1;
    std::list<AppArmor::Tree::FileRule> expected_file_rules2;

    AppArmor::Parser parser(filename);
    add_file_rule_to_profile(parser, "/bin/echo", "uxuxuxuxux", expected_file_rules1);
    AppArmor::Parser new_parser(temp_file);

    check_file_rules_for_profile(parser, new_parser, expected_file_rules1, "/**");
    check_file_rules_for_profile(parser, new_parser, expected_file_rules2, "/*");
}

//Test to add 1 rule to a file with 2 profiles and 1 rule each
TEST_F(AddFunctionCheck, test6_add) // NOLINT
{
    std::string filename = ADDITIONAL_PROFILE_SOURCE_DIR "/add-untouched/test6_add.sd";
    std::list<AppArmor::Tree::FileRule> expected_file_rules1;
    std::list<AppArmor::Tree::FileRule> expected_file_rules2;
    emplace_back(expected_file_rules1, "/usr/X11R6/lib/lib*so*", "rrr");
    emplace_back(expected_file_rules2, "/usr/X11R6/lib/lib*so*", "rrr");

    AppArmor::Parser parser(filename);
    add_file_rule_to_profile(parser, "/bin/echo", "uxuxuxuxux", expected_file_rules1);
    AppArmor::Parser new_parser(temp_file);

    check_file_rules_for_profile(parser, new_parser, expected_file_rules1, "/**");
    check_file_rules_for_profile(parser, new_parser, expected_file_rules2, "/*");
}

//Test to add 2 rules to a file with 2 profiles and 0 rules each
TEST_F(AddFunctionCheck, test7_add) // NOLINT
{
    std::string filename = ADDITIONAL_PROFILE_SOURCE_DIR "/add-untouched/test7_add.sd";
    std::list<AppArmor::Tree::FileRule> expected_file_rules1;
    std::list<AppArmor::Tree::FileRule> expected_file_rules2;

    AppArmor::Parser parser(filename);
    add_file_rule_to_profile(parser, "/bin/echo",  "uxuxuxuxux", expected_file_rules1);
    add_file_rule_to_profile(parser, "/var/log/messages", "www", expected_file_rules2, false);
    AppArmor::Parser new_parser(temp_file);

    check_file_rules_for_profile(parser, new_parser, expected_file_rules1, "/**");
    check_file_rules_for_profile(parser, new_parser, expected_file_rules2, "/*");
}

//Test to add 2 rules to a file with 2 profiles and 1 rule each
TEST_F(AddFunctionCheck, test8_add) // NOLINT
{
    std::string filename = ADDITIONAL_PROFILE_SOURCE_DIR "/add-untouched/test8_add.sd";
    std::list<AppArmor::Tree::FileRule> expected_file_rules1;
    std::list<AppArmor::Tree::FileRule> expected_file_rules2;
    emplace_back(expected_file_rules1, "/usr/X11R6/lib/lib*so*", "rrr");
    emplace_back(expected_file_rules2, "/usr/X11R6/lib/lib*so*", "rrr");

    AppArmor::Parser parser(filename);
    add_file_rule_to_profile(parser, "/bin/echo",  "uxuxuxuxux", expected_file_rules1);
    add_file_rule_to_profile(parser, "/var/log/messages", "www", expected_file_rules2, false);
    AppArmor::Parser new_parser(temp_file);

    check_file_rules_for_profile(parser, new_parser, expected_file_rules1, "/**");
    check_file_rules_for_profile(parser, new_parser, expected_file_rules2, "/*");
}

// Test to add rule to fake profile
TEST_F(AddFunctionCheck, test1_invalid_add) // NOLINT
{
    std::string filename = ADDITIONAL_PROFILE_SOURCE_DIR "/add-untouched/test1_add.sd";
    AppArmor::Parser parser(filename);

    // Create fake profile
    AppArmor::Tree::ProfileRule fake_prof;

    // Add file rule and push changes to temporary file
    AppArmor::Tree::FileRule new_rule(0, 0, "/usr/bin/echo", "rwix");
    std::ofstream temp_stream(temp_file);
    EXPECT_ANY_THROW(parser.addRule(fake_prof, new_rule, temp_stream));
    temp_stream.close();
}

// Test to add rule to add rule with transition
TEST_F(AddFunctionCheck, test_weird_add_1) // NOLINT
{
    std::string filename = ADDITIONAL_PROFILE_SOURCE_DIR "/add-untouched/test1_add.sd";
    std::list<AppArmor::Tree::FileRule> expected_file_rules;

    AppArmor::Parser parser(filename);
    add_file_rule_to_profile(parser, "/bin/echo", "px", expected_file_rules, true, "target_profile", false);
    AppArmor::Parser new_parser(temp_file);

    // Check that the expected file rules are present for both the old and new parser
    check_file_rules_for_profile(parser, new_parser, expected_file_rules, "/**");
}

// Test to add rule to add rule with subset
TEST_F(AddFunctionCheck, test_weird_add_2) // NOLINT
{
    std::string filename = ADDITIONAL_PROFILE_SOURCE_DIR "/add-untouched/test1_add.sd";
    std::list<AppArmor::Tree::FileRule> expected_file_rules;

    AppArmor::Parser parser(filename);
    add_file_rule_to_profile(parser, "/bin/echo", "rwk", expected_file_rules, true, "", true);
    AppArmor::Parser new_parser(temp_file);

    // Check that the expected file rules are present for both the old and new parser
    check_file_rules_for_profile(parser, new_parser, expected_file_rules, "/**");
}

// Test to add rule to add rule with subset and transition
TEST_F(AddFunctionCheck, test_weird_add_3) // NOLINT
{
    std::string filename = ADDITIONAL_PROFILE_SOURCE_DIR "/add-untouched/test1_add.sd";
    std::list<AppArmor::Tree::FileRule> expected_file_rules;

    AppArmor::Parser parser(filename);
    add_file_rule_to_profile(parser, "/bin/echo", "rwkPx", expected_file_rules, true, "target_profile", true);
    AppArmor::Parser new_parser(temp_file);

    // Check that the expected file rules are present for both the old and new parser
    check_file_rules_for_profile(parser, new_parser, expected_file_rules, "/**");
}
