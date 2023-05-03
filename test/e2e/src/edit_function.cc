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
                                                         std::list<AppArmor::FileRule> &expected_file_rules,
                                                         const bool &first_profile,
                                                         const bool &first_rule)
{
    // Retrieve either the first or last profile if it exists
    auto profile_list = parser.getProfileList();
    ASSERT_FALSE(profile_list.empty()) << "There should be at least one profile";
    auto prof = (first_profile)? profile_list.front() : profile_list.back();

    // Retrieve either the first or last file rule in profile
    auto rule_list = prof.getFileRules();
    ASSERT_FALSE(rule_list.empty()) << "There should be at least one file rule";
    auto frule = (first_rule)? rule_list.front() : rule_list.back();

    // Edit file rule and push changes to temporary file
    std::ofstream temp_stream(temp_file);
    parser.editRule(prof, frule, fileglob, filemode, temp_stream);
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
    std::list<AppArmor::FileRule> expected_file_rules;

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
    std::list<AppArmor::FileRule> expected_file_rules;

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
    std::list<AppArmor::FileRule> expected_file_rules1;
    std::list<AppArmor::FileRule> expected_file_rules2;

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
    std::list<AppArmor::FileRule> expected_file_rules1;
    std::list<AppArmor::FileRule> expected_file_rules2;

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
    std::list<AppArmor::FileRule> expected_file_rules;

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
    std::list<AppArmor::FileRule> expected_file_rules;

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
    std::list<AppArmor::FileRule> expected_file_rules1;
    std::list<AppArmor::FileRule> expected_file_rules2;

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
    std::list<AppArmor::FileRule> expected_file_rules1;
    std::list<AppArmor::FileRule> expected_file_rules2;

    AppArmor::Parser parser(filename);
    edit_file_rule_in_profile(parser, "/var/log/messages", "www", expected_file_rules1);
    edit_file_rule_in_profile(parser, "/bin/ls", "ixixixix", expected_file_rules2);
    AppArmor::Parser new_parser(temp_file);

    check_file_rules_for_profile(parser, new_parser, expected_file_rules2, "/**");
}