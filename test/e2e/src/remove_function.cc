#include <gtest/gtest.h>
#include <exception>
#include <fstream>
#include <iostream>
#include <memory>
#include <ostream>
#include <unordered_set>

#include "remove_function.hh"
#include "parser/tree/FileNode.hh"

inline void RemoveFunctionCheck::remove_file_rule_from_first_profile(AppArmor::Parser &parser)
{
    auto profile_list = parser.getProfileList();
    ASSERT_FALSE(profile_list.empty()) << "There should be at least one profile";
    auto prof = profile_list.front();

    // Get first file rule in profile
    auto rule_list = prof.getFileRules();
    ASSERT_FALSE(rule_list.empty()) << "There should be at least one file rule";
    auto frule = rule_list.front();

    // Remove file rule and push changes to temporary file
    std::ofstream temp_stream(temp_file);
    parser.removeRule(prof, frule, temp_stream);
    temp_stream.close();
}

inline void RemoveFunctionCheck::check_file_rules_for_profile(const AppArmor::Parser &parser,
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

// Creates and places a FileNode object at the end of the list
void emplace_back(std::list<AppArmor::FileRule> &list, const std::string &filename, const std::string &filemode)
{
    FileNode node(0, 1, filename, filemode);
    auto node_pointer = std::make_shared<FileNode>(node);
    AppArmor::FileRule rule(node_pointer);
    list.emplace_back(rule);
}

//Test to remove a rule from a file with 1 profile and 1 rule
TEST_F(RemoveFunctionCheck, test1_remove) // NOLINT
{
    std::string filename = ADDITIONAL_PROFILE_SOURCE_DIR "/remove-untouched/test1_remove.sd";

    std::list<AppArmor::FileRule> expected_file_rules;

    //remove rule /usr/X11R6/lib/lib*so* rrr,
    AppArmor::Parser parser(filename);

    remove_file_rule_from_first_profile(parser);
    AppArmor::Parser new_parser(temp_file);

    check_file_rules_for_profile(new_parser, expected_file_rules, "/**");
}

//Test to remove a rule from a file with 1 profile and more than 1 rule
TEST_F(RemoveFunctionCheck, test2_remove) // NOLINT
{
    std::string filename = ADDITIONAL_PROFILE_SOURCE_DIR "/remove-untouched/test2_remove.sd";
    std::list<AppArmor::FileRule> expected_file_rules;

    emplace_back(expected_file_rules, "/does/not/exist", "r");
    emplace_back(expected_file_rules, "/var/log/messages", "www");

    AppArmor::Parser parser(filename);
    remove_file_rule_from_first_profile(parser);
    AppArmor::Parser new_parser(temp_file);

    check_file_rules_for_profile(new_parser, expected_file_rules, "/**");
}

//Test to remove a rule from a file with 2 profiles and 1 rule each
TEST_F(RemoveFunctionCheck, test3_remove) // NOLINT
{
    std::string filename = ADDITIONAL_PROFILE_SOURCE_DIR "/remove-untouched/test3_remove.sd";
    std::list<AppArmor::FileRule> expected_file_rules1;
    std::list<AppArmor::FileRule> expected_file_rules2;

    emplace_back(expected_file_rules2, "/usr/X11R6/lib/lib*so*", "rrr");

    AppArmor::Parser parser(filename);
    remove_file_rule_from_first_profile(parser);
    AppArmor::Parser new_parser(temp_file);

    check_file_rules_for_profile(new_parser, expected_file_rules1, "/**");
    check_file_rules_for_profile(new_parser, expected_file_rules2, "/*");
}

//Test to remove a rule from a file with 2 profiles and more than 1 rule each
TEST_F(RemoveFunctionCheck, test4_remove) // NOLINT
{
    std::string filename = ADDITIONAL_PROFILE_SOURCE_DIR "/remove-untouched/test4_remove.sd";
    std::list<AppArmor::FileRule> expected_file_rules1;
    std::list<AppArmor::FileRule> expected_file_rules2;

    emplace_back(expected_file_rules1, "/does/not/exist", "r");
    emplace_back(expected_file_rules1, "/var/log/messages", "www");

    emplace_back(expected_file_rules2, "/usr/X11R6/lib/lib*so*", "rrr");
    emplace_back(expected_file_rules2, "/does/not/exist", "r");
    emplace_back(expected_file_rules2, "/var/log/messages", "www");

    AppArmor::Parser parser(filename);
    remove_file_rule_from_first_profile(parser);
    AppArmor::Parser new_parser(temp_file);

    check_file_rules_for_profile(new_parser, expected_file_rules1, "/**");
    check_file_rules_for_profile(new_parser, expected_file_rules2, "/*");
}

// //Test to remove a rule that DNI from a file with 1 profile and 1 rule
// TEST_F(RemoveFunctionCheck, test5)
// {
//     std::string filename = ADDITIONAL_PROFILE_SOURCE_DIR "/remove-untouched/test5.sd";
//     std::list<AppArmor::FileRule> expected_file_rules;

//     emplace_back(expected_file_rules, /usr/X11R6/lib/lib*so*, rrr);

//     //remove nonexistant rule from profile /**

//     check_file_rules_for_profile(parser, expected_file_rules, "/**");
// }

// //Test to remove a rule from a profile that DNI from a file with 1 profile and 1 rule
// TEST_F(RemoveFunctionCheck, test6)
// {
//     std::string filename = ADDITIONAL_PROFILE_SOURCE_DIR "/remove-untouched/test6.sd";
//     std::list<AppArmor::FileRule> expected_file_rules;

//     emplace_back(expected_file_rules, /usr/X11R6/lib/lib*so*, rrr);

//     //remove rule /usr/X11R6/lib/lib*so* rrr, from nonexistant profile

//     check_file_rules_for_profile(parser, expected_file_rules, "/**");
// }
