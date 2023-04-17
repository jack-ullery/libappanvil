#include <gtest/gtest-param-test.h>
#include <gtest/gtest.h>
#include <exception>
#include <fstream>
#include <iostream>
#include <memory>
#include <unordered_set>

#include "apparmor_parser.hh"
#include "parser/tree/FileNode.hh"

namespace EditFunctionCheck {
    std::list<AppArmor::Profile> getProfileList(const std::string &filename)
    {
        AppArmor::Parser parser(filename);
        return parser.getProfileList();
    }

    void check_file_rules_for_single_profile(const std::string &filename,
                                             const std::list<AppArmor::FileRule> &expected_file_rules,
                                             const std::string &profile_name)
    {
        auto profile_list = getProfileList(filename);
        while(profile_name != profile_list.front().name() && !profile_list.empty()){
            profile_list.pop_front();
        }

        auto profile = profile_list.front();
        EXPECT_EQ(profile.name(), profile_name) << "No profile name matched";

        auto file_rules = profile.getFileRules();
        ASSERT_EQ(file_rules, expected_file_rules);
    }

    void emplace_back(std::list<AppArmor::FileRule> &list, const std::string &filename, const std::string &filemode)
    {
        FileNode node(0, 1, filename, filemode);
        auto node_pointer = std::make_shared<FileNode>(node);
        AppArmor::FileRule rule(node_pointer);
        list.emplace_back(rule);
    }

    //Test to edit a rule from a file with 1 profile and 1 rule
    TEST(EditFunctionCheck, test1_edit) // NOLINT
    {
        std::string filename = ADDITIONAL_PROFILE_SOURCE_DIR "/edit-untouched/test1_edit.sd";
        std::list<AppArmor::FileRule> expected_file_rules;

        //Edit the one rule into the new rule
        AppArmor::Parser parser(filename);

        auto profile_list = parser.getProfileList();
        ASSERT_FALSE(profile_list.empty()) << "There should be at least one profile";
        auto prof = profile_list.front();

        auto rule_list = prof.getFileRules();
        ASSERT_FALSE(rule_list.empty()) << "There should be at least one file rule";
        auto frule = rule_list.front();

        parser = parser.editRule(prof, frule, "/bin/ls", "ixixixix");

        emplace_back(expected_file_rules, "/bin/ls", "ixixixix");

        check_file_rules_for_single_profile(filename, expected_file_rules, "/**");
    }

    //Test to edit a rule from a file with 1 profile and 2 rules
    TEST(EditFunctionCheck, test2_edit) // NOLINT
    {
        std::string filename = ADDITIONAL_PROFILE_SOURCE_DIR "/edit-untouched/test2_edit.sd";
        std::list<AppArmor::FileRule> expected_file_rules;

        //Edit the one rule into the new rule
        AppArmor::Parser parser(filename);

        auto profile_list = parser.getProfileList();
        ASSERT_FALSE(profile_list.empty()) << "There should be at least one profile";
        auto prof = profile_list.front();

        auto rule_list = prof.getFileRules();
        ASSERT_FALSE(rule_list.empty()) << "There should be at least one file rule";
        auto frule = rule_list.front();

        parser = parser.editRule(prof, frule, "/bin/ls", "ixixixix");

        emplace_back(expected_file_rules, "/bin/ls", "ixixixix");
        emplace_back(expected_file_rules, "/bin/echo", "uxuxuxuxux");

        check_file_rules_for_single_profile(filename, expected_file_rules, "/**");
    }

    //Test to edit a rule from a file with 2 profiles and 1 rule each
    TEST(EditFunctionCheck, test3_edit) // NOLINT
    {
        std::string filename = ADDITIONAL_PROFILE_SOURCE_DIR "/edit-untouched/test3_edit.sd";
        std::list<AppArmor::FileRule> expected_file_rules1;
        std::list<AppArmor::FileRule> expected_file_rules2;

        //Edit the one rule into the new rule
        AppArmor::Parser parser(filename);

        auto profile_list = parser.getProfileList();
        ASSERT_FALSE(profile_list.empty()) << "There should be at least one profile";
        auto prof = profile_list.front();

        auto rule_list = prof.getFileRules();
        ASSERT_FALSE(rule_list.empty()) << "There should be at least one file rule";
        auto frule = rule_list.front();

        parser = parser.editRule(prof, frule, "/bin/ls", "ixixixix");

        emplace_back(expected_file_rules1, "/bin/ls", "ixixixix");
        check_file_rules_for_single_profile(filename, expected_file_rules1, "/**");

        emplace_back(expected_file_rules2, "/usr/X11R6/lib/lib*so*", "rrr");
        check_file_rules_for_single_profile(filename, expected_file_rules2, "/*");
    }

    //Test to edit a rule from a file with 2 profiles and 2 rules each
    TEST(EditFunctionCheck, test4_edit) // NOLINT
    {
        std::string filename = ADDITIONAL_PROFILE_SOURCE_DIR "/edit-untouched/test4_edit.sd";
        std::list<AppArmor::FileRule> expected_file_rules1;
        std::list<AppArmor::FileRule> expected_file_rules2;

        //Edit the one rule into the new rule
        AppArmor::Parser parser(filename);

        auto profile_list = parser.getProfileList();
        ASSERT_FALSE(profile_list.empty()) << "There should be at least one profile";
        auto prof = profile_list.front();

        auto rule_list = prof.getFileRules();
        ASSERT_FALSE(rule_list.empty()) << "There should be at least one file rule";
        auto frule = rule_list.front();

        parser = parser.editRule(prof, frule, "/bin/ls", "ixixixix");

        emplace_back(expected_file_rules1, "/bin/ls", "ixixixix");
        emplace_back(expected_file_rules1, "/bin/echo", "uxuxuxuxux");
        check_file_rules_for_single_profile(filename, expected_file_rules1, "/**");

        emplace_back(expected_file_rules2, "/usr/X11R6/lib/lib*so*", "rrr");
        emplace_back(expected_file_rules2, "/var/log/messages", "www");
        check_file_rules_for_single_profile(filename, expected_file_rules2, "/*");
    }

    //Test to edit 2 rules from a file with 1 profile and 2 rule
    TEST(EditFunctionCheck, test5_edit) // NOLINT
    {
        std::string filename = ADDITIONAL_PROFILE_SOURCE_DIR "/edit-untouched/test5_edit.sd";
        std::list<AppArmor::FileRule> expected_file_rules;

        //Edit the one rule into the new rule
        AppArmor::Parser parser(filename);

        auto profile_list = parser.getProfileList();
        ASSERT_FALSE(profile_list.empty()) << "There should be at least one profile";
        auto prof = profile_list.front();

        auto rule_list = prof.getFileRules();
        ASSERT_FALSE(rule_list.empty()) << "There should be at least one file rule";
        auto frule = rule_list.front();

        parser = parser.editRule(prof, frule, "/bin/ls", "ixixixix");

        frule = prof.getFileRules().back();
        parser = parser.editRule(prof, frule, "/var/log/messages", "www");

        emplace_back(expected_file_rules, "/bin/ls", "ixixixix");
        emplace_back(expected_file_rules, "/var/log/messages", "www");

        check_file_rules_for_single_profile(filename, expected_file_rules, "/**");
    }

    //Test to edit 2 rules from a file with 2 profiles and 1 rule each
    TEST(EditFunctionCheck, test6_edit) // NOLINT
    {
        std::string filename = ADDITIONAL_PROFILE_SOURCE_DIR "/edit-untouched/test6_edit.sd";
        std::list<AppArmor::FileRule> expected_file_rules1;
        std::list<AppArmor::FileRule> expected_file_rules2;

        //Edit the one rule into the new rule
        AppArmor::Parser parser(filename);

        auto profile_list = parser.getProfileList();
        ASSERT_FALSE(profile_list.empty()) << "There should be at least one profile";
        auto prof = profile_list.front();

        auto rule_list = prof.getFileRules();
        ASSERT_FALSE(rule_list.empty()) << "There should be at least one file rule";
        auto frule = rule_list.front();

        parser.editRule(prof, frule, "/bin/ls", "ixixixix");

        emplace_back(expected_file_rules1, "/bin/ls", "ixixixix");
        check_file_rules_for_single_profile(filename, expected_file_rules1, "/**");

        prof = parser.getProfileList().back();
        frule = prof.getFileRules().front();

        parser.editRule(prof, frule, "/bin/ls", "ixixixix");

        emplace_back(expected_file_rules2, "/bin/ls", "ixixixix");
        check_file_rules_for_single_profile(filename, expected_file_rules2, "/*");
    }

    //Test to edit a rule twice from a file with 1 profile and 1 rule
    TEST(EditFunctionCheck, test7_edit) // NOLINT
    {
        std::string filename = ADDITIONAL_PROFILE_SOURCE_DIR "/edit-untouched/test7_edit.sd";
        std::list<AppArmor::FileRule> expected_file_rules1;
        std::list<AppArmor::FileRule> expected_file_rules2;

        //Edit the one rule into the new rule
        AppArmor::Parser parser(filename);

        auto profile_list = parser.getProfileList();
        ASSERT_FALSE(profile_list.empty()) << "There should be at least one profile";
        auto prof = profile_list.front();

        auto rule_list = prof.getFileRules();
        ASSERT_FALSE(rule_list.empty()) << "There should be at least one file rule";
        auto frule = rule_list.front();

        parser = parser.editRule(prof, frule, "/bin/ls", "ixixixix");

        emplace_back(expected_file_rules1, "/bin/ls", "ixixixix");

        check_file_rules_for_single_profile(filename, expected_file_rules1, "/**");

        frule = prof.getFileRules().front();

        parser = parser.editRule(prof, frule, "/usr/X11R6/lib/lib*so*", "rrr");

        emplace_back(expected_file_rules2, "/usr/X11R6/lib/lib*so*", "rrr");

        check_file_rules_for_single_profile(filename, expected_file_rules2, "/**");
    }
} // namespace EditFunctionCheck