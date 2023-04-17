#include <gtest/gtest-param-test.h>
#include <gtest/gtest.h>
#include <exception>
#include <fstream>
#include <iostream>
#include <memory>
#include <unordered_set>

#include "apparmor_parser.hh"
#include "parser/tree/FileNode.hh"

namespace AddFunctionCheck {
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

    //Test to add a rule to a file with 1 profile and 0 rules
    TEST(AddFunctionCheck, test1_add) // NOLINT
    {
        std::string filename = ADDITIONAL_PROFILE_SOURCE_DIR "/add-untouched/test1_add.sd";
        std::list<AppArmor::FileRule> expected_file_rules;

        AppArmor::Parser parser(filename);

        auto profile_list = parser.getProfileList();
        ASSERT_FALSE(profile_list.empty()) << "There should be at least one profile";
        auto prof = profile_list.front();

        std::string filemode = "uxuxuxuxux";
        //Idk why I needed to, but the compiler didn't like it if I used the filemode string without it being declared first
        parser = parser.addRule(prof, "/bin/echo", filemode);

        emplace_back(expected_file_rules, "/bin/echo", "uxuxuxuxux");

        check_file_rules_for_single_profile(filename, expected_file_rules, "/**");
    }

    //Test to add a rule to a file with 1 profile and 1 rule
    TEST(AddFunctionCheck, test2_add) // NOLINT
    {
        std::string filename = ADDITIONAL_PROFILE_SOURCE_DIR "/add-untouched/test2_add.sd";
        std::list<AppArmor::FileRule> expected_file_rules;
        emplace_back(expected_file_rules, "/usr/X11R6/lib/lib*so*", "rrr");

        AppArmor::Parser parser(filename);

        auto profile_list = parser.getProfileList();
        ASSERT_FALSE(profile_list.empty()) << "There should be at least one profile";
        auto prof = profile_list.front();

        std::string filemode = "uxuxuxuxux";
        parser = parser.addRule(prof, "/bin/echo", filemode);
        
        emplace_back(expected_file_rules, "/bin/echo", "uxuxuxuxux");

        check_file_rules_for_single_profile(filename, expected_file_rules, "/**");
    }

    //Test to add 2 rules to a file with 1 profile and 0 rules
    TEST(AddFunctionCheck, test3_add) // NOLINT
    {
        std::string filename = ADDITIONAL_PROFILE_SOURCE_DIR "/add-untouched/test3_add.sd";
        std::list<AppArmor::FileRule> expected_file_rules;

        AppArmor::Parser parser(filename);

        auto profile_list = parser.getProfileList();
        ASSERT_FALSE(profile_list.empty()) << "There should be at least one profile";
        auto prof = profile_list.front();

        std::string filemode1 = "uxuxuxuxux";
        parser = parser.addRule(prof, "/bin/echo", filemode1);

        //Call add-rule function for rule "/var/log/messages www," on profile "/**"
        std::string filemode2 = "www";
        parser = parser.addRule(prof, "/var/log/messages", filemode2);

        emplace_back(expected_file_rules, "/bin/echo", "uxuxuxuxux");
        emplace_back(expected_file_rules, "/var/log/messages", "www");

        check_file_rules_for_single_profile(filename, expected_file_rules, "/**");
    }

    //Test to add 2 rules to a file with 1 profile and 1 rule
    TEST(AddFunctionCheck, test4_add) // NOLINT
    {
        std::string filename = ADDITIONAL_PROFILE_SOURCE_DIR "/add-untouched/test4_add.sd";
        std::list<AppArmor::FileRule> expected_file_rules;
        emplace_back(expected_file_rules, "/usr/X11R6/lib/lib*so*", "rrr");

        AppArmor::Parser parser(filename);

        auto profile_list = parser.getProfileList();
        ASSERT_FALSE(profile_list.empty()) << "There should be at least one profile";
        auto prof = profile_list.front();

        std::string filemode1 = "uxuxuxuxux";
        parser = parser.addRule(prof, "/bin/echo", filemode1);

        //Call add-rule function for rule "/var/log/messages www," on profile "/**"
        std::string filemode2 = "www";
        parser = parser.addRule(prof, "/var/log/messages", filemode2);

        emplace_back(expected_file_rules, "/bin/echo", "uxuxuxuxux");
        emplace_back(expected_file_rules, "/var/log/messages", "www");

        check_file_rules_for_single_profile(filename, expected_file_rules, "/**");
    }

    //Test to add 1 rule to a file with 2 profiles and 0 rules each
    TEST(AddFunctionCheck, test5_add) // NOLINT
    {
        std::string filename = ADDITIONAL_PROFILE_SOURCE_DIR "/add-untouched/test5_add.sd";
        std::list<AppArmor::FileRule> expected_file_rules1;
        std::list<AppArmor::FileRule> expected_file_rules2;

        AppArmor::Parser parser(filename);

        auto profile_list = parser.getProfileList();
        ASSERT_FALSE(profile_list.empty()) << "There should be at least one profile";
        auto prof = profile_list.front();

        std::string filemode = "uxuxuxuxux";
        parser = parser.addRule(prof, "/bin/echo", filemode);

        emplace_back(expected_file_rules1, "/bin/echo", "uxuxuxuxux");

        check_file_rules_for_single_profile(filename, expected_file_rules1, "/**");
        check_file_rules_for_single_profile(filename, expected_file_rules2, "/*");
    }

    //Test to add 1 rule to a file with 2 profiles and 1 rule each
    TEST(AddFunctionCheck, test6_add) // NOLINT
    {
        std::string filename = ADDITIONAL_PROFILE_SOURCE_DIR "/add-untouched/test6_add.sd";
        std::list<AppArmor::FileRule> expected_file_rules1;
        std::list<AppArmor::FileRule> expected_file_rules2;
        emplace_back(expected_file_rules1, "/usr/X11R6/lib/lib*so*", "rrr");
        emplace_back(expected_file_rules2, "/usr/X11R6/lib/lib*so*", "rrr");

        AppArmor::Parser parser(filename);

        auto profile_list = parser.getProfileList();
        ASSERT_FALSE(profile_list.empty()) << "There should be at least one profile";
        auto prof = profile_list.front();

        std::string filemode = "uxuxuxuxux";
        parser = parser.addRule(prof, "/bin/echo", filemode);

        emplace_back(expected_file_rules1, "/bin/echo", "uxuxuxuxux");

        check_file_rules_for_single_profile(filename, expected_file_rules1, "/**");
        check_file_rules_for_single_profile(filename, expected_file_rules2, "/*");
    }

    //Test to add 2 rules to a file with 2 profiles and 0 rules each
    TEST(AddFunctionCheck, test7_add) // NOLINT
    {
        std::string filename = ADDITIONAL_PROFILE_SOURCE_DIR "/add-untouched/test7_add.sd";
        std::list<AppArmor::FileRule> expected_file_rules1;
        std::list<AppArmor::FileRule> expected_file_rules2;

        AppArmor::Parser parser(filename);

        auto profile_list = parser.getProfileList();
        ASSERT_FALSE(profile_list.empty()) << "There should be at least one profile";
        auto prof1 = profile_list.front();

        std::string filemode1 = "uxuxuxuxux";
        parser = parser.addRule(prof1, "/bin/echo", filemode1);

        //Call add-rule function for rule "/var/log/messages www," on profile "/*"
        AppArmor::Profile prof2 = profile_list.back();

        std::string filemode2 = "www";
        parser = parser.addRule(prof2, "/var/log/messages", filemode2);

        emplace_back(expected_file_rules1, "/bin/echo", "uxuxuxuxux");
        emplace_back(expected_file_rules2, "/var/log/messages", "www");

        check_file_rules_for_single_profile(filename, expected_file_rules1, "/**");
        check_file_rules_for_single_profile(filename, expected_file_rules2, "/*");
    }

    //Test to add 2 rules to a file with 2 profiles and 1 rule each
    TEST(AddFunctionCheck, test8_add) // NOLINT
    {
        std::string filename = ADDITIONAL_PROFILE_SOURCE_DIR "/add-untouched/test8_add.sd";
        std::list<AppArmor::FileRule> expected_file_rules1;
        std::list<AppArmor::FileRule> expected_file_rules2;
        emplace_back(expected_file_rules1, "/usr/X11R6/lib/lib*so*", "rrr");
        emplace_back(expected_file_rules2, "/usr/X11R6/lib/lib*so*", "rrr");

        AppArmor::Parser parser(filename);

        auto profile_list = parser.getProfileList();
        ASSERT_FALSE(profile_list.empty()) << "There should be at least one profile";
        auto prof1 = profile_list.front();

        std::string filemode1 = "uxuxuxuxux";
        parser = parser.addRule(prof1, "/bin/echo", filemode1);

        //Call add-rule function for rule "/var/log/messages www," on profile "/*"
        AppArmor::Profile prof2 = profile_list.back();

        std::string filemode2 = "www";
        parser = parser.addRule(prof2, "/var/log/messages", filemode2);

        emplace_back(expected_file_rules1, "/bin/echo", "uxuxuxuxux");
        emplace_back(expected_file_rules2, "/var/log/messages", "www");

        check_file_rules_for_single_profile(filename, expected_file_rules1, "/**");
        check_file_rules_for_single_profile(filename, expected_file_rules2, "/*");
    }
} // namespace AddFunctionCheck