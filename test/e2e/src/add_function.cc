#include <exception>
#include <fstream>
#include <gtest/gtest-param-test.h>
#include <gtest/gtest.h>
#include <iostream>
#include <memory>
#include <unordered_set>

#include "apparmor_parser.hh"
#include "parser/tree/FileNode.hh"

namespace RemoveFunctionCheck {
    std::list<AppArmor::Profile> getProfileList(std::string filename)
    {
        std::ifstream stream(filename);
        AppArmor::Parser parser(stream);
        return parser.getProfileList();
    }

    void check_file_rules_for_single_profile(std::string filename, std::list<AppArmor::FileRule> expected_file_rules, std::string profile_name)
    {
        auto profile_list = getProfileList(filename);

        while(profile_name.compare(profile_list.front().name()) != 0 && profile_list.size() != 0){
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

    //Quick reference for rule and rule mode to add
    //          /bin/echo uxuxuxuxux,
    //          /var/log/messages www,

    //Test to add a rule to a file with 1 profile and 0 rules
    TEST(RemoveFunctionCheck, test1)
    {
        auto filename = PROFILE_SOURCE_DIR "/add-untouched/test1-add.sd";
        std::list<AppArmor::FileRule> expected_file_rules;

        /*
        Call add-rule function for rule "/bin/echo uxuxuxuxux," on profile "/**"
        */

       emplace_back(expected_file_rules, "/bin/echo", "uxuxuxuxux");
    }

    //Test to add a rule to a file with 1 profile and 1 rule
    TEST(RemoveFunctionCheck, test2)
    {
        auto filename = PROFILE_SOURCE_DIR "/add-untouched/test2-add.sd";
        std::list<AppArmor::FileRule> expected_file_rules;
        emplace_back(expected_file_rules, "/usr/X11R6/lib/lib*so*", "rrr");

        /*
        Call add-rule function for rule "/bin/echo uxuxuxuxux," on profile "/**"
        */

       emplace_back(expected_file_rules, "/bin/echo", "uxuxuxuxux");
    }

    //Test to add 2 rules to a file with 1 profile and 0 rules
    TEST(RemoveFunctionCheck, test3)
    {
        auto filename = PROFILE_SOURCE_DIR "/add-untouched/test3-add.sd";
        std::list<AppArmor::FileRule> expected_file_rules;

        /*
        Call add-rule function for rule "/bin/echo uxuxuxuxux," on profile "/**"
        Call add-rule function for rule "/var/log/messages www," on profile "/**"
        */

       emplace_back(expected_file_rules, "/bin/echo", "uxuxuxuxux");
       emplace_back(expected_file_rules, "/var/log/messages", "www");
    }

    //Test to add 2 rules to a file with 1 profile and 1 rule
    TEST(RemoveFunctionCheck, test4)
    {
        auto filename = PROFILE_SOURCE_DIR "/add-untouched/test4-add.sd";
        std::list<AppArmor::FileRule> expected_file_rules;
        emplace_back(expected_file_rules, "/usr/X11R6/lib/lib*so*", "rrr");

        /*
        Call add-rule function for rule "/bin/echo uxuxuxuxux," on profile "/**"
        Call add-rule function for rule "/var/log/messages www," on profile "/**"
        */

       emplace_back(expected_file_rules, "/bin/echo", "uxuxuxuxux");
       emplace_back(expected_file_rules, "/var/log/messages", "www");
    }

    //Test to add 1 rule to a file with 2 profiles and 0 rules each
    TEST(RemoveFunctionCheck, test5)
    {
        auto filename = PROFILE_SOURCE_DIR "/add-untouched/test5-add.sd";
        std::list<AppArmor::FileRule> expected_file_rules1;
        std::list<AppArmor::FileRule> expected_file_rules2;

        /*
        Call add-rule function for rule "/bin/echo uxuxuxuxux," on profile "/**"
        */

       emplace_back(expected_file_rules1, "/bin/echo", "uxuxuxuxux");
    }

    //Test to add 1 rule to a file with 2 profiles and 1 rule each
    TEST(RemoveFunctionCheck, test6)
    {
        auto filename = PROFILE_SOURCE_DIR "/add-untouched/test6-add.sd";
        std::list<AppArmor::FileRule> expected_file_rules1;
        std::list<AppArmor::FileRule> expected_file_rules2;
        emplace_back(expected_file_rules1, "/usr/X11R6/lib/lib*so*", "rrr");
        emplace_back(expected_file_rules2, "/usr/X11R6/lib/lib*so*", "rrr");

        /*
        Call add-rule function for rule "/bin/echo uxuxuxuxux," on profile "/**"
        */

       emplace_back(expected_file_rules1, "/bin/echo", "uxuxuxuxux");
    }

    //Test to add 2 rules to a file with 2 profiles and 0 rules each
    TEST(RemoveFunctionCheck, test7)
    {
        auto filename = PROFILE_SOURCE_DIR "/add-untouched/test7-add.sd";
        std::list<AppArmor::FileRule> expected_file_rules1;
        std::list<AppArmor::FileRule> expected_file_rules2;

        /*
        Call add-rule function for rule "/bin/echo uxuxuxuxux," on profile "/**"
        Call add-rule function for rule "/var/log/messages www," on profile "/*"
        */

       emplace_back(expected_file_rules1, "/bin/echo", "uxuxuxuxux");
       emplace_back(expected_file_rules2, "/var/log/messages", "www");
    }

    //Test to add 2 rules to a file with 2 profiles and 1 rule each
    TEST(RemoveFunctionCheck, test8)
    {
        auto filename = PROFILE_SOURCE_DIR "/add-untouched/test8-add.sd";
        std::list<AppArmor::FileRule> expected_file_rules1;
        std::list<AppArmor::FileRule> expected_file_rules2;
        emplace_back(expected_file_rules1, "/usr/X11R6/lib/lib*so*", "rrr");
        emplace_back(expected_file_rules2, "/usr/X11R6/lib/lib*so*", "rrr");

        /*
        Call add-rule function for rule "/bin/echo uxuxuxuxux," on profile "/**"
        Call add-rule function for rule "/var/log/messages www," on profile "/*"
        */

       emplace_back(expected_file_rules1, "/bin/echo", "uxuxuxuxux");
       emplace_back(expected_file_rules2, "/var/log/messages", "www");
    }
}