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

    void emplace_back(std::list<AppArmor::FileRule> &list, const std::string &filename, const std::string &filemode)
    {
        FileNode node(0, 1, filename, filemode);
        auto node_pointer = std::make_shared<FileNode>(node);
        AppArmor::FileRule rule(node_pointer);
        list.emplace_back(rule);
    }

    //Test to remove a rule from a file with 1 profile and 1 rule
    TEST(RemoveFunctionCheck, test1)
    {
        auto filename = PROFILE_SOURCE_DIR "/remove-untouched/test1.sd";
        std::list<AppArmor::FileRule> expected_file_rules;

        //remove rule /usr/X11R6/lib/lib*so* rrr,

        check_file_rules_for_single_profile(filename, expected_file_rules, "/**");
    }

    //Test to remove a rule from a file with 1 profile and more than 1 rule
    TEST(RemoveFunctionCheck, test2)
    {
        auto filename = PROFILE_SOURCE_DIR "/remove-untouched/test2.sd";
        std::list<AppArmor::FileRule> expected_file_rules;

        emplace_back(expected_file_rules, /does/not/exist, r);
        emplace_back(expected_file_rules, /var/log/messages, www);

        //remove rule /usr/X11R6/lib/lib*so* rrr,

        check_file_rules_for_single_profile(filename, expected_file_rules, "/**");
    }

    //Test to remove a rule from a file with 2 profiles and 1 rule each
    TEST(RemoveFunctionCheck, test3)
    {
        auto filename = PROFILE_SOURCE_DIR "/remove-untouched/test3.sd";
        std::list<AppArmor::FileRule> expected_file_rules1;
        std::list<AppArmor::FileRule> expected_file_rules2;

        emplace_back(expected_file_rules2, /usr/X11R6/lib/lib*so*, rrr);

        //remove rule /usr/X11R6/lib/lib*so* rrr, from profile /**

        check_file_rules_for_single_profile(filename, expected_file_rules1, "/**");
        check_file_rules_for_single_profile(filename, expected_file_rules2, "/*");
    }

    //Test to remove a rule from a file with 2 profiles and more than 1 rule each
    TEST(RemoveFunctionCheck, test4)
    {
        auto filename = PROFILE_SOURCE_DIR "/remove-untouched/test4.sd";
        std::list<AppArmor::FileRule> expected_file_rules1;
        std::list<AppArmor::FileRule> expected_file_rules2;

        emplace_back(expected_file_rules1, /does/not/exist, r);
        emplace_back(expected_file_rules1, /var/log/messages, www);

        emplace_back(expected_file_rules2, /usr/X11R6/lib/lib*so*, rrr);
        emplace_back(expected_file_rules2, /does/not/exist, r);
        emplace_back(expected_file_rules2, /var/log/messages, www);

        //remove rule /usr/X11R6/lib/lib*so* rrr, from profile /**

        check_file_rules_for_single_profile(filename, expected_file_rules1, "/**");
        check_file_rules_for_single_profile(filename, expected_file_rules2, "/*");
    }

    //Test to remove a rule that DNI from a file with 1 profile and 1 rule
    TEST(RemoveFunctionCheck, test5)
    {
        auto filename = PROFILE_SOURCE_DIR "/remove-untouched/test5.sd";
        std::list<AppArmor::FileRule> expected_file_rules;

        emplace_back(expected_file_rules, /usr/X11R6/lib/lib*so*, rrr);

        //remove nonexistant rule from profile /**

        check_file_rules_for_single_profile(filename, expected_file_rules, "/**");
    }

    //Test to remove a rule from a profile that DNI from a file with 1 profile and 1 rule
    TEST(RemoveFunctionCheck, test6)
    {
        auto filename = PROFILE_SOURCE_DIR "/remove-untouched/test6.sd";
        std::list<AppArmor::FileRule> expected_file_rules;

        emplace_back(expected_file_rules, /usr/X11R6/lib/lib*so*, rrr);

        //remove rule /usr/X11R6/lib/lib*so* rrr, from nonexistant profile

        check_file_rules_for_single_profile(filename, expected_file_rules, "/**");
    }
}
