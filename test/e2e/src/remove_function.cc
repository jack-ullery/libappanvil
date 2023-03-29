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

    //Test to remove a rule from a file with 1 profile and 1 rule
    TEST(RemoveFunctionCheck, test1_remove)
    {
        auto filename = PROFILE_SOURCE_DIR "/remove-untouched/test1_remove.sd";
        std::cout << "Got profile";
        
        std::list<AppArmor::FileRule> expected_file_rules;

        //remove rule /usr/X11R6/lib/lib*so* rrr,
        //Something between here and the check_file_rules method is making the test fail
        std::ifstream stream(filename);
        AppArmor::Parser removeParser(stream);

        AppArmor::Profile prof = removeParser.getProfileList().front();
        AppArmor::FileRule frule = prof.getFileRules().front();
        
        removeParser = removeParser.removeRule(filename, prof, frule);
        std::cout << "Removed rule";

        check_file_rules_for_single_profile(filename, expected_file_rules, "/**");
        std::cout << "Checked for assertions";
    }

    //Test to remove a rule from a file with 1 profile and more than 1 rule
    TEST(RemoveFunctionCheck, test2_remove)
    {
        auto filename = PROFILE_SOURCE_DIR "/remove-untouched/test2_remove.sd";
        std::list<AppArmor::FileRule> expected_file_rules;

        emplace_back(expected_file_rules, "/does/not/exist", "r");
        emplace_back(expected_file_rules, "/var/log/messages", "www");

        //remove rule /usr/X11R6/lib/lib*so* rrr,
        std::ifstream stream(filename);
        AppArmor::Parser removeParser(stream);

        AppArmor::Profile prof = removeParser.getProfileList().front();
        AppArmor::FileRule frule = prof.getFileRules().front();

        removeParser = removeParser.removeRule(filename, prof, frule);

        check_file_rules_for_single_profile(filename, expected_file_rules, "/**");
    }

    //Test to remove a rule from a file with 2 profiles and 1 rule each
    TEST(RemoveFunctionCheck, test3_remove)
    {
        auto filename = PROFILE_SOURCE_DIR "/remove-untouched/test3_remove.sd";
        std::list<AppArmor::FileRule> expected_file_rules1;
        std::list<AppArmor::FileRule> expected_file_rules2;

        emplace_back(expected_file_rules2, "/usr/X11R6/lib/lib*so*", "rrr");

        //remove rule /usr/X11R6/lib/lib*so* rrr, from profile /**
        std::ifstream stream(filename);
        AppArmor::Parser removeParser(stream);

        AppArmor::Profile prof = removeParser.getProfileList().front();
        AppArmor::FileRule frule = prof.getFileRules().front();

        removeParser = removeParser.removeRule(filename, prof, frule);

        check_file_rules_for_single_profile(filename, expected_file_rules1, "/**");
        check_file_rules_for_single_profile(filename, expected_file_rules2, "/*");
    }

    //Test to remove a rule from a file with 2 profiles and more than 1 rule each
    TEST(RemoveFunctionCheck, test4_remove)
    {
        auto filename = PROFILE_SOURCE_DIR "/remove-untouched/test4_remove.sd";
        std::list<AppArmor::FileRule> expected_file_rules1;
        std::list<AppArmor::FileRule> expected_file_rules2;

        emplace_back(expected_file_rules1, "/does/not/exist", "r");
        emplace_back(expected_file_rules1, "/var/log/messages", "www");

        emplace_back(expected_file_rules2, "/usr/X11R6/lib/lib*so*", "rrr");
        emplace_back(expected_file_rules2, "/does/not/exist", "r");
        emplace_back(expected_file_rules2, "/var/log/messages", "www");

        //remove rule /usr/X11R6/lib/lib*so* rrr, from profile /**
        std::ifstream stream(filename);
        AppArmor::Parser removeParser(stream);

        AppArmor::Profile prof = removeParser.getProfileList().front();
        AppArmor::FileRule frule = prof.getFileRules().front();

        removeParser = removeParser.removeRule(filename, prof, frule);

        check_file_rules_for_single_profile(filename, expected_file_rules1, "/**");
        check_file_rules_for_single_profile(filename, expected_file_rules2, "/*");
    }
}