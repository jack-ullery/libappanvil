#include <exception>
#include <fstream>
#include <gtest/gtest-param-test.h>
#include <gtest/gtest.h>
#include <iostream>
#include <memory>
#include <unordered_set>

#include "apparmor_parser.hh"
#include "parser/tree/FileNode.hh"

namespace AddFunctionCheck {
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
    TEST(AddFunctionCheck, test1_add)
    {
        auto filename = PROFILE_SOURCE_DIR "/add-untouched/test1_add.sd";
        std::list<AppArmor::FileRule> expected_file_rules;

        //Call add-rule function for rule "/bin/echo uxuxuxuxux," on profile "/**"
        std::ifstream stream(filename);
        AppArmor::Parser addParser(stream);

        AppArmor::Profile prof = addParser.getProfileList().front();

        std::string filemode = "uxuxuxuxux";
        //Idk why I needed to, but the compiler didn't like it if I used the filemode string without it being declared first
        addParser = addParser.addRule(filename, prof, "/bin/echo", filemode);

        emplace_back(expected_file_rules, "/bin/echo", "uxuxuxuxux");

        check_file_rules_for_single_profile(filename, expected_file_rules, "/**");
    }

    //Test to add a rule to a file with 1 profile and 1 rule
    TEST(AddFunctionCheck, test2_add)
    {
        auto filename = PROFILE_SOURCE_DIR "/add-untouched/test2_add.sd";
        std::list<AppArmor::FileRule> expected_file_rules;
        emplace_back(expected_file_rules, "/usr/X11R6/lib/lib*so*", "rrr");

        //Call add-rule function for rule "/bin/echo uxuxuxuxux," on profile "/**"
        std::ifstream stream(filename);
        AppArmor::Parser addParser(stream);

        AppArmor::Profile prof = addParser.getProfileList().front();

        std::string filemode = "uxuxuxuxux";
        addParser = addParser.addRule(filename, prof, "/bin/echo", filemode);
        
        emplace_back(expected_file_rules, "/bin/echo", "uxuxuxuxux");

        check_file_rules_for_single_profile(filename, expected_file_rules, "/**");
    }

    //Test to add 2 rules to a file with 1 profile and 0 rules
    TEST(AddFunctionCheck, test3_add)
    {
        auto filename = PROFILE_SOURCE_DIR "/add-untouched/test3_add.sd";
        std::list<AppArmor::FileRule> expected_file_rules;

        //Call add-rule function for rule "/bin/echo uxuxuxuxux," on profile "/**"
        std::ifstream stream(filename);
        AppArmor::Parser addParser(stream);

        AppArmor::Profile prof = addParser.getProfileList().front();

        std::string filemode1 = "uxuxuxuxux";
        addParser = addParser.addRule(filename, prof, "/bin/echo", filemode1);

        //Call add-rule function for rule "/var/log/messages www," on profile "/**"
        std::string filemode2 = "www";
        addParser = addParser.addRule(filename, prof, "/var/log/messages", filemode2);


       emplace_back(expected_file_rules, "/bin/echo", "uxuxuxuxux");
       emplace_back(expected_file_rules, "/var/log/messages", "www");

       check_file_rules_for_single_profile(filename, expected_file_rules, "/**");
    }

    //Test to add 2 rules to a file with 1 profile and 1 rule
    TEST(AddFunctionCheck, test4_add)
    {
        auto filename = PROFILE_SOURCE_DIR "/add-untouched/test4_add.sd";
        std::list<AppArmor::FileRule> expected_file_rules;
        emplace_back(expected_file_rules, "/usr/X11R6/lib/lib*so*", "rrr");

        //Call add-rule function for rule "/bin/echo uxuxuxuxux," on profile "/**"
        std::ifstream stream(filename);
        AppArmor::Parser addParser(stream);

        AppArmor::Profile prof = addParser.getProfileList().front();

        std::string filemode1 = "uxuxuxuxux";
        addParser = addParser.addRule(filename, prof, "/bin/echo", filemode1);

        //Call add-rule function for rule "/var/log/messages www," on profile "/**"
        std::string filemode2 = "www";
        addParser = addParser.addRule(filename, prof, "/var/log/messages", filemode2);

        emplace_back(expected_file_rules, "/bin/echo", "uxuxuxuxux");
        emplace_back(expected_file_rules, "/var/log/messages", "www");
    }

    //Test to add 1 rule to a file with 2 profiles and 0 rules each
    TEST(AddFunctionCheck, test5_add)
    {
        auto filename = PROFILE_SOURCE_DIR "/add-untouched/test5_add.sd";
        std::list<AppArmor::FileRule> expected_file_rules1;
        std::list<AppArmor::FileRule> expected_file_rules2;

        //Call add-rule function for rule "/bin/echo uxuxuxuxux," on profile "/**"

       emplace_back(expected_file_rules1, "/bin/echo", "uxuxuxuxux");
    }

    //Test to add 1 rule to a file with 2 profiles and 1 rule each
    TEST(AddFunctionCheck, test6_add)
    {
        auto filename = PROFILE_SOURCE_DIR "/add-untouched/test6_add.sd";
        std::list<AppArmor::FileRule> expected_file_rules1;
        std::list<AppArmor::FileRule> expected_file_rules2;
        emplace_back(expected_file_rules1, "/usr/X11R6/lib/lib*so*", "rrr");
        emplace_back(expected_file_rules2, "/usr/X11R6/lib/lib*so*", "rrr");

        //Call add-rule function for rule "/bin/echo uxuxuxuxux," on profile "/**"

       emplace_back(expected_file_rules1, "/bin/echo", "uxuxuxuxux");
    }

    //Test to add 2 rules to a file with 2 profiles and 0 rules each
    TEST(AddFunctionCheck, test7_add)
    {
        auto filename = PROFILE_SOURCE_DIR "/add-untouched/test7_add.sd";
        std::list<AppArmor::FileRule> expected_file_rules1;
        std::list<AppArmor::FileRule> expected_file_rules2;

        //Call add-rule function for rule "/bin/echo uxuxuxuxux," on profile "/**"
        //Call add-rule function for rule "/var/log/messages www," on profile "/*"

       emplace_back(expected_file_rules1, "/bin/echo", "uxuxuxuxux");
       emplace_back(expected_file_rules2, "/var/log/messages", "www");
    }

    //Test to add 2 rules to a file with 2 profiles and 1 rule each
    TEST(AddFunctionCheck, test8_add)
    {
        auto filename = PROFILE_SOURCE_DIR "/add-untouched/test8_add.sd";
        std::list<AppArmor::FileRule> expected_file_rules1;
        std::list<AppArmor::FileRule> expected_file_rules2;
        emplace_back(expected_file_rules1, "/usr/X11R6/lib/lib*so*", "rrr");
        emplace_back(expected_file_rules2, "/usr/X11R6/lib/lib*so*", "rrr");

        //Call add-rule function for rule "/bin/echo uxuxuxuxux," on profile "/**"
        //Call add-rule function for rule "/var/log/messages www," on profile "/*"

       emplace_back(expected_file_rules1, "/bin/echo", "uxuxuxuxux");
       emplace_back(expected_file_rules2, "/var/log/messages", "www");
    }
}