#include <exception>
#include <fstream>
#include <gtest/gtest-param-test.h>
#include <gtest/gtest.h>
#include <iostream>
#include <unordered_set>

#include "apparmor_parser.hh"

namespace FileRuleCheck {
    std::list<AppArmor::Profile> getProfileList(std::string filename)
    {
        std::ifstream stream(filename);
        AppArmor::Parser parser(stream);
        return parser.getProfileList();
    }

    void check_file_rules_for_single_profile(std::string filename, std::list<AppArmor::FileRule> expected_file_rules, std::string profile_name = "/does/not/exist")
    {
        auto profile_list = getProfileList(filename);

        EXPECT_EQ(profile_list.size(), 1) << "There should only be one profile";

        auto first_profile = profile_list.begin();
        EXPECT_EQ(first_profile->name(), profile_name);

        auto file_rules = first_profile->getFileRules();
        ASSERT_EQ(file_rules, expected_file_rules);
    }

    TEST(FileRuleCheck, abi_ok_1)
    {
        auto filename = PROFILE_SOURCE_DIR "/abi/ok_1.sd";
        std::list<AppArmor::FileRule> expected_abstractions{};

        check_file_rules_for_single_profile(filename, expected_abstractions);
    }
}
