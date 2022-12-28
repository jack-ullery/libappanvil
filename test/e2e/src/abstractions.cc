#include <exception>
#include <fstream>
#include <gtest/gtest-param-test.h>
#include <gtest/gtest.h>
#include <iostream>
#include <unordered_set>

#include "apparmor_parser.hh"

std::list<AppArmor::Profile> getProfileList(std::string filename)
{
	std::fstream stream(filename);
	AppArmor::Parser parser(stream);
	return parser.getProfileList();
}

void check_abstractions_for_single_profile(std::string filename, std::unordered_set<std::string> expected_abstractions, std::string profile_name = "/does/not/exist")
{
    auto profile_list = getProfileList(filename);

    EXPECT_EQ(profile_list.size(), 1) << "There should only be one profile";

    auto first_profile = profile_list.begin();
    EXPECT_EQ(first_profile->getName(), profile_name);

    auto abstractions = first_profile->getAbstractions();
    EXPECT_EQ(abstractions, expected_abstractions);
}

TEST(AbstractionCheck, abi_ok_1)
{
    auto filename = PROFILE_SOURCE_DIR "/abi/ok_1.sd";
    std::unordered_set<std::string> expected_abstractions{};

    check_abstractions_for_single_profile(filename, expected_abstractions);
}

TEST(AbstractionCheck, bare_include_tests_ok_1)
{
    auto filename = PROFILE_SOURCE_DIR "/bare_include_tests/ok_1.sd";
    std::unordered_set<std::string> expected_abstractions{
        "includes/base",
        "include_tests/includes_okay_helper.include"
    };

    check_abstractions_for_single_profile(filename, expected_abstractions);
}

TEST(AbstractionCheck, bare_include_tests_ok_2)
{
    auto filename = PROFILE_SOURCE_DIR "/bare_include_tests/ok_2.sd";
    std::unordered_set<std::string> expected_abstractions{
        "includes/base",
        "include_tests/includes_okay_helper.include"
    };

    check_abstractions_for_single_profile(filename, expected_abstractions);
}

TEST(AbstractionCheck, bare_include_tests_ok_3)
{
    auto filename = PROFILE_SOURCE_DIR "/bare_include_tests/ok_3.sd";
    std::unordered_set<std::string> expected_abstractions{
        "includes/base",
        "includes/"
    };

    check_abstractions_for_single_profile(filename, expected_abstractions);
}

TEST(AbstractionCheck, bare_include_tests_ok_11)
{
    auto filename = PROFILE_SOURCE_DIR "/bare_include_tests/ok_11.sd";
    std::unordered_set<std::string> expected_abstractions{
        "simple_tests/include_tests/includes_okay_helper.include",
    };

    check_abstractions_for_single_profile(filename, expected_abstractions);
}

TEST(AbstractionCheck, bare_include_tests_ok_12)
{
    auto filename = PROFILE_SOURCE_DIR "/bare_include_tests/ok_12.sd";
    std::unordered_set<std::string> expected_abstractions{
        "../tst/simple_tests/include_tests/includes_okay_helper.include",
    };

    check_abstractions_for_single_profile(filename, expected_abstractions);
}

TEST(AbstractionCheck, bare_include_tests_ok_13)
{
    auto filename = PROFILE_SOURCE_DIR "/bare_include_tests/ok_13.sd";
    std::unordered_set<std::string> expected_abstractions{
        "./simple_tests/include_tests/includes_okay_helper.include",
    };

    check_abstractions_for_single_profile(filename, expected_abstractions);
}

TEST(AbstractionCheck, bare_include_tests_ok_14)
{
    auto filename = PROFILE_SOURCE_DIR "/bare_include_tests/ok_14.sd";
    std::unordered_set<std::string> expected_abstractions{
        "includes/base",
        "../tst/simple_tests/include_tests/includes_okay_helper.include",
    };

    check_abstractions_for_single_profile(filename, expected_abstractions);
}

TEST(AbstractionCheck, bare_include_tests_ok_15)
{
    auto filename = PROFILE_SOURCE_DIR "/bare_include_tests/ok_15.sd";
    std::unordered_set<std::string> expected_abstractions{
        "includes/base",
        "simple_tests/includes/",
    };

    check_abstractions_for_single_profile(filename, expected_abstractions);
}

TEST(AbstractionCheck, rewrite_alias_good_2)
{
    auto filename = PROFILE_SOURCE_DIR "/rewrite/alias_good_2.sd";
    std::unordered_set<std::string> expected_abstractions{
        "includes/base",
    };

    check_abstractions_for_single_profile(filename, expected_abstractions, "/bin/foo");
}
