#include <exception>
#include <fstream>
#include <gtest/gtest-param-test.h>
#include <gtest/gtest.h>
#include <iostream>
#include <list>

#include "apparmor_parser.hh"

namespace AbstractionCheck {
  void check_abstractions_for_single_profile(std::string filename, std::list<std::string> expected_abstractions, std::string profile_name = "/does/not/exist")
  {
    AppArmor::Parser parser(filename);
    auto profile_list = parser.getProfileList();

    EXPECT_EQ(profile_list.size(), 1) << "There should only be one profile";

    auto first_profile = profile_list.begin();
    EXPECT_EQ(first_profile->name(), profile_name);

    auto abstractions = first_profile->getAbstractions();
    EXPECT_EQ(abstractions.size(), expected_abstractions.size()) << "There should be the same number of abstractions";

    // Iterate over every value of each list to ensure that they point to the same path
    auto abs_it = abstractions.begin();
    auto str_it = expected_abstractions.begin();
    while(abs_it != abstractions.end() && 
          str_it != expected_abstractions.end())
    {
      EXPECT_EQ(abs_it->getPath(), *str_it);

      // Increment iterator
      abs_it++;
      str_it++;
    }
  }

  TEST(AbstractionCheck, abi_ok_1)
  {
    auto filename = PROFILE_SOURCE_DIR "/abi/ok_1.sd";
    std::list<std::string> expected_abstractions{};

    check_abstractions_for_single_profile(filename, expected_abstractions);
  }

  TEST(AbstractionCheck, bare_include_tests_ok_1)
  {
    auto filename = PROFILE_SOURCE_DIR "/bare_include_tests/ok_1.sd";
    std::list<std::string> expected_abstractions{
      "includes/base",
      "include_tests/includes_okay_helper.include",
      "includes/base"
    };

    check_abstractions_for_single_profile(filename, expected_abstractions);
  }

  TEST(AbstractionCheck, bare_include_tests_ok_2)
  {
    auto filename = PROFILE_SOURCE_DIR "/bare_include_tests/ok_2.sd";
    std::list<std::string> expected_abstractions{
      "includes/base",
      "include_tests/includes_okay_helper.include",
      "includes/base",
    };

    check_abstractions_for_single_profile(filename, expected_abstractions);
  }

  TEST(AbstractionCheck, bare_include_tests_ok_3)
  {
    auto filename = PROFILE_SOURCE_DIR "/bare_include_tests/ok_3.sd";
    std::list<std::string> expected_abstractions{
      "includes/base",
      "includes/",
      "includes/base",
    };

    check_abstractions_for_single_profile(filename, expected_abstractions);
  }

  TEST(AbstractionCheck, bare_include_tests_ok_11)
  {
    auto filename = PROFILE_SOURCE_DIR "/bare_include_tests/ok_11.sd";
    std::list<std::string> expected_abstractions{
      "simple_tests/include_tests/includes_okay_helper.include",
    };

    check_abstractions_for_single_profile(filename, expected_abstractions);
  }

  TEST(AbstractionCheck, bare_include_tests_ok_12)
  {
    auto filename = PROFILE_SOURCE_DIR "/bare_include_tests/ok_12.sd";
    std::list<std::string> expected_abstractions{
      "../tst/simple_tests/include_tests/includes_okay_helper.include",
    };

    check_abstractions_for_single_profile(filename, expected_abstractions);
  }

  TEST(AbstractionCheck, bare_include_tests_ok_13)
  {
    auto filename = PROFILE_SOURCE_DIR "/bare_include_tests/ok_13.sd";
    std::list<std::string> expected_abstractions{
      "./simple_tests/include_tests/includes_okay_helper.include",
    };

    check_abstractions_for_single_profile(filename, expected_abstractions);
  }

  TEST(AbstractionCheck, bare_include_tests_ok_14)
  {
    auto filename = PROFILE_SOURCE_DIR "/bare_include_tests/ok_14.sd";
    std::list<std::string> expected_abstractions{
      "includes/base",
      "../tst/simple_tests/include_tests/includes_okay_helper.include",
      "includes/base",
    };

    check_abstractions_for_single_profile(filename, expected_abstractions);
  }

  TEST(AbstractionCheck, bare_include_tests_ok_15)
  {
    auto filename = PROFILE_SOURCE_DIR "/bare_include_tests/ok_15.sd";
    std::list<std::string> expected_abstractions{
      "includes/base",
      "simple_tests/includes/",
      "includes/base",
    };

    check_abstractions_for_single_profile(filename, expected_abstractions);
  }

  TEST(AbstractionCheck, rewrite_alias_good_2)
  {
    auto filename = PROFILE_SOURCE_DIR "/rewrite/alias_good_2.sd";
    std::list<std::string> expected_abstractions{
      "includes/base",
    };

    check_abstractions_for_single_profile(filename, expected_abstractions, "/bin/foo");
  }
}
