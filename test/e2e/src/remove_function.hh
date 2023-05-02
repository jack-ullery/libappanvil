#ifndef REMOVE_FUNCTION_HH
#define REMOVE_FUNCTION_HH

#include <gtest/gtest.h>

#include "apparmor_file_rule.hh"
#include "apparmor_parser.hh"
#include "apparmor_profile.hh"

class RemoveFunctionCheck : public ::testing::Test {
public:
  void SetUp()
  {
    temp_file = ADDITIONAL_PROFILE_SOURCE_DIR "/remove-untouched/temp.sd";
  }

  void TearDown()
  {
    std::remove(temp_file.c_str());
  }

protected:
  // File that will be written to and read from temporarily for testing purposes
  std::string temp_file;

  // Removes the first file rule from the first profile, writing chages to the temp_file
  inline void remove_file_rule_from_first_profile(AppArmor::Parser &parser);

  // Checks that the AppArmor::Parser contains a profile with the expected file rules
  inline void check_file_rules_for_profile(const AppArmor::Parser &parser,
                                           const std::list<AppArmor::FileRule> &expected_file_rules,
                                           const std::string &profile_name);
};

#endif // REMOVE_FUNCTION_HH