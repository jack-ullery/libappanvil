#ifndef EDIT_FUNCTION_HH
#define EDIT_FUNCTION_HH

#include <gtest/gtest.h>

#include "apparmor_parser.hh"
#include "tree/FileNode.hh"
#include "tree/ProfileNode.hh"

class EditFunctionCheck : public ::testing::Test {
public:
  void SetUp()
  {
    temp_file = ADDITIONAL_PROFILE_SOURCE_DIR "/temp.sd";
  }

  void TearDown()
  {
    std::ignore = std::remove(temp_file.c_str());
  }

protected:
  // File that will be written to and read from temporarily for testing purposes
  std::string temp_file; // NOLINT

  // Edits a file rule in a profile
  inline void edit_file_rule_in_profile(AppArmor::Parser &parser, 
                                        const std::string &fileglob,
                                        const std::string &filemode,
                                        std::list<AppArmor::FileRule> &expected_file_rules,
                                        const bool &first_profile = true,
                                        const bool &first_rule = true);
};

#endif // EDIT_FUNCTION_HH