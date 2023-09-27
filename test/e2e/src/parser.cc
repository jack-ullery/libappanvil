#include <gtest/gtest.h>

#include "common.inl"
#include "parser.hh"

TEST(ParserCheck, update_from_string)
{
  auto profile = PROFILE_SOURCE_DIR "/file/ok_1.sd";
  auto new_profile_data = "/usr/bin/foo { /usr/bin/foo rwix, }";

  AppArmor::Parser parser_1(profile);
  AppArmor::Parser parser_2(profile);

  ASSERT_EQ(parser_1.getProfileList(), parser_2.getProfileList());
  ASSERT_NO_THROW(parser_1.updateFromString(new_profile_data));
  ASSERT_NE(parser_1.getProfileList(), parser_2.getProfileList());
}

  // TEST(ParserCheck, update_from_string_fail)
  // {
  //   auto profile = PROFILE_SOURCE_DIR "/file/ok_1.sd";
  //   auto new_profile_data = "/usr/bin/foo { /usr/bin/foo rwix }";

  //   AppArmor::Parser parser_1(profile);
  //   AppArmor::Parser parser_2(profile);

  //   ASSERT_EQ(parser_1.getProfileList(), parser_2.getProfileList());
  //   ASSERT_ANY_THROW(parser_1.updateFromString(new_profile_data));
  //   ASSERT_EQ(parser_1.getProfileList(), parser_2.getProfileList());
  // }

// Broken profiles should throw an exception, without a greater segfault
TEST_P(ParserCheck, fail_gracefully)
{
  std::string profile = ADDITIONAL_PROFILE_SOURCE_DIR + GetParam();

  ASSERT_NO_FATAL_FAILURE(
    EXPECT_ANY_THROW(AppArmor::Parser parser(profile));
  );
}

INSTANTIATE_TEST_SUITE_P(Parameterized, ParserCheck, testing::ValuesIn(broken_profiles));
