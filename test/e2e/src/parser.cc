#include <gtest/gtest.h>

#include "common.inl"

using Common::emplace_back;

// Grab bag of random AppArmor::Parser tests that are not covered in other files
namespace ParserCheck {
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

} // namespace FileModeCheck
