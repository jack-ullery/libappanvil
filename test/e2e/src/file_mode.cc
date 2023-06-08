#include <exception>
#include <fstream>
#include <gtest/gtest-param-test.h>
#include <gtest/gtest.h>
#include <iostream>
#include <memory>
#include <unordered_set>

#include "tree/FileMode.hh"
#include "common.inl"

using Common::emplace_back;

namespace FileModeCheck {
  inline void check_permissions(const AppArmor::Tree::FileMode &file_mode,
                                bool expect_read = false,
                                bool expect_write = false,
                                bool expect_append = false,
                                bool expect_mmap = false,
                                bool expect_link = false,
                                bool expect_lock = false,
                                const std::string exec_mode = "")
  {
    ASSERT_EQ(file_mode.getRead(), expect_read);
    ASSERT_EQ(file_mode.getWrite(), expect_write);
    ASSERT_EQ(file_mode.getAppend(), expect_append);
    ASSERT_EQ(file_mode.getMemoryMap(), expect_mmap);
    ASSERT_EQ(file_mode.getLink(), expect_link);
    ASSERT_EQ(file_mode.getLock(), expect_lock);
    ASSERT_EQ(file_mode.getExecuteMode(), exec_mode);
  }

  TEST(FileModeCheck, read)
  {
    AppArmor::Tree::FileMode file_mode("r");
    check_permissions(file_mode, true);
  }

  TEST(FileModeCheck, write)
  {
    AppArmor::Tree::FileMode file_mode("w");
    check_permissions(file_mode, false, true);
  }

  TEST(FileModeCheck, append)
  {
    AppArmor::Tree::FileMode file_mode("a");
    check_permissions(file_mode, false, false, true);
  }

  TEST(FileModeCheck, mmap)
  {
    AppArmor::Tree::FileMode file_mode("m");
    check_permissions(file_mode, false, false, false, true);
  }

  TEST(FileModeCheck, link)
  {
    AppArmor::Tree::FileMode file_mode("l");
    check_permissions(file_mode, false, false, false, false, true);
  }

  TEST(FileModeCheck, lock)
  {
    AppArmor::Tree::FileMode file_mode("k");
    check_permissions(file_mode, false, false, false, false, false, true);
  }

  TEST(FileModeCheck, write_append_conflict)
  {
    EXPECT_ANY_THROW(AppArmor::Tree::FileMode("wa"));
    EXPECT_ANY_THROW(AppArmor::Tree::FileMode("aw"));
  }

  TEST(FileModeCheck, unconfined_execute)
  {
    const std::string execute_mode = "ux";
    AppArmor::Tree::FileMode file_mode(execute_mode);
    check_permissions(file_mode, false, false, false, false, false, false, execute_mode);
  }

  TEST(FileModeCheck, unconfined_execute_scrub)
  {
    const std::string execute_mode = "Ux";
    AppArmor::Tree::FileMode file_mode(execute_mode);
    check_permissions(file_mode, false, false, false, false, false, false, execute_mode);
  }

  TEST(FileModeCheck, discrete_profile_execute)
  {
    const std::string execute_mode = "px";
    AppArmor::Tree::FileMode file_mode(execute_mode);
    check_permissions(file_mode, false, false, false, false, false, false, execute_mode);
  }

  TEST(FileModeCheck, discrete_profile_execute_scrub)
  {
    const std::string execute_mode = "Px";
    AppArmor::Tree::FileMode file_mode(execute_mode);
    check_permissions(file_mode, false, false, false, false, false, false, execute_mode);
  }

  TEST(FileModeCheck, subprofile_execute)
  {
    const std::string execute_mode = "cx";
    AppArmor::Tree::FileMode file_mode(execute_mode);
    check_permissions(file_mode, false, false, false, false, false, false, execute_mode);
  }

  TEST(FileModeCheck, subprofile_execute_scrub)
  {
    const std::string execute_mode = "Cx";
    AppArmor::Tree::FileMode file_mode(execute_mode);
    check_permissions(file_mode, false, false, false, false, false, false, execute_mode);
  }

  TEST(FileModeCheck, inherit_execute)
  {
    const std::string execute_mode = "ix";
    AppArmor::Tree::FileMode file_mode(execute_mode);
    check_permissions(file_mode, false, false, false, false, false, false, execute_mode);
  }

  TEST(FileModeCheck, discrete_profile_execute_inherit_fallback)
  {
    const std::string execute_mode = "pix";
    AppArmor::Tree::FileMode file_mode(execute_mode);
    check_permissions(file_mode, false, false, false, false, false, false, execute_mode);
  }

  TEST(FileModeCheck, discrete_profile_execute_scrub_inherit_fallback)
  {
    const std::string execute_mode = "Pix";
    AppArmor::Tree::FileMode file_mode(execute_mode);
    check_permissions(file_mode, false, false, false, false, false, false, execute_mode);
  }

  TEST(FileModeCheck, subprofile_execute_inherit_fallback)
  {
    const std::string execute_mode = "cix";
    AppArmor::Tree::FileMode file_mode(execute_mode);
    check_permissions(file_mode, false, false, false, false, false, false, execute_mode);
  }

  TEST(FileModeCheck, subprofile_execute_scrub_inherit_fallback)
  {
    const std::string execute_mode = "Cix";
    AppArmor::Tree::FileMode file_mode(execute_mode);
    check_permissions(file_mode, false, false, false, false, false, false, execute_mode);
  }

  TEST(FileModeCheck, discrete_profile_execute_unconfined_fallback)
  {
    const std::string execute_mode = "pux";
    AppArmor::Tree::FileMode file_mode(execute_mode);
    check_permissions(file_mode, false, false, false, false, false, false, execute_mode);
  }

  TEST(FileModeCheck, discrete_profile_execute_scrub_unconfined_fallback)
  {
    const std::string execute_mode = "Pux";
    AppArmor::Tree::FileMode file_mode(execute_mode);
    check_permissions(file_mode, false, false, false, false, false, false, execute_mode);
  }

  TEST(FileModeCheck, subprofile_execute_unconfined_fallback)
  {
    const std::string execute_mode = "cux";
    AppArmor::Tree::FileMode file_mode(execute_mode);
    check_permissions(file_mode, false, false, false, false, false, false, execute_mode);
  }

  TEST(FileModeCheck, subprofile_execute_scrub_unconfined_fallback)
  {
    const std::string execute_mode = "Cux";
    AppArmor::Tree::FileMode file_mode(execute_mode);
    check_permissions(file_mode, false, false, false, false, false, false, execute_mode);
  }

} // namespace FileModeCheck
