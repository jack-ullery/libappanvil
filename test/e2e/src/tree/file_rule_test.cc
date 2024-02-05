#include <gtest/gtest.h>
#include <string>

#include "file_rule_test.hh"
#include "apparmor_parser.hh"
#include "tree/FileRule.hh"

inline void check_file_rule(const AppArmor::Tree::FileRule &rule,
                            const std::string &path,
                            const AppArmor::Tree::FileMode &mode,
                            const std::string &exec_target,
                            const std::string &expected_output_string)
{
    EXPECT_EQ(rule.getFilename(), path);
    EXPECT_EQ(rule.getFilemode(), mode);
    EXPECT_EQ(rule.getExecTarget(), exec_target);
    EXPECT_EQ(rule.operator std::string(), expected_output_string);
}

inline void test_file_rule(const std::string &path,
                           const std::string &mode,
                           const std::string &exec_target,
                           const std::string &expected_output_string)
{
    AppArmor::Tree::FileMode file_mode(mode);
    AppArmor::Tree::FileRule rule_0(path, mode, exec_target);
    AppArmor::Tree::FileRule rule_1(path, file_mode, exec_target);
    AppArmor::Tree::FileRule rule_2(0, 1, path, mode, exec_target);
    AppArmor::Tree::FileRule rule_3(0, 1, path, file_mode, exec_target);

    check_file_rule(rule_0, path, file_mode, exec_target, expected_output_string);
    check_file_rule(rule_1, path, file_mode, exec_target, expected_output_string);
    check_file_rule(rule_2, path, file_mode, exec_target, expected_output_string);
    check_file_rule(rule_3, path, file_mode, exec_target, expected_output_string);
}

TEST_F(FileRuleTest, test_rule_1)
{
    std::stringstream expected_output;
    expected_output << path << " " << mode << ",";
    test_file_rule(path, mode, "", expected_output.str());
}

TEST_F(FileRuleTest, test_rule_2)
{
    std::stringstream expected_output;
    expected_output << path << " " << mode << " -> " << target << ",";
    test_file_rule(path, mode, target, expected_output.str());
}

TEST_F(FileRuleTest, test_rule_3)
{
    std::stringstream expected_output;
    expected_output << path << " ,";
    test_file_rule(path, "", "", expected_output.str());
}

TEST_F(FileRuleTest, test_rule_4)
{
    test_file_rule("", mode, "", "");
}

TEST_F(FileRuleTest, test_rule_5)
{
    test_file_rule("", mode, target, "");
}
