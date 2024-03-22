#include <gtest/gtest.h>

#include "abstraction_rule_test.hh"
#include "apparmor_parser.hh"
#include "tree/AbstractionRule.hh"

inline void test_rule_to_string(const std::string &path, bool is_relative, bool is_if_exists, std::string expected_output_string)
{
    AppArmor::Tree::AbstractionRule rule_0(path, is_relative, is_if_exists);
    AppArmor::Tree::AbstractionRule rule_1(0, 1, path, is_relative, is_if_exists);

    EXPECT_EQ(rule_0.operator std::string(), expected_output_string);
    EXPECT_EQ(rule_1.operator std::string(), expected_output_string);
}

TEST_F(AbstractionRuleTest, test_string_operator_1)
{
    std::stringstream expected_output;
    expected_output << "#include <" << rel_path << ">";
    test_rule_to_string(rel_path, true, false, expected_output.str());
}

TEST_F(AbstractionRuleTest, test_string_operator_2)
{
    std::stringstream expected_output;
    expected_output << "#include \"" << rel_path << "\"";
    test_rule_to_string(rel_path, false, false, expected_output.str());
}

TEST_F(AbstractionRuleTest, test_string_operator_3)
{
    std::stringstream expected_output;
    expected_output << "#include if exists <" << rel_path << ">";
    test_rule_to_string(rel_path, true, true, expected_output.str());
}

TEST_F(AbstractionRuleTest, test_string_operator_4)
{
    std::stringstream expected_output;
    expected_output << "#include if exists \"" << rel_path << "\"";
    test_rule_to_string(rel_path, false, true, expected_output.str());
}

