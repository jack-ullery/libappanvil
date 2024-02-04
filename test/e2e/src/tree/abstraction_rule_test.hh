#ifndef ABSTRACTION_RULE_TEST
#define ABSTRACTION_RULE_TEST

#include <gtest/gtest.h>

class AbstractionRuleTest : public ::testing::Test {
public:

protected:
  std::string rel_path = "abstractions/base";
  std::string abs_path = "/etc/apparmor.d/abstractions/base";
};

#endif // ABSTRACTION_RULE_TEST