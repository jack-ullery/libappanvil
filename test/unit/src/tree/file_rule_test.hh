#ifndef FILE_RULE_TEST
#define FILE_RULE_TEST

#include <gtest/gtest.h>

class FileRuleTest : public ::testing::Test {
public:

protected:
  const std::string path = "/tmp/file.txt";
  const std::string mode = "rwix";
  const std::string target = "target";  
};

#endif // FILE_RULE_TEST