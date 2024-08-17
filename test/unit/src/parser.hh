#ifndef PARSER_HH
#define PARSER_HH

#include <gtest/gtest.h>
#include <string>

// Grab bag of random AppArmor::Parser tests that are not covered in other files
class ParserCheck : public testing::TestWithParam<std::string> {
public:
};

const std::string broken_profiles[] = {
  "/broken/broken_1.sd", 
  "/broken/broken_2.sd", 
  "/broken/broken_3.sd", 
  "/broken/broken_4.sd"
};

#endif // PARSER_HH