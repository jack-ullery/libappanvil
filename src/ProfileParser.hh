#ifndef PROFILE_PARSER_H
#define PROFILE_PARSER_H

#include <fstream>
#include <stdlib.h>

class ProfileParser {
  public:
    ProfileParser(std::fstream &stream);
};

#endif // PROFILE_PARSER_H