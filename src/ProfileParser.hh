#ifndef PROFILE_PARSER_H
#define PROFILE_PARSER_H

#include <fstream>
#include <stdlib.h>

class ProfileParser {
  public:
    // Not implemented yet
    ProfileParser(std::fstream stream);

    // Would like to move away from using C types
    // Need to make the parser a C++ parser
    [[deprecated]]
    ProfileParser(FILE *file);
};

#endif // PROFILE_PARSER_H