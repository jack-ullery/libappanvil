#ifndef DRIVER_HH
#define DRIVER_HH

#include "parser.h"
#include "tree/ParseTree.hh"
#include "tree/TreeNode.hh"
#include <string>

class Driver
{
  public:
    bool success = false;

    // Parser fields
    std::shared_ptr<AppArmor::Tree::ParseTree> ast;

    // Lexer fields
    YYLTYPE yylloc = {.first_pos = 0, .last_pos = 0};
    uint64_t current_lineno = 0;
};

#endif // DRIVER_HH
