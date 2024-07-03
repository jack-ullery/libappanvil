#ifndef COMMON_HH
#define COMMON_HH

#include "parser_yacc.hh"

// Some common definitions that are used in multiple places
using token = yy::parser::token_type;
using location_type = yy::parser::location_type;
using symbol_type = yy::parser::symbol_type;

#endif // COMMON_HH
