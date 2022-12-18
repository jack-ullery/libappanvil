#ifndef LEXER_HH
#define LEXER_HH

#include "parser_yacc.hh"
#include "driver.hh"

using token = yy::parser::token_type;
using location_type = yy::parser::location_type;
using symbol_type = yy::parser::symbol_type;

// Define the lexer prototype
#define YY_DECL symbol_type yylex(Driver& driver)
YY_DECL;

#define YY_NULL yy::parser::symbol_type(0, driver.yylloc);

#endif // LEXER_HH