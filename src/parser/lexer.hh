#ifndef LEXER_HH
#define LEXER_HH

#include "parser_yacc.hh"

using token = yy::parser::token_type;
using location_type = yy::parser::location_type;
using symbol_type = yy::parser::symbol_type;

// Define the lexer prototype
# define YY_DECL symbol_type yylex()
YY_DECL;

#define YY_NULL yy::parser::symbol_type(0, yylloc);

#endif // LEXER_HH