#ifndef LEXER_HH
#define LEXER_HH

#ifndef yyFlexLexerOnce
#include <FlexLexer.h>
#endif

#include <iostream>

#include "common.hh"
#include "driver.hh"

#undef YY_NULL
#define YY_NULL yy::parser::symbol_type(0, driver.yylloc);

class Lexer : public yyFlexLexer {
  public:
    explicit Lexer(std::istream& arg_yyin)
      : yyFlexLexer(arg_yyin, std::cout) {}

    Lexer(std::istream& arg_yyin, std::ostream& arg_yyout)
      : yyFlexLexer(arg_yyin, arg_yyout) {}

    // NOLINTNEXTLINE
    virtual symbol_type yylex(Driver& driver);
};

// Define the lexer prototype
#undef YY_DECL
#define YY_DECL symbol_type Lexer::yylex(Driver& driver)

#define yyterminate() return( symbol_type(0, driver.yylloc) )

#define YY_NO_UNISTD_H

#endif // LEXER_HH