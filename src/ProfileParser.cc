#include "ProfileParser.hh"
#include "parser/driver.hh"
#include "parser/lexer.hh"

#include <parser_lex.hh>
#include <parser_yacc.hh>

ProfileParser::ProfileParser(std::string filename)
{
   Driver driver;

    if (!(yyin = fopen(filename.c_str(), "r")))
    {
        std::cerr << "cannot open " << filename << ": " << strerror(errno) << '\n';
        exit(EXIT_FAILURE);
    }

    yy::parser parse(driver);
    driver.success = parse();
}
