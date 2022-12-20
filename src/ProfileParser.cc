#include "ProfileParser.hh"
#include "parser/driver.hh"
#include "parser/lexer.hh"

#include <parser_yacc.hh>

ProfileParser::ProfileParser(std::fstream &stream)
{
    Driver driver;
    Lexer lexer(stream);

    yy::parser parse(lexer, driver);
    driver.success = parse();
}
