#include "ProfileParser.hh"
#include "parser/lexer.hh"

#include <parser_lex.hh>
#include <parser_yacc.hh>

// ProfileParser::ProfileParser(FILE *file)
// {
//     yyin = file;
// 	yyparse();
// }

ProfileParser::ProfileParser(std::string filename)
{
    yy::parser parser;
    parser.parse();
}
