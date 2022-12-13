#include "ProfileParser.hh"

#include <parser_lex.hh>
#include <parser_yacc.hh>

ProfileParser::ProfileParser(FILE *file)
{
    yyin = file;
	yyparse();
}