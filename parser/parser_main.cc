#include <cstdio>
#include "parser.h"
#include "parser_lex.hpp"
#include "parser_yacc.hpp"

int main() {
	yyin = stdin;

	while(!feof(yyin)) {
		yyparse();
	}

	return 0;
}