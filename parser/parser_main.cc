#include <stdio.h>
#include <stdlib.h>

#include "parser.h"
#include "parser_lex.h"
#include "parser_yacc.h"

int main(int argc, char** argv) {
	if(argc == 2) {
		yyin = fopen(argv[1], "r");

		yyparse();

		return 0;
	}

	return 1;
}