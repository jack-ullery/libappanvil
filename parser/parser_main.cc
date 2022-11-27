#include "parser_lex.h"
#include "parser_yacc.h"

int main() {
	yyin = stdin;

	do {
		yyparse();
	} while(!feof(yyin));

	return 0;
}