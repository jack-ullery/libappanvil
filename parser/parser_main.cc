#include <cstddef>
#include <cstdio>
#include <iostream>

#include "parser.h"
#include "parser_lex.hpp"
#include "parser_yacc.hpp"

int main() {
	std::cout << "Starting parsing" << std::endl;

	yyparse();
	std::cout << std::endl << "Number of lines: " << current_lineno << std::endl;

	std::cout << "end." << std::endl;

	return 0;
}