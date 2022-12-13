#include <stdlib.h>

#include "ProfileParser.hh"

int main(int argc, char** argv) {
	if(argc == 2) {
		FILE *file = fopen(argv[1], "r");

		ProfileParser parser(file);

		return 0;
	}

	return 1;
}