#include <fstream>
#include <stdlib.h>

#include "ProfileParser.hh"

int main(int argc, char** argv) {
	if(argc == 2) {
		std::fstream stream(argv[1]);
		ProfileParser parser(stream);
		return 0;
	}

	return 1;
}