#include <fstream>
#include <stdlib.h>

#include "apparmor_parser.hh"

int main(int argc, char** argv) {
	if(argc == 2) {
		std::fstream stream(argv[1]);
		AppArmor::Parser parser(stream);
		return 0;
	}

	return 1;
}