#include <fstream>
#include <stdlib.h>

#include "apparmor_parser.hh"

int main(int argc, char** argv) {
	if(argc == 2) {
		std::string path = argv[1];

		try {
			AppArmor::Parser parser(path);
		} catch(const std::exception &) {
			return 2;
		}

		return 0;
	}

	return 1;
}