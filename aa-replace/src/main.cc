#include "aa-replace.h"

#include <iostream>

void print_usage()
{
  std::cout << "A simple wrapper for 'apparmor_parser -r' (used internally by the AppAnvil Project)" << std::endl;
  std::cout << "This tool is not intended for direct use by the end-user" << std::endl << std::endl;
  std::cout << "Usage: aa-replace [filename] [filedata]" << std::endl << std::endl;
}

int main(int argc, char **argv)
{
  // NOLINTBEGIN(cppcoreguidelines-pro-bounds-pointer-arithmetic)
  if (argc == 3) {
    std::string arg_1(argv[1]);
    std::string arg_2(argv[2]);

    return AppArmorReplace::apply_profile(arg_1, arg_2);
  }

  print_usage();
  return 1;
  // NOLINTEND(cppcoreguidelines-pro-bounds-pointer-arithmetic)
}
