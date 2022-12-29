#ifndef APPARMOR_PARSER_HH
#define APPARMOR_PARSER_HH

#include "apparmor_profile.hh"

#include <fstream>
#include <list>

class ParseTree;

namespace AppArmor {
  class Parser {
    public:
      Parser(std::fstream &stream);

      std::list<Profile> getProfileList();

    private:
      void initializeProfileList(std::shared_ptr<ParseTree> ast);

      std::list<Profile> profile_list; 
  };
}

#endif // APPARMOR_PARSER_HH