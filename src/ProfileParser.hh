#ifndef PROFILE_PARSER_HH
#define PROFILE_PARSER_HH

#include "parser/tree/ParseTree.hh"
#include "Profile.hh"

#include <fstream>
#include <list>

class ProfileParser {
  public:
    ProfileParser(std::fstream &stream);

    std::list<Profile> getProfileList();

  private:
    void initializeProfileList(std::shared_ptr<ParseTree> ast);

    std::list<Profile> profile_list; 
};

#endif // PROFILE_PARSER_HH