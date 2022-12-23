#include "ProfileParser.hh"
#include "parser/driver.hh"
#include "parser/lexer.hh"

#include <memory>
#include <parser_yacc.hh>

ProfileParser::ProfileParser(std::fstream &stream)
{
    Driver driver;
    Lexer lexer(stream, std::cout);

    yy::parser parse(lexer, driver);
    parse();

    if(!driver.success) {
        std::throw_with_nested(std::runtime_error("error occured when parsing profile"));
    }

    initializeProfileList(driver.ast);
}

void ProfileParser::initializeProfileList(std::shared_ptr<ParseTree> ast)
{
    profile_list = std::list<Profile>();
    
    auto astList = ast->profileList;
    for (auto prof_iter = astList->begin(); prof_iter != astList->end(); prof_iter++){
        Profile profile(*prof_iter);
        profile_list.push_back(profile);
    }
}

std::list<Profile> ProfileParser::getProfileList()
{
    return profile_list;
}