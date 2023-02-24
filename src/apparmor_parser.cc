#include "apparmor_parser.hh"
#include "parser/driver.hh"
#include "parser/lexer.hh"
#include "parser/tree/ParseTree.hh"

#include <memory>
#include <parser_yacc.hh>
#include <string>
#include <iostream>
#include <fstream>

/**
 * Idea: change constructor to take a file path as an argument rather than ifstream.
 * Create ifstream within constructor
 * Create ofstream within remove function
*/
AppArmor::Parser::Parser(std::ifstream &stream)
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

void AppArmor::Parser::initializeProfileList(std::shared_ptr<ParseTree> ast)
{
    profile_list = std::list<Profile>();
    
    auto astList = ast->profileList;
    for (auto prof_iter = astList->begin(); prof_iter != astList->end(); prof_iter++){
        std::shared_ptr<ProfileNode> node = std::make_shared<ProfileNode>(*prof_iter);
        Profile profile(node);
        profile_list.push_back(profile);
    }
}

std::list<AppArmor::Profile> AppArmor::Parser::getProfileList() const
{
    return profile_list;
}

bool AppArmor::Parser::removeRule(std::string path, std::string profileName, std::string ruleName, 
std::string ruleMode) 
{
    std::string line {};
    std::fstream file(path, std::ios::out);
    bool foundProfile = false;

    while(std::getline(file, line)){
        // Find the matching profile
        if (line.compare(profileName + " {") == 0 || line.compare("profile " + profileName + " {") == 0) {
            foundProfile = true;
        } else if(line.compare("}")){
            foundProfile = false;
        }

        //Find the matching rule
        if (line.compare(ruleName + " " + ruleMode + ",") == 0 && foundProfile) {
            // the bastardline
            line.replace(0, ruleName.length() + ruleMode.length() + 2, "");
            return true;
        }
    }

    return false;
}