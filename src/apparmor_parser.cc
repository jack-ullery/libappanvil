#include "apparmor_parser.hh"
#include "parser/driver.hh"
#include "parser/lexer.hh"
#include "parser/tree/ParseTree.hh"

#include <iostream>
#include <memory>
#include <parser_yacc.hh>
#include <string>
#include <iostream>
#include <fstream>

std::string trim(const std::string& str);

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
    std::fstream file(path, std::ios::in);
    bool foundProfile = false;

    while(std::getline(file, line)){
        // Find the matching profile
        if (line.compare(profileName + " {") == 0 || line.compare("profile " + profileName + " {") == 0) {
            std::cout << "Found profile at: " << line << "\n";
            foundProfile = true;
        } else if(line.compare("}") == 0){
            foundProfile = false;
        }

        // Trim the leading whitespace and trailing whitespace for inside the profile braces.
        line = trim(line);

        if (foundProfile && line.compare(ruleName + " " + ruleMode + ",") == 0) {
            std::cout << "REMOVING RULE! Found rule at: " << line << "\n";
            
            /* Note: We will most likely need to rewrite the file. Unfortuantely, C++ doesn't provide an easy way to replace strings in a file.
                     Due to this, it is recommended to read the file, find the text we want to replace, and write back everything except for
                     that line to a new file. We can then rename the file so that the old one will be replaced.*/

            //line.replace(0, ruleName.length() + ruleMode.length() + 2, "");
            return true;
        }
    }

    return false;
}

// Trims leading and trailing whitespace
std::string trim(const std::string& str)
{

    const std::string& whitespace = " \t";

    // Find the character that isn't whitespace.
    const auto strBegin = str.find_first_not_of(whitespace);

    // If it cannot find it, then return an empty string.
    if (strBegin == std::string::npos)
        return ""; // no content

    // Find the last character that isn't whitespace.
    const auto strEnd = str.find_last_not_of(whitespace);

    // Remove the white space.
    const auto strRange = strEnd - strBegin + 1;

    return str.substr(strBegin, strRange);
}