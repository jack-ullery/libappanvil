#include "apparmor_parser.hh"
#include "parser/driver.hh"
#include "parser/lexer.hh"
#include "parser/tree/ParseTree.hh"

#include <fstream>
#include <iostream>
#include <memory>
#include <parser_yacc.hh>
#include <string>

/**
 * Idea: change constructor to take a file path as an argument rather than ifstream.
 * Create ifstream within constructor
 * Create ofstream within remove function
*/
AppArmor::Parser::Parser(const std::string &path)
{
    Driver driver;
    std::ifstream stream(path);
    Lexer lexer(stream, std::cout);

    yy::parser parse(lexer, driver);
    parse();

    if(!driver.success) {
        std::throw_with_nested(std::runtime_error("error occured when parsing profile"));
    }

    initializeProfileList(driver.ast);
}

void AppArmor::Parser::initializeProfileList(const std::shared_ptr<ParseTree> &ast)
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

AppArmor::Parser AppArmor::Parser::removeRule(AppArmor::Profile &profile, AppArmor::FileRule &fileRule) 
{
    std::string line {};
    std::string profileName = profile.name();
    std::string removeRule = fileRule.getFilename() + " " + fileRule.getFilemode() + ",";

    std::ifstream file;
    std::ofstream temp;
    bool foundProfile = false;
    bool removed = false;
    
    // Open the file we are working with and create a new temp file to write to.
    file.open(path);
    temp.open("temp.txt");

    // Write each line except the one we are replacing.
    // Flags used to make sure we don't delete multiple similar rules in different profiles.
    while (getline(file, line))
    {
        if(!foundProfile && !removed && (line == (profileName + " {") || line == ("profile " + profileName + " {"))) {
            foundProfile = true;
        }
        
        if (foundProfile && !removed && trim(line) == removeRule) {
            removed = true;
        }
        else {
            temp << line << std::endl;
        }
    }

    temp.close();
    file.close();

    // Delete original file and rename new file to old one.
    std::ignore = std::remove(path.c_str());
    std::ignore = std::rename("temp.txt", path.c_str());

    AppArmor::Parser parser(path);
    return parser;
}

AppArmor::Parser AppArmor::Parser::addRule(Profile &profile, const std::string &fileRule, std::string &fileMode)
{
    std::string line {};
    std::string profileName = profile.name();
    std::string addRule = "  " + fileRule + " " + fileMode + ",";

    std::ifstream file;
    std::ofstream temp;
    bool foundProfile = false;
    bool added = false;

    file.open(path);
    temp.open("temp.txt");

    while(getline(file, line)){
        if(!foundProfile && !added && (line == (profileName + " {") || line == ("profile " + profileName + " {"))) {
            foundProfile = true;
        }

        if (foundProfile && !added && (line == "}")) {
            added = true;
            temp << addRule << std::endl;
            temp << "}" << std::endl;
        } else {
            temp << line << std::endl;
        }
    }

    temp.close();
    file.close();

    // Delete original file and rename new file to old one.
    std::ignore = std::remove(path.c_str());
    std::ignore = std::rename("temp.txt", path.c_str());

    AppArmor::Parser parser(path);
    return parser;
}

// What should this do if old version of rule not found?
AppArmor::Parser AppArmor::Parser::editRule(Profile &profile, FileRule &oldFileRule, const std::string &newFileRule, const std::string &newFileMode) {
    
    std::string line {};
    std::string profileName = profile.name();
    std::string uneditedRule = oldFileRule.getFilename() + " " + oldFileRule.getFilemode() + ",";
    std::string editedRule = "  " + newFileRule + " " + newFileMode + ",";

    std::ifstream file;
    std::ofstream temp;
    bool foundProfile = false;
    bool edited = false;

    // Open the file we are working with and create a new temp file to write to.
    file.open(path);
    temp.open("temp.txt");

    // Write each line except for the old/unedited rule.
    // Write the edited version in its place.
    while (getline(file, line)) {
        if(!foundProfile && !edited && (line == (profileName + " {") || line == ("profile " + profileName + " {")))
        {
            foundProfile = true;
        }
        
        if (foundProfile && !edited && trim(line) == uneditedRule){
            temp << editedRule << std::endl;
            edited = true;
        } else {
            temp << line << std::endl;
        }
    }

    temp.close();
    file.close();

    // Delete original file and rename new file to old one.
    std::ignore = std::remove(path.c_str());
    std::ignore = std::rename("temp.txt", path.c_str());

    AppArmor::Parser parser(path);
    return parser;

}

// Trims leading and trailing whitespace
std::string trim(const std::string& str)
{

    const std::string& whitespace = " \t";

    // Find the character that isn't whitespace.
    const auto strBegin = str.find_first_not_of(whitespace);

    // If it cannot find it, then return an empty string.
    if (strBegin == std::string::npos) {
        return ""; // no content
    }

    // Find the last character that isn't whitespace.
    const auto strEnd = str.find_last_not_of(whitespace);

    // Remove the white space.
    const auto strRange = strEnd - strBegin + 1;

    return str.substr(strBegin, strRange);
}
