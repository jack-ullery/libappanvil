#include "apparmor_parser.hh"
#include "parser/driver.hh"
#include "parser/lexer.hh"
#include "parser/tree/ParseTree.hh"

#include <fstream>
#include <memory>
#include <parser_yacc.hh>
#include <string>

/**
 * Idea: change constructor to take a file path as an argument rather than ifstream.
 * Create ifstream within constructor
 * Create ofstream within remove function
*/
AppArmor::Parser::Parser(const std::string &path)
  : path{path}
{
    std::ifstream stream(path);

    // Read entire file into string and store if for later
    std::stringstream ss;
    ss << stream.rdbuf();
    file_contents = ss.str();

    // Seek back to beginning of file
    stream.seekg(0);

    // Perform lexical analysis
    Lexer lexer(stream, std::cerr);

    // Parse the file
    Driver driver;
    yy::parser parse(lexer, driver);
    parse();

    // If parsing was not successful, throw an exception
    if(!driver.success) {
        std::throw_with_nested(std::runtime_error("error occured when parsing profile"));
    }

    // Create list of profiles
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

void AppArmor::Parser::removeRule(AppArmor::Profile &profile, AppArmor::FileRule &fileRule)
{
    std::ofstream output_file(path);
    removeRule(profile, fileRule, output_file);
    output_file.close();
}

void AppArmor::Parser::removeRule(AppArmor::Profile &profile, AppArmor::FileRule &fileRule, std::ostream &output)
{
    // Erase the fileRule from 'file_contents'
    auto start_pos = static_cast<uint>(fileRule.getStartPosition()) - 1;
    auto end_pos   = fileRule.getEndPosition();
    auto length    = end_pos - start_pos;

    file_contents.erase(start_pos, length);

    // Push changes to 'output_file'
    output << file_contents;
}

void AppArmor::Parser::addRule(Profile &profile, const std::string &fileglob, const std::string &fileMode)
{
    std::ofstream output_file(path);
    addRule(profile, fileglob, fileMode, output_file);
    output_file.close();
}

void AppArmor::Parser::addRule(Profile &profile, const std::string &fileglob, const std::string &fileMode, std::ostream &output)
{
    // Get the position of the last rule
    auto pos = profile.getRuleEndPosition();

    // Create and insert the rule (TODO: Fix possible invalid rules and injection of extra rules)
    std::string addRule = "  " + fileglob + " " + fileMode + ",\n";
    file_contents.insert(pos, addRule);

    // Push changes to 'output_file'
    output << file_contents;
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
