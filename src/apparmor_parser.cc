#include "apparmor_parser.hh"
#include "parser/driver.hh"
#include "parser/lexer.hh"
#include "tree/FileRule.hh"
#include "tree/ParseTree.hh"
#include "tree/RuleNode.hh"

#include <fstream>
#include <memory>
#include <parser_yacc.hh>
#include <stdexcept>
#include <string>

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

    // Parse the file contents
    update_from_stream(stream);
}

void AppArmor::Parser::update_from_file_contents()
{
    // Put the file contents into a stream
    std::stringstream stream;
    stream << file_contents;
    update_from_stream(stream);
}

void AppArmor::Parser::update_from_stream(std::istream &stream)
{
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

    // Create or update the list of profiles
    initializeProfileList(driver.ast);
}

void AppArmor::Parser::initializeProfileList(const std::shared_ptr<AppArmor::Tree::ParseTree> &ast)
{
    profile_list = std::list<Profile>();
    auto astList = ast->profileList;
    for (auto prof_iter = astList->begin(); prof_iter != astList->end(); prof_iter++){
        profile_list.push_back(*prof_iter);
    }
}

std::list<AppArmor::Profile> AppArmor::Parser::getProfileList() const
{
    return profile_list;
}

void AppArmor::Parser::checkProfileValid(Profile &profile)
{
    // Attempt to find profile from the list and return on success
    for(const Profile &prof : profile_list) {
        if(profile == prof) {
            return;
        }
    }

    // Profile was not found so throw an exception
    std::stringstream message;
    message << "Invalid profile \"" << profile.name() << "\" was given as argument. This profile does not exist in this parser. Was it created using a different or outdated AppArmor::Parser object?\n";
    throw std::domain_error(message.str());
}

template<AppArmor::RuleDerived RuleType>
void AppArmor::Parser::removeRule(Profile &profile, RuleType &rule)
{
    checkProfileValid(profile);
    profile.checkRuleValid(rule);

    std::ofstream output_file(path);
    removeRule(profile, rule, output_file);
    output_file.close();
}

template<AppArmor::RuleDerived RuleType>
void AppArmor::Parser::removeRule(Profile &profile, RuleType &rule, std::ostream &output)
{
    checkProfileValid(profile);
    profile.checkRuleValid(rule);

    // Erase the rule from 'file_contents'
    auto start_pos = static_cast<uint>(rule.getStartPosition()) - 1;
    auto end_pos   = rule.getEndPosition();
    auto length    = end_pos - start_pos;

    file_contents.erase(start_pos, length);

    // Push changes to 'output_file' and update changes
    output << file_contents;
    update_from_file_contents();
}

void AppArmor::Parser::addRule(Profile &profile, const std::string &fileglob, const std::string &filemode)
{
    std::ofstream output_file(path);
    addRule(profile, fileglob, filemode, output_file);
    output_file.close();
}

void AppArmor::Parser::addRule(Profile &profile, const std::string &fileglob, const std::string &filemode, std::ostream &output)
{
    checkProfileValid(profile);

    // Get the position of the last rule
    auto pos = profile.getRuleEndPosition();

    // Create and insert the rule (TODO: Fix possible invalid rules and injection of extra rules)
    std::string addRule = "  " + fileglob + " " + filemode + ",\n";
    file_contents.insert(pos, addRule);

    // Push changes to 'output_file' and update changes
    output << file_contents;
    update_from_file_contents();
}

void AppArmor::Parser::editRule(Profile &profile,
                                FileRule &oldRule,
                                const std::string &fileglob,
                                const std::string &filemode)
{
    std::ofstream output_file(path);
    editRule(profile, oldRule, fileglob, filemode, output_file);
    output_file.close();
}

void AppArmor::Parser::editRule(Profile &profile,
                                FileRule &oldRule,
                                const std::string &fileglob,
                                const std::string &filemode,
                                std::ostream &output)
{
    checkProfileValid(profile);
    profile.checkRuleValid(oldRule);

    // Remove and replace the fileRule from 'file_contents'
    auto start_pos = oldRule.getStartPosition() - 1;
    auto end_pos   = oldRule.getEndPosition();
    auto length    = end_pos - start_pos;

    // Remove the old rule
    file_contents.erase(start_pos, length);

    // Create and insert the new rule (TODO: Fix possible invalid rules and injection of extra rules)
    std::string addRule = fileglob + " " + filemode + ",\n";
    file_contents.insert(start_pos, addRule);

    // Push changes to 'output_file' and update changes
    output << file_contents;
    update_from_file_contents();
}

template void AppArmor::Parser::removeRule<AppArmor::Tree::FileRule>(Profile &profile, AppArmor::Tree::FileRule &rule);
template void AppArmor::Parser::removeRule<AppArmor::Tree::LinkRule>(Profile &profile, AppArmor::Tree::LinkRule &rule);
template void AppArmor::Parser::removeRule<AppArmor::Tree::RuleList>(Profile &profile, AppArmor::Tree::RuleList &rule);
template void AppArmor::Parser::removeRule<AppArmor::Tree::AbstractionRule>(Profile &profile, AppArmor::Tree::AbstractionRule &rule);

template void AppArmor::Parser::removeRule<AppArmor::Tree::FileRule>(Profile &profile, AppArmor::Tree::FileRule &rule, std::ostream &output);
template void AppArmor::Parser::removeRule<AppArmor::Tree::LinkRule>(Profile &profile, AppArmor::Tree::LinkRule &rule, std::ostream &output);
template void AppArmor::Parser::removeRule<AppArmor::Tree::RuleList>(Profile &profile, AppArmor::Tree::RuleList &rule, std::ostream &output);
template void AppArmor::Parser::removeRule<AppArmor::Tree::AbstractionRule>(Profile &profile, AppArmor::Tree::AbstractionRule &rule, std::ostream &output);
