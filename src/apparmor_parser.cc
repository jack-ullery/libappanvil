#include "apparmor_parser.hh"
#include "parser/driver.hh"
#include "parser/lexer.hh"
#include "tree/AbstractionRule.hh"
#include "tree/FileRule.hh"
#include "tree/ParseTree.hh"
#include "tree/RuleNode.hh"

#include <fstream>
#include <glibmm/spawn.h>
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
    old_file_contents = std::string(file_contents);

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
    try
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
    catch (const std::runtime_error &ex)
    {
        file_contents = old_file_contents;
        std::throw_with_nested(ex);
    }
}

void AppArmor::Parser::initializeProfileList(const std::shared_ptr<AppArmor::Tree::ParseTree> &ast)
{
    profile_list = std::list<Profile>();
    auto astList = ast->profileList;
    for (auto prof_iter = astList->begin(); prof_iter != astList->end(); prof_iter++){
        profile_list.push_back(*prof_iter);
    }
}

std::string AppArmor::Parser::getPath() const
{
    return path;
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

    std::stringstream output;
    removeRule(profile, rule, output);
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

    // Push changes to 'output' and update changes
    output << file_contents;
    update_from_file_contents();
}

template<AppArmor::RuleDerived RuleType>
void AppArmor::Parser::addRule(Profile &profile, const RuleType &newRule)
{
    std::stringstream output;
    addRule(profile, newRule, output);
}

template<AppArmor::RuleDerived RuleType>
void AppArmor::Parser::addRule(Profile &profile, const RuleType &newRule, std::ostream &output)
{
    checkProfileValid(profile);

    // Get the position of the last rule
    auto pos = profile.getRuleEndPosition();

    // Create and insert the rule (TODO: Fix possible invalid rules and injection of extra rules)
    std::string addRule = "  " + newRule.operator std::string() + '\n';
    file_contents.insert(pos, addRule);

    // Push changes to 'output' and update changes
    output << file_contents;
    update_from_file_contents();
}

void AppArmor::Parser::editRule(Profile &profile,
                                FileRule &oldRule,
                                const FileRule &newRule)
{
    std::stringstream output;
    editRule(profile, oldRule, newRule, output);
}

void AppArmor::Parser::editRule(Profile &profile,
                                FileRule &oldRule,
                                const FileRule &newRule,
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
    std::string addRule = newRule.operator std::string();
    file_contents.insert(start_pos, addRule);

    // Push changes to 'output' and update changes
    output << file_contents;
    update_from_file_contents();
}

void AppArmor::Parser::updateFromString(const std::string &new_file_contents)
{
    std::stringstream stream;
    stream << new_file_contents;
    update_from_stream(stream);
    file_contents = new_file_contents;
}

bool AppArmor::Parser::hasChanges()
{
    return file_contents != old_file_contents;
}

int AppArmor::Parser::saveChanges()
{
  const std::vector<std::string> command = {"pkexec", "aa-replace", getPath(), file_contents};
  std::vector<std::string> envp = { "PATH=/usr/bin:/usr/sbin:/usr/local/bin" };

  std::string output;
  std::string error;
  int exit_status = 1;

  Glib::spawn_sync("/usr/sbin/",
                   command,
                   envp,
                   Glib::SpawnFlags::SPAWN_SEARCH_PATH_FROM_ENVP,
                   {},
                   &output,
                   &error,
                   &exit_status);

  if(exit_status == 0) {
    std::cout << output;
    old_file_contents = std::string(file_contents);
  } else {
    std::cerr << error;
  }

  return exit_status;
}

void AppArmor::Parser::cancelChanges()
{
    file_contents = std::string(old_file_contents);
    update_from_file_contents();
}

AppArmor::Parser::operator std::string() const
{
    std::string return_string(file_contents);
    return return_string;
}

// Link removeRule() functions
template void AppArmor::Parser::removeRule<AppArmor::Tree::FileRule>(Profile &profile, AppArmor::Tree::FileRule &rule);
template void AppArmor::Parser::removeRule<AppArmor::Tree::LinkRule>(Profile &profile, AppArmor::Tree::LinkRule &rule);
template void AppArmor::Parser::removeRule<AppArmor::Tree::RuleList>(Profile &profile, AppArmor::Tree::RuleList &rule);
template void AppArmor::Parser::removeRule<AppArmor::Tree::AbstractionRule>(Profile &profile, AppArmor::Tree::AbstractionRule &rule);

template void AppArmor::Parser::removeRule<AppArmor::Tree::FileRule>(Profile &profile, AppArmor::Tree::FileRule &rule, std::ostream &output);
template void AppArmor::Parser::removeRule<AppArmor::Tree::LinkRule>(Profile &profile, AppArmor::Tree::LinkRule &rule, std::ostream &output);
template void AppArmor::Parser::removeRule<AppArmor::Tree::RuleList>(Profile &profile, AppArmor::Tree::RuleList &rule, std::ostream &output);
template void AppArmor::Parser::removeRule<AppArmor::Tree::AbstractionRule>(Profile &profile, AppArmor::Tree::AbstractionRule &rule, std::ostream &output);

// Link addRule() functions
template void AppArmor::Parser::addRule<AppArmor::Tree::FileRule>(AppArmor::Profile&, AppArmor::FileRule const&);
template void AppArmor::Parser::addRule<AppArmor::Tree::AbstractionRule>(AppArmor::Profile&, AppArmor::AbstractionRule const&);

template void AppArmor::Parser::addRule<AppArmor::Tree::FileRule>(AppArmor::Profile&, AppArmor::FileRule const&, std::ostream&);
template void AppArmor::Parser::addRule<AppArmor::Tree::AbstractionRule>(AppArmor::Profile&, AppArmor::AbstractionRule const&, std::ostream&);
