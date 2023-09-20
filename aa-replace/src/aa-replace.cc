#include "aa-replace.h"

#include <cstdlib>
#include <glibmm/spawn.h>
#include <iostream>
#include <fstream>

AppArmorReplace::results AppArmorReplace::call_command(const std::vector<std::string> &command)
{
  results result;
  std::vector<std::string> envp = { "PATH=/usr/bin:/usr/sbin:/usr/local/bin" };
  Glib::spawn_sync("/usr/sbin/",
                   command,
                   envp,
                   Glib::SpawnFlags::SPAWN_SEARCH_PATH_FROM_ENVP,
                   {},
                   &result.output,
                   &result.error,
                   &result.exit_status);
  return result;
}

int AppArmorReplace::call_command_wrapper(const std::vector<std::string> &command)
{
  if (command.empty()) {
    throw std::invalid_argument("'command' argument must be nonempty.");
  }

  results result = call_command(command);

  if (result.exit_status != 0) {
    std::cout << "Error calling '" << command[0] << "'. " << result.error << std::endl;
  } else {
    std::cout << result.output << std::endl;
  }

  return result.exit_status;
}

// Static protected methods
int AppArmorReplace::apply_profile(AppArmorReplace *caller, const std::string &filename, const std::string &profile_data)
{
  std::ofstream file;
  file.open(filename);

  if (!file.is_open()) {
    return 2;
  }

  file << profile_data;
  file.close();

  std::vector<std::string> command = { "apparmor_parser", "-r", filename };
  return caller->call_command_wrapper(command);
}

// Static public methods
int AppArmorReplace::apply_profile(const std::string &filename, const std::string &profile_data)
{
  AppArmorReplace caller;
  return apply_profile(&caller, filename, profile_data);
}
