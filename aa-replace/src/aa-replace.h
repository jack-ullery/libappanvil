#ifndef SRC_AA_LOADER
#define SRC_AA_LOADER

#include <string>
#include <vector>

/**
 * Calls commands on the terminal to be used by the rest of the program.
 * This is where AppAnvil actually interfaces with AppArmor.
 * Most of these functions are called on the second thread.
 **/
class AppArmorReplace
{
public:
  // Default constructor and destructor
  AppArmorReplace()          = default;
  virtual ~AppArmorReplace() = default;

  // Copy/move constructors and operators
  AppArmorReplace(const AppArmorReplace &)            = default;
  AppArmorReplace(AppArmorReplace &&)                 = delete;
  AppArmorReplace &operator=(const AppArmorReplace &) = default;
  AppArmorReplace &operator=(AppArmorReplace &&)      = delete;

  static int apply_profile(const std::string &filename, const std::string &profile_data);

protected:
  struct results
  {
    int exit_status = 0;
    std::string output;
    std::string error;
  };

  // Used to call command-line commands from `/usr/sbin`
  virtual results call_command(const std::vector<std::string> &command);
  virtual int call_command_wrapper(const std::vector<std::string> &command);

  // Dependency Injection: For unit testing
  static int apply_profile(AppArmorReplace *caller, const std::string &filename, const std::string &profile_data);
};

#endif // COMMAND_CALLER_H
