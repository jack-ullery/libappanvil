#include "FileMode.hh"
#include "parser/parser.h"

#include <cctype>
#include <format>
#include <stdexcept>

AppArmor::Tree::FileMode::FileMode(const std::string &mode)
{
  bool expect_execute = false;
  for(const char &ch : mode) {
    auto lower_ch = std::tolower(ch);
    switch(lower_ch) {
      case COD_READ_CHAR:
        read = true;
        break;

      case COD_WRITE_CHAR:
        write = true;
        break;

      case COD_APPEND_CHAR:
        append = true;
        break;

      case COD_LINK_CHAR:
        link = true;
        break;

      case COD_LOCK_CHAR:
        lock = true;
        break;

      case COD_MMAP_CHAR:
        memory_map = true;
        break;

      case COD_INHERIT_CHAR:
      case COD_UNSAFE_UNCONFINED_CHAR:
      case COD_UNCONFINED_CHAR:
      case COD_UNSAFE_PROFILE_CHAR:
      case COD_PROFILE_CHAR:
      case COD_UNSAFE_LOCAL_CHAR:
      case COD_LOCAL_CHAR:
        execute_mode = std::format("{}x", ch);
        expect_execute = true;
        continue;

      case COD_EXEC_CHAR:
        if(!expect_execute) {
          throw std::runtime_error("Character 'x' encountered, but the type of execute mode was not specified (e.g. 'ix', 'px', 'cx', etc).\n"
                                   "Please reference \"Access Modes\" from `man apparmor.d`.");
        }
        break;

      default:
        throw std::runtime_error(std::format("Encountered unexpected character when parsing file mode: {}", ch));
    }

    expect_execute = false;
  }
}

bool AppArmor::Tree::FileMode::getRead() const
{
  return read;
}

bool AppArmor::Tree::FileMode::getWrite() const
{
  return write;
}

bool AppArmor::Tree::FileMode::getAppend() const
{
  return append;
}

bool AppArmor::Tree::FileMode::getMemoryMap() const
{
  return memory_map;
}

bool AppArmor::Tree::FileMode::getLink() const
{
  return link;
}

bool AppArmor::Tree::FileMode::getLock() const
{
  return lock;
}

std::string AppArmor::Tree::FileMode::getExecuteMode() const
{
  return execute_mode;
}

bool AppArmor::Tree::FileMode::operator==(const FileMode &other) const
{
  return read == other.read &&
         write == other.write &&
         append == other.append &&
         memory_map == other.memory_map &&
         link == other.link &&
         lock == other.lock &&
         execute_mode == other.execute_mode;
}
