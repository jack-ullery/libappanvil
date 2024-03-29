#include "FileMode.hh"
#include "parser/parser.h"

#include <cctype>
#include <iterator>
#include <sstream>
#include <stdexcept>

AppArmor::Tree::FileMode::FileMode(bool read, bool write, bool append, bool memory_map, bool link, bool lock, const std::string &execute_mode)
  : AppArmor::Tree::FileMode::FileMode(buildString(read, write, append, memory_map, link, lock, execute_mode))
{ }

AppArmor::Tree::FileMode::FileMode(const std::string &mode)
{
  std::stringstream potential_execute_mode;
  for(const char &ch : mode) {
    auto lower_ch = std::tolower(ch);
    switch(lower_ch) {
      case COD_READ_CHAR:
        read = true;
        break;

      case COD_WRITE_CHAR:
        if(append) {
          throw std::runtime_error("Both write and append permissions granted to same file_rule, which is not allowed.");
        }

        write = true;
        break;

      case COD_APPEND_CHAR:
        if(write) {
          throw std::runtime_error("Both write and append permissions granted to same file_rule, which is not allowed.");
        }

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
        potential_execute_mode << ch;
        continue;

      case COD_EXEC_CHAR:
        potential_execute_mode << ch;
        execute_mode = potential_execute_mode.str();
        break;

      default:
        std::stringstream message;
        message << "Encountered unexpected character when parsing file mode: " << ch;
        throw std::runtime_error(message.str());
    }
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

bool AppArmor::Tree::FileMode::empty() const
{
  return !read &&
         !write &&
         !append &&
         !memory_map &&
         !link &&
         !lock &&
         execute_mode.empty();
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

// Append a character to a stringstream if the boolean is true
inline void conditionalAppend(std::stringstream &ss, bool value, char ch)
{
  if(value) {
    ss << ch;
  }
}

std::string AppArmor::Tree::FileMode::buildString(bool read, bool write, bool append, bool memory_map, bool link, bool lock, const std::string &execute_mode)
{
  std::stringstream ss;
  conditionalAppend(ss, read, COD_READ_CHAR);
  conditionalAppend(ss, write, COD_WRITE_CHAR);
  conditionalAppend(ss, append, COD_APPEND_CHAR);
  conditionalAppend(ss, memory_map, COD_MMAP_CHAR);
  conditionalAppend(ss, link, COD_LINK_CHAR);
  conditionalAppend(ss, lock, COD_LOCK_CHAR);
  ss << execute_mode;

  return ss.str();
}

AppArmor::Tree::FileMode::operator std::string() const
{
  return buildString(read, write, append, memory_map, link, lock, execute_mode);
}
