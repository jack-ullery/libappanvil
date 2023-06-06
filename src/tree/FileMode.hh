#ifndef FILE_MODE_HH
#define FILE_MODE_HH

#include "TreeNode.hh"
#include <string>

namespace AppArmor::Tree {
  class FileMode : public TreeNode {
    public:
      FileMode() = default;
      explicit FileMode(const std::string &mode);

      bool getRead() const;
      bool getWrite() const;
      bool getAppend() const;
      bool getMemoryMap() const;
      bool getLink() const;
      bool getLock() const;
      std::string getExecuteMode() const;

      bool operator==(const FileMode &other) const;

    private:
      bool read = false;
      bool write = false;
      bool append = false;
      bool memory_map = false;
      bool link = false;
      bool lock = false;
      std::string execute_mode;
  };
} // namespace AppArmor::Tree

#endif // FILE_MODE_HH