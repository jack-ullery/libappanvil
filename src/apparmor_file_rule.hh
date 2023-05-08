#ifndef APPARMOR_FILE_RULE_HH
#define APPARMOR_FILE_RULE_HH

#include <memory>
#include <string>

namespace AppArmor {
  namespace Tree {
    class FileNode;
  };

  class FileRule {
    public:
      FileRule() = default;
      explicit FileRule(std::shared_ptr<AppArmor::Tree::FileNode> model);

      std::string getFilename() const;
      std::string getFilemode() const;
      uint64_t getStartPosition() const;
      uint64_t getEndPosition() const;

      // Whether or not two FileRule objects have same filename/filemode
      // Does not check other values like start/stop position
      // This is useful for testing
      bool operator==(const AppArmor::FileRule& that) const;

      // Checks whether this object points to a copy of that FileNode
      // Checks that the filename, filemode, start_pos, and stop_pos are the same
      bool operator==(const AppArmor::Tree::FileNode& that) const;

    private:
      std::shared_ptr<AppArmor::Tree::FileNode> model;
  };
} // namespace AppArmor

#endif // APPARMOR_FILE_RULE_HH
