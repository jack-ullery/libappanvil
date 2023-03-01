#ifndef APPARMOR_FILE_RULE_HH
#define APPARMOR_FILE_RULE_HH

#include <memory>
#include <string>

class FileNode;

namespace AppArmor {
  class FileRule {
    public:
      FileRule() = default;
      explicit FileRule(std::shared_ptr<FileNode> model);

      std::string getFilename() const;
      std::string getFilemode() const;

      // Whether or not two FileRule objects are equal
      bool operator==(const AppArmor::FileRule& that) const;

    private:
      std::shared_ptr<FileNode> model;
  };
} // namespace AppArmor

#endif // APPARMOR_FILE_RULE_HH