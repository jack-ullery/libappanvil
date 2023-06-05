#ifndef FILE_RULE_HH
#define FILE_RULE_HH

#include "FileMode.hh"
#include "RuleNode.hh"

#include <string>

namespace AppArmor::Tree {
  class FileRule : public RuleNode {
    public:
      FileRule() = default;
      FileRule(uint64_t startPos, uint64_t stopPos);

      FileRule(uint64_t startPos, 
               uint64_t stopPos, 
               const std::string &filename, 
               const std::string &fileMode, 
               const std::string &exec_target = "", 
               bool isSubset = false);

      FileRule(uint64_t startPos, 
               uint64_t stopPos, 
               const std::string &filename, 
               const FileMode &fileMode, 
               const std::string &exec_target = "", 
               bool isSubset = false);

      std::string getFilename() const;
      FileMode getFilemode() const;

      // Checks all private memebrs are equal, including members of superclass (RuleNode)
      bool operator==(const FileRule &other) const;

      // Checks all private memebers are equal, not including members of superclass
      bool almostEquals(const FileRule &other) const;

    private:
      bool isSubset = false;
      std::string filename;
      std::string exec_target;
      FileMode fileMode;
  };
} // namespace AppArmor::Tree

#endif // FILE_RULE_HH