#ifndef FILE_NODE_HH
#define FILE_NODE_HH

#include "RuleNode.hh"
#include <string>

namespace AppArmor::Tree {
  class FileNode : public RuleNode {
    public:
      FileNode() = default;
      FileNode(uint64_t startPos, uint64_t stopPos);
      FileNode(uint64_t startPos, 
              uint64_t stopPos, 
              const std::string &filename, 
              const std::string &fileMode, 
              const std::string &exec_target = "", 
              bool isSubset = false);

      std::string getFilename() const;
      std::string getFilemode() const;

      // Checks all private memebrs are equal, including members of superclass (RuleNode)
      bool operator==(const FileNode &other) const;

      // Checks all private memebers are equal, not including members of superclass
      bool almostEquals(const FileNode &other) const;

    private:
      bool isSubset = false;
      std::string filename;
      std::string exec_target;
      std::string fileMode;
  };
} // namespace AppArmor::Tree

#endif // FILE_NODE_HH