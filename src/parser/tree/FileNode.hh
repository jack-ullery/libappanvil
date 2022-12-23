#ifndef FILE_NODE_HH
#define FILE_NODE_HH

#include "RuleNode.hh"
#include <string>

class FileNode : public RuleNode {
  public:
    FileNode() = default;
    FileNode(uint64_t startPos, uint64_t stopPos);
    FileNode(uint64_t startPos, 
             uint64_t stopPos, 
             const std::string &fromFile, 
             const std::string &fileMode, 
             const std::string &toFile = "", 
             bool isSubset = false);

  private:
    bool isSubset;
    std::string fromFile;
    std::string toFile;
    std::string fileMode;
};

#endif // FILE_NODE_HH