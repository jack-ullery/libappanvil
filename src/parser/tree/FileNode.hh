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
             const std::string &filename, 
             const std::string &fileMode, 
             const std::string &exec_target = "", 
             bool isSubset = false);

    std::string getFilename() const;
    std::string getFilemode() const;

  private:
    bool isSubset;
    std::string filename;
    std::string exec_target;
    std::string fileMode;
};

#endif // FILE_NODE_HH