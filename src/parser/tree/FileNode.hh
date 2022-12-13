#ifndef FILE_NODE_HH
#define FILE_NODE_HH

#include "RuleNode.hh"
#include <string>

// The root node of the abstract syntax tree
class FileNode : public RuleNode {
  public:
    FileNode(uint64_t startPos, uint64_t stopPos);
    FileNode(uint64_t startPos, 
             uint64_t stopPos, 
             const std::string &fromFile, 
             const std::string &fileMode, 
             const std::string &toFile = "", 
             bool isSubset = false);

  private:
    virtual operator std::string() const;
    bool isSubset;
    std::string fromFile;
    std::string toFile;
    std::string fileMode;
};

#endif // FILE_NODE_HH