#ifndef FILE_NODE_H
#define FILE_NODE_H

#include "TreeNode.h"
#include <string>

// The root node of the abstract syntax tree
class FileNode : public TreeNode {
  public:
    FileNode();
    FileNode(const std::string &from, const std::string &fileMode, const std::string &to = "", bool isSubset = false);

  private:
    virtual operator std::string() const;
    bool isSubset;
    std::string from;
    std::string to;
    std::string fileMode;
};

#endif // FILE_NODE_H