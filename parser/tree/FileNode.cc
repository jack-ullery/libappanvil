#include "FileNode.h"
#include "tree/TreeNode.h"

#include <sstream>

FileNode::FileNode() 
  : TreeNode("file"),
    isSubset{false}
{   }

FileNode::FileNode(const std::string &from, const std::string &fileMode, const std::string &to, bool isSubset)
  : TreeNode("file"),
    isSubset{isSubset},
    from{from},
    to{to},
    fileMode{fileMode}
{   }

FileNode::operator std::string() const
{
  std::stringstream stream;
  stream << "file " << (isSubset? "subset " : "") << from << " " << fileMode; 
  
  if(to != "") {
    stream << " -> " << to;
  }

  stream << ",\n";
  return stream.str();
};
