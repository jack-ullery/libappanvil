#include "FileNode.hh"

#include <sstream>

FileNode::FileNode(uint64_t startPos, uint64_t stopPos) 
  : RuleNode("file", startPos, stopPos),
    isSubset{false}
{   }

FileNode::FileNode(uint64_t startPos, 
                   uint64_t stopPos, 
                   const std::string &fromFile, 
                   const std::string &fileMode, 
                   const std::string &toFile, 
                   bool isSubset)
  : RuleNode("file", startPos, stopPos),
    isSubset{isSubset},
    fromFile{fromFile},
    toFile{toFile},
    fileMode{fileMode}
{   }

FileNode::operator std::string() const
{
  std::stringstream stream;
  stream << "file " << (isSubset? "subset " : "") << fromFile << " " << fileMode; 
  
  if(toFile != "") {
    stream << " -> " << toFile;
  }

  stream << ",\n";
  return stream.str();
};
