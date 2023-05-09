#include "FileNode.hh"
#include "RuleNode.hh"

#include <sstream>

AppArmor::Tree::FileNode::FileNode(uint64_t startPos, uint64_t stopPos) 
  : RuleNode("file", startPos, stopPos),
    isSubset{false}
{   }

AppArmor::Tree::FileNode::FileNode(uint64_t startPos, 
                   uint64_t stopPos, 
                   const std::string &filename, 
                   const std::string &fileMode, 
                   const std::string &exec_target, 
                   bool isSubset)
  : RuleNode("file", startPos, stopPos),
    isSubset{isSubset},
    filename{filename},
    exec_target{exec_target},
    fileMode{fileMode}
{   }

std::string AppArmor::Tree::FileNode::getFilename() const
{
  return filename;
}

std::string AppArmor::Tree::FileNode::getFilemode() const
{
  return fileMode;
}

bool AppArmor::Tree::FileNode::operator==(const FileNode &other) const
{
  // Check that all the member fields are equal
  //  and that the objects are equal when interpreted as RuleNodes
  return almostEquals(other) &&
         RuleNode(*this) == other; // NOLINT(*slicing)
}

bool AppArmor::Tree::FileNode::almostEquals(const FileNode &other) const
{
  return this->isSubset == other.isSubset &&
         this->filename == other.filename &&
         this->exec_target == other.exec_target &&
         this->fileMode == other.fileMode;
}
