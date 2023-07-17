#include "FileRule.hh"
#include "RuleNode.hh"

#include <sstream>

AppArmor::Tree::FileRule::FileRule(uint64_t startPos, uint64_t stopPos) 
  : RuleNode("file", startPos, stopPos),
    isSubset{false}
{   }

AppArmor::Tree::FileRule::FileRule(uint64_t startPos,
                                   uint64_t stopPos,
                                   const std::string &filename,
                                   const FileMode &fileMode,
                                   const std::string &exec_target,
                                   bool isSubset)
  : RuleNode("file", startPos, stopPos),
    isSubset{isSubset},
    filename{filename},
    exec_target{exec_target},
    fileMode{fileMode}
{   }

AppArmor::Tree::FileRule::FileRule(uint64_t startPos,
                                   uint64_t stopPos,
                                   const std::string &filename,
                                   const std::string &fileMode,
                                   const std::string &exec_target,
                                   bool isSubset)
  : RuleNode("file", startPos, stopPos),
    isSubset{isSubset},
    filename{filename},
    exec_target{exec_target},
    fileMode(fileMode)
{   }

std::string AppArmor::Tree::FileRule::getFilename() const
{
  return filename;
}

AppArmor::Tree::FileMode AppArmor::Tree::FileRule::getFilemode() const
{
  return fileMode;
}

bool AppArmor::Tree::FileRule::getIsSubset() const
{
  return isSubset;
}

std::string AppArmor::Tree::FileRule::getExecTarget() const
{
  return exec_target;
}

bool AppArmor::Tree::FileRule::operator==(const FileRule &other) const
{
  // Check that all the member fields are equal
  //  and that the objects are equal when interpreted as RuleNodes
  return almostEquals(other) &&
         RuleNode(*this) == other; // NOLINT(*slicing)
}

bool AppArmor::Tree::FileRule::almostEquals(const FileRule &other) const
{
  return this->isSubset == other.isSubset &&
         this->filename == other.filename &&
         this->exec_target == other.exec_target &&
         this->fileMode == other.fileMode;
}

AppArmor::Tree::FileRule::operator std::string() const
{
  std::stringstream ss;

  if(!filename.empty()) {
    // Add prefix to file rule
    ss << getPrefix().operator std::string();

    if(!isSubset) {
      // Recreate the rule: using filename first, followed by permissions for non subset rule
      ss << filename << ' ' << fileMode.operator std::string();
    } else {
      ss << fileMode.operator std::string() << " subset " << filename;
    }

    // If there was an exec_target, add it
    if(!exec_target.empty()) {
      ss << " -> " << exec_target;
    }

    // Closing comma
    ss << ',';
  }

  return ss.str();
}
