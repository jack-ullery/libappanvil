#include <utility>

#include "apparmor_file_rule.hh"
#include "parser/tree/FileNode.hh"

AppArmor::FileRule::FileRule(std::shared_ptr<FileNode> model)
  : model{std::move(model)}
{   }

std::string AppArmor::FileRule::getFilename() const
{
  return model->getFilename();
}

std::string AppArmor::FileRule::getFilemode() const
{
  return model->getFilemode();
}

uint64_t AppArmor::FileRule::getStartPosition() const
{
  return model->getStartPosition();
}

uint64_t AppArmor::FileRule::getEndPosition() const
{
  return model->getStopPosition();
}

bool AppArmor::FileRule::operator==(const AppArmor::FileRule& that) const
{
  return (that.getFilename() == this->getFilename()) && 
         (that.getFilemode() == this->getFilemode());
}
