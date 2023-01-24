#include "apparmor_file_rule.hh"
#include "parser/tree/FileNode.hh"

AppArmor::FileRule::FileRule(std::shared_ptr<FileNode> model)
  : model{model}
{   }

std::string AppArmor::FileRule::getFilename() const
{
  return model->getFilename();
}

std::string AppArmor::FileRule::getFilemode() const
{
  return model->getFilemode();
}

bool AppArmor::FileRule::operator==(const AppArmor::FileRule& that) const
{
  return (that.getFilename() == this->getFilename()) && 
         (that.getFilemode() == this->getFilemode());
}
