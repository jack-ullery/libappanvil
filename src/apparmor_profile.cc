#include "apparmor_profile.hh"
#include "parser/tree/AbstractionNode.hh"
#include "parser/tree/ProfileNode.hh"

#include <iostream>

AppArmor::Profile::Profile(std::shared_ptr<ProfileNode> profile_model)
  : profile_model{profile_model}
{   }

std::string AppArmor::Profile::getName() const
{
    return profile_model->getText();
}

std::unordered_set<std::string> AppArmor::Profile::getAbstractions() const
{
  std::unordered_set<std::string> set;

  auto ruleList = profile_model->getRules();
  auto abstractionList = ruleList.getAbstractionList();

  for(AbstractionNode node : abstractionList) {
    set.insert(node.getPath());
  }

  return set;
}
