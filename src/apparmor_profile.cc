#include "parser/tree/AbstractionNode.hh"
#include "apparmor_profile.hh"

#include <iostream>

AppArmor::Profile::Profile(ProfileNode& profile_model)
  : profile_model{profile_model}
{   }

std::string AppArmor::Profile::getName()
{
    return profile_model.getText();
}

std::unordered_set<std::string> AppArmor::Profile::getAbstractions()
{
  std::unordered_set<std::string> set;

  auto ruleList = profile_model.getRules();
  auto abstractionList = ruleList.getAbstractionList();

  for(AbstractionNode node : abstractionList) {
    set.insert(node.getPath());
  }

  return set;
}
