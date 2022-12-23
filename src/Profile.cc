#include "Profile.hh"
#include "parser/tree/AbstractionNode.hh"

#include <iostream>

Profile::Profile(ProfileNode& profile_model)
  : profile_model{profile_model}
{   }

std::string Profile::getName()
{
    return profile_model.getText();
}

std::unordered_set<std::string> Profile::getAbstractions()
{
  std::unordered_set<std::string> set;

  auto ruleList = profile_model.getRules();
  auto abstractionList = ruleList.getAbstractionList();

  for(AbstractionNode node : abstractionList) {
    set.insert(node.getPath());
  }

  return set;
}
