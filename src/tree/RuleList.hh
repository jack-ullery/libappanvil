#ifndef RULE_LIST_HH
#define RULE_LIST_HH

#include "AbstractionRule.hh"
#include "FileRule.hh"
#include "LinkRule.hh"
#include "PrefixNode.hh"
#include "RuleNode.hh"
#include "TreeNode.hh"

#include <cstdint>
#include <string>

namespace AppArmor::Tree {
  class ProfileRule;
  class RuleList : public RuleNode {
    public:
      RuleList() = default;
      explicit RuleList(uint64_t startPos);

      std::list<FileRule>        getFileList() const;
      std::list<LinkRule>        getLinkList() const;
      std::list<RuleList>        getRuleList() const;
      std::list<AbstractionRule> getAbstractions() const;
      std::list<ProfileRule>     getSubprofiles() const;

    protected:
      friend class yy::parser;

      void appendFileRule(const PrefixNode &prefix, FileRule &node);
      void appendLinkRule(const PrefixNode &prefix, LinkRule &node);
      void appendRuleList(const PrefixNode &prefix, RuleList &node);
      void appendAbstraction(AbstractionRule &node);
      void appendSubprofile(ProfileRule &node);

    private:
      std::list<FileRule>         files;
      std::list<LinkRule>         links;
      std::list<RuleList>         rules;
      std::list<AbstractionRule>  abstractions;
      std::list<ProfileRule>      subprofiles;
  };
} // namespace AppArmor::Tree

#endif // RULE_LIST_HH