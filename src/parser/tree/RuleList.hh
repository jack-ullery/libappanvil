#ifndef RULE_LIST_HH
#define RULE_LIST_HH

#include "AbstractionNode.hh"
#include "FileNode.hh"
#include "LinkNode.hh"
#include "PrefixNode.hh"
#include "RuleNode.hh"
#include "TreeNode.hh"

#include <cstdint>
#include <string>

template <class ProfileNode>
class RuleList : public RuleNode {
  public:
    RuleList() = default;
    explicit RuleList(uint64_t startPos);

    void appendFileNode(const PrefixNode &prefix, FileNode &node);
    void appendLinkNode(const PrefixNode &prefix, LinkNode &node);
    void appendRuleList(const PrefixNode &prefix, RuleList &node);
    void appendAbstraction(AbstractionNode &node);
    void appendSubprofile(ProfileNode &node);

    std::list<FileNode>        getFileList();
    std::list<LinkNode>        getLinkList();
    std::list<RuleList>        getRuleList();
    std::list<AbstractionNode> getAbstractionList();
    std::list<ProfileNode>     getSubprofiles();

  private:
    std::list<FileNode>         files;
    std::list<LinkNode>         links;
    std::list<RuleList>         rules;
    std::list<AbstractionNode>  abstractions;
    std::list<ProfileNode>      subprofiles;
};

#endif // RULE_LIST_HH