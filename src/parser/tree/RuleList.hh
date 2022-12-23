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

class RuleList : public RuleNode {
  public:
    RuleList() = default;
    RuleList(uint64_t startPos);

    void setStartPosition(uint64_t start_pos);
    void setStopPosition(uint64_t stop_pos);

    void appendFileNode(const PrefixNode &prefix, FileNode &node);
    void appendLinkNode(const PrefixNode &prefix, LinkNode &node);
    void appendRuleList(const PrefixNode &prefix, RuleList &node);
    void appendAbstraction(AbstractionNode &node);

    std::list<FileNode>        getFileList();
    std::list<LinkNode>        getLinkList();
    std::list<RuleList>        getRuleList();
    std::list<AbstractionNode> getAbstractionList();

  private:
    std::list<FileNode>         files;
    std::list<LinkNode>         links;
    std::list<RuleList>         rules;
    std::list<AbstractionNode>  abstractions;
};

#endif // RULE_LIST_HH