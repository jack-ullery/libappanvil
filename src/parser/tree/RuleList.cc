#include "AbstractionNode.hh"
#include "FileNode.hh"
#include "LinkNode.hh"
#include "PrefixNode.hh"
#include "ProfileNode.hh"
#include "TreeNode.hh"

#include <iostream>

template<class ProfileNode>
RuleList<ProfileNode>::RuleList(uint64_t startPos)
  : RuleNode(startPos, startPos)
{   }

/** Append methods **/
template <typename T, typename = typename std::enable_if<std::is_base_of<RuleNode, T>::value, T>::type>
inline void appendPrefixedNode(const PrefixNode &prefix, T &node, std::list<T> &list)
{
  node.setPrefix(prefix);
  list.push_back(node);
}

template<class ProfileNode>
void RuleList<ProfileNode>::appendFileNode(const PrefixNode &prefix, FileNode &node)
{
  appendPrefixedNode(prefix, node, files);
}

template<class ProfileNode>
void RuleList<ProfileNode>::appendLinkNode(const PrefixNode &prefix, LinkNode &node)
{
  appendPrefixedNode(prefix, node, links);
}

template<class ProfileNode>
void RuleList<ProfileNode>::appendRuleList(const PrefixNode &prefix, RuleList<ProfileNode> &node)
{
  appendPrefixedNode(prefix, node, rules);
}

template<class ProfileNode>
void RuleList<ProfileNode>::appendAbstraction(AbstractionNode &node)
{
  abstractions.push_back(node);
}

template<class ProfileNode>
void RuleList<ProfileNode>::appendSubprofile(ProfileNode &node)
{
  subprofiles.push_back(node);
}

/** Get methods **/
template<class ProfileNode>
std::list<FileNode> RuleList<ProfileNode>::getFileList()
{
  return files;
}

template<class ProfileNode>
std::list<LinkNode> RuleList<ProfileNode>::getLinkList()
{
  return links;
}

template<class ProfileNode>
std::list<RuleList<ProfileNode>> RuleList<ProfileNode>::getRuleList()
{
  return rules;
}

template<class ProfileNode>
std::list<AbstractionNode> RuleList<ProfileNode>::getAbstractionList()
{
  return abstractions;
}

template<class ProfileNode>
std::list<ProfileNode> RuleList<ProfileNode>::getSubprofiles()
{
  return subprofiles;
}

// Helpful for the linker
template class RuleList<ProfileNode>;