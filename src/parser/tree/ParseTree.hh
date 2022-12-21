#ifndef PARSE_TREE_HH
#define PARSE_TREE_HH

#include "TreeNode.hh"
#include "ProfileNode.hh"

#include <list>
#include <memory>

// The root node of the abstract syntax tree
class ParseTree : public TreeNode {
  public:
    ParseTree(TreeNode preamble, std::shared_ptr<std::list<ProfileNode>> profileList);

    TreeNode preamble;
    std::shared_ptr<std::list<ProfileNode>> profileList;
};

#endif // PARSE_TREE_HH