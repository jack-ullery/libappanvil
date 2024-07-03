#ifndef PARSE_TREE_HH
#define PARSE_TREE_HH

#include "TreeNode.hh"
#include "ProfileRule.hh"

#include <list>
#include <memory>

namespace AppArmor::Tree {
  // The root node of the abstract syntax tree
  class ParseTree : public TreeNode {
    public:
      ParseTree(TreeNode preamble, std::shared_ptr<std::list<ProfileRule>> profileList);

      TreeNode preamble;
      std::shared_ptr<std::list<ProfileRule>> profileList;
  };
} // namespace AppArmor::Tree

#endif // PARSE_TREE_HH