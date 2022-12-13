#ifndef PREFIX_NODE_HH
#define PREFIX_NODE_HH

#include "TreeNode.hh"
#include <string>

// The root node of the abstract syntax tree
class PrefixNode : public TreeNode {
  public:
    PrefixNode(bool audit, bool should_deny, bool owner);

  private:
    bool audit; 
    bool should_deny;
    bool owner;
};

#endif // PREFIX_NODE_HH