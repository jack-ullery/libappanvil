#ifndef FILE_NODE_H
#define FILE_NODE_H

#include "TreeNode.h"
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

#endif // FILE_NODE_H