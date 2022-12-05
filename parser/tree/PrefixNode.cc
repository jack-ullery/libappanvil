#include "PrefixNode.h"
#include "tree/TreeNode.h"

PrefixNode::PrefixNode(bool audit, bool should_deny, bool owner)
  : TreeNode(),
    audit{audit},
    should_deny{should_deny},
    owner{owner}
{   }
