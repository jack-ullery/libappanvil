#ifndef PREFIX_NODE_HH
#define PREFIX_NODE_HH

#include "TreeNode.hh"
#include <string>

class PrefixNode : public TreeNode {
  public:
    PrefixNode(bool audit = DEFAULT_AUDIT, bool should_deny = DEFAULT_PERM_MODE, bool owner = DEFAULT_OWNER);

    static constexpr bool DEFAULT_AUDIT       = false; 
    static constexpr bool DEFAULT_PERM_MODE   = false;
    static constexpr bool DEFAULT_OWNER       = false;

  private:
    bool audit; 
    bool should_deny;
    bool owner;
};

#endif // PREFIX_NODE_HH