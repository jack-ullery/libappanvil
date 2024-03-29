#ifndef PREFIX_NODE_HH
#define PREFIX_NODE_HH

#include "TreeNode.hh"
#include <string>

namespace AppArmor::Tree {
  class PrefixNode : public TreeNode {
    public:
      explicit PrefixNode(bool audit = DEFAULT_AUDIT, bool should_deny = DEFAULT_PERM_MODE, bool owner = DEFAULT_OWNER);

      static constexpr bool DEFAULT_AUDIT       = false; 
      static constexpr bool DEFAULT_PERM_MODE   = false;
      static constexpr bool DEFAULT_OWNER       = false;

      bool getAudit() const;
      bool getShouldDeny() const;
      bool getOwner() const;     

      bool operator==(const PrefixNode &other) const;

      // Conversion operator to string, attempts to write a string for this prefix
      explicit operator std::string() const;

    private:
      bool audit; 
      bool should_deny;
      bool owner;
  };
} // namespace AppArmor::Tree

#endif // PREFIX_NODE_HH