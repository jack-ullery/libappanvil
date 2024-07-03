#ifndef ALIAS_NODE_HH
#define ALIAS_NODE_HH

#include "TreeNode.hh"
#include <string>

namespace AppArmor::Tree {
  class AliasNode : public TreeNode {
    public:
      AliasNode(const std::string &from, const std::string &to);

      virtual explicit operator std::string() const;

    private:
      std::string from;
      std::string to;
  };
} // namespace AppArmor::Tree

#endif // ALIAS_NODE_HH