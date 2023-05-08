#ifndef ABSTRACTION_NODE_HH
#define ABSTRACTION_NODE_HH

#include "RuleNode.hh"
#include <string>

namespace AppArmor::Tree {
  class AbstractionNode : public RuleNode {
    public:
      AbstractionNode() = default;
      AbstractionNode(uint64_t startPos, uint64_t stopPos, const std::string &path, bool is_if_exists = false);

      std::string getPath() const;

    private:
      virtual explicit operator std::string() const;

      std::string path;
      bool is_if_exists = false;
  };
} // namespace AppArmor::Tree

#endif // ABSTRACTION_NODE_HH