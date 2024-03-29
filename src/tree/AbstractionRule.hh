#ifndef ABSTRACTION_RULE_HH
#define ABSTRACTION_RULE_HH

#include "RuleNode.hh"
#include <string>

namespace AppArmor::Tree {
  class AbstractionRule : public RuleNode {
    public:
      AbstractionRule() = default;

      AbstractionRule(uint64_t startPos,
                      uint64_t stopPos,
                      const std::string &path,
                      bool is_relative = true,
                      bool is_if_exists = false);

      explicit AbstractionRule(const std::string &path,
                               bool is_relative = true,
                               bool is_if_exists = false);

      std::string getPath() const;
      bool isRelative() const;
      bool isIfExists() const;

      virtual bool operator==(const AbstractionRule &other) const;
      virtual bool operator==(const std::string &path) const;

      explicit operator std::string() const override;

    private:
      std::string path;
      bool is_relative = true;
      bool is_if_exists = false;
  };
} // namespace AppArmor::Tree

#endif // ABSTRACTION_RULE_HH